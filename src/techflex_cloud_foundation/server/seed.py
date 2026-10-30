"""Persistent seed-pilot composition for PostgreSQL and private local objects."""

from __future__ import annotations

import asyncio
import base64
import binascii
from collections.abc import Callable
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from techflex_cloud_foundation.contracts.cloud import (
    INSOLE_ARCHIVE_PAYLOAD_SCHEMA,
    INSOLE_MANIFEST_SCHEMA,
)
from techflex_cloud_foundation.object_store import FileSystemObjectStore
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessTokenIssuer,
    RefreshTokenFactory,
    TenantAccessTokenIssuer,
    TerminalAccessTokenIssuer,
    TerminalRefreshTokenFactory,
)
from techflex_cloud_foundation.server.access_control.capture_grants import CaptureGrantService
from techflex_cloud_foundation.server.access_control.lease_service import HardwareLeaseService
from techflex_cloud_foundation.server.access_control.platform_iam import (
    PlatformIdentityService,
    SensitiveAccessService,
)
from techflex_cloud_foundation.server.access_control.platform_service import (
    PlatformProvisioningService,
)
from techflex_cloud_foundation.server.access_control.postgres import PostgresAccessRepository
from techflex_cloud_foundation.server.access_control.tenant_service import (
    TenantAuthenticationService,
)
from techflex_cloud_foundation.server.access_control.terminal_service import TerminalAccessService
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.device_management.heartbeat_service import (
    DeviceHeartbeatService,
)
from techflex_cloud_foundation.server.identity_recovery.postgres import (
    PostgresRecoveryCaseRepository,
    PostgresRecoveryIdentityReader,
)
from techflex_cloud_foundation.server.identity_recovery.service import IdentityRecoveryService
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.insole_inventory.postgres import (
    PostgresInsoleInventoryRepository,
)
from techflex_cloud_foundation.server.insole_inventory.service import InsoleInventoryService
from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)
from techflex_cloud_foundation.server.validation_telemetry import (
    FileSystemValidationTelemetryRepository,
    ValidationTelemetryService,
)


# Runtime roots must stay outside the source checkout; an installed wheel has none.
def _checkout_root() -> Path | None:
    """The source checkout this module runs from, or None when installed from a wheel."""
    root = Path(__file__).resolve().parents[3]
    return root if (root / "pyproject.toml").is_file() and (root / "src").is_dir() else None


REPOSITORY_ROOT = _checkout_root()


def _secret(value: str, name: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) < 32:
        raise ValueError(f"{name} must contain at least 32 bytes")
    return encoded


def _raw_b64(value: str, name: str, *, length: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} must be valid base64") from exc
    if len(decoded) != length:
        raise ValueError(f"{name} must decode to {length} bytes")
    return decoded


@dataclass(frozen=True, slots=True)
class SeedSettings:
    migration_dsn: str
    tenant_dsn: str
    activation_dsn: str
    platform_dsn: str
    tenant_token_secret: str
    platform_token_secret: str
    tenant_refresh_hmac_key: str
    platform_refresh_hmac_key: str
    tenant_login_hmac_key: str
    platform_login_hmac_key: str
    activation_hmac_key: str
    identity_lookup_hmac_key: str
    identity_encryption_key_b64: str
    license_private_key_b64: str
    license_key_id: str
    object_root: Path | str
    public_base_url: str
    trusted_proxies: tuple[str, ...]
    object_backend: Literal["filesystem", "aliyun-oss"] = "filesystem"
    validation_telemetry_root: Path | str | None = None
    oss_region: str | None = None
    oss_bucket: str | None = None
    oss_endpoint: str | None = None
    oss_server_side_encryption: Literal["KMS", "AES256"] = "KMS"
    oss_ecs_ram_role: str | None = None
    secret_file: Path | str | None = None
    tenant_token_key_id: str = "tenant/1"
    platform_token_key_id: str = "platform/1"
    identity_key_version: str = "identity/1"

    def __post_init__(self) -> None:
        if self.object_backend not in {"filesystem", "aliyun-oss"}:
            raise ValueError("object backend must be filesystem or aliyun-oss")
        dsns = (self.migration_dsn, self.tenant_dsn, self.activation_dsn, self.platform_dsn)
        if any(urlparse(dsn).scheme not in {"postgres", "postgresql"} for dsn in dsns):
            raise ValueError("all seed database DSNs must use PostgreSQL")
        if len(set(dsns)) != 4:
            raise ValueError("migration, tenant, activation, and Platform DSNs must be distinct")
        for name in (
            "tenant_token_secret", "platform_token_secret", "tenant_refresh_hmac_key",
            "platform_refresh_hmac_key", "tenant_login_hmac_key",
            "platform_login_hmac_key", "activation_hmac_key", "identity_lookup_hmac_key",
        ):
            _secret(getattr(self, name), name)
        if self.tenant_token_secret == self.platform_token_secret:
            raise ValueError("tenant and Platform token secrets must be distinct")
        if self.tenant_refresh_hmac_key == self.platform_refresh_hmac_key:
            raise ValueError("tenant and Platform refresh secrets must be distinct")
        _raw_b64(self.identity_encryption_key_b64, "identity encryption key", length=32)
        _raw_b64(self.license_private_key_b64, "License private key", length=32)
        if not self.license_key_id.strip():
            raise ValueError("License key ID is required")
        parsed_url = urlparse(self.public_base_url)
        if parsed_url.scheme != "https" or not parsed_url.netloc:
            raise ValueError("public base URL must be absolute HTTPS")
        root = Path(self.object_root).expanduser().resolve()
        if REPOSITORY_ROOT is not None and (
            root == REPOSITORY_ROOT or root.is_relative_to(REPOSITORY_ROOT)
        ):
            raise ValueError("object root must stay outside the repository")
        object.__setattr__(self, "object_root", root)
        telemetry_root = Path(
            self.validation_telemetry_root or root.parent / "validation-telemetry"
        ).expanduser().resolve()
        if (
            (
                REPOSITORY_ROOT is not None
                and (
                    telemetry_root == REPOSITORY_ROOT
                    or telemetry_root.is_relative_to(REPOSITORY_ROOT)
                )
            )
            or telemetry_root == root
            or telemetry_root.is_relative_to(root)
        ):
            raise ValueError("validation telemetry must use a separate external security domain")
        object.__setattr__(self, "validation_telemetry_root", telemetry_root)
        if self.object_backend == "aliyun-oss":
            if not self.oss_region or not self.oss_region.strip():
                raise ValueError("OSS region is required")
            if not self.oss_bucket or not self.oss_bucket.strip():
                raise ValueError("OSS bucket is required")
            endpoint = urlparse(self.oss_endpoint or "")
            if endpoint.scheme != "https" or not endpoint.netloc:
                raise ValueError("OSS endpoint must be absolute HTTPS")
            if (
                endpoint.hostname is None
                or endpoint.hostname
                != f"oss-{self.oss_region.strip()}-internal.aliyuncs.com"
                or endpoint.username is not None
                or endpoint.password is not None
                or endpoint.port is not None
                or endpoint.path not in {"", "/"}
                or endpoint.params
                or endpoint.query
                or endpoint.fragment
            ):
                raise ValueError("OSS endpoint must be an internal HTTPS origin")
            if self.oss_server_side_encryption not in {"KMS", "AES256"}:
                raise ValueError("OSS server-side encryption must be KMS or AES256")
        if not self.trusted_proxies:
            raise ValueError("at least one trusted reverse proxy is required")
        if self.secret_file is not None:
            secret_path = Path(self.secret_file).expanduser().resolve()
            mode = secret_path.stat().st_mode & 0o777
            if mode != 0o600:
                raise ValueError("seed secret file permissions must be exactly 0600")
            if hasattr(os, "getuid") and secret_path.stat().st_uid != os.getuid():
                raise ValueError("seed secret file must be owned by the service user")
            object.__setattr__(self, "secret_file", secret_path)

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> SeedSettings:
        values = environ if environ is not None else os.environ

        def required(name: str) -> str:
            value = values.get(name, "")
            if not value:
                raise ValueError(f"missing required setting {name}")
            return value

        return cls(
            migration_dsn=required("FEETFORCEPLATE_MIGRATION_DSN"),
            tenant_dsn=required("FEETFORCEPLATE_TENANT_DSN"),
            activation_dsn=required("FEETFORCEPLATE_ACTIVATION_DSN"),
            platform_dsn=required("FEETFORCEPLATE_PLATFORM_DSN"),
            tenant_token_secret=required("FEETFORCEPLATE_TENANT_TOKEN_SECRET"),
            platform_token_secret=required("FEETFORCEPLATE_PLATFORM_TOKEN_SECRET"),
            tenant_refresh_hmac_key=required("FEETFORCEPLATE_TENANT_REFRESH_HMAC_KEY"),
            platform_refresh_hmac_key=required("FEETFORCEPLATE_PLATFORM_REFRESH_HMAC_KEY"),
            tenant_login_hmac_key=required("FEETFORCEPLATE_TENANT_LOGIN_HMAC_KEY"),
            platform_login_hmac_key=required("FEETFORCEPLATE_PLATFORM_LOGIN_HMAC_KEY"),
            activation_hmac_key=required("FEETFORCEPLATE_ACTIVATION_HMAC_KEY"),
            identity_lookup_hmac_key=required("FEETFORCEPLATE_IDENTITY_LOOKUP_HMAC_KEY"),
            identity_encryption_key_b64=required("FEETFORCEPLATE_IDENTITY_ENCRYPTION_KEY_B64"),
            license_private_key_b64=required("FEETFORCEPLATE_LICENSE_PRIVATE_KEY_B64"),
            license_key_id=required("FEETFORCEPLATE_LICENSE_KEY_ID"),
            object_root=required("FEETFORCEPLATE_OBJECT_ROOT"),
            public_base_url=required("FEETFORCEPLATE_PUBLIC_BASE_URL"),
            trusted_proxies=tuple(
                item.strip() for item in required("FEETFORCEPLATE_TRUSTED_PROXIES").split(",")
                if item.strip()
            ),
            object_backend=cast(Any, values.get("FEETFORCEPLATE_OBJECT_BACKEND", "filesystem")),
            validation_telemetry_root=(
                values.get("FEETFORCEPLATE_VALIDATION_TELEMETRY_ROOT") or None
            ),
            oss_region=values.get("FEETFORCEPLATE_OSS_REGION") or None,
            oss_bucket=values.get("FEETFORCEPLATE_OSS_BUCKET") or None,
            oss_endpoint=values.get("FEETFORCEPLATE_OSS_ENDPOINT") or None,
            oss_server_side_encryption=cast(
                Any, values.get("FEETFORCEPLATE_OSS_SERVER_SIDE_ENCRYPTION", "KMS")
            ),
            oss_ecs_ram_role=values.get("FEETFORCEPLATE_OSS_ECS_RAM_ROLE") or None,
            secret_file=values.get("FEETFORCEPLATE_SEED_ENV_FILE") or None,
            tenant_token_key_id=values.get("FEETFORCEPLATE_TENANT_TOKEN_KEY_ID", "tenant/1"),
            platform_token_key_id=values.get("FEETFORCEPLATE_PLATFORM_TOKEN_KEY_ID", "platform/1"),
            identity_key_version=values.get("FEETFORCEPLATE_IDENTITY_KEY_VERSION", "identity/1"),
        )

    def license_private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(
            _raw_b64(self.license_private_key_b64, "License private key", length=32)
        )


async def build_seed_app(
    settings: SeedSettings,
    *,
    pool_factory: Callable[..., Any] | None = None,
    object_store_factory: Callable[[SeedSettings], Any] | None = None,
) -> FastAPI:
    if pool_factory is None:
        import asyncpg  # type: ignore[import-untyped]

        pool_factory = asyncpg.create_pool
    tenant_pool = await pool_factory(dsn=settings.tenant_dsn, min_size=1, max_size=10)
    activation_pool = await pool_factory(dsn=settings.activation_dsn, min_size=1, max_size=5)
    platform_pool = await pool_factory(dsn=settings.platform_dsn, min_size=1, max_size=5)

    access_repository = PostgresAccessRepository(
        tenant_pool=tenant_pool, activation_pool=activation_pool, platform_pool=platform_pool
    )
    data_repository = PostgresPlatformRepository(tenant_pool, platform_pool=platform_pool)
    from techflex_cloud_foundation.server.report_copy.object_store import LocalBasicPdfStore
    from techflex_cloud_foundation.server.report_copy.postgres import (
        PostgresLocalBasicCopyRepository,
    )
    from techflex_cloud_foundation.server.report_copy.service import LocalBasicCopyService
    from techflex_cloud_foundation.server.session_hold.postgres import PostgresSessionHoldRepository
    from techflex_cloud_foundation.server.session_hold.service import SessionHoldService

    hold_repository = PostgresSessionHoldRepository(platform_pool)
    session_holds = SessionHoldService(hold_repository)
    if object_store_factory is not None:
        objects = object_store_factory(settings)
    elif settings.object_backend == "aliyun-oss":
        from techflex_cloud_foundation.aliyun_oss import build_aliyun_oss_object_store

        objects = build_aliyun_oss_object_store(settings)
    else:
        objects = FileSystemObjectStore(settings.object_root)
    private_key = settings.license_private_key()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    license_signer = LicenseDocumentSigner(
        private_key=private_key, key_id=settings.license_key_id,
        public_keys={settings.license_key_id: public_key},
    )
    tenant_tokens = TenantAccessTokenIssuer(
        secret=_secret(settings.tenant_token_secret, "tenant token secret"),
        key_id=settings.tenant_token_key_id,
    )
    platform_tokens = PlatformAccessTokenIssuer(
        secret=_secret(settings.platform_token_secret, "Platform token secret"),
        key_id=settings.platform_token_key_id,
    )
    tenant_access = TenantAuthenticationService(
        access_repository,
        login_lookup_hmac_key=_secret(settings.tenant_login_hmac_key, "tenant login key"),
        activation_hmac_key=_secret(settings.activation_hmac_key, "activation key"),
        tenant_tokens=tenant_tokens,
        refresh_tokens=RefreshTokenFactory(
            digest_key=_secret(settings.tenant_refresh_hmac_key, "tenant refresh key")
        ),
        license_signer=license_signer,
    )
    # Terminal tokens share the tenant signing secret but carry their own
    # token type and audience, so neither verifier accepts the other's token.
    terminal_tokens = TerminalAccessTokenIssuer(
        secret=_secret(settings.tenant_token_secret, "tenant token secret"),
        key_id=settings.tenant_token_key_id,
    )
    terminal_access = TerminalAccessService(
        access_repository,
        login_lookup_hmac_key=_secret(settings.tenant_login_hmac_key, "tenant login key"),
        terminal_tokens=terminal_tokens,
        refresh_tokens=TerminalRefreshTokenFactory(
            digest_key=_secret(settings.tenant_refresh_hmac_key, "tenant refresh key")
        ),
        license_signer=license_signer,
    )
    platform_identities = PlatformIdentityService(
        access_repository,
        login_lookup_hmac_key=_secret(settings.platform_login_hmac_key, "Platform login key"),
        token_issuer=platform_tokens,
        refresh_tokens=RefreshTokenFactory(
            digest_key=_secret(settings.platform_refresh_hmac_key, "Platform refresh key")
        ),
    )
    platform_access = PlatformProvisioningService(
        access_repository,
        login_lookup_hmac_key=_secret(settings.tenant_login_hmac_key, "tenant login key"),
        activation_hmac_key=_secret(settings.activation_hmac_key, "activation key"),
        license_signer=license_signer,
    )
    identity = IdentityProtector(
        encryption_key=_raw_b64(
            settings.identity_encryption_key_b64, "identity encryption key", length=32
        ),
        lookup_hmac_key=_secret(settings.identity_lookup_hmac_key, "identity lookup key"),
        key_version=settings.identity_key_version,
    )
    subjects = SubjectConsentService(data_repository, identity)
    sensitive = SensitiveAccessService(access_repository)
    # D10 and identity recovery share one reader: ACTIVE subjects only, decrypt
    # failures masked, and called only after the sensitive grant is used.
    identity_reader = PostgresRecoveryIdentityReader(tenant_pool, identity)
    app = create_app(
        ServiceContainer(
            ingestion=IngestionService(
                data_repository, SegmentObjectStore(objects),
                # RAY-825: insole archive sessions alongside force-plate raw segments.
                supported_payload_schemas={"raw-segment/1", INSOLE_ARCHIVE_PAYLOAD_SCHEMA},
                supported_manifest_schemas={"session-manifest/1", INSOLE_MANIFEST_SCHEMA},
            ),
            subjects=subjects,
            heartbeats=DeviceHeartbeatService(data_repository),
            tenant_access=tenant_access,
            tenant_tokens=tenant_tokens,
            terminal_access=terminal_access,
            terminal_tokens=terminal_tokens,
            insole_inventory=InsoleInventoryService(
                PostgresInsoleInventoryRepository(activation_pool), access_repository
            ),
            hardware_leases=HardwareLeaseService(access_repository),
            capture_grants=CaptureGrantService(data_repository),
            platform_identities=platform_identities,
            platform_access=platform_access,
            platform_tokens=platform_tokens,
            platform_sensitive=sensitive,
            platform_subjects=identity_reader,
            session_holds=session_holds,
            report_copies=LocalBasicCopyService(
                PostgresLocalBasicCopyRepository(tenant_pool, LocalBasicPdfStore(objects)),
                hold_repository,
            ),
            validation_telemetry=ValidationTelemetryService(
                FileSystemValidationTelemetryRepository(
                    Path(cast(str, settings.validation_telemetry_root))
                )
            ),
            identity_recovery=IdentityRecoveryService(
                PostgresRecoveryCaseRepository(tenant_pool, platform_pool),
                sensitive=sensitive,
                identity_reader=identity_reader,
            ),
        )
    )
    app.state.seed_settings = settings
    app.state.seed_pools = (tenant_pool, activation_pool, platform_pool)
    app.state.access_repository = access_repository

    @app.get("/health/live", include_in_schema=False)
    async def health_live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready", include_in_schema=False)
    async def health_ready() -> JSONResponse:
        dependencies = {"postgres": "unavailable", "object_store": "unavailable"}
        try:
            for pool in app.state.seed_pools:
                async with pool.acquire() as connection:
                    if await connection.fetchval("SELECT 1") != 1:
                        raise RuntimeError("database readiness failed")
            dependencies["postgres"] = "ready"
            if settings.object_backend == "aliyun-oss":
                await objects.check_ready()
            else:
                root = Path(settings.object_root)
                if not root.is_dir() or not os.access(root, os.W_OK | os.X_OK):
                    raise RuntimeError("object storage readiness failed")
            dependencies["object_store"] = "ready"
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "dependencies": dependencies},
            )
        return JSONResponse(
            status_code=200, content={"status": "ready", "dependencies": dependencies}
        )

    async def close_pools() -> None:
        for pool in app.state.seed_pools:
            await pool.close()

    app.router.add_event_handler("shutdown", close_pools)
    return app


async def serve_seed(
    settings: SeedSettings | None = None,
    *,
    pool_factory: Callable[..., Any] | None = None,
    server_factory: Callable[[Any], Any] | None = None,
) -> None:
    import uvicorn

    resolved_settings = settings or SeedSettings.from_env()
    app = await build_seed_app(resolved_settings, pool_factory=pool_factory)
    host = os.environ.get("FEETFORCEPLATE_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("FEETFORCEPLATE_BIND_PORT", "8743"))
    config = uvicorn.Config(
        app, host=host, port=port, proxy_headers=False, server_header=False
    )
    server = (server_factory or uvicorn.Server)(config)
    await server.serve()


def main() -> None:
    asyncio.run(serve_seed())


if __name__ == "__main__":
    main()


__all__ = ["SeedSettings", "build_seed_app", "serve_seed"]
