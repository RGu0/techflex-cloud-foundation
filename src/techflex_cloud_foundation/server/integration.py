"""Explicit, ephemeral network-integration composition for remote testing.

This module must never be used as a production bootstrap: repository and object
storage state are process-memory only. Production still requires PostgreSQL,
S3/KMS, deployment IAM and a TLS ingress configured outside this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import os
from uuid import UUID

from fastapi import FastAPI

from techflex_cloud_foundation.contracts.cloud import (
    INSOLE_ARCHIVE_PAYLOAD_SCHEMA,
    INSOLE_MANIFEST_SCHEMA,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.device_management.service import DeviceManagementService
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)


@dataclass(frozen=True, slots=True)
class IntegrationSettings:
    tenant_id: str
    site_id: str
    device_id: str
    activation_code: str
    terminal_token_secret: str
    activation_hmac_key: str
    identity_encryption_key: bytes
    identity_lookup_hmac_key: bytes

    @classmethod
    def required_environment_names(cls) -> tuple[str, ...]:
        return (
            "FFP_INTEGRATION_TENANT_ID",
            "FFP_INTEGRATION_SITE_ID",
            "FFP_INTEGRATION_DEVICE_ID",
            "FFP_INTEGRATION_ACTIVATION_CODE",
            "FFP_INTEGRATION_TERMINAL_TOKEN_SECRET",
            "FFP_INTEGRATION_ACTIVATION_HMAC_KEY",
            "FFP_INTEGRATION_IDENTITY_ENCRYPTION_KEY",
            "FFP_INTEGRATION_IDENTITY_LOOKUP_HMAC_KEY",
        )

    @classmethod
    def from_environment(cls) -> IntegrationSettings:
        missing = tuple(
            name for name in cls.required_environment_names() if not os.environ.get(name)
        )
        if missing:
            raise RuntimeError(
                "missing required integration environment: " + ", ".join(missing)
            )
        return cls(
            tenant_id=os.environ["FFP_INTEGRATION_TENANT_ID"],
            site_id=os.environ["FFP_INTEGRATION_SITE_ID"],
            device_id=os.environ["FFP_INTEGRATION_DEVICE_ID"],
            activation_code=os.environ["FFP_INTEGRATION_ACTIVATION_CODE"],
            terminal_token_secret=os.environ[
                "FFP_INTEGRATION_TERMINAL_TOKEN_SECRET"
            ],
            activation_hmac_key=os.environ["FFP_INTEGRATION_ACTIVATION_HMAC_KEY"],
            identity_encryption_key=_hex_key(
                os.environ["FFP_INTEGRATION_IDENTITY_ENCRYPTION_KEY"],
                name="FFP_INTEGRATION_IDENTITY_ENCRYPTION_KEY",
            ),
            identity_lookup_hmac_key=_hex_key(
                os.environ["FFP_INTEGRATION_IDENTITY_LOOKUP_HMAC_KEY"],
                name="FFP_INTEGRATION_IDENTITY_LOOKUP_HMAC_KEY",
            ),
        )

    def __post_init__(self) -> None:
        UUID(self.tenant_id)
        UUID(self.site_id)
        UUID(self.device_id)
        if len(self.activation_code.strip()) < 8:
            raise ValueError("integration activation code is too short")
        if len(self.terminal_token_secret.encode("utf-8")) < 32:
            raise ValueError("integration terminal token secret is too short")
        if len(self.activation_hmac_key.encode("utf-8")) < 32:
            raise ValueError("integration activation HMAC key is too short")
        if len(self.identity_encryption_key) != 32:
            raise ValueError("integration identity encryption key must contain 32 bytes")
        if len(self.identity_lookup_hmac_key) < 32:
            raise ValueError("integration identity lookup HMAC key is too short")


def build_integration_app(settings: IntegrationSettings) -> FastAPI:
    """Compose the real HTTP contracts over explicitly ephemeral adapters."""

    tenant_id = UUID(settings.tenant_id)
    site_id = UUID(settings.site_id)
    device_id = UUID(settings.device_id)
    repository = InMemoryPlatformRepository()
    repository.add_tenant(tenant_id, "Aliyun Integration Tenant")
    repository.add_device(tenant_id, device_id, "DO-P4864")
    objects = InMemoryObjectStore()
    tokens = TerminalTokenIssuer(
        secret=settings.terminal_token_secret.encode("utf-8"),
        key_id="aliyun-integration-terminal/1",
        token_ttl=timedelta(hours=1),
    )
    devices = DeviceManagementService(
        repository,
        tokens,
        activation_code_hmac_key=settings.activation_hmac_key.encode("utf-8"),
    )
    repository.add_activation_code_hash(
        devices.hash_activation_code(settings.activation_code),
        tenant_id=tenant_id,
        site_id=site_id,
        device_id=device_id,
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    subjects = SubjectConsentService(
        repository,
        IdentityProtector(
            encryption_key=settings.identity_encryption_key,
            lookup_hmac_key=settings.identity_lookup_hmac_key,
            key_version="aliyun-integration-identity/1",
        ),
    )
    ingestion = IngestionService(
        repository,
        SegmentObjectStore(objects),
        # RAY-825: insole archive sessions alongside force-plate raw segments.
        supported_payload_schemas={"raw-segment/1", INSOLE_ARCHIVE_PAYLOAD_SCHEMA},
        supported_manifest_schemas={"session-manifest/1", INSOLE_MANIFEST_SCHEMA},
    )
    app = create_app(
        ServiceContainer(
            ingestion=ingestion,
            token_issuer=tokens,
            subjects=subjects,
            devices=devices,
        )
    )

    @app.get("/health/live")
    async def health_live() -> dict[str, str]:
        return {"status": "ok", "environment": "integration"}

    @app.get("/health/ready")
    async def health_ready() -> dict[str, str]:
        return {
            "status": "ready",
            "environment": "integration",
            "persistence": "ephemeral",
            "object_storage": "in_memory",
        }

    return app


def _hex_key(value: str, *, name: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be hexadecimal") from exc
    return key


def app_from_environment() -> FastAPI:
    return build_integration_app(IntegrationSettings.from_environment())
