"""Provider identities, role bindings, masked views, and sensitive access grants."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import inspect
from typing import Any
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.access_control import (
    MaskedTenantSummary,
    PlatformLoginRequest,
    PlatformLoginResponse,
    PlatformRole,
    SensitiveAccessGrantRequest,
    SensitiveAccessGrantResponse,
    SensitiveIdentityResponse,
)
from techflex_cloud_foundation.platform_errors import PlatformError
from techflex_cloud_foundation.server.access_auth import (
    PlatformAccessContext,
    PlatformAccessTokenIssuer,
    RefreshTokenFactory,
)

from .passwords import hash_password, verify_password
from .platform_service import normalize_login_name
from .repository import (
    AccessRepository,
    AccessRepositoryConflict,
    AuditEventRecord,
    AuthenticationAttemptRecord,
    PlatformIdentityRecord,
    PlatformRoleBindingRecord,
    SensitiveAccessGrantRecord,
)


class PlatformPermissionDenied(PlatformError):
    """A Platform role, grant, or token lifetime does not authorize an action."""

    code = "E-PLT-403"
    http_status = 403
    action = "CONTACT_PLATFORM_OWNER"


class PlatformIdentityService:
    _ACCESS_TTL = timedelta(minutes=15)
    _FAILED_WINDOW = timedelta(minutes=15)
    _FAILED_LIMIT = 5

    def __init__(
        self,
        repository: AccessRepository,
        *,
        login_lookup_hmac_key: bytes,
        token_issuer: PlatformAccessTokenIssuer,
        refresh_tokens: RefreshTokenFactory,
        now: Any = None,
    ) -> None:
        if len(login_lookup_hmac_key) < 32:
            raise ValueError("platform login lookup key must contain at least 32 bytes")
        self._repository = repository
        self._login_lookup_hmac_key = login_lookup_hmac_key
        self._token_issuer = token_issuer
        self._refresh_tokens = refresh_tokens
        self._now = now or (lambda: datetime.now(UTC))

    def _login_digest(self, login_name: str) -> bytes:
        return hmac.new(
            self._login_lookup_hmac_key,
            normalize_login_name(login_name).encode("utf-8"),
            hashlib.sha256,
        ).digest()

    async def _ensure_not_rate_limited(self, *, login_name_hmac: bytes, now: datetime) -> None:
        failures = await self._repository.failed_authentication_attempts_for_login(
            login_name_hmac=login_name_hmac,
            since=now - self._FAILED_WINDOW,
        )
        if failures >= self._FAILED_LIMIT:
            raise PlatformPermissionDenied("Platform login is temporarily unavailable")

    async def _record_attempt(
        self,
        *,
        login_name_hmac: bytes,
        source_fingerprint: bytes,
        succeeded: bool,
        attempted_at: datetime,
    ) -> None:
        await self._repository.record_authentication_attempt(
            AuthenticationAttemptRecord(
                authentication_attempt_id=uuid4(),
                login_name_hmac=login_name_hmac,
                source_fingerprint=source_fingerprint,
                attempt_kind="PLATFORM_LOGIN",
                succeeded=succeeded,
                attempted_at=attempted_at,
            )
        )

    async def bootstrap_owner(
        self,
        *,
        login_name: str,
        display_name: str,
        password: str,
    ) -> PlatformLoginResponse:
        if await self._repository.platform_identity_count() != 0:
            raise RuntimeError("Platform owner bootstrap has already been completed")
        return await self._create_identity(
            login_name=login_name,
            display_name=display_name,
            password=password,
            roles=(PlatformRole.OWNER,),
            actor_id=None,
        )

    async def create_identity(
        self,
        context: PlatformAccessContext,
        *,
        login_name: str,
        display_name: str,
        password: str,
        roles: tuple[PlatformRole, ...],
    ) -> PlatformLoginResponse:
        self._require_active_context(context)
        if PlatformRole.OWNER not in context.roles:
            raise PlatformPermissionDenied("only Platform owner can create identities")
        return await self._create_identity(
            login_name=login_name,
            display_name=display_name,
            password=password,
            roles=roles,
            actor_id=context.platform_identity_id,
        )

    async def _create_identity(
        self,
        *,
        login_name: str,
        display_name: str,
        password: str,
        roles: tuple[PlatformRole, ...],
        actor_id: UUID | None,
    ) -> PlatformLoginResponse:
        now = self._now()
        if not display_name.strip():
            raise ValueError("Platform display name is required")
        if not roles or len(set(roles)) != len(roles):
            raise ValueError("Platform roles must be non-empty and unique")
        identity = PlatformIdentityRecord(
            platform_identity_id=uuid4(),
            login_name_hmac=self._login_digest(login_name),
            display_name=display_name.strip(),
            password_hash=hash_password(password),
            status="ACTIVE",
            token_version=1,
            created_at=now,
        )
        bindings = tuple(
            PlatformRoleBindingRecord(
                binding_id=uuid4(),
                platform_identity_id=identity.platform_identity_id,
                role=role,
                valid_from=now,
            )
            for role in roles
        )
        await self._repository.create_platform_identity(identity, bindings)
        if actor_id is not None:
            await self._repository.append_audit(
                AuditEventRecord(
                    event_id=uuid4(),
                    actor_id=actor_id,
                    action="platform-identity.create",
                    tenant_id=None,
                    resource_id=identity.platform_identity_id,
                    occurred_at=now,
                    details=tuple(
                        ("role", role.value) for role in sorted(roles, key=lambda r: r.value)
                    ),
                )
            )
        return self._login_response(identity, roles, now=now)

    async def login(
        self,
        request: PlatformLoginRequest,
        *,
        source_fingerprint: bytes = b"",
    ) -> PlatformLoginResponse:
        now = self._now()
        login_digest = self._login_digest(request.login_name)
        await self._ensure_not_rate_limited(login_name_hmac=login_digest, now=now)
        succeeded = False
        try:
            identity = await self._repository.platform_identity_by_login_hmac(login_digest)
            if (
                identity is None
                or identity.status != "ACTIVE"
                or not verify_password(request.password, identity.password_hash)
            ):
                raise PlatformPermissionDenied("Platform credentials were rejected")
            roles = await self._repository.platform_roles(
                identity.platform_identity_id,
                at=now,
            )
            if not roles:
                raise PlatformPermissionDenied("Platform identity has no active role")
            succeeded = True
            return self._login_response(identity, roles, now=now)
        except PlatformPermissionDenied:
            raise
        finally:
            await self._record_attempt(
                login_name_hmac=login_digest,
                source_fingerprint=source_fingerprint,
                succeeded=succeeded,
                attempted_at=now,
            )

    def _login_response(
        self,
        identity: PlatformIdentityRecord,
        roles: tuple[PlatformRole, ...],
        *,
        now: datetime,
    ) -> PlatformLoginResponse:
        access_token = self._token_issuer.issue(
            platform_identity_id=identity.platform_identity_id,
            roles=roles,
            token_version=identity.token_version,
            now=now,
        )
        refresh = self._refresh_tokens.issue()
        return PlatformLoginResponse(
            platform_identity_id=identity.platform_identity_id,
            roles=roles,
            access_token=access_token,
            access_token_expires_at=now + self._ACCESS_TTL,
            refresh_token=refresh.raw_token,
        )

    async def verify_access_token(self, token: str) -> PlatformAccessContext:
        token_context = self._token_issuer.verify(token, now=self._now())
        identity = await self._repository.platform_identity_by_id(
            token_context.platform_identity_id
        )
        if identity is None or identity.status != "ACTIVE":
            raise PlatformPermissionDenied("Platform identity is not active")
        if identity.token_version != token_context.token_version:
            raise PlatformPermissionDenied("Platform access token is stale")
        roles = await self._repository.platform_roles(identity.platform_identity_id, at=self._now())
        if not roles:
            raise PlatformPermissionDenied("Platform identity has no active role")
        return PlatformAccessContext(
            platform_identity_id=identity.platform_identity_id,
            roles=frozenset(roles),
            token_version=identity.token_version,
            expires_at=token_context.expires_at,
        )

    def _require_active_context(self, context: PlatformAccessContext) -> None:
        if context.expires_at <= self._now():
            raise PlatformPermissionDenied("Platform access token is expired")


class SensitiveAccessService:
    _DISCLOSE_ROLES = frozenset({PlatformRole.OWNER, PlatformRole.SUPPORT})

    def __init__(self, repository: AccessRepository, *, now: Any = None) -> None:
        self._repository = repository
        self._now = now or (lambda: datetime.now(UTC))

    def _require_context(self, context: PlatformAccessContext) -> None:
        if context.expires_at <= self._now() or not context.roles:
            raise PlatformPermissionDenied("Platform context is not active")

    async def list_tenants(
        self,
        context: PlatformAccessContext,
    ) -> tuple[MaskedTenantSummary, ...]:
        self._require_context(context)
        rows: list[MaskedTenantSummary] = []
        for tenant in await self._repository.list_tenants():
            account_count, license_count = await self._repository.tenant_access_counts(
                tenant.tenant_id
            )
            rows.append(
                MaskedTenantSummary(
                    tenant_id=tenant.tenant_id,
                    display_name=tenant.name,
                    active_account_count=account_count,
                    active_license_count=license_count,
                )
            )
        return tuple(rows)

    async def issue_grant(
        self,
        context: PlatformAccessContext,
        request: SensitiveAccessGrantRequest,
    ) -> SensitiveAccessGrantResponse:
        if context.expires_at <= self._now() or not context.roles:
            await self._append_denial(
                context=context,
                tenant_id=request.tenant_id,
                resource_id=None,
                reason="context_inactive",
                details=(
                    ("purpose_code", request.purpose_code),
                    ("ticket_reference", request.ticket_reference),
                ),
            )
            raise PlatformPermissionDenied("Platform context is not active")
        if not context.roles.intersection(self._DISCLOSE_ROLES):
            await self._append_denial(
                context=context,
                tenant_id=request.tenant_id,
                resource_id=None,
                reason="role_unauthorized",
                details=(
                    ("purpose_code", request.purpose_code),
                    ("ticket_reference", request.ticket_reference),
                ),
            )
            raise PlatformPermissionDenied("Platform role cannot disclose sensitive identity")
        now = self._now()
        record = SensitiveAccessGrantRecord(
            grant_id=uuid4(),
            tenant_id=request.tenant_id,
            platform_identity_id=context.platform_identity_id,
            purpose_code=request.purpose_code,
            ticket_reference=request.ticket_reference,
            issued_at=now,
            expires_at=now + timedelta(minutes=request.requested_duration_minutes),
        )
        await self._repository.create_sensitive_grant(record)
        await self._repository.append_audit(
            AuditEventRecord(
                event_id=uuid4(),
                actor_id=context.platform_identity_id,
                action="sensitive-access.grant",
                tenant_id=request.tenant_id,
                resource_id=record.grant_id,
                occurred_at=now,
                details=(
                    ("purpose_code", request.purpose_code),
                    ("ticket_reference", request.ticket_reference),
                ),
            )
        )
        return SensitiveAccessGrantResponse(
            grant_id=record.grant_id,
            tenant_id=record.tenant_id,
            purpose_code=record.purpose_code,
            ticket_reference=record.ticket_reference,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
        )

    async def read_identity(
        self,
        context: PlatformAccessContext,
        *,
        grant_id: UUID,
        tenant_id: UUID,
        subject_id: UUID,
        identity_loader: Callable[
            [],
            tuple[str | None, str | None] | Awaitable[tuple[str | None, str | None]],
        ],
        grant_observer: Callable[[SensitiveAccessGrantRecord], None] | None = None,
    ) -> SensitiveIdentityResponse:
        if context.expires_at <= self._now() or not context.roles:
            await self._append_denial(
                context=context,
                tenant_id=tenant_id,
                resource_id=subject_id,
                reason="context_inactive",
                details=(("grant_id", str(grant_id)),),
            )
            raise PlatformPermissionDenied("Platform context is not active")
        if not context.roles.intersection(self._DISCLOSE_ROLES):
            await self._append_denial(
                context=context,
                tenant_id=tenant_id,
                resource_id=subject_id,
                reason="role_unauthorized",
                details=(("grant_id", str(grant_id)),),
            )
            raise PlatformPermissionDenied("Platform role cannot disclose sensitive identity")
        now = self._now()
        try:
            grant = await self._repository.use_sensitive_grant(
                grant_id=grant_id,
                tenant_id=tenant_id,
                platform_identity_id=context.platform_identity_id,
                used_at=now,
            )
        except AccessRepositoryConflict as exc:
            await self._append_denial(
                context=context,
                tenant_id=tenant_id,
                resource_id=grant_id,
                reason="grant_invalid",
                details=(("grant_id", str(grant_id)),),
            )
            raise PlatformPermissionDenied("sensitive access grant is invalid") from exc
        if grant_observer is not None:
            grant_observer(grant)
        try:
            identity = identity_loader()
            if inspect.isawaitable(identity):
                identity = await identity
        except Exception:
            await self._append_denial(
                context=context,
                tenant_id=tenant_id,
                resource_id=subject_id,
                reason="identity_load_failed",
                details=(("grant_id", str(grant_id)),),
            )
            raise
        display_name, contact = identity
        response = SensitiveIdentityResponse(
            grant_id=grant.grant_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            display_name=display_name,
            contact=contact,
            disclosed_at=now,
        )
        await self._repository.append_audit(
            AuditEventRecord(
                event_id=uuid4(),
                actor_id=context.platform_identity_id,
                action="sensitive-access.use",
                tenant_id=tenant_id,
                resource_id=subject_id,
                occurred_at=now,
                details=(
                    ("grant_id", str(grant_id)),
                    ("purpose_code", grant.purpose_code),
                    ("ticket_reference", grant.ticket_reference),
                ),
            )
        )
        return response

    async def _append_denial(
        self,
        *,
        context: PlatformAccessContext,
        tenant_id: UUID | None,
        resource_id: UUID | None,
        reason: str,
        details: tuple[tuple[str, str], ...] = (),
    ) -> None:
        await self._repository.append_audit(
            AuditEventRecord(
                event_id=uuid4(),
                actor_id=context.platform_identity_id,
                action="sensitive-access.deny",
                tenant_id=tenant_id,
                resource_id=resource_id,
                occurred_at=self._now(),
                details=(("reason", reason), *details),
            )
        )


__all__ = [
    "PlatformIdentityService",
    "PlatformPermissionDenied",
    "SensitiveAccessService",
]
