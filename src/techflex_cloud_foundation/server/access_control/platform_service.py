"""Provider-operated tenant provisioning and remote License lifecycle control."""

from __future__ import annotations

import calendar
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import secrets
from typing import Any
import unicodedata
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.access_control import (
    LicenseControlAction,
    LicenseControlRequest,
    LicenseControlResponse,
    LicenseDocumentV2,
    LicenseState,
    PlatformRole,
    ProvisionTenantRequest,
    ProvisionTenantResponse,
)
from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.platform_errors import PlatformError
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessContext,
)

from .repository import (
    AccessGroupSeed,
    AccessRepository,
    AuditEventRecord,
    TenantSeed,
)


class PlatformAuthorizationDenied(PlatformError):
    """Platform identity lacks the explicit role for a provider operation."""

    code = "E-PLT-403"
    http_status = 403
    action = "CONTACT_PLATFORM_OWNER"


def normalize_login_name(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().lower()


def _add_months(value: datetime, months: int) -> datetime:
    target_month = value.month - 1 + months
    target_year = value.year + target_month // 12
    month = target_month % 12 + 1
    day = min(value.day, calendar.monthrange(target_year, month)[1])
    return value.replace(year=target_year, month=month, day=day)


class PlatformProvisioningService:
    _WRITE_ROLES = frozenset({PlatformRole.OWNER, PlatformRole.OPERATIONS})

    def __init__(
        self,
        repository: AccessRepository,
        *,
        login_lookup_hmac_key: bytes,
        activation_hmac_key: bytes,
        license_signer: LicenseDocumentSigner,
        now: Any = None,
    ) -> None:
        if len(login_lookup_hmac_key) < 32:
            raise ValueError("login lookup key must contain at least 32 bytes")
        if len(activation_hmac_key) < 32:
            raise ValueError("activation key must contain at least 32 bytes")
        self._repository = repository
        self._login_lookup_hmac_key = login_lookup_hmac_key
        self._activation_hmac_key = activation_hmac_key
        self._license_signer = license_signer
        self._now = now or (lambda: datetime.now(UTC))

    @staticmethod
    def _require_write_role(context: PlatformAccessContext) -> None:
        if not context.roles.intersection(PlatformProvisioningService._WRITE_ROLES):
            raise PlatformAuthorizationDenied("platform role cannot manage tenant access")

    def _lookup_digest(self, account_name: str) -> bytes:
        normalized = normalize_login_name(account_name)
        return hmac.new(
            self._login_lookup_hmac_key,
            normalized.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    def _activation_digest(self, activation_code: str) -> bytes:
        return hmac.new(
            self._activation_hmac_key,
            activation_code.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    def _make_group(
        self,
        request: ProvisionTenantRequest,
        *,
        created_at: datetime,
    ) -> tuple[AccessGroupSeed, str]:
        activation_code = secrets.token_urlsafe(32)
        seed = AccessGroupSeed(
            account_id=uuid4(),
            login_name_hmac=self._lookup_digest(request.account_name),
            account_display_name=normalize_login_name(request.account_name),
            license_id=uuid4(),
            hardware_id=uuid4(),
            hardware_identity=request.hardware_id,
            hardware_model="DO-P4864",
            activation_code_id=uuid4(),
            activation_code_hash=self._activation_digest(activation_code),
            activation_expires_at=created_at + timedelta(days=7),
            license_valid_from=created_at,
            license_valid_until=_add_months(created_at, request.license_period_months),
            enabled_features=request.enabled_features,
        )
        return seed, activation_code

    @staticmethod
    def _response(
        *,
        tenant_id: UUID,
        request: ProvisionTenantRequest,
        seed: AccessGroupSeed,
        activation_code: str,
    ) -> ProvisionTenantResponse:
        return ProvisionTenantResponse(
            tenant_id=tenant_id,
            account_id=seed.account_id,
            license_id=seed.license_id,
            hardware_id=seed.hardware_identity,
            account_name=request.account_name,
            activation_code=activation_code,
            activation_expires_at=seed.activation_expires_at,
            license_period_months=request.license_period_months,
        )

    async def provision_tenant(
        self,
        context: PlatformAccessContext,
        request: ProvisionTenantRequest,
    ) -> ProvisionTenantResponse:
        self._require_write_role(context)
        now = self._now()
        tenant_id = uuid4()
        seed, activation_code = self._make_group(request, created_at=now)
        await self._repository.provision_tenant(
            TenantSeed(tenant_id=tenant_id, name=request.tenant_name),
            seed,
            created_at=now,
        )
        await self._audit(
            context,
            action="tenant.provision",
            tenant_id=tenant_id,
            resource_id=seed.license_id,
            occurred_at=now,
            details={"license_period_months": str(request.license_period_months)},
        )
        return self._response(
            tenant_id=tenant_id,
            request=request,
            seed=seed,
            activation_code=activation_code,
        )

    async def add_tenant_access_group(
        self,
        context: PlatformAccessContext,
        tenant_id: UUID,
        request: ProvisionTenantRequest,
    ) -> ProvisionTenantResponse:
        self._require_write_role(context)
        tenant = await self._repository.tenant(tenant_id)
        if tenant.name != request.tenant_name:
            raise ValueError("tenant name does not match the existing tenant")
        now = self._now()
        seed, activation_code = self._make_group(request, created_at=now)
        await self._repository.add_access_group(tenant_id, seed, created_at=now)
        await self._audit(
            context,
            action="tenant.access-group.add",
            tenant_id=tenant_id,
            resource_id=seed.license_id,
            occurred_at=now,
            details={"license_period_months": str(request.license_period_months)},
        )
        return self._response(
            tenant_id=tenant_id,
            request=request,
            seed=seed,
            activation_code=activation_code,
        )

    async def reduce_tenant_access_group(
        self,
        context: PlatformAccessContext,
        *,
        tenant_id: UUID,
        license_id: UUID,
        reason_code: str,
    ) -> UUID:
        self._require_write_role(context)
        group = await self._repository.access_group_for_license(license_id)
        if group.tenant_id != tenant_id:
            raise PlatformAuthorizationDenied("license is not in the target tenant")
        now = self._now()
        closed_at = max(now, group.assigned_at + timedelta(microseconds=1))
        result = await self._repository.close_access_group(
            tenant_id=tenant_id,
            license_id=license_id,
            closed_at=closed_at,
            reason_code=reason_code,
        )
        await self._audit(
            context,
            action="tenant.access-group.reduce",
            tenant_id=tenant_id,
            resource_id=license_id,
            occurred_at=closed_at,
            details={"reason_code": reason_code},
        )
        return result

    async def control_license(
        self,
        context: PlatformAccessContext,
        license_id: UUID,
        request: LicenseControlRequest,
    ) -> LicenseControlResponse:
        self._require_write_role(context)
        current = await self._repository.license(license_id)
        if current.status is LicenseState.PENDING_ACTIVATION:
            raise ValueError("pending License cannot be remotely controlled")
        if current.status is LicenseState.REVOKED:
            raise ValueError("revoked License is terminal")

        status: LicenseState = current.status
        valid_until = current.valid_until
        if request.action is LicenseControlAction.RENEW:
            assert request.valid_until is not None
            if request.valid_until <= current.valid_until:
                raise ValueError("renewal must extend valid_until")
            valid_until = request.valid_until
        elif request.action is LicenseControlAction.SUSPEND:
            if current.status is not LicenseState.ACTIVE:
                raise ValueError("only active License can be suspended")
            status = LicenseState.SUSPENDED
        elif request.action is LicenseControlAction.RESTORE:
            if current.status is not LicenseState.SUSPENDED:
                raise ValueError("only suspended License can be restored")
            status = LicenseState.ACTIVE
        elif request.action is LicenseControlAction.REVOKE:
            status = LicenseState.REVOKED

        group = await self._repository.access_group_for_license(license_id)
        account = await self._repository.account(group.account_id)
        hardware = await self._repository.hardware(group.hardware_id)
        now = self._now()
        document = LicenseDocumentV2(
            tenant_id=current.tenant_id,
            account_id=account.account_id,
            license_id=current.license_id,
            hardware_id=hardware.stable_identity,
            status=status,
            issued_at=now,
            valid_from=current.valid_from,
            valid_until=valid_until,
            version=current.version + 1,
            enabled_features=current.enabled_features,
        )
        signed = self._license_signer.sign(document)
        await self._repository.replace_license(
            license_id=license_id,
            expected_version=current.version,
            status=status,
            issued_at=now,
            valid_until=valid_until,
            key_id=signed.key_id,
            document_json=canonical_json_bytes(document).decode("utf-8"),
            signature=signed.signature,
        )
        await self._audit(
            context,
            action=f"license.{request.action.value.lower()}",
            tenant_id=current.tenant_id,
            resource_id=license_id,
            occurred_at=now,
            details={
                "reason_code": request.reason_code or "",
                "license_version": str(document.version),
            },
        )
        return LicenseControlResponse(signed_license=signed, changed_at=now)

    async def set_terminal_seats(
        self,
        context: PlatformAccessContext,
        license_id: UUID,
        seats: int,
    ) -> Any:
        """Set the RAY-656 terminal seat limit carried by signed terminal Licenses.

        Lowering the limit below the active count blocks new activations only;
        already active terminals keep their seats until revoked.
        """
        self._require_write_role(context)
        if not 0 <= seats <= 1000:
            raise ValueError("terminal seats must be between 0 and 1000")
        current = await self._repository.license(license_id)
        now = self._now()
        updated = await self._repository.set_terminal_seats(
            license_id=license_id, seats=seats, changed_at=now
        )
        await self._audit(
            context,
            action="license.terminal_seats",
            tenant_id=current.tenant_id,
            resource_id=license_id,
            occurred_at=now,
            details={
                "previous_seats": str(current.terminal_seats),
                "terminal_seats": str(seats),
            },
        )
        return updated

    async def list_terminals(self, context: PlatformAccessContext, license_id: UUID) -> Any:
        """RAY-656 operations view of one License's terminals (write role only)."""
        self._require_write_role(context)
        group = await self._repository.access_group_for_license(license_id)
        rows = await self._repository.terminals_for_account(
            tenant_id=group.tenant_id, account_id=group.account_id
        )
        return tuple(row for row in rows if row.license_id == license_id)

    async def revoke_terminal(
        self,
        context: PlatformAccessContext,
        client_installation_id: UUID,
        *,
        reason_code: str,
    ) -> Any:
        """Free a seat held by a lost, reinstalled or expired terminal."""
        self._require_write_role(context)
        reason_code = reason_code.strip()
        if not 0 < len(reason_code) <= 64:
            raise ValueError("terminal revoke requires a reason_code")
        terminal = await self._repository.terminal(client_installation_id)
        if terminal is None:
            raise ValueError("terminal does not exist")
        now = self._now()
        revoked = await self._repository.revoke_terminal(
            tenant_id=terminal.tenant_id,
            account_id=terminal.account_id,
            client_installation_id=client_installation_id,
            revoked_at=now,
        )
        await self._audit(
            context,
            action="terminal.revoke",
            tenant_id=terminal.tenant_id,
            resource_id=client_installation_id,
            occurred_at=now,
            details={"reason_code": reason_code, "license_id": str(terminal.license_id)},
        )
        return revoked

    async def _audit(
        self,
        context: PlatformAccessContext,
        *,
        action: str,
        tenant_id: UUID | None,
        resource_id: UUID | None,
        occurred_at: datetime,
        details: dict[str, str],
    ) -> None:
        await self._repository.append_audit(
            AuditEventRecord(
                event_id=uuid4(),
                actor_id=context.platform_identity_id,
                action=action,
                tenant_id=tenant_id,
                resource_id=resource_id,
                occurred_at=occurred_at,
                details=tuple(sorted(details.items())),
            )
        )


__all__ = [
    "PlatformAuthorizationDenied",
    "PlatformProvisioningService",
    "normalize_login_name",
]
