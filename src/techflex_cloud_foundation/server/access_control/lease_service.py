"""Short-lived online lease for one License-bound physical hardware device."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.access_control import (
    HardwareLeaseRequest,
    HardwareLeaseResponse,
    LicenseState,
)
from techflex_cloud_foundation.platform_errors import PlatformError
from techflex_cloud_foundation.server.access_auth import TenantAccessContext

from .repository import (
    AccessRepository,
    AccessRepositoryConflict,
    AccessRepositoryError,
    HardwareLeaseRecord,
)


class HardwareLeaseConflict(PlatformError):
    code = "E-LSE-409"
    http_status = 409
    action = "RETRY_AFTER_LEASE_EXPIRY"


class HardwareLeaseService:
    _TTL = timedelta(minutes=10)

    def __init__(self, repository: AccessRepository, *, now: Any = None) -> None:
        self._repository = repository
        self._now = now or (lambda: datetime.now(UTC))

    async def acquire(
        self,
        context: TenantAccessContext,
        request: HardwareLeaseRequest,
    ) -> HardwareLeaseResponse:
        now = self._now()
        if (
            context.expires_at <= now
            or not context.capabilities.allow_new_test
            or request.hardware_id != context.hardware_id
            or request.client_installation_id != context.client_installation_id
        ):
            raise HardwareLeaseConflict("hardware lease authorization does not match")
        try:
            hardware = await self._repository.hardware_by_identity(request.hardware_id)
            if hardware is None:
                raise HardwareLeaseConflict("hardware lease authorization does not match")
            group = await self._repository.access_group_for_license(context.license_id)
            license_record = await self._repository.license(context.license_id)
        except AccessRepositoryError as exc:
            raise HardwareLeaseConflict("hardware lease authorization does not match") from exc
        if (
            group.tenant_id != context.tenant_id
            or group.account_id != context.account_id
            or group.hardware_id != hardware.hardware_id
            or license_record.status is not LicenseState.ACTIVE
            or not (license_record.valid_from <= now < license_record.valid_until)
        ):
            raise HardwareLeaseConflict("hardware lease authorization does not match")
        lease = HardwareLeaseRecord(
            lease_id=uuid4(),
            tenant_id=context.tenant_id,
            license_id=context.license_id,
            account_id=context.account_id,
            hardware_id=hardware.hardware_id,
            client_installation_id=context.client_installation_id,
            acquired_at=now,
            renewed_at=now,
            expires_at=now + self._TTL,
        )
        try:
            stored = await self._repository.acquire_hardware_lease(
                lease,
                acquired_at=now,
            )
        except AccessRepositoryConflict as exc:
            raise HardwareLeaseConflict("hardware is already in use") from exc
        return self._response(stored, hardware.stable_identity)

    async def renew(
        self,
        context: TenantAccessContext,
        lease_id: UUID,
    ) -> HardwareLeaseResponse:
        now = self._now()
        if context.expires_at <= now or not context.capabilities.allow_new_test:
            raise HardwareLeaseConflict("hardware lease authorization does not match")
        try:
            stored = await self._repository.renew_hardware_lease(
                lease_id=lease_id,
                tenant_id=context.tenant_id,
                account_id=context.account_id,
                license_id=context.license_id,
                installation_id=context.client_installation_id,
                renewed_at=now,
                expires_at=now + self._TTL,
            )
        except AccessRepositoryConflict as exc:
            raise HardwareLeaseConflict("hardware lease cannot be renewed") from exc
        hardware = await self._repository.hardware(stored.hardware_id)
        return self._response(stored, hardware.stable_identity)

    async def release(
        self,
        context: TenantAccessContext,
        lease_id: UUID,
    ) -> None:
        try:
            await self._repository.release_hardware_lease(
                lease_id=lease_id,
                tenant_id=context.tenant_id,
                account_id=context.account_id,
                license_id=context.license_id,
                installation_id=context.client_installation_id,
                released_at=self._now(),
                reason="CLIENT_RELEASED",
            )
        except AccessRepositoryConflict as exc:
            raise HardwareLeaseConflict("hardware lease cannot be released") from exc

    @staticmethod
    def _response(
        record: HardwareLeaseRecord,
        hardware_identity: str,
    ) -> HardwareLeaseResponse:
        return HardwareLeaseResponse(
            lease_id=record.lease_id,
            hardware_id=hardware_identity,
            client_installation_id=record.client_installation_id,
            acquired_at=record.acquired_at,
            expires_at=record.expires_at,
        )


__all__ = ["HardwareLeaseConflict", "HardwareLeaseService"]
