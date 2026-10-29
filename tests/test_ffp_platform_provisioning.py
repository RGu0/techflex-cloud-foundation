from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from techflex_cloud_foundation.contracts.access_control import (
    LicenseControlAction,
    LicenseControlRequest,
    LicenseState,
    PlatformRole,
    ProvisionTenantRequest,
)
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessContext,
)
from techflex_cloud_foundation.server.access_control.platform_service import (
    PlatformAuthorizationDenied,
    PlatformProvisioningService,
)
from techflex_cloud_foundation.server.access_control.repository import InMemoryAccessRepository

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def _context(*roles: PlatformRole) -> PlatformAccessContext:
    return PlatformAccessContext(
        platform_identity_id=uuid4(),
        roles=frozenset(roles),
        token_version=1,
        expires_at=NOW + timedelta(minutes=15),
    )


def _service(repository: InMemoryAccessRepository) -> PlatformProvisioningService:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return PlatformProvisioningService(
        repository,
        login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
        activation_hmac_key=b"activation-key-must-contain-at-least-32-bytes",
        license_signer=LicenseDocumentSigner(
            private_key=private_key,
            key_id="license/2-key-1",
            public_keys={"license/2-key-1": public_key},
        ),
        now=lambda: NOW,
    )


def _request(account: str = "seed-clinic", hardware_suffix: int = 1) -> ProvisionTenantRequest:
    return ProvisionTenantRequest(
        tenant_name="Seed Clinic",
        account_name=account,
        hardware_id=f"usb-serial-{hardware_suffix:020x}",
        license_period_months=12,
    )


def test_operations_provisions_atomic_bundle_and_returns_code_once() -> None:
    async def exercise() -> None:
        repository = InMemoryAccessRepository()
        service = _service(repository)

        issued = await service.provision_tenant(
            _context(PlatformRole.OPERATIONS),
            _request(),
        )

        assert issued.license_period_months == 12
        assert issued.activation_expires_at == NOW + timedelta(days=7)
        assert not await repository.activation_storage_contains(issued.activation_code)
        history = await repository.access_group_history(issued.tenant_id)
        assert len(history) == 1
        events = await repository.audit_events(tenant_id=issued.tenant_id)
        assert [event.action for event in events] == ["tenant.provision"]

    asyncio.run(exercise())


def test_support_and_engineer_cannot_provision_or_control_license() -> None:
    async def exercise() -> None:
        service = _service(InMemoryAccessRepository())
        for role in (PlatformRole.SUPPORT, PlatformRole.ENGINEER):
            with pytest.raises(PlatformAuthorizationDenied):
                await service.provision_tenant(_context(role), _request())

    asyncio.run(exercise())


def test_duplicate_account_or_hardware_has_no_partial_second_tenant() -> None:
    async def exercise() -> None:
        repository = InMemoryAccessRepository()
        service = _service(repository)
        operator = _context(PlatformRole.OWNER)
        first = await service.provision_tenant(operator, _request())

        with pytest.raises(ValueError, match="account"):
            await service.provision_tenant(
                operator,
                ProvisionTenantRequest(
                    tenant_name="Other Clinic",
                    account_name="seed-clinic",
                    hardware_id="usb-serial-00000000000000000002",
                    license_period_months=6,
                ),
            )

        assert len(await repository.access_group_history(first.tenant_id)) == 1

    asyncio.run(exercise())


def test_license_renew_suspend_restore_and_revoke_create_signed_versions() -> None:
    async def exercise() -> None:
        repository = InMemoryAccessRepository()
        service = _service(repository)
        operator = _context(PlatformRole.OPERATIONS)
        issued = await service.provision_tenant(operator, _request())
        await repository.activate_account_atomically(
            login_name_hmac=hmac.new(
                b"login-lookup-key-must-contain-32-bytes",
                b"seed-clinic",
                hashlib.sha256,
            ).digest(),
            activation_code_hash=hmac.new(
                b"activation-key-must-contain-at-least-32-bytes",
                issued.activation_code.encode(),
                hashlib.sha256,
            ).digest(),
            hardware_identity=issued.hardware_id,
            password_hash="$ffp-scrypt$test",
            installation_id=uuid4(),
            activated_at=NOW,
        )

        renewed = await service.control_license(
            operator,
            issued.license_id,
            LicenseControlRequest(
                action=LicenseControlAction.RENEW,
                valid_until=NOW + timedelta(days=730),
            ),
        )
        suspended = await service.control_license(
            operator,
            issued.license_id,
            LicenseControlRequest(
                action=LicenseControlAction.SUSPEND,
                reason_code="CUSTOMER_REQUEST",
            ),
        )
        restored = await service.control_license(
            operator,
            issued.license_id,
            LicenseControlRequest(action=LicenseControlAction.RESTORE),
        )
        revoked = await service.control_license(
            operator,
            issued.license_id,
            LicenseControlRequest(
                action=LicenseControlAction.REVOKE,
                reason_code="CONTRACT_ENDED",
            ),
        )

        assert [
            renewed.signed_license.document.version,
            suspended.signed_license.document.version,
            restored.signed_license.document.version,
            revoked.signed_license.document.version,
        ] == [2, 3, 4, 5]
        assert suspended.signed_license.document.status is LicenseState.SUSPENDED
        assert restored.signed_license.document.status is LicenseState.ACTIVE
        assert revoked.signed_license.document.status is LicenseState.REVOKED
        assert [event.action for event in await repository.audit_events(tenant_id=issued.tenant_id)] == [
            "tenant.provision",
            "license.renew",
            "license.suspend",
            "license.restore",
            "license.revoke",
        ]

    asyncio.run(exercise())


def test_existing_tenant_can_expand_to_three_and_contract_to_two() -> None:
    async def exercise() -> None:
        repository = InMemoryAccessRepository()
        service = _service(repository)
        operator = _context(PlatformRole.OWNER)
        first = await service.provision_tenant(operator, _request())
        second = await service.add_tenant_access_group(
            operator, first.tenant_id, _request("seed-clinic-2", 2)
        )
        third = await service.add_tenant_access_group(
            operator, first.tenant_id, _request("seed-clinic-3", 3)
        )
        assert len(await repository.active_access_groups(first.tenant_id)) == 3

        await service.reduce_tenant_access_group(
            operator,
            tenant_id=first.tenant_id,
            license_id=third.license_id,
            reason_code="SEED_CAPACITY_REDUCED",
        )

        assert second.tenant_id == first.tenant_id
        assert len(await repository.active_access_groups(first.tenant_id)) == 2
        assert len(await repository.access_group_history(first.tenant_id)) == 3

    asyncio.run(exercise())
