from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.access_control import (
    AccessCapabilities,
    HardwareLeaseRequest,
)
from techflex_cloud_foundation.server.access_auth import TenantAccessContext
from techflex_cloud_foundation.server.access_control.lease_service import (
    HardwareLeaseConflict,
    HardwareLeaseService,
)
from techflex_cloud_foundation.server.access_control.repository import (
    AccessGroupSeed,
    InMemoryAccessRepository,
    TenantSeed,
)

START = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
HARDWARE_IDENTITY = "usb-serial-0123456789abcdef0123"


@dataclass
class MutableClock:
    value: datetime = START

    def __call__(self) -> datetime:
        return self.value


async def _setup():
    repository = InMemoryAccessRepository()
    tenant_id = uuid4()
    account_id = uuid4()
    license_id = uuid4()
    hardware_id = uuid4()
    installation_id = uuid4()
    group = AccessGroupSeed(
        account_id=account_id,
        login_name_hmac=b"a" * 32,
        account_display_name="seed-clinic",
        license_id=license_id,
        hardware_id=hardware_id,
        hardware_identity=HARDWARE_IDENTITY,
        hardware_model="DO-P4864",
        activation_code_id=uuid4(),
        activation_code_hash=b"b" * 32,
        activation_expires_at=START + timedelta(days=1),
        license_valid_from=START,
        license_valid_until=START + timedelta(days=365),
        enabled_features=("screening.start",),
    )
    await repository.provision_tenant(
        TenantSeed(tenant_id=tenant_id, name="Seed Clinic"),
        group,
        created_at=START,
    )
    await repository.activate_account_atomically(
        login_name_hmac=group.login_name_hmac,
        activation_code_hash=group.activation_code_hash,
        hardware_identity=group.hardware_identity,
        password_hash="$ffp-scrypt$test",
        installation_id=installation_id,
        activated_at=START,
    )
    context = TenantAccessContext(
        tenant_id=tenant_id,
        account_id=account_id,
        license_id=license_id,
        hardware_id=HARDWARE_IDENTITY,
        client_installation_id=installation_id,
        token_version=1,
        capabilities=AccessCapabilities(
            allow_new_test=True,
            allow_upload=True,
            allow_report_view=True,
        ),
        expires_at=START + timedelta(minutes=15),
    )
    return repository, context


def test_acquire_renew_release_and_takeover_after_release() -> None:
    async def exercise() -> None:
        repository, context = await _setup()
        clock = MutableClock()
        service = HardwareLeaseService(repository, now=clock)
        request = HardwareLeaseRequest(
            hardware_id=HARDWARE_IDENTITY,
            client_installation_id=context.client_installation_id,
        )

        acquired = await service.acquire(context, request)
        assert acquired.expires_at == START + timedelta(minutes=10)
        clock.value += timedelta(minutes=5)
        renewed = await service.renew(context, acquired.lease_id)
        assert renewed.lease_id == acquired.lease_id
        assert renewed.expires_at == clock.value + timedelta(minutes=10)
        await service.release(context, acquired.lease_id)

        replacement_installation = uuid4()
        await repository.register_or_touch_installation(
            tenant_id=context.tenant_id,
            account_id=context.account_id,
            installation_id=replacement_installation,
            seen_at=clock.value,
        )
        replacement_context = replace(
            context,
            client_installation_id=replacement_installation,
            expires_at=clock.value + timedelta(minutes=15),
        )
        replacement = await service.acquire(
            replacement_context,
            HardwareLeaseRequest(
                hardware_id=HARDWARE_IDENTITY,
                client_installation_id=replacement_installation,
            ),
        )
        assert replacement.client_installation_id == replacement_installation

    asyncio.run(exercise())


def test_second_installation_is_rejected_until_ttl_expires() -> None:
    async def exercise() -> None:
        repository, context = await _setup()
        clock = MutableClock()
        service = HardwareLeaseService(repository, now=clock)
        await service.acquire(
            context,
            HardwareLeaseRequest(
                hardware_id=HARDWARE_IDENTITY,
                client_installation_id=context.client_installation_id,
            ),
        )
        second_installation = uuid4()
        await repository.register_or_touch_installation(
            tenant_id=context.tenant_id,
            account_id=context.account_id,
            installation_id=second_installation,
            seen_at=clock.value,
        )
        second = replace(
            context,
            client_installation_id=second_installation,
            expires_at=clock.value + timedelta(minutes=15),
        )
        request = HardwareLeaseRequest(
            hardware_id=HARDWARE_IDENTITY,
            client_installation_id=second_installation,
        )

        with pytest.raises(HardwareLeaseConflict):
            await service.acquire(second, request)
        assert second.capabilities.allow_upload
        assert second.capabilities.allow_report_view

        clock.value += timedelta(minutes=10, seconds=1)
        acquired = await service.acquire(second, request)
        assert acquired.client_installation_id == second_installation

    asyncio.run(exercise())


def test_context_must_match_license_hardware_and_installation() -> None:
    async def exercise() -> None:
        repository, context = await _setup()
        service = HardwareLeaseService(repository, now=MutableClock())

        for invalid in (
            replace(context, hardware_id="usb-serial-ffffffffffffffffffff"),
            replace(context, license_id=uuid4()),
            replace(context, account_id=uuid4()),
        ):
            with pytest.raises(HardwareLeaseConflict):
                await service.acquire(
                    invalid,
                    HardwareLeaseRequest(
                        hardware_id=invalid.hardware_id,
                        client_installation_id=invalid.client_installation_id,
                    ),
                )

    asyncio.run(exercise())
