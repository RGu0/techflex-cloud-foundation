from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.access_control import AccountState, LicenseState
from techflex_cloud_foundation.server.access_control.repository import (
    AccessActivationRejected,
    AccessGroupSeed,
    InMemoryAccessRepository,
    TenantSeed,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def _group(index: int) -> AccessGroupSeed:
    suffix = f"{index:020x}"
    return AccessGroupSeed(
        account_id=uuid4(),
        login_name_hmac=bytes([index]) * 32,
        account_display_name=f"seed-{index}",
        license_id=uuid4(),
        hardware_id=uuid4(),
        hardware_identity=f"usb-serial-{suffix}",
        hardware_model="DO-P4864",
        activation_code_id=uuid4(),
        activation_code_hash=bytes([index + 10]) * 32,
        activation_expires_at=NOW + timedelta(days=7),
        license_valid_from=NOW,
        license_valid_until=NOW + timedelta(days=365),
        enabled_features=("reports.view", "screening.start", "sync.upload"),
    )


def test_tenant_grows_one_to_three_then_reduces_to_two_without_data_move() -> None:
    async def exercise() -> None:
        repository = InMemoryAccessRepository()
        tenant = TenantSeed(tenant_id=uuid4(), name="Dynamic Clinic")
        groups = [_group(index) for index in (1, 2, 3)]

        await repository.provision_tenant(tenant, groups[0], created_at=NOW)
        await repository.add_access_group(tenant.tenant_id, groups[1], created_at=NOW)
        await repository.add_access_group(tenant.tenant_id, groups[2], created_at=NOW)

        assert len(await repository.active_access_groups(tenant.tenant_id)) == 3
        closed = await repository.close_access_group(
            tenant_id=tenant.tenant_id,
            license_id=groups[2].license_id,
            closed_at=NOW + timedelta(days=30),
            reason_code="SEED_CAPACITY_REDUCED",
        )

        assert closed == groups[2].license_id
        assert len(await repository.active_access_groups(tenant.tenant_id)) == 2
        history = await repository.access_group_history(tenant.tenant_id)
        assert {row.license_id for row in history} == {group.license_id for group in groups}
        assert all(row.tenant_id == tenant.tenant_id for row in history)
        assert sum(row.closed_at is not None for row in history) == 1
        assert (await repository.license(groups[2].license_id)).status is LicenseState.REVOKED
        with pytest.raises(AccessActivationRejected):
            await repository.activate_account_atomically(
                login_name_hmac=groups[2].login_name_hmac,
                activation_code_hash=groups[2].activation_code_hash,
                hardware_identity=groups[2].hardware_identity,
                password_hash="$ffp-scrypt$closed",
                installation_id=uuid4(),
                activated_at=NOW + timedelta(days=31),
            )

    asyncio.run(exercise())


def test_activation_is_atomic_and_exactly_one_concurrent_consumer_wins() -> None:
    async def exercise() -> None:
        repository = InMemoryAccessRepository()
        tenant = TenantSeed(tenant_id=uuid4(), name="Activation Clinic")
        group = _group(4)
        await repository.provision_tenant(tenant, group, created_at=NOW)

        async def activate():
            return await repository.activate_account_atomically(
                login_name_hmac=group.login_name_hmac,
                activation_code_hash=group.activation_code_hash,
                hardware_identity=group.hardware_identity,
                password_hash="$ffp-scrypt$test",
                installation_id=uuid4(),
                activated_at=NOW + timedelta(minutes=1),
            )

        results = await asyncio.gather(activate(), activate(), return_exceptions=True)

        successes = [result for result in results if not isinstance(result, Exception)]
        failures = [result for result in results if isinstance(result, Exception)]
        assert len(successes) == 1
        assert len(failures) == 1
        assert isinstance(failures[0], AccessActivationRejected)
        activated = successes[0]
        assert activated.account.status is AccountState.ACTIVE
        assert activated.license.status is LicenseState.ACTIVE
        assert activated.activation_code.consumed_at == NOW + timedelta(minutes=1)

    asyncio.run(exercise())


def test_failed_activation_changes_nothing_and_does_not_consume_code() -> None:
    async def exercise() -> None:
        repository = InMemoryAccessRepository()
        tenant = TenantSeed(tenant_id=uuid4(), name="Rollback Clinic")
        group = _group(5)
        await repository.provision_tenant(tenant, group, created_at=NOW)

        with pytest.raises(AccessActivationRejected):
            await repository.activate_account_atomically(
                login_name_hmac=group.login_name_hmac,
                activation_code_hash=group.activation_code_hash,
                hardware_identity="usb-serial-ffffffffffffffffffff",
                password_hash="$ffp-scrypt$test",
                installation_id=uuid4(),
                activated_at=NOW + timedelta(minutes=1),
            )

        account = await repository.account_by_login_hmac(group.login_name_hmac)
        activation = await repository.activation_code(group.activation_code_id)
        license_record = await repository.license(group.license_id)
        assert account is not None and account.status is AccountState.PENDING_ACTIVATION
        assert account.password_hash is None
        assert activation is not None and activation.consumed_at is None
        assert license_record.status is LicenseState.PENDING_ACTIVATION

    asyncio.run(exercise())


def test_duplicate_account_or_hardware_rolls_back_entire_group() -> None:
    async def exercise() -> None:
        repository = InMemoryAccessRepository()
        tenant = TenantSeed(tenant_id=uuid4(), name="Duplicate Clinic")
        first = _group(6)
        duplicate = replace(_group(7), login_name_hmac=first.login_name_hmac)
        await repository.provision_tenant(tenant, first, created_at=NOW)

        with pytest.raises(ValueError, match="account"):
            await repository.add_access_group(tenant.tenant_id, duplicate, created_at=NOW)

        assert len(await repository.access_group_history(tenant.tenant_id)) == 1

    asyncio.run(exercise())
