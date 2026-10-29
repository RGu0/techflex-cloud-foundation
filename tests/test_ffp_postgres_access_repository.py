from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.access_control import LicenseState, PlatformRole
from techflex_cloud_foundation.server.access_control.postgres import PostgresAccessRepository
from techflex_cloud_foundation.server.access_control.repository import (
    AccessActivationRejected,
    AccessGroupSeed,
    HardwareLeaseRecord,
    PlatformIdentityRecord,
    PlatformRoleBindingRecord,
    SensitiveAccessGrantRecord,
    TenantSeed,
)
from tests.pg_platform import live_environment

live_environment()

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def _group(index: int, *, run_nonce: bytes = b"") -> AccessGroupSeed:
    seed = hashlib.sha256(run_nonce + index.to_bytes(4, "big")).digest()
    return AccessGroupSeed(
        account_id=uuid4(), login_name_hmac=hashlib.sha256(b"login" + seed).digest(),
        account_display_name=f"pg-seed-{index}-{seed.hex()[:8]}", license_id=uuid4(),
        hardware_id=uuid4(),
        hardware_identity=f"usb-serial-{hashlib.sha256(b'hardware' + seed).hexdigest()[:20]}",
        hardware_model="DO-P4864", activation_code_id=uuid4(),
        activation_code_hash=hashlib.sha256(b"activation" + seed).digest(),
        activation_expires_at=NOW + timedelta(days=7), license_valid_from=NOW,
        license_valid_until=NOW + timedelta(days=365),
        enabled_features=("reports.view", "screening.start", "sync.upload"),
    )


def test_live_group_identifiers_are_unique_between_acceptance_runs() -> None:
    first = _group(11, run_nonce=b"first-acceptance-run")
    second = _group(11, run_nonce=b"second-acceptance-run")

    assert first.login_name_hmac != second.login_name_hmac
    assert first.activation_code_hash != second.activation_code_hash
    assert first.hardware_identity != second.hardware_identity


def test_constructor_requires_three_explicit_pools() -> None:
    marker = object()
    repository = PostgresAccessRepository(
        tenant_pool=marker, activation_pool=marker, platform_pool=marker
    )
    assert repository._tenant_pool is marker
    with pytest.raises(ValueError, match="required"):
        PostgresAccessRepository(tenant_pool=marker, activation_pool=None, platform_pool=marker)


def test_adapter_and_migration_encode_locking_routing_and_least_privilege() -> None:
    source = (ROOT / "src/techflex_cloud_foundation/server/access_control/postgres.py").read_text()
    migration = (ROOT / "src/techflex_cloud_foundation/schema/sql/0003_seed_mvp_access_control.sql").read_text()
    assert source.count("FOR UPDATE") >= 6
    assert "tenant_transaction(self._tenant_pool" in source
    assert "tenant_transaction(self._activation_pool" in source
    assert "tenant_transaction(self._platform_pool" in source
    assert "ops.access_resource_directory" in migration
    assert "device.hardware_identity_directory" in migration
    assert "NOBYPASSRLS" in migration
    assert "GRANT SELECT, INSERT ON ops.access_resource_directory TO ffp_activation_app" in migration


def _live_dsns() -> tuple[str, str, str] | None:
    names = (
        "FEETFORCEPLATE_TEST_TENANT_DSN",
        "FEETFORCEPLATE_TEST_ACTIVATION_DSN",
        "FEETFORCEPLATE_TEST_PLATFORM_DSN",
    )
    values = tuple(os.environ.get(name, "") for name in names)
    return values if all(values) else None


@pytest.mark.skipif(_live_dsns() is None, reason="three PostgreSQL role DSNs are not configured")
def test_live_repository_parity_for_seed_lifecycle() -> None:
    async def exercise() -> None:
        import asyncpg

        tenant_dsn, activation_dsn, platform_dsn = _live_dsns() or ("", "", "")
        tenant_pool = await asyncpg.create_pool(tenant_dsn, min_size=1, max_size=3)
        activation_pool = await asyncpg.create_pool(activation_dsn, min_size=1, max_size=3)
        platform_pool = await asyncpg.create_pool(platform_dsn, min_size=1, max_size=3)
        repository = PostgresAccessRepository(
            tenant_pool=tenant_pool, activation_pool=activation_pool, platform_pool=platform_pool
        )
        tenant = TenantSeed(uuid4(), f"Postgres parity {uuid4()}")
        run_nonce = os.urandom(32)
        groups = [_group(index, run_nonce=run_nonce) for index in (11, 12, 13)]
        try:
            async with activation_pool.acquire() as connection:
                assert await connection.fetchval(
                    "SELECT has_table_privilege(current_user,'iam.tenants','SELECT')"
                )
            await repository.provision_tenant(tenant, groups[0], created_at=NOW)
            await repository.add_access_group(tenant.tenant_id, groups[1], created_at=NOW)
            await repository.add_access_group(tenant.tenant_id, groups[2], created_at=NOW)
            assert len(await repository.active_access_groups(tenant.tenant_id)) == 3

            with pytest.raises(AccessActivationRejected):
                await repository.activate_account_atomically(
                    login_name_hmac=groups[0].login_name_hmac,
                    activation_code_hash=groups[0].activation_code_hash,
                    hardware_identity="usb-serial-ffffffffffffffffffff",
                    password_hash="$ffp-scrypt$bad", installation_id=uuid4(),
                    activated_at=NOW + timedelta(minutes=1),
                )
            activated = await repository.activate_account_atomically(
                login_name_hmac=groups[0].login_name_hmac,
                activation_code_hash=groups[0].activation_code_hash,
                hardware_identity=groups[0].hardware_identity,
                password_hash="$ffp-scrypt$good", installation_id=uuid4(),
                activated_at=NOW + timedelta(minutes=2), license_key_id="license/2-test",
                license_document_json='{"schema_version":"license/2"}',
                license_signature="s" * 86,
            )
            assert activated.account.password_hash == "$ffp-scrypt$good"
            async with tenant_pool.acquire() as connection:
                async with connection.transaction():
                    await connection.execute(
                        "SELECT set_config('app.tenant_id', $1, true)", str(tenant.tenant_id)
                    )
                    projected = await connection.fetchrow(
                        """SELECT
                               EXISTS (SELECT 1 FROM device.terminals
                                       WHERE tenant_id=$1 AND terminal_id=$2) AS terminal_ok,
                               EXISTS (SELECT 1 FROM device.devices
                                       WHERE tenant_id=$1 AND device_id=$3) AS device_ok,
                               EXISTS (SELECT 1 FROM device.terminal_device_bindings
                                       WHERE tenant_id=$1 AND terminal_id=$2
                                         AND device_id=$3 AND valid_to IS NULL) AS binding_ok""",
                        tenant.tenant_id,
                        activated.installation.client_installation_id,
                        groups[0].hardware_id,
                    )
                    assert all(projected.values())
            with pytest.raises(AccessActivationRejected):
                await repository.activate_account_atomically(
                    login_name_hmac=groups[0].login_name_hmac,
                    activation_code_hash=groups[0].activation_code_hash,
                    hardware_identity=groups[0].hardware_identity,
                    password_hash="$ffp-scrypt$replay", installation_id=uuid4(),
                    activated_at=NOW + timedelta(minutes=3),
                )

            lease = HardwareLeaseRecord(
                lease_id=uuid4(), tenant_id=tenant.tenant_id,
                license_id=groups[0].license_id, account_id=groups[0].account_id,
                hardware_id=groups[0].hardware_id,
                client_installation_id=activated.installation.client_installation_id,
                acquired_at=NOW + timedelta(minutes=3), renewed_at=NOW + timedelta(minutes=3),
                expires_at=NOW + timedelta(minutes=13),
            )
            assert (await repository.acquire_hardware_lease(lease, acquired_at=lease.acquired_at)).lease_id == lease.lease_id

            current = await repository.license(groups[0].license_id)
            suspended = await repository.replace_license(
                license_id=current.license_id, expected_version=current.version,
                status=LicenseState.SUSPENDED, issued_at=NOW + timedelta(minutes=4),
                valid_until=current.valid_until, key_id="license/2-test",
                document_json='{"schema_version":"license/2"}', signature="t" * 86,
            )
            assert suspended.status is LicenseState.SUSPENDED

            identity = PlatformIdentityRecord(
                platform_identity_id=uuid4(), login_name_hmac=os.urandom(32),
                display_name="Postgres Support", password_hash="$ffp-scrypt$platform",
                status="ACTIVE", token_version=1, created_at=NOW,
            )
            await repository.create_platform_identity(
                identity,
                (PlatformRoleBindingRecord(uuid4(), identity.platform_identity_id,
                                           PlatformRole.SUPPORT, NOW),),
            )
            assert await repository.platform_roles(identity.platform_identity_id, at=NOW) == (PlatformRole.SUPPORT,)
            grant = SensitiveAccessGrantRecord(
                grant_id=uuid4(), tenant_id=tenant.tenant_id,
                platform_identity_id=identity.platform_identity_id,
                purpose_code="SUPPORT_DIAGNOSIS", ticket_reference="PG-PARITY",
                issued_at=NOW, expires_at=NOW + timedelta(minutes=15),
            )
            await repository.create_sensitive_grant(grant)
            assert (await repository.use_sensitive_grant(
                grant_id=grant.grant_id, tenant_id=tenant.tenant_id,
                platform_identity_id=identity.platform_identity_id,
                used_at=NOW + timedelta(minutes=1),
            )).last_used_at == NOW + timedelta(minutes=1)

            await repository.close_access_group(
                tenant_id=tenant.tenant_id, license_id=groups[2].license_id,
                closed_at=NOW + timedelta(days=30), reason_code="SEED_CAPACITY_REDUCED",
            )
            assert len(await repository.active_access_groups(tenant.tenant_id)) == 2
            assert len(await repository.access_group_history(tenant.tenant_id)) == 3
        finally:
            await tenant_pool.close()
            await activation_pool.close()
            await platform_pool.close()

    asyncio.run(exercise())
