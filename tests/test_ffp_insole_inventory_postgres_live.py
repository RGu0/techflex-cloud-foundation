"""RAY-778 insole inventory persistence against live PostgreSQL role pools."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.insole_inventory import (
    InsoleIdentity,
    InsoleIdentityKind,
    InsoleNode,
    InsoleRecord,
    InsoleRegistrationRequest,
    InsoleReportRequest,
    InsoleState,
    StoredBatteryReading,
)
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    InsoleCursorInvalid,
    InsoleIdentityRegistered,
    InsoleNumberTaken,
    InsoleRetired,
    ResourceNotFound,
)
from techflex_cloud_foundation.server.access_auth import TerminalAccessContext
from techflex_cloud_foundation.server.access_control.postgres import PostgresAccessRepository
from techflex_cloud_foundation.server.access_control.repository import TenantSeed, TerminalRecord
from techflex_cloud_foundation.server.contract_export import build_vectors
from techflex_cloud_foundation.server.insole_inventory.postgres import (
    PostgresInsoleInventoryRepository,
)
from techflex_cloud_foundation.server.insole_inventory.repository import (
    InMemoryInsoleInventoryRepository,
)
from techflex_cloud_foundation.server.insole_inventory.service import InsoleInventoryService
from tests.test_ffp_postgres_access_repository import NOW, _group, _live_dsns

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "src/techflex_cloud_foundation/schema/sql/0013_insole_inventory.sql"
TABLES = (
    "device.insole_revision_counters", "device.insole_pairs",
    "device.insole_identities", "device.insole_registration_keys",
)


def test_migration_is_additive_rls_scoped_retire_only_and_least_privilege() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;")
    assert "DROP " not in sql and "ALTER TABLE device.devices" not in sql
    for table in TABLES:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;" in sql
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;" in sql
    assert "DELETE" not in sql.split("-- No DELETE grant")[1].split("COMMIT;")[0].replace(
        "No DELETE grant", "")
    assert "TO ffp_tenant_app" not in sql
    assert "TO ffp_platform_app" not in sql
    assert "UNIQUE (tenant_id, institution_number)" in sql
    assert "PRIMARY KEY (tenant_id, identity_kind, identity_value)" in sql


def _record(insole_id, *, number, left, right, revision, now) -> InsoleRecord:
    def node(value):
        return InsoleNode(identity=InsoleIdentity(
            kind=InsoleIdentityKind.SERIAL, value=value, provenance="ble_advertisement"))

    return InsoleRecord(
        insole_id=insole_id, institution_number=number, size=38,
        left=node(left), right=node(right), state=InsoleState.AVAILABLE,
        registered_at=now, registered_by_client_installation_id=uuid4(),
        revision=revision, updated_at=now,
    )


async def _exercise(repository, tenant_id, other_tenant_id) -> None:
    insole_id = uuid4()
    async with repository.writer(tenant_id) as tx:
        record = _record(insole_id, number="A-001", left="L1", right="R1",
                         revision=await tx.next_revision(), now=NOW)
        await tx.insert(record)
    async with repository.writer(tenant_id) as tx:
        assert (await tx.by_identity(InsoleIdentityKind.SERIAL, "R1")).insole_id == insole_id
        assert await tx.by_identity(InsoleIdentityKind.MAC, "R1") is None
        assert (await tx.by_number("A-001")).insole_id == insole_id
        current = await tx.get_for_update(insole_id)
        reading = StoredBatteryReading(
            millivolts=3900, percent=75, read_at=NOW,
            reported_by_client_installation_id=uuid4())
        await tx.update(current.model_copy(update={
            "left": current.left.model_copy(update={"battery": reading}),
            "revision": await tx.next_revision(),
            "updated_at": NOW + timedelta(seconds=1),
        }))
    changes = await repository.changes(tenant_id, after_revision=0, limit=10)
    assert [(row.insole_id, row.revision) for row in changes] == [(insole_id, 2)]
    assert changes[0].left.battery.millivolts == 3900
    assert await repository.changes(other_tenant_id, after_revision=0, limit=10) == ()
    assert await repository.get(other_tenant_id, insole_id) is None

    # Writers of one tenant serialize: every revision is distinct and gapless.
    async def write(index):
        async with repository.writer(tenant_id) as tx:
            await tx.insert(_record(uuid4(), number=f"B-{index}", left=f"L-{index}",
                                    right=f"R-{index}", revision=await tx.next_revision(),
                                    now=NOW))

    await asyncio.gather(*(write(index) for index in range(8)))
    revisions = [row.revision for row in await repository.changes(
        tenant_id, after_revision=0, limit=100)]
    assert revisions == list(range(2, 11))


class _Terminals:
    def __init__(self) -> None:
        self.rows: dict = {}

    def add(self, tenant_id, name) -> TerminalAccessContext:
        record = TerminalRecord(
            tenant_id=tenant_id, client_installation_id=uuid4(), account_id=uuid4(),
            license_id=uuid4(), terminal_name=name, platform="ios", status="ACTIVE",
            refresh_family_id=uuid4(), activated_at=NOW)
        self.rows[record.client_installation_id] = record
        return TerminalAccessContext(
            tenant_id=tenant_id, account_id=record.account_id, license_id=record.license_id,
            client_installation_id=record.client_installation_id,
            expires_at=NOW + timedelta(minutes=15))

    async def terminal(self, client_installation_id):
        return self.rows.get(client_installation_id)


async def _exercise_service(repository, tenant_id, other_tenant_id) -> None:
    vectors = build_vectors()["insole_inventory"]
    terminals = _Terminals()
    # After the vector reading times, so none of them is in the future.
    service = InsoleInventoryService(
        repository, terminals, now=lambda: datetime(2026, 10, 20, 9, 0, tzinfo=UTC))
    a, b = terminals.add(tenant_id, "Front desk"), terminals.add(tenant_id, "Gait lab")
    foreign = terminals.add(other_tenant_id, "Elsewhere")
    request = InsoleRegistrationRequest.model_validate(vectors["registration_request"])
    created, is_new = await service.register(a, request, "key-1")
    replay, replay_new = await service.register(a, request, "key-1")
    assert is_new and not replay_new and replay.idempotent_replay
    assert replay.insole.insole_id == created.insole.insole_id
    with pytest.raises(IdempotencyConflict):
        await service.register(a, request.model_copy(update={"size": 40}), "key-1")
    for scenario in vectors["registration"]["scenarios"]:
        attempt = InsoleRegistrationRequest.model_validate(scenario["attempt"])
        code = scenario["expect"].get("code")
        if code is None:
            continue
        with pytest.raises((InsoleIdentityRegistered, InsoleNumberTaken)) as raised:
            await service.register(b, attempt, f"conflict-{scenario['name']}")
        assert raised.value.code == code
        assert raised.value.details["existing"]["insole_id"] == str(created.insole.insole_id)
    insole_id = created.insole.insole_id
    report = InsoleReportRequest.model_validate(vectors["report_request"])
    applied = await service.report(b, insole_id, report)
    assert applied.applied.state and applied.applied.left and applied.applied.right
    assert applied.insole.holder.terminal_name == "Gait lab"
    assert applied.insole.left.battery.millivolts == 3987
    stale = await service.report(a, insole_id, report)
    assert not (stale.applied.state or stale.applied.left or stale.applied.right)
    assert stale.insole.revision == applied.insole.revision
    with pytest.raises(ResourceNotFound):
        await service.report(foreign, insole_id, report)
    retired = await service.retire(a, insole_id)
    assert retired.insole.state is InsoleState.RETIRED and retired.insole.holder is None
    assert (await service.retire(b, insole_id)).idempotent_replay
    with pytest.raises(InsoleRetired):
        await service.report(b, insole_id, report)
    page = await service.changes(b, cursor=None, limit=None)
    assert [(row.insole_id, row.state) for row in page.items] == [(insole_id, InsoleState.RETIRED)]
    assert page.items[0].left.battery.read_at == report.left.read_at
    assert (await service.changes(b, cursor=page.next_cursor, limit=None)).items == ()
    assert (await service.changes(foreign, cursor=None, limit=None)).items == ()
    with pytest.raises(InsoleCursorInvalid):
        await service.changes(
            b, cursor=vectors["download"]["out_of_range_cursor_example"], limit=None)
    theirs, theirs_new = await service.register(foreign, request, "key-1")
    assert theirs_new and theirs.insole.revision == 1


def test_in_memory_parity() -> None:
    asyncio.run(_exercise(InMemoryInsoleInventoryRepository(), uuid4(), uuid4()))
    asyncio.run(_exercise_service(InMemoryInsoleInventoryRepository(), uuid4(), uuid4()))


@pytest.mark.skipif(_live_dsns() is None, reason="live PostgreSQL role DSNs are not configured")
def test_postgres_repository_against_live_cluster() -> None:
    import asyncpg

    tenant_dsn, activation_dsn, platform_dsn = _live_dsns()

    async def exercise() -> None:
        pools = [await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=4)
                 for dsn in (tenant_dsn, activation_dsn, platform_dsn)]
        try:
            access = PostgresAccessRepository(
                tenant_pool=pools[0], activation_pool=pools[1], platform_pool=pools[2])
            nonce = os.urandom(32)
            tenants = []
            for index, name in ((61, "RAY-778 clinic"), (62, "RAY-778 other")):
                tenant = TenantSeed(uuid4(), f"{name} {uuid4()}")
                await access.provision_tenant(
                    tenant, _group(index, run_nonce=nonce), created_at=NOW)
                tenants.append(tenant.tenant_id)
            await _exercise(PostgresInsoleInventoryRepository(pools[1]), *tenants)
            service_tenants = []
            for index in (63, 64):
                tenant = TenantSeed(uuid4(), f"RAY-778 service {uuid4()}")
                await access.provision_tenant(
                    tenant, _group(index, run_nonce=nonce), created_at=NOW)
                service_tenants.append(tenant.tenant_id)
            await _exercise_service(
                PostgresInsoleInventoryRepository(pools[1]), *service_tenants)
        finally:
            for pool in pools:
                await pool.close()

    asyncio.run(exercise())
