"""RAY-802 diagnostic package persistence against live PostgreSQL role pools."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.platform_errors import IdempotencyConflict, ResourceNotFound
from techflex_cloud_foundation.server.access_auth import (
    PlatformAccessContext,
    TerminalAccessContext,
)
from techflex_cloud_foundation.server.access_control.postgres import PostgresAccessRepository
from techflex_cloud_foundation.server.access_control.repository import (
    AuditEventRecord,
    TenantSeed,
    TerminalRecord,
)
from techflex_cloud_foundation.server.terminal_diagnostics.object_store import (
    DiagnosticPackageStore,
)
from techflex_cloud_foundation.server.terminal_diagnostics.postgres import (
    PostgresDiagnosticRepository,
)
from techflex_cloud_foundation.server.terminal_diagnostics.repository import (
    DiagnosticRecord,
    InMemoryDiagnosticRepository,
    diagnostic_object_key,
)
from techflex_cloud_foundation.server.terminal_diagnostics.service import TerminalDiagnosticsService
from tests.test_ffp_postgres_access_repository import NOW, _group, _live_dsns

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "src/techflex_cloud_foundation/schema/sql/0019_terminal_diagnostics.sql"
FIXTURE = ROOT / "tests/fixtures/ffp_terminal_diagnostics/ray910_export.ndjson"
FIXTURE_IDS = ("5a1f0c3e-7b2d-4e8a-9c6f-2d4b8e1a0f37", "c3d9e2f1-6a4b-4f0c-8e7d-9b2a1c0d3e5f")


def test_migration_is_additive_rls_forced_and_tombstone_only() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;")
    assert "DROP " not in sql and "ALTER TABLE ops.terminal_diagnostics ADD" not in sql
    assert "ALTER TABLE ops.terminal_diagnostics ENABLE ROW LEVEL SECURITY;" in sql
    assert "ALTER TABLE ops.terminal_diagnostics FORCE ROW LEVEL SECURITY;" in sql
    assert "USING (tenant_id = ops.current_tenant_id())" in sql
    assert "UNIQUE (tenant_id, client_installation_id, idempotency_key)" in sql
    grants = [line for line in sql.splitlines() if line.startswith("GRANT")]
    assert grants == [
        "GRANT SELECT, INSERT ON ops.terminal_diagnostics TO ffp_activation_app;",
        "GRANT SELECT ON ops.terminal_diagnostics TO ffp_platform_app;",
        "GRANT UPDATE (deleted_at) ON ops.terminal_diagnostics TO ffp_platform_app;",
    ]


def test_plan_applies_and_backs_up_diagnostics_migration() -> None:
    from techflex_cloud_foundation.schema import DEFAULT_PLAN
    from techflex_cloud_foundation.schema.plan import Probe

    ids = [step.step_id for step in DEFAULT_PLAN]
    step = DEFAULT_PLAN[ids.index("0019_terminal_diagnostics")]
    assert ids.index("0019_terminal_diagnostics") > ids.index("0018_subject_sync")
    # A database that ran the migration as FeetForcePlate 0018 is recognised, not re-run.
    assert step.probe == Probe(relation="ops.terminal_diagnostics")
    grant = DEFAULT_PLAN[ids.index("grants_0019_diagnostics_to_backup")]
    assert grant.inline_sql == "GRANT SELECT ON ops.terminal_diagnostics TO ffp_seed_backup;"
    backup = (ROOT / "deploy/aliyun/seed/backup.sh").read_text(encoding="utf-8")
    assert '0018_subject_sync,0019_terminal_diagnostics"' in backup


def _record(tenant_id, installation, key, *, received=NOW, days=30) -> DiagnosticRecord:
    diagnostic_id = uuid4()
    return DiagnosticRecord(
        diagnostic_id=diagnostic_id, tenant_id=tenant_id,
        client_installation_id=installation, idempotency_key=key,
        format="gait-insole-diagnostics/1", size_bytes=10, sha256="a" * 64,
        object_key=diagnostic_object_key(tenant_id, diagnostic_id),
        received_at=received, expires_at=received + timedelta(days=days),
    )


async def _exercise(repository, tenant_id, other_tenant_id) -> None:
    installation = uuid4()
    first = _record(tenant_id, installation, "k-1")
    assert await repository.insert(first) == first
    # Same key: the stored record comes back unchanged.
    duplicate = replace(_record(tenant_id, installation, "k-1"), sha256="b" * 64)
    assert await repository.insert(duplicate) == first
    assert await repository.by_key(tenant_id, installation, "k-1") == first
    assert await repository.by_key(other_tenant_id, installation, "k-1") is None
    # The key is scoped to the installation and the tenant.
    other_installation = _record(tenant_id, uuid4(), "k-1", received=NOW + timedelta(seconds=1))
    assert await repository.insert(other_installation) == other_installation
    elsewhere = _record(other_tenant_id, installation, "k-1")
    assert await repository.insert(elsewhere) == elsewhere
    assert [row.diagnostic_id for row in await repository.list(tenant_id)] == [
        other_installation.diagnostic_id, first.diagnostic_id]
    assert await repository.get(other_tenant_id, first.diagnostic_id) is None
    assert await repository.get(tenant_id, first.diagnostic_id) == first
    old = _record(tenant_id, uuid4(), "k-old", received=NOW - timedelta(days=31))
    old_elsewhere = _record(other_tenant_id, uuid4(), "k-old", received=NOW - timedelta(days=40))
    await repository.insert(old)
    await repository.insert(old_elsewhere)
    expired = {row.diagnostic_id for row in await repository.expired(NOW)}
    assert {old.diagnostic_id, old_elsewhere.diagnostic_id} <= expired
    assert first.diagnostic_id not in expired
    await repository.mark_deleted(tenant_id, old.diagnostic_id, NOW)
    await repository.mark_deleted(other_tenant_id, old.diagnostic_id, NOW + timedelta(days=1))
    tombstone = await repository.get(tenant_id, old.diagnostic_id)
    assert tombstone == replace(old, deleted_at=NOW)
    # A second purge does not move the tombstone.
    await repository.mark_deleted(tenant_id, old.diagnostic_id, NOW + timedelta(days=1))
    assert (await repository.get(tenant_id, old.diagnostic_id)).deleted_at == NOW
    assert old.diagnostic_id not in {row.diagnostic_id for row in await repository.expired(NOW)}


class _Access:
    """Terminals from a dict; tenants and the audit from the real repository."""

    def __init__(self, access) -> None:
        self._access = access
        self.rows: dict = {}

    def add(self, tenant_id) -> TerminalAccessContext:
        record = TerminalRecord(
            tenant_id=tenant_id, client_installation_id=uuid4(), account_id=uuid4(),
            license_id=uuid4(), terminal_name="Front desk", platform="android", status="ACTIVE",
            refresh_family_id=uuid4(), activated_at=NOW)
        self.rows[record.client_installation_id] = record
        return TerminalAccessContext(
            tenant_id=tenant_id, account_id=record.account_id, license_id=record.license_id,
            client_installation_id=record.client_installation_id,
            expires_at=NOW + timedelta(minutes=15))

    async def terminal(self, client_installation_id):
        return self.rows.get(client_installation_id)

    async def tenant(self, tenant_id):
        return await self._access.tenant(tenant_id)

    async def append_audit(self, event):
        await self._access.append_audit(event)

    async def audit_events(self, *, tenant_id):
        # Read directly: the access repository's reader expects a jsonb codec.
        async with self._access._plain_transaction(self._access._platform_pool) as connection:
            rows = await connection.fetch(
                "SELECT * FROM ops.access_audit_events WHERE tenant_id=$1 "
                "ORDER BY occurred_at,access_audit_event_id", tenant_id)
        return tuple(AuditEventRecord(
            event_id=row["access_audit_event_id"], actor_id=row["actor_id"],
            action=row["action"], tenant_id=row["tenant_id"], resource_id=row["resource_id"],
            occurred_at=row["occurred_at"],
            details=tuple(sorted(json.loads(row["details"]).items()))) for row in rows)


async def _stream(payload: bytes):
    yield payload


async def _exercise_service(repository, access, tenant_id, other_tenant_id) -> None:
    access = _Access(access)
    objects = InMemoryObjectStore()
    service = TerminalDiagnosticsService(repository, DiagnosticPackageStore(objects), access, now=lambda: NOW)
    terminal = access.add(tenant_id)
    payload = FIXTURE.read_bytes().replace(
        FIXTURE_IDS[0].encode(), str(tenant_id).encode()).replace(
        FIXTURE_IDS[1].encode(), str(terminal.client_installation_id).encode())
    digest = hashlib.sha256(payload).hexdigest()

    async def upload(body, key):
        return await service.upload(
            terminal, _stream(body), declared_length=len(body),
            content_sha256=hashlib.sha256(body).hexdigest(), idempotency_key=key)

    created, is_new = await upload(payload, "key-1")
    replay, replay_new = await upload(payload, "key-1")
    assert is_new and not replay_new and replay == created and created.sha256 == digest
    with pytest.raises(IdempotencyConflict):
        await upload(payload + payload[-50:], "key-1")
    support = PlatformAccessContext(
        platform_identity_id=uuid4(), roles=frozenset({PlatformRole.SUPPORT}),
        token_version=1, expires_at=NOW + timedelta(minutes=15))
    listed = await service.list(support, tenant_id, "SUP-1")
    assert [row.diagnostic_id for row in listed.items] == [created.diagnostic_id]
    assert (await service.list(support, other_tenant_id, "SUP-1")).items == ()
    record, content = await service.read(support, tenant_id, created.diagnostic_id, "SUP-1")
    assert content == payload and record.sha256 == digest
    with pytest.raises(ResourceNotFound):
        await service.read(support, other_tenant_id, created.diagnostic_id, "SUP-1")
    # The service clock is fixed, so both events share one occurred_at.
    actions = sorted((event.action, dict(event.details).get("reason"))
               for event in await access.audit_events(tenant_id=tenant_id)
               if event.action.startswith("diagnostics."))
    assert actions == [("diagnostics.list", None), ("diagnostics.read", None)]
    [denial] = [event for event in await access.audit_events(tenant_id=other_tenant_id)
                if event.action == "diagnostics.deny"]
    assert dict(denial.details)["reason"] == "not_found"
    assert denial.resource_id == created.diagnostic_id
    # Thirty days on, the purge deletes the content and keeps the tombstone.
    later = TerminalDiagnosticsService(
        repository, objects, access, now=lambda: NOW + timedelta(days=30))
    assert await later.purge() >= 1
    assert objects.object_count == 0
    tombstone = await repository.get(tenant_id, created.diagnostic_id)
    assert tombstone.deleted_at == NOW + timedelta(days=30)
    assert (tombstone.sha256, tombstone.size_bytes) == (digest, len(payload))
    with pytest.raises(ResourceNotFound):
        await service.read(support, tenant_id, created.diagnostic_id, "SUP-1")


def test_in_memory_parity() -> None:
    asyncio.run(_exercise(InMemoryDiagnosticRepository(), uuid4(), uuid4()))


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
            for index in (71, 72, 73, 74):
                tenant = TenantSeed(uuid4(), f"RAY-802 clinic {uuid4()}")
                await access.provision_tenant(
                    tenant, _group(index, run_nonce=nonce), created_at=NOW)
                tenants.append(tenant.tenant_id)
            repository = PostgresDiagnosticRepository(pools[1], pools[2])
            await _exercise(repository, *tenants[:2])
            await _exercise_service(repository, access, *tenants[2:])
            await _assert_role_boundaries(pools, tenants[0])
        finally:
            for pool in pools:
                await pool.close()

    asyncio.run(exercise())


async def _assert_role_boundaries(pools, tenant_id) -> None:
    import asyncpg

    from techflex_cloud_foundation.server.postgres import tenant_transaction

    tenant_pool, activation_pool, platform_pool = pools
    # Tenant credentials have no read path at all.
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with tenant_transaction(tenant_pool, tenant_id) as connection:
            await connection.fetch("SELECT * FROM ops.terminal_diagnostics")
    # The activation role uploads but cannot tombstone or delete.
    for statement in ("UPDATE ops.terminal_diagnostics SET deleted_at=now()",
                      "DELETE FROM ops.terminal_diagnostics"):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with tenant_transaction(activation_pool, tenant_id) as connection:
                await connection.execute(statement)
    # The platform role reads and sets deleted_at only.
    for statement in ("UPDATE ops.terminal_diagnostics SET size_bytes=1",
                      "DELETE FROM ops.terminal_diagnostics",
                      "INSERT INTO ops.terminal_diagnostics (diagnostic_id) VALUES (gen_random_uuid())"):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with tenant_transaction(platform_pool, tenant_id) as connection:
                await connection.execute(statement)
    # RLS: another tenant's context sees none of this tenant's rows.
    async with tenant_transaction(platform_pool, uuid4()) as connection:
        assert await connection.fetchval(
            "SELECT count(*) FROM ops.terminal_diagnostics WHERE tenant_id=$1", tenant_id) == 0


@pytest.mark.skipif(_live_dsns() is None, reason="live PostgreSQL role DSNs are not configured")
def test_purge_entry_point_runs_on_the_platform_pool_only(tmp_path) -> None:
    import asyncpg

    from techflex_cloud_foundation.server.seed import SeedSettings
    from techflex_cloud_foundation.server.terminal_diagnostics.purge import purge_expired
    from tests.test_ffp_seed_composition import _values

    platform_dsn = _live_dsns()[2]
    settings = SeedSettings(**{**_values(tmp_path / "objects"), "platform_dsn": platform_dsn})
    opened = []

    async def pool_factory(**kwargs):
        opened.append(kwargs["dsn"])
        return await asyncpg.create_pool(**kwargs)

    purged = asyncio.run(purge_expired(
        settings, pool_factory=pool_factory,
        object_store_factory=lambda _settings: InMemoryObjectStore()))
    assert purged >= 0
    assert opened == [platform_dsn]
