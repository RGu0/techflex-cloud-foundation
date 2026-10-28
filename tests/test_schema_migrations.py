"""The shipped schema: pinned SQL, plan order, and the runner against a real server."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
import hashlib
from importlib import resources
from itertools import count

import pytest

from techflex_cloud_foundation.schema import (
    DEFAULT_PLAN,
    ChecksumMismatch,
    MigrationPlanError,
    MigrationStep,
    Probe,
    RoleMissing,
    apply_migrations,
    load_step_sql,
    migration_status,
)
from techflex_cloud_foundation.schema.runner import LEDGER
from tests.pg_cluster import Cluster, find_postgres_bin, running_cluster

SQL_DIR = resources.files("techflex_cloud_foundation.schema") / "sql"
SHIPPED_FFP_FILES = 18  # cloud/migrations of ffp 2c61523: 0001-0016, 0009 and 0010 twice


def test_every_shipped_file_is_in_the_plan_with_its_digest() -> None:
    files = sorted(p.name for p in SQL_DIR.iterdir() if p.name.endswith(".sql"))
    planned = sorted(s.filename for s in DEFAULT_PLAN if s.filename is not None)
    assert files == planned
    assert len(files) == SHIPPED_FFP_FILES + 1
    for step in DEFAULT_PLAN:
        if step.filename is not None:
            raw = (SQL_DIR / step.filename).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == step.sha256, step.filename
            assert load_step_sql(step) == raw.decode("utf-8")


def test_plan_follows_the_installer_order_and_ends_with_the_ledger() -> None:
    ids = [s.step_id for s in DEFAULT_PLAN]
    assert len(ids) == len(set(ids))
    assert ids[0] == "0001_p3_cloud_platform"
    assert ids[-1] == "0017_schema_migrations"
    # 0008 follows 0010_session_expected_manifest: it ran after the role step.
    assert ids.index("0008_activation_projection_grants") == ids.index(
        "0010_session_expected_manifest"
    ) + 1
    # RAY-99: the hold table (0009) must precede identity recovery (0011).
    assert ids.index("0009_unverified_session_holds") < ids.index(
        "0011_controlled_identity_recovery"
    )
    needs_backup = {s.step_id for s in DEFAULT_PLAN if "ffp_seed_backup" in s.requires_roles}
    assert "0010_local_basic_report_copies" in needs_backup
    assert all(s.probe is not None or s.converges for s in DEFAULT_PLAN)


def test_a_changed_file_or_inline_sql_is_refused() -> None:
    forged = MigrationStep("x", None, "0" * 64, converges=True, inline_sql="SELECT 1;")
    with pytest.raises(MigrationPlanError):
        load_step_sql(forged)
    with pytest.raises(ValueError):
        MigrationStep("y", "a.sql", "0" * 64)  # neither probe nor converges
    with pytest.raises(ValueError):
        Probe()


# ---------------------------------------------------------------- real server

BIN = find_postgres_bin()
asyncpg = pytest.importorskip("asyncpg")
needs_server = pytest.mark.skipif(BIN is None, reason="no PostgreSQL server installation found")
_names = count()


@pytest.fixture(scope="module")
def cluster() -> Iterator[Cluster]:
    assert BIN is not None
    with running_cluster(BIN) as running:
        yield running


def _run(cluster: Cluster, encoding: str, body):  # type: ignore[no-untyped-def]
    async def go() -> object:
        admin = await asyncpg.connect(
            host=cluster.socket_dir, port=cluster.port, user="postgres", database="postgres"
        )
        name = f"t{next(_names)}_{encoding.lower()}"
        try:
            await admin.execute(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ffp_seed_backup')"
                " THEN CREATE ROLE ffp_seed_backup NOLOGIN BYPASSRLS; END IF; END $$"
            )
            await admin.execute(
                f"CREATE DATABASE {name} TEMPLATE template0 ENCODING '{encoding}' "
                "LC_COLLATE 'C' LC_CTYPE 'C'"
            )
            conn = await asyncpg.connect(
                host=cluster.socket_dir, port=cluster.port, user="postgres", database=name
            )
            try:
                return await body(conn)
            finally:
                await conn.close()
        finally:
            await admin.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
            await admin.close()

    return asyncio.run(go())


async def _fingerprint(conn) -> dict[str, list[tuple]]:  # type: ignore[no-untyped-def]
    schemas = "('iam','device','subject','screening','ops','sales','reporting')"
    queries = {
        "columns": f"SELECT table_schema, table_name, column_name, data_type, is_nullable, "
        f"column_default FROM information_schema.columns WHERE table_schema IN {schemas} "
        "ORDER BY 1, 2, ordinal_position",
        "constraints": "SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) "
        "FROM pg_constraint WHERE connamespace::regnamespace::text IN "
        "('iam','device','subject','screening','ops','sales','reporting') ORDER BY 1, 2",
        "indexes": f"SELECT schemaname, tablename, indexname, indexdef FROM pg_indexes "
        f"WHERE schemaname IN {schemas} ORDER BY 1, 2, 3",
        "policies": "SELECT schemaname, tablename, policyname, cmd, qual, with_check "
        "FROM pg_policies ORDER BY 1, 2, 3",
        "grants": "SELECT grantee, table_schema, table_name, privilege_type "
        "FROM information_schema.role_table_grants WHERE grantee LIKE 'ffp\\_%' "
        "ORDER BY 1, 2, 3, 4",
        "rls": "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE relnamespace::regnamespace::text IN "
        "('iam','device','subject','screening','ops','sales','reporting') AND relkind = 'r' "
        "ORDER BY 1",
    }
    return {k: [tuple(r) for r in await conn.fetch(q)] for k, q in queries.items()}


@needs_server
def test_empty_database_reaches_the_end_and_records_every_step(cluster: Cluster) -> None:
    async def body(conn):  # type: ignore[no-untyped-def]
        first = await apply_migrations(conn)
        rows = await conn.fetch(f"SELECT * FROM {LEDGER}")
        ledger = {r["migration_id"]: r["method"] for r in rows}
        again = await apply_migrations(conn)
        status = await migration_status(conn)
        return first, ledger, again, status

    first, ledger, again, status = _run(cluster, "UTF8", body)
    assert first.applied == [s.step_id for s in DEFAULT_PLAN]
    assert not first.baseline and not first.pending
    assert set(ledger) == {s.step_id for s in DEFAULT_PLAN}
    assert set(ledger.values()) == {"applied"}
    assert again.skipped == [s.step_id for s in DEFAULT_PLAN] and not again.changed
    assert status.pending == []


@needs_server
def test_a_database_installed_without_a_ledger_is_adopted_and_ends_identical(
    cluster: Cluster,
) -> None:
    async def installer_style(conn):  # type: ignore[no-untyped-def]
        # What install-seed-release.sh did: probe, apply, converging steps every time.
        from techflex_cloud_foundation.schema.runner import _probe_says_applied

        for _ in range(2):
            for step in DEFAULT_PLAN[:-1]:
                if step.probe is None or not await _probe_says_applied(conn, step):
                    await conn.execute(load_step_sql(step))

    async def legacy(conn):  # type: ignore[no-untyped-def]
        await installer_style(conn)
        assert await conn.fetchval("SELECT to_regclass($1)", LEDGER) is None
        report = await apply_migrations(conn)
        rows = await conn.fetch(f"SELECT * FROM {LEDGER}")
        methods = {r["migration_id"]: r["method"] for r in rows}
        return report, methods, await _fingerprint(conn)

    async def fresh(conn):  # type: ignore[no-untyped-def]
        await apply_migrations(conn)
        return await _fingerprint(conn)

    report, methods, legacy_print = _run(cluster, "UTF8", legacy)
    fresh_print = _run(cluster, "UTF8", fresh)

    probed = {
        s.step_id
        for s in DEFAULT_PLAN
        if s.probe is not None and s.step_id != "0017_schema_migrations"
    }
    assert set(report.baseline) == probed
    assert {s.step_id for s in DEFAULT_PLAN} - probed == set(report.applied)
    assert set(methods) == {s.step_id for s in DEFAULT_PLAN}
    assert legacy_print == fresh_print


@needs_server
def test_a_ledger_checksum_that_differs_from_the_plan_is_refused(cluster: Cluster) -> None:
    async def body(conn):  # type: ignore[no-untyped-def]
        await apply_migrations(conn)
        await conn.execute(
            f"UPDATE {LEDGER} SET sha256 = repeat('0', 64) "
            "WHERE migration_id = '0016_insole_session_archive'"
        )
        with pytest.raises(ChecksumMismatch):
            await apply_migrations(conn)
        with pytest.raises(ChecksumMismatch):
            await migration_status(conn)

    _run(cluster, "UTF8", body)


@needs_server
def test_a_missing_role_stops_before_the_step_that_needs_it(cluster: Cluster) -> None:
    sql = "SELECT 1;"
    steps = (
        DEFAULT_PLAN[0],
        MigrationStep(
            "needs_role",
            None,
            hashlib.sha256(sql.encode()).hexdigest(),
            converges=True,
            requires_roles=("tf_role_that_does_not_exist",),
            inline_sql=sql,
        ),
    )

    async def body(conn):  # type: ignore[no-untyped-def]
        with pytest.raises(RoleMissing, match="tf_role_that_does_not_exist"):
            await apply_migrations(conn, steps)
        # The earlier step ran and is not undone; nothing is recorded without a ledger.
        assert await conn.fetchval("SELECT to_regclass('iam.tenants') IS NOT NULL")

    _run(cluster, "UTF8", body)


@needs_server
def test_sql_ascii_database_takes_raw_utf8_jsonb_but_not_escaped_non_ascii(
    cluster: Cluster,
) -> None:
    # RAY-834: a SQL_ASCII database stores raw UTF-8 text in jsonb and rejects
    # \uXXXX escapes of non-ASCII characters. The schema must apply there.
    async def body(conn):  # type: ignore[no-untyped-def]
        assert await conn.fetchval("SHOW server_encoding") == "SQL_ASCII"
        await apply_migrations(conn)
        await conn.execute("CREATE TEMP TABLE probe (j jsonb)")
        await conn.execute("INSERT INTO probe VALUES ($1::jsonb)", '{"name": "足压板"}')
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute("INSERT INTO probe VALUES ($1::jsonb)", '{"name": "\\u8db3"}')
        return await conn.fetchval("SELECT j->>'name' FROM probe")

    assert _run(cluster, "SQL_ASCII", body) == "足压板"
