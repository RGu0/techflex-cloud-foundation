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
    MigrationError,
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
    # 0008 follows 0010_session_expected_manifest: it ran after the role step,
    # so the plan pauses there until the backup role exists.
    assert ids.index("0008_activation_projection_grants") == ids.index(
        "0010_session_expected_manifest"
    ) + 1
    by_id = {s.step_id: s for s in DEFAULT_PLAN}
    assert "ffp_seed_backup" in by_id["0008_activation_projection_grants"].requires_roles
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

# The role step of install-seed-release.sh (postgresql-role-grants.sql) without
# the login roles, which need passwords: the backup role and every grant the
# migrations do not make. Run where the installer ran it.
ROLE_STEP = """
CREATE ROLE ffp_seed_backup NOLOGIN NOINHERIT BYPASSRLS;
GRANT USAGE ON SCHEMA iam, device, subject, screening, ops, sales TO ffp_seed_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA iam, device, subject, screening, ops, sales
    TO ffp_seed_backup;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sales TO ffp_seed_backup;
GRANT USAGE ON SCHEMA sales TO ffp_platform_app, ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA sales
    TO ffp_platform_app, ffp_activation_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sales TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON device.devices TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON device.terminals TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON device.terminal_device_bindings TO ffp_activation_app;
GRANT SELECT ON iam.tenants TO ffp_activation_app;
GRANT INSERT ON iam.account_login_directory, device.license_entitlements
    TO ffp_activation_app;
"""

# install-seed-release.sh, written out here on its own (not derived from
# DEFAULT_PLAN) so the comparison below is against the installer's sequence:
# ("file", marker-or-None); a marker is a relation ("schema.table") or a column
# ("schema.table.column") whose presence makes the installer skip the file.
INSTALLER_SEQUENCE: list[tuple[str, str | None]] = [
    ("0001_p3_cloud_platform", "iam.tenants"),
    ("0002_p5_device_operations", "iam.users"),
    ("0003_seed_mvp_access_control", "iam.tenant_accounts"),
    ("0004_allow_unsigned_revoked_license", None),
    ("0005_sales_inventory_activation", "sales.inventory_batches"),
    ("0006_inventory_activation_pairing", "sales.inventory_batches.activation_binding_mode"),
    ("0007_completion_receipt_fields", "screening.session_manifests.eligibility_reason"),
    ("0009_capture_grants", "screening.capture_grants"),
    ("0010_session_expected_manifest", "screening.sessions.expected_manifest_sha256"),
    ("@roles", None),
    ("0008_activation_projection_grants", None),
    ("0009_unverified_session_holds", "ops.session_holds"),
    ("0010_local_basic_report_copies", "reporting.local_basic_report_copies"),
    ("@grant", "GRANT USAGE ON SCHEMA reporting TO ffp_seed_backup;"
     " GRANT SELECT ON reporting.local_basic_report_copies TO ffp_seed_backup;"),
    ("0011_controlled_identity_recovery", "ops.identity_recovery_cases"),
    ("0012_terminal_activation", "iam.access_terminals"),
    ("@grant", "GRANT SELECT ON iam.access_terminals, iam.terminal_refresh_sessions,"
     " iam.terminal_directory, iam.terminal_refresh_directory TO ffp_seed_backup;"),
    ("0013_insole_inventory", "device.insole_pairs"),
    ("@grant", "GRANT SELECT ON device.insole_revision_counters, device.insole_pairs,"
     " device.insole_identities, device.insole_registration_keys TO ffp_seed_backup;"),
    ("0014_recovery_bound_migration_permits",
     "screening.upload_migration_permits.original_envelope_sha256"),
    ("@grant", "GRANT SELECT ON ops.identity_recovery_cases, ops.identity_recovery_receipts,"
     " ops.identity_recovery_comparisons, ops.identity_recovery_registrations"
     " TO ffp_seed_backup;"),
    ("0015_terminal_data_plane_projection", None),
    ("0016_insole_session_archive", None),
]


@pytest.fixture
def cluster() -> Iterator[Cluster]:
    assert BIN is not None
    with running_cluster(BIN) as running:  # roles are cluster-wide: one cluster per test
        yield running


def _run(cluster: Cluster, encoding: str, body):  # type: ignore[no-untyped-def]
    async def go() -> object:
        admin = await asyncpg.connect(
            host=cluster.socket_dir, port=cluster.port, user="postgres", database="postgres"
        )
        name = f"t{next(_names)}_{encoding.lower()}"
        try:
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


async def _installer_run(conn) -> None:  # type: ignore[no-untyped-def]
    """Replay install-seed-release.sh twice, as an upgrade of an installed host does."""
    sql = {s.step_id: load_step_sql(s) for s in DEFAULT_PLAN if s.filename is not None}
    for pass_number in range(2):
        for name, marker in INSTALLER_SEQUENCE:
            if name == "@roles":
                if pass_number == 0:
                    await conn.execute(ROLE_STEP)
                continue
            if name == "@grant":
                assert marker is not None
                await conn.execute(marker)
                continue
            if marker is not None:
                parts = marker.split(".")
                if len(parts) == 2:
                    present = await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", marker)
                else:
                    present = await conn.fetchval(
                        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE "
                        "table_schema=$1 AND table_name=$2 AND column_name=$3)",
                        *parts,
                    )
                if present:
                    continue
            await conn.execute(sql[name])


async def _fingerprint(conn) -> dict[str, list[tuple]]:  # type: ignore[no-untyped-def]
    ns = "('iam','device','subject','screening','ops','sales','reporting')"
    queries = {
        "columns": f"SELECT table_schema, table_name, column_name, data_type, is_nullable, "
        f"column_default FROM information_schema.columns WHERE table_schema IN {ns} "
        "ORDER BY 1, 2, ordinal_position",
        "constraints": "SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) "
        f"FROM pg_constraint WHERE connamespace::regnamespace::text IN {ns} ORDER BY 1, 2",
        "indexes": f"SELECT schemaname, tablename, indexname, indexdef FROM pg_indexes "
        f"WHERE schemaname IN {ns} ORDER BY 1, 2, 3",
        "policies": "SELECT schemaname, tablename, policyname, cmd, qual, with_check "
        "FROM pg_policies ORDER BY 1, 2, 3",
        "relations": "SELECT relnamespace::regnamespace::text, relname, relkind, "
        "relowner::regrole::text, relrowsecurity, relforcerowsecurity, relacl::text "
        f"FROM pg_class WHERE relnamespace::regnamespace::text IN {ns} ORDER BY 1, 2",
        "schemas": f"SELECT nspname, nspowner::regrole::text, nspacl::text FROM pg_namespace "
        f"WHERE nspname IN {ns} ORDER BY 1",
        "functions": "SELECT pronamespace::regnamespace::text, proname, "
        "pg_get_function_identity_arguments(oid), md5(prosrc), proacl::text FROM pg_proc "
        f"WHERE pronamespace::regnamespace::text IN {ns} ORDER BY 1, 2, 3",
        "triggers": "SELECT tgrelid::regclass::text, tgname, pg_get_triggerdef(oid) "
        "FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1, 2",
        "columns_acl": "SELECT attrelid::regclass::text, attname, attacl::text FROM pg_attribute "
        f"WHERE attrelid::regclass::oid IN (SELECT oid FROM pg_class WHERE "
        f"relnamespace::regnamespace::text IN {ns}) AND attacl IS NOT NULL ORDER BY 1, 2",
        "roles": "SELECT rolname, rolcanlogin, rolbypassrls FROM pg_roles "
        "WHERE rolname LIKE 'ffp\\_%' ORDER BY 1",
    }
    return {k: [tuple(r) for r in await conn.fetch(q)] for k, q in queries.items()}


@needs_server
def test_empty_database_reaches_the_end_and_records_every_step(cluster: Cluster) -> None:
    async def body(conn):  # type: ignore[no-untyped-def]
        with pytest.raises(RoleMissing, match="0008_activation_projection_grants"):
            await apply_migrations(conn)  # pauses where the installer ran its role step
        assert await conn.fetchval("SELECT to_regclass('ops.session_holds')") is None
        assert await conn.fetchval("SELECT to_regclass('iam.tenants') IS NOT NULL")
        await conn.execute(ROLE_STEP)
        first = await apply_migrations(conn)
        rows = await conn.fetch(f"SELECT * FROM {LEDGER}")
        ledger = {r["migration_id"]: r["method"] for r in rows}
        again = await apply_migrations(conn)
        status = await migration_status(conn)
        return first, ledger, again, status

    first, ledger, again, status = _run(cluster, "UTF8", body)
    assert not first.pending
    # The run that paused had no ledger to write to, so what it applied before the
    # pause is found by its probes on the next run and recorded as baseline.
    before_pause = [s.step_id for s in DEFAULT_PLAN]
    before_pause = before_pause[: before_pause.index("0008_activation_projection_grants")]
    assert set(first.baseline) == {
        s.step_id for s in DEFAULT_PLAN if s.step_id in before_pause and s.probe is not None
    }
    assert set(ledger) == {s.step_id for s in DEFAULT_PLAN}
    assert set(ledger.values()) == {"applied", "baseline"}
    assert again.skipped == [s.step_id for s in DEFAULT_PLAN] and not again.changed
    assert status.pending == []


@needs_server
def test_a_database_installed_the_old_way_is_adopted_and_matches_a_fresh_one(
    cluster: Cluster,
) -> None:
    async def legacy(conn):  # type: ignore[no-untyped-def]
        await _installer_run(conn)
        assert await conn.fetchval("SELECT to_regclass($1)", LEDGER) is None
        report = await apply_migrations(conn)
        rows = await conn.fetch(f"SELECT * FROM {LEDGER}")
        return report, {r["migration_id"]: r["method"] for r in rows}, await _fingerprint(conn)

    report, methods, legacy_print = _run(cluster, "UTF8", legacy)

    probed = {
        s.step_id
        for s in DEFAULT_PLAN
        if s.probe is not None and s.step_id != "0017_schema_migrations"
    }
    assert set(report.baseline) == probed
    assert set(report.applied) == {s.step_id for s in DEFAULT_PLAN} - probed
    assert set(methods) == {s.step_id for s in DEFAULT_PLAN}
    # The installer's own sequence is the plan's: the same steps in the same order.
    assert [n for n, _ in INSTALLER_SEQUENCE if not n.startswith("@")] == [
        s.step_id for s in DEFAULT_PLAN if s.filename is not None
    ][:-1]

    async def fresh(conn):  # type: ignore[no-untyped-def]
        with pytest.raises(RoleMissing):
            await apply_migrations(conn)
        await conn.execute(ROLE_STEP)
        await apply_migrations(conn)
        return await _fingerprint(conn)

    with running_cluster(BIN) as other:  # type: ignore[arg-type]
        fresh_print = _run(other, "UTF8", fresh)
    assert legacy_print == fresh_print


@needs_server
def test_a_failing_step_surfaces_its_own_error_and_releases_the_lock(
    cluster: Cluster,
) -> None:
    sql = "BEGIN; CREATE TABLE tf_partial (a int); SELECT 1/0; COMMIT;"
    steps = (
        MigrationStep(
            "fails", None, hashlib.sha256(sql.encode()).hexdigest(), converges=True, inline_sql=sql
        ),
    )

    async def body(conn):  # type: ignore[no-untyped-def]
        with pytest.raises(asyncpg.DivisionByZeroError):
            await apply_migrations(conn, steps)
        assert not conn.is_in_transaction()
        assert await conn.fetchval("SELECT to_regclass('tf_partial')") is None
        # The lock is free again: another session can take it at once.
        other = await asyncpg.connect(
            host=cluster.socket_dir, port=cluster.port, user="postgres", database="postgres"
        )
        try:
            assert await other.fetchval("SELECT pg_try_advisory_lock(7201830017)")
        finally:
            await other.close()
        with pytest.raises(MigrationError, match="outside a transaction"):
            async with conn.transaction():
                await apply_migrations(conn, steps)

    _run(cluster, "UTF8", body)


@needs_server
def test_a_ledger_checksum_that_differs_from_the_plan_is_refused(cluster: Cluster) -> None:
    async def body(conn):  # type: ignore[no-untyped-def]
        await conn.execute("CREATE ROLE ffp_seed_backup NOLOGIN BYPASSRLS")
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
def test_sql_ascii_database_takes_raw_utf8_jsonb_but_not_escaped_non_ascii(
    cluster: Cluster,
) -> None:
    # RAY-834: a SQL_ASCII database stores raw UTF-8 text in jsonb and rejects
    # \uXXXX escapes of non-ASCII characters. The schema must apply there.
    async def body(conn):  # type: ignore[no-untyped-def]
        assert await conn.fetchval("SHOW server_encoding") == "SQL_ASCII"
        await conn.execute("CREATE ROLE ffp_seed_backup NOLOGIN BYPASSRLS")
        await apply_migrations(conn)
        await conn.execute("CREATE TEMP TABLE probe (j jsonb)")
        await conn.execute("INSERT INTO probe VALUES ($1::jsonb)", '{"name": "足压板"}')
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute("INSERT INTO probe VALUES ($1::jsonb)", '{"name": "\\u8db3"}')
        return await conn.fetchval("SELECT j->>'name' FROM probe")

    assert _run(cluster, "SQL_ASCII", body) == "足压板"
