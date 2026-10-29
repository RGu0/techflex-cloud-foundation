"""The installer's schema step, run for real on a scratch cluster (RAY-830 deploy-cutover).

It replays what ``install-seed-release.sh`` does: the migration runner as the
superuser over the Unix socket, the role step through psql, the runner again,
and the role step once more.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.pg_cluster import Cluster, find_postgres_bin, running_cluster

ROLE_FILE = Path(__file__).resolve().parents[1] / "deploy/aliyun/seed/postgresql-role-grants.sql"
DATABASE = "feetforceplate_seed"
BIN = find_postgres_bin()

pytestmark = pytest.mark.skipif(BIN is None, reason="no PostgreSQL server available")


def _psql(cluster: Cluster, *args: str) -> str:
    assert BIN is not None
    done = subprocess.run(
        [
            str(BIN / "psql"), "-h", cluster.socket_dir, "-p", str(cluster.port), "-U", "postgres",
            "-v", "ON_ERROR_STOP=1", "-Atq", *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def _schema(cluster: Cluster, command: str) -> subprocess.CompletedProcess[str]:
    dsn = f"postgresql://postgres@/{DATABASE}?host={cluster.socket_dir}&port={cluster.port}"
    return subprocess.run(
        [sys.executable, "-m", "techflex_cloud_foundation.schema", command, "--dsn", dsn],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ},
    )


def _apply_roles(cluster: Cluster, directory: Path) -> None:
    wrapper = directory / "roles.sql"
    wrapper.write_text(
        "".join(
            f"\\set {name} '{value}'\n"
            for name, value in (
                ("database_name", DATABASE),
                ("tenant_password", "t-pass"),
                ("activation_password", "a-pass"),
                ("platform_password", "p-pass"),
                ("backup_password", "b-pass"),
            )
        )
        + f"\\ir '{ROLE_FILE}'\n",
        encoding="utf-8",
    )
    _psql(cluster, "-d", DATABASE, "-f", str(wrapper))


def test_installer_sequence_pauses_for_roles_then_reaches_the_end_of_the_plan(
    tmp_path: Path,
) -> None:
    assert BIN is not None
    with running_cluster(BIN) as cluster:
        _psql(cluster, "-d", "postgres", "-c", f"CREATE DATABASE {DATABASE}")

        first = _schema(cluster, "apply")
        assert first.returncode == 3, first.stderr
        assert "role-missing" in first.stderr

        _apply_roles(cluster, tmp_path)
        second = _schema(cluster, "apply")
        assert second.returncode == 0, second.stderr
        _apply_roles(cluster, tmp_path)

        status = _schema(cluster, "status")
        assert status.returncode == 0, status.stderr
        assert json.loads(status.stdout)["pending"] == []
        assert '"pending": []' in status.stdout

        # The second role step is what gives the backup role the tables later
        # migrations created, such as the session-hold tables.
        held = _psql(
            cluster, "-d", DATABASE, "-c",
            "SELECT bool_and(has_table_privilege('ffp_seed_backup', format('%I.%I', schemaname, "
            "tablename), 'SELECT')) FROM pg_tables WHERE schemaname IN "
            "('iam','device','subject','screening','ops','sales')",
        )
        assert held == "t"
        logins = _psql(
            cluster, "-d", DATABASE, "-c",
            "SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles "
            "WHERE rolname LIKE 'ffp_seed_%' AND rolcanlogin",
        )
        assert logins == "ffp_seed_activation,ffp_seed_backup,ffp_seed_platform,ffp_seed_tenant"
        tenant = _psql(
            cluster, "-d", DATABASE, "-c",
            "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = 'ffp_seed_tenant'",
        )
        assert tenant == "f"

        # Running the whole sequence again changes nothing.
        again = _schema(cluster, "apply")
        assert again.returncode == 0, again.stderr
        assert json.loads(again.stdout)["applied"] == []


def test_a_database_left_by_the_old_installer_is_upgraded_and_can_roll_back(
    tmp_path: Path,
) -> None:
    import asyncio

    import asyncpg  # type: ignore[import-untyped]

    from tests.test_schema_migrations import _installer_run

    assert BIN is not None

    async def old_installer(cluster: Cluster) -> None:
        conn = await asyncpg.connect(
            host=cluster.socket_dir, port=cluster.port, user="postgres", database=DATABASE
        )
        try:
            await _installer_run(conn)
        finally:
            await conn.close()

    async def drop_ledger(cluster: Cluster) -> None:
        conn = await asyncpg.connect(
            host=cluster.socket_dir, port=cluster.port, user="postgres", database=DATABASE
        )
        try:
            await conn.execute("DROP TABLE ops.schema_migrations")
        finally:
            await conn.close()

    with running_cluster(BIN) as cluster:
        _psql(cluster, "-d", "postgres", "-c", f"CREATE DATABASE {DATABASE}")
        asyncio.run(old_installer(cluster))  # the 0016 state, no ledger

        before = _schema(cluster, "status")
        assert before.returncode != 0 or len(json.loads(before.stdout)["pending"]) > 0

        upgraded = _schema(cluster, "apply")
        assert upgraded.returncode == 0, upgraded.stderr
        report = json.loads(upgraded.stdout)
        assert report["baseline"], "steps already installed are adopted, not run again"
        assert "0017_schema_migrations" in report["applied"]
        _apply_roles(cluster, tmp_path)
        assert json.loads(_schema(cluster, "status").stdout)["pending"] == []

        # Rollback of the one reversible change: drop the ledger and the old
        # installer's own sequence runs again without error.
        asyncio.run(drop_ledger(cluster))
        asyncio.run(old_installer(cluster))
