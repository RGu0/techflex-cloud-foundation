from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from techflex_cloud_foundation.schema import MigrationError, RoleMissing
from techflex_cloud_foundation.schema import __main__ as cli
from tests.pg_platform import live_environment


def _fail_with(error: Exception):
    async def run(command: str, dsn: str) -> dict[str, list[str]]:
        raise error

    return run


def test_role_missing_is_a_distinct_exit_status(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_run", _fail_with(RoleMissing("0008: ffp_seed_backup")))

    assert cli.main(["apply", "--dsn", "postgresql:///x"]) == 3
    assert "role-missing" in capsys.readouterr().err


def test_other_migration_errors_fail_without_a_traceback(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_run", _fail_with(MigrationError("boom")))

    assert cli.main(["status", "--dsn", "postgresql:///x"]) == 1
    assert "migration-failed: MigrationError: boom" in capsys.readouterr().err


def test_a_dsn_is_required() -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["apply"])
    assert raised.value.code == 2


def test_success_prints_one_json_object(monkeypatch, capsys) -> None:
    async def run(command: str, dsn: str) -> dict[str, list[str]]:
        return {"applied": [], "baseline": [], "skipped": ["a"], "pending": []}

    monkeypatch.setattr(cli, "_run", run)

    assert cli.main(["status", "--dsn", "postgresql:///x"]) == 0
    assert json.loads(capsys.readouterr().out)["pending"] == []


def test_the_installer_can_read_pending_from_the_output(monkeypatch, capsys) -> None:
    async def run(command: str, dsn: str) -> dict[str, list[str]]:
        return {"applied": [], "baseline": [], "skipped": [], "pending": []}

    monkeypatch.setattr(cli, "_run", run)
    cli.main(["status", "--dsn", "postgresql:///x"])

    assert '"pending": []' in capsys.readouterr().out


@pytest.mark.skipif(not live_environment(), reason="no PostgreSQL server available")
def test_the_command_runs_against_a_migrated_cluster() -> None:
    dsn = os.environ["FEETFORCEPLATE_TEST_ADMIN_DSN"]
    for command in ("status", "apply", "status"):
        done = subprocess.run(
            [sys.executable, "-m", "techflex_cloud_foundation.schema", command, "--dsn", dsn],
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 0, done.stderr
        assert json.loads(done.stdout)["pending"] == []


def test_a_connection_failure_is_not_mistaken_for_a_missing_role() -> None:
    done = subprocess.run(
        [
            sys.executable, "-m", "techflex_cloud_foundation.schema", "status",
            "--dsn", "postgresql://postgres@/none?host=/nonexistent-socket-dir",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert done.returncode == 1
    assert done.returncode != 3
