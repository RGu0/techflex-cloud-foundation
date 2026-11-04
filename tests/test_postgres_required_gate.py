"""Required PostgreSQL must not turn missing core database coverage green."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("module", [
    "test_schema_migrations.py", "test_registry_postgres_invariants.py",
    "test_ffp_registry_postgres.py", "test_ffp_postgres_platform_live.py",
])
def test_required_postgres_missing_explicit_installation_fails(module, tmp_path):
    env = os.environ.copy()
    env.pop("PYTEST_ADDOPTS", None)
    env.update(FFP_REQUIRE_POSTGRES="1", FFP_POSTGRES_BIN=str(tmp_path / "missing"))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", f"tests/{module}"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "FFP_REQUIRE_POSTGRES=1" in result.stdout + result.stderr


def test_optional_postgres_missing_explicit_installation_skips(tmp_path):
    env = os.environ.copy()
    env.pop("PYTEST_ADDOPTS", None)
    env.update(FFP_REQUIRE_POSTGRES="0", FFP_POSTGRES_BIN=str(tmp_path / "missing"))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_ffp_registry_postgres.py"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 skipped" in result.stdout


def test_wrong_postgres_major_is_not_accepted():
    from tests.pg_cluster import find_postgres_bin

    binary = find_postgres_bin()
    if binary is None:
        pytest.skip("version check requires a local PostgreSQL installation")
    env = os.environ.copy()
    env.update(FFP_POSTGRES_BIN=str(binary), FFP_POSTGRES_MAJOR="999")
    result = subprocess.run(
        [sys.executable, "-c",
         "from tests.pg_cluster import find_postgres_bin; find_postgres_bin()"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert "major 999 required" in result.stderr
