"""Imported PostgreSQL fixtures must honor availability without hiding memory tests."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("required", [False, True])
def test_registry_http_tests_without_postgres_keep_memory_coverage(required):
    environment = os.environ.copy()
    environment.pop("PYTEST_ADDOPTS", None)
    environment["FFP_REQUIRE_POSTGRES"] = "1" if required else "0"
    result = subprocess.run(
        [sys.executable, "-c", (
            "import pytest; "
            "import tests.test_ffp_postgres_platform_live as live; "
            "live.BIN = None; "
            "raise SystemExit(pytest.main(['tests/test_registry_http_ingestion.py', '-q']))"
        )],
        cwd=Path(__file__).resolve().parents[1], env=environment,
        capture_output=True, text=True, check=False,
    )
    assert "4 passed" in result.stdout, result.stdout + result.stderr
    if required:
        assert result.returncode == 1, result.stdout + result.stderr
        assert "7 errors" in result.stdout, result.stdout
        assert "FFP_REQUIRE_POSTGRES=1" in result.stdout, result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "7 skipped" in result.stdout, result.stdout
