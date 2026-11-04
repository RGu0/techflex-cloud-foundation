"""Imported PostgreSQL fixtures must honor availability without hiding memory tests."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("required", [False, True])
def test_registry_http_tests_without_postgres_keep_memory_coverage(required, tmp_path):
    environment = os.environ.copy()
    environment.pop("PYTEST_ADDOPTS", None)
    environment["FFP_REQUIRE_POSTGRES"] = "1" if required else "0"
    environment["FFP_POSTGRES_BIN"] = str(tmp_path / "missing")
    result = subprocess.run(
        [sys.executable, "-c", (
            # This test isolates fixture behavior. Collection-time rejection is
            # exercised separately by test_postgres_required_gate on real modules.
            "import os, pytest; "
            "required = os.environ['FFP_REQUIRE_POSTGRES']; "
            "os.environ['FFP_REQUIRE_POSTGRES'] = '0'; "
            "import tests.test_ffp_postgres_platform_live as live; "
            "live.BIN = None; "
            "os.environ['FFP_REQUIRE_POSTGRES'] = required; "
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
