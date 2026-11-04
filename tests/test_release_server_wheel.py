"""Opt-in acceptance of a retained server wheel, outside the source checkout."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_retained_server_wheel(tmp_path: Path) -> None:
    artifact = os.environ.get("FOUNDATION_CANDIDATE_WHEEL")
    if not artifact:
        pytest.skip("retained candidate wheel not configured")
    from tests.pg_cluster import find_postgres_bin

    assert find_postgres_bin() is not None, "wheel acceptance requires real PostgreSQL"
    wheel = Path(artifact).resolve(strict=True)
    uv = shutil.which("uv")
    assert uv is not None
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("FOUNDATION_CANDIDATE_WHEEL", None)
    environment["FFP_REQUIRE_POSTGRES"] = "1"
    for tree in ("tests", "docs", "scripts"):
        shutil.copytree(ROOT / tree, consumer / tree,
                        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    python = consumer / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([uv, "venv", "--python", sys.executable, str(consumer / ".venv")],
                   check=True, env=environment, capture_output=True, text=True)
    subprocess.run([uv, "pip", "install", "--python", str(python),
                    f"{wheel}[server]", "pytest>=8,<10"],
                   check=True, env=environment, capture_output=True, text=True)
    probe = subprocess.run([str(python), "-c", """
import importlib.metadata, json
from pathlib import Path
import techflex_cloud_foundation as package
from techflex_cloud_foundation.schema import DEFAULT_PLAN
path = Path(package.__file__).resolve()
assert '.venv' in path.parts, path
assert importlib.metadata.version('techflex-cloud-foundation') == '0.9.1'
assert any(s.step_id == '0021_registry_ingestion' for s in DEFAULT_PLAN)
print(json.dumps({'version': '0.9.1', 'installed_path': str(path),
                  'schema_steps': [s.step_id for s in DEFAULT_PLAN]}))
"""], cwd=consumer, env=environment, capture_output=True, text=True, check=True)
    selected = [
        "tests/test_registry_http_ingestion.py",
        "tests/test_registry_http_authorization.py",
        "tests/test_registry_0020_upgrade.py",
        "tests/test_registry_postgres_invariants.py",
        "tests/test_registry_ingestion_http.py",
        "tests/test_registered_public_compatibility.py",
        "tests/test_ray830_pre_cutover_smoke.py",
        "tests/test_ffp_insole_session_archive.py::InsoleArchiveContractTests",
        "tests/test_ffp_insole_session_archive.py::InsoleArchiveApiTests",
        "tests/test_ffp_ray815_data_plane_smoke.py",
        "tests/test_ffp_ray825_insole_archive_smoke.py",
        "tests/test_ffp_ray907_subject_sync_smoke.py",
        "tests/test_ffp_terminal_diagnostics_api.py",
    ]
    assert all((consumer / name.split("::")[0]).exists() for name in selected)
    result = subprocess.run([str(python), "-m", "pytest", "-ra", "-o", "pythonpath=.",
                             "--junitxml=wheel-results.xml", *selected],
                            cwd=consumer, env=environment,
                            capture_output=True, text=True)
    suites = ET.parse(consumer / "wheel-results.xml").getroot()
    cases = list(suites.iter("testcase"))
    skipped = list(suites.iter("skipped"))
    record = {"executed_cases": len(cases), "skipped_cases": len(skipped),
              "wheel": str(wheel), "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
              "probe": json.loads(probe.stdout), "test_files": selected,
              "returncode": result.returncode, "stdout": result.stdout,
              "stderr": result.stderr}
    output = os.environ.get("FOUNDATION_CANDIDATE_REPORT")
    if output:
        destination = Path(output)
        assert not destination.exists(), "candidate reports must not be overwritten"
        destination.write_text(json.dumps(record, indent=2) + "\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(cases) >= 99 and not skipped, "wheel acceptance must execute all database cases"


    predecessor = os.environ.get("FOUNDATION_PREDECESSOR_WHEEL")
    if predecessor:
        import asyncpg

        from tests.pg_cluster import running_cluster

        old_wheel = Path(predecessor).resolve(strict=True)
        old_python = consumer / "old" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run([uv, "venv", "--python", sys.executable, str(consumer / "old")],
                       check=True, env=environment, capture_output=True, text=True)
        subprocess.run([uv, "pip", "install", "--python", str(old_python),
                        f"{old_wheel}[server]", "pytest>=8,<10"],
                       check=True, env=environment, capture_output=True, text=True)
        bin_dir = find_postgres_bin()
        assert bin_dir is not None, "real predecessor upgrade requires PostgreSQL"
        phases = []
        import asyncio
        for encoding in ("UTF8", "SQL_ASCII"):
            with running_cluster(bin_dir) as cluster:
                settings = dict(host=cluster.socket_dir, port=cluster.port, user="postgres")

                async def create_database(settings=settings, encoding=encoding):
                    connection = await asyncpg.connect(**settings, database="postgres")
                    try:
                        await connection.execute(
                            "CREATE DATABASE wheel_upgrade TEMPLATE template0 "
                            f"ENCODING '{encoding}' LC_COLLATE 'C' LC_CTYPE 'C'")
                    finally:
                        await connection.close()
                asyncio.run(create_database())
                phase_env = {**environment, "WHEEL_UPGRADE_DB": json.dumps(
                    {**settings, "database": "wheel_upgrade"}), "PYTHONPATH": str(consumer)}
                for phase, interpreter in (("old", old_python), ("new", python),
                                           ("restart", python)):
                    run = subprocess.run([str(interpreter), "-m", "tests.wheel_upgrade_program",
                                          phase, str(consumer / "state.json")],
                                         cwd=consumer, env=phase_env,
                                         capture_output=True, text=True)
                    phases.append({"encoding": encoding, "phase": phase,
                                   "returncode": run.returncode, "stdout": run.stdout,
                                   "stderr": run.stderr})
                    if output:
                        upgrade_report = Path(output).with_suffix(".upgrade.json")
                        upgrade_report.write_text(json.dumps({"predecessor_sha256":
                            hashlib.sha256(old_wheel.read_bytes()).hexdigest(),
                            "candidate_sha256": record["sha256"], "phases": phases}, indent=2))
                    assert run.returncode == 0, run.stdout + run.stderr
