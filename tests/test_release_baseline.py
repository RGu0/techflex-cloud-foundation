from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from scripts import record_foundation_release_baseline as release_baseline
from scripts.record_foundation_release_baseline import (
    BENCHMARK_ROUNDS,
    aggregate_performance_samples,
    assert_performance_budget,
    build_macos_ci_performance_evidence,
    build_release_evidence,
)


def test_release_evidence_records_artifacts_and_reused_transport(tmp_path: Path) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text(
        """version = 1

[[package]]
name = "httpx"
version = "0.28.1"

[[package]]
name = "cryptography"
version = "50.0.0"
""",
        encoding="utf-8",
    )
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    (dist_dir / "techflex_cloud_foundation-0.1.1-py3-none-any.whl").write_bytes(b"wheel")

    evidence = build_release_evidence(
        package_name="techflex-cloud-foundation",
        package_version="0.1.1",
        source_revision="a" * 40,
        lockfile=lockfile,
        dist_dir=dist_dir,
        operations=4,
    )

    assert evidence["sbom"]["bomFormat"] == "CycloneDX"
    assert evidence["artifacts"][0]["sha256"] == (
        "ba59926159d2aa256eb8739b8da7e2b574b960e1202c6d624cbe981cef996c91"
    )
    assert evidence["performance"]["transport_instances"] == 1
    assert evidence["performance"]["measurement_rounds"] == BENCHMARK_ROUNDS
    json.dumps(evidence)


def test_release_evidence_records_the_pre_extraction_baseline(tmp_path: Path) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text("version = 1\n", encoding="utf-8")
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    (dist_dir / "foundation.whl").write_bytes(b"wheel")

    evidence = build_release_evidence(
        package_name="techflex-cloud-foundation",
        package_version="0.1.1",
        source_revision="b" * 40,
        lockfile=lockfile,
        dist_dir=dist_dir,
        operations=4,
    )

    assert evidence["performance_baseline"]["source_revision"] == (
        "6e76234f0ec466f4fa62f6368ea646ec8b37979e"
    )
    assert evidence["performance_baseline"]["workload"] == "legacy-httpx-client/1"


def test_performance_budget_rejects_threshold_excess() -> None:
    baseline = {"p95_operation_seconds": 1.0, "peak_memory_bytes": 100}

    with pytest.raises(ValueError, match="P95"):
        assert_performance_budget(
            {"p95_operation_seconds": 1.051, "peak_memory_bytes": 110}, baseline
        )

    with pytest.raises(ValueError, match="memory"):
        assert_performance_budget(
            {"p95_operation_seconds": 1.05, "peak_memory_bytes": 111}, baseline
        )


def test_performance_aggregate_uses_median_to_resist_single_round_noise() -> None:
    aggregate = aggregate_performance_samples(
        [
            {"operations": 200, "p95_operation_seconds": 0.001, "peak_memory_bytes": 100, "transport_instances": 1},
            {"operations": 200, "p95_operation_seconds": 0.002, "peak_memory_bytes": 200, "transport_instances": 1},
            {"operations": 200, "p95_operation_seconds": 0.100, "peak_memory_bytes": 9_000, "transport_instances": 1},
            {"operations": 200, "p95_operation_seconds": 0.004, "peak_memory_bytes": 400, "transport_instances": 1},
            {"operations": 200, "p95_operation_seconds": 0.005, "peak_memory_bytes": 500, "transport_instances": 1},
        ]
    )

    assert aggregate == {
        "operations": 200,
        "p95_operation_seconds": 0.004,
        "peak_memory_bytes": 400,
        "transport_instances": 1,
        "measurement_rounds": 5,
    }


def test_macos_ci_evidence_allowlists_comparable_performance_only() -> None:
    release_evidence = {
        "source": {"revision": "secret-source-revision"},
        "artifacts": [{"name": "secret-wheel.whl"}],
        "performance_baseline": {
            "source_revision": "6e76234f0ec466f4fa62f6368ea646ec8b37979e",
            "workload": "legacy-httpx-client/1",
            "performance": {
                "measurement_rounds": 9,
                "operations": 1000,
                "p95_operation_seconds": 0.001,
                "peak_memory_bytes": 256,
                "transport_instances": 1,
            },
        },
        "performance": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.00104,
            "peak_memory_bytes": 260,
            "transport_instances": 1,
        },
    }

    evidence = build_macos_ci_performance_evidence(
        release_evidence,
        runner_os="macOS",
        python_version="3.11.9",
        uv_version="uv 0.12.5 (Homebrew 2026-08-14 arm64-apple-darwin)",
    )

    assert evidence == {
        "schema_version": 1,
        "baseline": {
            "source_revision": "6e76234f0ec466f4fa62f6368ea646ec8b37979e",
            "workload": "legacy-httpx-client/1",
            "measurement": {
                "measurement_rounds": 9,
                "operations": 1000,
                "p95_operation_seconds": 0.001,
                "peak_memory_bytes": 256,
                "transport_instances": 1,
            },
        },
        "measurement": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.00104,
            "peak_memory_bytes": 260,
            "transport_instances": 1,
        },
        "environment": {
            "runner_os": "macOS",
            "python_version": "3.11.9",
            "uv_version": "0.12.5",
        },
    }
    serialized = json.dumps(evidence)
    assert "secret-source-revision" not in serialized
    assert "secret-wheel.whl" not in serialized


def test_macos_ci_evidence_is_written_before_a_budget_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release_evidence = {
        "performance_baseline": {
            "source_revision": "6e76234f0ec466f4fa62f6368ea646ec8b37979e",
            "workload": "legacy-httpx-client/1",
            "performance": {
                "measurement_rounds": 9,
                "operations": 1000,
                "p95_operation_seconds": 1.0,
                "peak_memory_bytes": 100,
                "transport_instances": 1,
            },
        },
        "performance": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 1.051,
            "peak_memory_bytes": 100,
            "transport_instances": 1,
        },
    }
    output = tmp_path / "release-evidence.json"
    macos_output = tmp_path / "macos-release-performance.json"
    monkeypatch.setattr(release_baseline, "build_release_evidence", lambda **_: release_evidence)
    monkeypatch.setattr(release_baseline, "_package_metadata", lambda _: ("foundation", "0.1.1"))
    monkeypatch.setattr(release_baseline, "_git_revision", lambda _: "f" * 40)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "record_foundation_release_baseline.py",
            "--project-root",
            str(tmp_path),
            "--dist-dir",
            str(tmp_path),
            "--output",
            str(output),
            "--baseline-strategy",
            "legacy-httpx-client/1",
            "--macos-ci-evidence-output",
            str(macos_output),
            "--runner-os",
            "macOS",
            "--python-version",
            "3.11.9",
            "--uv-version",
            "0.12.5",
        ],
    )

    with pytest.raises(ValueError, match="P95"):
        release_baseline.main()

    assert json.loads(macos_output.read_text(encoding="utf-8"))["measurement"][
        "p95_operation_seconds"
    ] == 1.051


def test_release_workflow_enforces_locked_audit_and_budget() -> None:
    workflow = Path(".github/workflows/quality.yml").read_text(encoding="utf-8")

    assert "pip-audit --strict" in workflow
    assert "--baseline-strategy legacy-httpx-client/1" in workflow
    assert "uv build --out-dir foundation-dist" in workflow
    assert "windows-latest" in workflow


def test_release_workflow_uploads_macos_diagnostics_after_a_budget_failure() -> None:
    workflow = Path(".github/workflows/quality.yml").read_text(encoding="utf-8")

    assert "macos-release-evidence:" in workflow
    assert "macos-latest" in workflow
    assert "--macos-ci-evidence-output ci-evidence/macos-release-performance.json" in workflow
    assert "name: macos-release-performance-evidence" in workflow
    assert "if: always()" in workflow
