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
    assert_performance_budget_with_remeasure,
    build_macos_ci_performance_evidence,
    build_windows_ci_performance_evidence,
    build_release_evidence,
    write_windows_ci_performance_evidence,
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


def test_windows_ci_evidence_keeps_only_the_redacted_measurement_contract() -> None:
    """Removing the whitelist would leak release/SBOM data into a CI artifact."""
    release_evidence = {
        "source": {"revision": "current-revision", "uv_lock_sha256": "lock-digest"},
        "artifacts": [{"name": "private-wheel.whl", "sha256": "artifact-digest"}],
        "sbom": {"components": [{"name": "private-component", "version": "1.0"}]},
        "performance_baseline": {
            "source_revision": "baseline-revision",
            "workload": "legacy-httpx-client/1",
            "performance": {
                "measurement_rounds": 9,
                "operations": 1000,
                "p95_operation_seconds": 0.005,
                "peak_memory_bytes": 110,
                "transport_instances": 1,
            },
        },
        "performance": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.005,
            "peak_memory_bytes": 110,
            "transport_instances": 1,
        },
    }

    evidence = build_windows_ci_performance_evidence(
        release_evidence,
        runner_os="Windows",
        python_version="3.11.9",
        uv_version="0.12.5",
    )

    assert evidence == {
        "schema_version": 1,
        "baseline": {
            "source_revision": "baseline-revision",
            "workload": "legacy-httpx-client/1",
        },
        "measurement": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.005,
            "peak_memory_bytes": 110,
            "transport_instances": 1,
        },
        "environment": {
            "runner_os": "Windows",
            "python_version": "3.11.9",
            "uv_version": "0.12.5",
        },
    }


def test_windows_ci_evidence_rejects_a_path_like_runtime_value() -> None:
    """Accepting this value could expose a CI worker's user directory."""
    release_evidence = {
        "performance_baseline": {
            "source_revision": "baseline-revision",
            "workload": "legacy-httpx-client/1",
        },
        "performance": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.005,
            "peak_memory_bytes": 110,
            "transport_instances": 1,
        },
    }

    with pytest.raises(ValueError, match="python version"):
        build_windows_ci_performance_evidence(
            release_evidence,
            runner_os="Windows",
            python_version="C:/Users/runneradmin",
            uv_version="0.12.5",
        )


def test_windows_ci_evidence_redacts_uv_build_metadata() -> None:
    """Raw uv build text could otherwise disclose platform-specific details."""
    release_evidence = {
        "performance_baseline": {
            "source_revision": "baseline-revision",
            "workload": "legacy-httpx-client/1",
        },
        "performance": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.005,
            "peak_memory_bytes": 110,
            "transport_instances": 1,
        },
    }

    evidence = build_windows_ci_performance_evidence(
        release_evidence,
        runner_os="Windows",
        python_version="3.11.9",
        uv_version="uv 0.12.5 (Homebrew 2026-08-14 aarch64-apple-darwin)",
    )

    assert evidence["environment"]["uv_version"] == "0.12.5"


def test_windows_ci_evidence_writes_only_the_redacted_artifact(tmp_path: Path) -> None:
    """A missing writer would leave Windows CI with no downloadable measurement."""
    output = tmp_path / "artifacts" / "windows-release-performance.json"
    release_evidence = {
        "source": {"revision": "current-revision"},
        "performance_baseline": {
            "source_revision": "baseline-revision",
            "workload": "legacy-httpx-client/1",
        },
        "performance": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.005,
            "peak_memory_bytes": 110,
            "transport_instances": 1,
        },
    }

    write_windows_ci_performance_evidence(
        release_evidence,
        output=output,
        runner_os="Windows",
        python_version="3.11.9",
        uv_version="0.12.5",
    )

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "baseline": {
            "source_revision": "baseline-revision",
            "workload": "legacy-httpx-client/1",
        },
        "measurement": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.005,
            "peak_memory_bytes": 110,
            "transport_instances": 1,
        },
        "environment": {
            "runner_os": "Windows",
            "python_version": "3.11.9",
            "uv_version": "0.12.5",
        },
    }


def test_release_baseline_cli_writes_the_optional_windows_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Dropping the CLI wiring would silently prevent the CI upload artifact."""
    full_evidence = {
        "source": {"revision": "current-revision", "uv_lock_sha256": "lock-digest"},
        "performance_baseline": {
            "source_revision": "baseline-revision",
            "workload": "legacy-httpx-client/1",
            "performance": {
                "measurement_rounds": 9,
                "operations": 1000,
                "p95_operation_seconds": 0.005,
                "peak_memory_bytes": 110,
                "transport_instances": 1,
            },
        },
        "performance": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.005,
            "peak_memory_bytes": 110,
            "transport_instances": 1,
        },
    }
    monkeypatch.setattr(release_baseline, "build_release_evidence", lambda **_kwargs: full_evidence)
    monkeypatch.setattr(
        release_baseline,
        "_package_metadata",
        lambda _package_root: ("techflex-cloud-foundation", "0.1.1"),
    )
    monkeypatch.setattr(release_baseline, "_git_revision", lambda _project_root: "current-revision")
    output = tmp_path / "release-evidence.json"
    windows_output = tmp_path / "windows-release-performance.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "record_foundation_release_baseline.py",
            "--project-root", str(tmp_path),
            "--dist-dir", str(tmp_path),
            "--output", str(output),
            "--baseline-strategy", "legacy-httpx-client/1",
            "--windows-ci-evidence-output", str(windows_output),
            "--runner-os", "Windows",
            "--python-version", "3.11.9",
            "--uv-version", "0.12.5",
        ],
    )

    assert release_baseline.main() == 0
    assert json.loads(windows_output.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "baseline": {
            "source_revision": "baseline-revision",
            "workload": "legacy-httpx-client/1",
        },
        "measurement": {
            "measurement_rounds": 9,
            "operations": 1000,
            "p95_operation_seconds": 0.005,
            "peak_memory_bytes": 110,
            "transport_instances": 1,
        },
        "environment": {
            "runner_os": "Windows",
            "python_version": "3.11.9",
            "uv_version": "0.12.5",
        },
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
    # The re-measurement must also fail, so the budget gate still raises.
    monkeypatch.setattr(
        release_baseline,
        "_run_comparable_workloads",
        lambda operations, *, baseline_strategy: (
            release_evidence["performance_baseline"]["performance"],
            release_evidence["performance"],
        ),
    )
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


def _evidence(p95: float, *, baseline_p95: float = 1.0) -> dict:
    return {
        "performance": {"p95_operation_seconds": p95, "peak_memory_bytes": 100},
        "performance_baseline": {
            "performance": {"p95_operation_seconds": baseline_p95, "peak_memory_bytes": 100}
        },
    }


def test_budget_remeasure_recovers_single_flake(monkeypatch, capsys) -> None:
    calls = 0

    def fake_workloads(operations: int, *, baseline_strategy: str):
        nonlocal calls
        calls += 1
        return (
            {"p95_operation_seconds": 1.0, "peak_memory_bytes": 100},
            {"p95_operation_seconds": 1.0, "peak_memory_bytes": 100},
        )

    monkeypatch.setattr(release_baseline, "_run_comparable_workloads", fake_workloads)

    assert_performance_budget_with_remeasure(
        _evidence(1.20), operations=10, baseline_strategy="legacy-httpx-client/1"
    )

    assert calls == 1
    assert "flaked once" in capsys.readouterr().err


def test_budget_remeasure_still_fails_real_regression(monkeypatch) -> None:
    def regressed_workloads(operations: int, *, baseline_strategy: str):
        return (
            {"p95_operation_seconds": 1.0, "peak_memory_bytes": 100},
            {"p95_operation_seconds": 1.20, "peak_memory_bytes": 100},
        )

    monkeypatch.setattr(
        release_baseline, "_run_comparable_workloads", regressed_workloads
    )

    with pytest.raises(ValueError, match="P95"):
        assert_performance_budget_with_remeasure(
            _evidence(1.20), operations=10, baseline_strategy="legacy-httpx-client/1"
        )


def test_benchmark_clock_is_process_time() -> None:
    assert release_baseline.BENCHMARK_CLOCK is release_baseline.time.process_time
