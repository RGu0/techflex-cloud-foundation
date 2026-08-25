#!/usr/bin/env python3
"""Create non-secret supply-chain and performance evidence for the foundation package."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from statistics import median
import subprocess
import time
import tomllib
import tracemalloc
from typing import Any

import httpx

from techflex_cloud_foundation import SecureTransport


PRE_EXTRACTION_BASELINE_REVISION = "6e76234f0ec466f4fa62f6368ea646ec8b37979e"
"""Last default-branch revision before the foundation extraction (PR #8)."""

LEGACY_HTTPX_WORKLOAD = "legacy-httpx-client/1"
BENCHMARK_ROUNDS = 5


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _locked_components(lockfile: Path) -> list[dict[str, str]]:
    lock = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    components = [
        {"type": "library", "name": package["name"], "version": package["version"]}
        for package in lock.get("package", [])
        if "name" in package and "version" in package
    ]
    return sorted(components, key=lambda component: (component["name"], component["version"]))


def _run_transport_workload(
    operations: int, *, baseline_strategy: str | None = None
) -> dict[str, float | int]:
    if operations < 1:
        raise ValueError("operations must be positive")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, request=request)

    durations: list[float] = []
    tracemalloc.start()
    try:
        client_kwargs = {
            "base_url": "https://benchmark.invalid",
            "transport": httpx.MockTransport(handler),
            "trust_env": False,
            "timeout": httpx.Timeout(connect=5, read=20, write=20, pool=5),
        }
        if baseline_strategy == LEGACY_HTTPX_WORKLOAD:
            transport = httpx.Client(**client_kwargs)
        elif baseline_strategy is None:
            transport = SecureTransport(
                "https://benchmark.invalid",
                transport=client_kwargs["transport"],
            )
        else:
            raise ValueError(f"unsupported performance baseline strategy: {baseline_strategy}")
        with transport:
            for _ in range(operations):
                started_at = time.perf_counter()
                response = transport.request(
                    "POST",
                    "/v1/operation",
                    content=b"benchmark",
                    headers={"X-Correlation-ID": "release-benchmark"},
                )
                response.raise_for_status()
                durations.append(time.perf_counter() - started_at)
        _current, peak_memory = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    p95_index = max(0, (len(durations) * 95 + 99) // 100 - 1)
    return {
        "operations": operations,
        "p95_operation_seconds": sorted(durations)[p95_index],
        "peak_memory_bytes": peak_memory,
        "transport_instances": 1,
    }


def aggregate_performance_samples(
    samples: list[dict[str, float | int]],
) -> dict[str, float | int]:
    """Use median runs so one scheduler interruption cannot fail a release."""
    if not samples:
        raise ValueError("performance samples must not be empty")
    operations = {sample["operations"] for sample in samples}
    transport_instances = {sample["transport_instances"] for sample in samples}
    if len(operations) != 1 or len(transport_instances) != 1:
        raise ValueError("performance samples must use one workload configuration")
    return {
        "operations": operations.pop(),
        "p95_operation_seconds": median(
            float(sample["p95_operation_seconds"]) for sample in samples
        ),
        "peak_memory_bytes": int(
            median(int(sample["peak_memory_bytes"]) for sample in samples)
        ),
        "transport_instances": transport_instances.pop(),
        "measurement_rounds": len(samples),
    }


def _run_comparable_workloads(
    operations: int, *, baseline_strategy: str
) -> tuple[dict[str, float | int], dict[str, float | int]]:
    baseline_samples: list[dict[str, float | int]] = []
    current_samples: list[dict[str, float | int]] = []
    for _ in range(BENCHMARK_ROUNDS):
        baseline_samples.append(
            _run_transport_workload(operations, baseline_strategy=baseline_strategy)
        )
        current_samples.append(_run_transport_workload(operations))
    return (
        aggregate_performance_samples(baseline_samples),
        aggregate_performance_samples(current_samples),
    )


def build_release_evidence(
    *,
    package_name: str,
    package_version: str,
    source_revision: str,
    lockfile: Path,
    dist_dir: Path,
    operations: int,
    baseline_strategy: str = LEGACY_HTTPX_WORKLOAD,
) -> dict[str, Any]:
    artifacts = [
        {"name": artifact.name, "sha256": _sha256(artifact), "size_bytes": artifact.stat().st_size}
        for artifact in sorted(dist_dir.iterdir())
        if artifact.is_file()
    ]
    if not artifacts:
        raise ValueError("distribution directory contains no artifacts")
    baseline_performance, performance = _run_comparable_workloads(
        operations, baseline_strategy=baseline_strategy
    )
    return {
        "schema_version": 1,
        "source": {"revision": source_revision, "uv_lock_sha256": _sha256(lockfile)},
        "artifacts": artifacts,
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": package_name, "type": "library", "version": package_version}},
            "components": _locked_components(lockfile),
        },
        "performance_baseline": {
            "source_revision": PRE_EXTRACTION_BASELINE_REVISION,
            "workload": baseline_strategy,
            "performance": baseline_performance,
        },
        "performance": performance,
    }


def assert_performance_budget(
    current: dict[str, float | int], baseline: dict[str, float | int]
) -> None:
    if current["p95_operation_seconds"] > baseline["p95_operation_seconds"] * 1.05:
        raise ValueError("P95 operation overhead regressed by more than 5%")
    if current["peak_memory_bytes"] > baseline["peak_memory_bytes"] * 1.10:
        raise ValueError("peak memory regressed by more than 10%")


def _package_metadata(package_root: Path) -> tuple[str, str]:
    project = tomllib.loads((package_root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return project["name"], project["version"]


def _git_revision(project_root: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--package-root", type=Path, default=Path("."))
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=200)
    parser.add_argument(
        "--baseline-strategy",
        choices=(LEGACY_HTTPX_WORKLOAD,),
        required=True,
    )
    arguments = parser.parse_args()
    project_root = arguments.project_root.resolve()
    package_root = (project_root / arguments.package_root).resolve()
    package_name, package_version = _package_metadata(package_root)
    evidence = build_release_evidence(
        package_name=package_name,
        package_version=package_version,
        source_revision=_git_revision(project_root),
        lockfile=project_root / "uv.lock",
        dist_dir=(project_root / arguments.dist_dir).resolve(),
        operations=arguments.operations,
        baseline_strategy=arguments.baseline_strategy,
    )
    baseline = evidence["performance_baseline"]["performance"]
    assert_performance_budget(evidence["performance"], baseline)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
