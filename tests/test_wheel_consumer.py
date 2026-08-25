from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess


PROJECT_ROOT = Path(__file__).parents[1]


def _uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required for the clean artifact-consumer test")
    return uv


def build_one_wheel(dist_dir: Path) -> Path:
    subprocess.run(
        [_uv(), "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return next(dist_dir.glob("*.whl"))


def create_consumer_project(consumer_dir: Path, wheel: Path) -> Path:
    consumer_dir.mkdir()
    (consumer_dir / "pyproject.toml").write_text(
        "\n".join(
            (
                "[project]",
                'name = "foundation-artifact-consumer"',
                'version = "0.0.0"',
                'requires-python = ">=3.11"',
                "dependencies = [",
                f'  "techflex-cloud-foundation @ {wheel.resolve().as_uri()}",',
                "]",
                "",
            )
        ),
        encoding="utf-8",
    )
    shutil.copy2(PROJECT_ROOT / "tests/consumer_program.py", consumer_dir / "consumer_program.py")
    return consumer_dir


def run_consumer(consumer_dir: Path, program: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["FOUNDATION_SOURCE_ROOT"] = str(PROJECT_ROOT.resolve())
    subprocess.run(
        [_uv(), "lock"],
        cwd=consumer_dir,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return subprocess.run(
        [_uv(), "run", "--locked", "python", program.name],
        cwd=consumer_dir,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_wheel_consumer_runs_without_source_tree_on_pythonpath(tmp_path: Path) -> None:
    wheel = build_one_wheel(tmp_path / "dist")
    consumer = create_consumer_project(tmp_path / "consumer", wheel)

    result = run_consumer(consumer, Path("tests/consumer_program.py"))

    assert result.returncode == 0, result.stderr
