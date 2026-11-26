"""RAY-1029 R1: nothing but the seed service start changes the runtime venv.

``venv-python.sh`` syncs only when ``FEETFORCEPLATE_VENV_SYNC=1`` and then
records the runtime lock's digest in the venv; every other caller only
verifies that record and refuses a stale or unsynced venv without touching it.
Live acceptance builds and removes its own private venv.  The behavioural
tests run the real script against a fake ``uv`` that records each call.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parents[1]
SEED = REPO / "deploy/aliyun/seed"
RUNTIME_VENV = "/var/lib/feetforceplate/runtime/venv"
ACCEPTANCE_VENV = "/var/lib/feetforceplate/acceptance/venv"

posix_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the seed runtime helper is a Linux host script",
)


class _Host:
    """A release tree with the real helper, a runtime lock, a venv and a fake uv."""

    def __init__(self, root: Path) -> None:
        self.release = root / "release"
        seed = self.release / "deploy/aliyun/seed"
        (seed / "runtime").mkdir(parents=True)
        shutil.copy2(SEED / "venv-python.sh", seed / "venv-python.sh")
        self.helper = seed / "venv-python.sh"
        self.lock = seed / "runtime/uv.lock"
        self.lock.write_text("version = 1\n# runtime lock\n")
        self.venv = root / "venv"
        (self.venv / "bin").mkdir(parents=True)
        (self.venv / "bin/python").symlink_to(sys.executable)
        self.stamp = self.venv / ".feetforceplate-runtime-lock.sha256"
        self.bin = root / "bin"
        self.bin.mkdir()
        self.calls = root / "uv-calls"
        uv = self.bin / "uv"
        uv.write_text(
            "#!/usr/bin/env bash\n"
            'printf "%s|env=%s|offline=%s\\n" "$*" "$UV_PROJECT_ENVIRONMENT" "$UV_OFFLINE" >> '
            f'"{self.calls}"\n'
            f'touch "{self.venv}/synced-by-uv"\n'
        )
        uv.chmod(0o755)

    def run(self, **env: str) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "FEETFORCEPLATE_VENV": str(self.venv),
            **env,
        }
        return subprocess.run(
            ["bash", str(self.helper), "-c", "import os; print('ran', os.getcwd())"],
            env=environment, capture_output=True, text=True, check=False,
        )

    def uv_calls(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def snapshot(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.venv)): path.read_bytes() if path.is_file() else b"<dir>"
            for path in sorted(self.venv.rglob("*"))
            if not path.is_symlink()
        }

    def lock_digest(self) -> str:
        return hashlib.sha256(self.lock.read_bytes()).hexdigest()


@pytest.fixture
def host(tmp_path: Path) -> _Host:
    return _Host(tmp_path)


# --- verify mode (timers, CLIs): never syncs, never changes the venv ---------


@posix_bash
def test_verify_mode_refuses_an_unsynced_venv_without_touching_it(host: _Host) -> None:
    before = host.snapshot()
    result = host.run()
    assert result.returncode == 3, result.stderr
    assert "has not been synced by the seed service" in result.stderr
    assert host.uv_calls() == []
    assert host.snapshot() == before


@posix_bash
def test_verify_mode_refuses_a_venv_synced_for_another_lock(host: _Host) -> None:
    host.stamp.write_text("0" * 64 + "\n")
    before = host.snapshot()
    result = host.run()
    assert result.returncode == 3, result.stderr
    assert "does not match this release's runtime lock" in result.stderr
    assert host.uv_calls() == []
    assert host.snapshot() == before


@posix_bash
def test_verify_mode_runs_from_a_matching_venv_without_syncing(host: _Host) -> None:
    host.stamp.write_text(host.lock_digest() + "\n")
    before = host.snapshot()
    result = host.run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"ran {host.release}"
    assert host.uv_calls() == []
    assert host.snapshot() == before


@posix_bash
def test_the_acceptance_group_is_refused_outside_sync_mode(host: _Host) -> None:
    host.stamp.write_text(host.lock_digest() + "\n")
    before = host.snapshot()
    result = host.run(FEETFORCEPLATE_ACCEPTANCE="1")
    assert result.returncode == 2
    assert "needs FEETFORCEPLATE_VENV_SYNC=1" in result.stderr
    assert host.uv_calls() == []
    assert host.snapshot() == before


# --- sync mode (service start, private acceptance venv) ---------------------


@posix_bash
def test_sync_mode_syncs_offline_and_records_the_lock_digest(host: _Host) -> None:
    result = host.run(FEETFORCEPLATE_VENV_SYNC="1")
    assert result.returncode == 0, result.stderr
    (call,) = host.uv_calls()
    assert call.startswith("sync --frozen --no-dev --quiet --project ")
    assert call.endswith(f"|env={host.venv}|offline=1")
    assert "--group acceptance" not in call
    assert host.stamp.read_text().strip() == host.lock_digest()
    # A verify-mode caller (a timer) now runs without syncing again.
    assert host.run().returncode == 0
    assert len(host.uv_calls()) == 1


@posix_bash
def test_sync_mode_with_acceptance_adds_the_group(host: _Host) -> None:
    result = host.run(FEETFORCEPLATE_VENV_SYNC="1", FEETFORCEPLATE_ACCEPTANCE="1")
    assert result.returncode == 0, result.stderr
    (call,) = host.uv_calls()
    assert "sync --frozen --no-dev --group acceptance --quiet" in call


@posix_bash
def test_a_new_release_lock_needs_the_service_to_sync_first(host: _Host) -> None:
    assert host.run(FEETFORCEPLATE_VENV_SYNC="1").returncode == 0
    host.lock.write_text("version = 1\n# next release\n")
    assert host.run().returncode == 3  # a timer before the service restart refuses
    assert host.run(FEETFORCEPLATE_VENV_SYNC="1").returncode == 0  # service restart
    assert host.run().returncode == 0


# --- who syncs: only the service start and the private acceptance venv -----


def _text(name: str) -> str:
    return (SEED / name).read_text(encoding="utf-8")


def test_only_the_seed_service_start_syncs_the_runtime_venv() -> None:
    assert "export FEETFORCEPLATE_VENV_SYNC=1" in _text("run-seed.sh")
    for name in (
        "backup.sh", "feetforceplate-backup.service", "feetforceplate-diagnostics-purge.service",
        "feetforceplate-sales-inventory-server.sh", "feetforceplate-seed.service",
        "install-seed-release.sh",
    ):
        assert "FEETFORCEPLATE_VENV_SYNC" not in _text(name), name
        assert "FEETFORCEPLATE_ACCEPTANCE" not in _text(name), name


def test_live_acceptance_never_uses_the_runtime_venv() -> None:
    text = _text("run-live-acceptance.sh")
    assert RUNTIME_VENV not in text
    venvs = re.findall(r"export FEETFORCEPLATE_VENV=(\S+)", text)
    assert venvs and set(venvs) == {ACCEPTANCE_VENV}
    # Every block that names the private venv owns it: sync mode with the acceptance group.
    for block in text.split("runuser -u")[1:]:
        if "FEETFORCEPLATE_VENV=" in block:
            assert "export FEETFORCEPLATE_VENV_SYNC=1" in block
            assert "export FEETFORCEPLATE_ACCEPTANCE=1" in block
    assert 'acceptance_venv="$acceptance_root/venv"' in text
    assert 'acceptance_root="/var/lib/feetforceplate/acceptance"' in text
    # A stale private venv from an interrupted run is replaced, never reused.
    assert text.index('rm -rf -- "$acceptance_venv"') < text.index("run_seed_python before-restart")


@posix_bash
@pytest.mark.parametrize("exit_status", [0, 1])
def test_acceptance_cleanup_removes_the_private_venv_on_pass_and_fail(
    tmp_path: Path, exit_status: int,
) -> None:
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    state = tmp_path / "private-state.json"
    state.write_text("private")
    marker = tmp_path / "restart-complete"
    result = subprocess.run(
        ["bash", "-c", 'source "$1"; acceptance_cleanup "$2" "$3" "$4" "$5"', "bash",
         str(SEED / "run-live-acceptance.sh"), str(exit_status), str(state), str(marker),
         str(venv)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not venv.exists()
    assert state.exists() is (exit_status != 0)  # the resume state keeps its old rule


def test_installer_syncs_through_the_service_before_any_verify_mode_consumer() -> None:
    text = _text("install-seed-release.sh")
    restart = text.index("systemctl restart feetforceplate-seed.service")
    ready = text.index("https://127.0.0.1:17443/health/ready", restart)
    for consumer in (
        "systemctl start feetforceplate-backup.service",
        "systemctl start feetforceplate-backup.timer",
        "systemctl start feetforceplate-diagnostics-purge.timer",
    ):
        assert ready < text.index(consumer, restart), consumer
