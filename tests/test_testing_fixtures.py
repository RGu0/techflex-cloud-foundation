"""Contract tests for the shared durability fault-injection fixtures."""

from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

from techflex_cloud_foundation import atomic_write
from techflex_cloud_foundation.testing import (
    KillAndRecoverHarness,
    SimulatedPowerLoss,
    disk_full,
    fsync_failure,
    interrupted_replace,
    run_child_command,
    short_write_os,
)


def test_short_write_forces_partial_writes(tmp_path: Path) -> None:
    destination = tmp_path / "payload.bin"
    payload = bytes(range(256)) * 32

    with short_write_os(7):
        atomic_write(destination, payload)

    assert destination.read_bytes() == payload


def test_disk_full_rejects_all_writes(tmp_path: Path) -> None:
    destination = tmp_path / "payload.bin"

    with disk_full():
        with pytest.raises(OSError, match="No space left"):
            atomic_write(destination, b"data")

    assert not destination.exists()


def test_fsync_failure_is_injectable(tmp_path: Path) -> None:
    destination = tmp_path / "payload.bin"

    with fsync_failure():
        with pytest.raises(OSError, match="fsync"):
            atomic_write(destination, b"data")

    atomic_write(destination, b"data")
    assert destination.read_bytes() == b"data"


def test_interrupted_replace_preserves_destination(tmp_path: Path) -> None:
    destination = tmp_path / "payload.bin"
    destination.write_bytes(b"original")

    with interrupted_replace():
        with pytest.raises(OSError, match="rename interruption"):
            atomic_write(destination, b"replacement")

    assert destination.read_bytes() == b"original"


def test_fault_injection_restores_and_refuses_double_install(tmp_path: Path) -> None:
    fault = disk_full()
    fault.install()
    with pytest.raises(ValueError, match="already installed"):
        fault.install()
    fault.restore()
    fault.restore()  # idempotent

    target = tmp_path / "restored.bin"
    descriptor = os.open(target, os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        assert os.write(descriptor, b"ok") == 2
    finally:
        os.close(descriptor)


def test_simulated_power_loss_raises_at_chosen_boundary(tmp_path: Path) -> None:
    calls: list[str] = []

    class Recorder:
        def commit(self) -> None:
            calls.append("commit")

    recorder = Recorder()
    loss = SimulatedPowerLoss(recorder, "commit", on_call=2)

    with loss:
        recorder.commit()
        with pytest.raises(SystemExit, match="simulated power loss"):
            recorder.commit()

    assert loss.calls == 2
    recorder.commit()
    assert calls == ["commit", "commit"]


def test_simulated_power_loss_validates_boundary() -> None:
    with pytest.raises(ValueError, match="on_call"):
        SimulatedPowerLoss(object(), "missing", on_call=0)


def test_kill_and_recover_harness(tmp_path: Path) -> None:
    marker = tmp_path / "child-ready"
    child_script = (
        "import pathlib, time, sys;"
        f"pathlib.Path({str(marker)!r}).write_text('ready');"
        "time.sleep(60)"
    )
    recovered: list[bool] = []

    harness = KillAndRecoverHarness(
        spawn=lambda: run_child_command([sys.executable, "-c", child_script]),
        ready=marker.exists,
        recover=lambda: recovered.append(True),
        ready_timeout_seconds=20,
    )

    result = harness.run()

    assert result.recovery_completed is True
    assert result.child_returncode != 0
    assert recovered == [True]


def test_kill_and_recover_refuses_unready_child(tmp_path: Path) -> None:
    child_script = "import time; time.sleep(60)"
    process_ref: list[object] = []

    def spawn() -> object:
        process = run_child_command([sys.executable, "-c", child_script])
        process_ref.append(process)
        return process

    harness = KillAndRecoverHarness(
        spawn=spawn,  # type: ignore[arg-type]
        ready=lambda: False,
        recover=lambda: None,
        ready_timeout_seconds=0.5,
        poll_interval_seconds=0.05,
    )

    with pytest.raises(TimeoutError, match="never reached"):
        harness.run()
