"""Public contract tests for the hash-chained local audit log."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import threading

import pytest

from techflex_cloud_foundation import ChainedAppendLog


def _active(root: Path) -> Path:
    return root / "events.jsonl"


def test_append_and_verify_roundtrip(tmp_path: Path) -> None:
    log = ChainedAppendLog(tmp_path / "audit")
    first = log.append({"action": "open", "target": "session-1"})
    second = log.append({"action": "close", "target": "session-1"})

    assert first.previous_sha256 is None
    assert second.previous_sha256 == first.sha256

    records = log.verified_records()
    assert [record.payload["action"] for record in records] == ["open", "close"]
    assert records[1].sha256 == second.sha256


def test_chain_detects_tampered_record(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    log = ChainedAppendLog(root)
    log.append({"action": "open"})
    log.append({"action": "close"})

    path = _active(root)
    lines = path.read_bytes().splitlines()
    forged = json.loads(lines[0])
    forged["payload"]["action"] = "deleted-everything"
    path.write_bytes(
        json.dumps(forged).encode() + b"\n" + lines[1] + b"\n"
    )

    with pytest.raises(ValueError, match="invalid record digest"):
        log.verified_records()


def test_chain_detects_dropped_record(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    log = ChainedAppendLog(root)
    for index in range(3):
        log.append({"index": index})

    path = _active(root)
    lines = path.read_bytes().splitlines()
    path.write_bytes(lines[0] + b"\n" + lines[2] + b"\n")

    with pytest.raises(ValueError, match="broken record chain"):
        log.verified_records()


def test_startup_truncates_torn_final_line(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    log = ChainedAppendLog(root)
    log.append({"action": "complete"})
    with _active(root).open("ab") as handle:
        handle.write(b'{"payload": {"action": "torn')

    recovered = ChainedAppendLog(root)

    records = recovered.verified_records()
    assert [record.payload["action"] for record in records] == ["complete"]


def test_rotation_preserves_chain_across_generations(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    log = ChainedAppendLog(root, max_generation_bytes=800, generations=3)
    for index in range(12):
        log.append({"index": index})

    assert (root / "events.1.jsonl").exists()
    records = log.verified_records()
    assert [record.payload["index"] for record in records] == list(range(12))


def test_rotation_drops_oldest_generation(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    log = ChainedAppendLog(root, max_generation_bytes=120, generations=2)
    for index in range(20):
        log.append({"index": index})

    records = log.verified_records()
    assert records[-1].payload["index"] == 19
    assert len(records) < 20
    for left, right in zip(records, records[1:]):
        assert right.previous_sha256 == left.sha256


def test_append_rejects_non_canonical_payload(tmp_path: Path) -> None:
    log = ChainedAppendLog(tmp_path / "audit")

    with pytest.raises(ValueError):
        log.append({"reading": float("nan")})


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode")
def test_log_files_are_owner_only(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    log = ChainedAppendLog(root)
    log.append({"action": "open"})

    assert (_active(root).stat().st_mode & 0o777) == 0o600
    assert ((root / ".events.lock").stat().st_mode & 0o777) == 0o600


def test_append_propagates_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = ChainedAppendLog(tmp_path / "audit")

    def failing_fsync(descriptor: int) -> None:
        raise OSError(errno.EIO, "fsync failed")

    monkeypatch.setattr(os, "fsync", failing_fsync)

    with pytest.raises(OSError, match="fsync failed"):
        log.append({"action": "unflushed"})


def test_append_propagates_disk_full_and_log_stays_verifiable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "audit"
    log = ChainedAppendLog(root)
    log.append({"action": "complete"})

    def disk_full(descriptor: int, data: bytes | memoryview) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "write", disk_full)
    with pytest.raises(OSError, match="No space left"):
        log.append({"action": "never-landed"})
    monkeypatch.undo()

    recovered = ChainedAppendLog(root)
    assert [r.payload["action"] for r in recovered.verified_records()] == ["complete"]


def test_concurrent_instances_serialize_appends(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    ChainedAppendLog(root).append({"action": "seed"})
    logs = [ChainedAppendLog(root) for _ in range(4)]

    def worker(log: ChainedAppendLog, offset: int) -> None:
        for index in range(10):
            log.append({"worker": offset, "index": index})

    threads = [
        threading.Thread(target=worker, args=(log, offset))
        for offset, log in enumerate(logs)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    records = ChainedAppendLog(root).verified_records()
    assert len(records) == 41
    assert records[0].payload["action"] == "seed"


def test_configuration_is_validated(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="max_generation_bytes"):
        ChainedAppendLog(tmp_path / "a", max_generation_bytes=0)
    with pytest.raises(ValueError, match="generations"):
        ChainedAppendLog(tmp_path / "b", generations=0)
