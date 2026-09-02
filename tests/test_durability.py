"""Public contract tests for the durable local write primitives."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    StagedAtomicFileWriter,
    atomic_write,
    fsync_directory,
    set_private_file_mode,
    write_all,
)


def test_atomic_write_publishes_complete_payload(tmp_path: Path) -> None:
    destination = tmp_path / "payload.bin"

    atomic_write(destination, b"complete-payload")

    assert destination.read_bytes() == b"complete-payload"
    assert list(tmp_path.glob("*.tmp")) == []


def test_atomic_write_replaces_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "payload.bin"
    destination.write_bytes(b"old")

    atomic_write(destination, b"new")

    assert destination.read_bytes() == b"new"


def test_atomic_write_requires_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="destination directory"):
        atomic_write(tmp_path / "missing" / "payload.bin", b"data")


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode")
def test_atomic_write_applies_private_file_mode(tmp_path: Path) -> None:
    destination = tmp_path / "secret.bin"

    atomic_write(destination, b"secret")

    assert (destination.stat().st_mode & 0o777) == 0o600


def test_atomic_write_survives_short_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "payload.bin"
    payload = bytes(range(256)) * 64
    real_write = os.write

    def short_write(descriptor: int, data: bytes | memoryview) -> int:
        return real_write(descriptor, data[:7])

    monkeypatch.setattr(os, "write", short_write)

    atomic_write(destination, payload)

    assert destination.read_bytes() == payload


def test_atomic_write_cleans_up_when_disk_is_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "payload.bin"

    def disk_full(descriptor: int, data: bytes | memoryview) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "write", disk_full)

    with pytest.raises(OSError, match="No space left"):
        atomic_write(destination, b"never-complete")

    assert not destination.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_atomic_write_cleans_up_when_fsync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "payload.bin"

    def failing_fsync(descriptor: int) -> None:
        raise OSError(errno.EIO, "fsync failed")

    monkeypatch.setattr(os, "fsync", failing_fsync)

    with pytest.raises(OSError, match="fsync failed"):
        atomic_write(destination, b"unflushed")

    assert not destination.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_atomic_write_preserves_destination_when_rename_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "payload.bin"
    destination.write_bytes(b"previous")

    def failing_replace(source: object, target: object) -> None:
        raise OSError("rename interrupted")

    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(OSError, match="rename interrupted"):
        atomic_write(destination, b"replacement")

    assert destination.read_bytes() == b"previous"
    assert list(tmp_path.glob("*.tmp")) == []


def test_staged_writer_streams_chunks_before_commit(tmp_path: Path) -> None:
    destination = tmp_path / "stream.bin"
    writer = StagedAtomicFileWriter(destination)

    assert writer.write(b"part-1") == 6
    assert writer.write(b"part-2") == 6
    assert not destination.exists()

    assert writer.commit() == destination
    assert destination.read_bytes() == b"part-1part-2"


def test_staged_writer_rejects_use_after_finish(tmp_path: Path) -> None:
    destination = tmp_path / "stream.bin"
    writer = StagedAtomicFileWriter(destination)
    writer.write(b"data")
    writer.commit()

    with pytest.raises(ValueError, match="already committed or aborted"):
        writer.write(b"more")
    with pytest.raises(ValueError, match="already committed or aborted"):
        writer.commit()


def test_staged_writer_abort_discards_temporary_file(tmp_path: Path) -> None:
    destination = tmp_path / "stream.bin"
    writer = StagedAtomicFileWriter(destination)
    writer.write(b"discard-me")
    temporary = writer.temporary_path

    writer.abort()

    assert not temporary.exists()
    assert not destination.exists()
    writer.abort()


def test_staged_writer_context_manager_commits_or_aborts(tmp_path: Path) -> None:
    committed = tmp_path / "committed.bin"
    with StagedAtomicFileWriter(committed) as writer:
        writer.write(b"via-context")
    assert committed.read_bytes() == b"via-context"

    aborted = tmp_path / "aborted.bin"
    with pytest.raises(RuntimeError, match="boom"):
        with StagedAtomicFileWriter(aborted) as writer:
            writer.write(b"never")
            raise RuntimeError("boom")
    assert not aborted.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_staged_writer_fsync_failure_aborts_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "stream.bin"

    def failing_fsync(descriptor: int) -> None:
        raise OSError(errno.EIO, "fsync failed")

    monkeypatch.setattr(os, "fsync", failing_fsync)
    writer = StagedAtomicFileWriter(destination)
    writer.write(b"data")

    with pytest.raises(OSError, match="fsync failed"):
        writer.commit()

    assert not destination.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_write_all_rejects_zero_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "write", lambda descriptor, data: 0)

    with pytest.raises(OSError, match="no progress"):
        write_all(0, b"data")


def test_fsync_directory_persists_entry(tmp_path: Path) -> None:
    fsync_directory(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode")
def test_set_private_file_mode_with_descriptor(tmp_path: Path) -> None:
    target = tmp_path / "mode.bin"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        set_private_file_mode(target, descriptor)
    finally:
        os.close(descriptor)

    assert (target.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode")
def test_set_private_file_mode_by_path(tmp_path: Path) -> None:
    target = tmp_path / "mode.bin"
    target.write_bytes(b"data")
    os.chmod(target, 0o644)

    set_private_file_mode(target)

    assert (target.stat().st_mode & 0o777) == 0o600
