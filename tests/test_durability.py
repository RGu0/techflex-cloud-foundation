"""Public contract tests for the durable local write primitives."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from techflex_cloud_foundation.testing.durability import (
    FaultInjection,
    fsync_failure,
    interrupted_replace,
)
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


class TestDescriptorOwnership:
    """One close per descriptor, on every path out of ``commit``."""

    def test_a_failed_rename_closes_the_descriptor_exactly_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``commit`` closed, then ``_discard`` closed the same number again."""

        closed: list[int] = []
        real_close = os.close

        def counting_close(descriptor: int) -> None:
            closed.append(descriptor)
            real_close(descriptor)

        monkeypatch.setattr(os, "close", counting_close)
        writer = StagedAtomicFileWriter(tmp_path / "payload.bin")
        writer.write(b"payload")

        with interrupted_replace():
            with pytest.raises(OSError):
                writer.commit()

        assert len(closed) == 1, f"descriptor closed {len(closed)} times: {closed}"
        assert list(tmp_path.glob("*.tmp")) == []

    def test_a_failed_rename_does_not_close_an_unrelated_file(
        self, tmp_path: Path
    ) -> None:
        """The consequence the double close actually had.

        ``os.close`` raises ``EBADF`` only while the number is still free, so
        a second close looks harmless in a single-threaded test.  It is not:
        POSIX hands out the lowest available descriptor, so any thread that
        opens a file between the two closes receives the number the writer
        just released -- and the second close silently closes that file
        instead.

        The competing open happens inside the failing ``os.replace``, which
        is exactly the window between the two closes in the old code.
        """

        unrelated = tmp_path / "unrelated.bin"
        staged_descriptor: dict[str, int] = {}

        def failing_replace(source: object, destination: object) -> None:
            staged_descriptor["reused"] = os.open(
                unrelated, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            raise OSError(errno.EIO, "simulated rename interruption")

        writer = StagedAtomicFileWriter(tmp_path / "payload.bin")
        writer.write(b"payload")
        held = writer._descriptor

        with FaultInjection(os, "replace", failing_replace):
            with pytest.raises(OSError):
                writer.commit()

        reused = staged_descriptor["reused"]
        assert reused == held, (
            "this test only demonstrates the bug when the competing open "
            f"actually reuses the released number (got {reused}, freed {held})"
        )
        try:
            os.write(reused, b"still-open")
        finally:
            os.close(reused)
        assert unrelated.read_bytes() == b"still-open"

    def test_an_fsync_failure_closes_the_descriptor_exactly_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other error path: the descriptor is still owned when it fails."""

        closed: list[int] = []
        real_close = os.close

        def counting_close(descriptor: int) -> None:
            closed.append(descriptor)
            real_close(descriptor)

        monkeypatch.setattr(os, "close", counting_close)
        writer = StagedAtomicFileWriter(tmp_path / "payload.bin")
        writer.write(b"payload")

        with fsync_failure():
            with pytest.raises(OSError):
                writer.commit()

        assert len(closed) == 1, f"descriptor closed {len(closed)} times: {closed}"

    def test_abort_after_a_failed_commit_does_not_close_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``atomic_write`` takes this path: a failed commit, then abort."""

        closed: list[int] = []
        real_close = os.close

        def counting_close(descriptor: int) -> None:
            closed.append(descriptor)
            real_close(descriptor)

        monkeypatch.setattr(os, "close", counting_close)
        destination = tmp_path / "payload.bin"
        destination.write_bytes(b"previous")

        with interrupted_replace():
            with pytest.raises(OSError):
                atomic_write(destination, b"replacement")

        assert len(closed) == 1, f"descriptor closed {len(closed)} times: {closed}"
        assert destination.read_bytes() == b"previous"
        assert list(tmp_path.glob("*.tmp")) == []

    def test_repeated_aborts_close_only_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        closed: list[int] = []
        real_close = os.close

        def counting_close(descriptor: int) -> None:
            closed.append(descriptor)
            real_close(descriptor)

        monkeypatch.setattr(os, "close", counting_close)
        writer = StagedAtomicFileWriter(tmp_path / "payload.bin")
        writer.write(b"payload")

        writer.abort()
        writer.abort()

        assert len(closed) == 1
