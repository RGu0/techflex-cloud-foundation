"""Durable local file-writing primitives.

Local-first applications must persist data before it can be reliably
synchronised.  These primitives implement the write path that survives
power loss and disk failure: stage to a temporary file in the destination
directory, flush and fsync, atomically rename, then fsync the directory
where the platform allows it.  Nothing here knows about any application's
payload format.
"""

from __future__ import annotations

import os
from pathlib import Path
import secrets
from typing import Protocol

PRIVATE_FILE_MODE = 0o600


def write_all(descriptor: int, data: bytes) -> None:
    """Write every byte despite short writes, or raise ``OSError``."""

    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("os.write returned no progress")
        written += count


def fsync_directory(path: str | Path) -> None:
    """Persist a renamed directory entry where the platform exposes handles.

    Windows does not allow Python to open a directory with ``os.open``; the
    renamed file itself has already been flushed before this point, so this
    is a no-op there.
    """

    if os.name == "nt":
        return
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def set_private_file_mode(path: str | Path, descriptor: int | None = None) -> None:
    """Restrict a file to owner-only (0o600) on POSIX; best-effort on Windows.

    POSIX pins the open descriptor with ``fchmod`` when one is supplied,
    which is robust against a loose umask.  Windows has no ``fchmod``;
    ``os.chmod`` there only toggles the read-only attribute, so real access
    control rests on the directory ACL and payload encryption, not the mode.
    """

    target = Path(path)
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None and descriptor is not None:
        fchmod(descriptor, PRIVATE_FILE_MODE)
        return
    os.chmod(target, PRIVATE_FILE_MODE)


class AtomicFileWriter(Protocol):
    """Staged file writer: temporary until ``commit``, discarded on ``abort``."""

    def write(self, data: bytes) -> int: ...

    def commit(self) -> Path: ...

    def abort(self) -> None: ...


class StagedAtomicFileWriter:
    """Default ``AtomicFileWriter``: temp file, fsync, atomic rename.

    The temporary file is created with ``O_EXCL`` in the destination
    directory, so a crash never leaves a partially written final file and
    two writers never share one temporary path.  ``commit`` fsyncs the file,
    renames it over the destination, then fsyncs the directory unless
    disabled.  Any failure before or during ``commit`` removes the
    temporary file and leaves a pre-existing destination untouched.
    """

    def __init__(
        self,
        destination: str | Path,
        *,
        mode: int = PRIVATE_FILE_MODE,
        fsync_dir: bool = True,
    ) -> None:
        self._destination = Path(destination)
        if not self._destination.parent.is_dir():
            raise ValueError("destination directory does not exist")
        self._mode = mode
        self._fsync_dir = fsync_dir
        self._temporary = self._destination.parent / (
            f".{self._destination.name}.{secrets.token_hex(16)}.tmp"
        )
        # O_BINARY: without it Windows text mode rewrites \n bytes as \r\n,
        # which would silently corrupt binary payloads.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        self._descriptor = os.open(self._temporary, flags, mode)
        self._finished = False

    @property
    def temporary_path(self) -> Path:
        return self._temporary

    def write(self, data: bytes) -> int:
        if self._finished:
            raise ValueError("writer is already committed or aborted")
        write_all(self._descriptor, data)
        return len(data)

    def commit(self) -> Path:
        if self._finished:
            raise ValueError("writer is already committed or aborted")
        self._finished = True
        try:
            set_private_file_mode(self._temporary, self._descriptor)
            os.fsync(self._descriptor)
            os.close(self._descriptor)
            os.replace(self._temporary, self._destination)
            if self._fsync_dir:
                fsync_directory(self._destination.parent)
        except BaseException:
            self._discard()
            raise
        return self._destination

    def abort(self) -> None:
        if self._finished:
            return
        self._finished = True
        self._discard()

    def _discard(self) -> None:
        try:
            os.close(self._descriptor)
        except OSError:
            pass
        self._temporary.unlink(missing_ok=True)

    def __enter__(self) -> "StagedAtomicFileWriter":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.abort()


def atomic_write(
    destination: str | Path,
    payload: bytes,
    *,
    mode: int = PRIVATE_FILE_MODE,
    fsync_dir: bool = True,
) -> Path:
    """Write ``payload`` to ``destination`` in one crash-safe operation.

    The destination directory must already exist.  A pre-existing
    destination is replaced only after the new content is fully staged and
    fsynced; on any failure the old file remains in place.
    """

    writer = StagedAtomicFileWriter(destination, mode=mode, fsync_dir=fsync_dir)
    try:
        writer.write(payload)
        return writer.commit()
    except BaseException:
        writer.abort()
        raise
