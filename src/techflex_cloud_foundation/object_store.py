"""Immutable, content-verified object storage.

Objects are staged to a temporary file, streamed through a running
SHA-256/size verification, and atomically published under an opaque
caller-supplied key.  A key that already exists must hold identical
verified content — replay is idempotent, divergence is a conflict.  Key
layout is entirely the caller's concern; nothing here knows about any
application's naming scheme, and no cloud SDK is bound — remote adapters
implement the same protocol in the application layer.
"""

from __future__ import annotations

from collections.abc import AsyncIterable
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from .durability import fsync_directory, set_private_file_mode, write_all


class ObjectStoreError(Exception):
    """Base class for object-store failures."""


class ObjectSizeMismatch(ObjectStoreError):
    """Streamed payload length differs from the declared size."""


class ObjectDigestMismatch(ObjectStoreError):
    """Streamed payload digest differs from the declared sha256."""


class ObjectConflict(ObjectStoreError):
    """An immutable key already exists with different content."""


@dataclass(frozen=True, slots=True)
class StoredObject:
    object_key: str
    sha256: str
    size_bytes: int


class ImmutableObjectStore(Protocol):
    """Content-addressed, verify-on-write object storage boundary."""

    async def put_verified(
        self,
        object_key: str,
        chunks: AsyncIterable[bytes],
        *,
        expected_sha256: str,
        expected_size: int,
    ) -> StoredObject: ...

    async def read(self, object_key: str) -> bytes: ...

    async def delete(self, object_key: str) -> None: ...

    async def check_ready(self) -> None: ...


async def _verified_payload(
    chunks: AsyncIterable[bytes], *, expected_sha256: str, expected_size: int
) -> bytes:
    digest = hashlib.sha256()
    payload = bytearray()
    async for chunk in chunks:
        digest.update(chunk)
        payload.extend(chunk)
    if len(payload) != expected_size:
        raise ObjectSizeMismatch(
            f"payload size {len(payload)} differs from declared {expected_size}"
        )
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise ObjectDigestMismatch(
            f"payload digest {actual} differs from declared {expected_sha256}"
        )
    return bytes(payload)


class InMemoryObjectStore:
    """Volatile reference implementation, suitable for tests and integration."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    @property
    def object_count(self) -> int:
        return len(self._objects)

    async def put_verified(
        self,
        object_key: str,
        chunks: AsyncIterable[bytes],
        *,
        expected_sha256: str,
        expected_size: int,
    ) -> StoredObject:
        payload = await _verified_payload(
            chunks, expected_sha256=expected_sha256, expected_size=expected_size
        )
        existing = self._objects.get(object_key)
        if existing is not None and existing != payload:
            raise ObjectConflict(f"object key {object_key!r} holds different content")
        self._objects[object_key] = payload
        return StoredObject(object_key, expected_sha256, expected_size)

    async def read(self, object_key: str) -> bytes:
        return self._objects[object_key]

    async def delete(self, object_key: str) -> None:
        self._objects.pop(object_key, None)

    async def check_ready(self) -> None:
        return None


class FileSystemObjectStore:
    """Private filesystem object storage with verified atomic publication."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).resolve()
        self._staging = self._root / ".staging"
        self._mkdir_private(self._root)
        self._mkdir_private(self._staging)

    @property
    def root(self) -> Path:
        return self._root

    @staticmethod
    def _mkdir_private(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(path, 0o700)

    def _path(self, object_key: str) -> Path:
        key_path = Path(object_key)
        if (
            not object_key
            or object_key.startswith(("/", "\\"))
            or ".." in key_path.parts
            or "\\" in object_key
        ):
            raise ValueError("object key must be a relative path")
        candidate = (self._root / key_path).resolve()
        if candidate == self._root or not candidate.is_relative_to(self._root):
            raise ValueError("object key escapes the storage root")
        return candidate

    async def put_verified(
        self,
        object_key: str,
        chunks: AsyncIterable[bytes],
        *,
        expected_sha256: str,
        expected_size: int,
    ) -> StoredObject:
        final_path = self._path(object_key)
        self._mkdir_private(final_path.parent)
        staging_path = self._staging / f"{uuid4()}.part"
        digest = hashlib.sha256()
        size = 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(staging_path, flags, 0o600)
            try:
                set_private_file_mode(staging_path, descriptor)
                async for chunk in chunks:
                    write_all(descriptor, chunk)
                    digest.update(chunk)
                    size += len(chunk)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            actual = digest.hexdigest()
            if size != expected_size:
                raise ObjectSizeMismatch(
                    f"payload size {size} differs from declared {expected_size}"
                )
            if actual != expected_sha256:
                raise ObjectDigestMismatch(
                    f"payload digest {actual} differs from declared {expected_sha256}"
                )
            if final_path.exists():
                self._verify_existing(final_path, expected_sha256=expected_sha256,
                                      expected_size=expected_size, object_key=object_key)
                return StoredObject(object_key, expected_sha256, expected_size)
            os.replace(staging_path, final_path)
            fsync_directory(final_path.parent)
            return StoredObject(object_key, expected_sha256, expected_size)
        finally:
            staging_path.unlink(missing_ok=True)

    @staticmethod
    def _verify_existing(
        path: Path, *, expected_sha256: str, expected_size: int, object_key: str
    ) -> None:
        data = path.read_bytes()
        if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_sha256:
            raise ObjectConflict(f"object key {object_key!r} holds different content")

    async def read(self, object_key: str) -> bytes:
        return self._path(object_key).read_bytes()

    async def delete(self, object_key: str) -> None:
        target = self._path(object_key)
        target.unlink(missing_ok=True)
        fsync_directory(target.parent)

    async def check_ready(self) -> None:
        probe = self._staging / f".ready-{uuid4()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(probe, flags, 0o600)
        try:
            write_all(descriptor, b"ready")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
            probe.unlink(missing_ok=True)
