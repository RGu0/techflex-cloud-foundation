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
import errno
import hashlib
import os
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from .durability import fsync_directory, set_private_file_mode, write_all

_READ_CHUNK_BYTES = 1 << 20
# errno values that mean "this filesystem cannot hard-link", as opposed to a
# transient or unrelated failure.  Only these are translated; everything else
# keeps its own meaning.
_LINK_UNSUPPORTED_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, name, None)
        for name in ("EPERM", "EOPNOTSUPP", "ENOTSUP", "EXDEV", "ENOSYS", "EMLINK")
    )
    if value is not None
)


class ObjectStoreError(Exception):
    """Base class for object-store failures."""


class ObjectSizeMismatch(ObjectStoreError):
    """Streamed payload length differs from the declared size."""


class ObjectDigestMismatch(ObjectStoreError):
    """Streamed payload digest differs from the declared sha256."""


class ObjectConflict(ObjectStoreError):
    """An immutable key already exists with different content."""


class ObjectStoreUnsupported(ObjectStoreError):
    """The storage root cannot provide an invariant this store depends on."""


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

    # ``read`` returns the whole object.  Implementations are free to stream
    # internally, but the contract's return type bounds a read by available
    # memory, so a caller holding objects larger than it can afford in RAM
    # needs a different boundary than this one.
    #
    # ``delete`` on an immutable store is not a contradiction, but it is
    # narrower than it looks.  Immutability here means a key never silently
    # changes content *while it exists*: a reader that resolved a key once
    # can trust what it read.  It does not mean bytes are permanent.
    # Deletion exists for retention and lifecycle enforcement -- the
    # application decides what may be deleted and when -- and a deleted key
    # may later be published again, with the same content or different
    # content.  Callers that need permanence enforce it above this boundary.


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
    """Volatile reference implementation, suitable for tests and integration.

    Every object is held in memory in full, so total storage is bounded by the
    process's memory.  Use :class:`FileSystemObjectStore` for payloads whose
    combined size is not comfortably affordable in RAM; it streams a put
    through to disk and never holds a whole object.
    """

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
    """Private filesystem object storage with verified atomic publication.

    A put streams to a staging file and is published with :func:`os.link`,
    which either creates the key or fails because it already exists -- one
    indivisible step, with no window in which the key is observed free and
    then written.  The storage root must therefore be on a filesystem that
    supports hard links; publication raises :class:`ObjectStoreUnsupported`
    rather than falling back to a non-atomic path, because the fallback is
    precisely the silent-overwrite bug this avoids.

    Neither a put nor an existence check holds a whole object in memory.
    :meth:`read` does, because the protocol returns ``bytes``.
    """

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
        """Map a key to its file, rejecting any key that could leave the root.

        Containment is decided from the key's text alone.  It used to be
        decided by resolving the joined path and comparing the result against
        a root resolved back in ``__init__`` -- two ``Path.resolve`` calls,
        made at different moments under different filesystem conditions.  That
        compares two observations rather than two paths.  On Windows
        ``resolve`` expands 8.3 short components (``RUNNER~1`` ->
        ``runneradmin``) only as far as it can successfully query the
        filesystem, and when a query fails it gives up silently and returns
        the remainder unexpanded.  Concurrent creation in the same directory
        makes such failures transient, so two writers racing on one key could
        have a valid key resolve to the unexpanded form, compare as outside
        the expanded root, and be rejected as an escape.  Whether a key is
        valid cannot depend on who else happens to be writing at the time.

        The rules below are exact and read nothing outside the argument.  A
        key must be ``/``-separated ordinary names: no empty component (which
        covers the empty key, a leading ``/``, a trailing ``/``, and ``//``),
        no ``.`` or ``..``, no backslash, and no colon.  The colon matters on
        Windows, where ``C:evil`` is drive-relative and ``file:stream`` names
        an alternate data stream; both survive the other checks, and joining a
        drive-relative component onto the root discards the root entirely.
        A path built only from ordinary relative names can name nothing above
        the root, so no filesystem lookup is needed to know that.

        A symlink planted inside the root could still redirect a key outward,
        which the old ``resolve`` incidentally caught.  That is not a
        regression worth the exchange: the root is created ``0o700`` by this
        store, and anyone able to plant a symlink inside it can equally
        replace the object files the check would have protected.
        """

        parts = object_key.split("/")
        if (
            not object_key
            or "\\" in object_key
            or any(part in ("", ".", "..") or ":" in part for part in parts)
        ):
            raise ValueError("object key must be a relative path")
        return self._root.joinpath(*parts)

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
            if self._publish(staging_path, final_path):
                fsync_directory(final_path.parent)
                return StoredObject(object_key, expected_sha256, expected_size)
            # The key was already taken -- either by an earlier put or by a
            # writer that won the race a moment ago.  Whatever is there is a
            # complete object, never a partial one, so comparing against it
            # decides replay from conflict.
            self._verify_existing(final_path, expected_sha256=expected_sha256,
                                  expected_size=expected_size, object_key=object_key)
            return StoredObject(object_key, expected_sha256, expected_size)
        finally:
            staging_path.unlink(missing_ok=True)

    @staticmethod
    def _publish(staging_path: Path, final_path: Path) -> bool:
        """Claim ``final_path`` for the staged file; False if already taken.

        ``if final_path.exists(): ... else: os.replace(...)`` left a window
        between the two calls.  Two writers carrying different content could
        both find the key free, and the second ``os.replace`` silently
        overwrote the first writer's object -- while both callers were handed
        a successful ``StoredObject``.  On a store whose protocol is named
        ``ImmutableObjectStore``, that is the one thing that must not happen.

        ``os.link`` collapses the check and the write into a single operation
        the kernel resolves: it publishes the fully written, already verified
        staging file, or it fails with ``FileExistsError`` and nothing is
        touched.
        """

        try:
            os.link(staging_path, final_path)
        except FileExistsError:
            return False
        except OSError as exc:
            if exc.errno not in _LINK_UNSUPPORTED_ERRNOS:
                raise
            raise ObjectStoreUnsupported(
                f"cannot publish {final_path.name} atomically: the storage root does "
                f"not support hard links ({exc.strerror}). Place the root on a "
                "filesystem that does; publishing without them would reintroduce a "
                "window in which concurrent writers silently overwrite each other."
            ) from exc
        return True

    @staticmethod
    def _verify_existing(
        path: Path, *, expected_sha256: str, expected_size: int, object_key: str
    ) -> None:
        """Compare a stored object against a declaration, without loading it."""

        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(_READ_CHUNK_BYTES):
                digest.update(chunk)
                size += len(chunk)
        if size != expected_size or digest.hexdigest() != expected_sha256:
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
