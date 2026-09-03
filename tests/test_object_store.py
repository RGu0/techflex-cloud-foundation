"""Public contract tests for the immutable object store."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    FileSystemObjectStore,
    ImmutableObjectStore,
    InMemoryObjectStore,
    ObjectConflict,
    ObjectDigestMismatch,
    ObjectSizeMismatch,
    StoredObject,
)
from techflex_cloud_foundation.testing import disk_full, fsync_failure

pytestmark = pytest.mark.anyio


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"

PAYLOAD = b"object-payload-" * 64
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
KEY = "alpha/beta/object.bin"


async def _chunks(payload: bytes, size: int = 100):
    for offset in range(0, len(payload), size):
        yield payload[offset : offset + size]


@pytest.fixture(params=[InMemoryObjectStore, FileSystemObjectStore])
def store(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param is InMemoryObjectStore:
        return InMemoryObjectStore()
    return FileSystemObjectStore(tmp_path / "objects")


class TestSharedContract:
    async def test_put_read_roundtrip(self, store: ImmutableObjectStore) -> None:
        stored = await store.put_verified(
            KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
        )

        assert stored == StoredObject(KEY, DIGEST, len(PAYLOAD))
        assert await store.read(KEY) == PAYLOAD

    async def test_replay_with_identical_content_is_idempotent(
        self, store: ImmutableObjectStore
    ) -> None:
        await store.put_verified(KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD))

        stored = await store.put_verified(KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD))

        assert stored.object_key == KEY

    async def test_conflicting_content_is_refused(self, store: ImmutableObjectStore) -> None:
        await store.put_verified(KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD))
        other = b"different"
        other_digest = hashlib.sha256(other).hexdigest()

        with pytest.raises(ObjectConflict):
            await store.put_verified(
                KEY, _chunks(other), expected_sha256=other_digest, expected_size=len(other)
            )

    async def test_size_mismatch_is_refused(self, store: ImmutableObjectStore) -> None:
        with pytest.raises(ObjectSizeMismatch):
            await store.put_verified(
                KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD) + 1
            )

    async def test_digest_mismatch_is_refused(self, store: ImmutableObjectStore) -> None:
        with pytest.raises(ObjectDigestMismatch):
            await store.put_verified(
                KEY, _chunks(PAYLOAD), expected_sha256="0" * 64, expected_size=len(PAYLOAD)
            )

    async def test_delete_and_read_missing(self, store: ImmutableObjectStore) -> None:
        await store.put_verified(KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD))
        await store.delete(KEY)

        with pytest.raises((KeyError, FileNotFoundError)):
            await store.read(KEY)
        await store.delete(KEY)  # idempotent

    async def test_check_ready(self, store: ImmutableObjectStore) -> None:
        await store.check_ready()


class TestFileSystemSpecifics:
    async def test_rejects_unsafe_keys(self, tmp_path: Path) -> None:
        store = FileSystemObjectStore(tmp_path / "objects")
        for bad_key in ("", "/absolute", "..\\up", "a/../../escape", "back\\slash"):
            with pytest.raises(ValueError):
                await store.put_verified(
                    bad_key, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
                )

    @pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode")
    async def test_objects_are_owner_only(self, tmp_path: Path) -> None:
        store = FileSystemObjectStore(tmp_path / "objects")
        await store.put_verified(KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD))

        target = tmp_path / "objects" / KEY
        assert (target.stat().st_mode & 0o777) == 0o600

    async def test_staging_is_cleaned_on_digest_mismatch(self, tmp_path: Path) -> None:
        store = FileSystemObjectStore(tmp_path / "objects")
        with pytest.raises(ObjectDigestMismatch):
            await store.put_verified(
                KEY, _chunks(PAYLOAD), expected_sha256="0" * 64, expected_size=len(PAYLOAD)
            )

        assert list((tmp_path / "objects" / ".staging").iterdir()) == []

    async def test_tampered_existing_object_conflicts_on_replay(self, tmp_path: Path) -> None:
        store = FileSystemObjectStore(tmp_path / "objects")
        await store.put_verified(KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD))
        target = tmp_path / "objects" / KEY
        target.write_bytes(b"tampered")

        with pytest.raises(ObjectConflict):
            await store.put_verified(
                KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
            )

    async def test_disk_full_leaves_no_residue(self, tmp_path: Path) -> None:
        store = FileSystemObjectStore(tmp_path / "objects")
        with disk_full():
            with pytest.raises(OSError, match="No space left"):
                await store.put_verified(
                    KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
                )

        assert list((tmp_path / "objects" / ".staging").iterdir()) == []
        assert not (tmp_path / "objects" / KEY).exists()

    async def test_fsync_failure_leaves_no_residue(self, tmp_path: Path) -> None:
        store = FileSystemObjectStore(tmp_path / "objects")
        with fsync_failure():
            with pytest.raises(OSError, match="fsync"):
                await store.put_verified(
                    KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
                )

        assert list((tmp_path / "objects" / ".staging").iterdir()) == []
        assert not (tmp_path / "objects" / KEY).exists()
