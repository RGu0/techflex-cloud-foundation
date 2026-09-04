"""Public contract tests for the immutable object store."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import errno
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
    ObjectStoreUnsupported,
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
        bad_keys = (
            "",
            "/absolute",
            "..\\up",
            "a/../../escape",
            "back\\slash",
            "trailing/",
            "double//slash",
            "./here",
            # Drive-relative on Windows, and an alternate data stream: both
            # pass every other rule, and joining the first onto the root
            # replaces the root rather than extending it.
            "C:evil",
            "object.bin:stream",
        )
        for bad_key in bad_keys:
            with pytest.raises(ValueError):
                await store.put_verified(
                    bad_key, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
                )

    def test_key_validity_does_not_depend_on_the_filesystem(self, tmp_path: Path) -> None:
        """A key maps to its path by text, with no lookup that could vary.

        Deciding containment by resolving the joined path made the answer
        depend on what the filesystem reported at that instant.  Under
        concurrent creation on Windows the resolution silently stopped
        expanding short path components, and a valid key was rejected as an
        escape by a store that had accepted the same key moments earlier.
        Pinning the mapping to ``joinpath`` is what removes that dependency,
        so the test asserts the mapping rather than the symptom.
        """

        store = FileSystemObjectStore(tmp_path / "objects")

        assert store._path("race/0/object.bin") == store.root / "race" / "0" / "object.bin"
        # Nothing along the key exists, and the answer is the same regardless.
        assert not (store.root / "race").exists()

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


OTHER_PAYLOAD = b"a-different-object-" * 64
OTHER_DIGEST = hashlib.sha256(OTHER_PAYLOAD).hexdigest()


class TestExclusivePublication:
    """The one invariant a store named ``ImmutableObjectStore`` must hold."""

    async def test_a_key_written_during_the_publish_step_is_not_overwritten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Publication must be indivisible, not merely quick.

        ``if final_path.exists(): ... else: os.replace(...)`` left a window
        between the check and the write.  Two writers carrying different
        content could both find the key free, and the second ``os.replace``
        silently overwrote the first writer's object while handing both
        callers a successful ``StoredObject``.

        The window is microseconds wide, so a timing test would only catch it
        by luck.  Widening it on purpose is what makes the invariant testable:
        a competing object appears at the key immediately before the publish
        call, which is the worst case the old code could not survive.
        """

        store = FileSystemObjectStore(tmp_path / "objects")
        target = tmp_path / "objects" / KEY
        real_link = os.link

        def link_after_a_competitor_wins(source: str | Path, destination: str | Path) -> None:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(OTHER_PAYLOAD)
            real_link(source, destination)

        monkeypatch.setattr(os, "link", link_after_a_competitor_wins)

        with pytest.raises(ObjectConflict):
            await store.put_verified(
                KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
            )

        # The writer that got there first keeps the key.
        assert target.read_bytes() == OTHER_PAYLOAD
        assert list((tmp_path / "objects" / ".staging").iterdir()) == []

    async def test_an_identical_replay_during_the_publish_step_still_succeeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Losing the race to the same content is a replay, not a conflict."""

        store = FileSystemObjectStore(tmp_path / "objects")
        target = tmp_path / "objects" / KEY
        real_link = os.link

        def link_after_a_twin_wins(source: str | Path, destination: str | Path) -> None:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(PAYLOAD)
            real_link(source, destination)

        monkeypatch.setattr(os, "link", link_after_a_twin_wins)

        stored = await store.put_verified(
            KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
        )

        assert stored == StoredObject(KEY, DIGEST, len(PAYLOAD))
        assert target.read_bytes() == PAYLOAD

    async def test_concurrent_writers_of_different_content_produce_one_winner(
        self, tmp_path: Path
    ) -> None:
        """Real threads, repeated: exactly one success, and the disk agrees."""

        root = tmp_path / "objects"

        def put(payload: bytes, digest: str, key: str) -> bool:
            store = FileSystemObjectStore(root)

            async def run() -> bool:
                try:
                    await store.put_verified(
                        key, _chunks(payload), expected_sha256=digest, expected_size=len(payload)
                    )
                except ObjectConflict:
                    return False
                return True

            return asyncio.run(run())

        for round_number in range(25):
            key = f"race/{round_number}/object.bin"
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(
                    pool.map(
                        lambda argument: put(*argument),
                        ((PAYLOAD, DIGEST, key), (OTHER_PAYLOAD, OTHER_DIGEST, key)),
                    )
                )

            assert sum(outcomes) == 1, f"round {round_number}: {outcomes}"
            written = (root / key).read_bytes()
            assert written in (PAYLOAD, OTHER_PAYLOAD)
            # The survivor is the writer that reported success.
            expected = PAYLOAD if outcomes[0] else OTHER_PAYLOAD
            assert written == expected

    async def test_a_root_without_hard_links_fails_loudly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No silent fallback: the fallback is the bug."""

        store = FileSystemObjectStore(tmp_path / "objects")

        def unsupported(source: str | Path, destination: str | Path) -> None:
            raise OSError(errno.EOPNOTSUPP, "Operation not supported")

        monkeypatch.setattr(os, "link", unsupported)

        with pytest.raises(ObjectStoreUnsupported, match="hard links"):
            await store.put_verified(
                KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
            )
        assert not (tmp_path / "objects" / KEY).exists()
        assert list((tmp_path / "objects" / ".staging").iterdir()) == []

    async def test_an_unrelated_link_failure_keeps_its_own_meaning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = FileSystemObjectStore(tmp_path / "objects")

        def out_of_space(source: str | Path, destination: str | Path) -> None:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(os, "link", out_of_space)

        with pytest.raises(OSError, match="No space left") as caught:
            await store.put_verified(
                KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
            )
        assert not isinstance(caught.value, ObjectStoreUnsupported)

    async def test_existence_check_does_not_load_the_object(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Replay verification streams; it used to read the whole object."""

        store = FileSystemObjectStore(tmp_path / "objects")
        await store.put_verified(
            KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
        )

        def refuse(self: Path) -> bytes:
            raise AssertionError(f"whole-file read of {self}")

        monkeypatch.setattr(Path, "read_bytes", refuse)

        stored = await store.put_verified(
            KEY, _chunks(PAYLOAD), expected_sha256=DIGEST, expected_size=len(PAYLOAD)
        )
        assert stored == StoredObject(KEY, DIGEST, len(PAYLOAD))
