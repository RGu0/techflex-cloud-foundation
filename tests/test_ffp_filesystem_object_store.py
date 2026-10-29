from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    ManifestSegment,
    SegmentMetadata,
    SessionManifest,
)
from techflex_cloud_foundation.object_store import FileSystemObjectStore
from techflex_cloud_foundation.platform_errors import (
    DigestMismatch,
    SegmentDigestConflict,
    SizeMismatch,
)
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore


async def chunks(*values: bytes):
    for value in values:
        yield value


class FileSystemObjectStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "private-objects"
        self.store = SegmentObjectStore(FileSystemObjectStore(self.root))
        self.tenant_id = uuid4()
        self.session_id = uuid4()
        self.payload = b"immutable segment payload"

    async def asyncTearDown(self) -> None:
        self.temp.cleanup()

    def metadata(self, *, digest: str | None = None, size: int | None = None):
        return SegmentMetadata(
            segment_index=0,
            start_frame_index=0,
            frame_count=10,
            start_monotonic_ns=1,
            end_monotonic_ns=2,
            compression="zstd",
            cipher="aes-256-gcm",
            size_bytes=len(self.payload) if size is None else size,
            sha256=digest or hashlib.sha256(self.payload).hexdigest(),
            payload_schema_version="raw-segment/1",
        )

    async def test_segment_is_tenant_prefixed_private_and_idempotent(self) -> None:
        metadata = self.metadata()
        first = await self.store.put_segment(
            self.tenant_id,
            self.session_id,
            metadata,
            chunks(self.payload[:5], self.payload[5:]),
        )
        replay = await self.store.put_segment(
            self.tenant_id,
            self.session_id,
            metadata,
            chunks(self.payload),
        )

        self.assertEqual(first, replay)
        self.assertTrue(first.object_key.startswith(f"tenants/{self.tenant_id}/"))
        final_path = self.root / first.object_key
        self.assertEqual(final_path.read_bytes(), self.payload)
        if os.name == "posix":
            self.assertEqual(final_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)

    async def test_digest_size_failure_cleans_staging(self) -> None:
        with self.assertRaises(SizeMismatch):
            await self.store.put_segment(
                self.tenant_id,
                self.session_id,
                self.metadata(size=len(self.payload) + 1),
                chunks(self.payload),
            )
        with self.assertRaises(DigestMismatch):
            await self.store.put_segment(
                self.tenant_id,
                self.session_id,
                self.metadata(digest="0" * 64),
                chunks(self.payload),
            )
        self.assertEqual(tuple((self.root / ".staging").iterdir()), ())

    async def test_existing_tampered_immutable_key_conflicts(self) -> None:
        metadata = self.metadata()
        stored = await self.store.put_segment(
            self.tenant_id,
            self.session_id,
            metadata,
            chunks(self.payload),
        )
        (self.root / stored.object_key).write_bytes(b"different existing bytes")

        with self.assertRaises(SegmentDigestConflict):
            await self.store.put_segment(
                self.tenant_id,
                self.session_id,
                metadata,
                chunks(self.payload),
            )

    async def test_manifest_is_canonical_and_immutable(self) -> None:
        metadata = self.metadata()
        manifest = SessionManifest(
            segment_count=1,
            total_frames=10,
            total_bytes=len(self.payload),
            segments=(
                ManifestSegment(
                    index=0,
                    sha256=metadata.sha256,
                    size_bytes=len(self.payload),
                    frame_count=10,
                ),
            ),
            ended_at=datetime.now(UTC),
            local_quality_outcome="VALID",
        )
        digest = canonical_sha256(manifest)

        stored = await self.store.put_manifest(
            self.tenant_id,
            self.session_id,
            manifest,
            digest,
        )

        self.assertIn("/manifests/", stored.object_key)
        self.assertEqual(hashlib.sha256(await self.store.read(stored.object_key)).hexdigest(), digest)

    async def test_path_traversal_is_rejected(self) -> None:
        for key in ("../outside", "/absolute", "tenants/x/../../outside"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    await self.store.delete(key)


if __name__ == "__main__":
    unittest.main()
