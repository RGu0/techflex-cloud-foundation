"""FeetForcePlate segment/manifest publication over the OSS store, as it was (RAY-830)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import hashlib
from uuid import uuid4

import pytest

from techflex_cloud_foundation.aliyun_oss import AliyunOSSObjectStore
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    ManifestSegment,
    SegmentMetadata,
    SessionManifest,
)
from techflex_cloud_foundation.platform_errors import SegmentDigestConflict
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from tests.test_aliyun_oss import _chunks, _Gateway, _Object


def _metadata(payload: bytes, *, index: int = 0) -> SegmentMetadata:
    return SegmentMetadata(
        segment_index=index,
        start_frame_index=index,
        frame_count=1,
        start_monotonic_ns=1,
        end_monotonic_ns=2,
        compression="zstd",
        cipher="aes-256-gcm",
        payload_schema_version="raw-segment/1",
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
    )


def test_oss_segment_is_tenant_prefixed_immutable_and_kms_encrypted() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = SegmentObjectStore(AliyunOSSObjectStore(gateway, server_side_encryption="KMS"))
        tenant_id = uuid4()
        session_id = uuid4()
        payload = b"raw-segment"
        metadata = _metadata(payload)

        stored = await store.put_segment(
            tenant_id, session_id, metadata, _chunks(payload)
        )

        assert stored.object_key.startswith(
            f"tenants/{tenant_id}/sessions/{session_id}/segments/0-"
        )
        uploaded = gateway.objects[stored.object_key]
        assert uploaded.body == payload
        assert uploaded.metadata == {
            "sha256": metadata.sha256,
            "schema-version": "raw-segment/1",
        }
        assert uploaded.server_side_encryption == "KMS"

    asyncio.run(exercise())


def test_oss_same_digest_replay_is_idempotent() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = SegmentObjectStore(AliyunOSSObjectStore(gateway, server_side_encryption="KMS"))
        tenant_id = uuid4()
        session_id = uuid4()
        payload = b"same-segment"
        metadata = _metadata(payload)

        first = await store.put_segment(
            tenant_id, session_id, metadata, _chunks(payload)
        )
        second = await store.put_segment(
            tenant_id, session_id, metadata, _chunks(payload)
        )

        assert second == first
        assert len(gateway.objects) == 1
        assert gateway.put_attempts == 1

    asyncio.run(exercise())


def test_oss_existing_key_with_wrong_integrity_metadata_is_rejected() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = SegmentObjectStore(AliyunOSSObjectStore(gateway, server_side_encryption="KMS"))
        tenant_id = uuid4()
        session_id = uuid4()
        payload = b"expected"
        metadata = _metadata(payload)
        key = (
            f"tenants/{tenant_id}/sessions/{session_id}/segments/"
            f"0-{metadata.sha256}.ffps"
        )
        gateway.objects[key] = _Object(
            body=b"different",
            content_type="application/octet-stream",
            metadata={"sha256": "0" * 64, "schema-version": "raw-segment/1"},
            server_side_encryption="KMS",
        )

        with pytest.raises(SegmentDigestConflict):
            await store.put_segment(tenant_id, session_id, metadata, _chunks(payload))
        assert gateway.put_attempts == 0

    asyncio.run(exercise())


def test_oss_readiness_delegates_to_bucket_gateway() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = SegmentObjectStore(AliyunOSSObjectStore(gateway, server_side_encryption="KMS"))

        await store.check_ready()

        assert gateway.ready_checks == 1

    asyncio.run(exercise())


def test_oss_manifest_is_canonical_immutable_and_kms_encrypted() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = SegmentObjectStore(AliyunOSSObjectStore(gateway, server_side_encryption="KMS"))
        tenant_id = uuid4()
        session_id = uuid4()
        payload = b"raw-segment"
        segment = _metadata(payload)
        manifest = SessionManifest(
            segment_count=1,
            total_frames=1,
            total_bytes=len(payload),
            segments=(
                ManifestSegment(
                    index=0,
                    sha256=segment.sha256,
                    size_bytes=len(payload),
                    frame_count=1,
                ),
            ),
            ended_at=datetime.now(UTC),
            local_quality_outcome="VALID",
        )
        digest = canonical_sha256(manifest)

        stored = await store.put_manifest(tenant_id, session_id, manifest, digest)

        uploaded = gateway.objects[stored.object_key]
        assert "/manifests/" in stored.object_key
        assert hashlib.sha256(uploaded.body).hexdigest() == digest
        assert uploaded.metadata == {
            "sha256": digest,
            "schema-version": "session-manifest/1",
        }
        assert uploaded.server_side_encryption == "KMS"

    asyncio.run(exercise())

