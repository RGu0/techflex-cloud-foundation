"""Session segment and manifest publication over an ``ImmutableObjectStore``.

The key layout, error mapping and OSS object headers are those of the ffp
cloud service, so objects written before and after the migration are
interchangeable.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, AsyncIterator
import hashlib
from typing import Any
from uuid import UUID

from techflex_cloud_foundation.aliyun_oss import AliyunOSSObjectStore
from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.contracts.cloud import AnySegmentMetadata, AnySessionManifest
from techflex_cloud_foundation.object_store import (
    ImmutableObjectStore,
    ObjectConflict,
    ObjectDigestMismatch,
    ObjectSizeMismatch,
    StoredObject,
)
from techflex_cloud_foundation.platform_errors import (
    DigestMismatch,
    SegmentDigestConflict,
    SizeMismatch,
)

SEGMENT_CONTENT_TYPE = "application/vnd.feetforceplate.segment.v1+octet-stream"
MANIFEST_CONTENT_TYPE = "application/json"
_OSS_CONFLICT_MESSAGE = "不可变 OSS 对象键已存在不同内容或安全属性"


def segment_object_key(tenant_id: UUID, session_id: UUID, segment_index: int, sha256: str) -> str:
    return f"tenants/{tenant_id}/sessions/{session_id}/segments/{segment_index}-{sha256}.ffps"


def manifest_object_key(tenant_id: UUID, session_id: UUID, sha256: str) -> str:
    return f"tenants/{tenant_id}/sessions/{session_id}/manifests/{sha256}.json"


class _Tally:
    """Counts and hashes the stream so a mismatch can report both sides."""

    def __init__(self, chunks: AsyncIterable[bytes]) -> None:
        self._chunks = chunks
        self._digest = hashlib.sha256()
        self.size = 0

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._chunks:
            self._digest.update(chunk)
            self.size += len(chunk)
            yield chunk


class SegmentObjectStore:
    """Publishes session segments and final manifests under tenant-scoped keys."""

    def __init__(self, store: ImmutableObjectStore) -> None:
        self._store = store

    async def put_segment(
        self,
        tenant_id: UUID,
        session_id: UUID,
        metadata: AnySegmentMetadata,
        chunks: AsyncIterable[bytes],
    ) -> StoredObject:
        object_key = segment_object_key(
            tenant_id, session_id, metadata.segment_index, metadata.sha256
        )
        return await self._put(
            object_key,
            chunks,
            expected_sha256=metadata.sha256,
            expected_size=metadata.size_bytes,
            content_type=SEGMENT_CONTENT_TYPE,
            schema_version=metadata.payload_schema_version,
            conflict_message="不可变对象键已存在不同内容",
            mismatch_label="分段",
        )

    async def put_manifest(
        self,
        tenant_id: UUID,
        session_id: UUID,
        manifest: AnySessionManifest,
        expected_sha256: str,
    ) -> StoredObject:
        payload = canonical_json_bytes(manifest)
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if actual_sha256 != expected_sha256:
            raise DigestMismatch(
                "最终清单摘要与规范化内容不一致",
                expected=expected_sha256,
                actual=actual_sha256,
            )

        async def chunks() -> AsyncIterable[bytes]:
            yield payload

        return await self._put(
            manifest_object_key(tenant_id, session_id, expected_sha256),
            chunks(),
            expected_sha256=expected_sha256,
            expected_size=len(payload),
            content_type=MANIFEST_CONTENT_TYPE,
            schema_version=manifest.schema_version,
            conflict_message="不可变清单对象键已存在不同内容",
            mismatch_label="最终清单",
        )

    async def delete(self, object_key: str) -> None:
        await self._store.delete(object_key)

    async def read(self, object_key: str) -> bytes:
        return await self._store.read(object_key)

    async def check_ready(self) -> None:
        await self._store.check_ready()

    async def _put(
        self,
        object_key: str,
        chunks: AsyncIterable[bytes],
        *,
        expected_sha256: str,
        expected_size: int,
        content_type: str,
        schema_version: str,
        conflict_message: str,
        mismatch_label: str,
    ) -> StoredObject:
        tally = _Tally(chunks)
        options: dict[str, Any] = {}
        if isinstance(self._store, AliyunOSSObjectStore):
            options = {
                "content_type": content_type,
                "extra_metadata": {"schema-version": schema_version},
            }
        try:
            return await self._store.put_verified(
                object_key,
                tally,
                expected_sha256=expected_sha256,
                expected_size=expected_size,
                **options,
            )
        except ObjectSizeMismatch as exc:
            raise SizeMismatch(
                f"{mismatch_label}长度与声明不一致", expected=expected_size, actual=tally.size
            ) from exc
        except ObjectDigestMismatch as exc:
            raise DigestMismatch(
                f"{mismatch_label}摘要与声明不一致",
                expected=expected_sha256,
                actual=tally.sha256,
            ) from exc
        except ObjectConflict as exc:
            if isinstance(self._store, AliyunOSSObjectStore):
                conflict_message = _OSS_CONFLICT_MESSAGE
            raise SegmentDigestConflict(conflict_message, object_key=object_key) from exc
