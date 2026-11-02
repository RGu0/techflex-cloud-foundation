"""Private diagnostic-package adapter over the immutable object store."""

from __future__ import annotations

import hashlib
from typing import Any

from techflex_cloud_foundation.aliyun_oss import AliyunOSSObjectStore
from techflex_cloud_foundation.object_store import (
    ImmutableObjectStore,
    ObjectConflict,
    ObjectStoreError,
    StoredObject,
)
from techflex_cloud_foundation.platform_errors import DigestMismatch, SegmentDigestConflict

DIAGNOSTIC_CONTENT_TYPE = "application/x-ndjson"
DIAGNOSTIC_SCHEMA_VERSION = "gait-insole-diagnostics/1"
MAX_DIAGNOSTIC_BYTES = 8 * 1024 * 1024


class DiagnosticPackageStore:
    def __init__(self, object_store: ImmutableObjectStore) -> None:
        self._object_store = object_store

    async def put_diagnostic(self, object_key: str, payload: bytes) -> StoredObject:
        digest = hashlib.sha256(payload).hexdigest()

        async def chunks() -> Any:
            yield payload

        options: dict[str, Any] = {}
        if isinstance(self._object_store, AliyunOSSObjectStore):
            options = {
                "content_type": DIAGNOSTIC_CONTENT_TYPE,
                "extra_metadata": {"schema-version": DIAGNOSTIC_SCHEMA_VERSION},
            }
        try:
            return await self._object_store.put_verified(
                object_key, chunks(), expected_sha256=digest, expected_size=len(payload), **options
            )
        except ObjectConflict as exc:
            raise SegmentDigestConflict(
                "immutable object key already holds different content", object_key=object_key
            ) from exc

    async def read_diagnostic(self, object_key: str) -> bytes:
        try:
            if isinstance(self._object_store, AliyunOSSObjectStore):
                return await self._object_store.read(object_key, max_bytes=MAX_DIAGNOSTIC_BYTES)
            return await self._object_store.read(object_key)
        except ObjectStoreError as exc:
            raise DigestMismatch("diagnostic package attributes or digest invalid") from exc

    async def delete(self, object_key: str) -> None:
        await self._object_store.delete(object_key)
