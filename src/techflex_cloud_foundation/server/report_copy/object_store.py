"""Narrow private PDF adapter; callers never receive an object URL."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID, uuid4

from techflex_cloud_foundation.aliyun_oss import AliyunOSSObjectStore
from techflex_cloud_foundation.object_store import (
    ImmutableObjectStore,
    ObjectConflict,
    ObjectStoreError,
    StoredObject,
)
from techflex_cloud_foundation.platform_errors import DigestMismatch, SegmentDigestConflict

REPORT_PDF_CONTENT_TYPE = "application/pdf"
REPORT_PDF_SCHEMA_VERSION = "local-basic-copy/1"
MAX_REPORT_PDF_BYTES = 8 * 1024 * 1024


class LocalBasicPdfStore:
    def __init__(self, object_store: ImmutableObjectStore) -> None:
        self._object_store = object_store

    async def put(self, tenant_id: UUID, session_id: UUID, payload: bytes) -> StoredObject:
        key = f"tenants/{tenant_id}/sessions/{session_id}/basic-report-copies/{uuid4()}.pdf"
        digest = hashlib.sha256(payload).hexdigest()

        async def chunks() -> Any:
            yield payload

        options: dict[str, Any] = {}
        if isinstance(self._object_store, AliyunOSSObjectStore):
            options = {
                "content_type": REPORT_PDF_CONTENT_TYPE,
                "extra_metadata": {"schema-version": REPORT_PDF_SCHEMA_VERSION},
            }
        try:
            return await self._object_store.put_verified(
                key, chunks(), expected_sha256=digest, expected_size=len(payload), **options
            )
        except ObjectConflict as exc:
            raise SegmentDigestConflict(
                "immutable object key already holds different content", object_key=key
            ) from exc

    async def read(self, object_key: str) -> bytes:
        try:
            if isinstance(self._object_store, AliyunOSSObjectStore):
                return await self._object_store.read(object_key, max_bytes=MAX_REPORT_PDF_BYTES)
            return await self._object_store.read(object_key)
        except ObjectStoreError as exc:
            raise DigestMismatch("basic report PDF security attributes or digest invalid") from exc

    async def delete(self, object_key: str) -> None:
        await self._object_store.delete(object_key)
