"""The report PDF remains a private object and is read through the adapter."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
from uuid import uuid4

from techflex_cloud_foundation.aliyun_oss import AliyunOSSObjectStore
from techflex_cloud_foundation.object_store import FileSystemObjectStore
from techflex_cloud_foundation.server.report_copy.object_store import LocalBasicPdfStore
from tests.test_aliyun_oss import _Gateway


def test_filesystem_report_pdf_round_trip_and_cleanup(tmp_path) -> None:
    async def exercise() -> None:
        store = LocalBasicPdfStore(FileSystemObjectStore(tmp_path))
        tenant_id, session_id = uuid4(), uuid4()
        payload = b"%PDF-1.4\nsynthetic\n%%EOF"
        saved = await store.put(tenant_id, session_id, payload)
        assert saved.object_key.startswith(f"tenants/{tenant_id}/sessions/{session_id}/basic-report-copies/")
        assert await store.read(saved.object_key) == payload
        await store.delete(saved.object_key)
        assert not (tmp_path / saved.object_key).exists()

    asyncio.run(exercise())


def test_private_oss_report_pdf_round_trip() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = LocalBasicPdfStore(AliyunOSSObjectStore(gateway, server_side_encryption="KMS"))
        payload = b"%PDF-1.4\nsynthetic\n%%EOF"
        saved = await store.put(uuid4(), uuid4(), payload)
        assert await store.read(saved.object_key) == payload
        assert gateway.objects[saved.object_key].server_side_encryption == "KMS"
    asyncio.run(exercise())


def test_oss_report_pdf_headers_digest_check_and_read_cap() -> None:
    import pytest

    from techflex_cloud_foundation.platform_errors import DigestMismatch
    from techflex_cloud_foundation.server.report_copy.object_store import (
        MAX_REPORT_PDF_BYTES,
        REPORT_PDF_CONTENT_TYPE,
        REPORT_PDF_SCHEMA_VERSION,
    )

    async def exercise() -> None:
        gateway = _Gateway()
        store = LocalBasicPdfStore(AliyunOSSObjectStore(gateway, server_side_encryption="KMS"))
        saved = await store.put(uuid4(), uuid4(), b"%PDF-1.4\nx\n%%EOF")
        stored = gateway.objects[saved.object_key]
        assert stored.content_type == REPORT_PDF_CONTENT_TYPE == "application/pdf"
        assert stored.metadata["schema-version"] == REPORT_PDF_SCHEMA_VERSION
        assert stored.metadata["sha256"] == saved.sha256
        # A body that no longer matches its recorded digest is refused on read.
        gateway.objects[saved.object_key] = replace(stored, body=b"tampered")
        with pytest.raises(DigestMismatch):
            await store.read(saved.object_key)
        # An object above the cap is refused before it is read.
        big = b"x" * (MAX_REPORT_PDF_BYTES + 1)  # its digest is consistent, so only the cap refuses it
        gateway.objects[saved.object_key] = replace(
            stored, body=big, metadata={**stored.metadata, "sha256": hashlib.sha256(big).hexdigest()}
        )
        with pytest.raises(DigestMismatch):
            await store.read(saved.object_key)

    asyncio.run(exercise())
