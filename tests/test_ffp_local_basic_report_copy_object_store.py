"""The report PDF remains a private object and is read through the adapter."""

from __future__ import annotations

import asyncio
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
