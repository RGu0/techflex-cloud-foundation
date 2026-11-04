"""Characterize HTTP metadata completion separately from generic content/1.

These tests pin the current compatibility boundary, not a new storage guarantee.
A future authorized content-verification adapter must revise that boundary.
"""
from __future__ import annotations

import asyncio
import base64
from datetime import timedelta
import hashlib
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation import ArtifactEntry, ArtifactManifest, ResumeDriver
from techflex_cloud_foundation.contracts.cloud import ManifestCompletionResponse
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from tests.test_registry_ingestion_http import canonical, documents


@pytest.mark.parametrize("lose_object_after_put", [False, True])
def test_http_ingested_is_not_a_generic_content_receipt(lose_object_after_put):
    async def exercise():
        tenant, terminal = uuid4(), uuid4()
        repository = InMemoryPlatformRepository()
        repository.add_terminal(tenant, None, terminal)
        objects = InMemoryObjectStore()
        issuer = TerminalTokenIssuer(
            secret=b"receipt-boundary-test-secret-32-bytes", key_id="test",
            token_ttl=timedelta(hours=1),
        )
        app = create_app(ServiceContainer(
            ingestion=IngestionService(repository, SegmentObjectStore(objects)),
            token_issuer=issuer,
        ))
        session, metadata, manifest, payload = documents(terminal)
        headers = {"Authorization": "Bearer " + issuer.issue(tenant, terminal),
                   "X-Terminal-ID": str(terminal), "Idempotency-Key": str(uuid4())}
        path = f"/v1/sessions/{session['session_id']}"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as client:
            created = await client.post("/v1/sessions", json=session, headers=headers)
            assert created.status_code == 201, created.text
            uploaded = await client.put(path + "/segments/0", content=payload, headers={
                **headers, "Content-Type": "application/octet-stream",
                "X-Content-SHA256": metadata["sha256"],
                "X-Schema-Version": metadata["payload_schema_version"],
                "X-Segment-Metadata": base64.urlsafe_b64encode(canonical(metadata)).decode(),
            })
            assert uploaded.status_code == 201, uploaded.text
            key = uploaded.json()["data"]["object_key"]
            assert await objects.read(key) == payload
            if lose_object_after_put:
                # Isolated fault injection, after valid upload and before complete.
                await objects.delete(key)
                with pytest.raises(KeyError):
                    await objects.read(key)
            digest = hashlib.sha256(canonical(manifest)).hexdigest()
            completed = await client.post(path + "/complete", json=manifest, headers={
                **headers, "Idempotency-Key": str(uuid4()), "X-Content-SHA256": digest,
                "X-Schema-Version": manifest["schema_version"],
            })
            assert completed.status_code == 200, completed.text
            response = ManifestCompletionResponse.model_validate(completed.json()["data"])
            assert response.ingest_status == "INGESTED"
            assert response.manifest_sha256 == digest
            assert "verification_version" not in completed.json()["data"]
            local_manifest = ArtifactManifest(entries=(ArtifactEntry(
                path="archive.bin", size=len(payload), sha256=metadata["sha256"],
            ),), artifact_kind="test.archive")
            assert not ResumeDriver.may_retire_local(response, local_manifest)
            status = await client.get(path + "/status", headers=headers)
            assert status.status_code == 200, status.text
            assert status.json()["data"]["ingest_status"] == "INGESTED"
            assert "receipt" not in status.json()["data"]
    asyncio.run(exercise())
