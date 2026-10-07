"""Execute the application reconciliation example against real public contracts."""

from collections import Counter
from collections.abc import AsyncIterable
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    ArtifactEntry,
    ArtifactManifest,
    EligibilityDecision,
    IngestionPrincipal,
    IngestionService,
    InMemoryIngestionStore,
    InMemoryObjectStore,
    OperationState,
    PartMetadata,
    ReliableOperation,
    ResumeDriver,
    SqliteOperationStore,
)

pytestmark = pytest.mark.anyio
NOW = datetime(2026, 10, 7, tzinfo=UTC)
SCHEMA = "application-upload/1"
PAYLOAD = b"durable local artifact"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _application_reconcile():
    guide = (Path(__file__).parents[1] / "docs/guides/reliable-upload.md").read_text()
    section = "## 4. Application-owned status reconciliation"
    assert section in guide, "Missing executable application reconciliation example"
    block = guide.split(section, 1)[1].split("```python\n", 1)[1].split("```", 1)[0]
    namespace = {}
    exec(compile(block, "reliable-upload.md", "exec"), namespace)
    return namespace["reconcile_completed_upload"]


def _manifest(payload=PAYLOAD):
    return ArtifactManifest(
        artifact_kind=SCHEMA,
        entries=(ArtifactEntry(path="payload.bin", size=len(payload),
                               sha256=hashlib.sha256(payload).hexdigest()),),
    )


class ObservedServiceEndpoint:
    """Observe calls while delegating every result to the actual ingestion service."""

    def __init__(self):
        self.service = IngestionService(
            InMemoryObjectStore(), InMemoryIngestionStore(),
            supported_payload_schemas=frozenset({SCHEMA}),
        )
        self.principal = IngestionPrincipal(
            tenant_id="institution-a", uploader_id="terminal-a", allow_upload=True,
            expires_at=NOW + timedelta(hours=1),
        )
        self.calls = Counter()
        self.drop_completion_response = False
        self.committed_receipt = None

    async def begin_session(self, **kwargs):
        self.calls["begin"] += 1
        return await self.service.begin_session(self.principal, **kwargs)

    async def list_parts(self, session_id, **kwargs):
        self.calls["list"] += 1
        return await self.service.list_parts(self.principal, session_id, **kwargs)

    async def put_part(self, session_id, metadata, chunks):
        self.calls["put"] += 1
        return await self.service.put_part(self.principal, session_id, metadata, chunks, now=NOW)

    async def complete(self, session_id, **kwargs):
        self.calls["complete"] += 1
        receipt = await self.service.complete(self.principal, session_id, **kwargs)
        self.committed_receipt = receipt
        if self.drop_completion_response:
            raise ConnectionError("response lost after server commit")
        return receipt

    async def status(self, session_id, **kwargs):
        self.calls["status"] += 1
        return await self.service.status(self.principal, session_id, **kwargs)


async def _server_session(endpoint, *, completed=True, lose_response=False):
    manifest = _manifest()
    session_id, _ = await endpoint.begin_session(
        payload_schema=SCHEMA, part_count=1, idempotency_key="stable-begin", now=NOW,
    )
    if not completed:
        endpoint.calls.clear()
        return session_id, None

    async def chunks() -> AsyncIterable[bytes]:
        yield PAYLOAD

    await endpoint.put_part(
        session_id, PartMetadata(index=0, sha256=hashlib.sha256(PAYLOAD).hexdigest(),
                                 size=len(PAYLOAD), payload_schema=SCHEMA), chunks(),
    )
    completion = dict(
        manifest=manifest, expected_manifest_digest=manifest.digest(),
        eligibility=EligibilityDecision(purpose="analysis", allowed=True,
                                        reason="valid consent", policy_version="consent/1",
                                        decided_at=NOW),
        idempotency_key="stable-complete", now=NOW,
    )
    endpoint.drop_completion_response = lose_response
    if lose_response:
        with pytest.raises(ConnectionError, match="response lost after server commit"):
            await endpoint.complete(session_id, **completion)
        receipt = endpoint.committed_receipt
    else:
        receipt = await endpoint.complete(session_id, **completion)
    endpoint.calls.clear()
    return session_id, receipt


def _lease(store, local_file, manifest):
    operation = ReliableOperation.create(
        kind="application.upload", payload_ref=str(local_file),
        payload_digest=manifest.digest(), idempotency_key="local-upload",
    )
    store.enqueue(operation)
    return store.lease_due(now=NOW)


async def test_completed_status_confirms_real_queue_without_upload_calls(tmp_path):
    reconcile = _application_reconcile()
    endpoint = ObservedServiceEndpoint()
    session_id, receipt = await _server_session(endpoint)
    local = tmp_path / "payload.bin"
    local.write_bytes(PAYLOAD)
    store = SqliteOperationStore(tmp_path / "queue.sqlite")
    try:
        lease = _lease(store, local, _manifest())
        result = await reconcile(endpoint, session_id, _manifest(), store, lease, now=NOW)
        assert result == receipt
        assert store.get(lease.operation_id).state is OperationState.CONFIRMED
        assert endpoint.calls == {"status": 1}
        # Only the application retires bytes, after both receipt and queue confirmation.
        local.unlink()
        assert not local.exists()
    finally:
        store.close()


@pytest.mark.parametrize("missing_receipt", [True, False])
async def test_missing_or_mismatched_receipt_keeps_local_bytes_and_queue(tmp_path, missing_receipt):
    reconcile = _application_reconcile()
    endpoint = ObservedServiceEndpoint()
    session_id, receipt = await _server_session(endpoint, completed=not missing_receipt)
    local_payload = PAYLOAD if missing_receipt else b"different pending bytes"
    manifest = _manifest(local_payload)
    local = tmp_path / "payload.bin"
    local.write_bytes(local_payload)
    store = SqliteOperationStore(tmp_path / "queue.sqlite")
    try:
        lease = _lease(store, local, manifest)
        result = await reconcile(endpoint, session_id, manifest, store, lease, now=NOW)
        assert result is None
        assert not ResumeDriver.may_retire_local(receipt, manifest)
        assert store.get(lease.operation_id).state is OperationState.LEASED
        assert local.read_bytes() == local_payload
        assert endpoint.calls == {"status": 1}
    finally:
        store.close()


async def test_lost_completion_response_reconciles_immutable_authoritative_receipt(tmp_path):
    reconcile = _application_reconcile()
    endpoint = ObservedServiceEndpoint()
    session_id, receipt = await _server_session(endpoint, lose_response=True)
    original_bytes, original_digest = receipt.canonical_bytes(), receipt.digest()
    # The service committed completion; the response never reached the client.
    local = tmp_path / "payload.bin"
    local.write_bytes(PAYLOAD)
    store = SqliteOperationStore(tmp_path / "queue.sqlite")
    try:
        lease = _lease(store, local, _manifest())
        result = await reconcile(endpoint, session_id, _manifest(), store, lease, now=NOW)
        status = await endpoint.status(session_id, now=NOW + timedelta(seconds=1))
        assert result.canonical_bytes() == status.receipt.canonical_bytes() == original_bytes
        assert result.digest() == status.receipt.digest() == original_digest
        assert store.get(lease.operation_id).state is OperationState.CONFIRMED
        assert endpoint.calls == {"status": 2}
    finally:
        store.close()
