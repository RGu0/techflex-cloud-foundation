"""Contract tests for the client-side resume driver (F-29, RAY-425 R2)."""

from __future__ import annotations

from collections.abc import AsyncIterable
from datetime import UTC, datetime, timedelta
import hashlib
from uuid import UUID, uuid4

import pytest

from techflex_cloud_foundation import (
    ArtifactEntry,
    ArtifactManifest,
    ArtifactPart,
    EligibilityDecision,
    IngestionPrincipal,
    IngestionService,
    InMemoryIngestionStore,
    InMemoryObjectStore,
    PartMetadata,
    PartSource,
    ResumeDriver,
    TransferConflict,
    TransferExhausted,
    TransferQuarantined,
    TransferRetryable,
)
from techflex_cloud_foundation.ingestion import (
    ArtifactReceipt,
    PartAcknowledgement,
    PartListResponse,
    SessionState,
    SessionStatus,
)

pytestmark = pytest.mark.anyio

NOW = datetime(2026, 9, 7, tzinfo=UTC)
PART_A = b"part-a" * 100
PART_B = b"part-b" * 100
DIGEST_A = hashlib.sha256(PART_A).hexdigest()
DIGEST_B = hashlib.sha256(PART_B).hexdigest()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _manifest() -> ArtifactManifest:
    return ArtifactManifest(
        artifact_kind="test/transfer",
        entries=(
            ArtifactEntry(
                path="payload.bin",
                size=len(PART_A) + len(PART_B),
                sha256=hashlib.sha256(PART_A + PART_B).hexdigest(),
                parts=(
                    ArtifactPart(index=0, offset=0, size=len(PART_A), sha256=DIGEST_A),
                    ArtifactPart(index=1, offset=len(PART_A), size=len(PART_B), sha256=DIGEST_B),
                ),
            ),
        ),
    )


def _source(index: int, payload: bytes, digest: str) -> PartSource:
    async def open_chunks() -> AsyncIterable[bytes]:
        for offset in range(0, len(payload), 64):
            yield payload[offset : offset + 64]

    return PartSource(
        metadata=PartMetadata(
            index=index, sha256=digest, size=len(payload), payload_schema="test/transfer"
        ),
        open_chunks=open_chunks,
    )


def _eligibility() -> EligibilityDecision:
    return EligibilityDecision(
        purpose="analysis",
        allowed=True,
        reason="purpose allows upload",
        policy_version="policy/1",
        decided_at=NOW,
    )


class FakeEndpoint:
    """In-memory stand-in for the remote plane, tracking server state."""

    def __init__(self) -> None:
        self.sessions: dict[UUID, dict] = {}
        self.put_calls: list[int] = []
        self.flaky_parts: set[int] = set()

    async def begin_session(self, *, payload_schema, part_count, idempotency_key, now):
        for session_id, record in self.sessions.items():
            if record["begin_key"] == idempotency_key:
                return session_id, True
        session_id = uuid4()
        self.sessions[session_id] = {
            "begin_key": idempotency_key,
            "part_count": part_count,
            "parts": {},
            "receipt": None,
            "quarantined": (),
        }
        return session_id, False

    async def list_parts(self, session_id, *, now):
        record = self.sessions[session_id]
        received = tuple(record["parts"][i] for i in sorted(record["parts"]))
        missing = tuple(
            i for i in range(record["part_count"]) if i not in record["parts"]
        )
        return PartListResponse(session_id=session_id, received=received, missing=missing)

    async def put_part(self, session_id, metadata, chunks):
        self.put_calls.append(metadata.index)
        if metadata.index in self.flaky_parts:
            self.flaky_parts.remove(metadata.index)
            async for _ in chunks:
                pass
            raise TransferRetryable("simulated transient failure")
        running = hashlib.sha256()
        total = 0
        async for chunk in chunks:
            running.update(chunk)
            total += len(chunk)
        assert running.hexdigest() == metadata.sha256
        assert total == metadata.size
        ack = PartAcknowledgement(
            session_id=session_id,
            index=metadata.index,
            sha256=metadata.sha256,
            object_key=f"obj/{session_id}/{metadata.index}",
        )
        self.sessions[session_id]["parts"][metadata.index] = ack
        return ack

    async def status(self, session_id, *, now):
        record = self.sessions[session_id]
        return SessionStatus(
            session_id=session_id,
            state=SessionState.COMPLETED if record["receipt"] else SessionState.OPEN,
            payload_schema="test/transfer",
            part_count=record["part_count"],
            received_count=len(record["parts"]),
            conflicted_indices=record["quarantined"],
            receipt=record["receipt"],
        )

    async def complete(
        self,
        session_id,
        *,
        manifest,
        expected_manifest_digest,
        eligibility,
        idempotency_key,
        now,
    ):
        record = self.sessions[session_id]
        if record["receipt"] is not None:
            return record["receipt"]
        assert len(record["parts"]) == record["part_count"]
        receipt = ArtifactReceipt(
            session_id=session_id,
            manifest_digest=manifest.digest(),
            manifest_object_key=f"obj/{session_id}/manifest",
            eligibility_reason=eligibility.reason,
            eligibility_policy_version=eligibility.policy_version,
            completed_at=now,
            idempotency_key=idempotency_key,
            verification_version="content/1",
        )
        record["receipt"] = receipt
        return receipt


def _parts() -> tuple[PartSource, PartSource]:
    return (_source(0, PART_A, DIGEST_A), _source(1, PART_B, DIGEST_B))


async def test_full_upload_issues_receipt_that_authorizes_retirement() -> None:
    endpoint = FakeEndpoint()
    driver = ResumeDriver(endpoint)
    manifest = _manifest()

    receipt = await driver.upload(
        manifest=manifest, parts=_parts(), eligibility=_eligibility(), now=NOW
    )

    assert receipt.manifest_digest == manifest.digest()
    assert endpoint.put_calls == [0, 1]
    assert ResumeDriver.may_retire_local(receipt, manifest) is True


async def test_resume_skips_parts_the_server_already_holds() -> None:
    endpoint = FakeEndpoint()
    driver = ResumeDriver(endpoint)
    manifest = _manifest()
    session_id, _ = await endpoint.begin_session(
        payload_schema=manifest.artifact_kind,
        part_count=2,
        idempotency_key="transfer-begin:" + manifest.digest(),
        now=NOW,
    )
    await endpoint.put_part(session_id, _parts()[0].metadata, _parts()[0].open_chunks())
    endpoint.put_calls.clear()

    receipt = await driver.upload(
        manifest=manifest, parts=_parts(), eligibility=_eligibility(), now=NOW
    )

    assert endpoint.put_calls == [1]  # only the missing part was sent
    assert receipt.manifest_digest == manifest.digest()


@pytest.mark.parametrize("held_index", [0, 1])
async def test_resume_digest_conflict_refuses_all_puts_and_completion(held_index: int) -> None:
    """A stale held slot must fail before even an earlier missing slot is sent."""
    endpoint = FakeEndpoint()
    manifest = _manifest()
    session_id, _ = await endpoint.begin_session(
        payload_schema=manifest.artifact_kind,
        part_count=2,
        idempotency_key="stable-business-key",
        now=NOW,
    )
    stale_bytes = b"previous-sealed-bytes"
    stale = _source(held_index, stale_bytes, hashlib.sha256(stale_bytes).hexdigest())
    await endpoint.put_part(session_id, stale.metadata, stale.open_chunks())
    endpoint.put_calls.clear()

    with pytest.raises(TransferConflict):
        await ResumeDriver(endpoint).upload(
            manifest=manifest, parts=_parts(), eligibility=_eligibility(), now=NOW,
            begin_key="stable-business-key",
        )

    assert endpoint.put_calls == []
    assert endpoint.sessions[session_id]["receipt"] is None
    assert endpoint.sessions[session_id]["parts"][held_index].sha256 == stale.metadata.sha256
    assert endpoint.sessions[session_id]["quarantined"] == ()

    receipt = await ResumeDriver(endpoint).upload(
        manifest=manifest, parts=_parts(), eligibility=_eligibility(), now=NOW,
        begin_key="fresh-business-key",
    )
    assert receipt.session_id != session_id
    assert ResumeDriver.may_retire_local(receipt, manifest)


async def test_resume_compares_source_metadata_even_when_manifest_matches_remote() -> None:
    endpoint = FakeEndpoint()
    manifest = _manifest()
    session_id, _ = await endpoint.begin_session(
        payload_schema=manifest.artifact_kind,
        part_count=2,
        idempotency_key="stable-business-key",
        now=NOW,
    )
    await endpoint.put_part(session_id, _parts()[0].metadata, _parts()[0].open_chunks())
    endpoint.put_calls.clear()
    changed_bytes = b"newly-sealed-bytes"
    changed = _source(0, changed_bytes, hashlib.sha256(changed_bytes).hexdigest())

    with pytest.raises(TransferConflict):
        await ResumeDriver(endpoint).upload(
            manifest=manifest, parts=(changed, _parts()[1]), eligibility=_eligibility(),
            now=NOW, begin_key="stable-business-key",
        )

    assert endpoint.put_calls == []
    assert endpoint.sessions[session_id]["receipt"] is None


async def test_real_ingestion_replay_conflict_cannot_issue_a_retirement_receipt() -> None:
    service = IngestionService(
        InMemoryObjectStore(), InMemoryIngestionStore(),
        supported_payload_schemas=frozenset({"test/transfer"}),
    )
    principal = IngestionPrincipal(
        tenant_id="tenant-a", uploader_id="terminal-a", allow_upload=True,
        expires_at=NOW + timedelta(hours=1),
    )

    class ServiceEndpoint:
        async def begin_session(self, **kwargs):
            return await service.begin_session(principal, **kwargs)

        async def list_parts(self, session_id, **kwargs):
            return await service.list_parts(principal, session_id, **kwargs)

        async def status(self, session_id, **kwargs):
            return await service.status(principal, session_id, **kwargs)

        async def put_part(self, session_id, metadata, chunks):
            return await service.put_part(principal, session_id, metadata, chunks, now=NOW)

        async def complete(self, session_id, **kwargs):
            return await service.complete(principal, session_id, **kwargs)

    endpoint = ServiceEndpoint()
    manifest = _manifest()
    session_id, _ = await endpoint.begin_session(
        payload_schema=manifest.artifact_kind, part_count=2,
        idempotency_key="stable-business-key", now=NOW,
    )
    old_bytes = b"old-ciphertext"
    old_source = _source(1, old_bytes, hashlib.sha256(old_bytes).hexdigest())
    await endpoint.put_part(session_id, old_source.metadata, old_source.open_chunks())

    with pytest.raises(TransferConflict):
        await ResumeDriver(endpoint).upload(
            manifest=manifest, parts=_parts(), eligibility=_eligibility(), now=NOW,
            begin_key="stable-business-key",
        )

    status = await endpoint.status(session_id, now=NOW)
    listing = await endpoint.list_parts(session_id, now=NOW)
    assert status.receipt is None
    assert status.conflicted_indices == ()
    assert listing.missing == (0,)
    assert [(ack.index, ack.sha256) for ack in listing.received] == [
        (1, old_source.metadata.sha256)
    ]


async def test_transient_part_failure_is_retried_within_budget() -> None:
    endpoint = FakeEndpoint()
    endpoint.flaky_parts.add(1)
    driver = ResumeDriver(endpoint, max_part_attempts=2)

    receipt = await driver.upload(
        manifest=_manifest(), parts=_parts(), eligibility=_eligibility(), now=NOW
    )

    assert endpoint.put_calls == [0, 1, 1]
    assert receipt is not None


async def test_exhausting_the_budget_raises() -> None:
    endpoint = FakeEndpoint()
    endpoint.flaky_parts.update((1, 1))  # a set holds one; simulate persistent failure
    endpoint.flaky_parts = set()

    class AlwaysFlaky(FakeEndpoint):
        async def put_part(self, session_id, metadata, chunks):
            async for _ in chunks:
                pass
            raise TransferRetryable("always")

    driver = ResumeDriver(AlwaysFlaky(), max_part_attempts=2)

    with pytest.raises(TransferExhausted, match="2 attempts"):
        await driver.upload(
            manifest=_manifest(), parts=_parts(), eligibility=_eligibility(), now=NOW
        )


async def test_quarantined_session_is_refused() -> None:
    endpoint = FakeEndpoint()
    driver = ResumeDriver(endpoint)
    manifest = _manifest()
    session_id, _ = await endpoint.begin_session(
        payload_schema=manifest.artifact_kind,
        part_count=2,
        idempotency_key="transfer-begin:" + manifest.digest(),
        now=NOW,
    )
    endpoint.sessions[session_id]["quarantined"] = (0,)

    with pytest.raises(TransferQuarantined, match="quarantined"):
        await driver.upload(
            manifest=manifest, parts=_parts(), eligibility=_eligibility(), now=NOW
        )


async def test_rerun_after_completion_replays_without_new_puts() -> None:
    endpoint = FakeEndpoint()
    driver = ResumeDriver(endpoint)
    manifest = _manifest()

    first = await driver.upload(
        manifest=manifest, parts=_parts(), eligibility=_eligibility(), now=NOW
    )
    endpoint.put_calls.clear()
    second = await driver.upload(
        manifest=manifest, parts=_parts(), eligibility=_eligibility(), now=NOW
    )

    assert first.session_id == second.session_id
    assert endpoint.put_calls == []


async def test_receipt_only_retires_the_exact_manifest() -> None:
    endpoint = FakeEndpoint()
    driver = ResumeDriver(endpoint)
    receipt = await driver.upload(
        manifest=_manifest(), parts=_parts(), eligibility=_eligibility(), now=NOW
    )

    other = ArtifactManifest(
        artifact_kind="test/other",
        entries=(ArtifactEntry(path="x", size=1, sha256=DIGEST_A),),
    )
    assert ResumeDriver.may_retire_local(receipt, other) is False
