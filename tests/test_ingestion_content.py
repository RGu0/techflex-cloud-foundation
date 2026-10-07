"""RAY-540: receipts prove stored bytes, not just submitted metadata."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib

import pytest

from techflex_cloud_foundation import (
    ArtifactEntry,
    ArtifactManifest,
    ArtifactPart,
    ArtifactReceipt,
    EligibilityDecision,
    FileSystemObjectStore,
    IngestionConflict,
    IngestionMalformed,
    IngestionPrincipal,
    IngestionService,
    IngestionStateError,
    InMemoryIngestionStore,
    InMemoryObjectStore,
    PartMetadata,
    ResumeDriver,
)

pytestmark = pytest.mark.anyio
NOW = datetime(2026, 10, 7, tzinfo=UTC)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def manifest(payloads, *, mapping=True):
    return ArtifactManifest(
        entries=tuple(
            ArtifactEntry(
                str(i), len(data), sha(data), parts=(ArtifactPart(0, 0, len(data), sha(data)),)
            )
            for i, data in enumerate(payloads)
        ),
        artifact_kind="test",
        annotations={"ingestion_mapping": "entry-parts/1"} if mapping else {},
    )


async def opened(objects, payloads):
    sessions = InMemoryIngestionStore()
    service = IngestionService(objects, sessions, supported_payload_schemas=frozenset({"test/1"}))
    principal = IngestionPrincipal("tenant", "terminal", True, NOW + timedelta(hours=1))
    sid, _ = await service.begin_session(
        principal,
        payload_schema="test/1",
        part_count=len(payloads),
        idempotency_key="begin",
        now=NOW,
    )
    for i, data in enumerate(payloads):

        async def chunks(value=data):
            yield value

        await service.put_part(
            principal, sid, PartMetadata(i, sha(data), len(data), "test/1"), chunks(), now=NOW
        )
    return service, sessions, principal, sid


async def finish(service, principal, sid, doc, key="complete"):
    return await service.complete(
        principal,
        sid,
        manifest=doc,
        expected_manifest_digest=doc.digest(),
        eligibility=EligibilityDecision("test", True, "allowed", "test/1", NOW),
        idempotency_key=key,
        now=NOW,
    )


@pytest.mark.parametrize("declared", [b"BBB", b"AA", b"AAAA"])
async def test_direct_complete_refuses_unstored_content_without_manifest(declared):
    objects = InMemoryObjectStore()
    service, _, principal, sid = await opened(objects, [b"AAA"])
    with pytest.raises(IngestionConflict):
        await finish(service, principal, sid, manifest([declared]))
    assert (await service.status(principal, sid, now=NOW)).receipt is None
    assert objects.object_count == 1


async def test_correct_parts_with_wrong_entry_digest_are_not_a_proof():
    objects = InMemoryObjectStore()
    service, _, principal, sid = await opened(objects, [b"AAA"])
    doc = manifest([b"AAA"])
    doc = replace(doc, entries=(replace(doc.entries[0], sha256=sha(b"BBB")),))
    with pytest.raises(IngestionConflict):
        await finish(service, principal, sid, doc)
    assert objects.object_count == 1


@pytest.mark.parametrize(
    "kind", ["unknown", "legacy_multi", "empty", "duplicate", "gap", "overlap", "count"]
)
async def test_bad_mapping_never_signs_a_receipt(kind):
    objects = InMemoryObjectStore()
    service, _, principal, sid = await opened(objects, [b"AAA", b"BBB"])
    doc = manifest([b"AAA", b"BBB"])
    if kind == "unknown":
        doc = replace(doc, annotations={"ingestion_mapping": "future/1"})
    elif kind == "legacy_multi":
        doc = replace(doc, annotations={})
    elif kind == "empty":
        doc = replace(doc, entries=())
    elif kind == "count":
        doc = replace(doc, entries=doc.entries[:1])
    else:
        parts = (
            ArtifactPart(0, 0, 1, sha(b"A")),
            ArtifactPart(
                0 if kind == "duplicate" else 1,
                2 if kind == "gap" else 0 if kind == "overlap" else 1,
                1,
                sha(b"A"),
            ),
        )
        doc = replace(doc, entries=(ArtifactEntry("a", 3, sha(b"AAA"), parts=parts),))
    with pytest.raises((IngestionMalformed, IngestionStateError)):
        await finish(service, principal, sid, doc)
    assert (await service.status(principal, sid, now=NOW)).receipt is None
    assert objects.object_count == 2


@pytest.mark.parametrize("filesystem", [False, True])
async def test_two_local_zero_indices_and_empty_entry_stream_success(filesystem, tmp_path):
    objects = FileSystemObjectStore(tmp_path) if filesystem else InMemoryObjectStore()
    service, _, principal, sid = await opened(objects, [b"AAA", b""])
    doc = manifest([b"AAA", b""])
    receipt = await finish(service, principal, sid, doc)
    assert receipt.verification_version == "content/1"
    assert ResumeDriver.may_retire_local(receipt, doc)
    assert b'"verification_version":"content/1"' in receipt.canonical_bytes()


async def test_concurrent_completion_returns_one_identical_receipt():
    class YieldingObjects(InMemoryObjectStore):
        async def put_verified(self, *args, **kwargs):
            result = await super().put_verified(*args, **kwargs)
            await asyncio.sleep(0)
            return result

    service, _, principal, sid = await opened(YieldingObjects(), [b"AAA"])
    doc = manifest([b"AAA"])
    first, second = await asyncio.gather(
        finish(service, principal, sid, doc, "one"), finish(service, principal, sid, doc, "two")
    )
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first is second


@pytest.mark.parametrize("version", [None, "future/2"])
async def test_historical_receipt_status_unchanged_but_complete_and_retirement_refused(version):
    service, sessions, principal, sid = await opened(InMemoryObjectStore(), [b"AAA"])
    doc = manifest([b"AAA"], mapping=False)
    receipt = ArtifactReceipt(
        sid, doc.digest(), "old/manifest", "allowed", "test/1", NOW, "old", version
    )
    record = await sessions.get(principal.tenant_id, sid)
    record.receipt = receipt
    original = receipt.canonical_bytes()
    assert not ResumeDriver.may_retire_local(receipt, doc)
    with pytest.raises(IngestionStateError):
        await finish(service, principal, sid, doc)
    assert (await service.status(principal, sid, now=NOW)).receipt is receipt
    assert receipt.canonical_bytes() == original
    if version is None:
        assert b"verification_version" not in original


@pytest.mark.parametrize("filesystem", [False, True])
async def test_streaming_does_not_call_whole_object_read_and_chunks_are_bounded(
    filesystem, tmp_path
):
    base = FileSystemObjectStore if filesystem else InMemoryObjectStore

    class StreamOnly(base):
        async def read(self, key):
            raise AssertionError("completion must not materialize a whole object")

    objects = StreamOnly(tmp_path) if filesystem else StreamOnly()
    payload = b"large" * 500_000
    service, _, principal, sid = await opened(objects, [payload])
    listing = await service.list_parts(principal, sid, now=NOW)
    count = 0
    total = 0
    async for chunk in objects.read_chunks(listing.received[0].object_key):
        assert 0 < len(chunk) <= 1 << 20
        total += len(chunk)
        count += 1
    assert count >= 3 and total == len(payload)
    assert (
        await finish(service, principal, sid, manifest([payload]))
    ).verification_version == "content/1"


@pytest.mark.parametrize("corrupted", [False, True])
async def test_actual_storage_loss_or_replacement_never_signs(corrupted):
    objects = InMemoryObjectStore()
    service, _, principal, sid = await opened(objects, [b"AAA"])
    ack = (await service.list_parts(principal, sid, now=NOW)).received[0]
    await objects.delete(ack.object_key)
    if corrupted:

        async def chunks():
            yield b"BBB"

        await objects.put_verified(
            ack.object_key, chunks(), expected_sha256=sha(b"BBB"), expected_size=3
        )
    with pytest.raises(IngestionConflict if corrupted else KeyError):
        await finish(service, principal, sid, manifest([b"AAA"]))
    assert (await service.status(principal, sid, now=NOW)).receipt is None
    assert objects.object_count == int(corrupted)


async def test_swapped_global_slots_fail_and_do_not_quarantine_correct_parts():
    objects = InMemoryObjectStore()
    service, sessions, principal, sid = await opened(objects, [b"BBB", b"AAA"])
    with pytest.raises(IngestionConflict):
        await finish(service, principal, sid, manifest([b"AAA", b"BBB"]))
    assert not (await sessions.get("tenant", sid)).conflicted
    receipt = await finish(service, principal, sid, manifest([b"BBB", b"AAA"]))
    assert receipt.verification_version == "content/1"


async def test_multipart_entry_verifies_concatenated_digest_in_entry_order():
    service, _, principal, sid = await opened(InMemoryObjectStore(), [b"ab", b"cd", b"e"])
    doc = ArtifactManifest(
        entries=(
            ArtifactEntry(
                "first",
                4,
                sha(b"abcd"),
                parts=(ArtifactPart(0, 0, 2, sha(b"ab")), ArtifactPart(1, 2, 2, sha(b"cd"))),
            ),
            ArtifactEntry("second", 1, sha(b"e"), parts=(ArtifactPart(0, 0, 1, sha(b"e")),)),
        ),
        artifact_kind="test",
        annotations={"ingestion_mapping": "entry-parts/1"},
    )
    receipt = await finish(service, principal, sid, doc)
    assert receipt.manifest_digest == doc.digest()
    assert (await finish(service, principal, sid, doc, "lost-response")) is receipt


@pytest.mark.parametrize("version", [None, "future/2"])
async def test_retirement_refuses_unverified_and_unknown_receipts(version):
    service, _, principal, sid = await opened(InMemoryObjectStore(), [b"AAA"])
    doc = manifest([b"AAA"])
    verified = await finish(service, principal, sid, doc)
    assert not ResumeDriver.may_retire_local(replace(verified, verification_version=version), doc)
    assert not ResumeDriver.may_retire_local(verified, manifest([b"BBB"]))


@pytest.mark.parametrize("explicit", [False, True])
async def test_legacy_single_entry_slot_is_actually_verified(explicit):
    service, _, principal, sid = await opened(InMemoryObjectStore(), [b"AAA"])
    doc = manifest([b"AAA"], mapping=False)
    if not explicit:
        doc = replace(doc, entries=(replace(doc.entries[0], parts=()),))
    receipt = await finish(service, principal, sid, doc)
    assert ResumeDriver.may_retire_local(receipt, doc)


async def test_empty_entry_rejects_duplicate_zero_parts():
    service, _, principal, sid = await opened(InMemoryObjectStore(), [b"", b""])
    doc = ArtifactManifest(
        entries=(
            ArtifactEntry(
                "empty",
                0,
                sha(b""),
                parts=(ArtifactPart(0, 0, 0, sha(b"")), ArtifactPart(1, 0, 0, sha(b""))),
            ),
        ),
        artifact_kind="test",
        annotations={"ingestion_mapping": "entry-parts/1"},
    )
    with pytest.raises(IngestionMalformed):
        await finish(service, principal, sid, doc)


async def test_finalize_rechecks_part_set_changed_after_verification():
    class CleanupRace(InMemoryObjectStore):
        async def put_verified(self, key, chunks, **kwargs):
            stored = await super().put_verified(key, chunks, **kwargs)
            if key.endswith("/manifest"):
                # Simulate a concurrent persistence/retention adapter removing
                # a slot after read-back; finalization must not attest it.
                (await sessions.get("tenant", sid)).parts.clear()
            return stored

    service, sessions, principal, sid = await opened(CleanupRace(), [b"AAA"])
    with pytest.raises(IngestionStateError):
        await finish(service, principal, sid, manifest([b"AAA"]))
    assert (await service.status(principal, sid, now=NOW)).receipt is None


async def test_conflicting_put_during_verification_cannot_finalize():
    class ConcurrentWriter(InMemoryObjectStore):
        async def read_chunks(self, key):
            async for chunk in super().read_chunks(key):

                async def conflicting():
                    yield b"BBB"

                with pytest.raises(IngestionConflict):
                    await service.put_part(
                        principal,
                        sid,
                        PartMetadata(0, sha(b"BBB"), 3, "test/1"),
                        conflicting(),
                        now=NOW,
                    )
                yield chunk

    service, _, principal, sid = await opened(ConcurrentWriter(), [b"AAA"])
    with pytest.raises(IngestionStateError):
        await finish(service, principal, sid, manifest([b"AAA"]))
    status = await service.status(principal, sid, now=NOW)
    assert status.receipt is None and status.conflicted_indices == (0,)


async def test_portable_fixture_canonical_digests_mapping_and_retirement():
    import json
    from pathlib import Path
    from uuid import UUID

    fixture = json.loads(
        (Path(__file__).parents[1] / "docs/contracts/ingestion-content-vectors.json").read_text()
    )
    doc = ArtifactManifest.from_bytes(bytes.fromhex(fixture["manifest_canonical_hex"]))
    assert doc.to_canonical_bytes().hex() == fixture["manifest_canonical_hex"]
    assert doc.digest() == fixture["manifest_sha256"]
    payloads = [bytes.fromhex(slot["payload_hex"]) for slot in fixture["slots"]]
    service, _, principal, sid = await opened(InMemoryObjectStore(), payloads)
    actual = await finish(service, principal, sid, doc)
    assert actual.verification_version == "content/1"
    for vector in fixture["receipts"]:
        values = dict(vector["document"])
        values["session_id"] = UUID(values["session_id"])
        values["completed_at"] = datetime.fromisoformat(values["completed_at"])
        receipt = ArtifactReceipt(**values)
        assert receipt.canonical_bytes().hex() == vector["canonical_hex"]
        assert receipt.digest() == vector["sha256"]
        assert ResumeDriver.may_retire_local(receipt, doc) is vector["may_retire_local"]
