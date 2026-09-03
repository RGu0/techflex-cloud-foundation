from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib

import pytest

from techflex_cloud_foundation import (
    ArtifactEntry,
    ArtifactManifest,
    EligibilityDecision,
    IngestionAccessDenied,
    IngestionConflict,
    IngestionEligibilityRejected,
    IngestionMalformed,
    IngestionPrincipal,
    IngestionSchemaUnsupported,
    IngestionService,
    IngestionStateError,
    InMemoryIngestionStore,
    InMemoryObjectStore,
    PartMetadata,
    SessionState,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"

NOW = datetime(2026, 9, 3, tzinfo=UTC)
SCHEMA = "product-payload/1"


def _principal(**overrides: object) -> IngestionPrincipal:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "uploader_id": "terminal-1",
        "allow_upload": True,
        "expires_at": NOW + timedelta(hours=1),
    }
    values.update(overrides)
    return IngestionPrincipal(**values)  # type: ignore[arg-type]


def _service() -> tuple[IngestionService, InMemoryObjectStore]:
    objects = InMemoryObjectStore()
    service = IngestionService(
        objects, InMemoryIngestionStore(), supported_payload_schemas=frozenset({SCHEMA})
    )
    return service, objects


def _part(index: int, payload: bytes, schema: str = SCHEMA) -> PartMetadata:
    return PartMetadata(
        index=index,
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        payload_schema=schema,
    )


async def _put(service: IngestionService, session_id, part: PartMetadata, payload: bytes):
    async def chunks():
        yield payload

    return await service.put_part(_principal(), session_id, part, chunks(), now=NOW)


def _manifest(payload: bytes) -> ArtifactManifest:
    return ArtifactManifest(
        entries=(
            ArtifactEntry(
                path="payload.bin",
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ),
        ),
        artifact_kind="measurement",
    )


def _eligibility(allowed: bool = True) -> EligibilityDecision:
    return EligibilityDecision(
        purpose="analysis",
        allowed=allowed,
        reason="policy evaluation recorded by the application",
        policy_version="policy/1",
        decided_at=NOW,
    )


async def _begin(service: IngestionService, part_count: int = 1, key: str = "begin-1"):
    return await service.begin_session(
        _principal(),
        payload_schema=SCHEMA,
        part_count=part_count,
        idempotency_key=key,
        now=NOW,
    )


@pytest.mark.anyio
async def test_begin_put_list_complete_happy_path() -> None:
    service, objects = _service()
    session_id, replayed = await _begin(service)
    assert not replayed

    payload = b"measurement-bytes"
    ack = await _put(service, session_id, _part(0, payload), payload)
    assert ack.object_key.startswith(f"tenant-a/{session_id}/parts/")
    assert not ack.idempotent_replay

    listing = await service.list_parts(_principal(), session_id, now=NOW)
    assert [part.index for part in listing.received] == [0]
    assert listing.missing == ()

    manifest = _manifest(payload)
    receipt = await service.complete(
        _principal(),
        session_id,
        manifest=manifest,
        expected_manifest_digest=manifest.digest(),
        eligibility=_eligibility(),
        idempotency_key="complete-1",
        now=NOW,
    )
    assert receipt.manifest_digest == manifest.digest()
    assert receipt.manifest_object_key == f"tenant-a/{session_id}/manifest"

    status = await service.status(_principal(), session_id, now=NOW)
    assert status.state is SessionState.COMPLETED
    assert status.receipt == receipt
    assert await objects.read(receipt.manifest_object_key) == manifest.to_canonical_bytes()


@pytest.mark.anyio
async def test_begin_replays_same_request_under_one_key() -> None:
    service, _ = _service()
    first, _ = await _begin(service)
    second, replayed = await _begin(service)
    assert replayed and second == first

    with pytest.raises(IngestionConflict, match="different request"):
        await service.begin_session(
            _principal(),
            payload_schema=SCHEMA,
            part_count=9,
            idempotency_key="begin-1",
            now=NOW,
        )


@pytest.mark.anyio
async def test_unknown_schema_is_refused_at_begin_and_put() -> None:
    service, _ = _service()
    with pytest.raises(IngestionSchemaUnsupported):
        await service.begin_session(
            _principal(),
            payload_schema="product-payload/9",
            part_count=1,
            idempotency_key="k",
            now=NOW,
        )
    session_id, _ = await _begin(service)
    payload = b"x"
    with pytest.raises(IngestionSchemaUnsupported):
        await _put(service, session_id, _part(0, payload, schema="product-payload/9"), payload)


@pytest.mark.anyio
async def test_part_schema_must_match_session_schema() -> None:
    other = IngestionService(
        InMemoryObjectStore(),
        InMemoryIngestionStore(),
        supported_payload_schemas=frozenset({SCHEMA, "product-payload/2"}),
    )
    session_id, _ = await other.begin_session(
        _principal(),
        payload_schema=SCHEMA,
        part_count=1,
        idempotency_key="k",
        now=NOW,
    )
    payload = b"x"
    with pytest.raises(IngestionSchemaUnsupported, match="pinned"):
        await _put(other, session_id, _part(0, payload, schema="product-payload/2"), payload)


@pytest.mark.anyio
async def test_same_content_replays_different_content_conflicts_and_quarantines() -> None:
    service, _ = _service()
    session_id, _ = await _begin(service)
    payload = b"original"
    await _put(service, session_id, _part(0, payload), payload)

    replay = await _put(service, session_id, _part(0, payload), payload)
    assert replay.idempotent_replay

    forged = b"forged"
    with pytest.raises(IngestionConflict, match="quarantined"):
        await _put(service, session_id, _part(0, forged), forged)

    with pytest.raises(IngestionConflict, match="quarantined"):
        await _put(service, session_id, _part(0, payload), payload)

    manifest = _manifest(payload)
    with pytest.raises(IngestionStateError, match="quarantined"):
        await service.complete(
            _principal(),
            session_id,
            manifest=manifest,
            expected_manifest_digest=manifest.digest(),
            eligibility=_eligibility(),
            idempotency_key="complete-1",
            now=NOW,
        )


@pytest.mark.anyio
async def test_complete_requires_all_parts() -> None:
    service, _ = _service()
    session_id, _ = await _begin(service, part_count=2)
    payload = b"only-part"
    await _put(service, session_id, _part(0, payload), payload)

    manifest = _manifest(payload)
    with pytest.raises(IngestionStateError, match="missing part"):
        await service.complete(
            _principal(),
            session_id,
            manifest=manifest,
            expected_manifest_digest=manifest.digest(),
            eligibility=_eligibility(),
            idempotency_key="complete-1",
            now=NOW,
        )


@pytest.mark.anyio
async def test_complete_rejects_manifest_digest_mismatch() -> None:
    service, _ = _service()
    session_id, _ = await _begin(service)
    payload = b"bytes"
    await _put(service, session_id, _part(0, payload), payload)

    with pytest.raises(IngestionMalformed, match="differs"):
        await service.complete(
            _principal(),
            session_id,
            manifest=_manifest(payload),
            expected_manifest_digest=hashlib.sha256(b"other").hexdigest(),
            eligibility=_eligibility(),
            idempotency_key="complete-1",
            now=NOW,
        )


@pytest.mark.anyio
async def test_complete_requires_application_eligibility_allowance() -> None:
    service, _ = _service()
    session_id, _ = await _begin(service)
    payload = b"bytes"
    await _put(service, session_id, _part(0, payload), payload)

    manifest = _manifest(payload)
    with pytest.raises(IngestionEligibilityRejected):
        await service.complete(
            _principal(),
            session_id,
            manifest=manifest,
            expected_manifest_digest=manifest.digest(),
            eligibility=_eligibility(allowed=False),
            idempotency_key="complete-1",
            now=NOW,
        )


@pytest.mark.anyio
async def test_complete_is_idempotent_and_completed_sessions_are_immutable() -> None:
    service, _ = _service()
    session_id, _ = await _begin(service)
    payload = b"bytes"
    await _put(service, session_id, _part(0, payload), payload)
    manifest = _manifest(payload)

    first = await service.complete(
        _principal(),
        session_id,
        manifest=manifest,
        expected_manifest_digest=manifest.digest(),
        eligibility=_eligibility(),
        idempotency_key="complete-1",
        now=NOW,
    )
    replay = await service.complete(
        _principal(),
        session_id,
        manifest=manifest,
        expected_manifest_digest=manifest.digest(),
        eligibility=_eligibility(),
        idempotency_key="complete-1",
        now=NOW,
    )
    assert replay == first

    with pytest.raises(IngestionStateError, match="immutable"):
        await _put(service, session_id, _part(0, payload), payload)

    other = _manifest(b"different")
    with pytest.raises(IngestionConflict, match="immutable"):
        await service.complete(
            _principal(),
            session_id,
            manifest=other,
            expected_manifest_digest=other.digest(),
            eligibility=_eligibility(),
            idempotency_key="complete-2",
            now=NOW,
        )


@pytest.mark.anyio
async def test_tenant_isolation_comes_from_the_principal() -> None:
    service, _ = _service()
    session_id, _ = await _begin(service)

    stranger = _principal(tenant_id="tenant-b")
    with pytest.raises(IngestionMalformed, match="unknown session"):
        await service.status(stranger, session_id, now=NOW)


@pytest.mark.anyio
async def test_expired_or_disallowed_principals_are_refused() -> None:
    service, _ = _service()
    with pytest.raises(IngestionAccessDenied, match="expired"):
        await service.begin_session(
            _principal(expires_at=NOW - timedelta(seconds=1)),
            payload_schema=SCHEMA,
            part_count=1,
            idempotency_key="k",
            now=NOW,
        )
    with pytest.raises(IngestionAccessDenied, match="not allowed"):
        await service.begin_session(
            _principal(allow_upload=False),
            payload_schema=SCHEMA,
            part_count=1,
            idempotency_key="k",
            now=NOW,
        )


@pytest.mark.anyio
async def test_part_index_must_stay_within_declared_count() -> None:
    service, _ = _service()
    session_id, _ = await _begin(service, part_count=1)
    payload = b"x"
    with pytest.raises(IngestionMalformed, match="part count"):
        await _put(service, session_id, _part(1, payload), payload)


@pytest.mark.anyio
async def test_object_verification_failure_leaves_no_part_record() -> None:
    service, _ = _service()
    session_id, _ = await _begin(service)
    payload = b"real-bytes"
    declared = PartMetadata(
        index=0,
        sha256=hashlib.sha256(b"declared-otherwise").hexdigest(),
        size=len(payload),
        payload_schema=SCHEMA,
    )
    with pytest.raises(Exception, match="digest"):
        await _put(service, session_id, declared, payload)

    status = await service.status(_principal(), session_id, now=NOW)
    assert status.received_count == 0
