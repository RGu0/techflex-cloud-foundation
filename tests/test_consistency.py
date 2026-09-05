from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from techflex_cloud_foundation import (
    ArtifactIndexEntry,
    ArtifactReceipt,
    DeduplicatingConsumer,
    DeletionDecision,
    DeletionReceipt,
    Disposition,
    HmacTokenCodec,
    IdempotencyConflict,
    IdempotencyGuard,
    InMemoryConsistencyStore,
    InMemoryOutboxStore,
    InMemoryTenantConnectionPool,
    Outbox,
    OutboxAppendConflict,
    OutboxDispatcher,
    OutboxEvent,
    PartialFailureReconciler,
    ReceptionState,
    RequestValidator,
    TenantContext,
    TenantContextMissing,
    TenantDataPlane,
    TenantIsolationViolation,
    TrustedRequestContext,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


NOW = datetime(2026, 9, 5, tzinfo=UTC)
SECRET = b"c" * 32
TTL = timedelta(hours=24)


def _trusted(
    tenant: str = "tenant-a", subject: str = "operator-1"
) -> TrustedRequestContext:
    codec = HmacTokenCodec(
        secret=SECRET, key_id="tenant/1", token_type="access", audience="tenant-data"
    )
    now = datetime.now(UTC)
    token = codec.issue(
        {"tenant_id": tenant, "sub": subject}, expires_at=now + timedelta(days=1)
    )
    return RequestValidator(codec, max_payload_bytes=1024).validate(
        f"Bearer {token}", now=now
    )


def _context(tenant: str = "tenant-a") -> TenantContext:
    return TenantContext.from_request(_trusted(tenant))


class _Effects:
    """Counts how many times the business operation actually ran."""

    def __init__(self) -> None:
        self.runs = 0

    async def run(self, effect_id: str) -> dict[str, object]:
        self.runs += 1
        return {"effect_id": effect_id, "artifact": "artifact-1"}


async def test_the_same_key_and_request_runs_the_operation_once() -> None:
    store = InMemoryConsistencyStore()
    guard = IdempotencyGuard(store, ttl=TTL)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    effects = _Effects()
    request = {"artifact": "artifact-1", "part_count": 3}

    async with plane.scope(_context()) as session:
        first = await guard.run(
            session,
            key="cmd-1",
            request=request,
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )
        second = await guard.run(
            session,
            key="cmd-1",
            request=request,
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW + timedelta(seconds=5),
        )

    assert effects.runs == 1
    assert first.replayed is False
    assert second.replayed is True
    assert second.response == first.response


async def test_the_same_key_with_a_different_request_is_a_conflict() -> None:
    store = InMemoryConsistencyStore()
    guard = IdempotencyGuard(store, ttl=TTL)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    effects = _Effects()

    async with plane.scope(_context()) as session:
        await guard.run(
            session,
            key="cmd-1",
            request={"artifact": "artifact-1"},
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )
        with pytest.raises(IdempotencyConflict):
            await guard.run(
                session,
                key="cmd-1",
                request={"artifact": "artifact-2"},
                natural_key="artifact-2",
                operation=effects.run,
                now=NOW,
            )

    assert effects.runs == 1


async def test_after_the_ttl_the_natural_key_still_prevents_a_second_effect() -> None:
    store = InMemoryConsistencyStore()
    guard = IdempotencyGuard(store, ttl=TTL)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    effects = _Effects()
    request = {"artifact": "artifact-1"}

    async with plane.scope(_context()) as session:
        first = await guard.run(
            session,
            key="cmd-1",
            request=request,
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )
        # The idempotency record has expired; only the natural uniqueness of
        # the artifact stands between a retry and a duplicate effect.
        replay = await guard.run(
            session,
            key="cmd-1",
            request=request,
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW + TTL + timedelta(seconds=1),
        )

    assert effects.runs == 1
    assert replay.replayed is True
    assert replay.response == first.response


async def test_a_different_natural_key_produces_a_second_effect() -> None:
    store = InMemoryConsistencyStore()
    guard = IdempotencyGuard(store, ttl=TTL)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    effects = _Effects()

    async with plane.scope(_context()) as session:
        await guard.run(
            session,
            key="cmd-1",
            request={"artifact": "artifact-1"},
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )
        await guard.run(
            session,
            key="cmd-2",
            request={"artifact": "artifact-2"},
            natural_key="artifact-2",
            operation=effects.run,
            now=NOW,
        )

    assert effects.runs == 2


async def test_two_tenants_sharing_a_key_never_share_an_effect() -> None:
    store = InMemoryConsistencyStore()
    guard = IdempotencyGuard(store, ttl=TTL)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    effects = _Effects()
    request = {"artifact": "artifact-1"}

    async with plane.scope(_context("tenant-a")) as session:
        first = await guard.run(
            session,
            key="cmd-1",
            request=request,
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )

    async with plane.scope(_context("tenant-b")) as session:
        second = await guard.run(
            session,
            key="cmd-1",
            request=request,
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )

    assert effects.runs == 2
    assert first.response != second.response


async def test_a_command_outside_a_tenant_scope_is_refused() -> None:
    store = InMemoryConsistencyStore()
    guard = IdempotencyGuard(store, ttl=TTL)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    effects = _Effects()

    async with plane.scope(_context()) as session:
        pass

    with pytest.raises(TenantContextMissing):
        await guard.run(
            session,
            key="cmd-1",
            request={"artifact": "artifact-1"},
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )

    assert effects.runs == 0


def _event(**overrides: object) -> OutboxEvent:
    values: dict[str, object] = {
        "event_id": uuid4(),
        "tenant_id": "tenant-a",
        "aggregate_id": "artifact-1",
        "aggregate_version": 1,
        "event_type": "artifact.verified",
        "payload": {"manifest_digest": "a" * 64},
        "recorded_at": NOW,
    }
    values.update(overrides)
    return OutboxEvent(**values)  # type: ignore[arg-type]


class _Handler:
    """Records deliveries; refuses the (aggregate, version) pairs it is given."""

    def __init__(self, *, refuse: set[tuple[str, int]] | None = None) -> None:
        self.delivered: list[OutboxEvent] = []
        self.refuse = refuse or set()

    async def handle(self, event: OutboxEvent) -> None:
        if (event.aggregate_id, event.aggregate_version) in self.refuse:
            raise RuntimeError(
                f"worker refused {event.aggregate_id} v{event.aggregate_version}"
            )
        self.delivered.append(event)


async def test_an_event_is_appended_inside_the_tenant_scope() -> None:
    store = InMemoryOutboxStore()
    outbox = Outbox(store)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())

    async with plane.scope(_context()) as session:
        await outbox.append(session, _event())

    assert len(await store.unpublished("tenant-a")) == 1


async def test_an_event_cannot_be_appended_after_the_scope_closes() -> None:
    store = InMemoryOutboxStore()
    outbox = Outbox(store)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())

    async with plane.scope(_context()) as session:
        pass

    with pytest.raises(TenantContextMissing):
        await outbox.append(session, _event())

    assert await store.unpublished("tenant-a") == ()


async def test_an_event_for_another_tenant_is_refused() -> None:
    store = InMemoryOutboxStore()
    outbox = Outbox(store)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())

    async with plane.scope(_context("tenant-a")) as session:
        with pytest.raises(TenantIsolationViolation):
            await outbox.append(session, _event(tenant_id="tenant-b"))

    assert await store.unpublished("tenant-b") == ()


async def test_a_repeated_aggregate_version_is_refused() -> None:
    store = InMemoryOutboxStore()
    outbox = Outbox(store)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())

    async with plane.scope(_context()) as session:
        await outbox.append(session, _event(aggregate_version=1))
        with pytest.raises(OutboxAppendConflict):
            await outbox.append(session, _event(aggregate_version=1))


async def test_dispatch_delivers_pending_events_and_marks_them_published() -> None:
    store = InMemoryOutboxStore()
    outbox = Outbox(store)
    handler = _Handler()
    plane = TenantDataPlane(InMemoryTenantConnectionPool())

    async with plane.scope(_context()) as session:
        await outbox.append(session, _event(aggregate_version=1))
        await outbox.append(session, _event(aggregate_version=2))

    report = await OutboxDispatcher(store, handler.handle).dispatch_pending("tenant-a")

    assert len(report.delivered) == 2
    assert report.failed == ()
    assert await store.unpublished("tenant-a") == ()


async def test_a_failed_delivery_stays_pending_and_is_retried() -> None:
    store = InMemoryOutboxStore()
    outbox = Outbox(store)
    failing = _Handler(refuse={("artifact-1", 1)})
    plane = TenantDataPlane(InMemoryTenantConnectionPool())

    async with plane.scope(_context()) as session:
        await outbox.append(session, _event(aggregate_version=1))

    first = await OutboxDispatcher(store, failing.handle).dispatch_pending("tenant-a")
    assert first.delivered == ()
    assert len(first.failed) == 1
    assert len(await store.unpublished("tenant-a")) == 1

    recovered = _Handler()
    second = await OutboxDispatcher(store, recovered.handle).dispatch_pending(
        "tenant-a"
    )
    assert len(second.delivered) == 1
    assert await store.unpublished("tenant-a") == ()


async def test_a_failed_event_holds_back_later_versions_of_its_aggregate() -> None:
    store = InMemoryOutboxStore()
    outbox = Outbox(store)
    handler = _Handler(refuse={("artifact-1", 1)})
    plane = TenantDataPlane(InMemoryTenantConnectionPool())

    async with plane.scope(_context()) as session:
        await outbox.append(session, _event(aggregate_version=1))
        await outbox.append(session, _event(aggregate_version=2))
        await outbox.append(session, _event(aggregate_id="artifact-2"))

    report = await OutboxDispatcher(store, handler.handle).dispatch_pending("tenant-a")

    # artifact-2 is a different aggregate and is unaffected; artifact-1's
    # version 2 must not overtake the version 1 that failed.
    assert [event.aggregate_id for event in report.delivered] == ["artifact-2"]
    assert {event.aggregate_version for event in await store.unpublished("tenant-a")} == {
        1,
        2,
    }


async def test_at_least_once_redelivery_is_deduplicated_by_event_id() -> None:
    handler = _Handler()
    consumer = DeduplicatingConsumer(handler.handle)
    event = _event()

    assert await consumer.handle(event) is True
    assert await consumer.handle(event) is False

    assert len(handler.delivered) == 1


DIGEST = "b" * 64


def _receipt() -> ArtifactReceipt:
    return ArtifactReceipt(
        session_id=uuid4(),
        manifest_digest=DIGEST,
        manifest_object_key="tenant-a/session/manifest",
        eligibility_reason="purpose allows upload",
        eligibility_policy_version="policy/1",
        completed_at=NOW,
        idempotency_key="cmd-1",
    )


def _entry(**overrides: object) -> ArtifactIndexEntry:
    entry = ArtifactIndexEntry.from_receipt(
        _receipt(), tenant_id="tenant-a", indexed_at=NOW
    )
    if overrides:
        return replace(entry, **overrides)  # type: ignore[arg-type]
    return entry


def test_an_index_entry_is_built_from_the_cp06_receipt() -> None:
    receipt = _receipt()

    entry = ArtifactIndexEntry.from_receipt(
        receipt, tenant_id="tenant-a", indexed_at=NOW
    )

    assert entry.manifest_digest == receipt.manifest_digest
    assert entry.receipt_digest == receipt.digest()
    assert entry.session_id == receipt.session_id


def test_a_receipt_alone_does_not_make_an_artifact_ingested() -> None:
    # The receipt is the committed database fact. Whether the object is still
    # there and whether the event was published are two other facts.
    entry = _entry()

    assert entry.reception_state is ReceptionState.RECORDED
    assert entry.object_verified is False
    assert entry.event_published is False


def test_reception_state_models_no_analysis_or_report_fact() -> None:
    # Analysis complete and report complete are the product's facts; an index
    # that could express them would let INGESTED be read as either.
    members = {member.name for member in ReceptionState}

    assert members == {"RECORDED", "OBJECT_VERIFIED", "INGESTED"}


def test_all_three_facts_together_reconcile_as_consistent() -> None:
    outcome = PartialFailureReconciler().reconcile(
        _entry(), object_present=True, event_published=True
    )

    assert outcome.disposition is Disposition.CONSISTENT
    assert outcome.entry.reception_state is ReceptionState.INGESTED


def test_a_committed_row_with_an_unpublished_event_is_repairable() -> None:
    outcome = PartialFailureReconciler().reconcile(
        _entry(), object_present=True, event_published=False
    )

    assert outcome.disposition is Disposition.REPAIRABLE
    assert outcome.code == "event_unpublished"
    assert outcome.entry.reception_state is ReceptionState.OBJECT_VERIFIED


def test_a_committed_row_whose_object_is_gone_is_quarantined() -> None:
    outcome = PartialFailureReconciler().reconcile(
        _entry(), object_present=False, event_published=False
    )

    assert outcome.disposition is Disposition.QUARANTINE
    assert outcome.code == "object_missing"


def test_an_event_published_for_a_missing_object_is_quarantined() -> None:
    outcome = PartialFailureReconciler().reconcile(
        _entry(), object_present=False, event_published=True
    )

    assert outcome.disposition is Disposition.QUARANTINE
    assert outcome.code == "event_published_without_object"


def test_an_object_with_no_indexed_row_is_repairable() -> None:
    outcome = PartialFailureReconciler().reconcile_unreferenced_object(
        "tenant-a/session/parts/000000", tenant_id="tenant-a"
    )

    assert outcome.disposition is Disposition.REPAIRABLE
    assert outcome.code == "unreferenced_object"
    assert outcome.entry is None


def test_a_quarantine_outcome_does_not_authorize_deletion() -> None:
    outcome = PartialFailureReconciler().reconcile(
        _entry(), object_present=False, event_published=False
    )

    # Reconciliation reports; it never carries a deletion authorization.
    assert not hasattr(outcome, "deletion_decision")
    # Deleting still takes an explicit, attributable decision the application
    # constructs -- the reconciler's verdict is not one.
    decision = DeletionDecision(
        artifact_digest=DIGEST,
        reason="quarantined artifact purged after review",
        decided_by="operator-1",
        decided_at=NOW,
        policy_version="retention/1",
    )
    assert DeletionReceipt.for_decision(decision, deleted_at=NOW).decision_digest == (
        decision.digest()
    )


class _FlakyEffects:
    """Fails the first attempt, then succeeds -- the ordinary transient case."""

    def __init__(self) -> None:
        self.runs = 0

    async def run(self, effect_id: str) -> dict[str, object]:
        self.runs += 1
        if self.runs == 1:
            raise RuntimeError("storage refused the write")
        return {"effect_id": effect_id, "artifact": "artifact-1"}


async def test_a_failed_operation_leaves_the_command_retryable() -> None:
    store = InMemoryConsistencyStore()
    guard = IdempotencyGuard(store, ttl=TTL)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    effects = _FlakyEffects()
    request = {"artifact": "artifact-1"}

    async with plane.scope(_context()) as session:
        with pytest.raises(RuntimeError):
            await guard.run(
                session,
                key="cmd-1",
                request=request,
                natural_key="artifact-1",
                operation=effects.run,
                now=NOW,
            )
        # The claim must not outlive the effect it was reserving: in
        # PostgreSQL the insert rolls back with the transaction, and a retry
        # of a transient failure has to be able to succeed.
        retried = await guard.run(
            session,
            key="cmd-1",
            request=request,
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )

    assert effects.runs == 2
    assert retried.replayed is False


async def test_a_natural_key_replay_leaves_the_new_key_replayable() -> None:
    store = InMemoryConsistencyStore()
    guard = IdempotencyGuard(store, ttl=TTL)
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    effects = _Effects()

    async with plane.scope(_context()) as session:
        await guard.run(
            session,
            key="cmd-1",
            request={"artifact": "artifact-1", "attempt": 1},
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )
        # A different command, phrased differently, that would create the same
        # artifact: it must replay the one effect...
        second = await guard.run(
            session,
            key="cmd-2",
            request={"artifact": "artifact-1", "attempt": 2},
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )
        # ...and cmd-2 must stay replayable under its own request, rather than
        # being recorded against cmd-1's digest and conflicting with itself.
        third = await guard.run(
            session,
            key="cmd-2",
            request={"artifact": "artifact-1", "attempt": 2},
            natural_key="artifact-1",
            operation=effects.run,
            now=NOW,
        )

    assert effects.runs == 1
    assert second.replayed is True
    assert third.replayed is True
    assert third.effect_id == second.effect_id
