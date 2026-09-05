"""Idempotency, Outbox, and partial-failure reconciliation (CP-08).

The consistency half of the tenant data plane, built on `tenancy.py`: a
command runs at most once per idempotency key, an event is appended in the
same tenant scope as the state change it describes, and a reconciler decides
what to do when the database, the object store, and the event stream
disagree.

Invariants carried over from RAY-341 and the deployment architecture:

- HTTP 200, a successful object write, a committed database row, INGESTED,
  a finished analysis, and a finished report are six different facts.  None
  of them stands in for another, and this module models only the first four
  — the last two belong to the product.
- The same key with the same request digest replays one result; the same key
  with a different digest is a conflict, never a second effect.
- An idempotency record expires; the natural uniqueness of the thing it
  created does not.  After the record is gone, the natural key is what still
  stops a retry from producing a duplicate.
- An event is appended inside the tenant scope that produced it, so it
  commits with the state change or not at all.
- Delivery is at least once, so a consumer deduplicates by event id; per
  aggregate, events are delivered in version order.
- A server-side confirmation never authorizes deletion: a reconciler
  quarantines, and deleting still requires an explicit
  `lifecycle.DeletionDecision` the application makes.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from .ingestion import ArtifactReceipt
from .manifest import ManifestMalformed
from .manifest import _require_text as _manifest_require_text
from .tenancy import CompositeTenantReference, TenantScopedSession


class ConsistencyError(Exception):
    """Base class for idempotency, Outbox, and reconciliation failures."""


class ConsistencyMalformed(ConsistencyError):
    """A command, event, or index entry is structurally invalid."""


class IdempotencyConflict(ConsistencyError):
    """An idempotency key was reused with a different request."""


def _require_text(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_text(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise ConsistencyMalformed(str(exc)) from exc


def _require_aware(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None:
        raise ConsistencyMalformed(f"{field_name} must be timezone-aware")


def _canonical_digest(document: Mapping[str, Any]) -> str:
    """Digest a request reproducibly, so replay and conflict are decidable."""
    try:
        payload = json.dumps(
            document, sort_keys=True, separators=(",", ":"), default=str
        )
    except TypeError as exc:
        raise ConsistencyMalformed(f"request is not serializable: {exc}") from exc
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IdempotentOutcome:
    """One command's stored result, replayed for a repeat of that command."""

    effect_id: str
    request_digest: str
    response: Mapping[str, Any]
    recorded_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.effect_id, field_name="effect id")
        _require_text(self.request_digest, field_name="request digest")
        _require_aware(self.recorded_at, field_name="recorded_at")

    def has_expired(self, now: datetime, *, ttl: timedelta) -> bool:
        return now - self.recorded_at > ttl


@dataclass(frozen=True)
class IdempotentResult:
    """What a guarded command returned, and whether it actually ran.

    ``replayed`` is the honest part: a caller that treats a replay as a fresh
    effect would double-count it, and one that treats a fresh effect as a
    replay would drop work.
    """

    response: Mapping[str, Any]
    effect_id: str
    replayed: bool


class InMemoryConsistencyStore:
    """Volatile reference store for idempotency records and natural keys.

    Production binds this to PostgreSQL, where ``claim_natural_key`` is an
    insert against a unique constraint inside the command's own transaction —
    which is what makes the claim atomic rather than a check followed by an
    act, and what makes ``release_natural_key`` unnecessary there, because a
    failing command rolls the claim back with everything else.  This
    implementation has no transaction to roll back, so the guard releases the
    claim explicitly; it is single-threaded, and gets atomicity by not
    yielding between the lookup and the write.
    """

    def __init__(self) -> None:
        self._outcomes: dict[tuple[str, str], IdempotentOutcome] = {}
        self._natural: dict[tuple[str, str], str] = {}
        self._by_effect: dict[tuple[str, str], IdempotentOutcome] = {}

    async def outcome_for_key(
        self, tenant_id: str, key: str
    ) -> IdempotentOutcome | None:
        return self._outcomes.get((tenant_id, key))

    async def outcome_for_effect(
        self, tenant_id: str, effect_id: str
    ) -> IdempotentOutcome | None:
        return self._by_effect.get((tenant_id, effect_id))

    async def record_outcome(
        self, tenant_id: str, key: str, outcome: IdempotentOutcome
    ) -> None:
        self._outcomes[(tenant_id, key)] = outcome
        self._by_effect[(tenant_id, outcome.effect_id)] = outcome

    async def claim_natural_key(
        self, tenant_id: str, natural_key: str, effect_id: str
    ) -> str:
        """Claim the key; return whichever effect id actually holds it."""
        return self._natural.setdefault((tenant_id, natural_key), effect_id)

    async def release_natural_key(
        self, tenant_id: str, natural_key: str, effect_id: str
    ) -> None:
        """Drop a claim that never became an effect; other holders are kept."""
        if self._natural.get((tenant_id, natural_key)) == effect_id:
            del self._natural[(tenant_id, natural_key)]


class IdempotencyGuard:
    """Runs a command at most once per key, and once per natural key after that.

    Two layers, because they expire differently.  The idempotency record
    answers "have I seen this exact request under this key" and is kept for a
    bounded TTL, since keeping every key forever is not affordable.  The
    natural key answers "does the thing this command would create already
    exist" and never expires, because the row it guards does not.  A retry
    arriving after the TTL therefore still finds the original effect instead
    of making a second one.
    """

    def __init__(self, store: InMemoryConsistencyStore, *, ttl: timedelta) -> None:
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise ConsistencyMalformed("idempotency ttl must be a positive timedelta")
        self._store = store
        self._ttl = ttl

    async def run(
        self,
        session: TenantScopedSession,
        *,
        key: str,
        request: Mapping[str, Any],
        natural_key: str,
        operation: Callable[[str], Awaitable[Mapping[str, Any]]],
        now: datetime,
    ) -> IdempotentResult:
        """Execute ``operation`` unless this command already had its effect."""
        if not isinstance(session, TenantScopedSession):
            raise ConsistencyMalformed(
                "a guarded command requires an open TenantScopedSession"
            )
        # Reading the tenant through the session's own guard means a closed
        # scope refuses here rather than running the command unscoped.
        session.ensure_open()
        tenant_id = session.tenant_id
        _require_text(key, field_name="idempotency key")
        _require_text(natural_key, field_name="natural key")
        _require_aware(now, field_name="now")
        digest = _canonical_digest(request)

        stored = await self._store.outcome_for_key(tenant_id, key)
        if stored is not None:
            if stored.request_digest != digest:
                raise IdempotencyConflict(
                    f"idempotency key {key!r} was already used with a different "
                    "request; the key identifies one command, so a different "
                    "request needs a different key"
                )
            if not stored.has_expired(now, ttl=self._ttl):
                return IdempotentResult(
                    response=stored.response,
                    effect_id=stored.effect_id,
                    replayed=True,
                )

        candidate = uuid4().hex
        holder = await self._store.claim_natural_key(tenant_id, natural_key, candidate)
        if holder != candidate:
            # Something already owns this natural key.  Whether the original
            # idempotency record expired or a concurrent command won the
            # insert, creating a second effect is the one wrong answer.
            original = await self._store.outcome_for_effect(tenant_id, holder)
            if original is None:
                raise ConsistencyMalformed(
                    f"natural key {natural_key!r} is held by effect {holder!r} "
                    "with no recorded outcome; this is a partial write to "
                    "reconcile, not a command to retry"
                )
            # Record under *this* key with *this* request's digest, pointing at
            # the one effect.  Storing the original's digest instead would
            # leave this key conflicting with the very request that just used
            # it, the next time it is retried.
            await self._store.record_outcome(
                tenant_id,
                key,
                IdempotentOutcome(
                    effect_id=original.effect_id,
                    request_digest=digest,
                    response=original.response,
                    recorded_at=now,
                ),
            )
            return IdempotentResult(
                response=original.response,
                effect_id=original.effect_id,
                replayed=True,
            )

        try:
            response = await operation(candidate)
        except BaseException:
            # The claim was reserving an effect that never happened.  Leaving
            # it would make every retry of a transient failure land on a
            # holder with no outcome -- unretryable forever, from one blip.
            await self._store.release_natural_key(
                tenant_id, natural_key, candidate
            )
            raise
        outcome = IdempotentOutcome(
            effect_id=candidate,
            request_digest=digest,
            response=response,
            recorded_at=now,
        )
        await self._store.record_outcome(tenant_id, key, outcome)
        return IdempotentResult(
            response=response, effect_id=candidate, replayed=False
        )


class OutboxAppendConflict(ConsistencyError):
    """An event id or aggregate version was already appended."""


@dataclass(frozen=True)
class OutboxEvent:
    """One fact to publish, appended with the state change that produced it.

    ``event_type`` and ``payload`` are the product's: this module orders,
    stores and delivers events without reading what they mean.
    """

    event_id: UUID
    tenant_id: str
    aggregate_id: str
    aggregate_version: int
    event_type: str
    payload: Mapping[str, Any]
    recorded_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, UUID):
            raise ConsistencyMalformed("event id must be a UUID")
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.aggregate_id, field_name="aggregate id")
        _require_text(self.event_type, field_name="event type")
        if (
            not isinstance(self.aggregate_version, int)
            or isinstance(self.aggregate_version, bool)
            or self.aggregate_version < 1
        ):
            raise ConsistencyMalformed(
                "aggregate version must be a positive integer"
            )
        if not isinstance(self.payload, Mapping):
            raise ConsistencyMalformed("event payload must be a mapping")
        _require_aware(self.recorded_at, field_name="recorded_at")


@dataclass(frozen=True)
class DispatchReport:
    """What one dispatch pass delivered and what it left pending."""

    delivered: tuple[OutboxEvent, ...] = ()
    failed: tuple[OutboxEvent, ...] = ()
    held_back: tuple[OutboxEvent, ...] = ()


class InMemoryOutboxStore:
    """Volatile reference outbox; production binds the ``operations`` schema."""

    def __init__(self) -> None:
        self._events: dict[UUID, OutboxEvent] = {}
        self._published: set[UUID] = set()
        self._versions: set[tuple[str, str, int]] = set()
        self._sequence: dict[UUID, int] = {}
        self._next_sequence = 0

    async def append(self, event: OutboxEvent) -> None:
        if event.event_id in self._events:
            raise OutboxAppendConflict(
                f"event {event.event_id} was already appended"
            )
        slot = (event.tenant_id, event.aggregate_id, event.aggregate_version)
        if slot in self._versions:
            raise OutboxAppendConflict(
                f"aggregate {event.aggregate_id!r} already has version "
                f"{event.aggregate_version}; a version identifies one state "
                "change, so a second event needs the next version"
            )
        self._versions.add(slot)
        self._events[event.event_id] = event
        self._sequence[event.event_id] = self._next_sequence
        self._next_sequence += 1

    async def unpublished(
        self, tenant_id: str, *, limit: int | None = None
    ) -> tuple[OutboxEvent, ...]:
        """Pending events, ordered so an aggregate's versions stay in order."""
        pending = [
            event
            for event in self._events.values()
            if event.tenant_id == tenant_id and event.event_id not in self._published
        ]
        pending.sort(
            key=lambda event: (
                event.aggregate_id,
                event.aggregate_version,
                self._sequence[event.event_id],
            )
        )
        return tuple(pending if limit is None else pending[:limit])

    async def mark_published(self, tenant_id: str, event_id: UUID) -> None:
        event = self._events.get(event_id)
        if event is None or event.tenant_id != tenant_id:
            raise ConsistencyMalformed(
                f"event {event_id} is not this tenant's to publish"
            )
        self._published.add(event_id)

    async def is_published(self, event_id: UUID) -> bool:
        return event_id in self._published


class Outbox:
    """Appends events inside the tenant scope that produced the state change.

    Requiring an open :class:`TenantScopedSession` is the enforceable half of
    "the event commits with the state change": an append that cannot name a
    live scope has no transaction to join, and an event for another tenant
    would announce a change the bound tenant never made.
    """

    def __init__(self, store: InMemoryOutboxStore) -> None:
        self._store = store

    async def append(
        self, session: TenantScopedSession, event: OutboxEvent
    ) -> None:
        """Append one event under the session's bound tenant."""
        if not isinstance(session, TenantScopedSession):
            raise ConsistencyMalformed(
                "an outbox append requires an open TenantScopedSession"
            )
        session.ensure_open()
        if not isinstance(event, OutboxEvent):
            raise ConsistencyMalformed("append requires an OutboxEvent")
        session.ensure_owns(
            CompositeTenantReference(
                tenant_id=event.tenant_id, entity_id=str(event.event_id)
            )
        )
        await self._store.append(event)


class OutboxDispatcher:
    """Delivers pending events at least once, in per-aggregate order.

    A failure holds back the rest of that aggregate rather than skipping past
    it: versions delivered out of order would show a consumer a later state
    before the one it replaces, which is worse than delivering nothing yet.
    Other aggregates are independent and keep moving.
    """

    def __init__(
        self,
        store: InMemoryOutboxStore,
        handler: Callable[[OutboxEvent], Awaitable[None]],
    ) -> None:
        self._store = store
        self._handler = handler

    async def dispatch_pending(
        self, tenant_id: str, *, limit: int | None = None
    ) -> DispatchReport:
        """Attempt one pass over this tenant's pending events."""
        _require_text(tenant_id, field_name="tenant id")
        delivered: list[OutboxEvent] = []
        failed: list[OutboxEvent] = []
        held_back: list[OutboxEvent] = []
        blocked: set[str] = set()
        for event in await self._store.unpublished(tenant_id, limit=limit):
            if event.aggregate_id in blocked:
                held_back.append(event)
                continue
            try:
                await self._handler(event)
            except Exception:
                # The event stays pending; redelivery is the contract, which
                # is why the consumer side deduplicates by event id.
                blocked.add(event.aggregate_id)
                failed.append(event)
                continue
            await self._store.mark_published(tenant_id, event.event_id)
            delivered.append(event)
        return DispatchReport(
            delivered=tuple(delivered),
            failed=tuple(failed),
            held_back=tuple(held_back),
        )


class DeduplicatingConsumer:
    """Applies each event id once, however many times it is delivered.

    Delivery is at least once by construction -- a handler that succeeded and
    a dispatcher that crashed before marking it published are
    indistinguishable from the store -- so the consumer, not the dispatcher,
    is where a repeat stops being a repeated effect.
    """

    def __init__(self, handler: Callable[[OutboxEvent], Awaitable[None]]) -> None:
        self._handler = handler
        self._seen: set[UUID] = set()

    async def handle(self, event: OutboxEvent) -> bool:
        """Handle ``event`` unless its id was already applied."""
        if not isinstance(event, OutboxEvent):
            raise ConsistencyMalformed("a consumer requires an OutboxEvent")
        if event.event_id in self._seen:
            return False
        await self._handler(event)
        self._seen.add(event.event_id)
        return True


class ReceptionState(StrEnum):
    """How far one artifact has got through reception, and no further.

    Three states, because three facts are observable here: a committed index
    row, the object still being present, and the event having been published.
    A finished analysis and a finished report are the product's facts and have
    deliberately no member -- a state that could express them would let
    ``INGESTED`` be read as either.
    """

    RECORDED = "recorded"
    OBJECT_VERIFIED = "object-verified"
    INGESTED = "ingested"


class Disposition(StrEnum):
    """What a reconciler concluded about one artifact.

    ``REPAIRABLE`` means the platform can restore agreement by itself -- by
    republishing an event or reclaiming an object it never referenced.
    ``QUARANTINE`` means it cannot, and guessing would be worse than stopping.
    Neither is an authorization to delete anything.
    """

    CONSISTENT = "consistent"
    REPAIRABLE = "repairable"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class ArtifactIndexEntry:
    """What the platform knows about one received artifact.

    Built from a CP-06 `ArtifactReceipt`, which is the committed database
    fact and nothing more.  ``object_verified`` and ``event_published`` start
    false and are set by observation, because a receipt issued at one moment
    does not say the object is still there now or that the event ever left.
    """

    tenant_id: str
    session_id: UUID
    manifest_digest: str
    manifest_object_key: str
    receipt_digest: str
    indexed_at: datetime
    object_verified: bool = False
    event_published: bool = False

    def __post_init__(self) -> None:
        _require_text(self.tenant_id, field_name="tenant id")
        if not isinstance(self.session_id, UUID):
            raise ConsistencyMalformed("session id must be a UUID")
        _require_text(self.manifest_digest, field_name="manifest digest")
        _require_text(self.manifest_object_key, field_name="manifest object key")
        _require_text(self.receipt_digest, field_name="receipt digest")
        _require_aware(self.indexed_at, field_name="indexed_at")

    @classmethod
    def from_receipt(
        cls, receipt: ArtifactReceipt, *, tenant_id: str, indexed_at: datetime
    ) -> ArtifactIndexEntry:
        """Index one completed session, committing to that exact receipt."""
        if not isinstance(receipt, ArtifactReceipt):
            raise ConsistencyMalformed(
                "an index entry is built from a CP-06 ArtifactReceipt; the "
                "ingestion plane already decided completion"
            )
        return cls(
            tenant_id=tenant_id,
            session_id=receipt.session_id,
            manifest_digest=receipt.manifest_digest,
            manifest_object_key=receipt.manifest_object_key,
            receipt_digest=receipt.digest(),
            indexed_at=indexed_at,
        )

    @property
    def reception_state(self) -> ReceptionState:
        if not self.object_verified:
            return ReceptionState.RECORDED
        if not self.event_published:
            return ReceptionState.OBJECT_VERIFIED
        return ReceptionState.INGESTED


@dataclass(frozen=True)
class ReconciliationOutcome:
    """One reconciler verdict.

    It carries no deletion authorization, by construction.  A server-side
    confirmation never authorizes deletion, and neither does a quarantine:
    removing anything still takes an explicit `lifecycle.DeletionDecision`
    the application makes and can be held to.
    """

    disposition: Disposition
    code: str
    detail: str
    entry: ArtifactIndexEntry | None = None


class PartialFailureReconciler:
    """Decides what to do when the database, objects, and events disagree.

    The database row, the object, and the published event are written by
    three different systems, so any of them can be the one that did not land.
    A missing event is repairable because the outbox still holds it.  A
    missing object is not: the row asserts an artifact whose bytes are gone,
    and the only honest move is to stop rather than to synthesize agreement.
    """

    def reconcile(
        self,
        entry: ArtifactIndexEntry,
        *,
        object_present: bool,
        event_published: bool,
    ) -> ReconciliationOutcome:
        """Reconcile one indexed artifact against what is actually there."""
        if not isinstance(entry, ArtifactIndexEntry):
            raise ConsistencyMalformed("reconciliation requires an ArtifactIndexEntry")
        observed = replace(
            entry, object_verified=object_present, event_published=event_published
        )
        if not object_present:
            if event_published:
                return ReconciliationOutcome(
                    disposition=Disposition.QUARANTINE,
                    code="event_published_without_object",
                    detail=(
                        "an event announced this artifact while its object is "
                        "absent; consumers may already have acted on something "
                        "the platform cannot produce"
                    ),
                    entry=observed,
                )
            return ReconciliationOutcome(
                disposition=Disposition.QUARANTINE,
                code="object_missing",
                detail=(
                    "the index row asserts an artifact whose object is absent; "
                    "this cannot be repaired by writing one, because the bytes "
                    "that were verified are what is missing"
                ),
                entry=observed,
            )
        if not event_published:
            return ReconciliationOutcome(
                disposition=Disposition.REPAIRABLE,
                code="event_unpublished",
                detail=(
                    "row and object agree; the outbox still holds the event, so "
                    "dispatching it restores agreement"
                ),
                entry=observed,
            )
        return ReconciliationOutcome(
            disposition=Disposition.CONSISTENT,
            code="ingested",
            detail="row, object, and published event all agree",
            entry=observed,
        )

    def reconcile_unreferenced_object(
        self, object_key: str, *, tenant_id: str
    ) -> ReconciliationOutcome:
        """Judge an object no index row references."""
        _require_text(object_key, field_name="object key")
        _require_text(tenant_id, field_name="tenant id")
        return ReconciliationOutcome(
            disposition=Disposition.REPAIRABLE,
            code="unreferenced_object",
            detail=(
                "an object write landed without a committed row; nothing "
                "references it, so it can be reclaimed -- reclaiming still "
                "takes an explicit DeletionDecision, which this verdict is not"
            ),
            entry=None,
        )
