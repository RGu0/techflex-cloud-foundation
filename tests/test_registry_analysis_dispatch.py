"""RAY-831 R2: analysis dispatch is driven by the payload schema registry.

- Analyzer bindings are registry data (names only) and not part of a schema's
  immutable definition.
- ``session.ingested.v1`` carries ``payload_schema_version`` on the in-memory
  and PostgreSQL paths, beside its existing fields.
- A schema without a binding reaches ``INGESTED`` and is ingested only: no
  handler runs and nothing is raised.
- Binding an analyzer to an application's own schema needs no ingestion
  change: the same ingestion service and HTTP plane, given a registry that
  carries the binding, produce an event the dispatcher routes to the handler.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
from typing import Any
from uuid import UUID, uuid4

import pytest

from techflex_cloud_foundation import (
    FORCE_PLATE_ANALYZER,
    INGESTED_EVENT_TYPE,
    AnalyzerBindingConflict,
    AnalyzerHandlerMissing,
    AnalyzerHandlerUnbound,
    DispatchKind,
    IngestedEventDispatcher,
    PayloadSchemaRegistry,
    PayloadSchemaUnregistered,
    UndispatchableEvent,
    default_payload_schema_registry,
)
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.events import EventEnvelope
from techflex_cloud_foundation.payload_contracts import (
    GAIT_ARCHIVE_SCHEMA,
    INSOLE_ARCHIVE_SCHEMA,
    RAW_SEGMENT_SCHEMA,
)
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from tests.test_ffp_postgres_platform_live import (
    ELIGIBILITY,
    POLICY,
    Harness,
    _key,
    _manifest,
    _run,
    _segment,
)
from tests.test_ffp_postgres_platform_live import cluster as cluster  # shared ephemeral PG fixture
from tests.test_registry_http_ingestion import FOURTH, SCHEMAS, exercise, fourth_schema

RAW = RAW_SEGMENT_SCHEMA.schema_id
INSOLE = INSOLE_ARCHIVE_SCHEMA.schema_id
GAIT = GAIT_ARCHIVE_SCHEMA.schema_id
FOURTH_ANALYZER = "test.fourth-analysis"
EXISTING_KEYS = {"session_id", "manifest_sha256", "segment_count"}


@dataclass
class Recorder:
    calls: list[Any] = field(default_factory=list)

    def __call__(self, event: Any) -> str:
        self.calls.append(event)
        return f"analysed:{event.payload['session_id']}"


@dataclass(frozen=True)
class Event:
    event_type: str
    payload: dict[str, Any]


def ingested(schema: str | None, **extra: Any) -> Event:
    payload: dict[str, Any] = {"session_id": str(uuid4()), **extra}
    if schema is not None:
        payload["payload_schema_version"] = schema
    return Event(INGESTED_EVENT_TYPE, payload)


def force_plate_dispatcher(recorder: Recorder) -> IngestedEventDispatcher[Any, str]:
    return IngestedEventDispatcher(
        default_payload_schema_registry(), {FORCE_PLATE_ANALYZER: recorder}
    )


# --- registry bindings -------------------------------------------------------


def test_default_registry_binds_only_raw_segment_to_force_plate_analyzer():
    registry = default_payload_schema_registry()
    assert FORCE_PLATE_ANALYZER == "ffp.force-plate-analysis"
    assert registry.analyzer_bindings == {RAW: FORCE_PLATE_ANALYZER}
    assert registry.analyzer_for(RAW) == FORCE_PLATE_ANALYZER
    assert registry.analyzer_for(INSOLE) is None
    assert registry.analyzer_for(GAIT) is None


def test_binding_is_registry_data_not_part_of_the_immutable_schema():
    registry = PayloadSchemaRegistry([GAIT_ARCHIVE_SCHEMA])
    registry.bind_analyzer(GAIT, "gait.imu-analysis")
    # The published definition is untouched, so registering it again is still a no-op.
    registry.register(GAIT_ARCHIVE_SCHEMA)
    assert registry.get(GAIT) == GAIT_ARCHIVE_SCHEMA
    assert registry.analyzer_for(GAIT) == "gait.imu-analysis"
    # The snapshot is a copy.
    snapshot = registry.analyzer_bindings
    snapshot[GAIT] = "tampered"  # type: ignore[index]
    assert registry.analyzer_for(GAIT) == "gait.imu-analysis"


def test_bind_analyzer_refuses_unknown_schema_bad_name_and_rebinding():
    registry = PayloadSchemaRegistry([GAIT_ARCHIVE_SCHEMA])
    with pytest.raises(PayloadSchemaUnregistered):
        registry.bind_analyzer("unknown-schema/1", "a.b")
    with pytest.raises(PayloadSchemaUnregistered):
        registry.analyzer_for("unknown-schema/1")
    for bad in ("", "Upper.case", "trailing.", ".leading", "has space", None):
        with pytest.raises(AnalyzerBindingConflict):
            registry.bind_analyzer(GAIT, bad)  # type: ignore[arg-type]
    registry.bind_analyzer(GAIT, "gait.imu-analysis")
    registry.bind_analyzer(GAIT, "gait.imu-analysis")  # same name: no-op
    with pytest.raises(AnalyzerBindingConflict):
        registry.bind_analyzer(GAIT, "gait.other-analysis")
    assert registry.analyzer_for(GAIT) == "gait.imu-analysis"


def test_constructor_bindings_follow_the_same_rules():
    registry = PayloadSchemaRegistry([GAIT_ARCHIVE_SCHEMA], analyzers={GAIT: "gait.imu"})
    assert registry.analyzer_bindings == {GAIT: "gait.imu"}
    with pytest.raises(PayloadSchemaUnregistered):
        PayloadSchemaRegistry([GAIT_ARCHIVE_SCHEMA], analyzers={INSOLE: "insole.x"})


# --- dispatcher --------------------------------------------------------------


def test_dispatcher_refuses_to_start_with_a_bound_analyzer_lacking_a_handler():
    with pytest.raises(AnalyzerHandlerMissing, match=FORCE_PLATE_ANALYZER):
        IngestedEventDispatcher(default_payload_schema_registry(), {})


def test_dispatcher_refuses_to_start_with_a_handler_no_schema_is_bound_to():
    with pytest.raises(AnalyzerHandlerUnbound, match="ffp.typo"):
        IngestedEventDispatcher(
            default_payload_schema_registry(),
            {FORCE_PLATE_ANALYZER: Recorder(), "ffp.typo": Recorder()},
        )


def test_bound_schema_runs_its_handler_once_and_returns_its_result():
    recorder = Recorder()
    event = ingested(RAW)
    outcome = force_plate_dispatcher(recorder).dispatch(event)
    assert outcome.kind is DispatchKind.ANALYZED
    assert (outcome.payload_schema_version, outcome.analyzer) == (RAW, FORCE_PLATE_ANALYZER)
    assert outcome.result == f"analysed:{event.payload['session_id']}"
    assert recorder.calls == [event]


@pytest.mark.parametrize("schema", (INSOLE, GAIT))
def test_unbound_schema_is_ingested_only_without_handler_or_error(schema):
    recorder = Recorder()
    outcome = force_plate_dispatcher(recorder).dispatch(ingested(schema))
    assert outcome.kind is DispatchKind.INGEST_ONLY
    assert (outcome.payload_schema_version, outcome.analyzer, outcome.result) == (
        schema, None, None,
    )
    assert recorder.calls == []


def test_dispatch_refuses_other_events_missing_schema_and_unknown_schema():
    recorder = Recorder()
    dispatcher = force_plate_dispatcher(recorder)
    with pytest.raises(UndispatchableEvent, match="session.ingested.v1"):
        dispatcher.dispatch(Event("analysis.started.v1", {"payload_schema_version": RAW}))
    # An event committed before RAY-831 has no schema; it is refused, not guessed.
    with pytest.raises(UndispatchableEvent, match="payload_schema_version"):
        dispatcher.dispatch(ingested(None))
    with pytest.raises(UndispatchableEvent):
        dispatcher.dispatch(ingested(""))
    # Every refusal stays in the dispatch family, so one except clause covers it.
    with pytest.raises(UndispatchableEvent, match="not registered"):
        dispatcher.dispatch(ingested("estimated-force-session/1"))
    # An undecoded JSON outbox payload is refused clearly, not with AttributeError.
    with pytest.raises(UndispatchableEvent, match="mapping"):
        raw_json = '{"payload_schema_version": "raw-segment/1"}'
        dispatcher.dispatch(Event(INGESTED_EVENT_TYPE, raw_json))  # type: ignore[arg-type]
    # analyzer_for keeps the registry's own error for a direct lookup.
    with pytest.raises(PayloadSchemaUnregistered):
        dispatcher.analyzer_for("estimated-force-session/1")
    assert recorder.calls == []


def test_handler_errors_propagate_unchanged():
    error = RuntimeError("analysis failed")

    def failing(event: Any) -> str:
        raise error

    dispatcher = IngestedEventDispatcher(
        default_payload_schema_registry(), {FORCE_PLATE_ANALYZER: failing}
    )
    with pytest.raises(RuntimeError) as raised:
        dispatcher.dispatch(ingested(RAW))
    assert raised.value is error


def test_dispatcher_uses_the_bindings_it_was_built_with():
    registry = PayloadSchemaRegistry([GAIT_ARCHIVE_SCHEMA, INSOLE_ARCHIVE_SCHEMA])
    gait_recorder = Recorder()
    dispatcher = IngestedEventDispatcher(registry, {})
    # A binding added after construction is not seen, even with a handler ready for it.
    registry.bind_analyzer(GAIT, "gait.imu-analysis")
    assert dispatcher.dispatch(ingested(GAIT)).kind is DispatchKind.INGEST_ONLY
    assert IngestedEventDispatcher(
        registry, {"gait.imu-analysis": gait_recorder}
    ).dispatch(ingested(GAIT)).kind is DispatchKind.ANALYZED
    assert len(gait_recorder.calls) == 1
    # A schema registered after construction is unknown to the old dispatcher.
    registry.register(RAW_SEGMENT_SCHEMA)
    with pytest.raises(UndispatchableEvent, match="not registered"):
        dispatcher.dispatch(ingested(RAW))


def test_dispatcher_accepts_the_published_event_envelope():
    recorder = Recorder()
    envelope = EventEnvelope(
        event_id=uuid4(), event_type=INGESTED_EVENT_TYPE, occurred_at=datetime.now(UTC),
        producer="ingestion", tenant_id=uuid4(), aggregate_type="screening_session",
        aggregate_id=uuid4(), aggregate_version=2,
        payload={"session_id": str(uuid4()), "manifest_sha256": "a" * 64,
                 "segment_count": 1, "payload_schema_version": RAW},
    )
    assert force_plate_dispatcher(recorder).dispatch(envelope).kind is DispatchKind.ANALYZED
    assert recorder.calls == [envelope]


# --- ingestion end to end ----------------------------------------------------


def fourth_registry() -> PayloadSchemaRegistry:
    """An application registers its own schema and binds its own analyzer."""
    registry = default_payload_schema_registry()
    registry.register(fourth_schema())
    registry.bind_analyzer(FOURTH, FOURTH_ANALYZER)
    return registry


def assert_event_payload(payload: dict[str, Any], session_id: str, schema: str) -> None:
    assert set(payload) == EXISTING_KEYS | {"payload_schema_version"}
    assert payload["session_id"] == session_id
    assert payload["payload_schema_version"] == schema
    assert isinstance(payload["segment_count"], int) and payload["segment_count"] >= 1
    assert isinstance(payload["manifest_sha256"], str) and len(payload["manifest_sha256"]) == 64


def assert_dispatched(registry, event, schema: str) -> None:
    force_plate, fourth = Recorder(), Recorder()
    handlers = {FORCE_PLATE_ANALYZER: force_plate}
    if FOURTH in registry.schema_ids:
        handlers[FOURTH_ANALYZER] = fourth
    outcome = IngestedEventDispatcher(registry, handlers).dispatch(event)
    if schema == FOURTH:
        assert (outcome.kind, outcome.analyzer) == (DispatchKind.ANALYZED, FOURTH_ANALYZER)
        assert (len(fourth.calls), force_plate.calls) == (1, [])
    elif schema == RAW:
        assert (outcome.kind, outcome.analyzer) == (DispatchKind.ANALYZED, FORCE_PLATE_ANALYZER)
        assert (len(force_plate.calls), fourth.calls) == (1, [])
    else:
        assert outcome.kind is DispatchKind.INGEST_ONLY
        assert (force_plate.calls, fourth.calls) == ([], [])


@pytest.mark.parametrize("schema", (*SCHEMAS, FOURTH))
def test_http_ingestion_in_memory_emits_schema_and_dispatches_by_registry(schema):
    repository = InMemoryPlatformRepository()
    tenant, terminal = uuid4(), uuid4()
    repository.add_terminal(tenant, None, terminal)
    registry = fourth_registry() if schema == FOURTH else None
    session_id = asyncio.run(exercise(repository, tenant, terminal, schema, registry=registry))
    events = [
        event for event in repository.events(INGESTED_EVENT_TYPE)
        if event.payload["session_id"] == session_id
    ]
    assert len(events) == 1
    assert_event_payload(events[0].payload, session_id, schema)
    assert_dispatched(registry or default_payload_schema_registry(), events[0], schema)


async def outbox_event(h: Harness, session_id: str | UUID) -> EventEnvelope:
    rows = await h.admin.fetch(
        "SELECT * FROM ops.outbox_events WHERE aggregate_id::text = $1", str(session_id)
    )
    assert len(rows) == 1
    row = rows[0]
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return EventEnvelope(
        event_id=row["event_id"], event_type=row["event_type"], occurred_at=row["occurred_at"],
        producer="ingestion", tenant_id=row["tenant_id"], aggregate_type=row["aggregate_type"],
        aggregate_id=row["aggregate_id"], aggregate_version=row["aggregate_version"],
        payload=payload,
    )


@pytest.mark.parametrize("schema", (*SCHEMAS, FOURTH))
def test_http_ingestion_postgres_emits_schema_and_dispatches_by_registry(cluster, schema):
    async def body(h: Harness):
        tenant = await h.tenant()
        registry = fourth_registry() if schema == FOURTH else None
        session_id = await exercise(
            h.repository, tenant.tenant_id, tenant.terminal_id, schema, registry=registry,
        )
        status = await h.admin.fetchval(
            "SELECT ingest_status FROM screening.sessions WHERE session_id::text = $1",
            session_id,
        )
        assert status == "INGESTED"
        event = await outbox_event(h, session_id)
        assert event.event_type == INGESTED_EVENT_TYPE
        assert_event_payload(event.payload, session_id, schema)
        assert_dispatched(registry or default_payload_schema_registry(), event, schema)
    _run(cluster, body)


def test_force_plate_completion_postgres_emits_raw_segment_and_reaches_its_analyzer(cluster):
    async def body(h: Harness):
        a = await h.tenant()
        session_id, _ = await h.session(a)
        seg0, seg1 = _segment(0), _segment(1)
        for seg in (seg0, seg1):
            await h.repository.register_segment(
                a.principal, session_id, seg, _key(session_id, a, seg)
            )
        manifest = _manifest(seg0, seg1)
        digest = canonical_sha256(manifest)
        await h.repository.complete_manifest(
            a.principal, session_id, manifest, digest,
            f"tenants/{a.tenant_id}/sessions/{session_id}/manifests/{digest}.json",
            "complete-1", eligibility_reason=ELIGIBILITY, eligibility_policy_version=POLICY,
            completed_at=datetime.now(UTC),
        )
        event = await outbox_event(h, session_id)
        assert_event_payload(event.payload, str(session_id), RAW)
        assert event.payload["segment_count"] == 2
        assert event.payload["manifest_sha256"] == digest
        assert_dispatched(default_payload_schema_registry(), event, RAW)
    _run(cluster, body)
