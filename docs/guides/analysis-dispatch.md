# Analysis dispatch by payload schema registry

RAY-831 R2. Which analysis runs after a session reaches `INGESTED` is decided by
the payload schema registry, not by code that inspects schema names.

## The event

Every successful completion commits one `session.ingested.v1` event (the in-memory
repository's event list, or a row in `ops.outbox_events` committed in the same
transaction as the receipt). Its payload is:

| Field | Meaning |
|---|---|
| `session_id` | The ingested session. |
| `manifest_sha256` | Digest of the verified manifest. |
| `segment_count` | Segments in the manifest. |
| `payload_schema_version` | The session's registered payload schema, for example `raw-segment/1` (added in RAY-831). |

`payload_schema_version` was added to the existing `v1` payload. No field was
removed or renamed and the event type is unchanged, so existing consumers are
unaffected. Events committed before this change have no
`payload_schema_version`; the dispatcher refuses them with
`UndispatchableEvent` instead of guessing, and a consumer that needs them must
read the schema from `screening.sessions.payload_schema_version` first.

## Analyzer bindings

`PayloadSchemaRegistry.bind_analyzer(schema_id, analyzer)` binds a registered
schema to an analyzer *name*. The registry stores the name only; the algorithm
lives with the application that registers a handler for it. A binding is not
part of the immutable `PayloadSchema` definition, so binding or not binding a
schema never needs a new schema version or any change to ingestion.

- Names are dotted lowercase identifiers (`ffp.force-plate-analysis`).
- Binding an unregistered schema raises `PayloadSchemaUnregistered`.
- Binding the same name twice is a no-op; a different name for a bound schema
  raises `AnalyzerBindingConflict`.
- `analyzer_for(schema_id)` returns the name or `None`; `analyzer_bindings`
  returns a copy of every binding.

`default_payload_schema_registry()` binds `raw-segment/1` to
`FORCE_PLATE_ANALYZER` (`ffp.force-plate-analysis`), per the RAY-831 R2 note
(option A). FeetForcePlate registers the handler under that name and decides
inside it which of its pipelines to run. `insole-session-archive/1` and
`gait-session-archive/1` have no binding and are ingested only.

`estimated-force-session/1.0` is not a payload schema: it is the schema of the
physical input document FeetForcePlate derives from a session, never an upload
schema, so it is not registered here.

## The dispatcher

```python
from techflex_cloud_foundation import (
    FORCE_PLATE_ANALYZER, IngestedEventDispatcher, default_payload_schema_registry,
)

dispatcher = IngestedEventDispatcher(
    default_payload_schema_registry(),
    {FORCE_PLATE_ANALYZER: handle_force_plate_session},
)
outcome = dispatcher.dispatch(event)  # EventEnvelope or any object with event_type/payload
```

- A bound schema runs its handler once; the outcome is `ANALYZED` with the
  analyzer name and the handler's return value.
- An unbound schema runs nothing and raises nothing; the outcome is
  `INGEST_ONLY`.
- Construction fails with `AnalyzerHandlerMissing` when a bound analyzer has no
  handler, and with `AnalyzerHandlerUnbound` when a handler names no binding,
  so a mismatch stops startup instead of silently dropping analyses.
- The dispatcher snapshots the bindings when it is built; later changes to
  the registry need a new dispatcher.
- Events of another type, events without `payload_schema_version`, and
  unregistered schemas are refused.

## Not included

This is a library component. Reading `ops.outbox_events`, marking events
published, retries, and running a worker in production are the consumer's
concern and are outside RAY-831 R2; no production process consumes the outbox
today. FeetForcePlate's adoption (registering its handler and removing its
hard-coded schema check) is RAY-1006.
