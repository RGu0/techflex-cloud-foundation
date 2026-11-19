"""Registry-driven dispatch of ``session.ingested.v1`` events (RAY-831).

Ingestion commits one ``session.ingested.v1`` outbox event per session that
reaches ``INGESTED``; its payload carries ``payload_schema_version``.  This
module decides, from the payload schema registry alone, what happens next:

- the schema is bound to an analyzer: the handler registered under that
  analyzer name is called with the event and its result is returned;
- the schema has no binding: the session is ingested only, no handler runs
  and nothing is raised.

Analyzer bindings live in the payload schema registry
(:meth:`PayloadSchemaRegistry.bind_analyzer`), so a new analyzer is a
registration plus a handler, never a change to ingestion or to this module.
The dispatcher takes a snapshot of the bindings when it is built and refuses
to start when a bound analyzer has no handler or a handler names no binding,
so a mistake is caught at startup instead of silently dropping analyses.

This is a library component.  Reading the outbox, marking events published,
retries and running handlers in a worker are the consumer's concern; nothing
here touches a database.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Generic, Protocol, TypeVar

from .payload_contracts import PayloadSchemaRegistry, PayloadSchemaUnregistered

#: The only event type this dispatcher accepts.
INGESTED_EVENT_TYPE = "session.ingested.v1"

__all__ = [
    "INGESTED_EVENT_TYPE",
    "AnalysisDispatchError",
    "AnalyzerHandlerMissing",
    "AnalyzerHandlerUnbound",
    "DispatchKind",
    "DispatchOutcome",
    "IngestedEvent",
    "IngestedEventDispatcher",
    "UndispatchableEvent",
]


class AnalysisDispatchError(Exception):
    """Base class for analysis dispatch failures."""


class AnalyzerHandlerMissing(AnalysisDispatchError):
    """A schema is bound to an analyzer that has no registered handler."""


class AnalyzerHandlerUnbound(AnalysisDispatchError):
    """A handler is registered under a name no schema is bound to."""


class UndispatchableEvent(AnalysisDispatchError):
    """The event is not a ``session.ingested.v1`` event carrying a payload schema."""


class IngestedEvent(Protocol):
    """What the dispatcher reads from an event: its type and payload.

    :class:`techflex_cloud_foundation.contracts.events.EventEnvelope` and any
    outbox row adapter with these two attributes qualify.
    """

    @property
    def event_type(self) -> str: ...

    @property
    def payload(self) -> Mapping[str, Any]: ...


E = TypeVar("E", bound=IngestedEvent, contravariant=True)
R = TypeVar("R")


class DispatchKind(StrEnum):
    ANALYZED = "ANALYZED"
    INGEST_ONLY = "INGEST_ONLY"


@dataclass(frozen=True)
class DispatchOutcome(Generic[R]):
    """What dispatching one event did.

    ``result`` is the handler's return value for ``ANALYZED`` and ``None`` for
    ``INGEST_ONLY``.
    """

    kind: DispatchKind
    payload_schema_version: str
    analyzer: str | None = None
    result: R | None = None


class IngestedEventDispatcher(Generic[E, R]):
    """Route ``session.ingested.v1`` events to analyzer handlers by schema."""

    def __init__(
        self,
        registry: PayloadSchemaRegistry,
        handlers: Mapping[str, Callable[[E], R]],
    ) -> None:
        bindings = dict(registry.analyzer_bindings)
        bound = set(bindings.values())
        missing = sorted(bound - set(handlers))
        if missing:
            raise AnalyzerHandlerMissing(
                f"no handler registered for bound analyzer(s) {missing}"
            )
        unbound = sorted(set(handlers) - bound)
        if unbound:
            raise AnalyzerHandlerUnbound(
                f"handler(s) {unbound} are registered but no schema is bound to them"
            )
        self._schemas = frozenset(registry.schema_ids)
        self._bindings = bindings
        self._handlers = dict(handlers)

    def analyzer_for(self, payload_schema_version: str) -> str | None:
        """The analyzer this dispatcher routes ``payload_schema_version`` to,
        or ``None`` when that schema is ingested only."""
        if payload_schema_version not in self._schemas:
            raise PayloadSchemaUnregistered(
                f"payload schema {payload_schema_version!r} is not registered; "
                "unknown schemas are refused"
            )
        return self._bindings.get(payload_schema_version)

    def dispatch(self, event: E) -> DispatchOutcome[R]:
        """Run the bound handler for ``event``, or report it as ingested only."""
        if event.event_type != INGESTED_EVENT_TYPE:
            raise UndispatchableEvent(
                f"only {INGESTED_EVENT_TYPE} events are dispatched, got {event.event_type!r}"
            )
        schema = event.payload.get("payload_schema_version")
        if not isinstance(schema, str) or not schema:
            raise UndispatchableEvent(
                "event payload carries no payload_schema_version; events committed "
                "before RAY-831 must be enriched from the session before dispatch"
            )
        analyzer = self.analyzer_for(schema)
        if analyzer is None:
            return DispatchOutcome(DispatchKind.INGEST_ONLY, schema)
        result = self._handlers[analyzer](event)
        return DispatchOutcome(DispatchKind.ANALYZED, schema, analyzer, result)
