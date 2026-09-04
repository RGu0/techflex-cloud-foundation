"""Safe observability interfaces that do not prescribe application telemetry."""

from __future__ import annotations

from typing import Mapping, Protocol


class AuditSink(Protocol):
    """Where the application records that something happened.

    The library defines the shape of the call and nothing else: no sink is
    provided, no transport is assumed, and no field is named for it. What is
    worth auditing, and what may legally be written down, is the
    application's decision.
    """

    def record(
        self,
        name: str,
        *,
        outcome: str,
        correlation_id: str,
        fields: Mapping[str, int | str] | None = None,
    ) -> None:
        """Record one audited event; ``None`` means no additional fields.

        The default used to be ``fields: Mapping[str, int | str] = {}``. A
        Protocol's signature is copied into every implementation, so that
        literal became one dict shared by all calls to each implementing
        method -- and the annotation says ``Mapping``, which is exactly the
        promise that stops an implementer from wondering whether mutating it
        is safe. An implementation that enriched the argument (adding a
        tenant, say) or that stored it for later would leak fields from one
        audited event into the next, silently and only under load.

        ``None`` cannot be mutated or aliased, so the default is a value
        rather than an object with a lifetime.
        """
        ...


class MetricsSink(Protocol):
    """Counters and observations; the library never buffers or aggregates."""

    def increment(self, name: str, *, value: int = 1) -> None: ...

    def observe(self, name: str, *, value: float) -> None: ...
