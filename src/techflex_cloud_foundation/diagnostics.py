"""Safe observability interfaces that do not prescribe application telemetry."""

from __future__ import annotations

from typing import Mapping, Protocol


class AuditSink(Protocol):
    def record(self, name: str, *, outcome: str, correlation_id: str, fields: Mapping[str, int | str] = {}) -> None: ...


class MetricsSink(Protocol):
    def increment(self, name: str, *, value: int = 1) -> None: ...

    def observe(self, name: str, *, value: float) -> None: ...
