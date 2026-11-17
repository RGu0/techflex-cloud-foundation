from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Protocol
import uuid

from techflex_cloud_foundation.server.observability.events import Severity, TelemetryEvent


@dataclass(frozen=True, slots=True)
class TelemetryBatch:
    batch_id: str
    events: tuple[TelemetryEvent, ...]


class TelemetryBatchUploader(Protocol):
    def upload(self, batch: TelemetryBatch) -> None: ...


_SEVERITY_RANK = {
    Severity.DEBUG: 0,
    Severity.INFO: 1,
    Severity.WARNING: 2,
    Severity.ERROR: 3,
    Severity.CRITICAL: 4,
}


class TelemetryUploadQueue:
    """Independent ring buffer with retry-stable batch identifiers.

    The queue is intentionally independent from acquisition and raw-data upload. A network
    failure returns control to the worker and leaves the batch leased for the next retry.
    """

    def __init__(self, *, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("telemetry queue capacity must be positive")
        self.capacity = capacity
        self._events: list[TelemetryEvent] = []
        self._lease: TelemetryBatch | None = None
        self._lock = threading.RLock()

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._events)

    def snapshot(self) -> tuple[TelemetryEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def enqueue(self, event: TelemetryEvent) -> None:
        with self._lock:
            if len(self._events) >= self.capacity:
                leased_count = len(self._lease.events) if self._lease is not None else 0
                candidates = range(leased_count, len(self._events))
                candidate_indexes = list(candidates)
                if not candidate_indexes:
                    return
                new_rank = _SEVERITY_RANK[event.severity]
                lower_priority = [
                    index
                    for index in candidate_indexes
                    if _SEVERITY_RANK[self._events[index].severity] < new_rank
                ]
                if lower_priority:
                    remove_index = lower_priority[0]
                else:
                    minimum_rank = min(
                        _SEVERITY_RANK[self._events[index].severity] for index in candidate_indexes
                    )
                    if new_rank < minimum_rank:
                        return
                    remove_index = next(
                        index
                        for index in candidate_indexes
                        if _SEVERITY_RANK[self._events[index].severity] == minimum_rank
                    )
                del self._events[remove_index]
            self._events.append(event)

    def upload_next(
        self,
        uploader: TelemetryBatchUploader,
        *,
        max_events: int,
    ) -> bool:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        with self._lock:
            if not self._events:
                return True
            if self._lease is None:
                self._lease = TelemetryBatch(
                    batch_id=str(uuid.uuid4()),
                    events=tuple(self._events[:max_events]),
                )
            lease = self._lease
        try:
            uploader.upload(lease)
        except Exception:
            return False
        with self._lock:
            if self._lease == lease:
                del self._events[: len(lease.events)]
                self._lease = None
        return True
