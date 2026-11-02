"""Terminal diagnostic package records and the in-memory implementation.

A record is the package's metadata; the content lives in the object store
under ``object_key``. The purge keeps the record as a tombstone with
``deleted_at`` set, so the audit trail can still name what was there.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class DiagnosticRecord:
    diagnostic_id: UUID
    tenant_id: UUID
    client_installation_id: UUID
    idempotency_key: str
    format: str
    size_bytes: int
    sha256: str
    object_key: str
    received_at: datetime
    expires_at: datetime
    deleted_at: datetime | None = None


def diagnostic_object_key(tenant_id: UUID, diagnostic_id: UUID) -> str:
    return f"diagnostics/{tenant_id}/{diagnostic_id}.ndjson"


class DiagnosticRepository(Protocol):
    async def by_key(
        self, tenant_id: UUID, client_installation_id: UUID, idempotency_key: str
    ) -> DiagnosticRecord | None: ...

    async def insert(self, record: DiagnosticRecord) -> DiagnosticRecord:
        """Store ``record`` and return it, or the record already stored
        under its Idempotency-Key, unchanged."""

    async def list(self, tenant_id: UUID) -> tuple[DiagnosticRecord, ...]:
        """Newest first, tombstones included."""

    async def get(self, tenant_id: UUID, diagnostic_id: UUID) -> DiagnosticRecord | None: ...

    async def expired(self, now: datetime) -> tuple[DiagnosticRecord, ...]:
        """Every tenant's records past ``expires_at`` that are not tombstones."""

    async def mark_deleted(
        self, tenant_id: UUID, diagnostic_id: UUID, deleted_at: datetime
    ) -> None: ...


class InMemoryDiagnosticRepository:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[UUID, DiagnosticRecord] = {}

    async def by_key(
        self, tenant_id: UUID, client_installation_id: UUID, idempotency_key: str
    ) -> DiagnosticRecord | None:
        for record in self._records.values():
            if (record.tenant_id, record.client_installation_id, record.idempotency_key) == (
                tenant_id, client_installation_id, idempotency_key
            ):
                return record
        return None

    async def insert(self, record: DiagnosticRecord) -> DiagnosticRecord:
        async with self._lock:
            existing = await self.by_key(
                record.tenant_id, record.client_installation_id, record.idempotency_key
            )
            if existing is not None:
                return existing
            self._records[record.diagnostic_id] = record
            return record

    async def list(self, tenant_id: UUID) -> tuple[DiagnosticRecord, ...]:
        return tuple(sorted(
            (row for row in self._records.values() if row.tenant_id == tenant_id),
            key=lambda row: (row.received_at, row.diagnostic_id),
            reverse=True,
        ))

    async def get(self, tenant_id: UUID, diagnostic_id: UUID) -> DiagnosticRecord | None:
        record = self._records.get(diagnostic_id)
        return record if record is not None and record.tenant_id == tenant_id else None

    async def expired(self, now: datetime) -> tuple[DiagnosticRecord, ...]:
        return tuple(
            row for row in self._records.values()
            if row.deleted_at is None and row.expires_at <= now
        )

    async def mark_deleted(
        self, tenant_id: UUID, diagnostic_id: UUID, deleted_at: datetime
    ) -> None:
        async with self._lock:
            record = await self.get(tenant_id, diagnostic_id)
            if record is not None and record.deleted_at is None:
                self._records[diagnostic_id] = replace(record, deleted_at=deleted_at)


__all__ = [
    "DiagnosticRecord",
    "DiagnosticRepository",
    "InMemoryDiagnosticRepository",
    "diagnostic_object_key",
]
