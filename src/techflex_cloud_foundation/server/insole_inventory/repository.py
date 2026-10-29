"""Insole inventory persistence ports and the in-memory implementation.

Every write runs inside ``writer(tenant_id)``, which serializes the writers of
one tenant. Revisions are assigned inside that critical section, so commit
order equals revision order and a reader that has seen revision N has also
seen every revision below N: the download cursor can never skip a change.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, ValuesView
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from techflex_cloud_foundation.contracts.insole_inventory import InsoleIdentityKind, InsoleRecord


@dataclass(frozen=True, slots=True)
class RegistrationKeyRecord:
    request_sha256: bytes
    insole_id: UUID


class InsoleWriteTransaction(Protocol):
    async def registration_key(
        self, client_installation_id: UUID, idempotency_key: str
    ) -> RegistrationKeyRecord | None: ...

    async def save_registration_key(
        self,
        client_installation_id: UUID,
        idempotency_key: str,
        record: RegistrationKeyRecord,
    ) -> None: ...

    async def by_identity(self, kind: InsoleIdentityKind, value: str) -> InsoleRecord | None: ...

    async def by_number(self, institution_number: str) -> InsoleRecord | None: ...

    async def get_for_update(self, insole_id: UUID) -> InsoleRecord | None: ...

    async def next_revision(self) -> int: ...

    async def insert(self, record: InsoleRecord) -> None: ...

    async def update(self, record: InsoleRecord) -> None: ...


class InsoleInventoryRepository(Protocol):
    def writer(self, tenant_id: UUID) -> AbstractAsyncContextManager[InsoleWriteTransaction]: ...

    async def get(self, tenant_id: UUID, insole_id: UUID) -> InsoleRecord | None: ...

    async def changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[InsoleRecord, ...]: ...


class _TenantState:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.last_revision = 0
        self.records: dict[UUID, InsoleRecord] = {}
        self.keys: dict[tuple[UUID, str], RegistrationKeyRecord] = {}


class _InMemoryWriteTransaction:
    """Stages writes and publishes them only when the block exits cleanly."""

    def __init__(self, state: _TenantState) -> None:
        self._state = state
        self._records: dict[UUID, InsoleRecord] = {}
        self._keys: dict[tuple[UUID, str], RegistrationKeyRecord] = {}
        self._revision = state.last_revision

    def _all(self) -> ValuesView[InsoleRecord]:
        merged = dict(self._state.records)
        merged.update(self._records)
        return merged.values()

    async def registration_key(
        self, client_installation_id: UUID, idempotency_key: str
    ) -> RegistrationKeyRecord | None:
        key = (client_installation_id, idempotency_key)
        return self._keys.get(key) or self._state.keys.get(key)

    async def save_registration_key(
        self, client_installation_id: UUID, idempotency_key: str, record: RegistrationKeyRecord
    ) -> None:
        self._keys[(client_installation_id, idempotency_key)] = record

    async def by_identity(self, kind: InsoleIdentityKind, value: str) -> InsoleRecord | None:
        for record in self._all():
            for node in (record.left, record.right):
                if node.identity.kind is kind and node.identity.value == value:
                    return record
        return None

    async def by_number(self, institution_number: str) -> InsoleRecord | None:
        for record in self._all():
            if record.institution_number == institution_number:
                return record
        return None

    async def get_for_update(self, insole_id: UUID) -> InsoleRecord | None:
        return self._records.get(insole_id) or self._state.records.get(insole_id)

    async def next_revision(self) -> int:
        self._revision += 1
        return self._revision

    async def insert(self, record: InsoleRecord) -> None:
        self._records[record.insole_id] = record

    async def update(self, record: InsoleRecord) -> None:
        self._records[record.insole_id] = record

    def commit(self) -> None:
        self._state.records.update(self._records)
        self._state.keys.update(self._keys)
        self._state.last_revision = self._revision


class InMemoryInsoleInventoryRepository:
    def __init__(self) -> None:
        self._tenants: dict[UUID, _TenantState] = {}

    def _tenant(self, tenant_id: UUID) -> _TenantState:
        return self._tenants.setdefault(tenant_id, _TenantState())

    @asynccontextmanager
    async def writer(self, tenant_id: UUID) -> AsyncIterator[_InMemoryWriteTransaction]:
        state = self._tenant(tenant_id)
        async with state.lock:
            transaction = _InMemoryWriteTransaction(state)
            yield transaction
            transaction.commit()

    async def get(self, tenant_id: UUID, insole_id: UUID) -> InsoleRecord | None:
        return self._tenant(tenant_id).records.get(insole_id)

    async def changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[InsoleRecord, ...]:
        rows = sorted(
            (
                row
                for row in self._tenant(tenant_id).records.values()
                if row.revision > after_revision
            ),
            key=lambda row: row.revision,
        )
        return tuple(rows[:limit])


__all__ = [
    "InMemoryInsoleInventoryRepository",
    "InsoleInventoryRepository",
    "InsoleWriteTransaction",
    "RegistrationKeyRecord",
]
