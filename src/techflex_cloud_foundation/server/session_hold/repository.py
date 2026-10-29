from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RequestContractError,
    ResourceNotFound,
)

from .models import (
    HoldApplyRequest,
    HoldDispositionRequest,
    HoldDispositionResult,
    HoldReleaseRequest,
    SessionHoldRecord,
    SessionHoldStatus,
)


class SessionHoldRepository(Protocol):
    async def apply(
        self,
        request: HoldApplyRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> SessionHoldRecord: ...

    async def status(self, tenant_id: UUID, session_id: UUID) -> SessionHoldStatus: ...

    async def dispose(
        self,
        request: HoldDispositionRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> HoldDispositionResult: ...

    async def release(
        self,
        request: HoldReleaseRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> SessionHoldRecord: ...


class SessionHoldReader(Protocol):
    """Synchronous, tenant-scoped decision passed to one domain processing step."""

    def is_held(self, tenant_id: UUID | str, session_id: UUID | str) -> bool: ...


class InMemorySessionHoldRepository:
    """Reference adapter; identity and raw session state are deliberately separate."""

    def __init__(self) -> None:
        self._sessions: dict[tuple[UUID, UUID], tuple[str, int]] = {}
        self._holds: dict[tuple[UUID, UUID], SessionHoldRecord] = {}
        self._keys: dict[tuple[UUID, str], tuple[str, Any]] = {}
        self._dispositions: dict[tuple[UUID, UUID], HoldDispositionResult] = {}
        self._policies: dict[tuple[UUID, UUID | None], tuple[bool, str]] = {}
        self._planned_jobs: list[tuple[UUID, UUID, UUID]] = []
        self._audit: list[tuple[str, UUID, UUID]] = []
        self._lock = asyncio.Lock()

    def add_session(
        self, tenant_id: UUID, session_id: UUID, *, status: str, raw_object_count: int
    ) -> None:
        self._sessions[(tenant_id, session_id)] = (status, raw_object_count)

    def session_status(self, tenant_id: UUID, session_id: UUID) -> str:
        return self._sessions[(tenant_id, session_id)][0]

    def raw_object_count(self, tenant_id: UUID, session_id: UUID) -> int:
        return self._sessions[(tenant_id, session_id)][1]

    def audit_count(self, action: str) -> int:
        return sum(1 for item in self._audit if item[0] == action)

    def add_retention_policy(
        self, tenant_id: UUID, policy_id: UUID, *, approved: bool, data_category: str = "RAW_DATA"
    ) -> None:
        self._policies[(tenant_id, policy_id)] = (approved, data_category)

    def planned_job_count(self, tenant_id: UUID, session_id: UUID) -> int:
        return sum(
            1
            for tenant, session, _ in self._planned_jobs
            if (tenant, session) == (tenant_id, session_id)
        )

    def is_held(self, tenant_id: UUID, session_id: UUID) -> bool:
        record = self._holds.get((tenant_id, session_id))
        return record is not None and record.state == "HELD"

    async def status(self, tenant_id: UUID, session_id: UUID) -> SessionHoldStatus:
        key = (tenant_id, session_id)
        if key not in self._sessions:
            raise ResourceNotFound("session not found")
        record = self._holds.get(key)
        if record is None:
            return SessionHoldStatus(held=False)
        return SessionHoldStatus(record.state == "HELD", record.hold_id, record.state)

    async def apply(
        self,
        request: HoldApplyRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> SessionHoldRecord:
        key = (request.tenant_id, request.session_id)
        async with self._lock:
            if key not in self._sessions:
                raise ResourceNotFound("session not found")
            prior = self._keys.get((request.tenant_id, idempotency_key))
            if prior is not None:
                if prior[0] != request_sha256:
                    raise IdempotencyConflict("idempotency key conflict")
                return cast(SessionHoldRecord, prior[1])
            if key in self._holds:
                raise IdempotencyConflict("session already held")
            record = SessionHoldRecord(
                hold_id=uuid4(),
                tenant_id=request.tenant_id,
                session_id=request.session_id,
                state="HELD",
                reason_code=request.reason_code,
                applied_at=datetime.now(UTC),
            )
            self._holds[key] = record
            self._keys[(request.tenant_id, idempotency_key)] = (request_sha256, record)
            self._audit.append(("session-hold.apply", request.tenant_id, request.session_id))
            return record

    async def dispose(
        self,
        request: HoldDispositionRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> HoldDispositionResult:
        key = (request.tenant_id, request.session_id)
        async with self._lock:
            hold = self._holds.get(key)
            if hold is None:
                raise ResourceNotFound("session hold not found")
            prior = self._keys.get((request.tenant_id, idempotency_key))
            if prior is not None:
                if prior[0] != request_sha256:
                    raise IdempotencyConflict("idempotency key conflict")
                return cast(HoldDispositionResult, prior[1])
            if hold.state != "HELD" or key in self._dispositions:
                raise IdempotencyConflict("hold disposition already recorded")
            job_id = None
            if request.decision_code == "RESTRICT_AND_DISPOSE":
                if self._policies.get((request.tenant_id, request.retention_policy_id)) != (
                    True,
                    "RAW_DATA",
                ):
                    raise ResourceNotFound("approved retention policy not found")
                job_id = uuid4()
                self._planned_jobs.append((request.tenant_id, request.session_id, job_id))
            result = HoldDispositionResult(
                disposition_id=uuid4(),
                hold_id=hold.hold_id,
                decision_code=request.decision_code,
                state="HELD",
                planned_job_id=job_id,
                planned_job_status="PLANNED" if job_id is not None else None,
            )
            self._dispositions[key] = result
            self._keys[(request.tenant_id, idempotency_key)] = (request_sha256, result)
            self._audit.append(("session-hold.disposition", *key))
            return result

    async def release(
        self,
        request: HoldReleaseRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> SessionHoldRecord:
        key = (request.tenant_id, request.session_id)
        async with self._lock:
            hold = self._holds.get(key)
            if hold is None:
                raise ResourceNotFound("session hold not found")
            prior = self._keys.get((request.tenant_id, idempotency_key))
            if prior is not None:
                if prior[0] != request_sha256:
                    raise IdempotencyConflict("idempotency key conflict")
                return cast(SessionHoldRecord, prior[1])
            disposition = self._dispositions.get(key)
            if disposition is None or disposition.decision_code != "RETAIN_WITH_VALID_BASIS":
                raise RequestContractError("retention disposition required before release")
            if hold.state != "HELD":
                raise IdempotencyConflict("hold already released")
            released = SessionHoldRecord(
                hold.hold_id,
                hold.tenant_id,
                hold.session_id,
                "RELEASED",
                hold.reason_code,
                hold.applied_at,
            )
            self._holds[key] = released
            self._keys[(request.tenant_id, idempotency_key)] = (request_sha256, released)
            self._audit.append(("session-hold.release", *key))
            return released
