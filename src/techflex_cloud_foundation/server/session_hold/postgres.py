from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID, uuid4

from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RequestContractError,
    ResourceNotFound,
)
from techflex_cloud_foundation.server.postgres import tenant_transaction

from .models import (
    HoldApplyRequest,
    HoldDispositionRequest,
    HoldDispositionResult,
    HoldReleaseRequest,
    SessionHoldRecord,
    SessionHoldStatus,
)


def _record(row: Any) -> SessionHoldRecord:
    return SessionHoldRecord(
        hold_id=row["hold_id"],
        tenant_id=row["tenant_id"],
        session_id=row["session_id"],
        state=row["state"],
        reason_code=row["reason_code"],
        applied_at=row["applied_at"],
    )


class PostgresSessionHoldRepository:
    """All reads and transitions use transaction-local tenant RLS context."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    @staticmethod
    def _sha(value: str) -> str:
        return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()

    @staticmethod
    async def _lock_key(connection: Any, tenant_id: UUID, key_sha256: str) -> None:
        # Key lock always precedes the session lock. This serializes reuse of
        # one tenant-wide idempotency key across distinct sessions.
        await connection.execute(
            """SELECT pg_advisory_xact_lock(hashtextextended(
                   'hold-key:' || $1::uuid::text || ':' || $2::text, 0))""",
            tenant_id,
            key_sha256,
        )

    @staticmethod
    async def _lock_hold(connection: Any, tenant_id: UUID, session_id: UUID) -> Any:
        await connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || $2::uuid::text, 0))",
            tenant_id,
            session_id,
        )
        hold = await connection.fetchrow(
            """SELECT hold_id, tenant_id, session_id, state, reason_code, applied_at
               FROM ops.session_holds WHERE tenant_id=$1 AND session_id=$2 FOR UPDATE""",
            tenant_id,
            session_id,
        )
        if hold is None:
            raise ResourceNotFound("session hold not found")
        return hold

    async def status(self, tenant_id: UUID, session_id: UUID) -> SessionHoldStatus:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            session_exists = await connection.fetchval(
                "SELECT EXISTS(SELECT 1 FROM screening.sessions WHERE tenant_id=$1 AND session_id=$2)",
                tenant_id,
                session_id,
            )
            if not session_exists:
                raise ResourceNotFound("session not found")
            row = await connection.fetchrow(
                "SELECT hold_id, state FROM ops.session_holds WHERE tenant_id=$1 AND session_id=$2",
                tenant_id,
                session_id,
            )
            if row is None:
                return SessionHoldStatus(held=False)
            return SessionHoldStatus(row["state"] == "HELD", row["hold_id"], row["state"])

    async def is_held(self, tenant_id: UUID, session_id: UUID) -> bool:
        status = await self.status(tenant_id, session_id)
        return status.held

    async def apply(
        self,
        request: HoldApplyRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> SessionHoldRecord:
        tenant_id, session_id = request.tenant_id, request.session_id
        key_sha256 = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        ticket_sha256 = hashlib.sha256(request.ticket_reference.strip().encode("utf-8")).hexdigest()
        async with tenant_transaction(self._pool, tenant_id) as connection:
            await self._lock_key(connection, tenant_id, key_sha256)
            # Session-scoped advisory lock serializes distinct-key requests without
            # granting the platform role UPDATE on screening.sessions.
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || $2::uuid::text, 0))",
                tenant_id,
                session_id,
            )
            exists = await connection.fetchval(
                "SELECT 1 FROM screening.sessions WHERE tenant_id=$1 AND session_id=$2",
                tenant_id,
                session_id,
            )
            if not exists:
                raise ResourceNotFound("session not found")
            prior = await connection.fetchrow(
                """SELECT request_sha256, h.hold_id, h.tenant_id, h.session_id,
                          i.result_state AS state, h.reason_code, h.applied_at
                   FROM ops.session_hold_idempotency i
                   JOIN ops.session_holds h ON h.tenant_id=i.tenant_id AND h.hold_id=i.hold_id
                   WHERE i.tenant_id=$1 AND i.key_sha256=$2""",
                tenant_id,
                key_sha256,
            )
            if prior is not None:
                if prior["request_sha256"] != request_sha256:
                    raise IdempotencyConflict("idempotency key conflict")
                return _record(prior)
            held = await connection.fetchval(
                "SELECT 1 FROM ops.session_holds WHERE tenant_id=$1 AND session_id=$2",
                tenant_id,
                session_id,
            )
            if held:
                raise IdempotencyConflict("session already held")
            hold_id, event_id = uuid4(), uuid4()
            row = await connection.fetchrow(
                """INSERT INTO ops.session_holds
                   (hold_id, tenant_id, session_id, state, reason_code)
                   VALUES ($1,$2,$3,'HELD',$4)
                   RETURNING hold_id, tenant_id, session_id, state, reason_code, applied_at""",
                hold_id,
                tenant_id,
                session_id,
                request.reason_code,
            )
            await connection.execute(
                """INSERT INTO ops.session_hold_idempotency
                   (tenant_id, key_sha256, request_sha256, hold_id, action, result_state)
                   VALUES ($1,$2,$3,$4,'APPLY','HELD')""",
                tenant_id,
                key_sha256,
                request_sha256,
                hold_id,
            )
            await connection.execute(
                """INSERT INTO ops.session_hold_events
                   (event_id, tenant_id, hold_id, session_id, action, actor_id, ticket_sha256)
                   VALUES ($1,$2,$3,$4,'APPLY',$5,$6)""",
                event_id,
                tenant_id,
                hold_id,
                session_id,
                actor_id,
                ticket_sha256,
            )
            await connection.execute(
                """INSERT INTO ops.audit_logs
                   (audit_log_id, tenant_id, actor_type, actor_id, action, resource_type,
                    resource_id, outcome, safe_context)
                   VALUES ($1,$2,'PLATFORM_IDENTITY',$3,'session-hold.apply','SESSION',$4,
                           'ALLOWED',jsonb_build_object('reason_code',$5::text,'hold_id',$6::uuid::text))""",
                uuid4(),
                tenant_id,
                actor_id,
                session_id,
                request.reason_code,
                hold_id,
            )
            return _record(row)

    async def dispose(
        self,
        request: HoldDispositionRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> HoldDispositionResult:
        tenant_id, session_id = request.tenant_id, request.session_id
        key_sha256 = self._sha(idempotency_key)
        async with tenant_transaction(self._pool, tenant_id) as connection:
            await self._lock_key(connection, tenant_id, key_sha256)
            hold = await self._lock_hold(connection, tenant_id, session_id)
            prior = await connection.fetchrow(
                "SELECT request_sha256 FROM ops.session_hold_idempotency WHERE tenant_id=$1 AND key_sha256=$2",
                tenant_id,
                key_sha256,
            )
            if prior is not None:
                if prior["request_sha256"] != request_sha256:
                    raise IdempotencyConflict("idempotency key conflict")
                disposition = await connection.fetchrow(
                    """SELECT disposition_id, hold_id, decision_code, planned_job_id
                       FROM ops.session_hold_dispositions WHERE tenant_id=$1 AND hold_id=$2""",
                    tenant_id,
                    hold["hold_id"],
                )
                if disposition is None:
                    raise IdempotencyConflict("idempotency action conflict")
                return self._disposition_result(disposition)
            if hold["state"] != "HELD":
                raise IdempotencyConflict("session hold already released")
            existing = await connection.fetchval(
                "SELECT 1 FROM ops.session_hold_dispositions WHERE tenant_id=$1 AND hold_id=$2",
                tenant_id,
                hold["hold_id"],
            )
            if existing:
                raise IdempotencyConflict("hold disposition already recorded")
            planned_job_id = None
            if request.decision_code == "RESTRICT_AND_DISPOSE":
                policy_id = request.retention_policy_id
                approved = await connection.fetchval(
                    """SELECT 1 FROM ops.retention_policies WHERE tenant_id=$1
                       AND retention_policy_id=$2 AND effective_at <= now()
                       AND superseded_at IS NULL AND approved_by IS NOT NULL
                       AND data_category='RAW_DATA'""",
                    tenant_id,
                    policy_id,
                )
                if not approved:
                    raise ResourceNotFound("approved retention policy not found")
                subject_id = await connection.fetchval(
                    "SELECT subject_uuid FROM screening.sessions WHERE tenant_id=$1 AND session_id=$2",
                    tenant_id,
                    session_id,
                )
                planned_job_id = uuid4()
                await connection.execute(
                    """INSERT INTO ops.data_disposition_jobs
                       (data_disposition_job_id, tenant_id, retention_policy_id,
                        subject_uuid, action, status, evidence_json)
                       VALUES ($1,$2,$3,$4,'RESTRICT','PLANNED',
                               jsonb_build_object('scope','SESSION_ONLY',
                                                  'session_id',$5::uuid::text,'hold_id',$6::uuid::text))""",
                    planned_job_id,
                    tenant_id,
                    policy_id,
                    subject_id,
                    session_id,
                    hold["hold_id"],
                )
            disposition_id = uuid4()
            row = await connection.fetchrow(
                """INSERT INTO ops.session_hold_dispositions
                   (disposition_id, tenant_id, hold_id, decision_code, evidence_sha256,
                    valid_basis_sha256, retention_policy_id, planned_job_id)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                   RETURNING disposition_id, hold_id, decision_code, planned_job_id""",
                disposition_id,
                tenant_id,
                hold["hold_id"],
                request.decision_code,
                self._sha(request.evidence_reference),
                self._sha(request.valid_basis_reference) if request.valid_basis_reference else None,
                request.retention_policy_id,
                planned_job_id,
            )
            await connection.execute(
                """INSERT INTO ops.session_hold_idempotency
                   (tenant_id, key_sha256, request_sha256, hold_id, action, result_state)
                   VALUES ($1,$2,$3,$4,'DISPOSITION','HELD')""",
                tenant_id,
                key_sha256,
                request_sha256,
                hold["hold_id"],
            )
            await connection.execute(
                """INSERT INTO ops.session_hold_events
                   (event_id, tenant_id, hold_id, session_id, action, actor_id,
                    ticket_sha256, safe_context)
                   VALUES ($1,$2,$3,$4,'DISPOSITION',$5,$6,
                           jsonb_build_object('decision_code',$7::text))""",
                uuid4(),
                tenant_id,
                hold["hold_id"],
                session_id,
                actor_id,
                self._sha(request.ticket_reference),
                request.decision_code,
            )
            await connection.execute(
                """INSERT INTO ops.audit_logs
                   (audit_log_id, tenant_id, actor_type, actor_id, action, resource_type,
                    resource_id, outcome, safe_context)
                   VALUES ($1,$2,'PLATFORM_IDENTITY',$3,'session-hold.disposition',
                           'SESSION',$4,'ALLOWED',jsonb_build_object('decision_code',$5::text))""",
                uuid4(),
                tenant_id,
                actor_id,
                session_id,
                request.decision_code,
            )
            return self._disposition_result(row)

    @staticmethod
    def _disposition_result(row: Any) -> HoldDispositionResult:
        job_id = row["planned_job_id"]
        return HoldDispositionResult(
            disposition_id=row["disposition_id"],
            hold_id=row["hold_id"],
            decision_code=row["decision_code"],
            state="HELD",
            planned_job_id=job_id,
            planned_job_status="PLANNED" if job_id else None,
        )

    async def release(
        self,
        request: HoldReleaseRequest,
        *,
        actor_id: UUID,
        idempotency_key: str,
        request_sha256: str,
    ) -> SessionHoldRecord:
        tenant_id, session_id = request.tenant_id, request.session_id
        key_sha256 = self._sha(idempotency_key)
        async with tenant_transaction(self._pool, tenant_id) as connection:
            await self._lock_key(connection, tenant_id, key_sha256)
            hold = await self._lock_hold(connection, tenant_id, session_id)
            prior = await connection.fetchrow(
                "SELECT request_sha256, action, result_state FROM ops.session_hold_idempotency WHERE tenant_id=$1 AND key_sha256=$2",
                tenant_id,
                key_sha256,
            )
            if prior is not None:
                if prior["request_sha256"] != request_sha256 or prior["action"] != "RELEASE":
                    raise IdempotencyConflict("idempotency key conflict")
                return SessionHoldRecord(
                    hold["hold_id"],
                    tenant_id,
                    session_id,
                    prior["result_state"],
                    hold["reason_code"],
                    hold["applied_at"],
                )
            disposition = await connection.fetchrow(
                """SELECT decision_code, valid_basis_sha256 FROM ops.session_hold_dispositions
                   WHERE tenant_id=$1 AND hold_id=$2""",
                tenant_id,
                hold["hold_id"],
            )
            if (
                disposition is None
                or disposition["decision_code"] != "RETAIN_WITH_VALID_BASIS"
                or not disposition["valid_basis_sha256"]
            ):
                raise RequestContractError("retention disposition required before release")
            if hold["state"] != "HELD":
                raise IdempotencyConflict("hold already released")
            row = await connection.fetchrow(
                """UPDATE ops.session_holds SET state='RELEASED', released_at=now()
                   WHERE tenant_id=$1 AND session_id=$2
                   RETURNING hold_id, tenant_id, session_id, state, reason_code, applied_at""",
                tenant_id,
                session_id,
            )
            await connection.execute(
                """INSERT INTO ops.session_hold_idempotency
                   (tenant_id, key_sha256, request_sha256, hold_id, action, result_state)
                   VALUES ($1,$2,$3,$4,'RELEASE','RELEASED')""",
                tenant_id,
                key_sha256,
                request_sha256,
                hold["hold_id"],
            )
            await connection.execute(
                """INSERT INTO ops.session_hold_events
                   (event_id, tenant_id, hold_id, session_id, action, actor_id, ticket_sha256)
                   VALUES ($1,$2,$3,$4,'RELEASE',$5,$6)""",
                uuid4(),
                tenant_id,
                hold["hold_id"],
                session_id,
                actor_id,
                self._sha(request.ticket_reference),
            )
            await connection.execute(
                """INSERT INTO ops.audit_logs
                   (audit_log_id, tenant_id, actor_type, actor_id, action, resource_type,
                    resource_id, outcome, safe_context)
                   VALUES ($1,$2,'PLATFORM_IDENTITY',$3,'session-hold.release',
                           'SESSION',$4,'ALLOWED',jsonb_build_object('hold_id',$5::uuid::text))""",
                uuid4(),
                tenant_id,
                actor_id,
                session_id,
                hold["hold_id"],
            )
            return _record(row)
