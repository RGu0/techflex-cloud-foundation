"""In-memory reference transaction for immutable recovery cases."""

from __future__ import annotations

import asyncio
import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.capture_grants import SessionAuthorization
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.identity_recovery import (
    RecoveryCaseCreateRequest,
    RecoveryComparisonResult,
    RecoveryRegistrationRequest,
    RecoveryRegistrationResult,
)
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    ResourceNotFound,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.principal import IngestionPrincipal

from .models import RecoveryCaseRecord


class InMemoryRecoveryCaseRepository:
    def __init__(self, data_repository: Any = None) -> None:
        self._subjects: dict[tuple[UUID, UUID], tuple[UUID, str | None]] = {}
        self._cases: dict[tuple[UUID, UUID], RecoveryCaseRecord] = {}
        self._by_id: dict[tuple[UUID, UUID], RecoveryCaseRecord] = {}
        self._keys: dict[tuple[UUID, str], RecoveryCaseRecord] = {}
        self._lock = asyncio.Lock()
        self._data_repository = data_repository
        self._registrations: dict[tuple[UUID, UUID], RecoveryRegistrationResult] = {}
        self._registration_keys: dict[tuple[UUID, str], tuple[str, RecoveryRegistrationResult]] = {}

    def attach_data_repository(self, data_repository: Any) -> None:
        self._data_repository = data_repository

    def open_case_id(self, tenant_id: UUID, session_id: UUID) -> UUID | None:
        case = self._cases.get((tenant_id, session_id))
        return case.case_id if case is not None else None

    def add_subject(
        self, tenant_id: UUID, subject_id: UUID, *, masked_clue: str | None = None
    ) -> UUID:
        identifier_id = uuid4()
        self._subjects[(tenant_id, subject_id)] = (identifier_id, masked_clue)
        return identifier_id

    def replace_identifier(self, tenant_id: UUID, subject_id: UUID) -> UUID:
        identifier_id = uuid4()
        _prior_id, clue = self._subjects[(tenant_id, subject_id)]
        self._subjects[(tenant_id, subject_id)] = (identifier_id, clue)
        return identifier_id

    def deactivate_subject(self, tenant_id: UUID, subject_id: UUID) -> None:
        self._subjects.pop((tenant_id, subject_id), None)

    async def create_case(
        self,
        tenant_id: UUID,
        terminal_id: UUID,
        request: RecoveryCaseCreateRequest,
        key_sha256: str,
        request_sha256: str,
    ) -> RecoveryCaseRecord:
        async with self._lock:
            keyed = self._keys.get((tenant_id, key_sha256))
            if keyed is not None:
                if keyed.request_sha256 != request_sha256:
                    raise IdempotencyConflict("recovery case idempotency key conflict")
                return keyed
            if (tenant_id, request.cloud_subject_uuid) not in self._subjects or self._subjects[
                (tenant_id, request.cloud_subject_uuid)
            ][0] != request.external_identifier_id:
                raise ResourceNotFound("cloud subject not found")
            if (
                self._data_repository is not None
                and (tenant_id, request.session_id) in self._data_repository._sessions
            ):
                raise IdempotencyConflict("session already registered before recovery case")
            existing = self._cases.get((tenant_id, request.session_id))
            if existing is not None:
                if existing.request_sha256 != request_sha256:
                    raise IdempotencyConflict("recovery case binding conflict")
                self._keys[(tenant_id, key_sha256)] = existing
                return existing
            record = RecoveryCaseRecord(
                case_id=uuid4(),
                tenant_id=tenant_id,
                terminal_id=terminal_id,
                request=request,
                request_sha256=request_sha256,
                key_sha256=key_sha256,
                masked_clue=self._subjects[(tenant_id, request.cloud_subject_uuid)][1],
                status="PENDING",
                created_at=datetime.now(UTC),
            )
            self._cases[(tenant_id, request.session_id)] = record
            self._by_id[(tenant_id, record.case_id)] = record
            self._keys[(tenant_id, key_sha256)] = record
            return record

    async def get_case(
        self, tenant_id: UUID, terminal_id: UUID, case_id: UUID
    ) -> RecoveryCaseRecord:
        record = self._by_id.get((tenant_id, case_id))
        if record is None or record.terminal_id != terminal_id:
            raise ResourceNotFound("recovery case not found")
        return record

    async def get_platform_case(self, tenant_id: UUID, case_id: UUID) -> RecoveryCaseRecord:
        record = self._by_id.get((tenant_id, case_id))
        if record is None:
            raise ResourceNotFound("recovery case not found")
        return record

    async def record_comparison(
        self,
        tenant_id: UUID,
        case_id: UUID,
        *,
        matched: bool,
        actor_id: UUID,
        grant_id: UUID,
        ticket_sha256: str,
    ) -> RecoveryComparisonResult:
        async with self._lock:
            case = await self.get_platform_case(tenant_id, case_id)
            if (
                case.status == "MATCHED"
                and case.receipt_expires_at is not None
                and case.receipt_expires_at > datetime.now(UTC)
            ):
                raise IdempotencyConflict("comparison already completed")
            if case.attempts >= 3:
                return RecoveryComparisonResult(case_id=case_id, decision="NOT_VERIFIED")
            if (tenant_id, case.request.cloud_subject_uuid) not in self._subjects or self._subjects[
                (tenant_id, case.request.cloud_subject_uuid)
            ][0] != case.request.external_identifier_id:
                raise ResourceNotFound("cloud subject is no longer active")
            receipt_id = uuid4() if matched else None
            expires_at = datetime.now(UTC) + timedelta(minutes=15) if matched else None
            updated = replace(
                case,
                attempts=case.attempts + 1,
                status="MATCHED" if matched else ("DENIED" if case.attempts >= 2 else "PENDING"),
                receipt_id=receipt_id,
                receipt_expires_at=expires_at,
                ticket_sha256=ticket_sha256 if matched else None,
            )
            self._by_id[(tenant_id, case_id)] = updated
            self._cases[(tenant_id, case.request.session_id)] = updated
            self._keys[(tenant_id, case.key_sha256)] = updated
            return RecoveryComparisonResult(
                case_id=case_id,
                decision="MATCHED" if matched else "NOT_VERIFIED",
                receipt_id=receipt_id,
                receipt_expires_at=expires_at,
            )

    async def register(
        self,
        context: IngestionPrincipal,
        case_id: UUID,
        request: RecoveryRegistrationRequest,
        idempotency_key: str,
        request_sha256: str,
        *,
        replay_only: bool,
        authorization: SessionAuthorization | None = None,
    ) -> RecoveryRegistrationResult:
        async with self._lock:
            key = (context.tenant_id, idempotency_key)
            prior = self._registration_keys.get(key)
            if prior is not None:
                if prior[0] != request_sha256 or prior[1].case_id != case_id:
                    raise IdempotencyConflict("recovery registration key conflict")
                return prior[1]
            if replay_only:
                raise IdempotencyConflict("recovery registration binding conflict")
            case = await self.get_case(context.tenant_id, context.terminal_id, case_id)
            if (
                case.status != "MATCHED"
                or case.receipt_id != request.receipt_id
                or case.receipt_expires_at is None
                or case.receipt_expires_at <= datetime.now(UTC)
                or case.receipt_consumed_at is not None
                or case.request.original_subject_uuid != request.original_subject_uuid
                or case.request.envelope_sha256 != request.original_envelope_sha256
                or case.request.session_id != request.session.session_id
                or case.request.cloud_subject_uuid != request.session.subject_uuid
                or request.consent.subject_uuid != case.request.cloud_subject_uuid
                or request.consent.consent_record_id != request.session.consent_record_id
                or request.session.terminal_id != context.terminal_id
                or request.session.client_installation_id != context.terminal_id
            ):
                raise IdempotencyConflict("recovery registration binding conflict")
            if self._data_repository is None:
                raise TenantAccessDenied("recovery data repository unavailable")
            if (
                context.tenant_id,
                case.request.cloud_subject_uuid,
            ) not in self._subjects or self._subjects[
                (context.tenant_id, case.request.cloud_subject_uuid)
            ][0] != case.request.external_identifier_id:
                raise ResourceNotFound("cloud subject is no longer active")
            data = self._data_repository
            snapshot = {
                name: copy.deepcopy(getattr(data, name))
                for name in ("_consents", "_sessions", "_session_tenants", "_idempotency")
            }
            try:
                await data.create_consent(
                    context,
                    request.consent,
                    canonical_sha256(request.consent),
                    f"recovery-consent:{case_id}",
                )
                await data.create_session(
                    context,
                    request.session,
                    f"recovery-session:{case_id}",
                    authorization=authorization,
                    recovery_case_id=case_id,
                )
            except Exception:
                for name, state in snapshot.items():
                    setattr(data, name, state)
                raise
            result = RecoveryRegistrationResult(
                case_id=case_id,
                receipt_id=request.receipt_id,
                consent_record_id=request.consent.consent_record_id,
                session_id=request.session.session_id,
                registered_at=datetime.now(UTC),
            )
            updated = replace(case, receipt_consumed_at=result.registered_at)
            self._by_id[(context.tenant_id, case_id)] = updated
            self._cases[(context.tenant_id, case.request.session_id)] = updated
            self._keys[(context.tenant_id, case.key_sha256)] = updated
            self._registrations[(context.tenant_id, case_id)] = result
            self._registration_keys[key] = (request_sha256, result)
            return result
