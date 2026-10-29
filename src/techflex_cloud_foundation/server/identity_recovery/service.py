"""Terminal-authorized immutable case entrypoint."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any, cast
import unicodedata
from uuid import UUID

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.contracts.capture_grants import SessionAuthorization
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.identity_recovery import (
    RecoveryCaseCreateRequest,
    RecoveryCaseSummary,
    RecoveryComparisonResult,
    RecoveryRegistrationRequest,
    RecoveryRegistrationResult,
)
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RepositoryUnavailable,
    RequestContractError,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.access_auth import PlatformAccessContext
from techflex_cloud_foundation.server.principal import IngestionPrincipal

from .models import RecoveryCaseRecord


class IdentityRecoveryService:
    def __init__(
        self, repository: Any, *, sensitive: Any = None, identity_reader: Any = None
    ) -> None:
        self._repository = repository
        self._sensitive = sensitive
        self._identity_reader = identity_reader

    @staticmethod
    def _summary(record: RecoveryCaseRecord) -> RecoveryCaseSummary:
        expired = (
            record.status == "MATCHED"
            and record.receipt_expires_at is not None
            and record.receipt_expires_at <= datetime.now(UTC)
        )
        return RecoveryCaseSummary(
            case_id=record.case_id,
            session_id=record.request.session_id,
            status="EXPIRED" if expired else cast(Any, record.status),
            masked_clue=record.masked_clue,
            created_at=record.created_at,
            receipt_id=None
            if expired or record.status != "MATCHED" or record.receipt_consumed_at
            else record.receipt_id,
            receipt_expires_at=None
            if expired or record.status != "MATCHED" or record.receipt_consumed_at
            else record.receipt_expires_at,
            platform_ticket_sha256=None
            if expired or record.status != "MATCHED" or record.receipt_consumed_at
            else record.ticket_sha256,
        )

    async def create_case(
        self,
        context: IngestionPrincipal,
        request: RecoveryCaseCreateRequest,
        idempotency_key: str,
    ) -> RecoveryCaseSummary:
        context.ensure_can_upload()
        if request.terminal_id != context.terminal_id:
            raise TenantAccessDenied("terminal does not own recovery case")
        if not idempotency_key or len(idempotency_key) > 128:
            raise RequestContractError("invalid recovery idempotency key")
        key_sha256 = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        request_sha256 = canonical_sha256(request)
        record = await self._repository.create_case(
            context.tenant_id,
            context.terminal_id,
            request,
            key_sha256,
            request_sha256,
        )
        return self._summary(record)

    async def get_case(self, context: IngestionPrincipal, case_id: UUID) -> RecoveryCaseSummary:
        context.ensure_can_upload()
        return self._summary(
            await self._repository.get_case(context.tenant_id, context.terminal_id, case_id)
        )

    @staticmethod
    def _name(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = unicodedata.normalize("NFKC", value).strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            return None
        return normalized

    @staticmethod
    def _contact(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = unicodedata.normalize("NFKC", value).strip()
        if not normalized or any(character in normalized for character in ",;\n\r/|"):
            return None
        return normalized

    async def compare(
        self,
        context: PlatformAccessContext,
        case_id: UUID,
        grant_id: UUID,
        original_name: str,
        original_contact: str,
        *,
        tenant_id: UUID,
        ticket_reference: str,
    ) -> RecoveryComparisonResult:
        if context.expires_at <= datetime.now(UTC) or not context.roles.intersection(
            {PlatformRole.OWNER, PlatformRole.SUPPORT}
        ):
            raise TenantAccessDenied("platform identity comparison is not authorized")
        if self._sensitive is None or self._identity_reader is None:
            raise RepositoryUnavailable("identity comparison is unavailable")
        case = await self._repository.get_platform_case(tenant_id, case_id)
        if (
            case.status == "MATCHED"
            and case.receipt_consumed_at is None
            and case.receipt_expires_at
            and case.receipt_expires_at > datetime.now(UTC)
        ):
            raise IdempotencyConflict("comparison already completed; read case status")
        if case.attempts >= 3 or case.status == "DENIED":
            return RecoveryComparisonResult(case_id=case_id, decision="NOT_VERIFIED")
        # Only the platform boundary reads plaintext. It is never passed to
        # repository methods, response models, or terminal-safe summaries.
        grant_records: list[Any] = []
        disclosed = await self._sensitive.read_identity(
            context,
            grant_id=grant_id,
            tenant_id=tenant_id,
            subject_id=case.request.cloud_subject_uuid,
            identity_loader=lambda: self._identity_reader.read_identity(
                tenant_id,
                case.request.cloud_subject_uuid,
            ),
            grant_observer=grant_records.append,
        )
        if len(grant_records) != 1 or grant_records[0].ticket_reference != ticket_reference:
            raise TenantAccessDenied("comparison ticket does not match grant")
        name = self._name(original_name)
        contact = self._contact(original_contact)
        matched = bool(
            name
            and contact
            and name == self._name(disclosed.display_name)
            and contact == self._contact(disclosed.contact)
        )
        return cast(
            RecoveryComparisonResult,
            await self._repository.record_comparison(
                tenant_id,
                case_id,
                matched=matched,
                actor_id=context.platform_identity_id,
                grant_id=grant_id,
                ticket_sha256=hashlib.sha256(
                    grant_records[0].ticket_reference.encode("utf-8")
                ).hexdigest(),
            ),
        )

    async def register(
        self,
        context: IngestionPrincipal,
        case_id: UUID,
        request: RecoveryRegistrationRequest,
        idempotency_key: str,
        authorization: SessionAuthorization | None = None,
    ) -> RecoveryRegistrationResult:
        context.ensure_can_upload()
        if not idempotency_key or len(idempotency_key) > 128:
            raise RequestContractError("invalid recovery idempotency key")
        case = await self._repository.get_case(context.tenant_id, context.terminal_id, case_id)
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
            or request.session.terminal_id != context.terminal_id
            or request.session.client_installation_id != context.terminal_id
            or request.consent.subject_uuid != case.request.cloud_subject_uuid
            or request.consent.consent_record_id != request.session.consent_record_id
        ):
            # A successful retry is resolved by the repository's idempotency
            # record before this current-state check in its own transaction.
            return cast(
                RecoveryRegistrationResult,
                await self._repository.register(
                    context,
                    case_id,
                    request,
                    idempotency_key,
                    canonical_sha256(request),
                    replay_only=True,
                    authorization=authorization,
                ),
            )
        if request.consent.evidence_type not in {"SUBJECT_CONFIRMED", "REPRESENTATIVE_CONFIRMED"}:
            raise RequestContractError("fresh subject or representative consent is required")
        if not any(purpose != "ALGORITHM_RESEARCH" for purpose in request.consent.purpose_codes):
            raise RequestContractError("necessary screening consent is required")
        if (
            request.consent.granted_at.tzinfo is None
            or request.consent.granted_at < case.receipt_expires_at - timedelta(minutes=15)
            or request.consent.granted_at > datetime.now(UTC) + timedelta(minutes=2)
        ):
            raise RequestContractError("fresh consent time is invalid")
        return cast(
            RecoveryRegistrationResult,
            await self._repository.register(
                context,
                case_id,
                request,
                idempotency_key,
                canonical_sha256(request),
                replay_only=False,
                authorization=authorization,
            ),
        )
