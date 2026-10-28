"""Terminal-safe contracts for controlled offline identity recovery."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from .cloud import ConsentCreateRequest, ContractModel, SessionCreateRequest, Sha256Hex


class RecoveryCaseCreateRequest(ContractModel):
    session_id: UUID
    original_subject_uuid: UUID
    cloud_subject_uuid: UUID
    envelope_sha256: Sha256Hex
    identifier_issuer: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    identifier_type: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    external_identifier_id: UUID
    terminal_id: UUID

    @model_validator(mode="after")
    def different_subjects(self) -> Self:
        if self.original_subject_uuid == self.cloud_subject_uuid:
            raise ValueError("recovery requires distinct local and cloud subjects")
        return self


class RecoveryCaseSummary(ContractModel):
    case_id: UUID
    session_id: UUID
    status: Literal["PENDING", "MATCHED", "DENIED", "EXPIRED"]
    masked_clue: str | None = None
    created_at: datetime
    receipt_id: UUID | None = None
    receipt_expires_at: datetime | None = None
    platform_ticket_sha256: Sha256Hex | None = None


class RecoveryCaseCreateResponse(ContractModel):
    case: RecoveryCaseSummary
    idempotent_replay: bool = Field(default=False)


class RecoveryComparisonRequest(ContractModel):
    tenant_id: UUID
    grant_id: UUID
    original_name: Annotated[str, StringConstraints(max_length=256)]
    original_contact: Annotated[str, StringConstraints(max_length=512)]
    ticket_reference: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class RecoveryComparisonResult(ContractModel):
    case_id: UUID
    decision: Literal["MATCHED", "NOT_VERIFIED"]
    receipt_id: UUID | None = None
    receipt_expires_at: datetime | None = None


class RecoveryRegistrationRequest(ContractModel):
    receipt_id: UUID
    original_subject_uuid: UUID
    original_envelope_sha256: Sha256Hex
    consent: ConsentCreateRequest
    session: SessionCreateRequest

    @model_validator(mode="after")
    def consent_matches_session(self) -> Self:
        if (
            self.consent.subject_uuid != self.session.subject_uuid
            or self.consent.consent_record_id != self.session.consent_record_id
        ):
            raise ValueError("consent and session do not share subject and consent identity")
        return self


class RecoveryRegistrationResult(ContractModel):
    case_id: UUID
    receipt_id: UUID
    consent_record_id: UUID
    session_id: UUID
    registered_at: datetime
