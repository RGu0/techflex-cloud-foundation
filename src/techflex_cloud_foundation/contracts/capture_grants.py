"""Transport contracts for one-time capture grants and migration permits.

These values carry credentials; validation here does not prove authorization.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, SecretStr, StringConstraints, field_validator, model_validator

from .access_control import HardwareIdentity
from .cloud import ContractModel, Sha256Hex

NonemptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class _TokenContract(ContractModel):
    token: SecretStr

    @field_validator("token")
    @classmethod
    def require_opaque_token(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 20:
            raise ValueError("authorization token must contain at least 20 characters")
        return value


class CaptureGrant(_TokenContract):
    session_id: UUID


class CaptureGrantBatchRequest(ContractModel):
    count: Annotated[int, Field(ge=1, le=50)]


class CaptureGrantBatchResponse(ContractModel):
    grants: tuple[CaptureGrant, ...]


class RetireCaptureGrantRequest(ContractModel):
    session_id: UUID
    reason: NonemptyText


class CaptureCredential(_TokenContract):
    session_id: UUID
    kind: Literal["grant", "migration_permit"]


class SessionAuthorization(CaptureCredential):
    manifest_sha256: Sha256Hex

    def headers(self) -> dict[str, str]:
        return {
            "X-Capture-Authorization": f"{self.kind} {self.token.get_secret_value()}",
            "X-Expected-Manifest-SHA256": self.manifest_sha256,
        }


class UploadMigrationPermitRequest(ContractModel):
    tenant_id: UUID
    account_id: UUID
    license_id: UUID
    installation_id: UUID
    hardware_id: HardwareIdentity
    session_id: UUID
    request_sha256: Sha256Hex
    manifest_sha256: Sha256Hex
    original_envelope_sha256: Sha256Hex | None = None
    original_subject_uuid: UUID | None = None
    final_subject_uuid: UUID
    consent_record_id: UUID
    consent_sha256: Sha256Hex
    evidence_reference: NonemptyText
    reason: Literal["LEGACY_VALID_SESSION_REVIEWED"]
    identity_conflict: bool
    reconciliation_reference: UUID | None
    local_valid_reviewed: bool
    immutable_manifest_reviewed: bool
    original_consent_reviewed: bool
    historical_authorization_reviewed: bool

    @field_validator("evidence_reference")
    @classmethod
    def require_safe_evidence_reference(cls, value: str) -> str:
        # Opaque relative references only: no credentials, URI parameters,
        # traversal, free-text rationale, or evidence payloads in the audit.
        if (
            len(value) > 240
            or re.fullmatch(r"evidence/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value) is None
        ):
            raise ValueError("an opaque evidence/ reference is required")
        return value

    @model_validator(mode="after")
    def validate_reconciliation_reference(self) -> UploadMigrationPermitRequest:
        if self.identity_conflict and (
            self.reconciliation_reference is None
            or self.original_envelope_sha256 is None
            or self.original_subject_uuid is None
        ):
            raise ValueError("identity-conflict permits require a persisted recovery case binding")
        if not self.identity_conflict and self.reconciliation_reference is not None:
            raise ValueError("recovery case reference is only valid for identity-conflict permits")
        return self


class MigrationPermitResponse(_TokenContract):
    session_id: UUID


class LegacyMigrationBinding(ContractModel):
    """Immutable client-side binding for a reviewed legacy upload permit."""

    session_id: UUID
    original_envelope_sha256: Sha256Hex
    reconciliation_case_id: UUID | None = None
    original_subject_uuid: UUID
    final_subject_uuid: UUID
    final_consent_id: UUID
    final_consent_sha256: Sha256Hex
    request_sha256: Sha256Hex
    manifest_sha256: Sha256Hex
    approval_reference: NonemptyText
    permit: CaptureCredential

    @field_validator("approval_reference")
    @classmethod
    def require_safe_approval_reference(cls, value: str) -> str:
        if len(value) > 240 or re.fullmatch(
            r"evidence/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value
        ) is None:
            raise ValueError("an opaque evidence/ reference is required")
        return value

    @field_validator("permit")
    @classmethod
    def require_matching_migration_permit(cls, value: CaptureCredential) -> CaptureCredential:
        if value.kind != "migration_permit":
            raise ValueError("legacy binding requires a migration permit")
        return value

    @model_validator(mode="after")
    def validate_session_binding(self) -> LegacyMigrationBinding:
        if self.permit.session_id != self.session_id:
            raise ValueError("migration permit session mismatch")
        return self
