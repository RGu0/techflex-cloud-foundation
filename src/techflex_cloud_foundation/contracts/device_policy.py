from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StringConstraints, field_validator, model_validator

from .client_sync import canonical_json_bytes
from .cloud import ContractModel, EnrollmentStatus, SchemaVersion


class LicenseStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class LicenseValidationState(StrEnum):
    VALID = "VALID"
    MISSING = "MISSING"
    INVALID = "INVALID"
    EXPIRED = "EXPIRED"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class OperationalCapability(StrEnum):
    START_NEW_TEST = "START_NEW_TEST"
    FINISH_CURRENT_TEST = "FINISH_CURRENT_TEST"
    VIEW_EXISTING_REPORTS = "VIEW_EXISTING_REPORTS"
    CONTINUE_UPLOAD = "CONTINUE_UPLOAD"
    DOWNLOAD_COMPLETED_REPORTS = "DOWNLOAD_COMPLETED_REPORTS"
    EXPORT_DIAGNOSTICS = "EXPORT_DIAGNOSTICS"


class GateReason(StrEnum):
    NOT_ACTIVATED = "NOT_ACTIVATED"
    TERMINAL_SUSPENDED = "TERMINAL_SUSPENDED"
    TERMINAL_REVOKED = "TERMINAL_REVOKED"
    CREDENTIAL_INVALID = "CREDENTIAL_INVALID"
    LICENSE_MISSING = "LICENSE_MISSING"
    LICENSE_INVALID = "LICENSE_INVALID"
    LICENSE_EXPIRED = "LICENSE_EXPIRED"
    LICENSE_SUSPENDED = "LICENSE_SUSPENDED"
    LICENSE_REVOKED = "LICENSE_REVOKED"
    FEATURE_DISABLED = "FEATURE_DISABLED"
    NEVER_ONLINE = "NEVER_ONLINE"
    OFFLINE_TOO_LONG = "OFFLINE_TOO_LONG"
    PENDING_SESSION_LIMIT = "PENDING_SESSION_LIMIT"
    PENDING_BYTES_LIMIT = "PENDING_BYTES_LIMIT"
    CLOCK_ROLLBACK = "CLOCK_ROLLBACK"
    HARDWARE_MISMATCH = "HARDWARE_MISMATCH"
    LICENSE_DOWNGRADE = "LICENSE_DOWNGRADE"
    LEASE_REQUIRED = "LEASE_REQUIRED"
    LEASE_CONFLICT = "LEASE_CONFLICT"


FeatureName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$", max_length=128),
]


class LicenseDocument(ContractModel):
    license_id: UUID
    license_version: Annotated[int, Field(gt=0)]
    tenant_id: UUID
    site_id: UUID | None
    terminal_id: UUID
    status: LicenseStatus
    enabled_features: tuple[FeatureName, ...]
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    schema_version: SchemaVersion = "license/1"

    @field_validator("enabled_features")
    @classmethod
    def normalize_features(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("enabled_features must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_window(self) -> LicenseDocument:
        if self.expires_at <= self.not_before:
            raise ValueError("expires_at must follow not_before")
        return self


class SignedLicense(ContractModel):
    document: LicenseDocument
    key_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    signature: Annotated[str, StringConstraints(min_length=80, max_length=128)]


class LegacyTerminalLicenseVerifier:
    """Legacy License/1 terminal-bound verifier retained for compatibility."""

    def __init__(self, public_keys: Mapping[str, bytes]) -> None:
        if not public_keys:
            raise ValueError("at least one license public key is required")
        self._public_keys = {
            key_id: Ed25519PublicKey.from_public_bytes(public_key)
            for key_id, public_key in public_keys.items()
        }

    def verify(
        self,
        license_bundle: SignedLicense,
        *,
        expected_tenant_id: UUID,
        expected_terminal_id: UUID,
        now: datetime,
    ) -> LicenseDocument:
        public_key = self._public_keys.get(license_bundle.key_id)
        if public_key is None:
            raise ValueError("license signature key is unknown")
        try:
            signature = base64.b64decode(license_bundle.signature, validate=True)
            public_key.verify(signature, canonical_json_bytes(license_bundle.document))
        except (binascii.Error, InvalidSignature) as exc:
            raise ValueError("license signature is invalid") from exc
        document = license_bundle.document
        if (
            document.tenant_id != expected_tenant_id
            or document.terminal_id != expected_terminal_id
        ):
            raise ValueError("license binding does not match this terminal")
        if document.status is not LicenseStatus.ACTIVE:
            raise ValueError("license is not active")
        if now < document.not_before or now >= document.expires_at:
            raise ValueError("license validity window is not active")
        return document


# Backward-compatible import name for existing License/1 callers. New client
# compositions use AccountHardwareLicenseVerifier from client.cloud.policy.
LicenseVerifier = LegacyTerminalLicenseVerifier


class DevicePolicyThresholds(ContractModel):
    max_offline_duration: timedelta = timedelta(hours=24)
    max_pending_sessions: Annotated[int, Field(gt=0)] = 50
    max_pending_bytes: Annotated[int, Field(gt=0)] = 2 * 1024**3


class DevicePolicyInput(ContractModel):
    evaluated_at: datetime
    activated: bool
    terminal_status: EnrollmentStatus
    credential_valid: bool
    license_state: LicenseValidationState
    enabled_features: tuple[FeatureName, ...] = ()
    last_successful_online_at: datetime | None
    pending_sessions: Annotated[int, Field(ge=0)]
    pending_bytes: Annotated[int, Field(ge=0)]
    clock_rollback_detected: bool
    session_in_progress: bool


class DevicePolicyDecision(ContractModel):
    may_start_new_test: bool
    support_required: bool
    reasons: tuple[GateReason, ...]
    allowed_capabilities: tuple[OperationalCapability, ...]


_LICENSE_REASON = {
    LicenseValidationState.MISSING: GateReason.LICENSE_MISSING,
    LicenseValidationState.INVALID: GateReason.LICENSE_INVALID,
    LicenseValidationState.EXPIRED: GateReason.LICENSE_EXPIRED,
    LicenseValidationState.SUSPENDED: GateReason.LICENSE_SUSPENDED,
    LicenseValidationState.REVOKED: GateReason.LICENSE_REVOKED,
}


def detect_clock_rollback(
    *,
    last_trusted_time: datetime,
    observed_time: datetime,
    tolerance: timedelta = timedelta(minutes=5),
) -> bool:
    if tolerance < timedelta(0):
        raise ValueError("clock rollback tolerance cannot be negative")
    return observed_time + tolerance < last_trusted_time


def evaluate_device_policy(
    state: DevicePolicyInput,
    thresholds: DevicePolicyThresholds | None = None,
) -> DevicePolicyDecision:
    policy = thresholds or DevicePolicyThresholds()
    reasons: list[GateReason] = []
    if not state.activated:
        reasons.append(GateReason.NOT_ACTIVATED)
    if state.terminal_status is EnrollmentStatus.SUSPENDED:
        reasons.append(GateReason.TERMINAL_SUSPENDED)
    elif state.terminal_status is EnrollmentStatus.REVOKED:
        reasons.append(GateReason.TERMINAL_REVOKED)
    if not state.credential_valid:
        reasons.append(GateReason.CREDENTIAL_INVALID)
    license_reason = _LICENSE_REASON.get(state.license_state)
    if license_reason is not None:
        reasons.append(license_reason)
    if "screening.start" not in state.enabled_features:
        reasons.append(GateReason.FEATURE_DISABLED)
    if state.last_successful_online_at is None:
        reasons.append(GateReason.NEVER_ONLINE)
    elif state.evaluated_at - state.last_successful_online_at > policy.max_offline_duration:
        reasons.append(GateReason.OFFLINE_TOO_LONG)
    if state.pending_sessions >= policy.max_pending_sessions:
        reasons.append(GateReason.PENDING_SESSION_LIMIT)
    if state.pending_bytes >= policy.max_pending_bytes:
        reasons.append(GateReason.PENDING_BYTES_LIMIT)
    if state.clock_rollback_detected:
        reasons.append(GateReason.CLOCK_ROLLBACK)

    capabilities = [
        OperationalCapability.VIEW_EXISTING_REPORTS,
        OperationalCapability.CONTINUE_UPLOAD,
        OperationalCapability.DOWNLOAD_COMPLETED_REPORTS,
        OperationalCapability.EXPORT_DIAGNOSTICS,
    ]
    if state.session_in_progress:
        capabilities.append(OperationalCapability.FINISH_CURRENT_TEST)
    if not reasons:
        capabilities.append(OperationalCapability.START_NEW_TEST)

    support_reasons = {
        GateReason.NOT_ACTIVATED,
        GateReason.TERMINAL_SUSPENDED,
        GateReason.TERMINAL_REVOKED,
        GateReason.CREDENTIAL_INVALID,
        GateReason.LICENSE_INVALID,
        GateReason.LICENSE_SUSPENDED,
        GateReason.LICENSE_REVOKED,
        GateReason.CLOCK_ROLLBACK,
    }
    return DevicePolicyDecision(
        may_start_new_test=not reasons,
        support_required=any(reason in support_reasons for reason in reasons),
        reasons=tuple(reasons),
        allowed_capabilities=tuple(capabilities),
    )
