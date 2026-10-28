from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

Sha256Hex = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64),
]
SchemaVersion = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]+/[1-9][0-9]*$")]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class EnrollmentStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class MissingValueState(StrEnum):
    PROVIDED = "PROVIDED"
    NONE_REPORTED = "NONE_REPORTED"
    DECLINED = "DECLINED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ValidityStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


class IngestStatus(StrEnum):
    RECEIVING = "RECEIVING"
    VERIFYING = "VERIFYING"
    INGESTED = "INGESTED"
    QUARANTINED = "QUARANTINED"
    CONFLICT = "CONFLICT"


class AnalysisStatus(StrEnum):
    NOT_REQUESTED = "NOT_REQUESTED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"


class ReportStatus(StrEnum):
    NOT_AVAILABLE = "NOT_AVAILABLE"
    BASIC_READY = "BASIC_READY"
    CLOUD_ANALYZING = "CLOUD_ANALYZING"
    FULL_READY = "FULL_READY"
    CLOUD_FAILED = "CLOUD_FAILED"


class SegmentReceiptStatus(StrEnum):
    ACKNOWLEDGED = "ACKNOWLEDGED"
    CONFLICT = "CONFLICT"
    QUARANTINED = "QUARANTINED"


class SystemSummary(ContractModel):
    os: Literal["windows", "macos", "linux"]
    os_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    app_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]


class EnrollmentRequest(ContractModel):
    activation_code: Annotated[str, StringConstraints(min_length=8, max_length=128)]
    installation_id: UUID
    client_public_key: Annotated[str, StringConstraints(min_length=16, max_length=8192)]
    system: SystemSummary


class EnrollmentResponse(ContractModel):
    tenant_id: UUID
    site_id: UUID | None
    terminal_id: UUID
    status: EnrollmentStatus
    access_token: str
    token_expires_at: datetime
    config_version: str | None = None


class HeartbeatDevice(ContractModel):
    device_id: UUID | None = None
    model: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    connection_state: Literal["UNKNOWN", "DISCONNECTED", "CONNECTING", "READY", "ERROR"]


class HeartbeatSync(ContractModel):
    last_successful_sync: datetime | None
    pending_sessions: Annotated[int, Field(ge=0)]
    pending_bytes: Annotated[int, Field(ge=0)]


class HeartbeatHealth(ContractModel):
    disk_free_bytes: Annotated[int, Field(ge=0)]
    clock_skew_seconds: float
    last_error_code: (
        Annotated[str, StringConstraints(pattern=r"^E-[A-Z]{3}-[0-9]{3}$")] | None
    ) = None


class HeartbeatRequest(ContractModel):
    app_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    config_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    protocol_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    device: HeartbeatDevice
    sync: HeartbeatSync
    health: HeartbeatHealth
    observed_at: datetime


class HeartbeatResponse(ContractModel):
    terminal_id: UUID
    accepted_at: datetime
    status: EnrollmentStatus


class ExternalIdentifierInput(ContractModel):
    issuer: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    id_type: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    external_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]


class SubjectResolveRequest(ExternalIdentifierInput):
    pass


class ProfileValue(ContractModel):
    state: MissingValueState
    value: Any | None = None

    @model_validator(mode="after")
    def enforce_state_value_pair(self) -> ProfileValue:
        if self.state is MissingValueState.PROVIDED and self.value is None:
            raise ValueError("PROVIDED requires a value")
        if self.state is not MissingValueState.PROVIDED and self.value is not None:
            raise ValueError(f"{self.state.value} cannot carry a value")
        return self


class IdentityProfileInput(ContractModel):
    display_name: Annotated[str, StringConstraints(min_length=1, max_length=256)] | None = None
    contact: Annotated[str, StringConstraints(min_length=1, max_length=512)] | None = None

    @model_validator(mode="after")
    def require_one_identity_field(self) -> IdentityProfileInput:
        if self.display_name is None and self.contact is None:
            raise ValueError("identity profile requires at least one field")
        return self


class SubjectCreateRequest(ContractModel):
    subject_uuid: UUID
    external_identifier: ExternalIdentifierInput | None = None
    identity_profile: IdentityProfileInput | None = None
    analysis_profile: dict[str, ProfileValue] = Field(default_factory=dict)
    profile_schema_version: SchemaVersion = "analysis-profile/1"


class SubjectSummary(ContractModel):
    subject_uuid: UUID
    external_identifier_id: UUID | None = None
    external_id_masked: str | None = None
    conflict: bool = False
    analysis_profile: dict[str, ProfileValue] = Field(default_factory=dict)


class ConsentCreateRequest(ContractModel):
    consent_record_id: UUID
    subject_uuid: UUID
    policy_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    purpose_codes: tuple[Annotated[str, StringConstraints(min_length=1, max_length=64)], ...]
    data_categories: tuple[Annotated[str, StringConstraints(min_length=1, max_length=64)], ...]
    granted_at: datetime
    evidence_type: Literal["OPERATOR_CONFIRMED", "SUBJECT_CONFIRMED", "REPRESENTATIVE_CONFIRMED"]
    terminal_signature: Annotated[str, StringConstraints(min_length=16, max_length=8192)]

    @field_validator("purpose_codes", "data_categories")
    @classmethod
    def non_empty_unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(set(value)) != len(value):
            raise ValueError("values must be non-empty and unique")
        return value


class ConsentResponse(ContractModel):
    consent_record_id: UUID
    subject_uuid: UUID
    policy_version: str
    granted_at: datetime
    revoked_at: datetime | None = None


class ConsentRevokeRequest(ContractModel):
    revoked_at: datetime
    reason_code: Annotated[str, StringConstraints(min_length=1, max_length=64)]


class TestProtocol(ContractModel):
    id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    version: Annotated[str, StringConstraints(min_length=1, max_length=64)]


class SessionVersions(ContractModel):
    app: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    protocol_profile: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    payload_schema: SchemaVersion
    calibration: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class SessionCreateRequest(ContractModel):
    session_id: UUID
    subject_uuid: UUID
    consent_record_id: UUID
    site_id: UUID | None
    terminal_id: UUID
    client_installation_id: UUID
    device_id: UUID
    test_protocol: TestProtocol
    versions: SessionVersions
    started_at: datetime
    config_snapshot: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def installation_matches_legacy_terminal(self) -> SessionCreateRequest:
        if self.client_installation_id != self.terminal_id:
            raise ValueError("client installation must match legacy terminal id")
        return self


class SessionCreateResponse(ContractModel):
    session_id: UUID
    ingest_status: IngestStatus
    idempotent_replay: bool = False


class SegmentMetadata(ContractModel):
    segment_index: Annotated[int, Field(ge=0)]
    start_frame_index: Annotated[int, Field(ge=0)]
    frame_count: Annotated[int, Field(gt=0)]
    start_monotonic_ns: Annotated[int, Field(ge=0)]
    end_monotonic_ns: Annotated[int, Field(gt=0)]
    compression: Literal["none", "zstd"]
    cipher: Literal["aes-256-gcm"]
    size_bytes: Annotated[int, Field(gt=0)]
    sha256: Sha256Hex
    payload_schema_version: SchemaVersion

    @model_validator(mode="after")
    def validate_ranges(self) -> SegmentMetadata:
        if self.end_monotonic_ns <= self.start_monotonic_ns:
            raise ValueError("end_monotonic_ns must follow start_monotonic_ns")
        return self


class SegmentAcknowledgement(ContractModel):
    session_id: UUID
    index: int
    sha256: Sha256Hex
    status: SegmentReceiptStatus
    object_key: str
    idempotent_replay: bool = False


class ReceivedSegment(ContractModel):
    index: Annotated[int, Field(ge=0)]
    sha256: Sha256Hex
    status: SegmentReceiptStatus


class SegmentListResponse(ContractModel):
    session_id: UUID
    received: tuple[ReceivedSegment, ...]
    missing: tuple[int, ...]


class ManifestSegment(ContractModel):
    index: Annotated[int, Field(ge=0)]
    sha256: Sha256Hex
    size_bytes: Annotated[int, Field(gt=0)]
    frame_count: Annotated[int, Field(gt=0)]


class SessionManifest(ContractModel):
    segment_count: Annotated[int, Field(gt=0)]
    total_frames: Annotated[int, Field(gt=0)]
    total_bytes: Annotated[int, Field(gt=0)]
    segments: tuple[ManifestSegment, ...]
    ended_at: datetime
    local_quality_outcome: ValidityStatus
    schema_version: SchemaVersion = "session-manifest/1"

    @model_validator(mode="after")
    def validate_segment_set_and_totals(self) -> SessionManifest:
        indices = [segment.index for segment in self.segments]
        if len(self.segments) != self.segment_count:
            raise ValueError("segment_count does not match segments")
        if indices != list(range(self.segment_count)):
            raise ValueError("manifest indices must be unique, ordered, and contiguous from zero")
        if sum(segment.frame_count for segment in self.segments) != self.total_frames:
            raise ValueError("total_frames does not match segments")
        if sum(segment.size_bytes for segment in self.segments) != self.total_bytes:
            raise ValueError("total_bytes does not match segments")
        return self


# RAY-825 R1: the smart-insole session is one deterministic tar.gz archive
# split into parts after capture, so its parts carry no frame range, clock,
# compression or cipher. Only the bytes' digest and size are verified.
INSOLE_ARCHIVE_PAYLOAD_SCHEMA = "insole-session-archive/1"
INSOLE_MANIFEST_SCHEMA = "insole-session-manifest/1"


class ArchiveSegmentMetadata(ContractModel):
    segment_index: Annotated[int, Field(ge=0)]
    size_bytes: Annotated[int, Field(gt=0)]
    sha256: Sha256Hex
    payload_schema_version: Literal["insole-session-archive/1"]


class ArchiveManifestSegment(ContractModel):
    index: Annotated[int, Field(ge=0)]
    sha256: Sha256Hex
    size_bytes: Annotated[int, Field(gt=0)]


class InsoleSessionManifest(ContractModel):
    schema_version: Literal["insole-session-manifest/1"]
    segment_count: Annotated[int, Field(gt=0)]
    total_bytes: Annotated[int, Field(gt=0)]
    segments: tuple[ArchiveManifestSegment, ...]
    ended_at: datetime
    local_quality_outcome: ValidityStatus

    @model_validator(mode="after")
    def validate_segment_set_and_totals(self) -> InsoleSessionManifest:
        indices = [segment.index for segment in self.segments]
        if len(self.segments) != self.segment_count:
            raise ValueError("segment_count does not match segments")
        if indices != list(range(self.segment_count)):
            raise ValueError("manifest indices must be unique, ordered, and contiguous from zero")
        if sum(segment.size_bytes for segment in self.segments) != self.total_bytes:
            raise ValueError("total_bytes does not match segments")
        return self


AnySegmentMetadata = SegmentMetadata | ArchiveSegmentMetadata
AnySessionManifest = SessionManifest | InsoleSessionManifest

# Each payload schema completes with exactly one manifest schema.
MANIFEST_SCHEMA_FOR_PAYLOAD = {
    "raw-segment/1": "session-manifest/1",
    INSOLE_ARCHIVE_PAYLOAD_SCHEMA: INSOLE_MANIFEST_SCHEMA,
}


def parse_segment_metadata(value: Any) -> AnySegmentMetadata:
    if (
        isinstance(value, dict)
        and value.get("payload_schema_version") == INSOLE_ARCHIVE_PAYLOAD_SCHEMA
    ):
        return ArchiveSegmentMetadata.model_validate(value)
    return SegmentMetadata.model_validate(value)


def parse_session_manifest(value: Any) -> AnySessionManifest:
    if isinstance(value, dict) and value.get("schema_version") == INSOLE_MANIFEST_SCHEMA:
        return InsoleSessionManifest.model_validate(value)
    return SessionManifest.model_validate(value)


class ManifestCompletionResponse(ContractModel):
    session_id: UUID
    ingest_status: IngestStatus
    manifest_sha256: Sha256Hex
    idempotent_replay: bool = False
    # CP-06 completion receipt facts: recorded at completion and replayed
    # identically from the stored record, so the canonical digest of the
    # receipt is independently re-derivable (RAY-407).
    manifest_object_key: str
    eligibility_reason: str
    eligibility_policy_version: str
    completed_at: datetime


class SessionStatusResponse(ContractModel):
    session_id: UUID
    validity_status: ValidityStatus
    ingest_status: IngestStatus
    analysis_status: AnalysisStatus = AnalysisStatus.NOT_REQUESTED
    report_status: ReportStatus = ReportStatus.NOT_AVAILABLE
    latest_report_version: int | None = None
    retry_after_seconds: int | None = None


class ErrorDetail(ContractModel):
    code: str
    message: str
    retryable: bool
    action: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(ContractModel):
    error: ErrorDetail
