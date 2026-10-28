from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import Enum, StrEnum
import hashlib
import json
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, StringConstraints, model_validator

from .cloud import (
    AnySegmentMetadata,
    ConsentCreateRequest,
    ContractModel,
    ReceivedSegment,
    SegmentAcknowledgement,
    SegmentReceiptStatus,
    SessionCreateRequest,
    SessionVersions,
    Sha256Hex,
    SubjectCreateRequest,
    TestProtocol,
    parse_segment_metadata,
)

RAW_SEGMENT_PAYLOAD_SCHEMA = "raw-segment/1"


class FormalUploadEnvelope(ContractModel):
    """Immutable identity and version snapshot for one valid-session handoff."""

    schema_version: Literal["formal-upload-envelope/1"] = "formal-upload-envelope/1"
    session_id: UUID
    subject: SubjectCreateRequest
    consent: ConsentCreateRequest
    client_installation_id: UUID
    hardware_asset_id: UUID
    site_id: UUID | None
    test_protocol: TestProtocol
    versions: SessionVersions
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime

    @model_validator(mode="after")
    def validate_session_identities(self) -> FormalUploadEnvelope:
        if self.subject.subject_uuid != self.consent.subject_uuid:
            raise ValueError("consent subject must match upload subject")
        if self.session_id == self.subject.subject_uuid:
            raise ValueError("session id cannot alias subject uuid")
        return self

    def session_request(self) -> SessionCreateRequest:
        """Derive cloud registration only from the persisted immutable snapshot."""

        return SessionCreateRequest(
            session_id=self.session_id,
            subject_uuid=self.subject.subject_uuid,
            consent_record_id=self.consent.consent_record_id,
            site_id=self.site_id,
            terminal_id=self.client_installation_id,
            client_installation_id=self.client_installation_id,
            device_id=self.hardware_asset_id,
            test_protocol=self.test_protocol,
            versions=self.versions,
            started_at=self.started_at,
            config_snapshot=self.config_snapshot,
        )


class SubjectRecoveryAuthorization(ContractModel):
    """Encrypted local authorization; the original upload envelope stays immutable."""

    schema_version: Literal["subject-recovery/1", "subject-recovery/2"] = "subject-recovery/1"
    session_id: UUID
    original_envelope_sha256: Sha256Hex
    original_subject_uuid: UUID
    cloud_subject_uuid: UUID
    replacement_consent: ConsentCreateRequest
    operator_account_id: UUID
    confirmed_at: datetime
    cloud_external_id_masked: str | None = None
    case_id: UUID | None = None
    receipt_id: UUID | None = None
    receipt_expires_at: datetime | None = None
    platform_ticket_sha256: Sha256Hex | None = None

    @model_validator(mode="after")
    def validate_bindings(self) -> SubjectRecoveryAuthorization:
        if self.original_subject_uuid == self.cloud_subject_uuid:
            raise ValueError("recovery requires distinct subject identities")
        if self.replacement_consent.subject_uuid != self.cloud_subject_uuid:
            raise ValueError("replacement consent must target the cloud subject")
        if self.replacement_consent.granted_at < self.confirmed_at:
            raise ValueError("replacement consent predates operator confirmation")
        if self.schema_version == "subject-recovery/2":
            if (
                not self.case_id or not self.receipt_id or not self.receipt_expires_at
                or not self.platform_ticket_sha256
            ):
                raise ValueError("server case and receipt are required")
            if self.replacement_consent.evidence_type not in {
                "SUBJECT_CONFIRMED", "REPRESENTATIVE_CONFIRMED",
            }:
                raise ValueError("fresh subject or representative evidence is required")
        return self


class LocalSegmentState(StrEnum):
    WRITING = "WRITING"
    SEALED = "SEALED"
    PENDING_UPLOAD = "PENDING_UPLOAD"
    UPLOADING = "UPLOADING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RETRY_WAIT = "RETRY_WAIT"
    QUARANTINED = "QUARANTINED"
    CONFLICT = "CONFLICT"
    CORRUPT = "CORRUPT"


class UploadResourceType(StrEnum):
    SESSION = "SESSION"
    SEGMENT = "SEGMENT"
    MANIFEST = "MANIFEST"
    REPORT = "REPORT"
    TELEMETRY = "TELEMETRY"


class UploadTaskStatus(StrEnum):
    PENDING = "PENDING"
    LEASED = "LEASED"
    RETRY_WAIT = "RETRY_WAIT"
    SUCCEEDED = "SUCCEEDED"
    DEAD_LETTER = "DEAD_LETTER"


class DigestConflict(ContractModel):
    index: Annotated[int, Field(ge=0)]
    local_sha256: Sha256Hex
    remote_sha256: Sha256Hex
    remote_status: SegmentReceiptStatus


class SyncPlan(ContractModel):
    acknowledged: tuple[int, ...]
    upload: tuple[int, ...]
    conflicts: tuple[DigestConflict, ...]
    remote_only: tuple[int, ...]


class DurableUploadTask(ContractModel):
    """Transport-neutral row contract for a client-owned durable upload queue."""

    upload_task_id: UUID
    tenant_id: UUID
    terminal_id: UUID
    session_id: UUID | None = None
    resource_type: UploadResourceType
    resource_id: UUID
    operation: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    status: UploadTaskStatus = UploadTaskStatus.PENDING
    priority: int = 100
    idempotency_key: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    request_sha256: Sha256Hex
    attempt_count: Annotated[int, Field(ge=0)] = 0
    next_attempt_at: datetime | None = None
    lease_owner: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    lease_expires_at: datetime | None = None
    last_http_status: Annotated[int, Field(ge=100, le=599)] | None = None
    last_error_code: Annotated[
        str,
        StringConstraints(pattern=r"^E-[A-Z]{3}-[0-9]{3}$"),
    ] | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def validate_scheduler_state(self) -> DurableUploadTask:
        if self.status is UploadTaskStatus.RETRY_WAIT and self.next_attempt_at is None:
            raise ValueError("RETRY_WAIT requires next_attempt_at")
        lease_is_complete = self.lease_owner is not None and self.lease_expires_at is not None
        if self.status is UploadTaskStatus.LEASED and not lease_is_complete:
            raise ValueError("LEASED requires lease_owner and lease_expires_at")
        if self.status is not UploadTaskStatus.LEASED and (
            self.lease_owner is not None or self.lease_expires_at is not None
        ):
            raise ValueError("lease fields are only valid for LEASED tasks")
        return self


class RetryPolicy(ContractModel):
    base_seconds: Annotated[float, Field(gt=0)] = 1.0
    cap_seconds: Annotated[float, Field(gt=0)] = 900.0
    max_jitter_fraction: Annotated[float, Field(ge=0, le=1)] = 0.30

    def delay_seconds(
        self,
        *,
        attempt_count: int,
        jitter_fraction: float,
        retry_after_seconds: float | None = None,
    ) -> float:
        if attempt_count < 1:
            raise ValueError("attempt_count must be at least 1")
        if not 0 <= jitter_fraction <= self.max_jitter_fraction:
            raise ValueError(
                f"jitter_fraction must be between 0 and {self.max_jitter_fraction}"
            )
        if retry_after_seconds is not None:
            if retry_after_seconds < 0:
                raise ValueError("retry_after_seconds cannot be negative")
            return float(retry_after_seconds)
        exponential = self.base_seconds
        remaining_doublings = attempt_count - 1
        while remaining_doublings and exponential < self.cap_seconds:
            exponential = min(self.cap_seconds, exponential * 2)
            remaining_doublings -= 1
        return min(self.cap_seconds, exponential * (1 + jitter_fraction))


def may_enqueue_segment(state: LocalSegmentState) -> bool:
    return state in {
        LocalSegmentState.SEALED,
        LocalSegmentState.PENDING_UPLOAD,
        LocalSegmentState.RETRY_WAIT,
    }


def can_delete_local_segment(
    local_sha256: str,
    acknowledgement: SegmentAcknowledgement | None,
) -> bool:
    return bool(
        acknowledgement is not None
        and acknowledgement.status is SegmentReceiptStatus.ACKNOWLEDGED
        and acknowledgement.sha256 == local_sha256
    )


def build_sync_plan(
    local_segments: Mapping[int, str],
    remote_segments: Sequence[ReceivedSegment],
) -> SyncPlan:
    """Compare durable local facts with server receipts without overwriting conflicts."""

    remote_by_index: dict[int, ReceivedSegment] = {}
    for segment in remote_segments:
        if segment.index in remote_by_index:
            raise ValueError(f"duplicate remote segment index: {segment.index}")
        remote_by_index[segment.index] = segment

    acknowledged: list[int] = []
    upload: list[int] = []
    conflicts: list[DigestConflict] = []
    for index, local_sha256 in sorted(local_segments.items()):
        if index < 0:
            raise ValueError("local segment index cannot be negative")
        remote = remote_by_index.get(index)
        if remote is None:
            upload.append(index)
        elif (
            remote.status is SegmentReceiptStatus.ACKNOWLEDGED
            and remote.sha256 == local_sha256
        ):
            acknowledged.append(index)
        else:
            conflicts.append(
                DigestConflict(
                    index=index,
                    local_sha256=local_sha256,
                    remote_sha256=remote.sha256,
                    remote_status=remote.status,
                )
            )

    return SyncPlan(
        acknowledged=tuple(acknowledged),
        upload=tuple(upload),
        conflicts=tuple(conflicts),
        remote_only=tuple(sorted(set(remote_by_index) - set(local_segments))),
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=False)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, datetime):
        rendered = value.isoformat()
        return rendered.replace("+00:00", "Z")
    if isinstance(value, (UUID, Enum)):
        return str(value.value if isinstance(value, Enum) else value)
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def encode_segment_metadata(metadata: AnySegmentMetadata) -> str:
    return base64.urlsafe_b64encode(canonical_json_bytes(metadata)).rstrip(b"=").decode("ascii")


def decode_segment_metadata(value: str) -> AnySegmentMetadata:
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        decoded = json.loads(raw)
    except (UnicodeEncodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise ValueError("invalid X-Segment-Metadata header") from exc
    return parse_segment_metadata(decoded)
