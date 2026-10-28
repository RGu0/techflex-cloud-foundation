from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from .cloud import ContractModel

TechnicalIdentifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$",
    ),
]
ReasonCode = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$"),
]
ErrorCode = Annotated[
    str,
    StringConstraints(pattern=r"^E-[A-Z]{3}-[0-9]{3}$"),
]


class ValidationTelemetryVersions(ContractModel):
    app: TechnicalIdentifier
    protocol: TechnicalIdentifier
    data_mode: TechnicalIdentifier
    rules: TechnicalIdentifier
    threshold: TechnicalIdentifier
    failure_policy: TechnicalIdentifier


class ValidationTelemetryStatistics(ContractModel):
    start_monotonic_ns: Annotated[int, Field(ge=0)]
    end_monotonic_ns: Annotated[int, Field(ge=0)]
    duration_ns: Annotated[int, Field(ge=0)]
    start_source_index: Annotated[int, Field(ge=0)]
    end_source_index: Annotated[int, Field(ge=0)]
    valid_frame_count: Annotated[int, Field(ge=0)]
    invalid_candidate_count: Annotated[int, Field(ge=0)]
    resynchronization_count: Annotated[int, Field(ge=0)]
    received_rate_hz: Annotated[float, Field(ge=0)]
    maximum_host_gap_ns: Annotated[int, Field(ge=0)]


class DeviceValidationTelemetryPayload(ContractModel):
    schema_version: Literal["device-validation-run/1"]
    validation_run_id: UUID
    previous_validation_run_id: UUID | None
    terminal_id: UUID
    device_ref: TechnicalIdentifier
    attempt_number: Annotated[int, Field(gt=0)]
    versions: ValidationTelemetryVersions
    started_at_wall_ns: Annotated[int, Field(ge=0)]
    completed_at_wall_ns: Annotated[int, Field(ge=0)]
    outcome: Literal["PASS", "RETRYABLE_FAIL", "SERVICE_REQUIRED"]
    reason: ReasonCode | None
    error_code: ErrorCode | None
    diagnostic_id: UUID
    statistics: ValidationTelemetryStatistics | None
    transitions: Annotated[tuple[ReasonCode, ...], Field(min_length=1, max_length=64)]
    partial_window_discarded: bool

    @model_validator(mode="after")
    def validate_run_state(self) -> DeviceValidationTelemetryPayload:
        if self.completed_at_wall_ns < self.started_at_wall_ns:
            raise ValueError("completed wall time cannot precede start")
        if self.outcome == "PASS" and self.reason is not None:
            raise ValueError("passing telemetry cannot contain a failure reason")
        if self.outcome != "PASS" and self.reason is None:
            raise ValueError("failed telemetry requires a reason")
        return self


class DeviceValidationTelemetryEvent(ContractModel):
    event_id: UUID
    schema_version: Literal["device-validation-telemetry/1"]
    created_at_ns: Annotated[int, Field(ge=0)]
    attempt_count: Annotated[int, Field(ge=0)]
    payload: DeviceValidationTelemetryPayload


class DeviceValidationTelemetryBatchRequest(ContractModel):
    schema_version: Literal["device-validation-telemetry-batch/1"] = (
        "device-validation-telemetry-batch/1"
    )
    client_installation_id: UUID
    events: Annotated[
        tuple[DeviceValidationTelemetryEvent, ...],
        Field(min_length=1, max_length=50),
    ]

    @model_validator(mode="after")
    def bind_events_to_installation(self) -> DeviceValidationTelemetryBatchRequest:
        if any(
            event.payload.terminal_id != self.client_installation_id
            for event in self.events
        ):
            raise ValueError("telemetry terminal does not match client installation")
        if len({event.event_id for event in self.events}) != len(self.events):
            raise ValueError("telemetry event IDs must be unique")
        return self


class DeviceValidationTelemetryReceipt(ContractModel):
    schema_version: Literal["device-validation-telemetry-receipt/1"] = (
        "device-validation-telemetry-receipt/1"
    )
    acknowledged_event_ids: tuple[UUID, ...]
    idempotent_replays: Annotated[int, Field(ge=0)]
