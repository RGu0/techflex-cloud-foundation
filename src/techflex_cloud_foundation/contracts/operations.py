from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator, model_validator

from .cloud import ContractModel, EnrollmentStatus, Sha256Hex


class OperationsPermission(StrEnum):
    SITE_MANAGE = "SITE_MANAGE"
    TERMINAL_MANAGE = "TERMINAL_MANAGE"
    DEVICE_MANAGE = "DEVICE_MANAGE"
    ACTIVATION_MANAGE = "ACTIVATION_MANAGE"
    LICENSE_MANAGE = "LICENSE_MANAGE"
    UPGRADE_MANAGE = "UPGRADE_MANAGE"
    HEALTH_VIEW = "HEALTH_VIEW"
    RAW_DATA_ACCESS = "RAW_DATA_ACCESS"
    IDENTITY_ACCESS = "IDENTITY_ACCESS"
    LOG_ACCESS = "LOG_ACCESS"
    DIAGNOSTICS_ACCESS = "DIAGNOSTICS_ACCESS"


class DataAccessCategory(StrEnum):
    RAW_DATA = "RAW_DATA"
    IDENTITY = "IDENTITY"
    LOGS = "LOGS"
    DIAGNOSTICS = "DIAGNOSTICS"


class SiteCreateRequest(ContractModel):
    site_id: UUID
    site_code: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    name: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    timezone: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class SiteSummary(SiteCreateRequest):
    tenant_id: UUID
    status: Literal["ACTIVE", "SUSPENDED", "CLOSED"] = "ACTIVE"


class DeviceRegistrationRequest(ContractModel):
    device_id: UUID
    model: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    capabilities: dict[str, Any] = Field(default_factory=dict)


class DeviceSummary(DeviceRegistrationRequest):
    tenant_id: UUID
    status: Literal["ACTIVE", "SUSPENDED", "RETIRED"] = "ACTIVE"


class TerminalDeviceBindingSummary(ContractModel):
    binding_id: UUID
    tenant_id: UUID
    terminal_id: UUID
    device_id: UUID
    valid_from: datetime
    valid_to: datetime | None = None


class ActivationCodeIssueResponse(ContractModel):
    enrollment_code_id: UUID
    site_id: UUID | None
    device_id: UUID | None
    activation_code: Annotated[str, StringConstraints(min_length=20, max_length=128)]
    expires_at: datetime


class ActivationCodeIssueRequest(ContractModel):
    site_id: UUID | None
    device_id: UUID | None
    expires_at: datetime


FeatureName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$", max_length=128),
]


class LicenseIssueRequest(ContractModel):
    terminal_id: UUID
    site_id: UUID | None
    enabled_features: tuple[FeatureName, ...]
    not_before: datetime
    expires_at: datetime

    @field_validator("enabled_features")
    @classmethod
    def normalized_features(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("enabled_features must be non-empty and unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def valid_window(self) -> LicenseIssueRequest:
        if self.expires_at <= self.not_before:
            raise ValueError("expires_at must follow not_before")
        return self


class LicenseRenewRequest(ContractModel):
    expires_at: datetime
    enabled_features: tuple[FeatureName, ...] | None = None

    @field_validator("enabled_features")
    @classmethod
    def normalized_optional_features(
        cls, value: tuple[str, ...] | None
    ) -> tuple[str, ...] | None:
        if value is None:
            return None
        if not value or len(value) != len(set(value)):
            raise ValueError("enabled_features must be non-empty and unique")
        return tuple(sorted(value))


class LicenseRevokeRequest(ContractModel):
    reason_code: Annotated[
        str,
        StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{2,63}$"),
    ]


class TerminalStatusChangeRequest(ContractModel):
    status: Literal["ACTIVE", "SUSPENDED", "REVOKED"]


class TerminalHealthSummary(ContractModel):
    terminal_id: UUID
    site_id: UUID | None
    status: EnrollmentStatus
    last_seen_at: datetime | None
    app_version: str | None
    config_version: str | None
    protocol_version: str | None
    pending_sessions: Annotated[int, Field(ge=0)]
    pending_bytes: Annotated[int, Field(ge=0)]
    device_connection_state: Literal[
        "UNKNOWN", "DISCONNECTED", "CONNECTING", "READY", "ERROR"
    ]
    error_trends: dict[Annotated[str, StringConstraints(pattern=r"^E-[A-Z]{3}-[0-9]{3}$")], int]


class UpgradePolicyRequest(ContractModel):
    platform: Literal["windows", "macos", "linux"]
    target_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    minimum_supported_version: Annotated[
        str, StringConstraints(min_length=1, max_length=64)
    ]
    rollout_percent: Annotated[int, Field(ge=0, le=100)]
    package_sha256: Sha256Hex
    package_signature: Annotated[str, StringConstraints(min_length=16, max_length=8192)]
    rollback_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def validate_rollback(self) -> UpgradePolicyRequest:
        if self.rollback_version == self.target_version:
            raise ValueError("rollback_version must differ from target_version")
        return self


class UpgradePolicySummary(UpgradePolicyRequest):
    upgrade_policy_id: UUID
    tenant_id: UUID
    status: Literal["DRAFT", "ACTIVE", "PAUSED", "ROLLED_BACK"] = "DRAFT"
    created_at: datetime


class UpgradePolicyStatusRequest(ContractModel):
    status: Literal["DRAFT", "ACTIVE", "PAUSED", "ROLLED_BACK"]


class DataAccessRequest(ContractModel):
    category: DataAccessCategory
    site_id: UUID | None
    purpose: Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
    resource_id: UUID | None = None


class DataAccessDecision(ContractModel):
    allowed: bool
    audit_id: UUID
    category: DataAccessCategory
    expires_at: datetime
