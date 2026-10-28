"""Versioned seed-MVP account, License, hardware, and Platform IAM contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator, model_validator

from .cloud import ContractModel, SchemaVersion
from .device_policy import FeatureName

AccountName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    ),
]
TenantName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)]
HardwareIdentity = Annotated[
    str,
    StringConstraints(
        pattern=r"^(?:usb-serial-[0-9a-f]{20}|FFP-DP4864-[0-9]{6})$",
        min_length=17,
        max_length=31,
    ),
]
AssetSerial = Annotated[
    str,
    StringConstraints(pattern=r"^FFP-DP4864-[0-9]{6}$", min_length=17, max_length=17),
]
SecretValue = Annotated[str, StringConstraints(min_length=20, max_length=8192)]
PasswordValue = Annotated[str, StringConstraints(min_length=12, max_length=256)]
PurposeCode = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Z0-9][A-Z0-9._-]*$",
    ),
]
TicketReference = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=128),
]


class AccountState(StrEnum):
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


class LicenseState(StrEnum):
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class LicenseControlAction(StrEnum):
    RENEW = "RENEW"
    SUSPEND = "SUSPEND"
    RESTORE = "RESTORE"
    REVOKE = "REVOKE"


class PlatformRole(StrEnum):
    OWNER = "PLATFORM_OWNER"
    OPERATIONS = "PLATFORM_OPERATIONS"
    SUPPORT = "PLATFORM_SUPPORT"
    ENGINEER = "PLATFORM_ENGINEER"


class ProvisionTenantRequest(ContractModel):
    tenant_name: TenantName
    account_name: AccountName
    hardware_id: HardwareIdentity
    license_period_months: Literal[6, 12]
    enabled_features: tuple[FeatureName, ...] = ("reports.view", "screening.start", "sync.upload")

    @field_validator("enabled_features")
    @classmethod
    def normalize_features(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(set(value)) != len(value):
            raise ValueError("enabled_features must be non-empty and unique")
        return tuple(sorted(value))


class ProvisionTenantResponse(ContractModel):
    tenant_id: UUID
    account_id: UUID
    license_id: UUID
    hardware_id: HardwareIdentity
    account_name: AccountName
    activation_code: SecretValue
    activation_expires_at: datetime
    license_period_months: Literal[6, 12]


class InventoryBatchCreateRequest(ContractModel):
    quantity: Annotated[int, Field(ge=1, le=100)]
    model: Literal["DO-P4864"] = "DO-P4864"
    license_period_months: Literal[12] = 12


class InventoryActivationRequest(ContractModel):
    tenant_name: TenantName
    account_name: AccountName
    password: PasswordValue
    password_confirmation: PasswordValue
    asset_serial: AssetSerial
    activation_code: SecretValue
    client_installation_id: UUID

    @model_validator(mode="after")
    def require_password_confirmation(self) -> InventoryActivationRequest:
        if self.password != self.password_confirmation:
            raise ValueError("password confirmation does not match")
        return self


class ActivateAccountRequest(ContractModel):
    account_name: AccountName
    activation_code: SecretValue
    password: PasswordValue
    password_confirmation: PasswordValue
    hardware_id: HardwareIdentity
    client_installation_id: UUID

    @model_validator(mode="after")
    def require_password_confirmation(self) -> ActivateAccountRequest:
        if self.password != self.password_confirmation:
            raise ValueError("password confirmation does not match")
        return self


class LoginRequest(ContractModel):
    account_name: AccountName
    password: PasswordValue
    client_installation_id: UUID


class RefreshRequest(ContractModel):
    refresh_token: SecretValue
    client_installation_id: UUID


class LogoutRequest(ContractModel):
    refresh_token: SecretValue


class LicenseDocumentV2(ContractModel):
    tenant_id: UUID
    account_id: UUID
    license_id: UUID
    hardware_id: HardwareIdentity
    status: LicenseState
    issued_at: datetime
    valid_from: datetime
    valid_until: datetime
    version: Annotated[int, Field(gt=0)]
    enabled_features: tuple[FeatureName, ...]
    schema_version: SchemaVersion = "license/2"

    @field_validator("enabled_features")
    @classmethod
    def normalize_features(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("enabled_features must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_window(self) -> LicenseDocumentV2:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must follow valid_from")
        return self


class SignedLicenseV2(ContractModel):
    document: LicenseDocumentV2
    key_id: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
    signature: Annotated[str, StringConstraints(min_length=80, max_length=128)]


class AccessCapabilities(ContractModel):
    allow_new_test: bool
    allow_upload: bool = True
    allow_report_view: bool = True


class AccessSession(ContractModel):
    tenant_id: UUID
    account_id: UUID
    license_id: UUID
    hardware_asset_id: UUID
    hardware_id: HardwareIdentity
    client_installation_id: UUID
    access_token: SecretValue
    access_token_expires_at: datetime
    refresh_token: SecretValue
    refresh_idle_expires_at: datetime
    refresh_absolute_expires_at: datetime
    signed_license: SignedLicenseV2
    capabilities: AccessCapabilities


class ActivateAccountResponse(AccessSession):
    account_state: AccountState


class LoginResponse(AccessSession):
    account_state: AccountState


class RefreshResponse(AccessSession):
    pass


class LicenseControlRequest(ContractModel):
    action: LicenseControlAction
    valid_until: datetime | None = None
    reason_code: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=64),
    ] | None = None

    @model_validator(mode="after")
    def require_action_fields(self) -> LicenseControlRequest:
        if self.action is LicenseControlAction.RENEW and self.valid_until is None:
            raise ValueError("renew requires valid_until")
        if self.action is not LicenseControlAction.RENEW and self.valid_until is not None:
            raise ValueError("valid_until is accepted only for renew")
        if self.action in {LicenseControlAction.SUSPEND, LicenseControlAction.REVOKE}:
            if self.reason_code is None:
                raise ValueError("suspend and revoke require reason_code")
        return self


class LicenseControlResponse(ContractModel):
    signed_license: SignedLicenseV2
    changed_at: datetime


class HardwareLeaseRequest(ContractModel):
    hardware_id: HardwareIdentity
    client_installation_id: UUID


class HardwareLeaseResponse(ContractModel):
    lease_id: UUID
    hardware_id: HardwareIdentity
    client_installation_id: UUID
    acquired_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_window(self) -> HardwareLeaseResponse:
        if self.expires_at <= self.acquired_at:
            raise ValueError("lease expires_at must follow acquired_at")
        return self


class PlatformLoginRequest(ContractModel):
    login_name: AccountName
    password: PasswordValue


class PlatformLoginResponse(ContractModel):
    platform_identity_id: UUID
    roles: tuple[PlatformRole, ...]
    access_token: SecretValue
    access_token_expires_at: datetime
    refresh_token: SecretValue

    @field_validator("roles")
    @classmethod
    def require_unique_roles(cls, value: tuple[PlatformRole, ...]) -> tuple[PlatformRole, ...]:
        if not value or len(set(value)) != len(value):
            raise ValueError("roles must be non-empty and unique")
        return tuple(sorted(value, key=lambda role: role.value))


class SensitiveAccessGrantRequest(ContractModel):
    tenant_id: UUID
    purpose_code: PurposeCode
    ticket_reference: TicketReference
    requested_duration_minutes: Annotated[int, Field(gt=0, le=15)] = 15


class SensitiveAccessGrantResponse(ContractModel):
    grant_id: UUID
    tenant_id: UUID
    purpose_code: PurposeCode
    ticket_reference: TicketReference
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_window(self) -> SensitiveAccessGrantResponse:
        if self.expires_at <= self.issued_at:
            raise ValueError("grant expires_at must follow issued_at")
        return self


class MaskedTenantSummary(ContractModel):
    tenant_id: UUID
    display_name: TenantName
    active_account_count: Annotated[int, Field(ge=0)]
    active_license_count: Annotated[int, Field(ge=0)]


class MaskedReportSummary(ContractModel):
    tenant_id: UUID
    report_id: UUID
    subject_reference_masked: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=128),
    ]
    created_at: datetime
    status: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class SensitiveIdentityResponse(ContractModel):
    grant_id: UUID
    tenant_id: UUID
    subject_id: UUID
    display_name: str | None = None
    contact: str | None = None
    disclosed_at: datetime

    @model_validator(mode="after")
    def require_identity_value(self) -> SensitiveIdentityResponse:
        if self.display_name is None and self.contact is None:
            raise ValueError("sensitive identity response requires at least one field")
        return self


__all__ = [
    "AccessCapabilities",
    "AccessSession",
    "AccountName",
    "AccountState",
    "ActivateAccountRequest",
    "ActivateAccountResponse",
    "AssetSerial",
    "HardwareIdentity",
    "HardwareLeaseRequest",
    "HardwareLeaseResponse",
    "LicenseControlAction",
    "LicenseControlRequest",
    "LicenseControlResponse",
    "LicenseDocumentV2",
    "LicenseState",
    "InventoryActivationRequest",
    "InventoryBatchCreateRequest",
    "LoginRequest",
    "LoginResponse",
    "LogoutRequest",
    "MaskedReportSummary",
    "MaskedTenantSummary",
    "PlatformLoginRequest",
    "PlatformLoginResponse",
    "PlatformRole",
    "ProvisionTenantRequest",
    "ProvisionTenantResponse",
    "RefreshRequest",
    "RefreshResponse",
    "SensitiveAccessGrantRequest",
    "SensitiveAccessGrantResponse",
    "SensitiveIdentityResponse",
    "SignedLicenseV2",
]
