"""Versioned institutional multi-terminal activation contracts (RAY-656 R2).

One institutional account activates several mobile terminals. Each terminal
is identified by its ``client_installation_id``, holds its own refresh family,
and consumes one seat of the account License. The seat limit is carried in the
signed ``terminal-license/1`` document so clients verify it offline.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator, model_validator

from .access_control import (
    AccessCapabilities,
    AccountName,
    LicenseState,
    PasswordValue,
    SecretValue,
)
from .cloud import ContractModel
from .device_policy import FeatureName

TERMINAL_REFRESH_REPLAY_GRACE_SECONDS: Final = 30

TerminalName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=64),
]


class TerminalPlatform(StrEnum):
    IOS = "ios"
    ANDROID = "android"


class TerminalState(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class TerminalActivationRequest(ContractModel):
    account_name: AccountName
    password: PasswordValue
    terminal_name: TerminalName
    client_installation_id: UUID
    platform: TerminalPlatform


class TerminalRefreshRequest(ContractModel):
    refresh_token: SecretValue
    client_installation_id: UUID


class TerminalRenameRequest(ContractModel):
    terminal_name: TerminalName


class TerminalLicenseDocument(ContractModel):
    tenant_id: UUID
    account_id: UUID
    license_id: UUID
    status: LicenseState
    issued_at: datetime
    valid_from: datetime
    valid_until: datetime
    version: Annotated[int, Field(gt=0)]
    enabled_features: tuple[FeatureName, ...]
    seats: Annotated[int, Field(ge=0)]
    # A const, so a signature over this document can never verify as license/2.
    schema_version: Literal["terminal-license/1"] = "terminal-license/1"

    @field_validator("enabled_features")
    @classmethod
    def normalize_features(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("enabled_features must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_window(self) -> TerminalLicenseDocument:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must follow valid_from")
        return self


class SignedTerminalLicense(ContractModel):
    document: TerminalLicenseDocument
    key_id: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
    signature: Annotated[str, StringConstraints(min_length=80, max_length=128)]


class TerminalCredentialResponse(ContractModel):
    """Long-lived terminal credentials returned by activation and refresh.

    A refresh replayed inside ``refresh_replay_grace_seconds`` after rotation
    returns the identical ``refresh_token``; ``access_token`` is freshly issued.
    """

    tenant_id: UUID
    account_id: UUID
    license_id: UUID
    client_installation_id: UUID
    terminal_name: TerminalName
    platform: TerminalPlatform
    access_token: SecretValue
    access_token_expires_at: datetime
    refresh_token: SecretValue
    refresh_idle_expires_at: datetime
    refresh_absolute_expires_at: datetime
    refresh_replay_grace_seconds: Literal[30] = TERMINAL_REFRESH_REPLAY_GRACE_SECONDS
    signed_license: SignedTerminalLicense
    capabilities: AccessCapabilities


class TerminalSummary(ContractModel):
    client_installation_id: UUID
    terminal_name: TerminalName
    platform: TerminalPlatform
    status: TerminalState
    activated_at: datetime
    last_refreshed_at: datetime | None = None
    revoked_at: datetime | None = None


class TerminalListResponse(ContractModel):
    license_id: UUID
    seats: Annotated[int, Field(ge=0)]
    seats_used: Annotated[int, Field(ge=0)]
    terminals: tuple[TerminalSummary, ...]


__all__ = [
    "SignedTerminalLicense",
    "TERMINAL_REFRESH_REPLAY_GRACE_SECONDS",
    "TerminalActivationRequest",
    "TerminalCredentialResponse",
    "TerminalLicenseDocument",
    "TerminalListResponse",
    "TerminalName",
    "TerminalPlatform",
    "TerminalRefreshRequest",
    "TerminalRenameRequest",
    "TerminalState",
    "TerminalSummary",
]
