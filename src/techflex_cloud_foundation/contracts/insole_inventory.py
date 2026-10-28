"""Versioned institutional insole inventory contracts (RAY-778 R1).

One pair of insoles is one device group: the left (master) and right (slave)
node each carry their own identity and firmware, and the pair carries an
institution-unique number and a size. Any ACTIVE terminal of the institution
registers, reports and retires pairs; the inventory belongs to the tenant,
never to a terminal.

Merge rule (R1): every report group (``state``, ``left`` battery, ``right``
battery) is merged independently and keeps the reading with the newer
device-side time. A reading whose time equals the stored one is not applied,
so the first stored reading wins a tie and a resent report changes nothing.

Download (R1): a pair is never deleted. Retirement is a state, so a retired
pair is delivered by the incremental download like any other change.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
import re
from typing import Annotated, Final
from uuid import UUID

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from .cloud import ContractModel
from .terminal_access import TerminalName

INSOLE_CURSOR_SCHEMA: Final = "insole-cursor/1"
INSOLE_PAGE_DEFAULT_LIMIT: Final = 100
INSOLE_PAGE_MAX_LIMIT: Final = 500
# A device-side time later than server time plus this skew is rejected, so a
# terminal with a fast clock cannot pin a reading that no later one can beat.
INSOLE_READING_MAX_FUTURE_SKEW_SECONDS: Final = 300
# A MAC identity must be in this one canonical form, so the same device can
# never be registered twice under spellings that compare unequal.
INSOLE_MAC_PATTERN: Final = r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$"

InstitutionNumber = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=32),
]
IdentityValue = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=64),
]
IdentityProvenance = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=64),
]
FirmwareVersion = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=64),
]
InsoleSize = Annotated[int, Field(ge=1, le=99)]
BatteryMillivolts = Annotated[int, Field(ge=0, le=10000)]
BatteryPercent = Annotated[int, Field(ge=0, le=100)]


class InsoleIdentityKind(StrEnum):
    MAC = "mac"
    SERIAL = "serial"


class InsoleState(StrEnum):
    AVAILABLE = "available"
    IN_USE = "in_use"
    UNRETURNED_DATA = "unreturned_data"
    RETIRED = "retired"


class ReportedInsoleState(StrEnum):
    """States a report may set; ``retired`` is reached only by the retire route."""

    AVAILABLE = "available"
    IN_USE = "in_use"
    UNRETURNED_DATA = "unreturned_data"


class InsoleIdentity(ContractModel):
    """A node identity; it identifies the device and never authenticates it.

    ``kind`` + ``value`` name the device and are compared exactly as sent;
    ``provenance`` records how the value was derived and is not compared. A
    ``mac`` value must be uppercase hex octets joined by colons.
    """

    kind: InsoleIdentityKind
    value: IdentityValue
    provenance: IdentityProvenance

    @model_validator(mode="after")
    def canonical_mac(self) -> InsoleIdentity:
        if self.kind is InsoleIdentityKind.MAC and not re.fullmatch(
            INSOLE_MAC_PATTERN, self.value
        ):
            raise ValueError("mac value must look like AA:BB:CC:DD:EE:FF")
        return self


class InsoleNodeRegistration(ContractModel):
    identity: InsoleIdentity
    firmware_version: FirmwareVersion | None = None


class InsoleRegistrationRequest(ContractModel):
    institution_number: InstitutionNumber
    size: InsoleSize
    left: InsoleNodeRegistration
    right: InsoleNodeRegistration

    @model_validator(mode="after")
    def distinct_nodes(self) -> InsoleRegistrationRequest:
        left, right = self.left.identity, self.right.identity
        if (left.kind, left.value) == (right.kind, right.value):
            raise ValueError("left and right must be different devices")
        return self


class BatteryReading(ContractModel):
    """One side's battery reading; ``read_at`` is the device-side reading time.

    ``millivolts`` is the raw value so a later discharge curve can recompute
    ``percent``; the percent is the reporting client's conversion.
    """

    millivolts: BatteryMillivolts
    percent: BatteryPercent
    read_at: AwareDatetime


class InsoleStateReport(ContractModel):
    state: ReportedInsoleState
    observed_at: AwareDatetime


class InsoleReportRequest(ContractModel):
    """Any non-empty subset of the three independently merged groups."""

    state: InsoleStateReport | None = None
    left: BatteryReading | None = None
    right: BatteryReading | None = None

    @model_validator(mode="after")
    def not_empty(self) -> InsoleReportRequest:
        if self.state is None and self.left is None and self.right is None:
            raise ValueError("a report must carry state, left or right")
        return self


class StoredBatteryReading(ContractModel):
    millivolts: BatteryMillivolts
    percent: BatteryPercent
    read_at: datetime
    reported_by_client_installation_id: UUID


class InsoleNode(ContractModel):
    identity: InsoleIdentity
    firmware_version: FirmwareVersion | None = None
    battery: StoredBatteryReading | None = None


class InsoleHolder(ContractModel):
    """The terminal using the pair; present exactly while ``state`` is ``in_use``.

    ``terminal_name`` is the holder's name when it reported ``in_use``.
    """

    client_installation_id: UUID
    terminal_name: TerminalName


class InsoleRecord(ContractModel):
    insole_id: UUID
    institution_number: InstitutionNumber
    size: InsoleSize
    left: InsoleNode
    right: InsoleNode
    state: InsoleState
    # Device-side time of the stored state; null until the first state report.
    state_observed_at: datetime | None = None
    holder: InsoleHolder | None = None
    registered_at: datetime
    registered_by_client_installation_id: UUID
    retired_at: datetime | None = None
    retired_by_client_installation_id: UUID | None = None
    # Tenant-wide, strictly increasing change sequence; the download cursor.
    revision: Annotated[int, Field(gt=0)]
    # Server time of the last change; informational, never a cursor.
    updated_at: datetime


class InsoleRegistrationResponse(ContractModel):
    insole: InsoleRecord
    idempotent_replay: bool


class InsoleReportApplied(ContractModel):
    state: bool
    left: bool
    right: bool


class InsoleReportResponse(ContractModel):
    insole: InsoleRecord
    applied: InsoleReportApplied


class InsoleRetireResponse(ContractModel):
    insole: InsoleRecord
    idempotent_replay: bool


class InsoleChangesResponse(ContractModel):
    """One page of changes ordered by ``revision``.

    Pass ``next_cursor`` back as ``cursor``; it is returned on every page, also
    the last one, and is opaque. ``has_more`` says whether to fetch again now.
    """

    items: tuple[InsoleRecord, ...]
    next_cursor: str
    has_more: bool


__all__ = [
    "BatteryReading",
    "INSOLE_CURSOR_SCHEMA",
    "INSOLE_MAC_PATTERN",
    "INSOLE_PAGE_DEFAULT_LIMIT",
    "INSOLE_PAGE_MAX_LIMIT",
    "INSOLE_READING_MAX_FUTURE_SKEW_SECONDS",
    "InsoleChangesResponse",
    "InsoleHolder",
    "InsoleIdentity",
    "InsoleIdentityKind",
    "InsoleNode",
    "InsoleNodeRegistration",
    "InsoleRecord",
    "InsoleRegistrationRequest",
    "InsoleRegistrationResponse",
    "InsoleReportApplied",
    "InsoleReportRequest",
    "InsoleReportResponse",
    "InsoleRetireResponse",
    "InsoleState",
    "InsoleStateReport",
    "ReportedInsoleState",
    "StoredBatteryReading",
]
