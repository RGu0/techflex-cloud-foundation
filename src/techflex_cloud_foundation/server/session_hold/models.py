from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class HoldApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    session_id: UUID
    ticket_reference: str
    reason_code: Literal["IDENTITY_UNVERIFIED"]


class HoldApplyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ticket_reference: str
    reason_code: Literal["IDENTITY_UNVERIFIED"]


class HoldDispositionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    session_id: UUID
    ticket_reference: str
    decision_code: Literal["RETAIN_WITH_VALID_BASIS", "RESTRICT_AND_DISPOSE"]
    evidence_reference: str
    valid_basis_reference: str | None = None
    retention_policy_id: UUID | None = None


class HoldDispositionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ticket_reference: str
    decision_code: Literal["RETAIN_WITH_VALID_BASIS", "RESTRICT_AND_DISPOSE"]
    evidence_reference: str
    valid_basis_reference: str | None = None
    retention_policy_id: UUID | None = None


class HoldReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    session_id: UUID
    ticket_reference: str
    evidence_reference: str


class HoldReleaseBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ticket_reference: str
    evidence_reference: str


@dataclass(frozen=True, slots=True)
class SessionHoldRecord:
    hold_id: UUID
    tenant_id: UUID
    session_id: UUID
    state: Literal["HELD", "RELEASED"]
    reason_code: str
    applied_at: datetime


@dataclass(frozen=True, slots=True)
class SessionHoldStatus:
    held: bool
    hold_id: UUID | None = None
    state: str | None = None


@dataclass(frozen=True, slots=True)
class HoldDispositionResult:
    disposition_id: UUID
    hold_id: UUID
    decision_code: str
    state: Literal["HELD"]
    planned_job_id: UUID | None = None
    planned_job_status: Literal["PLANNED"] | None = None
