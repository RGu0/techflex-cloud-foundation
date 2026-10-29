from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from techflex_cloud_foundation.contracts.identity_recovery import RecoveryCaseCreateRequest


@dataclass(frozen=True, slots=True)
class RecoveryCaseRecord:
    case_id: UUID
    tenant_id: UUID
    terminal_id: UUID
    request: RecoveryCaseCreateRequest
    request_sha256: str
    key_sha256: str
    masked_clue: str | None
    status: str
    created_at: datetime
    attempts: int = 0
    receipt_id: UUID | None = None
    receipt_expires_at: datetime | None = None
    receipt_consumed_at: datetime | None = None
    ticket_sha256: str | None = None
