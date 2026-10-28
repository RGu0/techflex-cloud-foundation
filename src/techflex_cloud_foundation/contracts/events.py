from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import Field, StringConstraints

from .cloud import ContractModel


class EventEnvelope(ContractModel):
    event_id: UUID
    event_type: Annotated[str, StringConstraints(pattern=r"^[a-z]+(?:\.[a-z]+)+\.v[1-9][0-9]*$")]
    occurred_at: datetime
    producer: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    tenant_id: UUID
    aggregate_type: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    aggregate_id: UUID
    aggregate_version: Annotated[int, Field(gt=0)]
    correlation_id: UUID | None = None
    causation_id: UUID | None = None
    payload: dict[str, Any]
