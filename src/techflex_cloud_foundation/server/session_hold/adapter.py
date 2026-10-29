"""Fresh authoritative hold check for asynchronous workers with sync domain services."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar
from uuid import UUID

from techflex_cloud_foundation.platform_errors import RequestContractError

from .service import SessionHeld

T = TypeVar("T")


class AsyncHoldRepository(Protocol):
    async def is_held(self, tenant_id: UUID, session_id: UUID) -> bool: ...


@dataclass(frozen=True, slots=True)
class CheckedSessionHoldReader:
    """A one-call reader bound to the event/report tenant and session."""

    tenant_id: UUID
    session_id: UUID

    def is_held(self, tenant_id: UUID | str, session_id: UUID | str) -> bool:
        if str(tenant_id) != str(self.tenant_id) or str(session_id) != str(self.session_id):
            raise RequestContractError("hold check session binding mismatch")
        return False


async def run_with_current_hold(
    holds: AsyncHoldRepository,
    tenant_id: UUID | str,
    session_id: UUID | str,
    operation: Callable[[CheckedSessionHoldReader], T],
) -> T:
    """Query PostgreSQL immediately before invoking a synchronous consumer.

    No await separates the authoritative result from `operation`. Production
    workers must call this for each queued event or report publication, not
    retain a previous unheld reader across events.
    """

    try:
        tenant, session = UUID(str(tenant_id)), UUID(str(session_id))
    except ValueError as exc:
        raise RequestContractError("invalid hold check session binding") from exc
    if await holds.is_held(tenant, session):
        raise SessionHeld("session is under administrative hold")
    return operation(CheckedSessionHoldReader(tenant, session))
