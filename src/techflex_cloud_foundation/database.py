"""Server-only database lifecycle protocols without application schema ownership."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class TransactionScope(Protocol):
    async def __aenter__(self) -> object: ...

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None: ...


class HealthProbe(Protocol):
    async def ready(self) -> bool: ...


class _Pool(Protocol):
    async def close(self) -> None: ...


@dataclass(slots=True)
class DatabaseRuntime:
    """Own one server-side pool; repositories own SQL and transaction contents."""

    pool: _Pool
    health: HealthProbe

    async def close(self) -> None:
        await self.pool.close()
