"""Authenticated heartbeat service shared by legacy and License access tokens."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import HeartbeatRequest, HeartbeatResponse
from techflex_cloud_foundation.platform_errors import TenantAccessDenied
from techflex_cloud_foundation.server.auth import TerminalContext
from techflex_cloud_foundation.server.principal import IngestionPrincipal


class DeviceHeartbeatService:
    def __init__(self, repository: Any, *, now: Callable[[], datetime] | None = None) -> None:
        self._repository = repository
        self._now = now or (lambda: datetime.now(UTC))

    async def record_heartbeat(
        self,
        context: IngestionPrincipal | TerminalContext,
        terminal_id: UUID,
        request: HeartbeatRequest,
        idempotency_key: str,
    ) -> HeartbeatResponse:
        context.ensure_active(self._now())
        if context.terminal_id != terminal_id:
            raise TenantAccessDenied(
                "心跳路由终端与凭据不一致",
                terminal_id=str(terminal_id),
            )
        return cast(
            HeartbeatResponse,
            await self._repository.record_heartbeat(
                context,
                request,
                canonical_sha256(request),
                idempotency_key,
                self._now(),
            ),
        )


__all__ = ["DeviceHeartbeatService"]
