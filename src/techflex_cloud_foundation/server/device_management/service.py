from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import hashlib
import hmac
from typing import Any, cast
from uuid import UUID

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatRequest,
    HeartbeatResponse,
)
from techflex_cloud_foundation.platform_errors import TenantAccessDenied
from techflex_cloud_foundation.server.auth import TerminalContext, TerminalTokenIssuer


class DeviceManagementService:
    def __init__(
        self,
        repository: Any,
        token_issuer: TerminalTokenIssuer,
        *,
        activation_code_hmac_key: bytes,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if len(activation_code_hmac_key) < 32:
            raise ValueError("activation-code HMAC key must contain at least 32 bytes")
        self._repository = repository
        self._token_issuer = token_issuer
        self._activation_code_hmac_key = activation_code_hmac_key
        self._now = now or (lambda: datetime.now(UTC))

    def hash_activation_code(self, activation_code: str) -> bytes:
        normalized = activation_code.strip().encode("utf-8")
        return hmac.new(
            self._activation_code_hmac_key,
            normalized,
            hashlib.sha256,
        ).digest()

    async def enroll(
        self,
        request: EnrollmentRequest,
        idempotency_key: str,
    ) -> EnrollmentResponse:
        accepted_at = self._now()
        binding = await self._repository.consume_activation_code(
            self.hash_activation_code(request.activation_code),
            request,
            canonical_sha256(request),
            idempotency_key,
            accepted_at,
        )
        token = self._token_issuer.issue(
            binding.tenant_id,
            binding.terminal_id,
            now=accepted_at,
        )
        context = self._token_issuer.verify(token, now=accepted_at)
        return EnrollmentResponse(
            tenant_id=binding.tenant_id,
            site_id=binding.site_id,
            terminal_id=binding.terminal_id,
            status=binding.status,
            access_token=token,
            token_expires_at=context.expires_at,
            config_version=binding.config_version,
        )

    async def record_heartbeat(
        self,
        context: TerminalContext,
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
