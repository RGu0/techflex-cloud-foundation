from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.platform_errors import RequestContractError, TenantAccessDenied
from techflex_cloud_foundation.server.access_auth import PlatformAccessContext

from .models import (
    HoldApplyRequest,
    HoldDispositionRequest,
    HoldDispositionResult,
    HoldReleaseRequest,
    SessionHoldRecord,
    SessionHoldStatus,
)
from .repository import SessionHoldRepository


class SessionHeld(Exception):
    """A held session cannot produce new analysis or reports."""


class SessionHoldService:
    def __init__(self, repository: SessionHoldRepository) -> None:
        self.repository = repository

    @staticmethod
    def _require_operator(context: PlatformAccessContext) -> None:
        if not context.roles.intersection({PlatformRole.OWNER, PlatformRole.SUPPORT}):
            raise TenantAccessDenied("platform hold role required")

    @staticmethod
    def _require_reference(value: str, label: str) -> None:
        if not value.strip() or len(value) > 256:
            raise RequestContractError(f"{label} required")

    @staticmethod
    def _require_idempotency_key(value: str) -> None:
        if not value.strip() or len(value) > 128:
            raise RequestContractError("idempotency key required")

    @staticmethod
    def _digest(action: str, request: Any) -> str:
        return hashlib.sha256(
            f"{action}:".encode("ascii") + request.model_dump_json().encode("utf-8")
        ).hexdigest()

    async def apply(
        self, context: PlatformAccessContext, request: HoldApplyRequest, idempotency_key: str
    ) -> SessionHoldRecord:
        self._require_operator(context)
        self._require_reference(request.ticket_reference, "incident ticket")
        self._require_idempotency_key(idempotency_key)
        # The ticket is retained only in the restricted audit ledger, never the response.
        digest = self._digest("apply", request)
        return await self.repository.apply(
            request,
            actor_id=context.platform_identity_id,
            idempotency_key=idempotency_key,
            request_sha256=digest,
        )

    async def status(
        self, context: PlatformAccessContext, tenant_id: UUID, session_id: UUID
    ) -> SessionHoldStatus:
        self._require_operator(context)
        return await self.repository.status(tenant_id, session_id)

    async def dispose(
        self, context: PlatformAccessContext, request: HoldDispositionRequest, idempotency_key: str
    ) -> HoldDispositionResult:
        self._require_operator(context)
        self._require_reference(request.ticket_reference, "incident ticket")
        self._require_reference(request.evidence_reference, "evidence reference")
        self._require_idempotency_key(idempotency_key)
        if request.decision_code == "RETAIN_WITH_VALID_BASIS":
            self._require_reference(request.valid_basis_reference or "", "valid basis reference")
            if request.retention_policy_id is not None:
                raise RequestContractError("retention policy belongs only to restriction")
        elif request.retention_policy_id is None or request.valid_basis_reference is not None:
            raise RequestContractError("approved retention policy required")
        return await self.repository.dispose(
            request,
            actor_id=context.platform_identity_id,
            idempotency_key=idempotency_key,
            request_sha256=self._digest("dispose", request),
        )

    async def release(
        self, context: PlatformAccessContext, request: HoldReleaseRequest, idempotency_key: str
    ) -> SessionHoldRecord:
        self._require_operator(context)
        self._require_reference(request.ticket_reference, "incident ticket")
        self._require_reference(request.evidence_reference, "evidence reference")
        self._require_idempotency_key(idempotency_key)
        return await self.repository.release(
            request,
            actor_id=context.platform_identity_id,
            idempotency_key=idempotency_key,
            request_sha256=self._digest("release", request),
        )
