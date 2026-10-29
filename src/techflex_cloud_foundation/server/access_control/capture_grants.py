"""Issue opaque credentials for server-prebound future capture sessions."""

import hashlib
import secrets
from typing import Any, cast
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.contracts.capture_grants import (
    CaptureGrant,
    CaptureGrantBatchRequest,
    CaptureGrantBatchResponse,
    MigrationPermitResponse,
    RetireCaptureGrantRequest,
    UploadMigrationPermitRequest,
)
from techflex_cloud_foundation.platform_errors import TenantAccessDenied
from techflex_cloud_foundation.server.access_auth import PlatformAccessContext
from techflex_cloud_foundation.server.principal import IngestionPrincipal


class CaptureGrantService:
    def __init__(self, repository: Any) -> None:
        self._repository = repository

    async def approve_migration(
        self,
        context: PlatformAccessContext,
        request: UploadMigrationPermitRequest,
    ) -> MigrationPermitResponse:
        # Revalidate at the service boundary as internal callers can construct
        # models without validation. Never forward their unvalidated text to audit.
        request = UploadMigrationPermitRequest.model_validate(request.model_dump())
        decision = None
        if PlatformRole.OWNER not in context.roles:
            decision = "OWNER_REQUIRED"
        elif (
            request.identity_conflict
            and not await self._repository.validate_migration_reconciliation(request)
        ):
            decision = "RECONCILIATION_UNVERIFIABLE"
        elif not all(
            (
                request.local_valid_reviewed,
                request.immutable_manifest_reviewed,
                request.original_consent_reviewed,
                request.historical_authorization_reviewed,
            )
        ):
            decision = "REVIEW_INCOMPLETE"
        if decision is not None:
            await self._repository.audit_migration_denial(context, request, decision)
            raise TenantAccessDenied("migration approval requirements not satisfied")
        token = secrets.token_urlsafe(32)
        try:
            await self._repository.insert_migration_permit(
                context,
                request,
                hashlib.sha256(token.encode()).digest(),
            )
        except TenantAccessDenied:
            # Separate transaction survives rollback of rejected issuance.
            await self._repository.audit_migration_denial(
                context, request, "BINDING_OR_OWNER_REJECTED"
            )
            raise
        return MigrationPermitResponse(session_id=request.session_id, token=cast(Any, token))

    async def issue(self, context: IngestionPrincipal, count: int) -> CaptureGrantBatchResponse:
        context.ensure_can_start_new()
        count = CaptureGrantBatchRequest(count=count).count
        grants = tuple(
            CaptureGrant(session_id=uuid4(), token=cast(Any, secrets.token_urlsafe(32)))
            for _ in range(count)
        )
        return cast(
            CaptureGrantBatchResponse,
            await self._repository.issue_capture_grants(context, grants),
        )

    async def retire(self, context: IngestionPrincipal, session_id: UUID, reason: str) -> None:
        context.ensure_can_start_new()
        request = RetireCaptureGrantRequest(session_id=session_id, reason=reason)
        await self._repository.retire_capture_grant(context, request.session_id, request.reason)
