"""Terminal diagnostic package upload, platform support access and purge.

RAY-802 R1. Any ACTIVE terminal uploads its own export; the package belongs
to the terminal's tenant. Only PLATFORM_SUPPORT and PLATFORM_ENGINEER may
list or read packages, each time with a ticket reference, and every list,
read and denial is appended to the access audit before anything is
returned. No terminal or tenant credential has a read path.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.contracts.terminal_access import TerminalState
from techflex_cloud_foundation.contracts.terminal_diagnostics import (
    DIAGNOSTICS_FORMAT,
    DIAGNOSTICS_MAX_BYTES,
    DIAGNOSTICS_RETENTION_DAYS,
    DiagnosticListResponse,
    DiagnosticSummary,
    DiagnosticUploadResponse,
)
from techflex_cloud_foundation.platform_errors import (
    DiagnosticContentRejected,
    DiagnosticDigestMismatch,
    DiagnosticTooLarge,
    IdempotencyConflict,
    PlatformError,
    ResourceNotFound,
    TerminalRevoked,
)
from techflex_cloud_foundation.server.access_auth import (
    PlatformAccessContext,
    TerminalAccessContext,
)
from techflex_cloud_foundation.server.access_control.platform_iam import PlatformPermissionDenied
from techflex_cloud_foundation.server.access_control.repository import (
    AccessRepositoryError,
    AuditEventRecord,
    TerminalRecord,
)

from .repository import DiagnosticRecord, DiagnosticRepository, diagnostic_object_key
from .validation import DiagnosticRejection, validate_package

_TICKET_MAX_LENGTH = 256


@dataclass(frozen=True, slots=True)
class NonPlatformCaller:
    """A valid terminal or tenant credential presented to a support route.

    It is never authorised; it exists so the denial can name its actor.
    """

    kind: Literal["terminal", "tenant"]
    actor_id: UUID


SupportCaller = PlatformAccessContext | NonPlatformCaller


class TerminalDiagnosticsService:
    SUPPORT_ROLES = frozenset({PlatformRole.SUPPORT, PlatformRole.ENGINEER})
    _RETENTION = timedelta(days=DIAGNOSTICS_RETENTION_DAYS)

    def __init__(
        self,
        repository: DiagnosticRepository,
        objects: Any,
        access: Any,
        *,
        now: Any = None,
    ) -> None:
        self._repository = repository
        # put_diagnostic / read_diagnostic / delete of an ObjectStore.
        self._objects = objects
        # ``terminal``, ``tenant`` and ``append_audit`` of the access repository.
        self._access = access
        self._now = now or (lambda: datetime.now(UTC))

    async def _caller(self, context: TerminalAccessContext) -> TerminalRecord:
        terminal = await self._access.terminal(context.client_installation_id)
        if (
            terminal is None
            or terminal.tenant_id != context.tenant_id
            or terminal.account_id != context.account_id
            or terminal.status != TerminalState.ACTIVE.value
        ):
            raise TerminalRevoked("terminal was revoked")
        return cast(TerminalRecord, terminal)

    async def upload(
        self,
        context: TerminalAccessContext,
        body: AsyncIterable[bytes],
        *,
        declared_length: int | None,
        content_sha256: str,
        idempotency_key: str,
    ) -> tuple[DiagnosticUploadResponse, bool]:
        """Return the stored package and whether this request created it.

        The terminal is checked before the body is read; a declared length
        over the limit is refused unread, and reading stops at the limit.
        """

        caller = await self._caller(context)
        too_large = DiagnosticTooLarge(
            "diagnostic package exceeds the size limit", max_bytes=DIAGNOSTICS_MAX_BYTES
        )
        if declared_length is not None and declared_length > DIAGNOSTICS_MAX_BYTES:
            raise too_large
        buffer = bytearray()
        async for chunk in body:
            if len(buffer) + len(chunk) > DIAGNOSTICS_MAX_BYTES:
                raise too_large
            buffer.extend(chunk)
        payload = bytes(buffer)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != content_sha256:
            raise DiagnosticDigestMismatch("X-Content-SHA256 does not match the body")
        previous = await self._repository.by_key(
            caller.tenant_id, caller.client_installation_id, idempotency_key
        )
        if previous is not None:
            return self._replay(previous, digest), False
        try:
            # Up to 8 MiB of parsing and screening: off the event loop.
            await asyncio.to_thread(
                validate_package,
                payload,
                tenant_id=caller.tenant_id,
                client_installation_id=caller.client_installation_id,
            )
        except DiagnosticRejection as rejection:
            raise DiagnosticContentRejected(
                "diagnostic package rejected",
                line=rejection.line,
                reason=rejection.reason.value,
            ) from None
        now = self._now()
        diagnostic_id = uuid4()
        record = DiagnosticRecord(
            diagnostic_id=diagnostic_id,
            tenant_id=caller.tenant_id,
            client_installation_id=caller.client_installation_id,
            idempotency_key=idempotency_key,
            format=DIAGNOSTICS_FORMAT,
            size_bytes=len(payload),
            sha256=digest,
            object_key=diagnostic_object_key(caller.tenant_id, diagnostic_id),
            received_at=now,
            expires_at=now + self._RETENTION,
        )
        # Content first: a record never names an object that is not there.
        await self._objects.put_diagnostic(record.object_key, payload)
        try:
            stored = await self._repository.insert(record)
        except Exception:
            # Delete only content no committed record names.
            committed = await self._repository.by_key(
                caller.tenant_id, caller.client_installation_id, idempotency_key
            )
            if committed is None or committed.diagnostic_id != diagnostic_id:
                await self._objects.delete(record.object_key)
            raise
        if stored.diagnostic_id != diagnostic_id:
            # A concurrent request with the same key stored first.
            await self._objects.delete(record.object_key)
            return self._replay(stored, digest), False
        return _upload_response(stored), True

    @staticmethod
    def _replay(record: DiagnosticRecord, digest: str) -> DiagnosticUploadResponse:
        if record.sha256 != digest:
            raise IdempotencyConflict("Idempotency-Key was used for a different package")
        return _upload_response(record)

    async def list(
        self, caller: SupportCaller, tenant_id: UUID, ticket_reference: str | None
    ) -> DiagnosticListResponse:
        context, ticket = await self._authorize(caller, tenant_id, ticket_reference, None)
        records = await self._repository.list(tenant_id)
        await self._audit(
            context, "diagnostics.list", tenant_id, None,
            ticket_reference=ticket, count=str(len(records)),
        )
        return DiagnosticListResponse(items=tuple(_summary(record) for record in records))

    async def read(
        self,
        caller: SupportCaller,
        tenant_id: UUID,
        diagnostic_id: UUID,
        ticket_reference: str | None,
    ) -> tuple[DiagnosticRecord, bytes]:
        context, ticket = await self._authorize(
            caller, tenant_id, ticket_reference, diagnostic_id
        )
        record = await self._repository.get(tenant_id, diagnostic_id)
        reason = None
        if record is None:
            reason = "not_found"
        elif record.deleted_at is not None:
            reason = "deleted"
        elif record.expires_at <= self._now():
            reason = "expired"
        if reason is not None:
            await self._deny(caller, tenant_id, diagnostic_id, reason, ticket_reference=ticket)
            raise ResourceNotFound("diagnostic package does not exist")
        assert record is not None
        try:
            payload = await self._objects.read_diagnostic(record.object_key)
            if (
                len(payload) != record.size_bytes
                or hashlib.sha256(payload).hexdigest() != record.sha256
            ):
                raise PlatformError("stored diagnostic package does not match its record")
        except Exception:
            # The attempt is audited even though nothing is returned.
            await self._audit(
                context, "diagnostics.read_failed", tenant_id, diagnostic_id,
                ticket_reference=ticket,
            )
            raise
        await self._audit(
            context, "diagnostics.read", tenant_id, diagnostic_id, ticket_reference=ticket
        )
        return record, payload

    async def purge(self) -> int:
        """Delete the content of every expired package; keep its tombstone.

        Content goes first, so an interrupted purge leaves a record whose
        content is already gone; the next run deletes again and marks it.
        """

        now = self._now()
        expired = await self._repository.expired(now)
        for record in expired:
            await self._objects.delete(record.object_key)
            await self._repository.mark_deleted(record.tenant_id, record.diagnostic_id, now)
        return len(expired)

    async def _authorize(
        self,
        caller: SupportCaller,
        tenant_id: UUID,
        ticket_reference: str | None,
        diagnostic_id: UUID | None,
    ) -> tuple[PlatformAccessContext, str]:
        ticket = (ticket_reference or "").strip()
        reason = None
        if isinstance(caller, NonPlatformCaller):
            reason = f"{caller.kind}_credential"
        elif caller.expires_at <= self._now():
            reason = "context_inactive"
        elif not caller.roles & self.SUPPORT_ROLES:
            reason = "role_unauthorized"
        elif not ticket or len(ticket) > _TICKET_MAX_LENGTH:
            reason = "ticket_missing"
        if reason is not None:
            await self._deny(
                caller, tenant_id, diagnostic_id, reason,
                ticket_reference=ticket if 0 < len(ticket) <= _TICKET_MAX_LENGTH else None,
            )
            raise PlatformPermissionDenied("platform role cannot read diagnostic packages")
        assert isinstance(caller, PlatformAccessContext)
        if not await self._tenant_exists(tenant_id):
            await self._deny(
                caller, tenant_id, diagnostic_id, "tenant_unknown", ticket_reference=ticket
            )
            raise ResourceNotFound("tenant does not exist")
        return caller, ticket

    async def _deny(
        self,
        caller: SupportCaller,
        tenant_id: UUID,
        diagnostic_id: UUID | None,
        reason: str,
        *,
        ticket_reference: str | None,
    ) -> None:
        details = {"reason": reason}
        if ticket_reference is not None:
            details["ticket_reference"] = ticket_reference
        await self._audit(caller, "diagnostics.deny", tenant_id, diagnostic_id, **details)

    async def _tenant_exists(self, tenant_id: UUID) -> bool:
        try:
            await self._access.tenant(tenant_id)
        except AccessRepositoryError:
            return False
        return True

    async def _audit(
        self,
        caller: SupportCaller,
        action: str,
        tenant_id: UUID,
        diagnostic_id: UUID | None,
        **details: str,
    ) -> None:
        if isinstance(caller, NonPlatformCaller):
            actor_id = caller.actor_id
            details["actor_kind"] = caller.kind
        else:
            actor_id = caller.platform_identity_id
            details["actor_kind"] = "platform"
            details["roles"] = ",".join(sorted(role.value for role in caller.roles))
        # The audit references iam.tenants; an unknown tenant is kept as text.
        audited_tenant: UUID | None = tenant_id
        if not await self._tenant_exists(tenant_id):
            audited_tenant = None
            details["requested_tenant_id"] = str(tenant_id)
        await self._access.append_audit(
            AuditEventRecord(
                event_id=uuid4(),
                actor_id=actor_id,
                action=action,
                tenant_id=audited_tenant,
                resource_id=diagnostic_id,
                occurred_at=self._now(),
                details=tuple(sorted(details.items())),
            )
        )


def _upload_response(record: DiagnosticRecord) -> DiagnosticUploadResponse:
    return DiagnosticUploadResponse(
        diagnostic_id=record.diagnostic_id,
        format=record.format,
        size_bytes=record.size_bytes,
        sha256=record.sha256,
        received_at=record.received_at,
        expires_at=record.expires_at,
    )


def _summary(record: DiagnosticRecord) -> DiagnosticSummary:
    return DiagnosticSummary(
        diagnostic_id=record.diagnostic_id,
        client_installation_id=record.client_installation_id,
        format=record.format,
        size_bytes=record.size_bytes,
        sha256=record.sha256,
        received_at=record.received_at,
        expires_at=record.expires_at,
        deleted_at=record.deleted_at,
    )


__all__ = ["NonPlatformCaller", "SupportCaller", "TerminalDiagnosticsService"]
