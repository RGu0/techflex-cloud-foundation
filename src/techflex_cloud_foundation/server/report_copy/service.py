"""Local-basic cloud-copy access with live hold checks and redacted audit."""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID

from techflex_cloud_foundation.platform_errors import TenantAccessDenied


class LocalBasicCopyService:
    def __init__(self, repository: Any, holds: Any) -> None:
        self._repository = repository
        self._holds = holds

    async def accept(self, context: Any, request: Any, idempotency_key: str) -> Any:
        return await self._repository.accept(context, request, idempotency_key)

    async def list_for_tenant(self, tenant_id: UUID, actor_id: UUID) -> tuple[Any, ...]:
        rows = await self._repository.list_for_tenant(tenant_id)
        visible = []
        for row in rows:
            if row.tenant_id != tenant_id:
                raise TenantAccessDenied("report tenant binding mismatch")
            if not await self._holds.is_held(tenant_id, row.session_id):
                visible.append(row)
        await self._repository.audit_access(
            tenant_id,
            None,
            actor_id,
            "report-copy.list",
            "ALLOWED",
        )
        return tuple(visible)

    async def get(self, tenant_id: UUID, actor_id: UUID, report_id: str) -> Any:
        row = await self._repository.get(tenant_id, report_id)
        if row.tenant_id != tenant_id:
            raise TenantAccessDenied("report tenant binding mismatch")
        if await self._holds.is_held(tenant_id, row.session_id):
            await self._repository.audit_access(
                tenant_id,
                row.session_id,
                actor_id,
                "report-copy.read",
                "DENIED",
            )
            raise TenantAccessDenied("report session is held")
        await self._repository.audit_access(
            tenant_id,
            row.session_id,
            actor_id,
            "report-copy.read",
            "ALLOWED",
        )
        return row

    async def export_pdf(self, tenant_id: UUID, actor_id: UUID, report_id: str) -> bytes:
        row = await self._repository.get(tenant_id, report_id)
        if row.tenant_id != tenant_id:
            raise TenantAccessDenied("report tenant binding mismatch")
        if await self._holds.is_held(tenant_id, row.session_id):
            await self._repository.audit_access(
                tenant_id,
                row.session_id,
                actor_id,
                "report-copy.export",
                "DENIED",
            )
            raise TenantAccessDenied("report session is held")
        payload = await self._repository.read_pdf(row)
        await self._repository.audit_access(
            tenant_id,
            row.session_id,
            actor_id,
            "report-copy.export",
            "ALLOWED",
        )
        return cast(bytes, payload)
