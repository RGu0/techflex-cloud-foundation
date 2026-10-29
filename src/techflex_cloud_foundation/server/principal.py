"""Narrow data-plane principal independent of credential implementation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from techflex_cloud_foundation.platform_errors import AuthenticationError, TenantAccessDenied
from techflex_cloud_foundation.server.access_auth import TenantAccessContext, TerminalAccessContext
from techflex_cloud_foundation.server.auth import TerminalContext


@dataclass(frozen=True, slots=True)
class IngestionPrincipal:
    tenant_id: UUID
    terminal_id: UUID
    expires_at: datetime
    allow_new_test: bool
    allow_upload: bool
    account_id: UUID | None = None
    license_id: UUID | None = None
    hardware_id: str | None = None
    # RAY-728: an activated institutional terminal (`feetforceplate-terminal`
    # token) rather than a hardware-bound tenant or legacy terminal principal.
    terminal_access: bool = False

    def ensure_active(self, now: datetime | None = None) -> None:
        if self.expires_at <= (now or datetime.now(UTC)):
            raise AuthenticationError("数据访问凭据已过期")

    def ensure_can_start_new(self, now: datetime | None = None) -> None:
        self.ensure_active(now)
        if not self.allow_new_test:
            raise TenantAccessDenied("当前 License 不允许开始新检测")

    def ensure_can_upload(self, now: datetime | None = None) -> None:
        self.ensure_active(now)
        if not self.allow_upload:
            raise TenantAccessDenied("当前会话不允许上传")


def tenant_ingestion_principal(context: TenantAccessContext) -> IngestionPrincipal:
    return IngestionPrincipal(
        tenant_id=context.tenant_id,
        terminal_id=context.client_installation_id,
        expires_at=context.expires_at,
        allow_new_test=context.capabilities.allow_new_test,
        allow_upload=context.capabilities.allow_upload,
        account_id=context.account_id,
        license_id=context.license_id,
        hardware_id=context.hardware_id,
    )


def terminal_access_principal(
    context: TerminalAccessContext, *, license_id: UUID, allow_new_test: bool
) -> IngestionPrincipal:
    # The caller's current License decides allow_new_test on every request;
    # uploading already captured data stays allowed (RAY-728 D6).
    return IngestionPrincipal(
        tenant_id=context.tenant_id,
        terminal_id=context.client_installation_id,
        expires_at=context.expires_at,
        allow_new_test=allow_new_test,
        allow_upload=True,
        account_id=context.account_id,
        license_id=license_id,
        terminal_access=True,
    )


def legacy_terminal_principal(context: TerminalContext) -> IngestionPrincipal:
    return IngestionPrincipal(
        tenant_id=context.tenant_id,
        terminal_id=context.terminal_id,
        expires_at=context.expires_at,
        allow_new_test=True,
        allow_upload=True,
    )


def coerce_ingestion_principal(
    context: IngestionPrincipal | TerminalContext,
) -> IngestionPrincipal:
    if isinstance(context, IngestionPrincipal):
        return context
    if isinstance(context, TerminalContext):
        return legacy_terminal_principal(context)
    raise TypeError("unsupported ingestion principal")


__all__ = [
    "IngestionPrincipal",
    "coerce_ingestion_principal",
    "legacy_terminal_principal",
    "tenant_ingestion_principal",
    "terminal_access_principal",
]
