from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import secrets
from typing import Any, cast
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.contracts.device_policy import (
    LicenseDocument,
    LicenseStatus,
    SignedLicense,
)
from techflex_cloud_foundation.contracts.operations import (
    ActivationCodeIssueResponse,
    DataAccessCategory,
    DataAccessDecision,
    DataAccessRequest,
    DeviceRegistrationRequest,
    DeviceSummary,
    LicenseIssueRequest,
    LicenseRenewRequest,
    OperationsPermission,
    SiteCreateRequest,
    SiteSummary,
    TerminalDeviceBindingSummary,
    TerminalHealthSummary,
    UpgradePolicyRequest,
    UpgradePolicySummary,
)
from techflex_cloud_foundation.platform_errors import ResourceNotFound, TenantAccessDenied


@dataclass(frozen=True, slots=True)
class OperationsContext:
    actor_id: UUID
    tenant_id: UUID
    site_ids: frozenset[UUID]
    all_sites: bool
    permissions: frozenset[OperationsPermission]


_ACCESS_PERMISSION = {
    DataAccessCategory.RAW_DATA: OperationsPermission.RAW_DATA_ACCESS,
    DataAccessCategory.IDENTITY: OperationsPermission.IDENTITY_ACCESS,
    DataAccessCategory.LOGS: OperationsPermission.LOG_ACCESS,
    DataAccessCategory.DIAGNOSTICS: OperationsPermission.DIAGNOSTICS_ACCESS,
}


class OperationsService:
    def __init__(
        self,
        repository: Any,
        *,
        license_private_key: Ed25519PrivateKey,
        license_key_id: str,
        activation_code_hmac_key: bytes,
        now: Any = None,
    ) -> None:
        if len(activation_code_hmac_key) < 32:
            raise ValueError("activation-code HMAC key must contain at least 32 bytes")
        self._repository = repository
        self._license_private_key = license_private_key
        self._license_key_id = license_key_id
        self._activation_code_hmac_key = activation_code_hmac_key
        self._now = now or (lambda: datetime.now(UTC))

    def _deny(self, context: OperationsContext, message: str) -> None:
        self._repository.append_operations_audit(
            context.tenant_id,
            "operations.access.denied",
            "DENIED",
        )
        raise TenantAccessDenied(message)

    def _require(
        self,
        context: OperationsContext,
        permission: OperationsPermission,
        *,
        site_id: UUID | None = None,
    ) -> None:
        if permission not in context.permissions:
            self._deny(context, "运营权限不足")
        if site_id is not None and not context.all_sites and site_id not in context.site_ids:
            self._deny(context, "站点不在授权范围")

    def _terminal_site(self, context: OperationsContext, terminal_id: UUID) -> UUID | None:
        owner = self._repository.terminal_owner(terminal_id)
        if owner is None:
            raise ResourceNotFound("终端不存在")
        tenant_id, site_id = owner
        if tenant_id != context.tenant_id:
            self._deny(context, "终端不属于当前租户")
        return cast(UUID | None, site_id)

    def _audit(self, context: OperationsContext, action: str) -> None:
        self._repository.append_operations_audit(
            context.tenant_id,
            action,
            "ALLOWED",
        )

    async def create_site(
        self, context: OperationsContext, request: SiteCreateRequest
    ) -> SiteSummary:
        self._require(context, OperationsPermission.SITE_MANAGE)
        result = self._repository.create_site(context.tenant_id, request)
        self._audit(context, "site.create")
        return cast(SiteSummary, result)

    async def register_device(
        self, context: OperationsContext, request: DeviceRegistrationRequest
    ) -> DeviceSummary:
        self._require(context, OperationsPermission.DEVICE_MANAGE)
        result = self._repository.register_device(context.tenant_id, request)
        self._audit(context, "device.register")
        return cast(DeviceSummary, result)

    async def bind_device(
        self,
        context: OperationsContext,
        terminal_id: UUID,
        device_id: UUID,
    ) -> TerminalDeviceBindingSummary:
        site_id = self._terminal_site(context, terminal_id)
        self._require(context, OperationsPermission.DEVICE_MANAGE, site_id=site_id)
        if self._repository.device_owner(device_id) != context.tenant_id:
            self._deny(context, "设备不属于当前租户")
        result = self._repository.bind_terminal_device(
            context.tenant_id,
            terminal_id,
            device_id,
            self._now(),
        )
        self._audit(context, "terminal.device.bind")
        return cast(TerminalDeviceBindingSummary, result)

    async def set_terminal_status(
        self,
        context: OperationsContext,
        terminal_id: UUID,
        status: str,
    ) -> None:
        if status not in {"ACTIVE", "SUSPENDED", "REVOKED"}:
            raise ValueError("unsupported terminal status")
        site_id = self._terminal_site(context, terminal_id)
        self._require(context, OperationsPermission.TERMINAL_MANAGE, site_id=site_id)
        self._repository.set_terminal_status(context.tenant_id, terminal_id, status)
        self._audit(context, "terminal.status.change")

    def _activation_hash(self, code: str) -> bytes:
        return hmac.new(
            self._activation_code_hmac_key,
            code.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    async def issue_activation_code(
        self,
        context: OperationsContext,
        *,
        site_id: UUID | None,
        device_id: UUID | None,
        expires_at: datetime,
    ) -> ActivationCodeIssueResponse:
        self._require(context, OperationsPermission.ACTIVATION_MANAGE, site_id=site_id)
        if expires_at <= self._now():
            raise ValueError("activation code expiry must be in the future")
        if device_id is not None and self._repository.device_owner(device_id) != context.tenant_id:
            self._deny(context, "设备不属于当前租户")
        code = secrets.token_urlsafe(24)
        enrollment_code_id = uuid4()
        self._repository.add_activation_code_hash(
            self._activation_hash(code),
            tenant_id=context.tenant_id,
            site_id=site_id,
            device_id=device_id,
            expires_at=expires_at,
            enrollment_code_id=enrollment_code_id,
        )
        self._audit(context, "activation_code.issue")
        return ActivationCodeIssueResponse(
            enrollment_code_id=enrollment_code_id,
            site_id=site_id,
            device_id=device_id,
            activation_code=code,
            expires_at=expires_at,
        )

    def _sign(self, document: LicenseDocument) -> SignedLicense:
        signature = self._license_private_key.sign(canonical_json_bytes(document))
        return SignedLicense(
            document=document,
            key_id=self._license_key_id,
            signature=base64.b64encode(signature).decode("ascii"),
        )

    async def issue_license(
        self,
        context: OperationsContext,
        request: LicenseIssueRequest,
    ) -> SignedLicense:
        site_id = self._terminal_site(context, request.terminal_id)
        self._require(context, OperationsPermission.LICENSE_MANAGE, site_id=site_id)
        if request.site_id != site_id:
            self._deny(context, "License 站点与终端不一致")
        document = LicenseDocument(
            license_id=uuid4(),
            license_version=1,
            tenant_id=context.tenant_id,
            site_id=site_id,
            terminal_id=request.terminal_id,
            status=LicenseStatus.ACTIVE,
            enabled_features=request.enabled_features,
            issued_at=self._now(),
            not_before=request.not_before,
            expires_at=request.expires_at,
        )
        bundle = self._sign(document)
        self._repository.store_license_version(context.tenant_id, bundle)
        self._audit(context, "license.issue")
        return bundle

    async def renew_license(
        self,
        context: OperationsContext,
        license_id: UUID,
        request: LicenseRenewRequest,
    ) -> SignedLicense:
        current = self._repository.latest_license(context.tenant_id, license_id)
        site_id = self._terminal_site(context, current.document.terminal_id)
        self._require(context, OperationsPermission.LICENSE_MANAGE, site_id=site_id)
        if request.expires_at <= current.document.expires_at:
            raise ValueError("renewal expiry must extend the current License")
        document = current.document.model_copy(
            update={
                "license_version": current.document.license_version + 1,
                "status": LicenseStatus.ACTIVE,
                "enabled_features": request.enabled_features or current.document.enabled_features,
                "issued_at": self._now(),
                "expires_at": request.expires_at,
            }
        )
        bundle = self._sign(document)
        self._repository.store_license_version(context.tenant_id, bundle)
        self._audit(context, "license.renew")
        return bundle

    async def revoke_license(
        self,
        context: OperationsContext,
        license_id: UUID,
        *,
        reason_code: str,
    ) -> SignedLicense:
        if not reason_code or len(reason_code) > 64:
            raise ValueError("revocation reason code is required")
        current = self._repository.latest_license(context.tenant_id, license_id)
        site_id = self._terminal_site(context, current.document.terminal_id)
        self._require(context, OperationsPermission.LICENSE_MANAGE, site_id=site_id)
        document = current.document.model_copy(
            update={
                "license_version": current.document.license_version + 1,
                "status": LicenseStatus.REVOKED,
                "issued_at": self._now(),
            }
        )
        bundle = self._sign(document)
        self._repository.store_license_version(context.tenant_id, bundle)
        self._audit(context, "license.revoke")
        return bundle

    async def get_terminal_health(
        self,
        context: OperationsContext,
        terminal_id: UUID,
    ) -> TerminalHealthSummary:
        site_id = self._terminal_site(context, terminal_id)
        self._require(context, OperationsPermission.HEALTH_VIEW, site_id=site_id)
        self._audit(context, "terminal.health.view")
        return cast(
            TerminalHealthSummary,
            self._repository.terminal_health(context.tenant_id, terminal_id),
        )

    async def create_upgrade_policy(
        self,
        context: OperationsContext,
        request: UpgradePolicyRequest,
    ) -> UpgradePolicySummary:
        self._require(context, OperationsPermission.UPGRADE_MANAGE)
        policy = UpgradePolicySummary(
            **request.model_dump(),
            upgrade_policy_id=uuid4(),
            tenant_id=context.tenant_id,
            created_at=self._now(),
        )
        self._repository.store_upgrade_policy(policy)
        self._audit(context, "upgrade_policy.create")
        return policy

    async def set_upgrade_policy_status(
        self,
        context: OperationsContext,
        policy_id: UUID,
        status: str,
    ) -> UpgradePolicySummary:
        self._require(context, OperationsPermission.UPGRADE_MANAGE)
        if status not in {"DRAFT", "ACTIVE", "PAUSED", "ROLLED_BACK"}:
            raise ValueError("unsupported upgrade policy status")
        current = self._repository.get_upgrade_policy(context.tenant_id, policy_id)
        updated = current.model_copy(update={"status": status})
        self._repository.store_upgrade_policy(updated)
        self._audit(context, "upgrade_policy.status.change")
        return cast(UpgradePolicySummary, updated)

    async def authorize_data_access(
        self,
        context: OperationsContext,
        request: DataAccessRequest,
    ) -> DataAccessDecision:
        permission = _ACCESS_PERMISSION[request.category]
        try:
            self._require(context, permission, site_id=request.site_id)
        except TenantAccessDenied:
            self._repository.append_operations_audit(
                context.tenant_id,
                "data.access",
                "DENIED",
            )
            raise
        audit_id = self._repository.append_operations_audit(
            context.tenant_id,
            "data.access",
            "ALLOWED",
        )
        return DataAccessDecision(
            allowed=True,
            audit_id=audit_id,
            category=request.category,
            expires_at=self._now() + timedelta(minutes=15),
        )
