from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
import hashlib
import hmac
from typing import Any, cast
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.capture_grants import (
    CaptureGrantBatchResponse,
    SessionAuthorization,
)
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    AnySegmentMetadata,
    AnySessionManifest,
    ConsentCreateRequest,
    ConsentResponse,
    ConsentRevokeRequest,
    EnrollmentStatus,
    HeartbeatRequest,
    HeartbeatResponse,
    IngestStatus,
    ManifestCompletionResponse,
    SessionCreateRequest,
    SessionCreateResponse,
    SessionStatusResponse,
    SubjectCreateRequest,
    SubjectSummary,
    ValidityStatus,
)
from techflex_cloud_foundation.contracts.device_policy import SignedLicense
from techflex_cloud_foundation.contracts.events import EventEnvelope
from techflex_cloud_foundation.contracts.operations import (
    DeviceRegistrationRequest,
    DeviceSummary,
    SiteCreateRequest,
    SiteSummary,
    TerminalDeviceBindingSummary,
    TerminalHealthSummary,
    UpgradePolicySummary,
)
from techflex_cloud_foundation.platform_errors import (
    ActivationCodeInvalid,
    IdempotencyConflict,
    ManifestConflict,
    ManifestIncomplete,
    ResourceNotFound,
    SegmentDigestConflict,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.auth import TerminalContext
from techflex_cloud_foundation.server.principal import (
    IngestionPrincipal,
    coerce_ingestion_principal,
)


@dataclass(frozen=True, slots=True)
class TerminalRecord:
    tenant_id: UUID
    site_id: UUID | None
    terminal_id: UUID
    status: str = "ACTIVE"
    installation_id: UUID | None = None
    client_public_key: str | None = None
    app_version: str | None = None
    config_version: str | None = None
    protocol_version: str | None = None
    last_seen_at: datetime | None = None
    last_successful_sync_at: datetime | None = None
    pending_sessions: int = 0
    pending_bytes: int = 0


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    tenant_id: UUID
    device_id: UUID
    model: str
    status: str = "ACTIVE"
    capabilities: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ConsentRecord:
    tenant_id: UUID
    subject_uuid: UUID
    consent_record_id: UUID
    granted_at: datetime
    revoked_at: datetime | None = None
    request_sha256: str | None = None
    policy_version: str = "fixture/1"


@dataclass(frozen=True, slots=True)
class ExternalIdentifierRecord:
    tenant_id: UUID
    subject_uuid: UUID
    issuer: str
    id_type: str
    normalized_hmac: bytes
    encrypted_value: bytes
    encryption_nonce: bytes
    masked_value: str
    key_version: str
    external_identifier_id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True, slots=True)
class SessionRecord:
    tenant_id: UUID
    request: SessionCreateRequest
    request_sha256: str
    ingest_status: IngestStatus = IngestStatus.RECEIVING
    validity_status: ValidityStatus = ValidityStatus.UNKNOWN
    manifest_sha256: str | None = None
    manifest_object_key: str | None = None
    aggregate_version: int = 1
    expected_manifest_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class SegmentRecord:
    tenant_id: UUID
    session_id: UUID
    metadata: AnySegmentMetadata
    object_key: str
    received_at: datetime


@dataclass(frozen=True, slots=True)
class ManifestRecord:
    tenant_id: UUID
    session_id: UUID
    manifest: AnySessionManifest
    manifest_sha256: str
    object_key: str
    verification_status: str
    verified_at: datetime | None
    eligibility_reason: str = ""
    eligibility_policy_version: str = ""


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    request_sha256: str
    response: Any


@dataclass(frozen=True, slots=True)
class ActivationCodeRecord:
    activation_code_hash: bytes
    tenant_id: UUID
    site_id: UUID | None
    device_id: UUID | None
    expires_at: datetime
    used_at: datetime | None = None
    terminal_id: UUID | None = None
    enrollment_code_id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True, slots=True)
class EnrollmentBinding:
    tenant_id: UUID
    site_id: UUID | None
    terminal_id: UUID
    status: EnrollmentStatus
    config_version: str | None = None


@dataclass(frozen=True, slots=True)
class EnrollmentIdempotencyRecord:
    request_sha256: str
    binding: EnrollmentBinding


@dataclass(frozen=True, slots=True)
class CaptureGrantRecord:
    tenant_id: UUID
    session_id: UUID
    installation_id: UUID
    account_id: UUID
    license_id: UUID
    hardware_id: UUID
    token_sha256: bytes
    issued_at: datetime
    state: str = "ISSUED"
    consumed_request_sha256: str | None = None
    expected_manifest_sha256: str | None = None
    approver_id: UUID | None = None
    approval_reason: str | None = None
    evidence_reference: str | None = None
    original_envelope_sha256: str | None = None
    original_subject_uuid: UUID | None = None
    final_subject_uuid: UUID | None = None
    consent_record_id: UUID | None = None
    consent_sha256: str | None = None
    reconciliation_case_id: UUID | None = None


class InMemoryPlatformRepository:
    """Deterministic reference adapter for contract and fault tests."""

    def __init__(self, *, access_repository: Any = None) -> None:
        self._capture_access = access_repository
        self._capture_grants: dict[tuple[UUID, UUID], CaptureGrantRecord] = {}
        self._migration_permits: dict[tuple[UUID, UUID], CaptureGrantRecord] = {}
        self._migration_audits: list[dict[str, Any]] = []
        self._registration_lock = asyncio.Lock()
        self._capture_audits: list[tuple[UUID, UUID, UUID, str, str]] = []
        self._terminals: dict[tuple[UUID, UUID], TerminalRecord] = {}
        self._tenants: dict[UUID, tuple[str, str]] = {}
        self._sites: dict[tuple[UUID, UUID], SiteSummary] = {}
        self._devices: dict[tuple[UUID, UUID], DeviceRecord] = {}
        self._terminal_device_bindings: set[tuple[UUID, UUID, UUID]] = set()
        self._activation_codes: dict[bytes, ActivationCodeRecord] = {}
        self._enrollment_idempotency: dict[tuple[bytes, str], EnrollmentIdempotencyRecord] = {}
        self._heartbeats: list[tuple[UUID, UUID, HeartbeatRequest, datetime]] = []
        self._operations_audits: list[tuple[UUID, str, str, UUID]] = []
        self._license_versions: dict[tuple[UUID, UUID], list[SignedLicense]] = {}
        self._upgrade_policies: dict[tuple[UUID, UUID], UpgradePolicySummary] = {}
        self._terminal_health_overrides: dict[tuple[UUID, UUID], dict[str, Any]] = {}
        self._subjects: set[tuple[UUID, UUID]] = set()
        self._subject_profiles: dict[tuple[UUID, UUID], dict[str, Any]] = {}
        self._identity_profiles: dict[tuple[UUID, UUID], tuple[bytes, bytes, str]] = {}
        self._external_identifiers: dict[
            tuple[UUID, str, str, bytes], ExternalIdentifierRecord
        ] = {}
        self._consents: dict[tuple[UUID, UUID], ConsentRecord] = {}
        self._sessions: dict[tuple[UUID, UUID], SessionRecord] = {}
        self._session_tenants: dict[UUID, UUID] = {}
        self._segments: dict[tuple[UUID, UUID, int], SegmentRecord] = {}
        self._manifests: dict[tuple[UUID, UUID], ManifestRecord] = {}
        self._idempotency: dict[tuple[UUID, str, str], IdempotencyRecord] = {}
        self._events: list[EventEnvelope] = []
        self._problems: list[tuple[UUID, UUID, str]] = []
        self.recovery_case_guard = None

    async def audit_migration_denial(self, context: Any, request: Any, decision: Any) -> None:
        self._migration_audits.append(self._migration_audit(context, request, "REJECTED", decision))

    @staticmethod
    def _migration_audit(context: Any, request: Any, event: Any, decision: Any) -> dict[str, Any]:
        return dict(
            tenant_id=request.tenant_id,
            session_id=request.session_id,
            actor_id=context.platform_identity_id,
            event_kind=event,
            decision_code=decision,
            reason=request.reason,
            evidence_reference=request.evidence_reference,
        )

    async def insert_migration_permit(self, context: Any, request: Any, token_sha256: Any) -> None:
        from techflex_cloud_foundation.contracts.access_control import PlatformRole

        access = self._capture_access
        if access is None:
            raise TenantAccessDenied("migration approval unavailable")
        async with access._lock, self._registration_lock:
            now = datetime.now(UTC)
            owner = access._platform_identities.get(context.platform_identity_id)
            owner_role = any(
                binding.platform_identity_id == context.platform_identity_id
                and binding.role == PlatformRole.OWNER
                and binding.valid_from <= now
                and (binding.valid_to is None or now < binding.valid_to)
                for binding in access._platform_role_bindings
            )
            installation = access._installations.get(request.installation_id)
            hardware_id = access._hardware_by_identity.get(request.hardware_id)
            historical_records = (
                access._accounts.get(request.account_id),
                access._licenses.get(request.license_id),
                access._hardware.get(hardware_id),
            )
            history = any(
                row.tenant_id == request.tenant_id
                and row.account_id == request.account_id
                and row.license_id == request.license_id
                and row.hardware_id == hardware_id
                and (
                    row.closed_at is None
                    or (installation is not None and installation.first_seen_at < row.closed_at)
                )
                for row in access._group_history
            )
            key = (request.tenant_id, request.session_id)
            if (
                owner is None
                or owner.status != "ACTIVE"
                or owner.token_version != context.token_version
                or context.expires_at <= now
                or PlatformRole.OWNER not in context.roles
                or not owner_role
                or installation is None
                or installation.tenant_id != request.tenant_id
                or installation.account_id != request.account_id
                or not history
                or any(
                    row is None or row.tenant_id != request.tenant_id for row in historical_records
                )
                or key in self._migration_permits
            ):
                raise TenantAccessDenied("migration approval binding rejected")
            self._migration_permits[key] = CaptureGrantRecord(
                request.tenant_id,
                request.session_id,
                request.installation_id,
                request.account_id,
                request.license_id,
                hardware_id,
                token_sha256,
                now,
                consumed_request_sha256=request.request_sha256,
                expected_manifest_sha256=request.manifest_sha256,
                approver_id=context.platform_identity_id,
                approval_reason=request.reason,
                evidence_reference=request.evidence_reference,
                original_envelope_sha256=request.original_envelope_sha256,
                original_subject_uuid=request.original_subject_uuid,
                final_subject_uuid=request.final_subject_uuid,
                consent_record_id=request.consent_record_id,
                consent_sha256=request.consent_sha256,
                reconciliation_case_id=request.reconciliation_reference,
            )
            self._migration_audits.append(
                self._migration_audit(context, request, "APPROVED", request.reason)
            )

    async def validate_migration_reconciliation(self, request: Any) -> bool:
        case_id = request.reconciliation_reference
        if case_id is None or self.recovery_case_guard is None:
            return False
        record = getattr(self.recovery_case_guard, "_by_id", {}).get((request.tenant_id, case_id))
        if record is None:
            return False
        return bool(
            record.status == "MATCHED"
            and record.receipt_id is not None
            and record.receipt_expires_at is not None
            and record.receipt_expires_at > datetime.now(UTC)
            and record.receipt_consumed_at is None
            and record.request.session_id == request.session_id
            and record.request.terminal_id == request.installation_id
            and record.request.original_subject_uuid == request.original_subject_uuid
            and record.request.cloud_subject_uuid == request.final_subject_uuid
            and record.request.envelope_sha256 == request.original_envelope_sha256
        )

    def _capture_entitlement(self, context: Any) -> Any:
        """Called under the reference access adapter's shared mutation lock."""
        context.ensure_can_start_new()
        access = self._capture_access
        account = access._accounts.get(context.account_id)
        license_record = access._licenses.get(context.license_id)
        installation = access._installations.get(context.terminal_id)
        hardware = access._hardware.get(access._hardware_by_identity.get(context.hardware_id))
        now = datetime.now(UTC)
        group = next(
            (
                g
                for g in access._group_history
                if g.license_id == context.license_id and g.closed_at is None
            ),
            None,
        )
        if (
            account is None
            or license_record is None
            or installation is None
            or hardware is None
            or group is None
            or any(
                row.tenant_id != context.tenant_id
                for row in (account, license_record, installation, hardware, group)
            )
            or account.status != "ACTIVE"
            or license_record.status != "ACTIVE"
            or installation.status != "ACTIVE"
            or hardware.status != "ACTIVE"
            or installation.account_id != context.account_id
            or group.account_id != context.account_id
            or group.hardware_id != hardware.hardware_id
            or not license_record.valid_from <= now < license_record.valid_until
        ):
            raise TenantAccessDenied("采集额度授权不匹配")
        return hardware.hardware_id

    async def issue_capture_grants(self, context: Any, grants: Any) -> CaptureGrantBatchResponse:
        if self._capture_access is None:
            raise TenantAccessDenied("采集额度授权不匹配")
        async with self._capture_access._lock:
            hardware_id = self._capture_entitlement(context)
            outstanding = sum(
                row.tenant_id == context.tenant_id
                and row.installation_id == context.terminal_id
                and row.state == "ISSUED"
                for row in self._capture_grants.values()
            )
            if outstanding >= 50:
                raise TenantAccessDenied("采集额度已用尽")
            issued = grants[: 50 - outstanding]
            for grant in issued:
                self._capture_grants[(context.tenant_id, grant.session_id)] = CaptureGrantRecord(
                    context.tenant_id,
                    grant.session_id,
                    context.terminal_id,
                    context.account_id,
                    context.license_id,
                    hardware_id,
                    hashlib.sha256(grant.token.get_secret_value().encode()).digest(),
                    datetime.now(UTC),
                )
                self._capture_audits.append(
                    (
                        context.tenant_id,
                        grant.session_id,
                        context.account_id,
                        "ISSUED",
                        "ACTIVE_ENTITLEMENT",
                    )
                )
            return CaptureGrantBatchResponse(grants=issued)

    async def retire_capture_grant(self, context: Any, session_id: Any, reason: Any) -> None:
        if self._capture_access is None or not reason.strip():
            raise TenantAccessDenied("采集额度授权不匹配")
        async with self._capture_access._lock:
            self._capture_entitlement(context)
            key = (context.tenant_id, session_id)
            row = self._capture_grants.get(key)
            if (
                row is None
                or row.installation_id != context.terminal_id
                or row.account_id != context.account_id
                or row.state != "ISSUED"
            ):
                raise TenantAccessDenied("采集额度不可注销")
            self._capture_grants[key] = replace(row, state="RETIRED")
            # Do not persist arbitrary caller text which could contain credentials.
            self._capture_audits.append(
                (context.tenant_id, session_id, context.account_id, "RETIRED", "CLIENT_RETIRED")
            )

    def add_terminal(self, tenant_id: UUID, site_id: UUID, terminal_id: UUID) -> None:
        self._terminals[(tenant_id, terminal_id)] = TerminalRecord(tenant_id, site_id, terminal_id)

    def add_tenant(self, tenant_id: UUID, name: str, status: str = "ACTIVE") -> None:
        self._tenants[tenant_id] = (name, status)

    def create_site(self, tenant_id: UUID, request: SiteCreateRequest) -> SiteSummary:
        if tenant_id not in self._tenants:
            raise TenantAccessDenied("机构不存在")
        key = (tenant_id, request.site_id)
        if key in self._sites:
            raise IdempotencyConflict("站点 ID 已存在")
        if any(
            existing.tenant_id == tenant_id and existing.site_code == request.site_code
            for existing in self._sites.values()
        ):
            raise IdempotencyConflict("站点编码已存在")
        summary = SiteSummary(tenant_id=tenant_id, **request.model_dump())
        self._sites[key] = summary
        return summary

    def register_device(
        self,
        tenant_id: UUID,
        request: DeviceRegistrationRequest,
    ) -> DeviceSummary:
        existing_owner = next(
            (owner for owner, device_id in self._devices if device_id == request.device_id),
            None,
        )
        if existing_owner is not None and existing_owner != tenant_id:
            raise TenantAccessDenied("设备 ID 已属于其他租户")
        if (tenant_id, request.device_id) in self._devices:
            raise IdempotencyConflict("设备 ID 已存在")
        self._devices[(tenant_id, request.device_id)] = DeviceRecord(
            tenant_id,
            request.device_id,
            request.model,
            capabilities=dict(request.capabilities),
        )
        return DeviceSummary(tenant_id=tenant_id, **request.model_dump())

    def bind_terminal_device(
        self,
        tenant_id: UUID,
        terminal_id: UUID,
        device_id: UUID,
        valid_from: datetime,
    ) -> TerminalDeviceBindingSummary:
        terminal = self._terminals.get((tenant_id, terminal_id))
        device = self._devices.get((tenant_id, device_id))
        if terminal is None or device is None:
            raise TenantAccessDenied("终端或设备不属于当前租户")
        self._terminal_device_bindings.add((tenant_id, terminal_id, device_id))
        return TerminalDeviceBindingSummary(
            binding_id=uuid4(),
            tenant_id=tenant_id,
            terminal_id=terminal_id,
            device_id=device_id,
            valid_from=valid_from,
        )

    def terminal_owner(self, terminal_id: UUID) -> tuple[UUID, UUID | None] | None:
        for (tenant_id, candidate), terminal in self._terminals.items():
            if candidate == terminal_id:
                return tenant_id, terminal.site_id
        return None

    def device_owner(self, device_id: UUID) -> UUID | None:
        return next(
            (tenant_id for tenant_id, candidate in self._devices if candidate == device_id),
            None,
        )

    def terminal_status(self, tenant_id: UUID, terminal_id: UUID) -> str:
        return self._terminals[(tenant_id, terminal_id)].status

    def terminal_keys(self) -> tuple[tuple[UUID, UUID], ...]:
        return tuple(self._terminals)

    def append_operations_audit(
        self,
        tenant_id: UUID,
        action: str,
        outcome: str,
        audit_id: UUID | None = None,
    ) -> UUID:
        record_id = audit_id or uuid4()
        self._operations_audits.append((tenant_id, action, outcome, record_id))
        return record_id

    def audit_actions(self, tenant_id: UUID) -> list[str]:
        return [
            action
            for record_tenant, action, _, _ in self._operations_audits
            if record_tenant == tenant_id
        ]

    def access_audit_outcomes(self, tenant_id: UUID) -> list[str]:
        return [
            outcome
            for record_tenant, action, outcome, _ in self._operations_audits
            if record_tenant == tenant_id and action == "data.access"
        ]

    def store_license_version(self, tenant_id: UUID, bundle: SignedLicense) -> None:
        key = (tenant_id, bundle.document.license_id)
        versions = self._license_versions.setdefault(key, [])
        if versions and bundle.document.license_version != len(versions) + 1:
            raise IdempotencyConflict("License 版本不连续")
        versions.append(bundle)

    def latest_license(self, tenant_id: UUID, license_id: UUID) -> SignedLicense:
        versions = self._license_versions.get((tenant_id, license_id))
        if not versions:
            raise ResourceNotFound("License 不存在")
        return versions[-1]

    def license_version_count(self, tenant_id: UUID, license_id: UUID) -> int:
        return len(self._license_versions.get((tenant_id, license_id), ()))

    def store_upgrade_policy(self, policy: UpgradePolicySummary) -> None:
        self._upgrade_policies[(policy.tenant_id, policy.upgrade_policy_id)] = policy

    def get_upgrade_policy(self, tenant_id: UUID, policy_id: UUID) -> UpgradePolicySummary:
        policy = self._upgrade_policies.get((tenant_id, policy_id))
        if policy is None:
            raise ResourceNotFound("升级策略不存在")
        return policy

    def terminal_health(self, tenant_id: UUID, terminal_id: UUID) -> TerminalHealthSummary:
        terminal = self._terminals.get((tenant_id, terminal_id))
        if terminal is None:
            raise ResourceNotFound("终端不存在")
        heartbeats = [
            request
            for heartbeat_tenant, heartbeat_terminal, request, _ in self._heartbeats
            if heartbeat_tenant == tenant_id and heartbeat_terminal == terminal_id
        ]
        override = self._terminal_health_overrides.get((tenant_id, terminal_id), {})
        error_codes = [
            request.health.last_error_code
            for request in heartbeats
            if request.health.last_error_code is not None
        ]
        connection_state = (
            heartbeats[-1].device.connection_state
            if heartbeats
            else override.get("device_connection_state", "UNKNOWN")
        )
        return TerminalHealthSummary(
            terminal_id=terminal_id,
            site_id=terminal.site_id,
            status=cast("EnrollmentStatus", terminal.status),
            last_seen_at=terminal.last_seen_at,
            app_version=terminal.app_version,
            config_version=terminal.config_version,
            protocol_version=terminal.protocol_version,
            pending_sessions=terminal.pending_sessions,
            pending_bytes=terminal.pending_bytes,
            device_connection_state=connection_state,
            error_trends=dict(Counter(error_codes or override.get("error_codes", ()))),
        )

    def add_device(
        self, tenant_id: UUID, device_id: UUID, model: str, status: str = "ACTIVE"
    ) -> None:
        self._devices[(tenant_id, device_id)] = DeviceRecord(tenant_id, device_id, model, status)

    def add_activation_code_hash(
        self,
        activation_code_hash: bytes,
        *,
        tenant_id: UUID,
        site_id: UUID | None,
        device_id: UUID | None,
        expires_at: datetime,
        enrollment_code_id: UUID | None = None,
    ) -> None:
        self._activation_codes[activation_code_hash] = ActivationCodeRecord(
            activation_code_hash,
            tenant_id,
            site_id,
            device_id,
            expires_at,
            enrollment_code_id=enrollment_code_id or uuid4(),
        )

    def activation_storage_contains(self, activation_code: str) -> bool:
        raw = activation_code.encode("utf-8")
        return any(raw in digest for digest in self._activation_codes)

    def has_activation_code_id(self, enrollment_code_id: UUID) -> bool:
        return any(
            record.enrollment_code_id == enrollment_code_id
            for record in self._activation_codes.values()
        )

    def is_device_bound(
        self,
        tenant_id: UUID,
        terminal_id: UUID,
        device_id: UUID,
    ) -> bool:
        return (tenant_id, terminal_id, device_id) in self._terminal_device_bindings

    def set_terminal_status(
        self,
        tenant_id: UUID,
        terminal_id: UUID,
        status: str,
    ) -> None:
        record = self._terminals[(tenant_id, terminal_id)]
        self._terminals[(tenant_id, terminal_id)] = replace(record, status=status)

    async def consume_activation_code(
        self,
        activation_code_hash: bytes,
        request: Any,
        request_sha256: str,
        idempotency_key: str,
        accepted_at: datetime,
    ) -> EnrollmentBinding:
        replay = self._enrollment_idempotency.get((activation_code_hash, idempotency_key))
        if replay is not None:
            if replay.request_sha256 != request_sha256:
                raise IdempotencyConflict("同一激活幂等键对应不同请求", scope="device.enroll")
            return replay.binding
        code = self._activation_codes.get(activation_code_hash)
        if code is None or code.used_at is not None or code.expires_at <= accepted_at:
            raise ActivationCodeInvalid("激活码无效、已使用或已过期")
        if any(
            tenant_id == code.tenant_id and terminal.installation_id == request.installation_id
            for (tenant_id, _), terminal in self._terminals.items()
        ):
            raise ActivationCodeInvalid("安装实例已经绑定，请联系支持")
        if code.device_id is not None:
            device = self._devices.get((code.tenant_id, code.device_id))
            if device is None or device.status != "ACTIVE":
                raise ActivationCodeInvalid("激活码绑定的设备不可用")
        terminal_id = uuid4()
        terminal = TerminalRecord(
            tenant_id=code.tenant_id,
            site_id=code.site_id,
            terminal_id=terminal_id,
            installation_id=request.installation_id,
            client_public_key=request.client_public_key,
            app_version=request.system.app_version,
            last_seen_at=accepted_at,
        )
        self._terminals[(code.tenant_id, terminal_id)] = terminal
        if code.device_id is not None:
            self._terminal_device_bindings.add((code.tenant_id, terminal_id, code.device_id))
        self._activation_codes[activation_code_hash] = replace(
            code,
            used_at=accepted_at,
            terminal_id=terminal_id,
        )
        binding = EnrollmentBinding(
            tenant_id=code.tenant_id,
            site_id=code.site_id,
            terminal_id=terminal_id,
            status=EnrollmentStatus.ACTIVE,
        )
        self._enrollment_idempotency[(activation_code_hash, idempotency_key)] = (
            EnrollmentIdempotencyRecord(request_sha256, binding)
        )
        return binding

    async def record_heartbeat(
        self,
        context: TerminalContext,
        request: HeartbeatRequest,
        request_sha256: str,
        idempotency_key: str,
        accepted_at: datetime,
    ) -> HeartbeatResponse:
        terminal = self._terminal(context)
        replay = self._idempotent_result(
            context.tenant_id,
            "terminal.heartbeat",
            idempotency_key,
            request_sha256,
        )
        if replay is not None:
            return cast("HeartbeatResponse", replay)
        if request.device.device_id is not None and not self.is_device_bound(
            context.tenant_id,
            context.terminal_id,
            request.device.device_id,
        ):
            raise TenantAccessDenied(
                "设备未绑定到当前终端",
                device_id=str(request.device.device_id),
            )
        response = HeartbeatResponse(
            terminal_id=context.terminal_id,
            accepted_at=accepted_at,
            status=EnrollmentStatus(terminal.status),
        )
        self._terminals[(context.tenant_id, context.terminal_id)] = replace(
            terminal,
            app_version=request.app_version,
            config_version=request.config_version,
            protocol_version=request.protocol_version,
            last_seen_at=accepted_at,
            last_successful_sync_at=request.sync.last_successful_sync,
            pending_sessions=request.sync.pending_sessions,
            pending_bytes=request.sync.pending_bytes,
        )
        self._heartbeats.append((context.tenant_id, context.terminal_id, request, accepted_at))
        self._idempotency[(context.tenant_id, "terminal.heartbeat", idempotency_key)] = (
            IdempotencyRecord(request_sha256, response)
        )
        return response

    def add_subject(self, tenant_id: UUID, subject_uuid: UUID) -> None:
        self._subjects.add((tenant_id, subject_uuid))
        self._subject_profiles.setdefault((tenant_id, subject_uuid), {})

    def add_consent(
        self,
        tenant_id: UUID,
        subject_uuid: UUID,
        consent_record_id: UUID,
        granted_at: datetime,
    ) -> None:
        self._consents[(tenant_id, consent_record_id)] = ConsentRecord(
            tenant_id, subject_uuid, consent_record_id, granted_at
        )

    async def resolve_subject(
        self,
        context: TerminalContext,
        issuer: str,
        id_type: str,
        normalized_hmac: bytes,
    ) -> SubjectSummary | None:
        self._terminal(context)
        record = self._external_identifiers.get(
            (context.tenant_id, issuer, id_type, normalized_hmac)
        )
        if record is None:
            return None
        return SubjectSummary(
            subject_uuid=record.subject_uuid,
            external_identifier_id=record.external_identifier_id,
            external_id_masked=record.masked_value,
            analysis_profile=self._subject_profiles[(context.tenant_id, record.subject_uuid)],
        )

    async def create_subject(
        self,
        context: TerminalContext,
        request: SubjectCreateRequest,
        *,
        normalized_hmac: bytes | None,
        encrypted_value: bytes | None,
        encryption_nonce: bytes | None,
        masked_value: str | None,
        key_version: str | None,
        identity_ciphertext: bytes | None,
        identity_nonce: bytes | None,
        identity_key_version: str | None,
        idempotency_key: str,
    ) -> SubjectSummary:
        self._terminal(context)
        digest = canonical_sha256(request)
        replay = self._idempotent_result(
            context.tenant_id, "subject.create", idempotency_key, digest
        )
        if replay is not None:
            return cast("SubjectSummary", replay)
        external = request.external_identifier
        if external is not None and normalized_hmac is not None:
            existing = self._external_identifiers.get(
                (context.tenant_id, external.issuer, external.id_type, normalized_hmac)
            )
            if existing is not None:
                response = SubjectSummary(
                    subject_uuid=existing.subject_uuid,
                    external_identifier_id=existing.external_identifier_id,
                    external_id_masked=existing.masked_value,
                    conflict=True,
                    analysis_profile=self._subject_profiles[
                        (context.tenant_id, existing.subject_uuid)
                    ],
                )
                self._idempotency[(context.tenant_id, "subject.create", idempotency_key)] = (
                    IdempotencyRecord(digest, response)
                )
                return response
        existing_tenant = next(
            (tenant for tenant, subject_id in self._subjects if subject_id == request.subject_uuid),
            None,
        )
        if existing_tenant is not None and existing_tenant != context.tenant_id:
            raise TenantAccessDenied("受试者 ID 已属于其他租户")
        if (context.tenant_id, request.subject_uuid) in self._subjects:
            raise IdempotencyConflict("同一受试者 ID 对应不同创建请求")
        self._subjects.add((context.tenant_id, request.subject_uuid))
        self._subject_profiles[(context.tenant_id, request.subject_uuid)] = dict(
            request.analysis_profile
        )
        if request.identity_profile is not None:
            if None in (identity_ciphertext, identity_nonce, identity_key_version):
                raise ValueError("protected identity profile fields are required")
            self._identity_profiles[(context.tenant_id, request.subject_uuid)] = cast(
                "tuple[bytes, bytes, str]",
                (identity_ciphertext, identity_nonce, identity_key_version),
            )
        if external is not None:
            if None in (
                normalized_hmac,
                encrypted_value,
                encryption_nonce,
                masked_value,
                key_version,
            ):
                raise ValueError("external identifier protection fields are required")
            # The check above rules out None; ``in`` does not narrow for mypy.
            normalized_hmac = cast(bytes, normalized_hmac)
            encrypted_value = cast(bytes, encrypted_value)
            encryption_nonce = cast(bytes, encryption_nonce)
            masked_value = cast(str, masked_value)
            key_version = cast(str, key_version)
            self._external_identifiers[
                (context.tenant_id, external.issuer, external.id_type, normalized_hmac)
            ] = ExternalIdentifierRecord(
                context.tenant_id,
                request.subject_uuid,
                external.issuer,
                external.id_type,
                normalized_hmac,
                encrypted_value,
                encryption_nonce,
                masked_value,
                key_version,
            )
        response = SubjectSummary(
            subject_uuid=request.subject_uuid,
            external_identifier_id=(
                self._external_identifiers[
                    (
                        context.tenant_id,
                        external.issuer,
                        external.id_type,
                        cast(bytes, normalized_hmac),
                    )
                ].external_identifier_id
                if external is not None
                else None
            ),
            external_id_masked=masked_value,
            analysis_profile=request.analysis_profile,
        )
        self._idempotency[(context.tenant_id, "subject.create", idempotency_key)] = (
            IdempotencyRecord(digest, response)
        )
        return response

    async def create_consent(
        self,
        context: TerminalContext,
        request: ConsentCreateRequest,
        request_sha256: str,
        idempotency_key: str,
    ) -> ConsentResponse:
        self._terminal(context)
        replay = self._idempotent_result(
            context.tenant_id, "consent.create", idempotency_key, request_sha256
        )
        if replay is not None:
            return cast("ConsentResponse", replay)
        if (context.tenant_id, request.subject_uuid) not in self._subjects:
            raise TenantAccessDenied("受试者不属于当前租户")
        existing_tenant = next(
            (
                tenant
                for tenant, consent_id in self._consents
                if consent_id == request.consent_record_id
            ),
            None,
        )
        if existing_tenant is not None and existing_tenant != context.tenant_id:
            raise TenantAccessDenied("授权 ID 已属于其他租户")
        existing = self._consents.get((context.tenant_id, request.consent_record_id))
        if existing is not None:
            if existing.request_sha256 != request_sha256:
                raise IdempotencyConflict("同一授权 ID 对应不同内容")
            return ConsentResponse(
                consent_record_id=existing.consent_record_id,
                subject_uuid=existing.subject_uuid,
                policy_version=existing.policy_version,
                granted_at=existing.granted_at,
                revoked_at=existing.revoked_at,
            )
        record = ConsentRecord(
            context.tenant_id,
            request.subject_uuid,
            request.consent_record_id,
            request.granted_at,
            request_sha256=request_sha256,
            policy_version=request.policy_version,
        )
        self._consents[(context.tenant_id, request.consent_record_id)] = record
        response = ConsentResponse(
            consent_record_id=request.consent_record_id,
            subject_uuid=request.subject_uuid,
            policy_version=request.policy_version,
            granted_at=request.granted_at,
        )
        self._idempotency[(context.tenant_id, "consent.create", idempotency_key)] = (
            IdempotencyRecord(request_sha256, response)
        )
        return response

    async def revoke_consent(
        self,
        context: TerminalContext,
        consent_record_id: UUID,
        request: ConsentRevokeRequest,
        request_sha256: str,
        idempotency_key: str,
    ) -> ConsentResponse:
        self._terminal(context)
        replay = self._idempotent_result(
            context.tenant_id, "consent.revoke", idempotency_key, request_sha256
        )
        if replay is not None:
            return cast("ConsentResponse", replay)
        record = self._consents.get((context.tenant_id, consent_record_id))
        if record is None:
            if any(consent_id == consent_record_id for _, consent_id in self._consents):
                raise TenantAccessDenied("授权不属于当前租户")
            raise ResourceNotFound("授权不存在")
        if record.revoked_at is not None and record.revoked_at != request.revoked_at:
            raise IdempotencyConflict("授权已经以不同撤回事实撤回")
        updated = replace(record, revoked_at=request.revoked_at)
        self._consents[(context.tenant_id, consent_record_id)] = updated
        response = ConsentResponse(
            consent_record_id=record.consent_record_id,
            subject_uuid=record.subject_uuid,
            policy_version=record.policy_version,
            granted_at=record.granted_at,
            revoked_at=request.revoked_at,
        )
        self._idempotency[(context.tenant_id, "consent.revoke", idempotency_key)] = (
            IdempotencyRecord(request_sha256, response)
        )
        return response

    async def is_consent_active(self, tenant_id: UUID, consent_record_id: UUID) -> bool:
        record = self._consents.get((tenant_id, consent_record_id))
        return record is not None and record.revoked_at is None

    def identity_storage_contains(self, plaintext: str) -> bool:
        needle = plaintext.encode("utf-8")
        external_contains = any(
            needle in record.encrypted_value for record in self._external_identifiers.values()
        )
        identity_contains = any(
            needle in ciphertext for ciphertext, _, _ in self._identity_profiles.values()
        )
        return external_contains or identity_contains

    def has_identity_profile(self, tenant_id: UUID, subject_uuid: UUID) -> bool:
        return (tenant_id, subject_uuid) in self._identity_profiles

    def subject_count(self, tenant_id: UUID) -> int:
        return sum(1 for tenant, _ in self._subjects if tenant == tenant_id)

    def _terminal(
        self,
        context: TerminalContext,
        *,
        require_active: bool = True,
    ) -> TerminalRecord:
        context.ensure_active()
        terminal = self._terminals.get((context.tenant_id, context.terminal_id))
        if terminal is None or (require_active and terminal.status != "ACTIVE"):
            raise TenantAccessDenied("终端未绑定到当前租户", terminal_id=str(context.terminal_id))
        return terminal

    def _session(self, context: TerminalContext, session_id: UUID) -> SessionRecord:
        self._terminal(context, require_active=False)
        tenant = self._session_tenants.get(session_id)
        if tenant is not None and tenant != context.tenant_id:
            raise TenantAccessDenied("会话不属于当前租户", session_id=str(session_id))
        session = self._sessions.get((context.tenant_id, session_id))
        if session is None:
            raise ResourceNotFound("会话不存在", session_id=str(session_id))
        return session

    def _idempotent_result(
        self,
        tenant_id: UUID,
        scope: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> Any | None:
        record = self._idempotency.get((tenant_id, scope, idempotency_key))
        if record is None:
            return None
        if record.request_sha256 != request_sha256:
            raise IdempotencyConflict("同一幂等键对应不同请求", scope=scope)
        return record.response

    async def create_session(
        self,
        context: IngestionPrincipal | TerminalContext,
        request: SessionCreateRequest,
        idempotency_key: str,
        authorization: SessionAuthorization | None = None,
        *,
        recovery_case_id: UUID | None = None,
    ) -> SessionCreateResponse:
        context = coerce_ingestion_principal(context)
        context.ensure_can_upload()
        # Shared with issuance/retirement when access control is configured.
        lock = (
            self._capture_access._lock
            if self._capture_access is not None
            else self._registration_lock
        )
        async with lock:
            return cast(
                "SessionCreateResponse",
                self._create_session_locked(
                    context, request, idempotency_key, authorization, recovery_case_id
                ),
            )

    def _create_session_locked(
        self,
        context: Any,
        request: Any,
        idempotency_key: Any,
        authorization: Any,
        recovery_case_id: Any = None,
    ) -> Any:
        self._terminal(context)
        if self.recovery_case_guard is not None:
            protected_case = self.recovery_case_guard.open_case_id(
                context.tenant_id, request.session_id
            )
            if protected_case is not None and protected_case != recovery_case_id:
                raise TenantAccessDenied("session requires controlled identity recovery")
        digest = canonical_sha256(request)
        self._idempotent_result(context.tenant_id, "session.create", idempotency_key, digest)
        key = (context.tenant_id, request.session_id)
        existing = self._sessions.get(key)
        if existing is not None:
            if existing.request_sha256 != digest:
                raise IdempotencyConflict("同一会话 ID 对应不同请求")
            if existing.expected_manifest_sha256 is not None and (
                authorization is None
                or authorization.manifest_sha256 != existing.expected_manifest_sha256
            ):
                raise IdempotencyConflict("同一会话对应不同最终清单")
        elif authorization is None:
            context.ensure_can_start_new()
        authorization_row = None
        if authorization is not None:
            rows = (
                self._capture_grants if authorization.kind == "grant" else self._migration_permits
            )
            authorization_row = rows.get(key)
            row = authorization_row
            if (
                row is None
                or row.tenant_id != context.tenant_id
                or row.session_id != request.session_id
                or authorization.session_id != request.session_id
                or row.installation_id != context.terminal_id
                or row.installation_id != request.client_installation_id
                or row.account_id != context.account_id
                or row.hardware_id != request.device_id
                or not hmac.compare_digest(
                    row.token_sha256,
                    hashlib.sha256(authorization.token.get_secret_value().encode()).digest(),
                )
                or row.state != ("CONSUMED" if existing is not None else "ISSUED")
                or (
                    row.consumed_request_sha256 is not None
                    and row.consumed_request_sha256 != digest
                )
                or (
                    row.expected_manifest_sha256 is not None
                    and row.expected_manifest_sha256 != authorization.manifest_sha256
                )
            ):
                raise TenantAccessDenied("采集授权不匹配")
            if authorization.kind == "migration_permit":
                consent_record = self._consents.get((context.tenant_id, request.consent_record_id))
                if (
                    row.final_subject_uuid != request.subject_uuid
                    or row.consent_record_id != request.consent_record_id
                    or consent_record is None
                    or consent_record.request_sha256 != row.consent_sha256
                ):
                    raise TenantAccessDenied("migration permit consent binding mismatch")
                if recovery_case_id is not None:
                    case = getattr(self.recovery_case_guard, "_by_id", {}).get(
                        (context.tenant_id, recovery_case_id)
                    )
                    if (
                        case is None
                        or row.reconciliation_case_id != recovery_case_id
                        or row.original_envelope_sha256 != case.request.envelope_sha256
                        or row.original_subject_uuid != case.request.original_subject_uuid
                        or row.final_subject_uuid != case.request.cloud_subject_uuid
                    ):
                        raise TenantAccessDenied("migration permit reconciliation binding mismatch")
            # The grant/permit records the historical License and hardware UUID.
            # Current entitlement may legitimately use another License/hardware.
        if existing is not None:
            response = SessionCreateResponse(
                session_id=request.session_id,
                ingest_status=existing.ingest_status,
                idempotent_replay=True,
            )
            self._idempotency[(context.tenant_id, "session.create", idempotency_key)] = (
                IdempotencyRecord(digest, response)
            )
            return response
        captured_installation = self._terminals.get(
            (context.tenant_id, request.client_installation_id)
        )
        if captured_installation is None or request.site_id != captured_installation.site_id:
            raise TenantAccessDenied("采集安装或站点不属于认证租户")
        device = self._devices.get((context.tenant_id, request.device_id))
        if (
            device is not None
            and context.terminal_access
            and (device.model != "insole-pair" or device.status != "ACTIVE")
        ):
            # RAY-728 D5: terminals capture with ACTIVE insole-pair projections only.
            device = None
        if device is None:
            raise TenantAccessDenied(
                "采集硬件资产不属于认证租户",
                device_id=str(request.device_id),
            )
        if (context.tenant_id, request.subject_uuid) not in self._subjects:
            raise TenantAccessDenied("受试者不属于当前租户", subject_uuid=str(request.subject_uuid))
        consent = self._consents.get((context.tenant_id, request.consent_record_id))
        if (
            consent is None
            or consent.subject_uuid != request.subject_uuid
            or consent.revoked_at is not None
        ):
            raise TenantAccessDenied("授权无效或不属于当前受试者")
        existing_tenant = self._session_tenants.get(request.session_id)
        if existing_tenant is not None and existing_tenant != context.tenant_id:
            raise TenantAccessDenied("会话 ID 已属于其他租户")
        self._sessions[key] = SessionRecord(
            tenant_id=context.tenant_id,
            request=request,
            request_sha256=digest,
            expected_manifest_sha256=authorization.manifest_sha256 if authorization else None,
        )
        self._session_tenants[request.session_id] = context.tenant_id
        response = SessionCreateResponse(
            session_id=request.session_id,
            ingest_status=IngestStatus.RECEIVING,
        )
        if authorization_row is not None:
            rows[key] = replace(
                authorization_row,
                state="CONSUMED",
                consumed_request_sha256=digest,
                expected_manifest_sha256=authorization.manifest_sha256,
            )
            self._capture_audits.append(
                (
                    context.tenant_id,
                    request.session_id,
                    context.account_id,
                    "CONSUMED",
                    "AUTHORIZED_REGISTRATION",
                )
            )
        self._idempotency[(context.tenant_id, "session.create", idempotency_key)] = (
            IdempotencyRecord(digest, response.model_copy(update={"idempotent_replay": False}))
        )
        return response

    async def session(self, context: TerminalContext, session_id: UUID) -> SessionRecord:
        return self._session(context, session_id)

    async def get_segment(
        self, context: TerminalContext, session_id: UUID, index: int
    ) -> SegmentRecord | None:
        self._session(context, session_id)
        return self._segments.get((context.tenant_id, session_id, index))

    async def register_segment(
        self,
        context: TerminalContext,
        session_id: UUID,
        metadata: AnySegmentMetadata,
        object_key: str,
    ) -> SegmentRecord:
        session = self._session(context, session_id)
        if session.ingest_status in (IngestStatus.INGESTED, IngestStatus.CONFLICT):
            raise SegmentDigestConflict("会话不再接受分段", session_id=str(session_id))
        key = (context.tenant_id, session_id, metadata.segment_index)
        existing = self._segments.get(key)
        if existing is not None:
            if existing.metadata.sha256 != metadata.sha256:
                raise SegmentDigestConflict(
                    "同一分段索引已存在不同摘要",
                    session_id=str(session_id),
                    segment_index=metadata.segment_index,
                )
            return existing
        record = SegmentRecord(
            tenant_id=context.tenant_id,
            session_id=session_id,
            metadata=metadata,
            object_key=object_key,
            received_at=datetime.now(UTC),
        )
        self._segments[key] = record
        return record

    async def mark_segment_conflict(
        self, context: TerminalContext, session_id: UUID, index: int
    ) -> None:
        session = self._session(context, session_id)
        self._sessions[(context.tenant_id, session_id)] = replace(
            session, ingest_status=IngestStatus.CONFLICT
        )
        self._problems.append((context.tenant_id, session_id, "CONTENT_CONFLICT"))

    async def list_segments(
        self, context: TerminalContext, session_id: UUID
    ) -> tuple[SegmentRecord, ...]:
        self._session(context, session_id)
        return tuple(
            sorted(
                (
                    record
                    for (tenant, current_session, _), record in self._segments.items()
                    if tenant == context.tenant_id and current_session == session_id
                ),
                key=lambda record: record.metadata.segment_index,
            )
        )

    async def object_is_referenced(self, tenant_id: UUID, object_key: str) -> bool:
        return any(
            record.tenant_id == tenant_id and record.object_key == object_key
            for record in self._segments.values()
        ) or any(
            record.tenant_id == tenant_id and record.object_key == object_key
            for record in self._manifests.values()
        )

    async def complete_manifest(
        self,
        context: TerminalContext,
        session_id: UUID,
        manifest: AnySessionManifest,
        manifest_sha256: str,
        object_key: str,
        idempotency_key: str,
        *,
        eligibility_reason: str,
        eligibility_policy_version: str,
        completed_at: datetime,
    ) -> ManifestCompletionResponse:
        session = self._session(context, session_id)
        if (
            session.expected_manifest_sha256 is not None
            and canonical_sha256(manifest) != session.expected_manifest_sha256
        ):
            raise ManifestConflict("最终清单与登记授权不一致", session_id=str(session_id))
        replay = self._idempotent_result(
            context.tenant_id, "session.complete", idempotency_key, manifest_sha256
        )
        if replay is not None:
            return cast(
                "ManifestCompletionResponse", replay.model_copy(update={"idempotent_replay": True})
            )
        existing_manifest = self._manifests.get((context.tenant_id, session_id))
        if existing_manifest is not None:
            if existing_manifest.manifest_sha256 != manifest_sha256:
                raise ManifestConflict("同一会话已存在不同最终清单", session_id=str(session_id))
            if existing_manifest.verification_status == "VERIFIED":
                original_completed_at = existing_manifest.verified_at
                if original_completed_at is None:
                    raise RuntimeError("verified manifest record without verified_at")
                response = ManifestCompletionResponse(
                    session_id=session_id,
                    ingest_status=IngestStatus.INGESTED,
                    manifest_sha256=manifest_sha256,
                    idempotent_replay=True,
                    manifest_object_key=existing_manifest.object_key,
                    eligibility_reason=existing_manifest.eligibility_reason,
                    eligibility_policy_version=existing_manifest.eligibility_policy_version,
                    completed_at=original_completed_at,
                )
                self._idempotency[(context.tenant_id, "session.complete", idempotency_key)] = (
                    IdempotencyRecord(
                        manifest_sha256, response.model_copy(update={"idempotent_replay": False})
                    )
                )
                return response
        if session.ingest_status is IngestStatus.CONFLICT:
            raise ManifestConflict("冲突会话不能确认最终清单", session_id=str(session_id))
        accepted = await self.list_segments(context, session_id)
        accepted_by_index = {record.metadata.segment_index: record for record in accepted}
        mismatch: list[int] = []
        for item in manifest.segments:
            record = accepted_by_index.get(item.index)
            if record is None or (
                record.metadata.sha256 != item.sha256
                or record.metadata.size_bytes != item.size_bytes
                # Archive parts (RAY-825) have no frame count on either side.
                or getattr(record.metadata, "frame_count", None)
                != getattr(item, "frame_count", None)
            ):
                mismatch.append(item.index)
        extra = sorted(set(accepted_by_index) - {item.index for item in manifest.segments})
        if mismatch or extra:
            self._manifests[(context.tenant_id, session_id)] = ManifestRecord(
                context.tenant_id,
                session_id,
                manifest,
                manifest_sha256,
                object_key,
                "PENDING",
                None,
            )
            self._problems.append((context.tenant_id, session_id, "MISSING_SEGMENT"))
            raise ManifestIncomplete(
                "最终清单与已接收分段集合不一致",
                session_id=str(session_id),
                missing_or_mismatched=mismatch,
                extra=extra,
            )
        verified_at = completed_at
        manifest_record = ManifestRecord(
            context.tenant_id,
            session_id,
            manifest,
            manifest_sha256,
            object_key,
            "VERIFIED",
            verified_at,
            eligibility_reason,
            eligibility_policy_version,
        )
        next_version = session.aggregate_version + 1
        event = EventEnvelope(
            event_id=uuid4(),
            event_type="session.ingested.v1",
            occurred_at=verified_at,
            producer="ingestion",
            tenant_id=context.tenant_id,
            aggregate_type="screening_session",
            aggregate_id=session_id,
            aggregate_version=next_version,
            payload={
                "session_id": str(session_id),
                "manifest_sha256": manifest_sha256,
                "segment_count": manifest.segment_count,
            },
        )
        self._manifests[(context.tenant_id, session_id)] = manifest_record
        self._sessions[(context.tenant_id, session_id)] = replace(
            session,
            ingest_status=IngestStatus.INGESTED,
            validity_status=ValidityStatus.VALID,
            manifest_sha256=manifest_sha256,
            manifest_object_key=object_key,
            aggregate_version=next_version,
        )
        self._events.append(event)
        response = ManifestCompletionResponse(
            session_id=session_id,
            ingest_status=IngestStatus.INGESTED,
            manifest_sha256=manifest_sha256,
            manifest_object_key=object_key,
            eligibility_reason=eligibility_reason,
            eligibility_policy_version=eligibility_policy_version,
            completed_at=completed_at,
        )
        self._idempotency[(context.tenant_id, "session.complete", idempotency_key)] = (
            IdempotencyRecord(manifest_sha256, response)
        )
        return response

    async def expected_segment_count(
        self, context: TerminalContext, session_id: UUID
    ) -> int | None:
        self._session(context, session_id)
        manifest = self._manifests.get((context.tenant_id, session_id))
        return None if manifest is None else manifest.manifest.segment_count

    async def status(self, context: TerminalContext, session_id: UUID) -> SessionStatusResponse:
        # Authorization rule (commit f7fb6a4): session status is shared within a
        # tenant so a replacement installation can recover a workflow started on
        # a retired terminal. Tenant scope is enforced; terminal ownership is
        # intentionally not checked here, unlike session/segment read methods.
        context.ensure_active()
        tenant = self._session_tenants.get(session_id)
        if tenant is not None and tenant != context.tenant_id:
            raise TenantAccessDenied("会话不属于当前租户", session_id=str(session_id))
        session = self._sessions.get((context.tenant_id, session_id))
        if session is None:
            raise ResourceNotFound("会话不存在", session_id=str(session_id))
        return SessionStatusResponse(
            session_id=session_id,
            validity_status=session.validity_status,
            ingest_status=session.ingest_status,
        )

    def events(self, event_type: str) -> tuple[EventEnvelope, ...]:
        return tuple(event for event in self._events if event.event_type == event_type)

    def problem_types(self, tenant_id: UUID, session_id: UUID) -> list[str]:
        return [
            problem_type
            for tenant, current_session, problem_type in self._problems
            if tenant == tenant_id and current_session == session_id
        ]
