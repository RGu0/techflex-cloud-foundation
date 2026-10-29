"""Tenant activation, login, refresh rotation, and access capability service."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from typing import Any
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.access_control import (
    AccessCapabilities,
    AccountState,
    ActivateAccountRequest,
    ActivateAccountResponse,
    InventoryActivationRequest,
    LicenseDocumentV2,
    LicenseState,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    RefreshRequest,
    RefreshResponse,
    SignedLicenseV2,
)
from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.platform_errors import AuthenticationError
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    RefreshTokenFactory,
    TenantAccessContext,
    TenantAccessTokenIssuer,
    reject_local_test_license,
)

from .passwords import hash_password, verify_password
from .platform_service import _add_months, normalize_login_name
from .repository import (
    AccessActivationRejected,
    AccessGroupSeed,
    AccessRepository,
    AuthenticationAttemptRecord,
    HardwareAssetRecord,
    InventoryActivationSeed,
    LicenseEntitlementRecord,
    RefreshSessionRecord,
    TenantAccountRecord,
    TenantSeed,
)


class TenantAuthenticationRejected(AuthenticationError):
    code = "E-ACC-401"
    action = "VERIFY_CREDENTIALS"


class TenantAuthenticationService:
    _FAILED_WINDOW = timedelta(minutes=15)
    _LOCK_DURATION = timedelta(minutes=15)
    _FAILED_LIMIT = 5
    _REFRESH_IDLE = timedelta(days=30)
    _REFRESH_ABSOLUTE = timedelta(days=180)
    _ACCESS_TTL = timedelta(minutes=15)

    def __init__(
        self,
        repository: AccessRepository,
        *,
        login_lookup_hmac_key: bytes,
        activation_hmac_key: bytes,
        tenant_tokens: TenantAccessTokenIssuer,
        refresh_tokens: RefreshTokenFactory,
        license_signer: LicenseDocumentSigner,
        now: Any = None,
    ) -> None:
        if len(login_lookup_hmac_key) < 32:
            raise ValueError("login lookup key must contain at least 32 bytes")
        if len(activation_hmac_key) < 32:
            raise ValueError("activation key must contain at least 32 bytes")
        self._repository = repository
        self._login_lookup_hmac_key = login_lookup_hmac_key
        self._activation_hmac_key = activation_hmac_key
        self._tenant_tokens = tenant_tokens
        self._refresh_tokens = refresh_tokens
        self._license_signer = license_signer
        self._now = now or (lambda: datetime.now(UTC))

    def login_name_digest(self, account_name: str) -> bytes:
        return hmac.new(
            self._login_lookup_hmac_key,
            normalize_login_name(account_name).encode("utf-8"),
            hashlib.sha256,
        ).digest()

    def _activation_digest(self, activation_code: str) -> bytes:
        return hmac.new(
            self._activation_hmac_key,
            activation_code.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    async def _ensure_not_rate_limited(
        self,
        *,
        login_name_hmac: bytes,
        source_fingerprint: bytes,
        now: datetime,
    ) -> None:
        failures = await self._repository.failed_authentication_attempts(
            login_name_hmac=login_name_hmac,
            source_fingerprint=source_fingerprint,
            since=now - self._FAILED_WINDOW,
        )
        if failures >= self._FAILED_LIMIT:
            raise TenantAuthenticationRejected("authentication temporarily unavailable")

    async def _record_attempt(
        self,
        *,
        login_name_hmac: bytes,
        source_fingerprint: bytes,
        attempt_kind: str,
        succeeded: bool,
        attempted_at: datetime,
    ) -> None:
        await self._repository.record_authentication_attempt(
            AuthenticationAttemptRecord(
                authentication_attempt_id=uuid4(),
                login_name_hmac=login_name_hmac,
                source_fingerprint=source_fingerprint,
                attempt_kind=attempt_kind,
                succeeded=succeeded,
                attempted_at=attempted_at,
            )
        )

    async def activate(
        self,
        request: ActivateAccountRequest,
        *,
        source_fingerprint: bytes,
    ) -> ActivateAccountResponse:
        reject_local_test_license(request.activation_code)
        now = self._now()
        login_digest = self.login_name_digest(request.account_name)
        await self._ensure_not_rate_limited(
            login_name_hmac=login_digest,
            source_fingerprint=source_fingerprint,
            now=now,
        )
        succeeded = False
        try:
            account = await self._repository.account_by_login_hmac(login_digest)
            if account is None:
                raise AccessActivationRejected("activation credentials do not match")
            group = await self._repository.active_group_for_account(account.account_id)
            license_record = await self._repository.license(group.license_id)
            hardware = await self._repository.hardware(group.hardware_id)
            document = LicenseDocumentV2(
                tenant_id=account.tenant_id,
                account_id=account.account_id,
                license_id=license_record.license_id,
                hardware_id=hardware.stable_identity,
                status=LicenseState.ACTIVE,
                issued_at=now,
                valid_from=license_record.valid_from,
                valid_until=license_record.valid_until,
                version=license_record.version,
                enabled_features=license_record.enabled_features,
            )
            signed = self._license_signer.sign(document)
            activated = await self._repository.activate_account_atomically(
                login_name_hmac=login_digest,
                activation_code_hash=self._activation_digest(request.activation_code),
                hardware_identity=request.hardware_id,
                password_hash=hash_password(request.password),
                installation_id=request.client_installation_id,
                activated_at=now,
                license_key_id=signed.key_id,
                license_document_json=canonical_json_bytes(document).decode("utf-8"),
                license_signature=signed.signature,
            )
            fields = await self._new_session_fields(
                account=activated.account,
                license_record=activated.license,
                hardware=activated.hardware,
                installation_id=request.client_installation_id,
                signed_license=signed,
                now=now,
            )
            succeeded = True
            return ActivateAccountResponse(
                account_state=activated.account.status,
                **fields,
            )
        except (AccessActivationRejected, ValueError) as exc:
            raise TenantAuthenticationRejected("account activation was rejected") from exc
        finally:
            await self._record_attempt(
                login_name_hmac=login_digest,
                source_fingerprint=source_fingerprint,
                attempt_kind="TENANT_ACTIVATION",
                succeeded=succeeded,
                attempted_at=now,
            )

    async def activate_inventory(
        self,
        request: InventoryActivationRequest,
        *,
        source_fingerprint: bytes,
    ) -> ActivateAccountResponse:
        """Bind an unassigned sales asset and License at its first use."""

        reject_local_test_license(request.activation_code)
        now = self._now()
        login_digest = self.login_name_digest(request.account_name)
        await self._ensure_not_rate_limited(
            login_name_hmac=login_digest,
            source_fingerprint=source_fingerprint,
            now=now,
        )
        succeeded = False
        try:
            tenant = TenantSeed(tenant_id=uuid4(), name=request.tenant_name)
            group = AccessGroupSeed(
                account_id=uuid4(),
                login_name_hmac=login_digest,
                account_display_name=normalize_login_name(request.account_name),
                license_id=uuid4(),
                hardware_id=uuid4(),
                hardware_identity=request.asset_serial,
                hardware_model="DO-P4864",
                activation_code_id=uuid4(),
                activation_code_hash=self._activation_digest(request.activation_code),
                activation_expires_at=now + timedelta(days=1),
                license_valid_from=now,
                license_valid_until=_add_months(now, 12),
                enabled_features=("reports.view", "screening.start", "sync.upload"),
            )
            document = LicenseDocumentV2(
                tenant_id=tenant.tenant_id,
                account_id=group.account_id,
                license_id=group.license_id,
                hardware_id=request.asset_serial,
                status=LicenseState.ACTIVE,
                issued_at=now,
                valid_from=group.license_valid_from,
                valid_until=group.license_valid_until,
                version=1,
                enabled_features=group.enabled_features,
            )
            signed = self._license_signer.sign(document)
            activated = await self._repository.activate_inventory_atomically(
                seed=InventoryActivationSeed(
                    tenant=tenant, group=group, asset_serial=request.asset_serial
                ),
                activation_code_hash=group.activation_code_hash,
                password_hash=hash_password(request.password),
                installation_id=request.client_installation_id,
                activated_at=now,
                license_key_id=signed.key_id,
                license_document_json=canonical_json_bytes(document).decode("utf-8"),
                license_signature=signed.signature,
            )
            fields = await self._new_session_fields(
                account=activated.account,
                license_record=activated.license,
                hardware=activated.hardware,
                installation_id=request.client_installation_id,
                signed_license=signed,
                now=now,
            )
            succeeded = True
            return ActivateAccountResponse(account_state=activated.account.status, **fields)
        except (AccessActivationRejected, ValueError) as exc:
            raise TenantAuthenticationRejected("inventory activation was rejected") from exc
        finally:
            await self._record_attempt(
                login_name_hmac=login_digest,
                source_fingerprint=source_fingerprint,
                attempt_kind="TENANT_ACTIVATION",
                succeeded=succeeded,
                attempted_at=now,
            )

    async def login(
        self,
        request: LoginRequest,
        *,
        source_fingerprint: bytes,
    ) -> LoginResponse:
        now = self._now()
        login_digest = self.login_name_digest(request.account_name)
        await self._ensure_not_rate_limited(
            login_name_hmac=login_digest,
            source_fingerprint=source_fingerprint,
            now=now,
        )
        succeeded = False
        try:
            account = await self._repository.account_by_login_hmac(login_digest)
            if (
                account is None
                or account.status is not AccountState.ACTIVE
                or account.password_hash is None
                or not verify_password(request.password, account.password_hash)
            ):
                raise TenantAuthenticationRejected("account credentials were rejected")
            group = await self._repository.active_group_for_account(account.account_id)
            license_record = await self._repository.license(group.license_id)
            hardware = await self._repository.hardware(group.hardware_id)
            await self._repository.register_or_touch_installation(
                tenant_id=account.tenant_id,
                account_id=account.account_id,
                installation_id=request.client_installation_id,
                seen_at=now,
            )
            signed = self._stored_signed_license(license_record)
            fields = await self._new_session_fields(
                account=account,
                license_record=license_record,
                hardware=hardware,
                installation_id=request.client_installation_id,
                signed_license=signed,
                now=now,
            )
            succeeded = True
            return LoginResponse(account_state=account.status, **fields)
        except TenantAuthenticationRejected:
            raise
        except Exception as exc:
            raise TenantAuthenticationRejected("account credentials were rejected") from exc
        finally:
            await self._record_attempt(
                login_name_hmac=login_digest,
                source_fingerprint=source_fingerprint,
                attempt_kind="TENANT_LOGIN",
                succeeded=succeeded,
                attempted_at=now,
            )

    async def refresh(self, request: RefreshRequest) -> RefreshResponse:
        now = self._now()
        current_hash = self._refresh_tokens.digest(request.refresh_token)
        current = await self._repository.refresh_session_by_hash(current_hash)
        if (
            current is None
            or current.client_installation_id != request.client_installation_id
            or current.rotated_at is not None
            or current.revoked_at is not None
            or current.idle_expires_at <= now
            or current.absolute_expires_at <= now
        ):
            raise TenantAuthenticationRejected("refresh credential was rejected")
        try:
            account = await self._repository.account(current.account_id)
            if account.status is not AccountState.ACTIVE:
                raise TenantAuthenticationRejected("account is not active")
            group = await self._repository.active_group_for_account(account.account_id)
            license_record = await self._repository.license(group.license_id)
            hardware = await self._repository.hardware(group.hardware_id)
            signed = self._stored_signed_license(license_record)
            issued_refresh = self._refresh_tokens.issue()
            idle_expires_at = min(now + self._REFRESH_IDLE, current.absolute_expires_at)
            replacement = RefreshSessionRecord(
                refresh_session_id=uuid4(),
                tenant_id=current.tenant_id,
                account_id=current.account_id,
                client_installation_id=current.client_installation_id,
                refresh_token_hash=issued_refresh.token_hash,
                issued_at=now,
                last_used_at=now,
                idle_expires_at=idle_expires_at,
                absolute_expires_at=current.absolute_expires_at,
            )
            await self._repository.rotate_refresh_session(
                current_token_hash=current_hash,
                expected_installation_id=request.client_installation_id,
                replacement=replacement,
                rotated_at=now,
            )
            fields = self._session_fields(
                account=account,
                license_record=license_record,
                hardware=hardware,
                installation_id=request.client_installation_id,
                signed_license=signed,
                raw_refresh_token=issued_refresh.raw_token,
                refresh_session=replacement,
                now=now,
            )
            return RefreshResponse(**fields)
        except TenantAuthenticationRejected:
            raise
        except Exception as exc:
            raise TenantAuthenticationRejected("refresh credential was rejected") from exc

    async def logout(self, request: LogoutRequest) -> None:
        await self._repository.revoke_refresh_session(
            self._refresh_tokens.digest(request.refresh_token),
            revoked_at=self._now(),
        )

    async def current_license(self, context: TenantAccessContext) -> SignedLicenseV2:
        if context.expires_at <= self._now():
            raise TenantAuthenticationRejected("tenant access token is expired")
        license_record = await self._repository.license(context.license_id)
        group = await self._repository.access_group_for_license(context.license_id)
        hardware = await self._repository.hardware(group.hardware_id)
        if (
            group.tenant_id != context.tenant_id
            or group.account_id != context.account_id
            or hardware.stable_identity != context.hardware_id
        ):
            raise TenantAuthenticationRejected("tenant License context does not match")
        return self._stored_signed_license(license_record)

    async def _new_session_fields(
        self,
        *,
        account: TenantAccountRecord,
        license_record: LicenseEntitlementRecord,
        hardware: HardwareAssetRecord,
        installation_id: UUID,
        signed_license: SignedLicenseV2,
        now: datetime,
    ) -> dict[str, Any]:
        issued_refresh = self._refresh_tokens.issue()
        refresh_session = RefreshSessionRecord(
            refresh_session_id=uuid4(),
            tenant_id=account.tenant_id,
            account_id=account.account_id,
            client_installation_id=installation_id,
            refresh_token_hash=issued_refresh.token_hash,
            issued_at=now,
            last_used_at=now,
            idle_expires_at=now + self._REFRESH_IDLE,
            absolute_expires_at=now + self._REFRESH_ABSOLUTE,
        )
        await self._repository.create_refresh_session(refresh_session)
        return self._session_fields(
            account=account,
            license_record=license_record,
            hardware=hardware,
            installation_id=installation_id,
            signed_license=signed_license,
            raw_refresh_token=issued_refresh.raw_token,
            refresh_session=refresh_session,
            now=now,
        )

    def _session_fields(
        self,
        *,
        account: TenantAccountRecord,
        license_record: LicenseEntitlementRecord,
        hardware: HardwareAssetRecord,
        installation_id: UUID,
        signed_license: SignedLicenseV2,
        raw_refresh_token: str,
        refresh_session: RefreshSessionRecord,
        now: datetime,
    ) -> dict[str, Any]:
        capabilities = self._capabilities(license_record, now=now)
        access_token = self._tenant_tokens.issue(
            tenant_id=account.tenant_id,
            account_id=account.account_id,
            license_id=license_record.license_id,
            hardware_id=hardware.stable_identity,
            client_installation_id=installation_id,
            token_version=account.token_version,
            capabilities=capabilities,
            now=now,
        )
        return {
            "tenant_id": account.tenant_id,
            "account_id": account.account_id,
            "license_id": license_record.license_id,
            "hardware_asset_id": hardware.hardware_id,
            "hardware_id": hardware.stable_identity,
            "client_installation_id": installation_id,
            "access_token": access_token,
            "access_token_expires_at": now + self._ACCESS_TTL,
            "refresh_token": raw_refresh_token,
            "refresh_idle_expires_at": refresh_session.idle_expires_at,
            "refresh_absolute_expires_at": refresh_session.absolute_expires_at,
            "signed_license": signed_license,
            "capabilities": capabilities,
        }

    @staticmethod
    def _capabilities(
        license_record: LicenseEntitlementRecord,
        *,
        now: datetime,
    ) -> AccessCapabilities:
        allow_new = (
            license_record.status is LicenseState.ACTIVE
            and license_record.valid_from <= now < license_record.valid_until
            and "screening.start" in license_record.enabled_features
        )
        return AccessCapabilities(
            allow_new_test=allow_new,
            allow_upload=True,
            allow_report_view=True,
        )

    @staticmethod
    def _stored_signed_license(
        license_record: LicenseEntitlementRecord,
    ) -> SignedLicenseV2:
        if (
            license_record.key_id is None
            or license_record.document_json is None
            or license_record.signature is None
        ):
            raise TenantAuthenticationRejected("signed License is unavailable")
        document = LicenseDocumentV2.model_validate_json(license_record.document_json)
        return SignedLicenseV2(
            document=document,
            key_id=license_record.key_id,
            signature=license_record.signature,
        )


__all__ = ["TenantAuthenticationRejected", "TenantAuthenticationService"]
