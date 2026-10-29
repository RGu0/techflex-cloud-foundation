"""Institutional multi-terminal activation, refresh rotation and management.

RAY-656 R2: an ACTIVE institutional account activates several terminals
without an activation code. Each terminal consumes one seat of the account
License (``terminal_seats``), owns an independent refresh family, and is
revoked individually. A rotated refresh token replayed within
``TERMINAL_REFRESH_REPLAY_GRACE_SECONDS`` returns the identical successor;
any later replay revokes the whole family.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from typing import Any, cast
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.access_control import (
    AccessCapabilities,
    AccountState,
    LicenseState,
)
from techflex_cloud_foundation.contracts.terminal_access import (
    TERMINAL_REFRESH_REPLAY_GRACE_SECONDS,
    TerminalActivationRequest,
    TerminalCredentialResponse,
    TerminalLicenseDocument,
    TerminalListResponse,
    TerminalPlatform,
    TerminalRefreshRequest,
    TerminalRenameRequest,
    TerminalState,
    TerminalSummary,
)
from techflex_cloud_foundation.platform_errors import (
    ResourceNotFound,
    TerminalCredentialsRejected,
    TerminalInstallationConflict,
    TerminalLicenseInactive,
    TerminalRefreshExpired,
    TerminalRefreshInvalid,
    TerminalRefreshReplayed,
    TerminalRevoked,
    TerminalSeatLimitReached,
)
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    TerminalAccessContext,
    TerminalAccessTokenIssuer,
    TerminalRefreshTokenFactory,
)
from techflex_cloud_foundation.server.principal import IngestionPrincipal, terminal_access_principal

from .passwords import verify_password
from .platform_service import normalize_login_name
from .repository import (
    AccessRepository,
    AccessRepositoryError,
    AuthenticationAttemptRecord,
    LicenseEntitlementRecord,
    TerminalInstallationOwned,
    TerminalRecord,
    TerminalRefreshRace,
    TerminalRefreshSessionRecord,
    TerminalSeatsExhausted,
)


class TerminalAccessService:
    _FAILED_WINDOW = timedelta(minutes=15)
    _FAILED_LIMIT = 5
    _REFRESH_IDLE = timedelta(days=30)
    _REFRESH_ABSOLUTE = timedelta(days=180)
    _ACCESS_TTL = timedelta(minutes=15)
    _REPLAY_GRACE = timedelta(seconds=TERMINAL_REFRESH_REPLAY_GRACE_SECONDS)

    def __init__(
        self,
        repository: AccessRepository,
        *,
        login_lookup_hmac_key: bytes,
        terminal_tokens: TerminalAccessTokenIssuer,
        refresh_tokens: TerminalRefreshTokenFactory,
        license_signer: LicenseDocumentSigner,
        now: Any = None,
    ) -> None:
        if len(login_lookup_hmac_key) < 32:
            raise ValueError("login lookup key must contain at least 32 bytes")
        self._repository = repository
        self._login_lookup_hmac_key = login_lookup_hmac_key
        self._terminal_tokens = terminal_tokens
        self._refresh_tokens = refresh_tokens
        self._license_signer = license_signer
        self._now = now or (lambda: datetime.now(UTC))

    def _login_digest(self, account_name: str) -> bytes:
        return hmac.new(
            self._login_lookup_hmac_key,
            normalize_login_name(account_name).encode("utf-8"),
            hashlib.sha256,
        ).digest()

    async def activate(
        self,
        request: TerminalActivationRequest,
        *,
        source_fingerprint: bytes,
    ) -> TerminalCredentialResponse:
        now = self._now()
        login_digest = self._login_digest(request.account_name)
        failures = await self._repository.failed_authentication_attempts(
            login_name_hmac=login_digest,
            source_fingerprint=source_fingerprint,
            since=now - self._FAILED_WINDOW,
        )
        if failures >= self._FAILED_LIMIT:
            raise TerminalCredentialsRejected("authentication temporarily unavailable")
        verified = False
        try:
            account = await self._repository.account_by_login_hmac(login_digest)
            if (
                account is None
                or account.status is not AccountState.ACTIVE
                or account.password_hash is None
                or not verify_password(request.password, account.password_hash)
            ):
                raise TerminalCredentialsRejected("account credentials were rejected")
            verified = True
        finally:
            await self._repository.record_authentication_attempt(
                AuthenticationAttemptRecord(
                    authentication_attempt_id=uuid4(),
                    login_name_hmac=login_digest,
                    source_fingerprint=source_fingerprint,
                    attempt_kind="TERMINAL_ACTIVATION",
                    succeeded=verified,
                    attempted_at=now,
                )
            )
        try:
            group = await self._repository.active_group_for_account(account.account_id)
            license_record = await self._repository.license(group.license_id)
        except AccessRepositoryError as exc:
            raise TerminalLicenseInactive("account has no active License") from exc
        if not self._license_usable(license_record, now=now):
            raise TerminalLicenseInactive("account License is not active")
        terminal = TerminalRecord(
            tenant_id=account.tenant_id,
            client_installation_id=request.client_installation_id,
            account_id=account.account_id,
            license_id=license_record.license_id,
            terminal_name=request.terminal_name,
            platform=request.platform.value,
            status=TerminalState.ACTIVE.value,
            refresh_family_id=uuid4(),
            activated_at=now,
        )
        session_id = uuid4()
        issued = self._refresh_tokens.derive(session_id)
        session = TerminalRefreshSessionRecord(
            refresh_session_id=session_id,
            tenant_id=terminal.tenant_id,
            account_id=terminal.account_id,
            client_installation_id=terminal.client_installation_id,
            refresh_family_id=terminal.refresh_family_id,
            refresh_token_hash=issued.token_hash,
            issued_at=now,
            idle_expires_at=now + self._REFRESH_IDLE,
            absolute_expires_at=now + self._REFRESH_ABSOLUTE,
        )
        try:
            terminal = await self._repository.activate_terminal_atomically(
                terminal=terminal, session=session
            )
        except TerminalSeatsExhausted as exc:
            raise TerminalSeatLimitReached("all terminal seats are in use") from exc
        except TerminalInstallationOwned as exc:
            raise TerminalInstallationConflict(
                "client_installation_id belongs to another account"
            ) from exc
        return self._credentials(
            terminal=terminal,
            license_record=license_record,
            session=session,
            raw_refresh_token=issued.raw_token,
            now=now,
        )

    async def refresh(self, request: TerminalRefreshRequest) -> TerminalCredentialResponse:
        token_hash = self._refresh_tokens.digest(request.refresh_token)
        # One retry: a concurrent rotation of the same token is reclassified,
        # which turns the losing request into an in-grace idempotent replay.
        for _ in range(2):
            try:
                return await self._refresh_once(request, token_hash)
            except TerminalRefreshRace:
                continue
        raise TerminalRefreshInvalid("refresh credential was rejected")

    async def _refresh_once(
        self, request: TerminalRefreshRequest, token_hash: bytes
    ) -> TerminalCredentialResponse:
        now = self._now()
        current = await self._repository.terminal_refresh_by_hash(token_hash)
        if current is None or current.client_installation_id != request.client_installation_id:
            raise TerminalRefreshInvalid("refresh credential was rejected")
        terminal = await self._repository.terminal(current.client_installation_id)
        if (
            terminal is None
            or terminal.tenant_id != current.tenant_id
            or terminal.account_id != current.account_id
        ):
            raise TerminalRefreshInvalid("refresh credential was rejected")
        if (
            terminal.status != TerminalState.ACTIVE.value
            or current.revoke_reason == "TERMINAL_REVOKED"
        ):
            raise TerminalRevoked("terminal was revoked")
        if current.revoke_reason == "REFRESH_REPLAYED":
            raise TerminalRefreshReplayed("refresh family was revoked after replay")
        if current.revoked_at is not None:
            raise TerminalRefreshInvalid("refresh credential was superseded")
        if current.rotated_at is not None:
            return await self._replayed(current, terminal=terminal, now=now)
        if current.idle_expires_at <= now or current.absolute_expires_at <= now:
            raise TerminalRefreshExpired("refresh credential expired")
        account = await self._repository.account(terminal.account_id)
        if account.status is not AccountState.ACTIVE:
            raise TerminalRevoked("account is not active")
        license_record = await self._repository.license(terminal.license_id)
        replacement_id = uuid4()
        issued = self._refresh_tokens.derive(replacement_id)
        replacement = TerminalRefreshSessionRecord(
            refresh_session_id=replacement_id,
            tenant_id=current.tenant_id,
            account_id=current.account_id,
            client_installation_id=current.client_installation_id,
            refresh_family_id=current.refresh_family_id,
            refresh_token_hash=issued.token_hash,
            issued_at=now,
            idle_expires_at=min(now + self._REFRESH_IDLE, current.absolute_expires_at),
            absolute_expires_at=current.absolute_expires_at,
        )
        await self._repository.rotate_terminal_refresh(
            current_token_hash=token_hash,
            replacement=replacement,
            rotated_at=now,
        )
        return self._credentials(
            terminal=terminal,
            license_record=license_record,
            session=replacement,
            raw_refresh_token=issued.raw_token,
            now=now,
        )

    async def _replayed(
        self,
        current: TerminalRefreshSessionRecord,
        *,
        terminal: TerminalRecord,
        now: datetime,
    ) -> TerminalCredentialResponse:
        successor = (
            None
            if current.replaced_by_session_id is None
            else await self._repository.terminal_refresh_session(
                tenant_id=current.tenant_id,
                refresh_session_id=current.replaced_by_session_id,
            )
        )
        in_grace = (
            current.rotated_at is not None
            and now - current.rotated_at <= self._REPLAY_GRACE
            and successor is not None
            and successor.rotated_at is None
            and successor.revoked_at is None
            and successor.idle_expires_at > now
        )
        if not in_grace:
            await self._repository.revoke_terminal_refresh_family(
                tenant_id=current.tenant_id,
                client_installation_id=current.client_installation_id,
                refresh_family_id=current.refresh_family_id,
                reason="REFRESH_REPLAYED",
                revoked_at=now,
            )
            raise TerminalRefreshReplayed("rotated refresh credential was replayed")
        license_record = await self._repository.license(terminal.license_id)
        successor = cast(TerminalRefreshSessionRecord, successor)
        return self._credentials(
            terminal=terminal,
            license_record=license_record,
            session=successor,
            raw_refresh_token=self._refresh_tokens.derive(successor.refresh_session_id).raw_token,
            now=now,
        )

    async def _active_caller(self, context: TerminalAccessContext) -> TerminalRecord:
        terminal = await self._repository.terminal(context.client_installation_id)
        if (
            terminal is None
            or terminal.tenant_id != context.tenant_id
            or terminal.account_id != context.account_id
            or terminal.status != TerminalState.ACTIVE.value
        ):
            raise TerminalRevoked("terminal was revoked")
        return terminal

    async def data_principal(self, context: TerminalAccessContext) -> IngestionPrincipal:
        """Data-plane principal for an ACTIVE terminal (RAY-728 D1/D6)."""
        caller = await self._active_caller(context)
        license_record = await self._repository.license(caller.license_id)
        allow_new = (
            self._license_usable(license_record, now=self._now())
            and "screening.start" in license_record.enabled_features
        )
        return terminal_access_principal(
            context, license_id=caller.license_id, allow_new_test=allow_new
        )

    async def list_terminals(self, context: TerminalAccessContext) -> TerminalListResponse:
        caller = await self._active_caller(context)
        license_record = await self._repository.license(caller.license_id)
        rows = await self._repository.terminals_for_account(
            tenant_id=caller.tenant_id, account_id=caller.account_id
        )
        return TerminalListResponse(
            license_id=license_record.license_id,
            seats=license_record.terminal_seats,
            seats_used=sum(
                row.status == TerminalState.ACTIVE.value
                and row.license_id == license_record.license_id
                for row in rows
            ),
            terminals=tuple(self._summary(row) for row in rows),
        )

    async def rename_terminal(
        self,
        context: TerminalAccessContext,
        client_installation_id: UUID,
        request: TerminalRenameRequest,
    ) -> TerminalSummary:
        caller = await self._active_caller(context)
        try:
            renamed = await self._repository.rename_terminal(
                tenant_id=caller.tenant_id,
                account_id=caller.account_id,
                client_installation_id=client_installation_id,
                terminal_name=request.terminal_name,
            )
        except AccessRepositoryError as exc:
            raise ResourceNotFound("terminal does not exist") from exc
        return self._summary(renamed)

    async def revoke_terminal(
        self, context: TerminalAccessContext, client_installation_id: UUID
    ) -> TerminalSummary:
        caller = await self._active_caller(context)
        try:
            revoked = await self._repository.revoke_terminal(
                tenant_id=caller.tenant_id,
                account_id=caller.account_id,
                client_installation_id=client_installation_id,
                revoked_at=self._now(),
            )
        except AccessRepositoryError as exc:
            raise ResourceNotFound("terminal does not exist") from exc
        return self._summary(revoked)

    @staticmethod
    def _license_usable(license_record: LicenseEntitlementRecord, *, now: datetime) -> bool:
        return (
            license_record.status is LicenseState.ACTIVE
            and license_record.valid_from <= now < license_record.valid_until
        )

    @staticmethod
    def _summary(terminal: TerminalRecord) -> TerminalSummary:
        return TerminalSummary(
            client_installation_id=terminal.client_installation_id,
            terminal_name=terminal.terminal_name,
            platform=TerminalPlatform(terminal.platform),
            status=TerminalState(terminal.status),
            activated_at=terminal.activated_at,
            last_refreshed_at=terminal.last_refreshed_at,
            revoked_at=terminal.revoked_at,
        )

    def _credentials(
        self,
        *,
        terminal: TerminalRecord,
        license_record: LicenseEntitlementRecord,
        session: TerminalRefreshSessionRecord,
        raw_refresh_token: str,
        now: datetime,
    ) -> TerminalCredentialResponse:
        document = TerminalLicenseDocument(
            tenant_id=terminal.tenant_id,
            account_id=terminal.account_id,
            license_id=license_record.license_id,
            status=license_record.status,
            issued_at=now,
            valid_from=license_record.valid_from,
            valid_until=license_record.valid_until,
            version=license_record.version,
            enabled_features=license_record.enabled_features,
            seats=license_record.terminal_seats,
        )
        allow_new = (
            self._license_usable(license_record, now=now)
            and "screening.start" in license_record.enabled_features
        )
        return TerminalCredentialResponse(
            tenant_id=terminal.tenant_id,
            account_id=terminal.account_id,
            license_id=license_record.license_id,
            client_installation_id=terminal.client_installation_id,
            terminal_name=terminal.terminal_name,
            platform=TerminalPlatform(terminal.platform),
            access_token=self._terminal_tokens.issue(
                tenant_id=terminal.tenant_id,
                account_id=terminal.account_id,
                license_id=license_record.license_id,
                client_installation_id=terminal.client_installation_id,
                now=now,
            ),
            access_token_expires_at=now + self._ACCESS_TTL,
            refresh_token=raw_refresh_token,
            refresh_idle_expires_at=session.idle_expires_at,
            refresh_absolute_expires_at=session.absolute_expires_at,
            signed_license=self._license_signer.sign_terminal(document),
            capabilities=AccessCapabilities(
                allow_new_test=allow_new,
                allow_upload=True,
                allow_report_view=True,
            ),
        )


__all__ = ["TerminalAccessService"]
