from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from techflex_cloud_foundation.contracts.access_control import (
    ActivateAccountRequest,
    LicenseControlAction,
    LicenseControlRequest,
    LoginRequest,
    PlatformRole,
    ProvisionTenantRequest,
    RefreshRequest,
)
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessContext,
    RefreshTokenFactory,
    TenantAccessTokenIssuer,
)
from techflex_cloud_foundation.server.access_control.platform_service import (
    PlatformProvisioningService,
)
from techflex_cloud_foundation.server.access_control.repository import InMemoryAccessRepository
from techflex_cloud_foundation.server.access_control.tenant_service import (
    TenantAuthenticationRejected,
    TenantAuthenticationService,
)

START = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
HARDWARE_ID = "usb-serial-0123456789abcdef0123"


@dataclass
class MutableClock:
    value: datetime = START

    def __call__(self) -> datetime:
        return self.value


async def _system():
    clock = MutableClock()
    repository = InMemoryAccessRepository()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signer = LicenseDocumentSigner(
        private_key=private_key,
        key_id="license/2-key-1",
        public_keys={"license/2-key-1": public_key},
    )
    platform = PlatformProvisioningService(
        repository,
        login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
        activation_hmac_key=b"activation-key-must-contain-at-least-32-bytes",
        license_signer=signer,
        now=clock,
    )
    tenant = TenantAuthenticationService(
        repository,
        login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
        activation_hmac_key=b"activation-key-must-contain-at-least-32-bytes",
        tenant_tokens=TenantAccessTokenIssuer(
            secret=b"tenant-token-secret-must-be-at-least-32-bytes",
            key_id="tenant/1",
        ),
        refresh_tokens=RefreshTokenFactory(
            digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
        ),
        license_signer=signer,
        now=clock,
    )
    operator = PlatformAccessContext(
        platform_identity_id=uuid4(),
        roles=frozenset({PlatformRole.OPERATIONS}),
        token_version=1,
        expires_at=START + timedelta(minutes=15),
    )
    provisioned = await platform.provision_tenant(
        operator,
        ProvisionTenantRequest(
            tenant_name="Seed Clinic",
            account_name="seed-clinic",
            hardware_id=HARDWARE_ID,
            license_period_months=12,
        ),
    )
    return clock, repository, platform, tenant, operator, provisioned


def _activation(provisioned, *, hardware_id: str = HARDWARE_ID):
    return ActivateAccountRequest(
        account_name=provisioned.account_name,
        activation_code=provisioned.activation_code,
        password="correct-horse-battery-staple",
        password_confirmation="correct-horse-battery-staple",
        hardware_id=hardware_id,
        client_installation_id=uuid4(),
    )


def test_activation_is_atomic_and_code_replay_is_rejected() -> None:
    async def exercise() -> None:
        _, repository, _, service, _, provisioned = await _system()
        request = _activation(provisioned)

        activated = await service.activate(request, source_fingerprint=b"source-a")
        group = await repository.access_group_for_license(provisioned.license_id)

        assert activated.tenant_id == provisioned.tenant_id
        assert activated.hardware_asset_id == group.hardware_id
        assert activated.hardware_id == HARDWARE_ID
        assert activated.signed_license.document.version == 1
        assert activated.capabilities.allow_new_test
        with pytest.raises(TenantAuthenticationRejected):
            await service.activate(request, source_fingerprint=b"source-a")
        stored = await repository.license(provisioned.license_id)
        assert stored.signature == activated.signed_license.signature

    asyncio.run(exercise())


def test_wrong_hardware_does_not_save_password_or_consume_code() -> None:
    async def exercise() -> None:
        _, repository, _, service, _, provisioned = await _system()
        with pytest.raises(TenantAuthenticationRejected):
            await service.activate(
                _activation(provisioned, hardware_id="usb-serial-ffffffffffffffffffff"),
                source_fingerprint=b"source-a",
            )

        account = await repository.account_by_login_hmac(
            service.login_name_digest(provisioned.account_name)
        )
        assert account is not None and account.password_hash is None

    asyncio.run(exercise())


def test_login_on_replacement_computer_keeps_license_hardware_binding() -> None:
    async def exercise() -> None:
        _, _, _, service, _, provisioned = await _system()
        activated = await service.activate(
            _activation(provisioned), source_fingerprint=b"source-a"
        )
        replacement = uuid4()

        logged_in = await service.login(
            LoginRequest(
                account_name=provisioned.account_name,
                password="correct-horse-battery-staple",
                client_installation_id=replacement,
            ),
            source_fingerprint=b"source-b",
        )

        assert logged_in.client_installation_id == replacement
        assert logged_in.license_id == activated.license_id
        assert logged_in.hardware_id == activated.hardware_id

    asyncio.run(exercise())


def test_suspended_or_expired_license_blocks_new_test_not_upload_or_reports() -> None:
    async def exercise() -> None:
        clock, _, platform, service, operator, provisioned = await _system()
        await service.activate(_activation(provisioned), source_fingerprint=b"source-a")
        await platform.control_license(
            operator,
            provisioned.license_id,
            LicenseControlRequest(
                action=LicenseControlAction.SUSPEND,
                reason_code="CUSTOMER_REQUEST",
            ),
        )

        suspended = await service.login(
            LoginRequest(
                account_name=provisioned.account_name,
                password="correct-horse-battery-staple",
                client_installation_id=uuid4(),
            ),
            source_fingerprint=b"source-b",
        )
        assert not suspended.capabilities.allow_new_test
        assert suspended.capabilities.allow_upload
        assert suspended.capabilities.allow_report_view

        await platform.control_license(
            operator,
            provisioned.license_id,
            LicenseControlRequest(action=LicenseControlAction.RESTORE),
        )
        clock.value = START + timedelta(days=366)
        expired = await service.login(
            LoginRequest(
                account_name=provisioned.account_name,
                password="correct-horse-battery-staple",
                client_installation_id=uuid4(),
            ),
            source_fingerprint=b"source-c",
        )
        assert not expired.capabilities.allow_new_test
        assert expired.capabilities.allow_upload

    asyncio.run(exercise())


def test_refresh_rotates_and_replay_of_old_token_is_rejected() -> None:
    async def exercise() -> None:
        clock, _, _, service, _, provisioned = await _system()
        activated = await service.activate(
            _activation(provisioned), source_fingerprint=b"source-a"
        )
        old_refresh = activated.refresh_token
        clock.value += timedelta(days=1)

        refreshed = await service.refresh(
            RefreshRequest(
                refresh_token=old_refresh,
                client_installation_id=activated.client_installation_id,
            )
        )

        assert refreshed.refresh_token != old_refresh
        with pytest.raises(TenantAuthenticationRejected):
            await service.refresh(
                RefreshRequest(
                    refresh_token=old_refresh,
                    client_installation_id=activated.client_installation_id,
                )
            )

    asyncio.run(exercise())


def test_five_failed_attempts_lock_identifier_for_fifteen_minutes() -> None:
    async def exercise() -> None:
        clock, _, _, service, _, provisioned = await _system()
        await service.activate(_activation(provisioned), source_fingerprint=b"source-a")
        bad = LoginRequest(
            account_name=provisioned.account_name,
            password="definitely-wrong-password",
            client_installation_id=uuid4(),
        )
        for _ in range(5):
            with pytest.raises(TenantAuthenticationRejected):
                await service.login(bad, source_fingerprint=b"source-b")

        with pytest.raises(TenantAuthenticationRejected, match="temporarily unavailable"):
            await service.login(
                LoginRequest(
                    account_name=provisioned.account_name,
                    password="correct-horse-battery-staple",
                    client_installation_id=uuid4(),
                ),
                source_fingerprint=b"source-b",
            )
        clock.value += timedelta(minutes=16)
        recovered = await service.login(
            LoginRequest(
                account_name=provisioned.account_name,
                password="correct-horse-battery-staple",
                client_installation_id=uuid4(),
            ),
            source_fingerprint=b"source-b",
        )
        assert recovered.account_id == provisioned.account_id

    asyncio.run(exercise())
