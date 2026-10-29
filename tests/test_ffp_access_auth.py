from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import json
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from techflex_cloud_foundation.contracts.access_control import (
    AccessCapabilities,
    LicenseDocumentV2,
    LicenseState,
    PlatformRole,
    SignedLicenseV2,
)
from techflex_cloud_foundation.platform_errors import AuthenticationError
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessTokenIssuer,
    RefreshTokenFactory,
    TenantAccessTokenIssuer,
    reject_local_test_license,
)
from techflex_cloud_foundation.server.access_control.passwords import hash_password, verify_password

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
TENANT_ID = uuid4()
ACCOUNT_ID = uuid4()
LICENSE_ID = uuid4()
INSTALLATION_ID = uuid4()
PLATFORM_ID = uuid4()
HARDWARE_ID = "usb-serial-0123456789abcdef0123"


def test_password_hash_is_salted_versioned_and_verifiable() -> None:
    first = hash_password("correct-horse-battery-staple")
    second = hash_password("correct-horse-battery-staple")

    assert first.startswith("$ffp-scrypt$1$")
    assert first != second
    assert verify_password("correct-horse-battery-staple", first)
    assert not verify_password("wrong-password", first)
    assert not verify_password("correct-horse-battery-staple", "malformed")


def test_tenant_token_has_fixed_audience_and_15_minute_expiry() -> None:
    issuer = TenantAccessTokenIssuer(
        secret=b"tenant-token-secret-must-be-at-least-32-bytes",
        key_id="tenant/1",
    )

    token = issuer.issue(
        tenant_id=TENANT_ID,
        account_id=ACCOUNT_ID,
        license_id=LICENSE_ID,
        hardware_id=HARDWARE_ID,
        client_installation_id=INSTALLATION_ID,
        token_version=3,
        capabilities=AccessCapabilities(
            allow_new_test=True,
            allow_upload=True,
            allow_report_view=True,
        ),
        now=NOW,
    )
    context = issuer.verify(token, now=NOW + timedelta(minutes=14, seconds=59))

    assert context.tenant_id == TENANT_ID
    assert context.expires_at == NOW + timedelta(minutes=15)
    with pytest.raises(AuthenticationError):
        issuer.verify(token, now=NOW + timedelta(minutes=15))


def test_tenant_token_carries_cp03_sub_claim_for_realm_authority() -> None:
    issuer = TenantAccessTokenIssuer(
        secret=b"tenant-token-secret-must-be-at-least-32-bytes",
        key_id="tenant/1",
    )

    token = issuer.issue(
        tenant_id=TENANT_ID,
        account_id=ACCOUNT_ID,
        license_id=LICENSE_ID,
        hardware_id=HARDWARE_ID,
        client_installation_id=INSTALLATION_ID,
        token_version=3,
        capabilities=AccessCapabilities(
            allow_new_test=True,
            allow_upload=True,
            allow_report_view=True,
        ),
        now=NOW,
    )

    _, encoded_payload, _ = token.split(".")
    payload = json.loads(
        base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4))
    )
    assert payload["sub"] == str(ACCOUNT_ID)
    assert payload["account_id"] == str(ACCOUNT_ID)
    assert payload["tenant_id"] == str(TENANT_ID)


def test_platform_and_tenant_tokens_are_not_interchangeable() -> None:
    secret = b"shared-by-test-but-audiences-still-separate-32"
    tenant_issuer = TenantAccessTokenIssuer(secret=secret, key_id="tenant/1")
    platform_issuer = PlatformAccessTokenIssuer(secret=secret, key_id="platform/1")
    platform_token = platform_issuer.issue(
        platform_identity_id=PLATFORM_ID,
        roles=(PlatformRole.OWNER, PlatformRole.SUPPORT),
        token_version=1,
        now=NOW,
    )

    context = platform_issuer.verify(platform_token, now=NOW)
    assert context.roles == frozenset({PlatformRole.OWNER, PlatformRole.SUPPORT})
    with pytest.raises(AuthenticationError):
        tenant_issuer.verify(platform_token, now=NOW)


def test_refresh_token_exposes_random_value_once_and_hashes_with_key() -> None:
    factory = RefreshTokenFactory(
        digest_key=b"refresh-digest-secret-must-be-at-least-32-bytes"
    )

    first = factory.issue()
    second = factory.issue()

    assert first.raw_token != second.raw_token
    assert len(first.token_hash) == 32
    assert first.token_hash == factory.digest(first.raw_token)
    assert first.raw_token.encode() not in first.token_hash


def test_license_signature_and_binding_detect_any_mutation() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signer = LicenseDocumentSigner(
        private_key=private_key,
        key_id="license/2-key-1",
        public_keys={"license/2-key-1": public_key},
    )
    document = LicenseDocumentV2(
        tenant_id=TENANT_ID,
        account_id=ACCOUNT_ID,
        license_id=LICENSE_ID,
        hardware_id=HARDWARE_ID,
        status=LicenseState.ACTIVE,
        issued_at=NOW,
        valid_from=NOW,
        valid_until=NOW + timedelta(days=365),
        version=1,
        enabled_features=("screening.start",),
    )
    signed = signer.sign(document)

    assert signer.verify(signed) == document
    mutated = SignedLicenseV2(
        document=document.model_copy(update={"version": 2}),
        key_id=signed.key_id,
        signature=signed.signature,
    )
    with pytest.raises(ValueError, match="signature"):
        signer.verify(mutated)


def test_local_ui_test_license_is_rejected_at_cloud_boundary() -> None:
    with pytest.raises(AuthenticationError):
        reject_local_test_license("FFP-2026-TEST-0001")

    reject_local_test_license("real-one-time-activation-code")
