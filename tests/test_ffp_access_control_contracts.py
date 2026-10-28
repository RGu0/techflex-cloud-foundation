from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import ValidationError
import pytest

from techflex_cloud_foundation.contracts.access_control import (
    ActivateAccountRequest,
    LicenseDocumentV2,
    LicenseState,
    PlatformRole,
    ProvisionTenantRequest,
    RefreshRequest,
    SensitiveAccessGrantRequest,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
TENANT_ID = uuid4()
ACCOUNT_ID = uuid4()
LICENSE_ID = uuid4()
INSTALLATION_ID = uuid4()
HARDWARE_ID = "usb-serial-0123456789abcdef0123"


def test_license_document_binds_account_and_hardware_not_terminal() -> None:
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
        enabled_features=("screening.start", "reports.view"),
    )

    assert document.schema_version == "license/2"
    assert "terminal_id" not in document.model_dump()
    assert document.enabled_features == ("reports.view", "screening.start")


def test_platform_role_is_not_a_tenant_role() -> None:
    assert set(PlatformRole) == {
        PlatformRole.OWNER,
        PlatformRole.OPERATIONS,
        PlatformRole.SUPPORT,
        PlatformRole.ENGINEER,
    }


@pytest.mark.parametrize(
    "hardware_id",
    [
        "",
        "/dev/cu.usbserial-1",
        "usb-serial-short",
        "usb-serial-0123456789ABCDEF0123",
    ],
)
def test_hardware_identity_must_be_an_opaque_stable_usb_serial(hardware_id: str) -> None:
    with pytest.raises(ValidationError):
        ProvisionTenantRequest(
            tenant_name="Seed Clinic",
            account_name="seed-clinic",
            hardware_id=hardware_id,
            license_period_months=12,
        )


def test_provisioning_accepts_only_seed_license_periods() -> None:
    with pytest.raises(ValidationError):
        ProvisionTenantRequest(
            tenant_name="Seed Clinic",
            account_name="seed-clinic",
            hardware_id=HARDWARE_ID,
            license_period_months=1,
        )


def test_activation_requires_matching_password_confirmation() -> None:
    with pytest.raises(ValidationError, match="password confirmation"):
        ActivateAccountRequest(
            account_name="seed-clinic",
            activation_code="seed-activation-code-with-enough-entropy",
            password="long-enough-password",
            password_confirmation="different-password",
            hardware_id=HARDWARE_ID,
            client_installation_id=INSTALLATION_ID,
        )


def test_refresh_requires_installation_identity() -> None:
    with pytest.raises(ValidationError):
        RefreshRequest.model_validate(
            {"refresh_token": "refresh-token-with-enough-entropy"}
        )


def test_sensitive_grant_requires_unique_roles_and_operational_context() -> None:
    with pytest.raises(ValidationError):
        SensitiveAccessGrantRequest(
            tenant_id=TENANT_ID,
            purpose_code="",
            ticket_reference="SUP-100",
            requested_duration_minutes=15,
        )


def test_contracts_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ProvisionTenantRequest(
            tenant_name="Seed Clinic",
            account_name="seed-clinic",
            hardware_id=HARDWARE_ID,
            license_period_months=12,
            terminal_id=uuid4(),
        )
