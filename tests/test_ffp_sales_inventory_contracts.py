from uuid import uuid4

from pydantic import ValidationError
import pytest

from techflex_cloud_foundation.contracts.access_control import (
    InventoryActivationRequest,
    InventoryBatchCreateRequest,
)


def test_inventory_activation_accepts_sales_asset_serial() -> None:
    request = InventoryActivationRequest(
        tenant_name="康健中心",
        account_name="kangjian-01",
        password="correct-horse-battery-staple",
        password_confirmation="correct-horse-battery-staple",
        asset_serial="FFP-DP4864-000001",
        activation_code="ffp_inventory_code_1234567890",
        client_installation_id=uuid4(),
    )

    assert request.asset_serial == "FFP-DP4864-000001"


def test_inventory_batch_is_fixed_to_twelve_months() -> None:
    request = InventoryBatchCreateRequest(quantity=10)

    assert request.license_period_months == 12


def test_inventory_activation_rejects_usb_port_as_asset_serial() -> None:
    with pytest.raises(ValidationError):
        InventoryActivationRequest(
            tenant_name="康健中心",
            account_name="kangjian-01",
            password="correct-horse-battery-staple",
            password_confirmation="correct-horse-battery-staple",
            asset_serial="/dev/cu.usbserial-1410",
            activation_code="ffp_inventory_code_1234567890",
            client_installation_id=uuid4(),
        )
