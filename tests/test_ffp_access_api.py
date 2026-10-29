from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import PlatformRole, ProvisionTenantRequest
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessContext,
    PlatformAccessTokenIssuer,
    RefreshTokenFactory,
    TenantAccessTokenIssuer,
)
from techflex_cloud_foundation.server.access_control.lease_service import HardwareLeaseService
from techflex_cloud_foundation.server.access_control.platform_service import (
    PlatformProvisioningService,
)
from techflex_cloud_foundation.server.access_control.repository import InMemoryAccessRepository
from techflex_cloud_foundation.server.access_control.tenant_service import (
    TenantAuthenticationService,
)
from techflex_cloud_foundation.server.app import ServiceContainer, create_app


class TenantAccessApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)
        repository = InMemoryAccessRepository()
        self.repository = repository
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signer = LicenseDocumentSigner(
            private_key=private_key,
            key_id="license/2-key-1",
            public_keys={"license/2-key-1": public_key},
        )
        self.tenant_tokens = TenantAccessTokenIssuer(
            secret=b"tenant-token-secret-must-be-at-least-32-bytes",
            key_id="tenant/1",
        )
        refresh_tokens = RefreshTokenFactory(
            digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
        )
        self.tenant_access = TenantAuthenticationService(
            repository,
            login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
            activation_hmac_key=b"activation-key-must-contain-at-least-32-bytes",
            tenant_tokens=self.tenant_tokens,
            refresh_tokens=refresh_tokens,
            license_signer=signer,
            now=lambda: self.now,
        )
        platform = PlatformProvisioningService(
            repository,
            login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
            activation_hmac_key=b"activation-key-must-contain-at-least-32-bytes",
            license_signer=signer,
            now=lambda: self.now,
        )
        operator = PlatformAccessContext(
            platform_identity_id=uuid4(),
            roles=frozenset({PlatformRole.OPERATIONS}),
            token_version=1,
            expires_at=self.now + timedelta(minutes=15),
        )
        self.provisioned = await platform.provision_tenant(
            operator,
            ProvisionTenantRequest(
                tenant_name="Seed Clinic",
                account_name="seed-clinic",
                hardware_id="usb-serial-0123456789abcdef0123",
                license_period_months=12,
            ),
        )
        app = create_app(
            ServiceContainer(
                tenant_access=self.tenant_access,
                tenant_tokens=self.tenant_tokens,
                hardware_leases=HardwareLeaseService(repository, now=lambda: self.now),
            )
        )
        self.client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://cloud.test",
        )
        self.inventory_asset_serial = "FFP-DP4864-000001"
        self.inventory_activation_code = "ffp_inventory_code_1234567890"
        await repository.add_sales_inventory(
            asset_serial=self.inventory_asset_serial,
            activation_code_hash=hmac.new(
                b"activation-key-must-contain-at-least-32-bytes",
                self.inventory_activation_code.encode("utf-8"),
                hashlib.sha256,
            ).digest(),
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    def activation_body(self) -> dict[str, str]:
        return {
            "account_name": self.provisioned.account_name,
            "activation_code": self.provisioned.activation_code,
            "password": "correct-horse-battery-staple",
            "password_confirmation": "correct-horse-battery-staple",
            "hardware_id": self.provisioned.hardware_id,
            "client_installation_id": str(uuid4()),
        }

    async def test_activate_login_refresh_license_and_lease_routes(self) -> None:
        activated = await self.client.post("/v1/access/activate", json=self.activation_body())
        self.assertEqual(activated.status_code, 201, activated.text)
        session = activated.json()["data"]
        headers = {"Authorization": f"Bearer {session['access_token']}"}

        license_response = await self.client.get("/v1/access/license", headers=headers)
        lease = await self.client.post(
            "/v1/access/hardware-lease",
            headers=headers,
            json={
                "hardware_id": session["hardware_id"],
                "client_installation_id": session["client_installation_id"],
            },
        )
        refreshed = await self.client.post(
            "/v1/access/refresh",
            json={
                "refresh_token": session["refresh_token"],
                "client_installation_id": session["client_installation_id"],
            },
        )

        self.assertEqual(license_response.status_code, 200, license_response.text)
        self.assertEqual(lease.status_code, 201, lease.text)
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        self.assertNotEqual(
            refreshed.json()["data"]["refresh_token"],
            session["refresh_token"],
        )

    async def test_platform_token_cannot_call_tenant_access_route(self) -> None:
        platform_issuer = PlatformAccessTokenIssuer(
            secret=b"platform-token-secret-must-be-at-least-32-bytes",
            key_id="platform/1",
        )
        token = platform_issuer.issue(
            platform_identity_id=uuid4(),
            roles=(PlatformRole.OWNER,),
            token_version=1,
            now=self.now,
        )

        response = await self.client.get(
            "/v1/access/license",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertNotIn(token, response.text)

    async def test_tenant_login_lockout_survives_user_agent_rotation(self) -> None:
        activated = await self.client.post("/v1/access/activate", json=self.activation_body())
        self.assertEqual(activated.status_code, 201, activated.text)
        bad_body = {
            "account_name": self.provisioned.account_name,
            "password": "definitely-wrong-password",
            "client_installation_id": str(uuid4()),
        }
        for index in range(5):
            response = await self.client.post(
                "/v1/access/login",
                json=bad_body,
                headers={"User-Agent": f"rotating-agent-{index}"},
            )
            self.assertEqual(response.status_code, 401, response.text)

        locked = await self.client.post(
            "/v1/access/login",
            json={
                "account_name": self.provisioned.account_name,
                "password": "correct-horse-battery-staple",
                "client_installation_id": str(uuid4()),
            },
            headers={"User-Agent": "rotating-agent-999"},
        )
        self.assertEqual(locked.status_code, 401, locked.text)
        self.assertIn("temporarily unavailable", locked.text)

    async def test_local_ui_test_license_never_reaches_cloud_activation(self) -> None:
        body = self.activation_body()
        body["activation_code"] = "FFP-2026-TEST-0001"

        response = await self.client.post("/v1/access/activate", json=body)

        self.assertIn(response.status_code, {401, 422})
        self.assertNotIn("seed-clinic", response.text)

    async def test_inventory_activation_binds_asset_serial_once_and_starts_12_month_license(self) -> None:
        installation_id = uuid4()
        response = await self.client.post(
            "/v1/access/inventory-activate",
            json={
                "tenant_name": "Inventory Clinic",
                "account_name": "inventory-clinic",
                "password": "correct-horse-battery-staple",
                "password_confirmation": "correct-horse-battery-staple",
                "asset_serial": self.inventory_asset_serial,
                "activation_code": self.inventory_activation_code,
                "client_installation_id": str(installation_id),
            },
        )

        self.assertEqual(response.status_code, 201, response.text)
        data = response.json()["data"]
        self.assertEqual(data["hardware_id"], self.inventory_asset_serial)
        self.assertEqual(data["signed_license"]["document"]["hardware_id"], self.inventory_asset_serial)
        self.assertEqual(data["signed_license"]["document"]["valid_from"], self.now.isoformat().replace("+00:00", "Z"))
        self.assertEqual(
            data["signed_license"]["document"]["valid_until"],
            self.now.replace(year=self.now.year + 1).isoformat().replace("+00:00", "Z"),
        )

        replay = await self.client.post(
            "/v1/access/inventory-activate",
            json={
                "tenant_name": "Another Clinic",
                "account_name": "another-clinic",
                "password": "correct-horse-battery-staple",
                "password_confirmation": "correct-horse-battery-staple",
                "asset_serial": self.inventory_asset_serial,
                "activation_code": self.inventory_activation_code,
                "client_installation_id": str(uuid4()),
            },
        )
        self.assertEqual(replay.status_code, 401)
