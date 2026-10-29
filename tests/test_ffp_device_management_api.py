from __future__ import annotations

from datetime import UTC, datetime, timedelta
import unittest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.cloud import EnrollmentRequest, SystemSummary
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.device_management.service import DeviceManagementService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository


class DeviceManagementApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.tenant_id = uuid4()
        self.site_id = uuid4()
        self.device_id = uuid4()
        self.activation_code = "RAY-ACTIVATE-API-001"
        self.repository = InMemoryPlatformRepository()
        self.repository.add_device(self.tenant_id, self.device_id, "DO-P4864")
        self.issuer = TerminalTokenIssuer(
            secret=b"test-only-terminal-token-secret-32-bytes",
            key_id="terminal-key-1",
            token_ttl=timedelta(minutes=10),
        )
        self.devices = DeviceManagementService(
            self.repository,
            self.issuer,
            activation_code_hmac_key=b"test-only-activation-code-key-32-bytes",
            now=lambda: self.now,
        )
        self.repository.add_activation_code_hash(
            self.devices.hash_activation_code(self.activation_code),
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            device_id=self.device_id,
            expires_at=self.now + timedelta(hours=1),
        )
        app = create_app(
            ServiceContainer(
                ingestion=object(),
                token_issuer=self.issuer,
                subjects=object(),
                devices=self.devices,
            )
        )
        self.client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://cloud.test",
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def enroll(self):
        request = EnrollmentRequest(
            activation_code=self.activation_code,
            installation_id=uuid4(),
            client_public_key="ed25519-public-key-material",
            system=SystemSummary(os="macos", os_version="15.5", app_version="1.2.3"),
        )
        return await self.client.post(
            "/v1/terminals/enroll",
            headers={"Idempotency-Key": "enroll-api", "X-Correlation-ID": str(uuid4())},
            json=request.model_dump(mode="json"),
        )

    async def test_enrollment_and_authenticated_heartbeat_contract(self) -> None:
        enrolled = await self.enroll()
        self.assertEqual(enrolled.status_code, 201)
        body = enrolled.json()["data"]
        terminal_id = body["terminal_id"]

        heartbeat = await self.client.post(
            f"/v1/terminals/{terminal_id}/heartbeats",
            headers={
                "Authorization": f"Bearer {body['access_token']}",
                "X-Terminal-ID": terminal_id,
                "Idempotency-Key": "heartbeat-api",
            },
            json={
                "app_version": "1.2.3",
                "config_version": "config/7",
                "protocol_version": "do-p4864/1",
                "device": {
                    "device_id": str(self.device_id),
                    "model": "DO-P4864",
                    "connection_state": "READY",
                },
                "sync": {
                    "last_successful_sync": self.now.isoformat(),
                    "pending_sessions": 0,
                    "pending_bytes": 0,
                },
                "health": {
                    "disk_free_bytes": 10_000_000_000,
                    "clock_skew_seconds": 0.2,
                    "last_error_code": None,
                },
                "observed_at": self.now.isoformat(),
            },
        )

        self.assertEqual(heartbeat.status_code, 200)
        self.assertEqual(heartbeat.json()["data"]["terminal_id"], terminal_id)

    async def test_heartbeat_rejects_identity_fields_without_echoing_values(self) -> None:
        enrolled = await self.enroll()
        body = enrolled.json()["data"]
        terminal_id = body["terminal_id"]
        response = await self.client.post(
            f"/v1/terminals/{terminal_id}/heartbeats",
            headers={
                "Authorization": f"Bearer {body['access_token']}",
                "X-Terminal-ID": terminal_id,
                "Idempotency-Key": "heartbeat-private",
            },
            json={
                "app_version": "1.2.3",
                "config_version": "config/7",
                "protocol_version": "do-p4864/1",
                "device": {"connection_state": "READY"},
                "sync": {"pending_sessions": 0, "pending_bytes": 0},
                "health": {"disk_free_bytes": 1, "clock_skew_seconds": 0},
                "observed_at": self.now.isoformat(),
                "subject_name": "PRIVATE-SUBJECT-NAME",
            },
        )

        self.assertEqual(response.status_code, 422)
        self.assertNotIn("PRIVATE-SUBJECT-NAME", response.text)


if __name__ == "__main__":
    unittest.main()
