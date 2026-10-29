from __future__ import annotations

from datetime import UTC, datetime
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import AccessCapabilities
from techflex_cloud_foundation.server.access_auth import TenantAccessTokenIssuer
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.validation_telemetry import (
    FileSystemValidationTelemetryRepository,
    InMemoryValidationTelemetryRepository,
    ValidationTelemetryService,
)


class ValidationTelemetryApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC)
        self.tenant_id = uuid4()
        self.installation_id = UUID("c03732ad-c781-4364-9d3a-c3ce3ea8488c")
        self.other_installation_id = uuid4()
        issuer = TenantAccessTokenIssuer(
            secret=b"tenant-token-secret-must-be-at-least-32-bytes",
            key_id="tenant/1",
        )
        self.issuer = issuer
        capabilities = AccessCapabilities(
            allow_new_test=True,
            allow_upload=True,
            allow_report_view=True,
        )
        self.token = issuer.issue(
            tenant_id=self.tenant_id,
            account_id=uuid4(),
            license_id=uuid4(),
            hardware_id="usb-serial-left0000000000000001",
            client_installation_id=self.installation_id,
            token_version=1,
            capabilities=capabilities,
            now=self.now,
        )
        self.other_token = issuer.issue(
            tenant_id=self.tenant_id,
            account_id=uuid4(),
            license_id=uuid4(),
            hardware_id="usb-serial-left0000000000000001",
            client_installation_id=self.other_installation_id,
            token_version=1,
            capabilities=capabilities,
            now=self.now,
        )
        self.repository = InMemoryValidationTelemetryRepository()
        app = create_app(
            ServiceContainer(
                tenant_tokens=issuer,
                validation_telemetry=ValidationTelemetryService(self.repository),
            )
        )
        self.client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://cloud.test",
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    def headers(self, token: str | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {token or self.token}"}

    def body(self) -> dict[str, object]:
        return {
            "schema_version": "device-validation-telemetry-batch/1",
            "client_installation_id": str(self.installation_id),
            "events": [
                {
                    "event_id": "a02694ec-c62f-4bd4-be33-bbb6859b0540",
                    "schema_version": "device-validation-telemetry/1",
                    "created_at_ns": 30,
                    "attempt_count": 0,
                    "payload": {
                        "schema_version": "device-validation-run/1",
                        "validation_run_id": "8ddcb66e-d1d7-4dfa-998f-018dfb194a2b",
                        "previous_validation_run_id": None,
                        "terminal_id": str(self.installation_id),
                        "device_ref": "hardware-0123456789abcdef0123",
                        "attempt_number": 1,
                        "versions": {
                            "app": "0.1.0-test",
                            "protocol": "do-p4864-observed-compact-8bit/1",
                            "data_mode": "48x64-uint8-column-major/1",
                            "rules": "startup-baseline/1",
                            "threshold": "startup-baseline-thresholds/1",
                            "failure_policy": "startup-failure-escalation/1",
                        },
                        "started_at_wall_ns": 10,
                        "completed_at_wall_ns": 20,
                        "outcome": "RETRYABLE_FAIL",
                        "reason": "DEVICE_BUSY",
                        "error_code": "E-DEV-102",
                        "diagnostic_id": "86217533-9b9f-405d-9977-23cda4a8d003",
                        "statistics": None,
                        "transitions": ["BOOTSTRAPPING", "DEVICE_BUSY"],
                        "partial_window_discarded": False,
                    },
                }
            ],
        }

    async def test_authenticated_upload_is_idempotent_and_tenant_bound(self) -> None:
        first = await self.client.post(
            "/v1/telemetry/device-validation",
            headers=self.headers(),
            json=self.body(),
        )
        replay = await self.client.post(
            "/v1/telemetry/device-validation",
            headers=self.headers(),
            json=self.body(),
        )

        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(replay.status_code, 202, replay.text)
        self.assertEqual(first.json()["data"]["idempotent_replays"], 0)
        self.assertEqual(replay.json()["data"]["idempotent_replays"], 1)
        self.assertEqual(len(self.repository.events_for(self.tenant_id)), 1)

        denied = await self.client.post(
            "/v1/telemetry/device-validation",
            headers=self.headers(self.other_token),
            json=self.body(),
        )
        self.assertEqual(denied.status_code, 403, denied.text)
        self.assertNotIn(self.token, denied.text)
        self.assertNotIn(self.other_token, denied.text)

    async def test_unallowlisted_customer_identity_field_is_rejected(self) -> None:
        body = self.body()
        body["events"][0]["payload"]["institution_record_number"] = "MRN-000085"

        response = await self.client.post(
            "/v1/telemetry/device-validation",
            headers=self.headers(),
            json=body,
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertNotIn("MRN-000085", response.text)
        self.assertEqual(self.repository.events_for(self.tenant_id), ())

    async def test_private_repository_survives_reopen_and_replays_idempotently(self) -> None:
        request_body = self.body()
        event_id = UUID(request_body["events"][0]["event_id"])
        with TemporaryDirectory() as directory:
            first_repository = FileSystemValidationTelemetryRepository(directory)
            app = create_app(
                ServiceContainer(
                    tenant_tokens=self.issuer,
                    validation_telemetry=ValidationTelemetryService(first_repository),
                )
            )
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="https://cloud.test",
            ) as client:
                first = await client.post(
                    "/v1/telemetry/device-validation",
                    headers=self.headers(),
                    json=request_body,
                )

            reopened = FileSystemValidationTelemetryRepository(directory)
            replay_app = create_app(
                ServiceContainer(
                    tenant_tokens=self.issuer,
                    validation_telemetry=ValidationTelemetryService(reopened),
                )
            )
            async with AsyncClient(
                transport=ASGITransport(app=replay_app),
                base_url="https://cloud.test",
            ) as client:
                replay = await client.post(
                    "/v1/telemetry/device-validation",
                    headers=self.headers(),
                    json=request_body,
                )

            self.assertEqual(first.status_code, 202, first.text)
            self.assertEqual(replay.status_code, 202, replay.text)
            self.assertEqual(replay.json()["data"]["idempotent_replays"], 1)
            stored = reopened.events_for(self.tenant_id)
            self.assertEqual(tuple(item.event.event_id for item in stored), (event_id,))
            persisted = next(
                (Path(directory) / "tenants" / str(self.tenant_id) / "events").glob(
                    "*.json"
                )
            )
            if os.name != "nt":
                self.assertEqual(persisted.stat().st_mode & 0o777, 0o600)
            persisted_text = persisted.read_text()
            self.assertNotIn("institution_record_number", persisted_text)
            self.assertNotIn("name", persisted_text.lower())


if __name__ == "__main__":
    unittest.main()
