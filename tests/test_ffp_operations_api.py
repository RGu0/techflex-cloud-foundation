from __future__ import annotations

from datetime import UTC, datetime, timedelta
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.operations import OperationsPermission
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.device_management.operations import (
    OperationsContext,
    OperationsService,
)
from techflex_cloud_foundation.server.operations_auth import OperationsTokenIssuer
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository


class OperationsApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.tenant_id = uuid4()
        self.other_tenant_id = uuid4()
        self.site_id = uuid4()
        self.terminal_id = uuid4()
        self.other_terminal_id = uuid4()
        self.repository = InMemoryPlatformRepository()
        self.repository.add_tenant(self.tenant_id, "Ray Clinic")
        self.repository.add_tenant(self.other_tenant_id, "Other Clinic")
        self.repository.add_terminal(self.tenant_id, self.site_id, self.terminal_id)
        self.repository.add_terminal(
            self.other_tenant_id,
            uuid4(),
            self.other_terminal_id,
        )
        self.operations = OperationsService(
            self.repository,
            license_private_key=Ed25519PrivateKey.generate(),
            license_key_id="license-key-1",
            activation_code_hmac_key=b"test-only-operations-activation-key-32",
            now=lambda: self.now,
        )
        self.context = OperationsContext(
            actor_id=uuid4(),
            tenant_id=self.tenant_id,
            site_ids=frozenset(),
            all_sites=True,
            permissions=frozenset(OperationsPermission),
        )
        self.operations_tokens = OperationsTokenIssuer(
            secret=b"test-only-operations-token-secret-32-bytes",
            key_id="operations-key-1",
            token_ttl=timedelta(minutes=10),
        )
        terminal_tokens = TerminalTokenIssuer(
            secret=b"test-only-terminal-token-secret-32-bytes",
            key_id="terminal-key-1",
            token_ttl=timedelta(minutes=10),
        )
        app = create_app(
            ServiceContainer(
                ingestion=object(),
                token_issuer=terminal_tokens,
                subjects=object(),
                operations=self.operations,
                operations_tokens=self.operations_tokens,
            )
        )
        self.client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://cloud.test",
        )
        self.headers = {
            "Authorization": f"Bearer {self.operations_tokens.issue(self.context, now=self.now)}"
        }

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def test_site_registration_and_health_are_tenant_scoped(self) -> None:
        created = await self.client.post(
            "/v1/operations/sites",
            headers=self.headers,
            json={
                "site_id": str(self.site_id),
                "site_code": "LA-01",
                "name": "Los Angeles",
                "timezone": "America/Los_Angeles",
            },
        )
        own_health = await self.client.get(
            f"/v1/operations/terminals/{self.terminal_id}/health",
            headers=self.headers,
        )
        other_health = await self.client.get(
            f"/v1/operations/terminals/{self.other_terminal_id}/health",
            headers=self.headers,
        )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(own_health.status_code, 200)
        self.assertEqual(other_health.status_code, 403)

    async def test_separate_data_permissions_are_enforced_at_api_boundary(self) -> None:
        log_only = OperationsContext(
            actor_id=uuid4(),
            tenant_id=self.tenant_id,
            site_ids=frozenset({self.site_id}),
            all_sites=False,
            permissions=frozenset({OperationsPermission.LOG_ACCESS}),
        )
        headers = {
            "Authorization": f"Bearer {self.operations_tokens.issue(log_only, now=self.now)}"
        }
        logs = await self.client.post(
            "/v1/operations/data-access-authorizations",
            headers=headers,
            json={
                "category": "LOGS",
                "site_id": str(self.site_id),
                "purpose": "INCIDENT_TRIAGE",
            },
        )
        identity = await self.client.post(
            "/v1/operations/data-access-authorizations",
            headers=headers,
            json={
                "category": "IDENTITY",
                "site_id": str(self.site_id),
                "purpose": "INCIDENT_TRIAGE",
            },
        )

        self.assertEqual(logs.status_code, 200)
        self.assertEqual(identity.status_code, 403)

    async def test_operations_openapi_has_no_public_subject_report_route(self) -> None:
        schema = (await self.client.get("/openapi.json")).json()
        operations_paths = " ".join(
            path for path in schema["paths"] if path.startswith("/v1/operations")
        ).lower()

        self.assertNotIn("public-report", operations_paths)
        self.assertNotIn("subjects/{", operations_paths)
        self.assertNotIn("report-link", operations_paths)


if __name__ == "__main__":
    unittest.main()
