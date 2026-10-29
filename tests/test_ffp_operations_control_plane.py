from __future__ import annotations

from datetime import UTC, datetime, timedelta
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from techflex_cloud_foundation.contracts.cloud import (
    HeartbeatDevice,
    HeartbeatHealth,
    HeartbeatRequest,
    HeartbeatSync,
)
from techflex_cloud_foundation.contracts.device_policy import LicenseStatus, LicenseVerifier
from techflex_cloud_foundation.contracts.operations import (
    DataAccessCategory,
    DataAccessRequest,
    DeviceRegistrationRequest,
    LicenseIssueRequest,
    LicenseRenewRequest,
    OperationsPermission,
    SiteCreateRequest,
    TerminalHealthSummary,
    UpgradePolicyRequest,
)
from techflex_cloud_foundation.platform_errors import TenantAccessDenied
from techflex_cloud_foundation.server.auth import TerminalContext
from techflex_cloud_foundation.server.device_management.operations import (
    OperationsContext,
    OperationsService,
)
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository


class OperationsControlPlaneTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime(2026, 7, 20, 10, 30, tzinfo=UTC)
        self.tenant_id = uuid4()
        self.other_tenant_id = uuid4()
        self.actor_id = uuid4()
        self.site_id = uuid4()
        self.terminal_id = uuid4()
        self.device_id = uuid4()
        self.repository = InMemoryPlatformRepository()
        self.repository.add_tenant(self.tenant_id, "Ray Clinic")
        self.repository.add_tenant(self.other_tenant_id, "Other Clinic")
        self.repository.add_terminal(self.tenant_id, self.site_id, self.terminal_id)
        self.repository.add_terminal(self.other_tenant_id, uuid4(), uuid4())
        self.private_key = Ed25519PrivateKey.generate()
        self.service = OperationsService(
            self.repository,
            license_private_key=self.private_key,
            license_key_id="license-key-1",
            activation_code_hmac_key=b"test-only-operations-activation-key-32",
            now=lambda: self.now,
        )
        self.admin = OperationsContext(
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            site_ids=frozenset(),
            all_sites=True,
            permissions=frozenset(OperationsPermission),
        )

    async def test_site_device_binding_suspension_and_audit(self) -> None:
        site = await self.service.create_site(
            self.admin,
            SiteCreateRequest(
                site_id=self.site_id,
                site_code="LA-01",
                name="Los Angeles",
                timezone="America/Los_Angeles",
            ),
        )
        device = await self.service.register_device(
            self.admin,
            DeviceRegistrationRequest(
                device_id=self.device_id,
                model="DO-P4864",
                capabilities={"matrix": "48x64", "nominal_hz": 12},
            ),
        )
        binding = await self.service.bind_device(
            self.admin,
            self.terminal_id,
            self.device_id,
        )
        await self.service.set_terminal_status(self.admin, self.terminal_id, "SUSPENDED")

        self.assertEqual(site.tenant_id, self.tenant_id)
        self.assertEqual(device.tenant_id, self.tenant_id)
        self.assertEqual(binding.device_id, self.device_id)
        self.assertEqual(self.repository.terminal_status(self.tenant_id, self.terminal_id), "SUSPENDED")
        self.assertEqual(
            self.repository.audit_actions(self.tenant_id),
            ["site.create", "device.register", "terminal.device.bind", "terminal.status.change"],
        )

    async def test_cross_tenant_and_out_of_site_scope_are_denied_and_audited(self) -> None:
        scoped = OperationsContext(
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            site_ids=frozenset({self.site_id}),
            all_sites=False,
            permissions=frozenset({OperationsPermission.TERMINAL_MANAGE}),
        )
        other_terminal = next(
            terminal_id
            for tenant_id, terminal_id in self.repository.terminal_keys()
            if tenant_id == self.other_tenant_id
        )

        with self.assertRaises(TenantAccessDenied):
            await self.service.set_terminal_status(scoped, other_terminal, "SUSPENDED")

        self.assertIn("operations.access.denied", self.repository.audit_actions(self.tenant_id))

    async def test_activation_code_is_returned_once_but_only_hmac_is_persisted(self) -> None:
        await self.service.create_site(
            self.admin,
            SiteCreateRequest(
                site_id=self.site_id,
                site_code="LA-01",
                name="Los Angeles",
                timezone="America/Los_Angeles",
            ),
        )
        issued = await self.service.issue_activation_code(
            self.admin,
            site_id=self.site_id,
            device_id=None,
            expires_at=self.now + timedelta(hours=2),
        )

        self.assertGreaterEqual(len(issued.activation_code), 20)
        self.assertFalse(self.repository.activation_storage_contains(issued.activation_code))
        self.assertTrue(self.repository.has_activation_code_id(issued.enrollment_code_id))

    async def test_license_issue_renew_revoke_creates_signed_versions(self) -> None:
        issued = await self.service.issue_license(
            self.admin,
            LicenseIssueRequest(
                terminal_id=self.terminal_id,
                site_id=self.site_id,
                enabled_features=("screening.start", "cloud.full-report"),
                not_before=self.now,
                expires_at=self.now + timedelta(days=30),
            ),
        )
        renewed = await self.service.renew_license(
            self.admin,
            issued.document.license_id,
            LicenseRenewRequest(expires_at=self.now + timedelta(days=60)),
        )
        revoked = await self.service.revoke_license(
            self.admin,
            issued.document.license_id,
            reason_code="CONTRACT_ENDED",
        )

        public_key = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        verifier = LicenseVerifier({"license-key-1": public_key})
        verifier.verify(
            renewed,
            expected_tenant_id=self.tenant_id,
            expected_terminal_id=self.terminal_id,
            now=self.now + timedelta(days=31),
        )
        self.assertEqual(issued.document.license_version, 1)
        self.assertEqual(renewed.document.license_version, 2)
        self.assertEqual(revoked.document.license_version, 3)
        self.assertEqual(revoked.document.status, LicenseStatus.REVOKED)
        self.assertEqual(self.repository.license_version_count(self.tenant_id, issued.document.license_id), 3)

    async def test_health_summary_contains_operational_fields_and_error_trends_only(self) -> None:
        terminal = TerminalContext(
            tenant_id=self.tenant_id,
            terminal_id=self.terminal_id,
            expires_at=self.now + timedelta(days=365),
        )
        for index, error_code in enumerate(("E-DEV-101", "E-DEV-101", "E-SYN-503")):
            heartbeat = HeartbeatRequest(
                app_version="1.2.3",
                config_version="config/7",
                protocol_version="do-p4864/1",
                device=HeartbeatDevice(connection_state="ERROR"),
                sync=HeartbeatSync(
                    last_successful_sync=self.now - timedelta(minutes=3 - index),
                    pending_sessions=3,
                    pending_bytes=8192,
                ),
                health=HeartbeatHealth(
                    disk_free_bytes=10_000_000_000,
                    clock_skew_seconds=0.2,
                    last_error_code=error_code,
                ),
                observed_at=self.now - timedelta(minutes=3 - index),
            )
            await self.repository.record_heartbeat(
                terminal,
                heartbeat,
                request_sha256=str(index).zfill(64),
                idempotency_key=f"health-{index}",
                accepted_at=self.now - timedelta(minutes=3 - index),
            )

        health = await self.service.get_terminal_health(self.admin, self.terminal_id)

        self.assertEqual(health.pending_sessions, 3)
        self.assertEqual(health.error_trends, {"E-DEV-101": 2, "E-SYN-503": 1})
        serialized = health.model_dump_json().lower()
        self.assertNotIn("subject", serialized)
        self.assertNotIn("report_url", serialized)

    async def test_upgrade_policy_supports_staged_rollout_and_rollback_metadata(self) -> None:
        policy = await self.service.create_upgrade_policy(
            self.admin,
            UpgradePolicyRequest(
                platform="macos",
                target_version="1.3.0",
                minimum_supported_version="1.1.0",
                rollout_percent=10,
                package_sha256="a" * 64,
                package_signature="signed-package-metadata",
                rollback_version="1.2.3",
            ),
        )
        rolled_back = await self.service.set_upgrade_policy_status(
            self.admin,
            policy.upgrade_policy_id,
            "ROLLED_BACK",
        )

        self.assertEqual(policy.rollout_percent, 10)
        self.assertEqual(rolled_back.status, "ROLLED_BACK")

    async def test_raw_identity_logs_and_diagnostics_require_separate_permissions(self) -> None:
        log_support = OperationsContext(
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            site_ids=frozenset({self.site_id}),
            all_sites=False,
            permissions=frozenset({OperationsPermission.LOG_ACCESS}),
        )
        allowed = await self.service.authorize_data_access(
            log_support,
            DataAccessRequest(
                category=DataAccessCategory.LOGS,
                site_id=self.site_id,
                purpose="INCIDENT_TRIAGE",
            ),
        )
        with self.assertRaises(TenantAccessDenied):
            await self.service.authorize_data_access(
                log_support,
                DataAccessRequest(
                    category=DataAccessCategory.IDENTITY,
                    site_id=self.site_id,
                    purpose="INCIDENT_TRIAGE",
                ),
            )

        self.assertTrue(allowed.allowed)
        self.assertEqual(self.repository.access_audit_outcomes(self.tenant_id)[-2:], ["ALLOWED", "DENIED"])

    def test_operations_health_contract_forbids_public_report_links(self) -> None:
        with self.assertRaises(ValidationError):
            TerminalHealthSummary(
                terminal_id=self.terminal_id,
                site_id=self.site_id,
                status="ACTIVE",
                last_seen_at=self.now,
                app_version="1.2.3",
                config_version="config/7",
                protocol_version="do-p4864/1",
                pending_sessions=0,
                pending_bytes=0,
                device_connection_state="READY",
                error_trends={},
                public_report_url="https://forbidden.example/report",
            )


if __name__ == "__main__":
    unittest.main()
