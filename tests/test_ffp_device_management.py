from __future__ import annotations

from datetime import UTC, datetime, timedelta
import unittest
from uuid import uuid4

from techflex_cloud_foundation.contracts.cloud import (
    EnrollmentRequest,
    HeartbeatDevice,
    HeartbeatHealth,
    HeartbeatRequest,
    HeartbeatSync,
    SystemSummary,
)
from techflex_cloud_foundation.platform_errors import (
    ActivationCodeInvalid,
    AuthenticationError,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.device_management.service import DeviceManagementService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository


class DeviceManagementTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.tenant_id = uuid4()
        self.site_id = uuid4()
        self.device_id = uuid4()
        self.activation_code = "RAY-ACTIVATE-ONE-TIME-001"
        self.repository = InMemoryPlatformRepository()
        self.repository.add_device(self.tenant_id, self.device_id, "DO-P4864")
        self.issuer = TerminalTokenIssuer(
            secret=b"test-only-terminal-token-secret-32-bytes",
            key_id="terminal-key-1",
            token_ttl=timedelta(minutes=10),
        )
        self.service = DeviceManagementService(
            self.repository,
            self.issuer,
            activation_code_hmac_key=b"test-only-activation-code-key-32-bytes",
            now=lambda: self.now,
        )
        self.repository.add_activation_code_hash(
            self.service.hash_activation_code(self.activation_code),
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            device_id=self.device_id,
            expires_at=self.now + timedelta(hours=1),
        )

    def enrollment_request(self, **updates) -> EnrollmentRequest:
        values = dict(
            activation_code=self.activation_code,
            installation_id=uuid4(),
            client_public_key="ed25519-public-key-material",
            system=SystemSummary(os="macos", os_version="15.5", app_version="1.2.3"),
        )
        values.update(updates)
        return EnrollmentRequest(**values)

    def heartbeat(self) -> HeartbeatRequest:
        return HeartbeatRequest(
            app_version="1.2.3",
            config_version="config/7",
            protocol_version="do-p4864/1",
            device=HeartbeatDevice(
                device_id=self.device_id,
                model="DO-P4864",
                connection_state="READY",
            ),
            sync=HeartbeatSync(
                last_successful_sync=self.now - timedelta(minutes=1),
                pending_sessions=2,
                pending_bytes=4096,
            ),
            health=HeartbeatHealth(
                disk_free_bytes=20_000_000_000,
                clock_skew_seconds=0.5,
            ),
            observed_at=self.now,
        )

    async def test_activation_code_is_single_use_and_token_is_terminal_bound(self) -> None:
        request = self.enrollment_request()
        enrolled = await self.service.enroll(request, "enroll-1")

        context = self.issuer.verify(enrolled.access_token, now=self.now)
        self.assertEqual(context.tenant_id, self.tenant_id)
        self.assertEqual(context.terminal_id, enrolled.terminal_id)
        self.assertEqual(enrolled.site_id, self.site_id)
        self.assertTrue(
            self.repository.is_device_bound(
                self.tenant_id,
                enrolled.terminal_id,
                self.device_id,
            )
        )
        with self.assertRaises(ActivationCodeInvalid):
            await self.service.enroll(self.enrollment_request(), "enroll-2")

    async def test_identical_enrollment_replay_returns_same_terminal(self) -> None:
        request = self.enrollment_request()

        first = await self.service.enroll(request, "same-enrollment")
        second = await self.service.enroll(request, "same-enrollment")

        self.assertEqual(first.terminal_id, second.terminal_id)
        self.assertEqual(first.tenant_id, second.tenant_id)

    async def test_expired_code_and_tampered_token_are_rejected(self) -> None:
        self.now += timedelta(hours=2)
        with self.assertRaises(ActivationCodeInvalid):
            await self.service.enroll(self.enrollment_request(), "expired")

        self.now -= timedelta(hours=2)
        enrolled = await self.service.enroll(self.enrollment_request(), "valid")
        header, payload, signature = enrolled.access_token.split(".")
        replacement = "A" if signature[0] != "A" else "B"
        tampered = f"{header}.{payload}.{replacement}{signature[1:]}"
        with self.assertRaisesRegex(AuthenticationError, "签名"):
            self.issuer.verify(tampered, now=self.now)

    async def test_heartbeat_is_terminal_bound_and_contains_no_subject_payload(self) -> None:
        enrolled = await self.service.enroll(self.enrollment_request(), "enroll")
        context = self.issuer.verify(enrolled.access_token, now=self.now)

        response = await self.service.record_heartbeat(
            context,
            enrolled.terminal_id,
            self.heartbeat(),
            "heartbeat-1",
        )

        serialized = self.heartbeat().model_dump_json().lower()
        self.assertNotIn("subject", serialized)
        self.assertNotIn("external_id", serialized)
        self.assertNotIn("raw_pressure", serialized)
        self.assertNotIn("report_content", serialized)
        self.assertEqual(response.terminal_id, enrolled.terminal_id)
        with self.assertRaises(TenantAccessDenied):
            await self.service.record_heartbeat(
                context,
                uuid4(),
                self.heartbeat(),
                "wrong-terminal",
            )

    async def test_revoked_terminal_cannot_heartbeat_or_silently_login(self) -> None:
        enrolled = await self.service.enroll(self.enrollment_request(), "enroll")
        context = self.issuer.verify(enrolled.access_token, now=self.now)
        self.repository.set_terminal_status(
            self.tenant_id,
            enrolled.terminal_id,
            "REVOKED",
        )

        with self.assertRaises(TenantAccessDenied):
            await self.service.record_heartbeat(
                context,
                enrolled.terminal_id,
                self.heartbeat(),
                "heartbeat-revoked",
            )


if __name__ == "__main__":
    unittest.main()
