from datetime import UTC, datetime
import hashlib
import io
import unittest
import zipfile

from techflex_cloud_foundation.server.observability.diagnostics import (
    DiagnosticBundleBuilder,
    DiagnosticSource,
    EncryptedPayload,
    SupportAccessAuthorizer,
)
from techflex_cloud_foundation.server.observability.events import Severity, build_event


class RecordingEncryptor:
    def __init__(self) -> None:
        self.plaintext: bytes | None = None
        self.context: dict[str, str] | None = None

    def encrypt(self, plaintext: bytes, context: dict[str, str]) -> EncryptedPayload:
        self.plaintext = plaintext
        self.context = context
        return EncryptedPayload(
            ciphertext=b"encrypted:" + hashlib.sha256(plaintext).digest(),
            algorithm="kms-envelope/test",
            key_id="test-key",
        )


def source() -> DiagnosticSource:
    event = build_event(
        timestamp=datetime(2026, 7, 20, 9, 0, tzinfo=UTC),
        severity=Severity.ERROR,
        component="cloud.analysis",
        event_name="analysis_failed",
        tenant_id="tenant-a",
        terminal_id="terminal-a",
        session_id="session-a",
        correlation_id="correlation-a",
        error_code="E-ALG-500",
        safe_context={"status": "FAILED", "retryable": True},
    )
    return DiagnosticSource(
        tenant_id="tenant-a",
        terminal_id="terminal-a",
        requested_at=datetime(2026, 7, 20, 9, 5, tzinfo=UTC),
        software_versions=(
            ("app_version", "1.0.0"),
            ("config_version", "config/12"),
            ("protocol_version", "do-p4864/1"),
        ),
        health_summary=(
            ("disk_free_bytes", 10_000_000),
            ("pending_sessions", 2),
        ),
        events=(event,),
    )


class DiagnosticBundleTests(unittest.TestCase):
    def test_bundle_is_encrypted_and_records_plaintext_and_ciphertext_hashes(self) -> None:
        encryptor = RecordingEncryptor()
        artifact = DiagnosticBundleBuilder(encryptor).build(source())

        self.assertIsNotNone(encryptor.plaintext)
        self.assertEqual(
            artifact.plaintext_sha256,
            hashlib.sha256(encryptor.plaintext).hexdigest(),
        )
        self.assertEqual(
            artifact.ciphertext_sha256,
            hashlib.sha256(artifact.ciphertext).hexdigest(),
        )
        self.assertEqual(artifact.encryption_algorithm, "kms-envelope/test")
        self.assertEqual(artifact.key_id, "test-key")

    def test_default_archive_contains_only_allowlisted_safe_diagnostic_files(self) -> None:
        encryptor = RecordingEncryptor()
        DiagnosticBundleBuilder(encryptor).build(source())

        with zipfile.ZipFile(io.BytesIO(encryptor.plaintext)) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {"manifest.json", "events.json"},
            )
            combined = b"".join(archive.read(name) for name in archive.namelist())

        for forbidden in (
            b"raw_pressure",
            b"report_content",
            b"subject_name",
            b"external_id",
            b"token",
            b"stack_trace",
        ):
            self.assertNotIn(forbidden, combined)

    def test_session_data_cannot_be_attached_through_the_default_bundle_action(self) -> None:
        with self.assertRaisesRegex(ValueError, "separate authorization"):
            DiagnosticBundleBuilder(RecordingEncryptor()).build(
                source(),
                include_session_data=True,
            )

    def test_support_access_requires_an_allowed_role_and_creates_audit_record(self) -> None:
        authorizer = SupportAccessAuthorizer()

        audit = authorizer.authorize(
            actor_id="support-user-a",
            role="SUPPORT_ENGINEER",
            tenant_id="tenant-a",
            resource_type="DIAGNOSTIC_PACKAGE",
            resource_id="diagnostic-a",
            reason="ticket-123",
            occurred_at=datetime(2026, 7, 20, 9, 10, tzinfo=UTC),
        )

        self.assertEqual(audit.action, "SUPPORT_DIAGNOSTIC_ACCESS")
        self.assertEqual(audit.actor_id, "support-user-a")
        with self.assertRaises(PermissionError):
            authorizer.authorize(
                actor_id="operator-a",
                role="OPERATOR",
                tenant_id="tenant-a",
                resource_type="DIAGNOSTIC_PACKAGE",
                resource_id="diagnostic-a",
                reason="ticket-123",
                occurred_at=datetime.now(UTC),
            )


if __name__ == "__main__":
    unittest.main()
