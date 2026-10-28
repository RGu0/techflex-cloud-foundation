from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.contracts.device_policy import (
    DevicePolicyInput,
    DevicePolicyThresholds,
    GateReason,
    LicenseDocument,
    LicenseStatus,
    LicenseValidationState,
    LicenseVerifier,
    OperationalCapability,
    SignedLicense,
    detect_clock_rollback,
    evaluate_device_policy,
)


class DevicePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 20, 10, 0, tzinfo=UTC)
        self.tenant_id = uuid4()
        self.terminal_id = uuid4()
        self.private_key = Ed25519PrivateKey.generate()
        public_bytes = self.private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        self.verifier = LicenseVerifier({"license-key-1": public_bytes})

    def license_document(self, **updates) -> LicenseDocument:
        values = dict(
            license_id=uuid4(),
            license_version=1,
            tenant_id=self.tenant_id,
            site_id=None,
            terminal_id=self.terminal_id,
            status=LicenseStatus.ACTIVE,
            enabled_features=("screening.start", "cloud.full-report"),
            issued_at=self.now - timedelta(days=1),
            not_before=self.now - timedelta(days=1),
            expires_at=self.now + timedelta(days=30),
            schema_version="license/1",
        )
        values.update(updates)
        return LicenseDocument(**values)

    def signed_license(self, document: LicenseDocument) -> SignedLicense:
        signature = self.private_key.sign(canonical_json_bytes(document))
        return SignedLicense(
            document=document,
            key_id="license-key-1",
            signature=base64.b64encode(signature).decode("ascii"),
        )

    def policy_input(self, **updates) -> DevicePolicyInput:
        values = dict(
            evaluated_at=self.now,
            activated=True,
            terminal_status="ACTIVE",
            credential_valid=True,
            license_state=LicenseValidationState.VALID,
            enabled_features=("screening.start",),
            last_successful_online_at=self.now - timedelta(hours=1),
            pending_sessions=0,
            pending_bytes=0,
            clock_rollback_detected=False,
            session_in_progress=False,
        )
        values.update(updates)
        return DevicePolicyInput(**values)

    def test_license_signature_binding_and_feature_flags_are_verified(self) -> None:
        document = self.license_document()
        cacheable = self.signed_license(document)
        restored = SignedLicense.model_validate_json(cacheable.model_dump_json())

        verified = self.verifier.verify(
            restored,
            expected_tenant_id=self.tenant_id,
            expected_terminal_id=self.terminal_id,
            now=self.now,
        )

        self.assertEqual(verified.enabled_features, ("cloud.full-report", "screening.start"))

    def test_tampered_or_revoked_license_is_rejected(self) -> None:
        signed = self.signed_license(self.license_document())
        tampered = signed.model_copy(
            update={
                "document": signed.document.model_copy(
                    update={"enabled_features": ("screening.start", "ops.admin")}
                )
            }
        )

        with self.assertRaisesRegex(ValueError, "signature"):
            self.verifier.verify(
                tampered,
                expected_tenant_id=self.tenant_id,
                expected_terminal_id=self.terminal_id,
                now=self.now,
            )
        with self.assertRaisesRegex(ValueError, "not active"):
            self.verifier.verify(
                self.signed_license(self.license_document(status=LicenseStatus.REVOKED)),
                expected_tenant_id=self.tenant_id,
                expected_terminal_id=self.terminal_id,
                now=self.now,
            )

    def test_24_hour_threshold_allows_exact_boundary_and_blocks_after(self) -> None:
        exact = evaluate_device_policy(
            self.policy_input(last_successful_online_at=self.now - timedelta(hours=24))
        )
        exceeded = evaluate_device_policy(
            self.policy_input(
                last_successful_online_at=self.now - timedelta(hours=24, microseconds=1)
            )
        )

        self.assertTrue(exact.may_start_new_test)
        self.assertFalse(exceeded.may_start_new_test)
        self.assertIn(GateReason.OFFLINE_TOO_LONG, exceeded.reasons)

    def test_50_session_and_2_gib_thresholds_block_independently(self) -> None:
        sessions = evaluate_device_policy(self.policy_input(pending_sessions=50))
        bytes_limit = evaluate_device_policy(self.policy_input(pending_bytes=2 * 1024**3))

        self.assertEqual(sessions.reasons, (GateReason.PENDING_SESSION_LIMIT,))
        self.assertEqual(bytes_limit.reasons, (GateReason.PENDING_BYTES_LIMIT,))

    def test_gate_never_blocks_safe_finish_reports_upload_or_diagnostics(self) -> None:
        decision = evaluate_device_policy(
            self.policy_input(
                terminal_status="REVOKED",
                credential_valid=False,
                license_state="REVOKED",
                pending_sessions=50,
                pending_bytes=2 * 1024**3,
                session_in_progress=True,
            )
        )

        self.assertFalse(decision.may_start_new_test)
        self.assertTrue(decision.support_required)
        self.assertIn(OperationalCapability.FINISH_CURRENT_TEST, decision.allowed_capabilities)
        self.assertIn(OperationalCapability.VIEW_EXISTING_REPORTS, decision.allowed_capabilities)
        self.assertIn(OperationalCapability.CONTINUE_UPLOAD, decision.allowed_capabilities)
        self.assertIn(OperationalCapability.EXPORT_DIAGNOSTICS, decision.allowed_capabilities)

    def test_network_recovery_reevaluation_silently_clears_offline_gate(self) -> None:
        blocked = evaluate_device_policy(
            self.policy_input(last_successful_online_at=self.now - timedelta(hours=25))
        )
        recovered = evaluate_device_policy(
            self.policy_input(last_successful_online_at=self.now)
        )

        self.assertFalse(blocked.may_start_new_test)
        self.assertTrue(recovered.may_start_new_test)

    def test_feature_flag_and_clock_rollback_require_support(self) -> None:
        missing_feature = evaluate_device_policy(self.policy_input(enabled_features=()))
        rollback = evaluate_device_policy(self.policy_input(clock_rollback_detected=True))

        self.assertEqual(missing_feature.reasons, (GateReason.FEATURE_DISABLED,))
        self.assertEqual(rollback.reasons, (GateReason.CLOCK_ROLLBACK,))
        self.assertTrue(rollback.support_required)
        self.assertTrue(
            detect_clock_rollback(
                last_trusted_time=self.now,
                observed_time=self.now - timedelta(minutes=6),
                tolerance=timedelta(minutes=5),
            )
        )

    def test_threshold_defaults_are_the_approved_values(self) -> None:
        thresholds = DevicePolicyThresholds()

        self.assertEqual(thresholds.max_offline_duration, timedelta(hours=24))
        self.assertEqual(thresholds.max_pending_sessions, 50)
        self.assertEqual(thresholds.max_pending_bytes, 2 * 1024**3)


if __name__ == "__main__":
    unittest.main()
