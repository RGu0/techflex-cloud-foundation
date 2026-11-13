from datetime import UTC, datetime
import json
import unittest

from techflex_cloud_foundation.server.observability.events import (
    CUSTOMER_ERROR_ACTIONS,
    REQUIRED_SLI_NAMES,
    Severity,
    analysis_failure_event,
    build_event,
    customer_error_message,
)


class SafeTelemetryEventTests(unittest.TestCase):
    def test_builds_structured_event_with_controlled_correlation_ids(self) -> None:
        event = build_event(
            timestamp=datetime(2026, 7, 20, 9, 0, tzinfo=UTC),
            severity=Severity.ERROR,
            component="cloud.analysis",
            event_name="analysis_failed",
            tenant_id="tenant-a",
            terminal_id="terminal-a",
            device_id="device-a",
            session_id="session-a",
            analysis_run_id="run-a",
            correlation_id="correlation-a",
            error_code="E-ALG-500",
            safe_context={
                "status": "FAILED",
                "retryable": True,
                "attempt_count": 2,
            },
        )

        self.assertEqual(event.session_id, "session-a")
        self.assertEqual(event.error_code, "E-ALG-500")
        self.assertEqual(
            json.loads(event.safe_context_json),
            {"attempt_count": 2, "retryable": True, "status": "FAILED"},
        )

    def test_rejects_identity_secrets_raw_payloads_reports_and_stacks_recursively(self) -> None:
        unsafe_contexts = (
            {"subject_name": "Alice"},
            {"nested": {"phone": "123"}},
            {"operation": "Bearer secret-token"},
            {"raw_pressure_payload": [1, 2, 3]},
            {"report_content": "full report"},
            {"stack_trace": "Traceback"},
            {"external_id": "MRN-1"},
        )

        for unsafe in unsafe_contexts:
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                build_event(
                    timestamp=datetime.now(UTC),
                    severity=Severity.ERROR,
                    component="cloud.analysis",
                    event_name="unsafe",
                    tenant_id="tenant-a",
                    correlation_id="correlation-a",
                    error_code="E-ALG-500",
                    safe_context=unsafe,
                )

    def test_analysis_failure_helper_never_serializes_exception_text(self) -> None:
        event = analysis_failure_event(
            tenant_id="tenant-a",
            session_id="session-a",
            analysis_run_id="run-a",
            correlation_id="correlation-a",
            error_code="E-ALG-500",
            retryable=True,
            exception=RuntimeError("name=Alice token=secret"),
        )

        serialized = repr(event)
        self.assertNotIn("Alice", serialized)
        self.assertNotIn("secret", serialized)
        self.assertEqual(event.error_code, "E-ALG-500")

    def test_customer_error_messages_only_expose_code_and_action(self) -> None:
        message = customer_error_message("E-RPT-500")

        self.assertEqual(message.error_code, "E-RPT-500")
        self.assertEqual(message.action, CUSTOMER_ERROR_ACTIONS["E-RPT-500"])
        self.assertNotIn("stack", repr(message).lower())
        self.assertNotIn("debug", repr(message).lower())

    def test_sli_catalog_covers_every_required_stage_and_failure_mode(self) -> None:
        self.assertTrue(
            {
                "acquisition_completion_seconds",
                "segment_verification_failures",
                "upload_backlog_sessions",
                "terminal_offline_seconds",
                "manifest_conflicts",
                "analysis_queue_seconds",
                "analysis_failures",
                "report_generation_seconds",
                "report_failures",
            }.issubset(REQUIRED_SLI_NAMES)
        )


if __name__ == "__main__":
    unittest.main()
