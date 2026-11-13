from datetime import UTC, datetime
import unittest

from techflex_cloud_foundation.server.observability.events import Severity, build_event
from techflex_cloud_foundation.server.observability.uploader import TelemetryUploadQueue


def event(name: str, severity: Severity):
    return build_event(
        timestamp=datetime(2026, 7, 20, 9, 0, tzinfo=UTC),
        severity=severity,
        component="cloud.analysis",
        event_name=name,
        tenant_id="tenant-a",
        correlation_id=f"correlation-{name}",
        error_code="E-ALG-500" if severity in {Severity.ERROR, Severity.CRITICAL} else None,
        safe_context={"status": "FAILED" if severity is Severity.ERROR else "OK"},
    )


class RecordingUploader:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.calls = []

    def upload(self, batch) -> None:
        self.calls.append(batch)
        if self.failures:
            self.failures -= 1
            raise ConnectionError("offline")


class TelemetryUploadQueueTests(unittest.TestCase):
    def test_failed_upload_retains_batch_and_reuses_idempotent_batch_id(self) -> None:
        queue = TelemetryUploadQueue(capacity=10)
        queue.enqueue(event("analysis_failed", Severity.ERROR))
        uploader = RecordingUploader(failures=1)

        self.assertFalse(queue.upload_next(uploader, max_events=10))
        self.assertEqual(queue.pending_count, 1)
        self.assertTrue(queue.upload_next(uploader, max_events=10))

        self.assertEqual(queue.pending_count, 0)
        self.assertEqual(uploader.calls[0].batch_id, uploader.calls[1].batch_id)
        self.assertEqual(uploader.calls[0].events, uploader.calls[1].events)

    def test_full_ring_buffer_preserves_high_priority_errors(self) -> None:
        queue = TelemetryUploadQueue(capacity=3)
        queue.enqueue(event("info-1", Severity.INFO))
        queue.enqueue(event("error-1", Severity.ERROR))
        queue.enqueue(event("info-2", Severity.INFO))

        queue.enqueue(event("critical-1", Severity.CRITICAL))

        self.assertEqual(
            [item.event_name for item in queue.snapshot()],
            ["error-1", "info-2", "critical-1"],
        )

    def test_empty_queue_does_not_call_uploader(self) -> None:
        queue = TelemetryUploadQueue(capacity=3)
        uploader = RecordingUploader()

        self.assertTrue(queue.upload_next(uploader, max_events=3))
        self.assertEqual(uploader.calls, [])


if __name__ == "__main__":
    unittest.main()
