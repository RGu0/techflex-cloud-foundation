from __future__ import annotations

from datetime import UTC, datetime, timedelta
import unittest
from uuid import uuid4

from pydantic import ValidationError

from techflex_cloud_foundation.contracts.client_sync import (
    DurableUploadTask,
    LocalSegmentState,
    RetryPolicy,
    UploadResourceType,
    UploadTaskStatus,
    build_sync_plan,
    can_delete_local_segment,
    may_enqueue_segment,
)
from techflex_cloud_foundation.contracts.cloud import ReceivedSegment, SegmentAcknowledgement


class ClientSyncContractTests(unittest.TestCase):
    def acknowledgement(
        self,
        *,
        digest: str = "a" * 64,
        status: str = "ACKNOWLEDGED",
    ) -> SegmentAcknowledgement:
        return SegmentAcknowledgement(
            session_id=uuid4(),
            index=0,
            sha256=digest,
            status=status,
            object_key="tenant/session/0-a.raw",
        )

    def test_resume_plan_uploads_only_absent_segments(self) -> None:
        local = {0: "a" * 64, 1: "b" * 64, 2: "c" * 64}
        remote = (
            ReceivedSegment(index=0, sha256="a" * 64, status="ACKNOWLEDGED"),
            ReceivedSegment(index=2, sha256="d" * 64, status="ACKNOWLEDGED"),
            ReceivedSegment(index=7, sha256="e" * 64, status="ACKNOWLEDGED"),
        )

        plan = build_sync_plan(local, remote)

        self.assertEqual(plan.acknowledged, (0,))
        self.assertEqual(plan.upload, (1,))
        self.assertEqual(plan.remote_only, (7,))
        self.assertEqual(len(plan.conflicts), 1)
        self.assertEqual(plan.conflicts[0].index, 2)
        self.assertEqual(plan.conflicts[0].local_sha256, "c" * 64)
        self.assertEqual(plan.conflicts[0].remote_sha256, "d" * 64)

    def test_conflict_or_quarantine_is_never_scheduled_as_missing(self) -> None:
        local = {0: "a" * 64, 1: "b" * 64}
        remote = (
            ReceivedSegment(index=0, sha256="a" * 64, status="CONFLICT"),
            ReceivedSegment(index=1, sha256="b" * 64, status="QUARANTINED"),
        )

        plan = build_sync_plan(local, remote)

        self.assertEqual(plan.upload, ())
        self.assertEqual(tuple(item.index for item in plan.conflicts), (0, 1))

    def test_duplicate_remote_index_is_rejected_as_ambiguous(self) -> None:
        remote = (
            ReceivedSegment(index=0, sha256="a" * 64, status="ACKNOWLEDGED"),
            ReceivedSegment(index=0, sha256="a" * 64, status="ACKNOWLEDGED"),
        )

        with self.assertRaisesRegex(ValueError, "duplicate remote segment index"):
            build_sync_plan({0: "a" * 64}, remote)

    def test_local_deletion_requires_same_digest_acknowledgement(self) -> None:
        self.assertTrue(can_delete_local_segment("a" * 64, self.acknowledgement()))
        self.assertFalse(
            can_delete_local_segment(
                "b" * 64,
                self.acknowledgement(digest="a" * 64),
            )
        )
        self.assertFalse(
            can_delete_local_segment(
                "a" * 64,
                self.acknowledgement(status="QUARANTINED"),
            )
        )
        self.assertFalse(can_delete_local_segment("a" * 64, None))

    def test_only_immutable_or_retryable_segment_states_may_enter_queue(self) -> None:
        self.assertTrue(may_enqueue_segment(LocalSegmentState.SEALED))
        self.assertTrue(may_enqueue_segment(LocalSegmentState.PENDING_UPLOAD))
        self.assertTrue(may_enqueue_segment(LocalSegmentState.RETRY_WAIT))
        self.assertFalse(may_enqueue_segment(LocalSegmentState.WRITING))
        self.assertFalse(may_enqueue_segment(LocalSegmentState.CORRUPT))
        self.assertFalse(may_enqueue_segment(LocalSegmentState.ACKNOWLEDGED))

    def test_retry_policy_is_exponential_jittered_and_capped(self) -> None:
        policy = RetryPolicy()

        self.assertEqual(policy.delay_seconds(attempt_count=1, jitter_fraction=0.0), 1.0)
        self.assertEqual(policy.delay_seconds(attempt_count=4, jitter_fraction=0.25), 10.0)
        self.assertEqual(policy.delay_seconds(attempt_count=20, jitter_fraction=0.3), 900.0)
        self.assertEqual(
            policy.delay_seconds(
                attempt_count=2,
                jitter_fraction=0.0,
                retry_after_seconds=1_200,
            ),
            1_200.0,
        )

    def test_retry_policy_rejects_invalid_jitter(self) -> None:
        with self.assertRaisesRegex(ValueError, "jitter_fraction"):
            RetryPolicy().delay_seconds(attempt_count=1, jitter_fraction=0.31)

    def test_retry_policy_caps_without_overflow_after_many_restarts(self) -> None:
        self.assertEqual(
            RetryPolicy().delay_seconds(attempt_count=10_000, jitter_fraction=0.30),
            900.0,
        )

    def test_durable_task_carries_restart_and_idempotency_state(self) -> None:
        now = datetime.now(UTC)
        task = DurableUploadTask(
            upload_task_id=uuid4(),
            tenant_id=uuid4(),
            terminal_id=uuid4(),
            session_id=uuid4(),
            resource_type=UploadResourceType.SEGMENT,
            resource_id=uuid4(),
            operation="PUT_SEGMENT",
            status=UploadTaskStatus.RETRY_WAIT,
            priority=20,
            idempotency_key="segment:session:0:a",
            request_sha256="a" * 64,
            attempt_count=3,
            next_attempt_at=now + timedelta(seconds=5),
            created_at=now,
            updated_at=now,
        )

        restored = DurableUploadTask.model_validate_json(task.model_dump_json())

        self.assertEqual(restored, task)
        self.assertEqual(restored.attempt_count, 3)
        self.assertEqual(restored.status, UploadTaskStatus.RETRY_WAIT)

    def test_retry_wait_requires_next_attempt_and_lease_is_a_pair(self) -> None:
        common = dict(
            upload_task_id=uuid4(),
            tenant_id=uuid4(),
            terminal_id=uuid4(),
            resource_type="SESSION",
            resource_id=uuid4(),
            operation="POST_SESSION",
            priority=10,
            idempotency_key="session:create",
            request_sha256="a" * 64,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        with self.assertRaises(ValidationError):
            DurableUploadTask(status="RETRY_WAIT", **common)
        with self.assertRaises(ValidationError):
            DurableUploadTask(status="LEASED", lease_owner="worker-1", **common)


if __name__ == "__main__":
    unittest.main()
