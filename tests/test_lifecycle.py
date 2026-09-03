"""Contract tests for eligibility, retention, and deletion (F-30)."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib

import pytest

from techflex_cloud_foundation import (
    DeletionDecision,
    DeletionReceipt,
    EligibilityDecision,
    LifecycleMalformed,
    LifecycleVersionUnsupported,
    Purpose,
    RetentionClass,
    UploadEligibilityPolicy,
)

NOW = datetime(2026, 9, 3, tzinfo=UTC)
DIGEST = hashlib.sha256(b"artifact").hexdigest()


def _policy() -> UploadEligibilityPolicy:
    return UploadEligibilityPolicy(
        purposes=(
            Purpose(name="analysis", default_retention=RetentionClass.STANDARD),
            Purpose(
                name="diagnostics",
                default_retention=RetentionClass.EPHEMERAL,
                upload_allowed=False,
            ),
        ),
        policy_version="policy/1",
    )


def _decision(**overrides: object) -> DeletionDecision:
    kwargs: dict[str, object] = {
        "artifact_digest": DIGEST,
        "reason": "retention window elapsed",
        "decided_by": "lifecycle-worker",
        "decided_at": NOW,
        "policy_version": "policy/1",
    }
    kwargs.update(overrides)
    return DeletionDecision(**kwargs)  # type: ignore[arg-type]


def test_known_purpose_evaluation_records_reason_and_version() -> None:
    decision = _policy().evaluate("analysis", decided_at=NOW)

    assert decision.allowed is True
    assert decision.policy_version == "policy/1"
    assert decision.reason == "purpose allows upload"

    refused = _policy().evaluate("diagnostics", decided_at=NOW)
    assert refused.allowed is False


def test_unknown_purpose_is_never_silently_allowed() -> None:
    decision = _policy().evaluate("not-registered", decided_at=NOW)

    assert decision.allowed is False
    assert decision.reason == "unknown purpose"


def test_duplicate_purposes_are_refused() -> None:
    with pytest.raises(LifecycleMalformed, match="unique"):
        UploadEligibilityPolicy(
            purposes=(
                Purpose(name="a", default_retention=RetentionClass.STANDARD),
                Purpose(name="a", default_retention=RetentionClass.ARCHIVAL),
            ),
            policy_version="policy/1",
        )


def test_deletion_requires_explicit_decision_and_produces_bound_receipt() -> None:
    decision = _decision()
    receipt = DeletionReceipt.for_decision(
        decision, deleted_at=datetime(2026, 9, 4, tzinfo=UTC)
    )

    assert receipt.artifact_digest == decision.artifact_digest
    assert receipt.decision_digest == decision.digest()
    assert len(receipt.decision_digest) == 64


def test_decision_digest_is_reproducible() -> None:
    assert _decision().digest() == _decision().digest()
    assert _decision(reason="other").digest() != _decision().digest()


def test_short_digests_and_naive_timestamps_are_refused() -> None:
    with pytest.raises(LifecycleMalformed, match="complete"):
        _decision(artifact_digest=DIGEST[:32])
    with pytest.raises(LifecycleMalformed, match="complete"):
        DeletionReceipt(
            artifact_digest=DIGEST, decision_digest=DIGEST[:16], deleted_at=NOW
        )
    with pytest.raises(LifecycleMalformed, match="timezone-aware"):
        _decision(decided_at=datetime(2026, 9, 3))


def test_unknown_versions_are_refused() -> None:
    with pytest.raises(LifecycleVersionUnsupported):
        _decision(format_version=99)
    with pytest.raises(LifecycleVersionUnsupported):
        DeletionReceipt(
            artifact_digest=DIGEST,
            decision_digest=DIGEST,
            deleted_at=NOW,
            format_version=2,
        )


def test_empty_reason_or_actor_is_refused() -> None:
    with pytest.raises(LifecycleMalformed, match="reason"):
        _decision(reason="")
    with pytest.raises(LifecycleMalformed, match="decided_by"):
        _decision(decided_by="")
    with pytest.raises(LifecycleMalformed):
        EligibilityDecision(
            purpose="analysis",
            allowed=True,
            reason="",
            policy_version="policy/1",
            decided_at=NOW,
        )
