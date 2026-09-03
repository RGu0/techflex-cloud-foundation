"""Contract tests for provenance and layered validity evidence (F-28)."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib

import pytest

from techflex_cloud_foundation import (
    AdjudicationKind,
    AdjudicationRecord,
    ProvenanceMalformed,
    ProvenanceRecord,
    ProvenanceVersionUnsupported,
    ValidityEvidence,
    ValidityStatus,
)

NOW = datetime(2026, 9, 3, tzinfo=UTC)
DIGEST_A = hashlib.sha256(b"derived").hexdigest()
DIGEST_B = hashlib.sha256(b"raw").hexdigest()

AUTO = AdjudicationRecord(
    kind=AdjudicationKind.AUTOMATIC,
    rationale="rule evaluation",
    decided_at=NOW,
    rule_version="ruleset/3",
)
MANUAL = AdjudicationRecord(
    kind=AdjudicationKind.MANUAL,
    rationale="reviewer decision",
    decided_at=NOW,
    adjudicator="reviewer-1",
)


def _record(**overrides: object) -> ProvenanceRecord:
    kwargs: dict[str, object] = {
        "artifact_digest": DIGEST_A,
        "sources": (DIGEST_B,),
        "transform": "aggregate",
        "transform_version": "agg/1",
        "created_at": NOW,
    }
    kwargs.update(overrides)
    return ProvenanceRecord(**kwargs)  # type: ignore[arg-type]


def test_canonical_roundtrip_preserves_all_fields() -> None:
    record = _record(
        validity=(
            ValidityEvidence(
                level="session",
                status=ValidityStatus.SATISFIED,
                adjudication=AUTO,
                evidence_digest=DIGEST_B,
            ),
            ValidityEvidence(
                level="metric",
                status=ValidityStatus.VIOLATED,
                adjudication=MANUAL,
            ),
        )
    )

    parsed = ProvenanceRecord.from_bytes(record.to_canonical_bytes())

    assert parsed == record
    assert len(record.digest()) == 64


def test_serialization_is_reproducible_regardless_of_order() -> None:
    evidence_a = ValidityEvidence(level="segment", status=ValidityStatus.UNEVALUATED)
    evidence_b = ValidityEvidence(
        level="session", status=ValidityStatus.SATISFIED, adjudication=AUTO
    )

    first = _record(validity=(evidence_a, evidence_b))
    second = _record(validity=(evidence_b, evidence_a))

    assert first.to_canonical_bytes() == second.to_canonical_bytes()


def test_unknown_version_is_refused() -> None:
    with pytest.raises(ProvenanceVersionUnsupported):
        _record(format_version=99)


def test_levels_cannot_collapse_into_one_record() -> None:
    duplicate = ValidityEvidence(
        level="session", status=ValidityStatus.SATISFIED, adjudication=AUTO
    )

    with pytest.raises(ProvenanceMalformed, match="separate records"):
        _record(validity=(duplicate, duplicate))


def test_unevaluated_and_evaluated_invariants() -> None:
    with pytest.raises(ProvenanceMalformed, match="unevaluated"):
        ValidityEvidence(
            level="session", status=ValidityStatus.UNEVALUATED, adjudication=AUTO
        )
    with pytest.raises(ProvenanceMalformed, match="must name its adjudication"):
        ValidityEvidence(level="session", status=ValidityStatus.SATISFIED)


def test_automatic_requires_rule_version_and_manual_requires_adjudicator() -> None:
    with pytest.raises(ProvenanceMalformed, match="rule version"):
        AdjudicationRecord(
            kind=AdjudicationKind.AUTOMATIC, rationale="r", decided_at=NOW
        )
    with pytest.raises(ProvenanceMalformed, match="adjudicator"):
        AdjudicationRecord(kind=AdjudicationKind.MANUAL, rationale="r", decided_at=NOW)


def test_naive_timestamps_are_refused() -> None:
    with pytest.raises(ProvenanceMalformed, match="timezone-aware"):
        _record(created_at=datetime(2026, 9, 3))
    with pytest.raises(ProvenanceMalformed, match="timezone-aware"):
        AdjudicationRecord(
            kind=AdjudicationKind.AUTOMATIC,
            rationale="r",
            decided_at=datetime(2026, 9, 3),
            rule_version="ruleset/1",
        )


def test_sources_and_digests_are_complete() -> None:
    with pytest.raises(ProvenanceMalformed, match="at least one source"):
        _record(sources=())
    with pytest.raises(ProvenanceMalformed, match="complete"):
        _record(artifact_digest=DIGEST_A[:32])
    with pytest.raises(ProvenanceMalformed, match="complete"):
        _record(sources=(DIGEST_B[:16],))


def test_malformed_payloads_are_refused() -> None:
    with pytest.raises(ProvenanceMalformed):
        ProvenanceRecord.from_bytes(b"not json")
    with pytest.raises(ProvenanceMalformed, match="missing field"):
        ProvenanceRecord.from_bytes(b'{"format_version": 1}')
    document = _record().to_canonical_bytes().replace(b'"aggregate"', b'123')
    with pytest.raises(ProvenanceMalformed):
        ProvenanceRecord.from_bytes(document)
