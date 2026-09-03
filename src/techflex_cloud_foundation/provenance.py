"""Artifact provenance and layered validity evidence (PRD F-28).

Provenance links a derived artifact back to its sources.  Validity is
recorded per evaluation *level* (for example a caller-defined ``segment``,
``session``, or ``metric`` level) and never collapses into a single boolean.
Every adjudication keeps the raw facts, the deciding party, and the rule
version apart: automatic decisions must name the rule version, manual ones
must name the adjudicator.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib
import json
from typing import Any

from .manifest import ManifestMalformed
from .manifest import _require_digest as _manifest_require_digest
from .manifest import _require_text as _manifest_require_text

PROVENANCE_FORMAT_VERSION = 1


def _require_digest(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_digest(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise ProvenanceMalformed(str(exc)) from exc


def _require_text(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_text(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise ProvenanceMalformed(str(exc)) from exc


class ProvenanceError(Exception):
    """Base class for provenance and validity failures."""


class ProvenanceMalformed(ProvenanceError):
    """A record is structurally invalid."""


class ProvenanceVersionUnsupported(ProvenanceError):
    """The record declares a format version this build refuses."""


class ValidityStatus(StrEnum):
    """Evaluation outcome for one level; absence of evidence stays explicit."""

    UNEVALUATED = "unevaluated"
    SATISFIED = "satisfied"
    VIOLATED = "violated"


class AdjudicationKind(StrEnum):
    AUTOMATIC = "automatic"
    MANUAL = "manual"


@dataclass(frozen=True)
class AdjudicationRecord:
    """Who or what produced a decision, kept apart from the raw facts."""

    kind: AdjudicationKind
    rationale: str
    decided_at: datetime
    rule_version: str | None = None
    adjudicator: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, AdjudicationKind):
            raise ProvenanceMalformed("adjudication kind must be an AdjudicationKind")
        _require_text(self.rationale, field_name="adjudication rationale")
        if self.decided_at.tzinfo is None:
            raise ProvenanceMalformed("decided_at must be timezone-aware")
        if self.kind is AdjudicationKind.AUTOMATIC:
            if self.rule_version is None:
                raise ProvenanceMalformed("automatic adjudication must name the rule version")
            _require_text(self.rule_version, field_name="rule version")
        if self.kind is AdjudicationKind.MANUAL:
            if self.adjudicator is None:
                raise ProvenanceMalformed("manual adjudication must name the adjudicator")
            _require_text(self.adjudicator, field_name="adjudicator")


@dataclass(frozen=True)
class ValidityEvidence:
    """One level's outcome plus the adjudication and facts behind it."""

    level: str
    status: ValidityStatus
    adjudication: AdjudicationRecord | None = None
    evidence_digest: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.level, field_name="validity level")
        if not isinstance(self.status, ValidityStatus):
            raise ProvenanceMalformed("validity status must be a ValidityStatus")
        if self.status is ValidityStatus.UNEVALUATED and self.adjudication is not None:
            raise ProvenanceMalformed("unevaluated evidence cannot carry an adjudication")
        if self.status is not ValidityStatus.UNEVALUATED and self.adjudication is None:
            raise ProvenanceMalformed("evaluated evidence must name its adjudication")
        if self.evidence_digest is not None:
            _require_digest(self.evidence_digest, field_name="evidence digest")


@dataclass(frozen=True)
class ProvenanceRecord:
    """Lineage of one derived artifact: sources, transform, layered validity."""

    artifact_digest: str
    sources: tuple[str, ...]
    transform: str
    transform_version: str
    created_at: datetime
    validity: tuple[ValidityEvidence, ...] = ()
    format_version: int = PROVENANCE_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != PROVENANCE_FORMAT_VERSION:
            raise ProvenanceVersionUnsupported(
                f"unsupported provenance format version: {self.format_version!r}"
            )
        _require_digest(self.artifact_digest, field_name="artifact digest")
        if not self.sources:
            raise ProvenanceMalformed("a derived artifact must name at least one source")
        for source in self.sources:
            _require_digest(source, field_name="source digest")
        _require_text(self.transform, field_name="transform")
        _require_text(self.transform_version, field_name="transform version")
        if self.created_at.tzinfo is None:
            raise ProvenanceMalformed("created_at must be timezone-aware")
        levels = [evidence.level for evidence in self.validity]
        if len(set(levels)) != len(levels):
            raise ProvenanceMalformed(
                "validity levels must stay separate records; duplicate level refused"
            )
        # Canonical ordering by level makes the record itself reproducible.
        object.__setattr__(
            self, "validity", tuple(sorted(self.validity, key=lambda item: item.level))
        )

    def to_canonical_bytes(self) -> bytes:
        """Serialize reproducibly: sorted keys, evidence ordered by level."""

        def adjudication_document(record: AdjudicationRecord) -> dict[str, Any]:
            return {
                "kind": str(record.kind),
                "rationale": record.rationale,
                "decided_at": record.decided_at.isoformat(),
                "rule_version": record.rule_version,
                "adjudicator": record.adjudicator,
            }

        document: dict[str, Any] = {
            "format_version": self.format_version,
            "artifact_digest": self.artifact_digest,
            "sources": sorted(self.sources),
            "transform": self.transform,
            "transform_version": self.transform_version,
            "created_at": self.created_at.isoformat(),
            "validity": [
                {
                    "level": evidence.level,
                    "status": str(evidence.status),
                    "adjudication": (
                        adjudication_document(evidence.adjudication)
                        if evidence.adjudication
                        else None
                    ),
                    "evidence_digest": evidence.evidence_digest,
                }
                for evidence in sorted(self.validity, key=lambda item: item.level)
            ],
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        """Complete SHA-256 of the canonical bytes."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, payload: bytes) -> ProvenanceRecord:
        """Parse a record, refusing unknown versions instead of guessing."""
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProvenanceMalformed(f"provenance record is not valid JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise ProvenanceMalformed("provenance record must be a JSON object")

        def parse_adjudication(raw: dict[str, Any]) -> AdjudicationRecord:
            return AdjudicationRecord(
                kind=AdjudicationKind(raw["kind"]),
                rationale=raw["rationale"],
                decided_at=datetime.fromisoformat(raw["decided_at"]),
                rule_version=raw.get("rule_version"),
                adjudicator=raw.get("adjudicator"),
            )

        try:
            return cls(
                format_version=document["format_version"],
                artifact_digest=document["artifact_digest"],
                sources=tuple(document["sources"]),
                transform=document["transform"],
                transform_version=document["transform_version"],
                created_at=datetime.fromisoformat(document["created_at"]),
                validity=tuple(
                    ValidityEvidence(
                        level=item["level"],
                        status=ValidityStatus(item["status"]),
                        adjudication=(
                            parse_adjudication(item["adjudication"])
                            if item.get("adjudication")
                            else None
                        ),
                        evidence_digest=item.get("evidence_digest"),
                    )
                    for item in document.get("validity", ())
                ),
            )
        except KeyError as exc:
            raise ProvenanceMalformed(f"provenance record is missing field: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise ProvenanceMalformed(f"provenance record field has the wrong shape: {exc}") from exc
