"""Upload eligibility, retention, and deletion contracts (PRD F-30).

The foundation supplies the *mechanism*: purposes with retention classes, an
eligibility policy that answers "may this upload proceed", and an explicit
deletion decision/receipt pair.  It never supplies the business judgment —
whether a payload is VALID or INVALID, and what that means for upload, stays
with the application.  A server-side confirmation (an upload receipt) is not
a deletion authorization: deleting requires an explicit `DeletionDecision`,
and completion is proven by a `DeletionReceipt` that commits to it.
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

LIFECYCLE_FORMAT_VERSION = 1


class LifecycleError(Exception):
    """Base class for eligibility, retention, and deletion failures."""


class LifecycleMalformed(LifecycleError):
    """A policy, decision, or receipt is structurally invalid."""


class LifecycleVersionUnsupported(LifecycleError):
    """A serialized record declares a format version this build refuses."""


def _require_digest(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_digest(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise LifecycleMalformed(str(exc)) from exc


def _require_text(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_text(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise LifecycleMalformed(str(exc)) from exc


def _require_aware(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None:
        raise LifecycleMalformed(f"{field_name} must be timezone-aware")


class RetentionClass(StrEnum):
    """Neutral retention tiers; concrete durations stay deployment policy."""

    EPHEMERAL = "ephemeral"
    STANDARD = "standard"
    ARCHIVAL = "archival"


@dataclass(frozen=True)
class Purpose:
    """One declared use of uploaded artifacts and its retention behavior."""

    name: str
    default_retention: RetentionClass
    upload_allowed: bool = True
    deletion_requires_confirmation: bool = True

    def __post_init__(self) -> None:
        _require_text(self.name, field_name="purpose name")
        if not isinstance(self.default_retention, RetentionClass):
            raise LifecycleMalformed("default retention must be a RetentionClass")


@dataclass(frozen=True)
class EligibilityDecision:
    """The policy's answer for one upload attempt, with its reasoning."""

    purpose: str
    allowed: bool
    reason: str
    policy_version: str
    decided_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.purpose, field_name="purpose")
        _require_text(self.reason, field_name="decision reason")
        _require_text(self.policy_version, field_name="policy version")
        _require_aware(self.decided_at, field_name="decided_at")


@dataclass(frozen=True)
class UploadEligibilityPolicy:
    """Named purposes under one versioned policy; unknown purposes refuse."""

    purposes: tuple[Purpose, ...]
    policy_version: str

    def __post_init__(self) -> None:
        _require_text(self.policy_version, field_name="policy version")
        names = [purpose.name for purpose in self.purposes]
        if len(set(names)) != len(names):
            raise LifecycleMalformed("purpose names must be unique within a policy")

    def evaluate(
        self, purpose_name: str, *, decided_at: datetime
    ) -> EligibilityDecision:
        """Answer for one purpose; unknown purposes are never silently allowed."""
        _require_aware(decided_at, field_name="decided_at")
        _require_text(purpose_name, field_name="purpose name")
        for purpose in self.purposes:
            if purpose.name == purpose_name:
                return EligibilityDecision(
                    purpose=purpose.name,
                    allowed=purpose.upload_allowed,
                    reason=(
                        "purpose allows upload"
                        if purpose.upload_allowed
                        else "purpose forbids upload"
                    ),
                    policy_version=self.policy_version,
                    decided_at=decided_at,
                )
        return EligibilityDecision(
            purpose=purpose_name,
            allowed=False,
            reason="unknown purpose",
            policy_version=self.policy_version,
            decided_at=decided_at,
        )

    def purpose_named(self, name: str) -> Purpose:
        for purpose in self.purposes:
            if purpose.name == name:
                return purpose
        raise LifecycleMalformed(f"unknown purpose: {name!r}")


@dataclass(frozen=True)
class DeletionDecision:
    """An explicit, attributable authorization to delete one artifact.

    Constructing this type is the only way to authorize deletion; holding an
    upload receipt or any server confirmation never implies one.
    """

    artifact_digest: str
    reason: str
    decided_by: str
    decided_at: datetime
    policy_version: str
    format_version: int = LIFECYCLE_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != LIFECYCLE_FORMAT_VERSION:
            raise LifecycleVersionUnsupported(
                f"unsupported deletion decision format version: {self.format_version!r}"
            )
        _require_digest(self.artifact_digest, field_name="artifact digest")
        _require_text(self.reason, field_name="deletion reason")
        _require_text(self.decided_by, field_name="decided_by")
        _require_aware(self.decided_at, field_name="decided_at")
        _require_text(self.policy_version, field_name="policy version")

    def to_canonical_bytes(self) -> bytes:
        document: dict[str, Any] = {
            "format_version": self.format_version,
            "artifact_digest": self.artifact_digest,
            "reason": self.reason,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat(),
            "policy_version": self.policy_version,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class DeletionReceipt:
    """Proof that a deletion happened, committing to its explicit decision."""

    artifact_digest: str
    decision_digest: str
    deleted_at: datetime
    format_version: int = LIFECYCLE_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != LIFECYCLE_FORMAT_VERSION:
            raise LifecycleVersionUnsupported(
                f"unsupported deletion receipt format version: {self.format_version!r}"
            )
        _require_digest(self.artifact_digest, field_name="artifact digest")
        _require_digest(self.decision_digest, field_name="decision digest")
        _require_aware(self.deleted_at, field_name="deleted_at")

    @classmethod
    def for_decision(
        cls, decision: DeletionDecision, *, deleted_at: datetime
    ) -> DeletionReceipt:
        """Bind a receipt to the exact decision that authorized it."""
        return cls(
            artifact_digest=decision.artifact_digest,
            decision_digest=decision.digest(),
            deleted_at=deleted_at,
        )
