"""Privacy-safe security telemetry and recovery drill contracts (CP-10).

The foundation supplies the *mechanism* for security observability and
recovery evidence; the product SLIs, on-call process, and real backup
storage stay with the application.

Invariants:

- Telemetry events are whitelist-built: an event may carry only context
  fields a ``SafeFieldCatalog`` declared, and a field whose name even
  *contains* an identity, token, secret, raw-payload, or object-key marker
  can never be declared, so no event can carry one.
- Events are versioned; an unknown event version is refused, never guessed.
- Alert thresholds are validated contracts: a contradictory threshold
  (lower bound above upper bound, or a bound the direction does not use)
  is refused at construction.
- Recovery is proven, not asserted: a restore drill refuses a non-empty
  target, re-evaluates every component digest against the restored bytes,
  and re-checks tenant count, version, and old key references before it
  issues a receipt.  "The backup exists" is never a recovery.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any, Protocol

from .local_audit import ChainedAppendLog, ChainedRecord
from .manifest import ManifestMalformed
from .manifest import _require_digest as _manifest_require_digest
from .manifest import _require_text as _manifest_require_text

SUPPORTED_EVENT_VERSION = 1
SUPPORTED_THRESHOLD_VERSION = 1
SUPPORTED_BACKUP_FORMAT_VERSION = 1

_METRIC_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_SECRET_VALUE_RE = re.compile(
    r"(?i)(bearer\s+\S+|token\s*[=:]|password\s*[=:]|secret\s*[=:])"
)
# A context field whose name contains any of these fragments can carry an
# identity, a credential, raw payload bytes, or an object-store key, none of
# which may ever leave the process inside a telemetry event.  The check runs
# on the declared name as well as on every event, so a catalog cannot even
# declare such a field.
_FORBIDDEN_FIELD_PARTS = (
    "identity",
    "id_card",
    "external_id",
    "token",
    "password",
    "secret",
    "credential",
    "payload",
    "raw",
    "object_key",
    "email",
    "phone",
)


class ObservabilityError(Exception):
    """Base class for telemetry, threshold, and recovery failures."""


class ObservabilityMalformed(ObservabilityError):
    """An event, threshold, manifest, or receipt is structurally invalid."""


class ObservabilityVersionUnsupported(ObservabilityError):
    """A record declares an event or backup format version this build refuses."""


class RecoveryTargetNotEmpty(ObservabilityError):
    """A restore drill was pointed at a target that is not empty."""


class RecoveryVerificationFailed(ObservabilityError):
    """The restored target did not re-prove what the backup manifest commits to."""


def _require_digest(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_digest(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise ObservabilityMalformed(str(exc)) from exc


def _require_text(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_text(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise ObservabilityMalformed(str(exc)) from exc


def _require_aware(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None:
        raise ObservabilityMalformed(f"{field_name} must be timezone-aware")


def _require_finite(value: float, *, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ObservabilityMalformed(f"{field_name} must be a number")
    if not math.isfinite(value):
        raise ObservabilityMalformed(f"{field_name} must be finite")
    return float(value)


def _require_safe_field_name(name: str, *, field_name: str) -> str:
    _require_text(name, field_name=field_name)
    normalized = name.lower()
    for part in _FORBIDDEN_FIELD_PARTS:
        if part in normalized:
            raise ObservabilityMalformed(
                f"{field_name} is refused: {name!r} can carry identity, credential, "
                "raw payload, or object-key material"
            )
    return name


def _require_safe_value(value: Any, *, field_name: str) -> None:
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if _SECRET_VALUE_RE.search(value):
            raise ObservabilityMalformed(f"{field_name} contains a secret-like value")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ObservabilityMalformed(f"{field_name} keys must be text")
            _require_safe_value(item, field_name=field_name)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _require_safe_value(item, field_name=field_name)
        return
    raise ObservabilityMalformed(
        f"{field_name} accepts only JSON scalar and container values"
    )


class Severity(StrEnum):
    """Neutral severity ladder; paging policy stays with the application."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class SafeFieldCatalog:
    """The declared whitelist of context fields an event may carry.

    Declaring a field is the only way it can appear in an event, and a name
    carrying an identity/credential/payload/object-key marker cannot be
    declared at all.
    """

    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in self.fields:
            _require_safe_field_name(name, field_name="catalog field")
        if len(set(self.fields)) != len(self.fields):
            raise ObservabilityMalformed("catalog fields must be unique")

    def build_event(
        self,
        *,
        event_name: str,
        severity: Severity,
        component: str,
        correlation_id: str,
        occurred_at: datetime,
        fields: Mapping[str, Any] | None = None,
    ) -> SecurityEvent:
        """Build an event carrying only declared fields; anything else refuses."""
        provided = dict(fields or {})
        for key in provided:
            _require_safe_field_name(key, field_name="event field")
            if key not in self.fields:
                raise ObservabilityMalformed(
                    f"event field is not in the declared whitelist: {key!r}"
                )
        return SecurityEvent(
            event_name=event_name,
            severity=severity,
            component=component,
            correlation_id=correlation_id,
            occurred_at=occurred_at,
            fields=provided,
        )


@dataclass(frozen=True)
class SecurityEvent:
    """One versioned, privacy-safe security telemetry event.

    Construct this through :meth:`SafeFieldCatalog.build_event`; direct
    construction still enforces the version and value safety invariants but
    cannot enforce a catalog's whitelist.
    """

    event_name: str
    severity: Severity
    component: str
    correlation_id: str
    occurred_at: datetime
    fields: Mapping[str, Any]
    event_version: int = SUPPORTED_EVENT_VERSION

    def __post_init__(self) -> None:
        if self.event_version != SUPPORTED_EVENT_VERSION:
            raise ObservabilityVersionUnsupported(
                f"unsupported event version: {self.event_version!r}"
            )
        _require_text(self.event_name, field_name="event name")
        if not isinstance(self.severity, Severity):
            raise ObservabilityMalformed("severity must be a Severity")
        _require_text(self.component, field_name="component")
        _require_text(self.correlation_id, field_name="correlation id")
        _require_aware(self.occurred_at, field_name="occurred_at")
        for key, value in self.fields.items():
            _require_safe_field_name(key, field_name="event field")
            _require_safe_value(value, field_name=f"event field {key!r}")
        object.__setattr__(self, "fields", dict(self.fields))

    def to_canonical_mapping(self) -> dict[str, Any]:
        """A JSON-safe mapping with a reproducible byte form, fit for anchoring."""
        return {
            "event_version": self.event_version,
            "event_name": self.event_name,
            "severity": self.severity.value,
            "component": self.component,
            "correlation_id": self.correlation_id,
            "occurred_at": self.occurred_at.isoformat(),
            "fields": dict(self.fields),
        }

    def digest(self) -> str:
        encoded = json.dumps(
            self.to_canonical_mapping(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class ThresholdDirection(StrEnum):
    """Which side of the bound(s) constitutes a breach."""

    AT_MOST = "at_most"
    AT_LEAST = "at_least"
    WITHIN = "within"
    OUTSIDE = "outside"


@dataclass(frozen=True)
class SliThreshold:
    """A validated alerting contract for one metric over one window.

    The direction decides which bounds must be present; a bound the
    direction does not use, or a lower bound above the upper bound, is a
    contradiction and is refused rather than silently half-applied.
    """

    metric_name: str
    window: timedelta
    direction: ThresholdDirection
    lower: float | None = None
    upper: float | None = None
    threshold_version: int = SUPPORTED_THRESHOLD_VERSION

    def __post_init__(self) -> None:
        if self.threshold_version != SUPPORTED_THRESHOLD_VERSION:
            raise ObservabilityVersionUnsupported(
                f"unsupported threshold version: {self.threshold_version!r}"
            )
        _require_text(self.metric_name, field_name="metric name")
        if not _METRIC_NAME_RE.fullmatch(self.metric_name):
            raise ObservabilityMalformed(
                f"metric name must be lowercase snake case: {self.metric_name!r}"
            )
        if not isinstance(self.window, timedelta) or self.window <= timedelta(0):
            raise ObservabilityMalformed("window must be a positive duration")
        if not isinstance(self.direction, ThresholdDirection):
            raise ObservabilityMalformed("direction must be a ThresholdDirection")
        lower = self.lower
        upper = self.upper
        if lower is not None:
            lower = _require_finite(lower, field_name="threshold lower bound")
            object.__setattr__(self, "lower", lower)
        if upper is not None:
            upper = _require_finite(upper, field_name="threshold upper bound")
            object.__setattr__(self, "upper", upper)
        if self.direction in (ThresholdDirection.AT_MOST, ThresholdDirection.AT_LEAST):
            used, unused = (
                (upper, lower)
                if self.direction is ThresholdDirection.AT_MOST
                else (lower, upper)
            )
            if used is None:
                raise ObservabilityMalformed(
                    f"{self.direction.value} threshold requires its bound"
                )
            if unused is not None:
                raise ObservabilityMalformed(
                    f"{self.direction.value} threshold takes one bound; "
                    "a second bound is a contradiction"
                )
        else:
            if lower is None or upper is None:
                raise ObservabilityMalformed(
                    f"{self.direction.value} threshold requires both bounds"
                )
            if lower > upper:
                raise ObservabilityMalformed(
                    "threshold bounds contradict: lower bound is above the upper bound"
                )

    def is_breach(self, value: float) -> bool:
        """Whether one observed value breaches the contract."""
        _require_finite(value, field_name="observed value")
        lower = self.lower
        upper = self.upper
        if self.direction is ThresholdDirection.AT_MOST:
            if upper is None:
                raise ObservabilityMalformed("at_most threshold lost its bound")
            return value > upper
        if self.direction is ThresholdDirection.AT_LEAST:
            if lower is None:
                raise ObservabilityMalformed("at_least threshold lost its bound")
            return value < lower
        if lower is None or upper is None:
            raise ObservabilityMalformed("bounded threshold lost a bound")
        if self.direction is ThresholdDirection.WITHIN:
            return not (lower <= value <= upper)
        return lower <= value <= upper


class EventAuditAnchor:
    """Anchor a security event stream into a tamper-evident hash chain.

    Thin wrapper over :class:`ChainedAppendLog`: each event is appended as
    its canonical mapping, so ``verified_events`` re-proves the whole stream
    and ``head_digest`` is the anchor a caller stores outside the log
    directory.
    """

    def __init__(self, log: ChainedAppendLog) -> None:
        self._log = log

    def anchor(self, event: SecurityEvent) -> ChainedRecord:
        return self._log.append(event.to_canonical_mapping())

    def verified_events(self) -> tuple[ChainedRecord, ...]:
        return self._log.verified_records()

    def head_digest(self) -> str | None:
        return self._log.head_digest()


@dataclass(frozen=True)
class BackupComponent:
    """One restorable component, committed to by complete digest and size."""

    name: str
    sha256: str
    size_bytes: int
    key_reference: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.name, field_name="component name")
        _require_digest(self.sha256, field_name="component sha256")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes < 0
        ):
            raise ObservabilityMalformed("component size must be a non-negative integer")
        if self.key_reference is not None:
            _require_text(self.key_reference, field_name="component key reference")


@dataclass(frozen=True)
class BackupManifest:
    """Versioned commitment to what a backup must re-prove after a restore.

    The manifest carries component digests and sizes, the tenant count, the
    source version, and the old key references — everything a restore drill
    re-validates.  It never carries the payloads themselves.
    """

    components: tuple[BackupComponent, ...]
    tenant_count: int
    source_version: str
    created_at: datetime
    format_version: int = SUPPORTED_BACKUP_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != SUPPORTED_BACKUP_FORMAT_VERSION:
            raise ObservabilityVersionUnsupported(
                f"unsupported backup format version: {self.format_version!r}"
            )
        if not self.components:
            raise ObservabilityMalformed(
                "a backup manifest must declare at least one component; "
                "a manifest that asserts nothing proves nothing"
            )
        names = [component.name for component in self.components]
        if len(set(names)) != len(names):
            raise ObservabilityMalformed("component names must be unique")
        if (
            not isinstance(self.tenant_count, int)
            or isinstance(self.tenant_count, bool)
            or self.tenant_count < 0
        ):
            raise ObservabilityMalformed("tenant count must be a non-negative integer")
        _require_text(self.source_version, field_name="source version")
        _require_aware(self.created_at, field_name="created_at")

    def to_canonical_bytes(self) -> bytes:
        document: dict[str, Any] = {
            "format_version": self.format_version,
            "tenant_count": self.tenant_count,
            "source_version": self.source_version,
            "created_at": self.created_at.isoformat(),
            "components": [
                {
                    "name": component.name,
                    "sha256": component.sha256,
                    "size_bytes": component.size_bytes,
                    "key_reference": component.key_reference,
                }
                for component in self.components
            ],
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()


class RestoredTargetProbe(Protocol):
    """Read-only view of a restore target, before and after the restore.

    The application binds its real backup storage behind this protocol; the
    foundation never sees a backup location, credential, or payload beyond
    the bytes it is asked to re-digest.
    """

    def is_empty(self) -> bool:
        """Whether the target holds nothing yet; a drill refuses anything else."""
        ...

    def component_payload(self, name: str) -> bytes | None:
        """The restored bytes of one component, or None when it was not restored."""
        ...

    def tenant_count(self) -> int:
        """Tenants visible in the restored target."""
        ...

    def restored_version(self) -> str | None:
        """The schema/implementation version the restored target reports."""
        ...

    def available_key_references(self) -> tuple[str, ...]:
        """Key references resolvable against the restored target."""
        ...


@dataclass(frozen=True)
class ComponentVerification:
    """Proof that one component's restored bytes were actually re-digested."""

    name: str
    sha256: str
    size_bytes: int
    key_reference: str | None

    def __post_init__(self) -> None:
        _require_text(self.name, field_name="component name")
        _require_digest(self.sha256, field_name="component sha256")


@dataclass(frozen=True)
class RecoveryReceipt:
    """Evidence that a restore drill re-proved the manifest on an empty target.

    A receipt exists only when every component digest was re-evaluated
    against restored bytes and the tenant count, version, and key
    references matched; any shortfall raises instead.
    """

    manifest_digest: str
    components: tuple[ComponentVerification, ...]
    tenant_count: int
    restored_version: str
    verified_at: datetime
    format_version: int = SUPPORTED_BACKUP_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != SUPPORTED_BACKUP_FORMAT_VERSION:
            raise ObservabilityVersionUnsupported(
                f"unsupported recovery receipt format version: {self.format_version!r}"
            )
        _require_digest(self.manifest_digest, field_name="manifest digest")
        if not self.components:
            raise ObservabilityMalformed(
                "a recovery receipt must verify at least one component"
            )
        _require_text(self.restored_version, field_name="restored version")
        _require_aware(self.verified_at, field_name="verified_at")


class RestoreVerifier:
    """Run a restore drill against an empty target and prove the outcome."""

    def run_drill(
        self,
        manifest: BackupManifest,
        target: RestoredTargetProbe,
        restore: Callable[[], None],
        *,
        verified_at: datetime,
    ) -> RecoveryReceipt:
        """Restore into an empty target, then re-validate everything.

        The target must be empty before ``restore`` runs; afterwards every
        component digest is recomputed from the restored bytes, and the
        tenant count, source version, and declared key references are
        re-checked.  Any mismatch raises :class:`RecoveryVerificationFailed`
        with every shortfall listed.
        """

        _require_aware(verified_at, field_name="verified_at")
        if not target.is_empty():
            raise RecoveryTargetNotEmpty(
                "restore drills run against an empty target; restoring over live "
                "data would make the drill indistinguishable from an overwrite"
            )
        restore()

        failures: list[str] = []
        verifications: list[ComponentVerification] = []
        available_keys = set(target.available_key_references())
        for component in manifest.components:
            payload = target.component_payload(component.name)
            if payload is None:
                failures.append(
                    f"component {component.name!r} was declared but never restored"
                )
                continue
            if len(payload) != component.size_bytes:
                failures.append(
                    f"component {component.name!r} size mismatch: expected "
                    f"{component.size_bytes}, restored {len(payload)}"
                )
                continue
            digest = hashlib.sha256(payload).hexdigest()
            if digest != component.sha256:
                failures.append(f"component {component.name!r} digest mismatch")
                continue
            if component.key_reference is not None and (
                component.key_reference not in available_keys
            ):
                failures.append(
                    f"component {component.name!r} key reference "
                    f"{component.key_reference!r} is not resolvable after restore"
                )
                continue
            verifications.append(
                ComponentVerification(
                    name=component.name,
                    sha256=digest,
                    size_bytes=len(payload),
                    key_reference=component.key_reference,
                )
            )

        restored_version = target.restored_version()
        if restored_version != manifest.source_version:
            failures.append(
                f"restored version {restored_version!r} does not match the manifest "
                f"source version {manifest.source_version!r}"
            )
        tenant_count = target.tenant_count()
        if tenant_count != manifest.tenant_count:
            failures.append(
                f"restored tenant count {tenant_count} does not match the manifest "
                f"tenant count {manifest.tenant_count}"
            )
        if failures:
            raise RecoveryVerificationFailed("; ".join(failures))
        return RecoveryReceipt(
            manifest_digest=manifest.digest(),
            components=tuple(verifications),
            tenant_count=manifest.tenant_count,
            restored_version=manifest.source_version,
            verified_at=verified_at,
        )


class InMemoryRestoreTarget:
    """Reference :class:`RestoredTargetProbe` for tests and drills.

    Starts empty; ``load`` plays the role of the application's restore step
    by materialising component payloads and the restored facts.
    """

    def __init__(self) -> None:
        self._payloads: dict[str, bytes] = {}
        self._tenants = 0
        self._version: str | None = None
        self._key_references: tuple[str, ...] = ()

    def load(
        self,
        payloads: Mapping[str, bytes],
        *,
        tenant_count: int,
        version: str,
        key_references: tuple[str, ...] = (),
    ) -> None:
        for name, payload in payloads.items():
            self._payloads[name] = bytes(payload)
        self._tenants = tenant_count
        self._version = version
        self._key_references = tuple(key_references)

    def is_empty(self) -> bool:
        return not self._payloads and self._version is None

    def component_payload(self, name: str) -> bytes | None:
        return self._payloads.get(name)

    def tenant_count(self) -> int:
        return self._tenants

    def restored_version(self) -> str | None:
        return self._version

    def available_key_references(self) -> tuple[str, ...]:
        return self._key_references
