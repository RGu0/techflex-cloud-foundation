"""Server-side license/entitlement lifecycle (CP-04), business-neutral.

The issuance and control plane for licenses: stock (``issue``) → ``activate``
→ ``renew`` ⇄ ``suspend``/``resume`` → ``revoke``.  It composes the
foundation's ed25519 signing discipline (the same mechanism
``entitlement.TrustBundle`` uses for client trust bundles) without binding any
product SKU, price, seat rule, database, or cloud SDK.

Invariants carried over from RAY-341 and the reference implementation:

- The lifecycle is a whitelist: a transition is legal because it is written
  down, never by omission.  ``REVOKED`` is terminal; a license issued again
  after revocation is a new ``license_id``, never this record moved backwards.
- Every accepted step appends one immutable `LicenseLifecycleEvent` carrying
  its reason and an explicitly injected ``occurred_at`` — nothing here reads a
  real clock.
- Activation tokens are single-use.  A re-presented serial is refused, whether
  the replay comes from the same account (double spend) or a different one
  (cross-account replay); both are `LicenseReplayRejected`.
- License documents are signed and the signing keyset is versioned
  (`LicenseKeyset.revision`, active key id, revoked key ids).  A document
  signed under an unknown or revoked key id is refused, never guessed.
- A license *authorizes*; it never derives data keys.  This module neither
  accepts nor emits data-key material — the only key material in scope is the
  ed25519 signing keypair that authenticates license documents.
- SKU, term, feature set, and offline grace are product policy, injected
  through `LicensePolicy`; no FeetForcePlate rule is hardcoded here.
- Persistence sits behind the `LicenseLifecycleStore` protocol; the shipped
  `InMemoryLicenseLifecycleStore` covers tests and integration runs,
  production binds PostgreSQL in the application layer.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
import hashlib
import json
from typing import Any, Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LICENSE_LIFECYCLE_FORMAT_VERSION = 1
LICENSE_DOCUMENT_FORMAT_VERSION = 1


class LicenseLifecycleError(Exception):
    """Base class for license lifecycle failures."""


class LicenseLifecycleMalformed(LicenseLifecycleError):
    """A request, record, or document is structurally invalid."""


class LicenseLifecycleVersionUnsupported(LicenseLifecycleError):
    """A serialized record declares a format version this build refuses."""


class LicenseLifecycleConflict(LicenseLifecycleError):
    """A store write lost an optimistic-concurrency race or duplicates an id."""


class LicenseTransitionRejected(LicenseLifecycleError):
    """The requested move is not on the lifecycle whitelist."""


class LicenseActivationRejected(LicenseLifecycleError):
    """The activation serial is unknown or the license cannot be activated."""


class LicenseReplayRejected(LicenseActivationRejected):
    """The activation serial was already consumed — replay or double spend."""


class LicenseSigningKeyUnknown(LicenseLifecycleError):
    """A document names a key id the keyset does not hold, or a revoked one."""


class LicenseSignatureInvalid(LicenseLifecycleError):
    """A document signature does not verify under its named key."""


def _require_text(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LicenseLifecycleMalformed(f"{field_name} must be non-empty text")
    return value


def _require_aware(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None:
        raise LicenseLifecycleMalformed(f"{field_name} must be timezone-aware")


def _require_optional_aware(value: datetime | None, *, field_name: str) -> None:
    if value is not None:
        _require_aware(value, field_name=field_name)


class LicenseLifecycleState(StrEnum):
    """Server-side lifecycle states; ``ISSUED`` is the stocked state."""

    ISSUED = "ISSUED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class LicenseLifecycleAction(StrEnum):
    ISSUE = "ISSUE"
    ACTIVATE = "ACTIVATE"
    RENEW = "RENEW"
    SUSPEND = "SUSPEND"
    RESUME = "RESUME"
    REVOKE = "REVOKE"


# The whole lifecycle as a table rather than as guard clauses.  Every pair not
# named here is refused; ``ACTIVE -> ACTIVE`` exists only for ``renew``, which
# extends the validity window, so the plain ``_transition`` helper never takes
# it — renewal goes through :meth:`LicenseLifecycleService.renew`.
_ALLOWED_TRANSITIONS: Mapping[
    LicenseLifecycleState, frozenset[LicenseLifecycleState]
] = {
    LicenseLifecycleState.ISSUED: frozenset({LicenseLifecycleState.ACTIVE}),
    LicenseLifecycleState.ACTIVE: frozenset(
        {
            LicenseLifecycleState.ACTIVE,
            LicenseLifecycleState.SUSPENDED,
            LicenseLifecycleState.REVOKED,
        }
    ),
    LicenseLifecycleState.SUSPENDED: frozenset(
        {LicenseLifecycleState.ACTIVE, LicenseLifecycleState.REVOKED}
    ),
    LicenseLifecycleState.REVOKED: frozenset(),
}

_ACTION_TARGET: Mapping[LicenseLifecycleAction, LicenseLifecycleState] = {
    LicenseLifecycleAction.ACTIVATE: LicenseLifecycleState.ACTIVE,
    LicenseLifecycleAction.RENEW: LicenseLifecycleState.ACTIVE,
    LicenseLifecycleAction.SUSPEND: LicenseLifecycleState.SUSPENDED,
    LicenseLifecycleAction.RESUME: LicenseLifecycleState.ACTIVE,
    LicenseLifecycleAction.REVOKE: LicenseLifecycleState.REVOKED,
}

# Three actions share the target ACTIVE but not the source: the state table
# alone would let ``resume`` activate a stocked license and ``renew`` run from
# SUSPENDED, so each action also whitelists where it may start.
_ACTION_SOURCES: Mapping[
    LicenseLifecycleAction, frozenset[LicenseLifecycleState]
] = {
    LicenseLifecycleAction.ACTIVATE: frozenset({LicenseLifecycleState.ISSUED}),
    LicenseLifecycleAction.RENEW: frozenset({LicenseLifecycleState.ACTIVE}),
    LicenseLifecycleAction.SUSPEND: frozenset({LicenseLifecycleState.ACTIVE}),
    LicenseLifecycleAction.RESUME: frozenset({LicenseLifecycleState.SUSPENDED}),
    LicenseLifecycleAction.REVOKE: frozenset(
        {LicenseLifecycleState.ACTIVE, LicenseLifecycleState.SUSPENDED}
    ),
}


def _transition(
    current: LicenseLifecycleState, action: LicenseLifecycleAction
) -> LicenseLifecycleState:
    """Resolve one action against both whitelists, or explain the refusal."""

    target = _ACTION_TARGET[action]
    if (
        current not in _ACTION_SOURCES[action]
        or target not in _ALLOWED_TRANSITIONS[current]
    ):
        raise LicenseTransitionRejected(
            _rejection_reason(current, action, target)
        )
    return target


def _rejection_reason(
    current: LicenseLifecycleState,
    action: LicenseLifecycleAction,
    target: LicenseLifecycleState,
) -> str:
    if current is LicenseLifecycleState.REVOKED:
        return (
            "a revoked license is terminal and cannot be "
            f"{action.value.lower()}d again; issue a new license"
        )
    if current is target:
        return (
            f"a license is already {current.value}; {action.value.lower()} is "
            "not an idempotent replay, each step appends a new event"
        )
    if current is LicenseLifecycleState.ISSUED:
        return (
            "an issued license becomes ACTIVE only through activate(), which "
            "consumes its one-time serial and binds tenant, account, and hardware"
        )
    return f"{current.value} does not allow {action.value.lower()}"


@dataclass(frozen=True)
class LicenseLifecycleEvent:
    """One immutable step in a license's history, with its reason."""

    license_id: UUID
    sequence: int
    action: LicenseLifecycleAction
    from_state: LicenseLifecycleState | None
    to_state: LicenseLifecycleState
    reason: str
    occurred_at: datetime
    format_version: int = LICENSE_LIFECYCLE_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != LICENSE_LIFECYCLE_FORMAT_VERSION:
            raise LicenseLifecycleVersionUnsupported(
                f"unsupported lifecycle event format version: {self.format_version!r}"
            )
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 1
        ):
            raise LicenseLifecycleMalformed("event sequence must be a positive integer")
        if not isinstance(self.action, LicenseLifecycleAction):
            raise LicenseLifecycleMalformed("action must be a LicenseLifecycleAction")
        if not isinstance(self.to_state, LicenseLifecycleState):
            raise LicenseLifecycleMalformed("to_state must be a LicenseLifecycleState")
        if self.from_state is not None and not isinstance(
            self.from_state, LicenseLifecycleState
        ):
            raise LicenseLifecycleMalformed(
                "from_state must be a LicenseLifecycleState or None"
            )
        _require_text(self.reason, field_name="event reason")
        _require_aware(self.occurred_at, field_name="occurred_at")

    def canonical_bytes(self) -> bytes:
        document: dict[str, Any] = {
            "format_version": self.format_version,
            "license_id": str(self.license_id),
            "sequence": self.sequence,
            "action": self.action.value,
            "from_state": self.from_state.value if self.from_state else None,
            "to_state": self.to_state.value,
            "reason": self.reason,
            "occurred_at": self.occurred_at.isoformat(),
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class LicenseLifecycleRecord:
    """The current state of one managed license; history lives in events."""

    license_id: UUID
    state: LicenseLifecycleState
    version: int
    sku: str
    activation_serial: str
    issued_at: datetime
    tenant_id: UUID | None = None
    account_id: UUID | None = None
    hardware_id: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    activated_at: datetime | None = None
    activated_by: UUID | None = None
    event_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.state, LicenseLifecycleState):
            raise LicenseLifecycleMalformed("state must be a LicenseLifecycleState")
        if (
            not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or self.version < 1
        ):
            raise LicenseLifecycleMalformed("version must be a positive integer")
        _require_text(self.sku, field_name="sku")
        _require_text(self.activation_serial, field_name="activation serial")
        _require_aware(self.issued_at, field_name="issued_at")
        for field_name, value in (
            ("valid_from", self.valid_from),
            ("valid_until", self.valid_until),
            ("activated_at", self.activated_at),
        ):
            _require_optional_aware(value, field_name=field_name)
        if self.valid_from is not None and self.valid_until is not None:
            if self.valid_until <= self.valid_from:
                raise LicenseLifecycleMalformed("valid_until must follow valid_from")
        if (
            not isinstance(self.event_count, int)
            or isinstance(self.event_count, bool)
            or self.event_count < 0
        ):
            raise LicenseLifecycleMalformed("event_count must be a non-negative integer")
        if self.state is LicenseLifecycleState.ISSUED and (
            self.tenant_id is not None
            or self.account_id is not None
            or self.hardware_id is not None
            or self.activated_at is not None
        ):
            raise LicenseLifecycleMalformed(
                "an issued license carries no tenant, account, or hardware binding"
            )


class LicensePolicy(Protocol):
    """Product policy boundary: SKU, term, features, and offline grace.

    The foundation injects *what* is asked, the application decides *how
    much*: validity windows, feature sets, and grace durations are business
    decisions and never live in this module.
    """

    def activation_window(
        self, *, sku: str, activated_at: datetime
    ) -> tuple[datetime, datetime]:
        """The ``(valid_from, valid_until)`` a first activation grants."""
        ...

    def renewal_window(
        self, *, sku: str, current_valid_until: datetime, now: datetime
    ) -> tuple[datetime, datetime]:
        """The ``(valid_from, valid_until)`` a renewal grants."""
        ...

    def features(self, *, sku: str) -> frozenset[str]:
        """The capability set the SKU entitles; unknown SKUs are refused."""
        ...

    def offline_grace(self, *, sku: str) -> timedelta:
        """How long past ``valid_until`` an offline client may still run."""
        ...


@dataclass(frozen=True)
class OfflineAccessDecision:
    """The grace-aware expiry answer for one license at one instant."""

    license_id: UUID
    allowed: bool
    reason: str
    valid_until: datetime | None
    grace: timedelta
    evaluated_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.reason, field_name="decision reason")
        _require_optional_aware(self.valid_until, field_name="valid_until")
        _require_aware(self.evaluated_at, field_name="evaluated_at")
        if not isinstance(self.grace, timedelta) or self.grace < timedelta(0):
            raise LicenseLifecycleMalformed("grace must be a non-negative duration")


@dataclass(frozen=True)
class LicenseKeyset:
    """A versioned set of license signing keys: one active, some revoked."""

    revision: int
    active_key_id: str
    public_keys: Mapping[str, bytes]
    revoked_key_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 1
        ):
            raise LicenseLifecycleMalformed("keyset revision must be a positive integer")
        _require_text(self.active_key_id, field_name="active key id")
        if not self.public_keys:
            raise LicenseLifecycleMalformed("at least one public key is required")
        if self.active_key_id not in self.public_keys:
            raise LicenseLifecycleMalformed(
                "the active key id must name a key in this keyset"
            )
        if self.active_key_id in self.revoked_key_ids:
            raise LicenseLifecycleMalformed("the active key id cannot be revoked")
        if len(set(self.revoked_key_ids)) != len(self.revoked_key_ids):
            raise LicenseLifecycleMalformed("revoked key ids must be unique")

    def public_key(self, key_id: str) -> Ed25519PublicKey:
        """Resolve a key id for verification; unknown or revoked ids refuse."""
        if key_id in self.revoked_key_ids:
            raise LicenseSigningKeyUnknown(
                f"license signing key {key_id!r} is revoked in keyset "
                f"revision {self.revision}"
            )
        raw = self.public_keys.get(key_id)
        if raw is None:
            raise LicenseSigningKeyUnknown(
                f"license signing key {key_id!r} is unknown to keyset "
                f"revision {self.revision}"
            )
        return Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, signed: SignedLicenseDocument) -> LicenseDocument:
        """Verify a signed document; the signature is checked before any claim."""
        public_key = self.public_key(signed.key_id)
        try:
            signature = base64.b64decode(signed.signature, validate=True)
            public_key.verify(signature, signed.document.canonical_bytes())
        except (binascii.Error, ValueError, InvalidSignature) as exc:
            raise LicenseSignatureInvalid(
                "license document signature is invalid"
            ) from exc
        return signed.document


@dataclass(frozen=True)
class LicenseDocument:
    """The signed license payload; it authorizes and never derives data keys."""

    license_id: UUID
    state: LicenseLifecycleState
    version: int
    sku: str
    features: frozenset[str]
    issued_at: datetime
    tenant_id: UUID | None = None
    account_id: UUID | None = None
    hardware_id: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    format_version: int = LICENSE_DOCUMENT_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != LICENSE_DOCUMENT_FORMAT_VERSION:
            raise LicenseLifecycleVersionUnsupported(
                f"unsupported license document format version: {self.format_version!r}"
            )
        if not isinstance(self.state, LicenseLifecycleState):
            raise LicenseLifecycleMalformed("state must be a LicenseLifecycleState")
        if (
            not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or self.version < 1
        ):
            raise LicenseLifecycleMalformed("version must be a positive integer")
        _require_text(self.sku, field_name="sku")
        if not isinstance(self.features, frozenset):
            raise LicenseLifecycleMalformed("features must be a frozenset")
        for feature in self.features:
            _require_text(feature, field_name="feature")
        _require_aware(self.issued_at, field_name="issued_at")
        _require_optional_aware(self.valid_from, field_name="valid_from")
        _require_optional_aware(self.valid_until, field_name="valid_until")
        if self.valid_from is not None and self.valid_until is not None:
            if self.valid_until <= self.valid_from:
                raise LicenseLifecycleMalformed("valid_until must follow valid_from")

    @classmethod
    def for_record(
        cls, record: LicenseLifecycleRecord, *, features: frozenset[str]
    ) -> LicenseDocument:
        """Project the current record into the document clients receive."""
        return cls(
            license_id=record.license_id,
            state=record.state,
            version=record.version,
            sku=record.sku,
            features=features,
            issued_at=record.issued_at,
            tenant_id=record.tenant_id,
            account_id=record.account_id,
            hardware_id=record.hardware_id,
            valid_from=record.valid_from,
            valid_until=record.valid_until,
        )

    def canonical_bytes(self) -> bytes:
        document: dict[str, Any] = {
            "format_version": self.format_version,
            "license_id": str(self.license_id),
            "state": self.state.value,
            "version": self.version,
            "sku": self.sku,
            "features": sorted(self.features),
            "issued_at": self.issued_at.isoformat(),
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "account_id": str(self.account_id) if self.account_id else None,
            "hardware_id": self.hardware_id,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(
        self, signing_key: Ed25519PrivateKey, *, keyset: LicenseKeyset
    ) -> SignedLicenseDocument:
        """Sign under the keyset's active key id; the key id travels with it."""
        keyset.public_key(keyset.active_key_id)
        signature = base64.b64encode(
            signing_key.sign(self.canonical_bytes())
        ).decode("ascii")
        return SignedLicenseDocument(
            document=self,
            key_id=keyset.active_key_id,
            signature=signature,
            keyset_revision=keyset.revision,
        )


@dataclass(frozen=True)
class SignedLicenseDocument:
    """A license document plus the key id, signature, and keyset revision."""

    document: LicenseDocument
    key_id: str
    signature: str
    keyset_revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.document, LicenseDocument):
            raise LicenseLifecycleMalformed("document must be a LicenseDocument")
        _require_text(self.key_id, field_name="key id")
        _require_text(self.signature, field_name="signature")
        if (
            not isinstance(self.keyset_revision, int)
            or isinstance(self.keyset_revision, bool)
            or self.keyset_revision < 1
        ):
            raise LicenseLifecycleMalformed(
                "keyset revision must be a positive integer"
            )


class LicenseLifecycleStore(Protocol):
    """Persistence boundary; production binds PostgreSQL, tests use memory."""

    async def get(self, license_id: UUID) -> LicenseLifecycleRecord: ...

    async def find_by_activation_serial(
        self, activation_serial: str
    ) -> LicenseLifecycleRecord | None: ...

    async def insert(self, record: LicenseLifecycleRecord) -> None: ...

    async def replace(
        self, record: LicenseLifecycleRecord, *, expected_version: int
    ) -> None: ...

    async def append(self, event: LicenseLifecycleEvent) -> None: ...

    async def events(self, license_id: UUID) -> tuple[LicenseLifecycleEvent, ...]: ...


class InMemoryLicenseLifecycleStore:
    """Volatile reference store, suitable for tests and integration runs."""

    def __init__(self) -> None:
        self._records: dict[UUID, LicenseLifecycleRecord] = {}
        self._events: dict[UUID, list[LicenseLifecycleEvent]] = {}

    async def get(self, license_id: UUID) -> LicenseLifecycleRecord:
        try:
            return self._records[license_id]
        except KeyError:
            raise LicenseLifecycleMalformed(
                f"unknown license {license_id}"
            ) from None

    async def find_by_activation_serial(
        self, activation_serial: str
    ) -> LicenseLifecycleRecord | None:
        for record in self._records.values():
            if record.activation_serial == activation_serial:
                return record
        return None

    async def insert(self, record: LicenseLifecycleRecord) -> None:
        if record.license_id in self._records:
            raise LicenseLifecycleConflict(
                f"license {record.license_id} already exists"
            )
        self._records[record.license_id] = record
        self._events[record.license_id] = []

    async def replace(
        self, record: LicenseLifecycleRecord, *, expected_version: int
    ) -> None:
        current = await self.get(record.license_id)
        if current.version != expected_version:
            raise LicenseLifecycleConflict(
                f"license {record.license_id} is at version {current.version}, "
                f"not {expected_version}"
            )
        self._records[record.license_id] = record

    async def append(self, event: LicenseLifecycleEvent) -> None:
        history = self._events.setdefault(event.license_id, [])
        if any(existing.sequence == event.sequence for existing in history):
            raise LicenseLifecycleConflict(
                f"license {event.license_id} already has event {event.sequence}"
            )
        history.append(event)

    async def events(self, license_id: UUID) -> tuple[LicenseLifecycleEvent, ...]:
        await self.get(license_id)
        return tuple(self._events.get(license_id, ()))


class LicenseLifecycleService:
    """Orchestrates the lifecycle, signed documents, and replay refusal."""

    def __init__(
        self,
        store: LicenseLifecycleStore,
        policy: LicensePolicy,
        *,
        signing_key: Ed25519PrivateKey,
        keyset: LicenseKeyset,
    ) -> None:
        if not isinstance(keyset, LicenseKeyset):
            raise LicenseLifecycleMalformed("keyset must be a LicenseKeyset")
        self._store = store
        self._policy = policy
        self._signing_key = signing_key
        self._keyset = keyset

    async def _emit(
        self,
        record: LicenseLifecycleRecord,
        action: LicenseLifecycleAction,
        *,
        from_state: LicenseLifecycleState | None,
        reason: str,
        now: datetime,
    ) -> LicenseLifecycleEvent:
        """Append the event whose sequence is the record's event_count."""
        _require_text(reason, field_name="reason")
        _require_aware(now, field_name="now")
        event = LicenseLifecycleEvent(
            license_id=record.license_id,
            sequence=record.event_count,
            action=action,
            from_state=from_state,
            to_state=record.state,
            reason=reason,
            occurred_at=now,
        )
        await self._store.append(event)
        return event

    def _sign(self, record: LicenseLifecycleRecord) -> SignedLicenseDocument:
        document = LicenseDocument.for_record(
            record, features=self._policy.features(sku=record.sku)
        )
        return document.sign(self._signing_key, keyset=self._keyset)

    async def issue(
        self, *, sku: str, activation_serial: str, reason: str, now: datetime
    ) -> tuple[LicenseLifecycleRecord, SignedLicenseDocument]:
        """Stock one license; its serial is the one-time activation credential."""
        _require_text(sku, field_name="sku")
        _require_text(activation_serial, field_name="activation serial")
        _require_aware(now, field_name="now")
        self._policy.features(sku=sku)
        if await self._store.find_by_activation_serial(activation_serial) is not None:
            raise LicenseLifecycleConflict(
                "activation serial is already bound to a license"
            )
        record = LicenseLifecycleRecord(
            license_id=uuid4(),
            state=LicenseLifecycleState.ISSUED,
            version=1,
            sku=sku,
            activation_serial=activation_serial,
            issued_at=now,
            event_count=1,
        )
        await self._store.insert(record)
        await self._emit(
            record,
            LicenseLifecycleAction.ISSUE,
            from_state=None,
            reason=reason,
            now=now,
        )
        return record, self._sign(record)

    async def activate(
        self,
        *,
        activation_serial: str,
        tenant_id: UUID,
        account_id: UUID,
        hardware_id: str,
        reason: str,
        now: datetime,
    ) -> tuple[LicenseLifecycleRecord, SignedLicenseDocument]:
        """Consume a serial exactly once and bind tenant, account, hardware."""
        _require_text(activation_serial, field_name="activation serial")
        _require_text(hardware_id, field_name="hardware id")
        _require_aware(now, field_name="now")
        record = await self._store.find_by_activation_serial(activation_serial)
        if record is None:
            raise LicenseActivationRejected("activation serial is unknown")
        if record.activated_at is not None:
            if record.activated_by != account_id:
                raise LicenseReplayRejected(
                    "activation serial was already consumed by a different account; "
                    "cross-account replay is refused"
                )
            raise LicenseReplayRejected(
                "activation serial was already consumed; activation is single-use"
            )
        _transition(record.state, LicenseLifecycleAction.ACTIVATE)
        valid_from, valid_until = self._policy.activation_window(
            sku=record.sku, activated_at=now
        )
        updated = LicenseLifecycleRecord(
            license_id=record.license_id,
            state=LicenseLifecycleState.ACTIVE,
            version=record.version + 1,
            sku=record.sku,
            activation_serial=record.activation_serial,
            issued_at=record.issued_at,
            tenant_id=tenant_id,
            account_id=account_id,
            hardware_id=hardware_id,
            valid_from=valid_from,
            valid_until=valid_until,
            activated_at=now,
            activated_by=account_id,
            event_count=record.event_count + 1,
        )
        await self._store.replace(updated, expected_version=record.version)
        await self._emit(
            updated,
            LicenseLifecycleAction.ACTIVATE,
            from_state=record.state,
            reason=reason,
            now=now,
        )
        return await self._finish(updated)

    async def renew(
        self, license_id: UUID, *, reason: str, now: datetime
    ) -> tuple[LicenseLifecycleRecord, SignedLicenseDocument]:
        """Extend the validity window of an ACTIVE license; never a replay."""
        record = await self._store.get(license_id)
        _require_aware(now, field_name="now")
        _transition(record.state, LicenseLifecycleAction.RENEW)
        if record.valid_until is None:
            raise LicenseTransitionRejected(
                "only an activated license with a validity window can renew"
            )
        valid_from, valid_until = self._policy.renewal_window(
            sku=record.sku, current_valid_until=record.valid_until, now=now
        )
        _require_aware(valid_from, field_name="renewed valid_from")
        _require_aware(valid_until, field_name="renewed valid_until")
        if valid_until <= now:
            raise LicenseLifecycleMalformed(
                "renewal must not produce an already-expired window"
            )
        updated = LicenseLifecycleRecord(
            license_id=record.license_id,
            state=LicenseLifecycleState.ACTIVE,
            version=record.version + 1,
            sku=record.sku,
            activation_serial=record.activation_serial,
            issued_at=record.issued_at,
            tenant_id=record.tenant_id,
            account_id=record.account_id,
            hardware_id=record.hardware_id,
            valid_from=valid_from,
            valid_until=valid_until,
            activated_at=record.activated_at,
            activated_by=record.activated_by,
            event_count=record.event_count + 1,
        )
        await self._store.replace(updated, expected_version=record.version)
        await self._emit(
            updated,
            LicenseLifecycleAction.RENEW,
            from_state=record.state,
            reason=reason,
            now=now,
        )
        return await self._finish(updated)

    async def suspend(
        self, license_id: UUID, *, reason: str, now: datetime
    ) -> tuple[LicenseLifecycleRecord, SignedLicenseDocument]:
        return await self._control(
            license_id, LicenseLifecycleAction.SUSPEND, reason=reason, now=now
        )

    async def resume(
        self, license_id: UUID, *, reason: str, now: datetime
    ) -> tuple[LicenseLifecycleRecord, SignedLicenseDocument]:
        """Restore a suspended license; bindings and window are kept."""
        return await self._control(
            license_id, LicenseLifecycleAction.RESUME, reason=reason, now=now
        )

    async def revoke(
        self, license_id: UUID, *, reason: str, now: datetime
    ) -> tuple[LicenseLifecycleRecord, SignedLicenseDocument]:
        """Terminate a license; REVOKED has no outbound edge, by design."""
        return await self._control(
            license_id, LicenseLifecycleAction.REVOKE, reason=reason, now=now
        )

    async def _control(
        self,
        license_id: UUID,
        action: LicenseLifecycleAction,
        *,
        reason: str,
        now: datetime,
    ) -> tuple[LicenseLifecycleRecord, SignedLicenseDocument]:
        record = await self._store.get(license_id)
        _require_aware(now, field_name="now")
        target = _transition(record.state, action)
        updated = LicenseLifecycleRecord(
            license_id=record.license_id,
            state=target,
            version=record.version + 1,
            sku=record.sku,
            activation_serial=record.activation_serial,
            issued_at=record.issued_at,
            tenant_id=record.tenant_id,
            account_id=record.account_id,
            hardware_id=record.hardware_id,
            valid_from=record.valid_from,
            valid_until=record.valid_until,
            activated_at=record.activated_at,
            activated_by=record.activated_by,
            event_count=record.event_count + 1,
        )
        await self._store.replace(updated, expected_version=record.version)
        await self._emit(
            updated, action, from_state=record.state, reason=reason, now=now
        )
        return await self._finish(updated)

    async def _finish(
        self, record: LicenseLifecycleRecord
    ) -> tuple[LicenseLifecycleRecord, SignedLicenseDocument]:
        current = await self._store.get(record.license_id)
        return current, self._sign(current)

    async def history(self, license_id: UUID) -> tuple[LicenseLifecycleEvent, ...]:
        """The immutable event trail, in sequence order."""
        events = await self._store.events(license_id)
        return tuple(sorted(events, key=lambda event: event.sequence))

    async def offline_access(
        self, license_id: UUID, *, now: datetime
    ) -> OfflineAccessDecision:
        """Grace-aware expiry: ACTIVE and inside ``valid_until + grace`` only."""
        _require_aware(now, field_name="now")
        record = await self._store.get(license_id)
        grace = self._policy.offline_grace(sku=record.sku)
        if record.state is not LicenseLifecycleState.ACTIVE:
            return OfflineAccessDecision(
                license_id=license_id,
                allowed=False,
                reason=f"license is {record.state.value}; offline access requires ACTIVE",
                valid_until=record.valid_until,
                grace=grace,
                evaluated_at=now,
            )
        if record.valid_until is None:
            return OfflineAccessDecision(
                license_id=license_id,
                allowed=False,
                reason="license has no validity window",
                valid_until=None,
                grace=grace,
                evaluated_at=now,
            )
        deadline = record.valid_until + grace
        allowed = now < deadline
        return OfflineAccessDecision(
            license_id=license_id,
            allowed=allowed,
            reason=(
                "within validity and offline grace"
                if allowed
                else "validity and offline grace have both elapsed"
            ),
            valid_until=record.valid_until,
            grace=grace,
            evaluated_at=now,
        )
