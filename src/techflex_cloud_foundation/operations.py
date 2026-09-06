"""Platform operations console (CP-09), business-neutral.

The console is the mechanism layer for platform operators: immutable
commands over four neutral object kinds (organizations/accounts, licenses,
terminals/devices, product registrations), short-lived single-use
sensitive-access grants, signed and strictly-forward configuration
releases, and upgrade-order decisions taken from the product registry's
migration order and minimum versions.  What a command *means* — which SKU
a license stocks, what a device is, which roles may issue a command — is
the product's policy, injected or enforced upstream, never hardcoded here.

Invariants carried over from RAY-341 and the reference implementation:

- Platform principals only.  Commands are issued by
  ``iam.PlatformPrincipal``; a tenant principal is refused, the console
  never consults tenant roles, and no command carries a tenant identity
  to act as.  The console checks the principal's *realm*, not its
  business authorization — role enforcement stays with the application.
- Commands are immutable value objects with an explicit ``issued_at``.
  Each executes at most once: a second execution of the same command id
  is a conflict, and a retry is a new command, never a replay.
- Every execution appends one immutable `OperationsAuditRecord` — who,
  when, on what, with which outcome — carrying the command's digest
  rather than its parameters.  Raw parameters never enter the audit
  trail, so secret material placed in parameters is never logged; better
  still, secrets belong in the application's credential channels, not in
  command parameters at all.
- Sensitive commands (an injected set of purposes) additionally require
  an unconsumed, unexpired `SensitiveAccessGrant` whose purpose, holder,
  and target all match the command.  A grant that is missing, expired,
  already consumed, or issued for another purpose, operator, or object is
  refused — never guessed into validity.  Grants are short-lived by
  construction: the issuer enforces a maximum lifetime.
- Configuration releases are ed25519-signed under a versioned
  `OperationsKeyset` (the same keyset pattern ``license_lifecycle``
  uses) and each config id's release sequence never moves backwards: a
  release at or below the published version is a downgrade and refused.
- Upgrade order is decided against the product registry's declared
  migration order and minimum versions: incompatible or out-of-order
  targets are answered with explicit rejections, never silently
  reordered.
- Nothing here reads a real clock; every timestamp is an explicitly
  injected ``now``.
- Persistence sits behind the `OperationsStore` protocol; the shipped
  `InMemoryOperationsStore` covers tests and integration runs,
  production binds a database in the application layer.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
import hashlib
import json
from typing import Any, Mapping, Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .iam import PlatformPrincipal, TenantPrincipal
from .product_registry import ProductRegistry, VersionRelation

OPERATIONS_COMMAND_FORMAT_VERSION = 1
OPERATIONS_AUDIT_FORMAT_VERSION = 1
OPERATIONS_CONFIG_RELEASE_FORMAT_VERSION = 1


class OperationsError(Exception):
    """Base class for platform operations failures."""


class OperationsMalformed(OperationsError):
    """A command, record, grant, or release is structurally invalid."""


class OperationsVersionUnsupported(OperationsError):
    """A serialized record declares a format version this build refuses."""


class OperationsConflict(OperationsError):
    """A store write lost a race, or an id was reused where unique."""


class OperationsStateError(OperationsError):
    """The managed object's state does not allow this operation."""


class OperationsPermissionDenied(OperationsError):
    """The principal's realm does not reach the platform console."""


class OperationsGrantRefused(OperationsPermissionDenied):
    """A sensitive command lacks a valid sensitive-access grant.

    Every cause — no grant presented, unknown, expired, already consumed,
    another holder, another purpose, another target — refuses alike from
    the boundary's point of view: the sensitive operation does not run.
    The message names the cause because the caller already holds a
    platform principal; there is no account to enumerate.
    """


class OperationsDowngradeRejected(OperationsError):
    """A config release would move a config id's sequence backwards."""


class OperationsSigningKeyUnknown(OperationsError):
    """A release names a key id the keyset does not hold, or a revoked one."""


class OperationsSignatureInvalid(OperationsError):
    """A release signature does not verify under its named key."""


def _require_text(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperationsMalformed(f"{field_name} must be non-empty text")
    return value


def _require_aware(value: datetime, *, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OperationsMalformed(f"{field_name} must be timezone-aware")


def _require_uuid(value: UUID, *, field_name: str) -> None:
    if not isinstance(value, UUID):
        raise OperationsMalformed(f"{field_name} must be a UUID")


def _require_parameters(
    value: Mapping[str, str], *, field_name: str
) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise OperationsMalformed(f"{field_name} must be a mapping of text to text")
    for key, item in value.items():
        _require_text(key, field_name=f"{field_name} key")
        if not isinstance(item, str):
            raise OperationsMalformed(
                f"{field_name}[{key!r}] must be text; non-text values are refused "
                "rather than coerced"
            )
    return value


def _require_platform_principal(
    principal: PlatformPrincipal,
) -> PlatformPrincipal:
    """Accept a platform principal only; tenant identities never cross in."""

    if isinstance(principal, TenantPrincipal):
        raise OperationsPermissionDenied(
            "tenant principals cannot operate the platform console; a tenant "
            "operator acts through the tenant plane, never as the platform"
        )
    if not isinstance(principal, PlatformPrincipal):
        raise OperationsMalformed(
            "principal must be an iam.PlatformPrincipal; the console has no "
            "other principal kind"
        )
    return principal


class OperationsObjectKind(StrEnum):
    """The four neutral object kinds the console commands operate on."""

    ORGANIZATION = "organization"
    LICENSE = "license"
    DEVICE = "device"
    PRODUCT_REGISTRATION = "product-registration"


class OperationsAction(StrEnum):
    """Neutral operations actions; ``CLOSE`` is terminal for every kind."""

    CREATE = "CREATE"
    REGISTER = "REGISTER"
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"
    CLOSE = "CLOSE"


class OperationsObjectState(StrEnum):
    """The operational view of a managed object; ``CLOSED`` is terminal.

    This is the console's pointer state, not the business lifecycle: a
    license's entitlement lifecycle lives in ``license_lifecycle``, an
    account's IAM state lives in ``iam``.  The console records that an
    object is operationally active, suspended, or closed — the business
    modules remain authoritative for everything else.
    """

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"


class OperationsOutcome(StrEnum):
    """What an audit record says happened to the command."""

    APPLIED = "APPLIED"
    REFUSED = "REFUSED"


class UpgradeOrderKind(StrEnum):
    """The explicit outcome of an upgrade-order decision."""

    ORDERED = "ordered"
    REJECTED_INCOMPATIBLE = "rejected-incompatible"
    REJECTED_OUT_OF_ORDER = "rejected-out-of-order"


# The operational lifecycle as a table rather than guard clauses, matching
# ``iam``'s account transitions.  Every pair not named here is refused, so a
# transition is legal because it is written down.  Reactivation from
# SUSPENDED is deliberate; CLOSED is terminal because a reopened object
# would silently inherit the former incarnation's operational history.
_ALLOWED_OBJECT_TRANSITIONS: Mapping[
    OperationsObjectState, frozenset[OperationsObjectState]
] = {
    OperationsObjectState.ACTIVE: frozenset(
        {OperationsObjectState.SUSPENDED, OperationsObjectState.CLOSED}
    ),
    OperationsObjectState.SUSPENDED: frozenset(
        {OperationsObjectState.ACTIVE, OperationsObjectState.CLOSED}
    ),
    OperationsObjectState.CLOSED: frozenset(),
}

_ACTION_TARGET_STATE: Mapping[OperationsAction, OperationsObjectState] = {
    OperationsAction.ENABLE: OperationsObjectState.ACTIVE,
    OperationsAction.DISABLE: OperationsObjectState.SUSPENDED,
    OperationsAction.CLOSE: OperationsObjectState.CLOSED,
}

# Which actions apply to which kinds, as a whitelist.  Organizations and
# licenses are created; devices and product registrations register.  The
# three lifecycle actions apply to every kind.  A pair not named here —
# registering an organization, creating a device — is refused as malformed
# rather than guessed into meaning something.
_ACTION_KINDS: Mapping[OperationsAction, frozenset[OperationsObjectKind]] = {
    OperationsAction.CREATE: frozenset(
        {OperationsObjectKind.ORGANIZATION, OperationsObjectKind.LICENSE}
    ),
    OperationsAction.REGISTER: frozenset(
        {OperationsObjectKind.DEVICE, OperationsObjectKind.PRODUCT_REGISTRATION}
    ),
    OperationsAction.ENABLE: frozenset(OperationsObjectKind),
    OperationsAction.DISABLE: frozenset(OperationsObjectKind),
    OperationsAction.CLOSE: frozenset(OperationsObjectKind),
}


def command_purpose(
    action: OperationsAction, target_kind: OperationsObjectKind
) -> str:
    """The purpose string a command's sensitivity is declared with.

    ``"<kind>.<action>"`` in lowercase, e.g. ``"license.close"`` for
    revoking a license.  The application injects its set of sensitive
    purposes from these strings, so the vocabulary is stable and
    inspectable rather than an implicit convention.
    """

    if not isinstance(action, OperationsAction):
        raise OperationsMalformed("action must be an OperationsAction")
    if not isinstance(target_kind, OperationsObjectKind):
        raise OperationsMalformed("target_kind must be an OperationsObjectKind")
    if target_kind not in _ACTION_KINDS[action]:
        raise OperationsMalformed(
            f"action {action.value} does not apply to {target_kind.value} objects; "
            "the action/kind pairs are a whitelist, never guessed"
        )
    return f"{target_kind.value}.{action.value.lower()}"


def _transition(
    current: OperationsObjectState, action: OperationsAction
) -> OperationsObjectState:
    """Resolve one lifecycle action against the whitelist, or explain it."""

    target = _ACTION_TARGET_STATE[action]
    if target not in _ALLOWED_OBJECT_TRANSITIONS[current]:
        raise OperationsStateError(_state_rejection_reason(current, action, target))
    return target


def _state_rejection_reason(
    current: OperationsObjectState,
    action: OperationsAction,
    target: OperationsObjectState,
) -> str:
    if current is target:
        return (
            f"object is already {current.value}; {action.value.lower()} is not an "
            "idempotent replay — check the state instead of re-applying it"
        )
    if current is OperationsObjectState.CLOSED:
        return (
            "a closed object is terminal and cannot be reopened; create a new "
            "object rather than inheriting the closed one's history"
        )
    return (
        f"{current.value} -> {target.value} via {action.value} is not a legal "
        "operations transition"
    )


@dataclass(frozen=True)
class OperationsTarget:
    """A reference to the object a command acts on.

    ``object_id`` is the business module's identifier — an ``iam``
    organization id, a ``license_lifecycle`` license id, a
    ``device_trust`` terminal or device id, a registered product id.  The
    console references these ids; it never copies the business records
    behind them.
    """

    kind: OperationsObjectKind
    object_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, OperationsObjectKind):
            raise OperationsMalformed("target kind must be an OperationsObjectKind")
        _require_text(self.object_id, field_name="target object id")


@dataclass(frozen=True)
class OperationsCommand:
    """One immutable operator command; it is never persisted, only digested.

    ``parameters`` carry business context (a reason code, a display
    field, a declared model) as text.  They are covered by the command's
    digest but never stored or logged in the clear, so secret material
    must still not be placed in them — the application's credential
    channels are the only home for secrets.
    """

    command_id: UUID
    action: OperationsAction
    issued_by: PlatformPrincipal
    target: OperationsTarget
    parameters: Mapping[str, str]
    issued_at: datetime
    format_version: int = OPERATIONS_COMMAND_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != OPERATIONS_COMMAND_FORMAT_VERSION:
            raise OperationsVersionUnsupported(
                f"unsupported operations command format version: {self.format_version!r}"
            )
        _require_uuid(self.command_id, field_name="command id")
        if not isinstance(self.action, OperationsAction):
            raise OperationsMalformed("action must be an OperationsAction")
        if not isinstance(self.target, OperationsTarget):
            raise OperationsMalformed("target must be an OperationsTarget")
        _require_platform_principal(self.issued_by)
        # The action/kind whitelist is a construction invariant, so a
        # command that could never execute cannot even exist.
        command_purpose(self.action, self.target.kind)
        _require_parameters(self.parameters, field_name="command parameters")
        _require_aware(self.issued_at, field_name="issued_at")

    def canonical_bytes(self) -> bytes:
        document: dict[str, Any] = {
            "format_version": self.format_version,
            "command_id": str(self.command_id),
            "action": self.action.value,
            "issued_by": {
                "subject_id": self.issued_by.subject_id,
                "role_names": sorted(self.issued_by.role_names),
            },
            "target": {
                "kind": self.target.kind.value,
                "object_id": self.target.object_id,
            },
            "parameters": dict(sorted(self.parameters.items())),
            "issued_at": self.issued_at.isoformat(),
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        """The command's fingerprint; what the audit trail records."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def purpose(self) -> str:
        """The sensitive-operation vocabulary entry for this command."""

        return command_purpose(self.action, self.target.kind)


@dataclass(frozen=True)
class OperationsObjectRecord:
    """The console's operational view of one managed object."""

    kind: OperationsObjectKind
    object_id: str
    state: OperationsObjectState
    version: int
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.kind, OperationsObjectKind):
            raise OperationsMalformed("record kind must be an OperationsObjectKind")
        _require_text(self.object_id, field_name="record object id")
        if not isinstance(self.state, OperationsObjectState):
            raise OperationsMalformed("record state must be an OperationsObjectState")
        if (
            not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or self.version < 1
        ):
            raise OperationsMalformed("record version must be a positive integer")
        _require_aware(self.created_at, field_name="created_at")
        _require_aware(self.updated_at, field_name="updated_at")


@dataclass(frozen=True)
class OperationsAuditRecord:
    """One immutable audit entry: who, when, on what, with which outcome.

    The record carries the command's ``digest`` — never its parameters —
    so the trail proves exactly what executed without ever holding
    parameter values, secret or otherwise.  ``outcome`` is ``REFUSED``
    for sensitive commands refused for want of a valid grant: an attempt
    on a sensitive operation is itself a security event worth keeping.
    """

    record_id: UUID
    command_id: UUID
    actor_subject: str
    action: OperationsAction
    target: OperationsTarget
    outcome: OperationsOutcome
    command_digest: str
    occurred_at: datetime
    grant_id: UUID | None = None
    format_version: int = OPERATIONS_AUDIT_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != OPERATIONS_AUDIT_FORMAT_VERSION:
            raise OperationsVersionUnsupported(
                f"unsupported audit record format version: {self.format_version!r}"
            )
        _require_uuid(self.record_id, field_name="record id")
        _require_uuid(self.command_id, field_name="command id")
        _require_text(self.actor_subject, field_name="actor subject")
        if not isinstance(self.action, OperationsAction):
            raise OperationsMalformed("action must be an OperationsAction")
        if not isinstance(self.target, OperationsTarget):
            raise OperationsMalformed("target must be an OperationsTarget")
        if not isinstance(self.outcome, OperationsOutcome):
            raise OperationsMalformed("outcome must be an OperationsOutcome")
        if len(self.command_digest) != 64:
            raise OperationsMalformed(
                "command digest must be a complete SHA-256 hex"
            )
        _require_aware(self.occurred_at, field_name="occurred_at")
        if self.grant_id is not None:
            _require_uuid(self.grant_id, field_name="grant id")


@dataclass(frozen=True)
class SensitiveAccessGrant:
    """A short-lived, single-use authorization for one sensitive purpose.

    A grant authorizes exactly one purpose, one holder, and one target:
    a grant minted to close license A does not close license B, does not
    disable license A, and cannot be spent by another operator.  The
    holder is a platform subject id — the grant carries no tenant
    identity and no role, so it cannot smuggle tenant authority across
    the realm boundary.
    """

    grant_id: UUID
    purpose: str
    holder_subject: str
    target: OperationsTarget
    issued_at: datetime
    expires_at: datetime
    used_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_uuid(self.grant_id, field_name="grant id")
        _require_text(self.purpose, field_name="grant purpose")
        _require_text(self.holder_subject, field_name="grant holder subject")
        if not isinstance(self.target, OperationsTarget):
            raise OperationsMalformed("grant target must be an OperationsTarget")
        _require_aware(self.issued_at, field_name="issued_at")
        _require_aware(self.expires_at, field_name="expires_at")
        if self.expires_at <= self.issued_at:
            raise OperationsMalformed("grant expires_at must be after issued_at")
        if self.used_at is not None:
            _require_aware(self.used_at, field_name="used_at")
            if self.used_at < self.issued_at:
                raise OperationsMalformed("grant used_at cannot precede issued_at")


@dataclass(frozen=True)
class ConfigReleaseDocument:
    """The signed payload of one configuration release.

    ``payload`` is a flat text mapping so the signed bytes are canonical
    JSON and the release stays business-neutral: which settings exist and
    what they mean belong to the deployment.  Values are text — a value
    that is itself a secret should be a reference the deployment can
    resolve, never the secret.
    """

    config_id: str
    version: int
    payload: Mapping[str, str]
    published_by: str
    released_at: datetime
    format_version: int = OPERATIONS_CONFIG_RELEASE_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != OPERATIONS_CONFIG_RELEASE_FORMAT_VERSION:
            raise OperationsVersionUnsupported(
                f"unsupported config release format version: {self.format_version!r}"
            )
        _require_text(self.config_id, field_name="config id")
        if (
            not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or self.version < 1
        ):
            raise OperationsMalformed("release version must be a positive integer")
        _require_parameters(self.payload, field_name="release payload")
        _require_text(self.published_by, field_name="publisher subject")
        _require_aware(self.released_at, field_name="released_at")

    def canonical_bytes(self) -> bytes:
        document: dict[str, Any] = {
            "format_version": self.format_version,
            "config_id": self.config_id,
            "version": self.version,
            "payload": dict(sorted(self.payload.items())),
            "published_by": self.published_by,
            "released_at": self.released_at.isoformat(),
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(
        self, signing_key: Ed25519PrivateKey, *, keyset: OperationsKeyset
    ) -> SignedConfigRelease:
        """Sign under the keyset's active key id; the key id travels with it."""

        keyset.public_key(keyset.active_key_id)
        signature = base64.b64encode(
            signing_key.sign(self.canonical_bytes())
        ).decode("ascii")
        return SignedConfigRelease(
            document=self,
            key_id=keyset.active_key_id,
            signature=signature,
            keyset_revision=keyset.revision,
        )


@dataclass(frozen=True)
class SignedConfigRelease:
    """A config release document plus its key id, signature, and keyset revision."""

    document: ConfigReleaseDocument
    key_id: str
    signature: str
    keyset_revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.document, ConfigReleaseDocument):
            raise OperationsMalformed("document must be a ConfigReleaseDocument")
        _require_text(self.key_id, field_name="key id")
        _require_text(self.signature, field_name="signature")
        if (
            not isinstance(self.keyset_revision, int)
            or isinstance(self.keyset_revision, bool)
            or self.keyset_revision < 1
        ):
            raise OperationsMalformed("keyset revision must be a positive integer")


@dataclass(frozen=True)
class OperationsKeyset:
    """A versioned set of operations signing keys: one active, some revoked.

    The same keyset pattern ``license_lifecycle.LicenseKeyset`` uses,
    kept separate so a license key and a config-release key are never
    interchangeable: each family refuses the other's key ids through its
    own keyset, and nothing signs both.
    """

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
            raise OperationsMalformed("keyset revision must be a positive integer")
        _require_text(self.active_key_id, field_name="active key id")
        if not self.public_keys:
            raise OperationsMalformed("at least one public key is required")
        if self.active_key_id not in self.public_keys:
            raise OperationsMalformed(
                "the active key id must name a key in this keyset"
            )
        if self.active_key_id in self.revoked_key_ids:
            raise OperationsMalformed("the active key id cannot be revoked")
        if len(set(self.revoked_key_ids)) != len(self.revoked_key_ids):
            raise OperationsMalformed("revoked key ids must be unique")

    def public_key(self, key_id: str) -> Ed25519PublicKey:
        """Resolve a key id for verification; unknown or revoked ids refuse."""

        if key_id in self.revoked_key_ids:
            raise OperationsSigningKeyUnknown(
                f"operations signing key {key_id!r} is revoked in keyset "
                f"revision {self.revision}"
            )
        raw = self.public_keys.get(key_id)
        if raw is None:
            raise OperationsSigningKeyUnknown(
                f"operations signing key {key_id!r} is unknown to keyset "
                f"revision {self.revision}"
            )
        return Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, signed: SignedConfigRelease) -> ConfigReleaseDocument:
        """Verify a signed release; the signature is checked before any claim."""

        public_key = self.public_key(signed.key_id)
        try:
            signature = base64.b64decode(signed.signature, validate=True)
            public_key.verify(signature, signed.document.canonical_bytes())
        except (binascii.Error, ValueError, InvalidSignature) as exc:
            raise OperationsSignatureInvalid(
                "config release signature is invalid"
            ) from exc
        return signed.document


@dataclass(frozen=True)
class UpgradeOrderDecision:
    """The explicit answer for one declared upgrade, with its reasoning.

    An ``ORDERED`` decision carries the full upgrade path the fleet will
    traverse — including intermediate versions the operator did not
    declare.  Rejections carry none: an incompatible or out-of-order
    declaration is refused whole, never partially reordered.
    """

    kind: UpgradeOrderKind
    product_id: str
    reason: str
    upgrade_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, UpgradeOrderKind):
            raise OperationsMalformed("decision kind must be an UpgradeOrderKind")
        _require_text(self.product_id, field_name="decision product_id")
        _require_text(self.reason, field_name="decision reason")
        if self.kind is UpgradeOrderKind.ORDERED:
            if not self.upgrade_path:
                raise OperationsMalformed(
                    "an ordered decision carries the upgrade path; it is never implied"
                )
        elif self.upgrade_path:
            raise OperationsMalformed(
                f"a {self.kind} decision carries no upgrade path"
            )


def validate_upgrade_order(
    registry: ProductRegistry,
    *,
    product_id: str,
    current_version: str,
    declared_targets: tuple[str, ...],
) -> UpgradeOrderDecision:
    """Decide one declared upgrade against the product registry.

    The operator declares the versions the fleet will move to, in the
    order they intend to apply them.  The decision reuses the registry's
    own facts — the product's supported schema versions, minimum schema
    version, and migration order — under the registry's injected
    compatibility policy:

    - a target the product does not serve, or that predates the
      product's minimum version, is ``REJECTED_INCOMPATIBLE``;
    - a declaration that skips, reorders, or rolls back along the
      migration order is ``REJECTED_OUT_OF_ORDER``;
    - otherwise the decision is ``ORDERED`` and carries the full path
      from the current version to the last declared target.

    Nothing is silently reordered: what was declared is what is judged.
    """

    _require_text(product_id, field_name="product id")
    _require_text(current_version, field_name="current version")
    if not isinstance(declared_targets, tuple):
        raise OperationsMalformed("declared_targets must be a tuple of versions")
    if not declared_targets:
        raise OperationsMalformed(
            "an upgrade declaration names at least one target version"
        )
    for target in declared_targets:
        _require_text(target, field_name="declared target version")

    record = registry.get(product_id)
    if record is None:
        return UpgradeOrderDecision(
            kind=UpgradeOrderKind.REJECTED_INCOMPATIBLE,
            product_id=product_id,
            reason=f"product {product_id!r} is not registered in this catalog",
        )
    for target in declared_targets:
        if target not in record.supported_schema_versions:
            return UpgradeOrderDecision(
                kind=UpgradeOrderKind.REJECTED_INCOMPATIBLE,
                product_id=product_id,
                reason=(
                    f"target version {target!r} is not a supported schema version "
                    f"of product {product_id!r}"
                ),
            )
    minimum = record.minimum_version("schema")
    if minimum is not None:
        for target in declared_targets:
            if registry.policy.compare(target, minimum) is VersionRelation.OLDER:
                return UpgradeOrderDecision(
                    kind=UpgradeOrderKind.REJECTED_INCOMPATIBLE,
                    product_id=product_id,
                    reason=(
                        f"target version {target!r} predates the minimum schema "
                        f"version {minimum!r} of product {product_id!r}"
                    ),
                )

    if record.migration_order:
        if current_version not in record.migration_order:
            return UpgradeOrderDecision(
                kind=UpgradeOrderKind.REJECTED_OUT_OF_ORDER,
                product_id=product_id,
                reason=(
                    f"current version {current_version!r} is not on the migration "
                    f"order of product {product_id!r}; the order is the authority "
                    "and an unlisted position is never guessed"
                ),
            )
        current_position = record.migration_order.index(current_version)
        positions: list[int] = []
        for target in declared_targets:
            if target not in record.migration_order:
                return UpgradeOrderDecision(
                    kind=UpgradeOrderKind.REJECTED_OUT_OF_ORDER,
                    product_id=product_id,
                    reason=(
                        f"target version {target!r} is not on the migration order "
                        f"of product {product_id!r}; it cannot be sequenced"
                    ),
                )
            position = record.migration_order.index(target)
            if position <= current_position:
                return UpgradeOrderDecision(
                    kind=UpgradeOrderKind.REJECTED_OUT_OF_ORDER,
                    product_id=product_id,
                    reason=(
                        f"target version {target!r} does not follow the current "
                        f"version {current_version!r}; upgrades never move backwards"
                    ),
                )
            positions.append(position)
        for earlier, later in zip(positions, positions[1:], strict=False):
            if later <= earlier:
                return UpgradeOrderDecision(
                    kind=UpgradeOrderKind.REJECTED_OUT_OF_ORDER,
                    product_id=product_id,
                    reason=(
                        "declared targets do not follow the migration order of "
                        f"product {product_id!r}; skipping or reordering steps is "
                        "refused"
                    ),
                )
        last_position = positions[-1]
        return UpgradeOrderDecision(
            kind=UpgradeOrderKind.ORDERED,
            product_id=product_id,
            reason="declared targets follow the product's migration order",
            upgrade_path=record.migration_order[current_position + 1 : last_position + 1],
        )

    # No migration order is declared: the injected policy is the only
    # ordering authority, so each declared target must be strictly newer
    # than the one before it, current version first.
    previous = current_version
    for target in declared_targets:
        relation = registry.policy.compare(target, previous)
        if relation is not VersionRelation.NEWER:
            return UpgradeOrderDecision(
                kind=UpgradeOrderKind.REJECTED_OUT_OF_ORDER,
                product_id=product_id,
                reason=(
                    f"target version {target!r} does not follow {previous!r} under "
                    f"the compatibility policy of product {product_id!r}; upgrades "
                    "never move backwards or sideways"
                ),
            )
        previous = target
    return UpgradeOrderDecision(
        kind=UpgradeOrderKind.ORDERED,
        product_id=product_id,
        reason="declared targets are strictly increasing under the compatibility policy",
        upgrade_path=declared_targets,
    )


class OperationsStore(Protocol):
    """Persistence boundary; production binds a database, tests use memory.

    ``consume_grant`` is the single-use authority: it marks the grant
    used atomically and refuses a second consumption, so two racing
    executions of the same grant cannot both succeed.  ``append_audit``
    refuses a second ``APPLIED`` record for one command id — a command
    executes at most once.
    """

    async def find_object(
        self, target: OperationsTarget
    ) -> OperationsObjectRecord | None: ...

    async def insert_object(self, record: OperationsObjectRecord) -> None: ...

    async def replace_object(
        self, record: OperationsObjectRecord, *, expected_version: int
    ) -> None: ...

    async def append_audit(self, record: OperationsAuditRecord) -> None: ...

    async def audit_records(
        self, target: OperationsTarget
    ) -> tuple[OperationsAuditRecord, ...]: ...

    async def get_grant(self, grant_id: UUID) -> SensitiveAccessGrant | None: ...

    async def put_grant(self, grant: SensitiveAccessGrant) -> None: ...

    async def consume_grant(
        self, grant_id: UUID, *, used_at: datetime
    ) -> SensitiveAccessGrant: ...

    async def latest_release(self, config_id: str) -> SignedConfigRelease | None: ...

    async def insert_release(self, release: SignedConfigRelease) -> None: ...


class InMemoryOperationsStore:
    """Volatile reference store, suitable for tests and integration runs."""

    def __init__(self) -> None:
        self._objects: dict[OperationsTarget, OperationsObjectRecord] = {}
        self._audit: list[OperationsAuditRecord] = []
        self._grants: dict[UUID, SensitiveAccessGrant] = {}
        self._releases: dict[str, dict[int, SignedConfigRelease]] = {}

    async def find_object(
        self, target: OperationsTarget
    ) -> OperationsObjectRecord | None:
        return self._objects.get(target)

    async def insert_object(self, record: OperationsObjectRecord) -> None:
        target = OperationsTarget(kind=record.kind, object_id=record.object_id)
        if target in self._objects:
            raise OperationsConflict(
                f"{record.kind.value} {record.object_id!r} already exists"
            )
        self._objects[target] = record

    async def replace_object(
        self, record: OperationsObjectRecord, *, expected_version: int
    ) -> None:
        target = OperationsTarget(kind=record.kind, object_id=record.object_id)
        current = self._objects.get(target)
        if current is None:
            raise OperationsMalformed(
                f"{record.kind.value} {record.object_id!r} is unknown"
            )
        if current.version != expected_version:
            raise OperationsConflict(
                f"{record.kind.value} {record.object_id!r} is at version "
                f"{current.version}, not {expected_version}"
            )
        self._objects[target] = record

    async def append_audit(self, record: OperationsAuditRecord) -> None:
        if record.outcome is OperationsOutcome.APPLIED and any(
            existing.command_id == record.command_id
            and existing.outcome is OperationsOutcome.APPLIED
            for existing in self._audit
        ):
            raise OperationsConflict(
                f"command {record.command_id} was already executed; a retry is a "
                "new command, never a replay"
            )
        if any(existing.record_id == record.record_id for existing in self._audit):
            raise OperationsConflict(
                f"audit record {record.record_id} already exists"
            )
        self._audit.append(record)

    async def audit_records(
        self, target: OperationsTarget
    ) -> tuple[OperationsAuditRecord, ...]:
        return tuple(
            record for record in self._audit if record.target == target
        )

    async def get_grant(self, grant_id: UUID) -> SensitiveAccessGrant | None:
        return self._grants.get(grant_id)

    async def put_grant(self, grant: SensitiveAccessGrant) -> None:
        if grant.grant_id in self._grants:
            raise OperationsConflict(f"grant {grant.grant_id} already exists")
        self._grants[grant.grant_id] = grant

    async def consume_grant(
        self, grant_id: UUID, *, used_at: datetime
    ) -> SensitiveAccessGrant:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise OperationsMalformed(f"grant {grant_id} is unknown")
        if grant.used_at is not None:
            raise OperationsConflict(
                f"grant {grant_id} was already consumed; grants are single-use"
            )
        consumed = replace(grant, used_at=used_at)
        self._grants[grant_id] = consumed
        return consumed

    async def latest_release(self, config_id: str) -> SignedConfigRelease | None:
        releases = self._releases.get(config_id)
        if not releases:
            return None
        return releases[max(releases)]

    async def insert_release(self, release: SignedConfigRelease) -> None:
        releases = self._releases.setdefault(release.document.config_id, {})
        version = release.document.version
        if version in releases:
            raise OperationsConflict(
                f"config {release.document.config_id!r} already has release {version}"
            )
        releases[version] = release


@dataclass(frozen=True)
class _PlannedChange:
    """The validated effect of one command, computed before any write."""

    record: OperationsObjectRecord
    expected_version: int | None  # None means the record is new


class OperationsConsole:
    """Executes operator commands under grants, and publishes signed config.

    The console's checks are ordered so that nothing outlasts its
    authorization: the command, the object's state transition, and the
    grant are all validated before any write, the grant is consumed
    before the object changes, and only then are the object record and
    the audit entry written.  A command refused for its grant leaves a
    ``REFUSED`` audit record behind — an attempt on a sensitive operation
    is a security event — and an execution that loses a race leaves
    nothing behind at all.
    """

    def __init__(
        self,
        store: OperationsStore,
        *,
        signing_key: Ed25519PrivateKey,
        keyset: OperationsKeyset,
        sensitive_purposes: frozenset[str],
        max_grant_lifetime: timedelta,
    ) -> None:
        if not isinstance(keyset, OperationsKeyset):
            raise OperationsMalformed("keyset must be an OperationsKeyset")
        if not isinstance(sensitive_purposes, frozenset):
            raise OperationsMalformed("sensitive_purposes must be a frozenset")
        for purpose in sensitive_purposes:
            _require_text(purpose, field_name="sensitive purpose")
        if (
            not isinstance(max_grant_lifetime, timedelta)
            or max_grant_lifetime <= timedelta(0)
        ):
            raise OperationsMalformed(
                "max_grant_lifetime must be a positive duration"
            )
        self._store = store
        self._signing_key = signing_key
        self._keyset = keyset
        self._sensitive_purposes = sensitive_purposes
        self._max_grant_lifetime = max_grant_lifetime

    async def execute(
        self,
        command: OperationsCommand,
        *,
        now: datetime,
        grant_id: UUID | None = None,
    ) -> tuple[OperationsObjectRecord, OperationsAuditRecord]:
        """Execute one command at most once, appending its audit record."""

        if not isinstance(command, OperationsCommand):
            raise OperationsMalformed("command must be an OperationsCommand")
        _require_aware(now, field_name="now")
        if now < command.issued_at:
            raise OperationsMalformed(
                "a command cannot execute before it was issued"
            )
        sensitive = command.purpose in self._sensitive_purposes
        if not sensitive and grant_id is not None:
            raise OperationsMalformed(
                "only a sensitive command accepts a grant; presenting one for an "
                "ordinary command is a caller error, not an authorization"
            )
        grant: SensitiveAccessGrant | None = None
        if sensitive:
            # Authorization comes before any other work: a sensitive command
            # without a valid grant is refused — and audited — before the
            # object's state is even consulted.
            grant = await self._authorize(command, grant_id=grant_id, now=now)
        planned = await self._plan(command, now=now)
        if grant is not None:
            await self._consume(grant, command=command, now=now)
        if planned.expected_version is None:
            await self._store.insert_object(planned.record)
        else:
            await self._store.replace_object(
                planned.record, expected_version=planned.expected_version
            )
        audit = OperationsAuditRecord(
            record_id=uuid4(),
            command_id=command.command_id,
            actor_subject=command.issued_by.subject_id,
            action=command.action,
            target=command.target,
            outcome=OperationsOutcome.APPLIED,
            command_digest=command.digest(),
            occurred_at=now,
            grant_id=grant.grant_id if grant is not None else None,
        )
        await self._store.append_audit(audit)
        return planned.record, audit

    async def issue_grant(
        self,
        principal: PlatformPrincipal,
        *,
        action: OperationsAction,
        target: OperationsTarget,
        reason: str,
        duration: timedelta,
        now: datetime,
    ) -> SensitiveAccessGrant:
        """Mint one short-lived, single-use grant for a sensitive purpose.

        Only a purpose the console holds as sensitive can be granted: an
        operator cannot pre-mint authorization for ordinary commands, and
        the requested lifetime cannot exceed the console's maximum.
        """

        _require_platform_principal(principal)
        if not isinstance(action, OperationsAction):
            raise OperationsMalformed("action must be an OperationsAction")
        if not isinstance(target, OperationsTarget):
            raise OperationsMalformed("target must be an OperationsTarget")
        _require_text(reason, field_name="grant reason")
        _require_aware(now, field_name="now")
        if (
            not isinstance(duration, timedelta)
            or duration <= timedelta(0)
            or duration > self._max_grant_lifetime
        ):
            raise OperationsMalformed(
                "grant duration must be positive and at most "
                f"{self._max_grant_lifetime}"
            )
        purpose = command_purpose(action, target.kind)
        if purpose not in self._sensitive_purposes:
            raise OperationsGrantRefused(
                f"{purpose!r} is not a sensitive operation; grants exist only for "
                "sensitive commands"
            )
        grant = SensitiveAccessGrant(
            grant_id=uuid4(),
            purpose=purpose,
            holder_subject=principal.subject_id,
            target=target,
            issued_at=now,
            expires_at=now + duration,
        )
        await self._store.put_grant(grant)
        return grant

    async def publish_config(
        self,
        *,
        config_id: str,
        version: int,
        payload: Mapping[str, str],
        principal: PlatformPrincipal,
        now: datetime,
    ) -> SignedConfigRelease:
        """Sign and publish one config release; the sequence never rolls back."""

        _require_platform_principal(principal)
        _require_aware(now, field_name="now")
        document = ConfigReleaseDocument(
            config_id=config_id,
            version=version,
            payload=payload,
            published_by=principal.subject_id,
            released_at=now,
        )
        latest = await self._store.latest_release(document.config_id)
        if latest is not None and document.version <= latest.document.version:
            raise OperationsDowngradeRejected(
                f"config {document.config_id!r} is at release "
                f"{latest.document.version}; release {document.version} would move "
                "it backwards, and releases never roll back"
            )
        signed = document.sign(self._signing_key, keyset=self._keyset)
        await self._store.insert_release(signed)
        return signed

    def verify_config(
        self, signed: SignedConfigRelease
    ) -> ConfigReleaseDocument:
        """Verify a signed release under the keyset; signature first."""

        if not isinstance(signed, SignedConfigRelease):
            raise OperationsMalformed("signed must be a SignedConfigRelease")
        return self._keyset.verify(signed)

    async def latest_config(self, config_id: str) -> SignedConfigRelease | None:
        """The newest published release for one config id, if any."""

        _require_text(config_id, field_name="config id")
        return await self._store.latest_release(config_id)

    async def _plan(
        self, command: OperationsCommand, *, now: datetime
    ) -> _PlannedChange:
        """Validate the command's effect without writing anything."""

        if command.action in (
            OperationsAction.CREATE,
            OperationsAction.REGISTER,
        ):
            existing = await self._store.find_object(command.target)
            if existing is not None:
                raise OperationsConflict(
                    f"{command.target.kind.value} {command.target.object_id!r} "
                    "already exists"
                )
            record = OperationsObjectRecord(
                kind=command.target.kind,
                object_id=command.target.object_id,
                state=OperationsObjectState.ACTIVE,
                version=1,
                created_at=now,
                updated_at=now,
            )
            return _PlannedChange(record=record, expected_version=None)
        current = await self._store.find_object(command.target)
        if current is None:
            raise OperationsMalformed(
                f"{command.target.kind.value} {command.target.object_id!r} is unknown"
            )
        target_state = _transition(current.state, command.action)
        updated = OperationsObjectRecord(
            kind=current.kind,
            object_id=current.object_id,
            state=target_state,
            version=current.version + 1,
            created_at=current.created_at,
            updated_at=now,
        )
        return _PlannedChange(record=updated, expected_version=current.version)

    async def _authorize(
        self,
        command: OperationsCommand,
        *,
        grant_id: UUID | None,
        now: datetime,
    ) -> SensitiveAccessGrant:
        """Validate the presented grant, or audit the refusal and raise."""

        async def refuse(*, presented: UUID | None) -> None:
            await self._store.append_audit(
                OperationsAuditRecord(
                    record_id=uuid4(),
                    command_id=command.command_id,
                    actor_subject=command.issued_by.subject_id,
                    action=command.action,
                    target=command.target,
                    outcome=OperationsOutcome.REFUSED,
                    command_digest=command.digest(),
                    occurred_at=now,
                    grant_id=presented,
                )
            )

        if grant_id is None:
            await refuse(presented=None)
            raise OperationsGrantRefused(
                f"{command.purpose} is a sensitive operation and requires an "
                "unexpired sensitive-access grant"
            )
        grant = await self._store.get_grant(grant_id)
        if grant is None:
            await refuse(presented=grant_id)
            raise OperationsGrantRefused("sensitive-access grant is unknown")
        if grant.used_at is not None:
            await refuse(presented=grant_id)
            raise OperationsGrantRefused(
                "sensitive-access grant was already consumed; grants are single-use"
            )
        if grant.expires_at <= now:
            await refuse(presented=grant_id)
            raise OperationsGrantRefused(
                "sensitive-access grant has expired; request a fresh grant"
            )
        if grant.holder_subject != command.issued_by.subject_id:
            await refuse(presented=grant_id)
            raise OperationsGrantRefused(
                "sensitive-access grant belongs to another operator"
            )
        if grant.purpose != command.purpose:
            await refuse(presented=grant_id)
            raise OperationsGrantRefused(
                f"sensitive-access grant was issued for {grant.purpose!r}, not "
                f"{command.purpose!r}; a grant authorizes exactly one purpose"
            )
        if grant.target != command.target:
            await refuse(presented=grant_id)
            raise OperationsGrantRefused(
                "sensitive-access grant does not cover this target"
            )
        return grant

    async def _consume(
        self,
        grant: SensitiveAccessGrant,
        *,
        command: OperationsCommand,
        now: datetime,
    ) -> None:
        """Spend the grant atomically before the object changes."""

        try:
            await self._store.consume_grant(grant.grant_id, used_at=now)
        except OperationsConflict as exc:
            await self._store.append_audit(
                OperationsAuditRecord(
                    record_id=uuid4(),
                    command_id=command.command_id,
                    actor_subject=command.issued_by.subject_id,
                    action=command.action,
                    target=command.target,
                    outcome=OperationsOutcome.REFUSED,
                    command_digest=command.digest(),
                    occurred_at=now,
                    grant_id=grant.grant_id,
                )
            )
            raise OperationsGrantRefused(
                "sensitive-access grant was already consumed; grants are single-use"
            ) from exc
