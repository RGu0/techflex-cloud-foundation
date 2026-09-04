"""Business-neutral License facts, trust bundles, and entitlement decisions."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
import json
from typing import Any, Mapping, Protocol
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class LicenseState(StrEnum):
    UNUSED = "UNUSED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


# The whole lifecycle, as a table rather than as guard clauses.  Every pair not
# named here is refused; see :meth:`LicenseLifecycle.transition` for why each
# omission is deliberate.
_ALLOWED_TRANSITIONS: Mapping[LicenseState, frozenset[LicenseState]] = {
    LicenseState.UNUSED: frozenset(),
    LicenseState.ACTIVE: frozenset({LicenseState.SUSPENDED, LicenseState.REVOKED}),
    LicenseState.SUSPENDED: frozenset({LicenseState.ACTIVE, LicenseState.REVOKED}),
    LicenseState.REVOKED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class LicenseRecord:
    license_id: UUID
    state: LicenseState
    version: int
    tenant_id: UUID | None = None
    account_id: UUID | None = None
    hardware_id: str | None = None


class LicenseLifecycle:
    """The license state machine, enforced as a whitelist.

    Four states, four legal moves::

        UNUSED --activate()--> ACTIVE <--> SUSPENDED
                                  \\         /
                                   v       v
                                    REVOKED   (terminal)

    ``transition`` previously refused exactly one thing -- leaving REVOKED --
    and permitted every other pair by omission, including moves that erase
    binding facts.  ``UNUSED -> ACTIVE`` through ``transition`` produced an
    ACTIVE license with ``tenant_id``, ``account_id`` and ``hardware_id`` all
    still ``None``, because only :meth:`activate` sets them; anything moving
    *back* to UNUSED kept the bindings on a record whose state says it has
    none.  Both leave a record whose state and fields contradict each other,
    and neither raised.

    A whitelist inverts the default: a pair is legal because it is written
    down, not because nobody thought to forbid it.
    """

    @staticmethod
    def activate(
        record: LicenseRecord, *, tenant_id: UUID, account_id: UUID, hardware_id: str
    ) -> LicenseRecord:
        """The only entry into ACTIVE, because it is the only binding step."""

        if record.state is not LicenseState.UNUSED or not hardware_id:
            raise ValueError("only an unused license can be activated")
        return LicenseRecord(
            record.license_id, LicenseState.ACTIVE, record.version + 1,
            tenant_id, account_id, hardware_id,
        )

    @staticmethod
    def transition(record: LicenseRecord, state: LicenseState) -> LicenseRecord:
        """Move a license along the table above, or raise.

        Suspension is recoverable: ``SUSPENDED -> ACTIVE`` keeps the original
        binding, so a lapsed-then-restored subscription does not require the
        customer to re-activate hardware.  Revocation is not: REVOKED is
        terminal, and a license issued again after revocation is a new
        ``license_id``, not this record moved backwards.

        Identity transitions are refused too.  Each call increments
        ``version``, so re-revoking an already-REVOKED license is not the
        no-op it looks like -- it invalidates any concurrent holder's
        optimistic-concurrency check for no state change.  A caller making a
        revocation idempotent tests ``record.state is LicenseState.REVOKED``
        first, which is a question this boundary cannot answer for it.
        """

        allowed = _ALLOWED_TRANSITIONS[record.state]
        if state not in allowed:
            raise ValueError(_rejection_reason(record.state, state))
        return LicenseRecord(
            record.license_id, state, record.version + 1,
            record.tenant_id, record.account_id, record.hardware_id,
        )


def _rejection_reason(current: LicenseState, requested: LicenseState) -> str:
    """Explain a refusal in terms of the lifecycle, not of the table."""

    if current is requested:
        return (
            f"a license is already {current.value}; transition() always increments version, "
            "so check the state instead of re-applying it"
        )
    if current is LicenseState.REVOKED:
        return "a revoked license is terminal and cannot be reactivated; issue a new license"
    if requested is LicenseState.UNUSED:
        return (
            "a license cannot return to UNUSED; its tenant, account, and hardware "
            "bindings are permanent"
        )
    if current is LicenseState.UNUSED:
        return (
            "an unused license becomes ACTIVE only through activate(), which binds "
            "tenant, account, and hardware"
        )
    return f"{current.value} -> {requested.value} is not a legal license transition"


@dataclass(frozen=True, slots=True)
class EntitlementDecision:
    license_id: UUID
    application_id: str
    capabilities: frozenset[str]
    policy_revision: int
    evaluated_at: datetime

    def allows(self, capability: str) -> bool:
        return capability in self.capabilities


class EntitlementResolver(Protocol):
    def resolve(self, *, license_id: UUID, application_id: str) -> EntitlementDecision: ...


@dataclass(frozen=True, slots=True)
class TrustBundle:
    revision: int
    issued_at: datetime
    signing_keys: Mapping[str, bytes]
    revoked_key_ids: tuple[str, ...]
    policy: Mapping[str, bool]

    def canonical_bytes(self) -> bytes:
        if self.revision < 1 or self.issued_at.tzinfo is None:
            raise ValueError("trust bundle requires a positive revision and aware issue time")
        payload: dict[str, Any] = {
            "revision": self.revision,
            "issued_at": self.issued_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "signing_keys": {
                key: base64.b64encode(value).decode("ascii")
                for key, value in sorted(self.signing_keys.items())
            },
            "revoked_key_ids": list(sorted(self.revoked_key_ids)),
            "policy": dict(sorted(self.policy.items())),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, root: Ed25519PrivateKey) -> "SignedTrustBundle":
        signature = base64.b64encode(root.sign(self.canonical_bytes())).decode("ascii")
        return SignedTrustBundle(self, signature)


@dataclass(frozen=True, slots=True)
class SignedTrustBundle:
    bundle: TrustBundle
    signature: str


class TrustBundleVerifier:
    def __init__(self, root_public_key: bytes) -> None:
        self._root = Ed25519PublicKey.from_public_bytes(root_public_key)

    def verify(self, signed: SignedTrustBundle, *, minimum_revision: int) -> TrustBundle:
        if signed.bundle.revision <= minimum_revision:
            raise ValueError("trust bundle revision must be greater than the installed revision")
        try:
            signature = base64.b64decode(signed.signature, validate=True)
            self._root.verify(signature, signed.bundle.canonical_bytes())
        except (InvalidSignature, ValueError) as error:
            raise ValueError("trust bundle signature is invalid") from error
        return signed.bundle
