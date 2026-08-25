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


@dataclass(frozen=True, slots=True)
class LicenseRecord:
    license_id: UUID
    state: LicenseState
    version: int
    tenant_id: UUID | None = None
    account_id: UUID | None = None
    hardware_id: str | None = None


class LicenseLifecycle:
    @staticmethod
    def activate(record: LicenseRecord, *, tenant_id: UUID, account_id: UUID, hardware_id: str) -> LicenseRecord:
        if record.state is not LicenseState.UNUSED or not hardware_id:
            raise ValueError("only an unused license can be activated")
        return LicenseRecord(record.license_id, LicenseState.ACTIVE, record.version + 1, tenant_id, account_id, hardware_id)

    @staticmethod
    def transition(record: LicenseRecord, state: LicenseState) -> LicenseRecord:
        if record.state is LicenseState.REVOKED and state is not LicenseState.REVOKED:
            raise ValueError("a revoked license cannot be reactivated")
        return LicenseRecord(record.license_id, state, record.version + 1, record.tenant_id, record.account_id, record.hardware_id)


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
            "signing_keys": {key: base64.b64encode(value).decode("ascii") for key, value in sorted(self.signing_keys.items())},
            "revoked_key_ids": list(sorted(self.revoked_key_ids)),
            "policy": dict(sorted(self.policy.items())),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, root: Ed25519PrivateKey) -> "SignedTrustBundle":
        return SignedTrustBundle(self, base64.b64encode(root.sign(self.canonical_bytes())).decode("ascii"))


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
