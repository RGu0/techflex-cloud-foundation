"""Cloud release gate and redacted validation receipts (CP-11).

A `ReleaseGate` composes named validators over *snapshot evidence* -- the
deployment profile document, an RLS introspection snapshot, captured login
tokens, capacity measurements -- and refuses the release when any blocking
finding fails.  Nothing here connects to a cloud: everything the gate
decides on was captured beforehand, so the same gate runs in unit tests, in
CI with no infrastructure, and in a deployment's release pipeline.

Invariants carried over from RAY-341 and the reference seed composition:

- The gate decides on snapshots only.  A check that needs a live
  connection belongs to the deployment's own acceptance, not here.
- Any blocking failure refuses the release; a warning failure is recorded
  on the receipt but never blocks.  A missing snapshot is a blocking
  failure -- absent evidence is never a pass -- and so is a validator that
  crashes.
- A receipt is redacted by construction: serialization carries a field
  whitelist (decision, evidence tier, per-validator conclusions, time,
  version) and nothing else.  Credentials, endpoints, bucket names, DSNs,
  and customer data have no field to land in, a document carrying an
  unknown field is refused, and free-form reasons are never serialized.
- ``production_ready`` is structural: only a ``production``-tier receipt
  with no blocking failure can claim it, so local and seed evidence can
  never announce production readiness.
- `ProductProfiles` requires at least two product profiles or an explicit
  ``provisional`` marking, mirroring the single-consumer provisional rule
  the vendored cloud default already follows.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib
import json
import re
from typing import Any, Protocol

from .bucket_catalog import BucketCatalog, BucketCatalogError
from .iam import IamError, RealmTokenAuthority
from .ingestion import ArtifactReceipt
from .license_lifecycle import LicenseKeyset, LicenseLifecycleError
from .manifest import ManifestMalformed
from .manifest import _require_digest as _manifest_require_digest
from .manifest import _require_text as _manifest_require_text
from .object_store import InMemoryObjectStore
from .observability import (
    BackupManifest,
    ObservabilityError,
    RestoredTargetProbe,
    RestoreVerifier,
)
from .platform_config import (
    BucketRole,
    PlatformConfigError,
    ProductRegistration,
    parse_deployment_profile,
)
from .tenancy import RlsContract, TenancyError, parse_introspection_snapshot

RELEASE_RECEIPT_SCHEMA_VERSION = "techflex-release-receipt/1"

# The receipt document's complete field whitelist.  Everything a redacted
# receipt may carry is named here; a document carrying anything else is
# refused, which is what keeps a credential, an endpoint, a bucket name, a
# DSN, or customer data from ever landing on one.
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "decision",
        "evidence_tier",
        "release_version",
        "evaluated_at",
        "validators",
    }
)
_RECEIPT_ENTRY_FIELDS = frozenset({"validator", "component", "passed", "level"})
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(secret|password|token|credential|dsn|endpoint|bucket|host|url|customer|key)"
)


class ReleaseGateError(Exception):
    """Base class for release gate and receipt failures."""


class ReleaseGateMalformed(ReleaseGateError):
    """The gate, a snapshot, a profile set, or a receipt is structurally invalid."""


class ReleaseGateVersionUnsupported(ReleaseGateError):
    """A receipt document declares a schema version this build refuses."""


def _require_text(value: Any, *, field_name: str) -> str:
    try:
        return _manifest_require_text(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise ReleaseGateMalformed(str(exc)) from exc


def _require_digest(value: Any, *, field_name: str) -> str:
    try:
        return _manifest_require_digest(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise ReleaseGateMalformed(str(exc)) from exc


def _require_aware(value: datetime, *, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReleaseGateMalformed(f"{field_name} must be timezone-aware")


def _require_non_negative_int(value: Any, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReleaseGateMalformed(f"{field_name} must be a non-negative integer")
    return value


class FindingLevel(StrEnum):
    """What a failed finding costs the release."""

    BLOCKING = "blocking"
    WARNING = "warning"


class EvidenceTier(StrEnum):
    """Where the snapshot evidence came from; only production may claim readiness."""

    LOCAL = "local"
    SEED = "seed"
    PRODUCTION = "production"


class GateDecision(StrEnum):
    """The gate's conclusion; any blocking failure refuses the release."""

    APPROVED = "approved"
    REFUSED = "refused"


@dataclass(frozen=True)
class ValidationResult:
    """One validator's conclusion over one snapshot.

    ``level`` is the severity the finding carries when it fails; a passed
    result records the level its failure would have been.  ``reason`` stays
    in process: it is never serialized onto a receipt, because a reason is
    free-form text and free-form text is where a bucket name or a DSN
    hides.
    """

    validator: str
    component: str
    level: FindingLevel
    passed: bool
    reason: str

    def __post_init__(self) -> None:
        _require_text(self.validator, field_name="validator name")
        _require_text(self.component, field_name="component name")
        if not isinstance(self.level, FindingLevel):
            raise ReleaseGateMalformed("finding level must be a FindingLevel")
        if not isinstance(self.passed, bool):
            raise ReleaseGateMalformed("passed must be a boolean")
        _require_text(self.reason, field_name="finding reason")

    @property
    def is_blocking_failure(self) -> bool:
        return not self.passed and self.level is FindingLevel.BLOCKING


def _blocked(validator: str, component: str, reason: str) -> ValidationResult:
    return ValidationResult(
        validator=validator,
        component=component,
        level=FindingLevel.BLOCKING,
        passed=False,
        reason=reason,
    )


def _cleared(validator: str, component: str, reason: str) -> ValidationResult:
    return ValidationResult(
        validator=validator,
        component=component,
        level=FindingLevel.BLOCKING,
        passed=True,
        reason=reason,
    )


class ReleaseValidator(Protocol):
    """One named check over captured snapshot evidence.

    ``validate`` receives the snapshot registered under the validator's
    name plus the gate's explicit ``now``; it returns a conclusion rather
    than raising for evidence failures.  A structurally wrong snapshot --
    the wrong type entirely -- is a wiring error and raises
    ``ReleaseGateMalformed``; content failures are blocking results.
    """

    name: str

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult: ...


class DeploymentProfileValidator:
    """Validates the deployment profile snapshot through CP-01's parser.

    The parser enforces the whole profile contract, including the
    production ingress invariants: a production environment must present a
    public-CA hostname on 443, so this validator inherits that decision
    rather than restating it.
    """

    name = "deployment_profile"

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, Mapping):
            raise ReleaseGateMalformed(
                "deployment profile validation requires a profile document snapshot"
            )
        try:
            profile = parse_deployment_profile(snapshot)
        except PlatformConfigError as exc:
            return _blocked(
                self.name,
                "deployment-profile",
                f"deployment profile does not satisfy the platform schema: {exc}",
            )
        return _cleared(
            self.name,
            "deployment-profile",
            f"deployment profile parses for environment {profile.environment}; "
            "the production ingress invariants are enforced by the profile itself",
        )


class RlsSnapshotValidator:
    """Checks an RLS introspection snapshot against CP-08's contract."""

    name = "rls_snapshot"

    def __init__(self, contract: RlsContract) -> None:
        if not isinstance(contract, RlsContract):
            raise ReleaseGateMalformed(
                "RLS snapshot validation requires an RlsContract"
            )
        self._contract = contract

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, Mapping):
            raise ReleaseGateMalformed(
                "RLS snapshot validation requires an introspection snapshot document"
            )
        try:
            parsed = parse_introspection_snapshot(snapshot)
        except TenancyError as exc:
            return _blocked(
                self.name,
                "tenant-data-plane",
                f"introspection snapshot is not a valid catalog snapshot: {exc}",
            )
        report = self._contract.validate(parsed)
        if not report.satisfied:
            findings = "; ".join(
                f"{finding.code} on {finding.subject}" for finding in report.findings
            )
            return _blocked(
                self.name,
                "tenant-data-plane",
                f"deployment does not satisfy the RLS contract: {findings}",
            )
        return _cleared(
            self.name,
            "tenant-data-plane",
            "introspection snapshot satisfies every clause of the RLS contract",
        )


class BucketPolicyValidator:
    """Rebuilds the bucket catalog from the profile's bucket bindings.

    Runs the bindings through CP-01's policy enforcement (raw-immutable
    versioning, identical policies on shared physical buckets) and CP-07's
    catalog construction (unique roles, at least one binding), then
    re-resolves every bound role.  Reasons mention logical roles only;
    physical bucket names never leave the validator.
    """

    name = "bucket_policy"

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, Mapping):
            raise ReleaseGateMalformed(
                "bucket policy validation requires a deployment profile "
                "document snapshot"
            )
        try:
            profile = parse_deployment_profile(snapshot)
            catalog = BucketCatalog.from_profile(profile, InMemoryObjectStore())
        except PlatformConfigError as exc:
            return _blocked(
                self.name,
                "bucket-catalog",
                f"bucket bindings do not satisfy the platform policy: {exc}",
            )
        except BucketCatalogError as exc:
            return _blocked(
                self.name,
                "bucket-catalog",
                f"bucket catalog cannot be built from the bindings: {exc}",
            )
        for role in catalog.roles:
            binding = catalog.binding_for(role)
            if binding.role is BucketRole.RAW_IMMUTABLE and not binding.policy.versioning:
                return _blocked(
                    self.name,
                    "bucket-catalog",
                    "the raw-immutable binding lost versioning; originals are "
                    "never silently overwritten",
                )
        return _cleared(
            self.name,
            "bucket-catalog",
            f"bucket catalog binds {len(catalog.roles)} logical role(s) under "
            "enforced encryption, versioning, and retention policies",
        )


@dataclass(frozen=True)
class LicenseKeysetSnapshot:
    """The keyset facts a release presents, as raw fields.

    Carries public key bytes only; a license keyset authorizes and never
    holds data-key material, and nothing here is ever serialized onto a
    receipt.
    """

    revision: int
    active_key_id: str
    public_keys: Mapping[str, bytes]
    revoked_key_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_non_negative_int(self.revision, field_name="keyset revision")
        _require_text(self.active_key_id, field_name="active key id")
        if not isinstance(self.public_keys, Mapping) or not self.public_keys:
            raise ReleaseGateMalformed(
                "keyset public keys must be a non-empty mapping of key id to bytes"
            )
        copied: dict[str, bytes] = {}
        for key_id, raw in self.public_keys.items():
            _require_text(key_id, field_name="public key id")
            if not isinstance(raw, bytes):
                raise ReleaseGateMalformed("public key material must be bytes")
            copied[key_id] = raw
        object.__setattr__(self, "public_keys", copied)
        for key_id in self.revoked_key_ids:
            _require_text(key_id, field_name="revoked key id")


class LicenseKeysetValidator:
    """Runs the license keyset snapshot through CP-04's `LicenseKeyset`.

    The keyset enforces key id uniqueness, an active key that is present
    and not revoked, and unique revoked ids; the validator additionally
    resolves the active key as ed25519 material, so a key id that names
    non-key bytes is a blocking failure rather than a runtime surprise at
    first verification.
    """

    name = "license_keyset"

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, LicenseKeysetSnapshot):
            raise ReleaseGateMalformed(
                "license keyset validation requires a LicenseKeysetSnapshot"
            )
        try:
            keyset = LicenseKeyset(
                revision=snapshot.revision,
                active_key_id=snapshot.active_key_id,
                public_keys=snapshot.public_keys,
                revoked_key_ids=snapshot.revoked_key_ids,
            )
            keyset.public_key(keyset.active_key_id)
        except LicenseLifecycleError as exc:
            return _blocked(
                self.name, "license-keyset", f"license keyset is not valid: {exc}"
            )
        except ValueError as exc:
            return _blocked(
                self.name,
                "license-keyset",
                f"active key material is not a valid ed25519 public key: {exc}",
            )
        return _cleared(
            self.name,
            "license-keyset",
            f"license keyset revision {keyset.revision} holds a resolvable, "
            "unrevoked active key",
        )


@dataclass(frozen=True)
class OrgLoginSnapshot:
    """Login-drill evidence: the tokens an institutional sign-in produced.

    Tokens are credentials-adjacent material and stay in process; they are
    verified here and never serialized onto a receipt.
    """

    tenant_access_token: str
    expected_tenant_id: str
    expected_operator_id: str
    platform_access_token: str

    def __post_init__(self) -> None:
        _require_text(
            self.tenant_access_token, field_name="tenant access token"
        )
        _require_text(self.expected_tenant_id, field_name="expected tenant id")
        _require_text(
            self.expected_operator_id, field_name="expected operator id"
        )
        _require_text(
            self.platform_access_token, field_name="platform access token"
        )


class OrgLoginValidator:
    """Re-proves institutional login evidence through CP-03's authority.

    The tenant access token must verify for the tenant and operator the
    drill expects, and the platform access token must be *refused* in the
    tenant realm: the tokens are captured evidence, not tokens this
    authority issued, so the realm separation is re-proven from the
    evidence rather than trusted from construction.
    """

    name = "org_login"

    def __init__(self, authority: RealmTokenAuthority) -> None:
        if not isinstance(authority, RealmTokenAuthority):
            raise ReleaseGateMalformed(
                "organization login validation requires a RealmTokenAuthority"
            )
        self._authority = authority

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, OrgLoginSnapshot):
            raise ReleaseGateMalformed(
                "organization login validation requires an OrgLoginSnapshot"
            )
        try:
            principal = self._authority.verify_tenant(
                snapshot.tenant_access_token, now=now
            )
        except IamError as exc:
            return _blocked(
                self.name,
                "org-login",
                f"tenant access token does not verify: {exc}",
            )
        if (
            principal.tenant_id != snapshot.expected_tenant_id
            or principal.operator_id != snapshot.expected_operator_id
        ):
            return _blocked(
                self.name,
                "org-login",
                "the verified principal does not match the tenant and operator "
                "the login drill expected",
            )
        try:
            crossed = self._authority.verify_tenant(
                snapshot.platform_access_token, now=now
            )
        except IamError:
            pass
        else:
            return _blocked(
                self.name,
                "org-login",
                f"a platform-realm token verified in the tenant realm as "
                f"{crossed.operator_id!r}; the realms must stay separate",
            )
        return _cleared(
            self.name,
            "org-login",
            "the tenant login token verifies for the expected operator and a "
            "platform-realm token is refused in the tenant realm",
        )


@dataclass(frozen=True)
class IngestionReceiptSnapshot:
    """One completed CP-06 receipt plus the digest recorded for it."""

    receipt: ArtifactReceipt
    expected_digest: str
    expected_canonical_bytes: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, ArtifactReceipt):
            raise ReleaseGateMalformed(
                "ingestion receipt validation requires an ArtifactReceipt"
            )
        _require_digest(self.expected_digest, field_name="expected receipt digest")
        if self.expected_canonical_bytes is not None and not isinstance(
            self.expected_canonical_bytes, bytes
        ):
            raise ReleaseGateMalformed(
                "expected canonical bytes must be bytes or None"
            )


class IngestionReceiptValidator:
    """Replays a CP-06 receipt's canonical bytes against its recorded digest.

    The receipt recomputes its digest from its own canonical bytes, so a
    receipt altered after completion no longer replays the digest recorded
    elsewhere -- the same immutability rule completion itself enforces.
    """

    name = "ingestion_receipt"

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, IngestionReceiptSnapshot):
            raise ReleaseGateMalformed(
                "ingestion receipt validation requires an IngestionReceiptSnapshot"
            )
        if snapshot.receipt.digest() != snapshot.expected_digest:
            return _blocked(
                self.name,
                "ingestion-receipt",
                "receipt canonical bytes do not replay the recorded digest; "
                "the receipt was altered after completion",
            )
        if (
            snapshot.expected_canonical_bytes is not None
            and snapshot.receipt.canonical_bytes() != snapshot.expected_canonical_bytes
        ):
            return _blocked(
                self.name,
                "ingestion-receipt",
                "receipt canonical bytes differ from the bytes recorded at "
                "completion",
            )
        return _cleared(
            self.name,
            "ingestion-receipt",
            "receipt canonical bytes replay the recorded digest",
        )


@dataclass(frozen=True)
class TenantProbeResult:
    """One tenant's cross-tenant isolation probe outcome.

    Leak entries are opaque labels for the probe that leaked, never the
    leaked data itself.
    """

    tenant_id: str
    probes_executed: int
    cross_tenant_leaks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.tenant_id, field_name="probed tenant id")
        _require_non_negative_int(
            self.probes_executed, field_name="executed probe count"
        )
        for leak in self.cross_tenant_leaks:
            _require_text(leak, field_name="cross-tenant leak label")


@dataclass(frozen=True)
class TenantIsolationSnapshot:
    """Per-tenant isolation probe results, with the tenants that must appear."""

    required_tenant_ids: frozenset[str]
    results: tuple[TenantProbeResult, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.required_tenant_ids, frozenset) or not (
            self.required_tenant_ids
        ):
            raise ReleaseGateMalformed(
                "tenant isolation evidence must name at least one required tenant"
            )
        for tenant_id in self.required_tenant_ids:
            _require_text(tenant_id, field_name="required tenant id")
        for result in self.results:
            if not isinstance(result, TenantProbeResult):
                raise ReleaseGateMalformed(
                    "tenant isolation results must be TenantProbeResult entries"
                )


class TenantIsolationValidator:
    """Asserts the isolation probes found no cross-tenant leakage.

    A required tenant with no probe result is a blocking failure: nothing
    was learned about that tenant's isolation, and absence of evidence is
    never a pass.  So is a tenant whose probes never ran, and any leak at
    all.
    """

    name = "tenant_isolation"

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, TenantIsolationSnapshot):
            raise ReleaseGateMalformed(
                "tenant isolation validation requires a TenantIsolationSnapshot"
            )
        by_tenant: dict[str, TenantProbeResult] = {}
        for result in snapshot.results:
            if result.tenant_id in by_tenant:
                return _blocked(
                    self.name,
                    "tenant-isolation",
                    f"tenant {result.tenant_id!r} reports probe results twice; "
                    "ambiguous evidence is refused",
                )
            by_tenant[result.tenant_id] = result
        missing = sorted(
            tenant_id
            for tenant_id in snapshot.required_tenant_ids
            if tenant_id not in by_tenant
        )
        if missing:
            return _blocked(
                self.name,
                "tenant-isolation",
                f"{len(missing)} required tenant(s) have no probe result; "
                "absent evidence is blocking, never a pass",
            )
        for tenant_id in sorted(snapshot.required_tenant_ids):
            result = by_tenant[tenant_id]
            if result.probes_executed < 1:
                return _blocked(
                    self.name,
                    "tenant-isolation",
                    f"no isolation probes ran for tenant {tenant_id!r}",
                )
            if result.cross_tenant_leaks:
                return _blocked(
                    self.name,
                    "tenant-isolation",
                    f"tenant {tenant_id!r} observed cross-tenant leakage in "
                    f"{len(result.cross_tenant_leaks)} probe(s); any leak is "
                    "a release-stopping isolation failure",
                )
        return _cleared(
            self.name,
            "tenant-isolation",
            f"{len(snapshot.required_tenant_ids)} required tenant(s) probed "
            "with no cross-tenant leakage",
        )


@dataclass(frozen=True)
class RecoveryDrillSnapshot:
    """A restore drill's inputs: manifest, empty target, and restore step.

    The drill runs when validated, against the target the snapshot carries;
    a drill is single-use by nature, because the target must start empty.
    """

    manifest: BackupManifest
    target: RestoredTargetProbe
    restore: Callable[[], None]

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, BackupManifest):
            raise ReleaseGateMalformed(
                "recovery drill validation requires a BackupManifest"
            )
        # ``RestoredTargetProbe`` is a Protocol, so the target is checked by
        # the surface it must expose rather than by isinstance.
        for attr in (
            "is_empty",
            "component_payload",
            "tenant_count",
            "restored_version",
            "available_key_references",
        ):
            if not callable(getattr(self.target, attr, None)):
                raise ReleaseGateMalformed(
                    "recovery drill validation requires a RestoredTargetProbe"
                )
        if not callable(self.restore):
            raise ReleaseGateMalformed("the restore step must be callable")


class RecoveryDrillValidator:
    """Proves recovery through CP-10's `RestoreVerifier`.

    The verifier refuses a non-empty target, re-evaluates every component
    digest against the restored bytes, and re-checks tenant count, version,
    and key references before issuing a receipt.  A backup merely existing
    is not a recovery, and this validator inherits that decision rather
    than restating it.
    """

    name = "backup_recovery"

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, RecoveryDrillSnapshot):
            raise ReleaseGateMalformed(
                "recovery drill validation requires a RecoveryDrillSnapshot"
            )
        try:
            RestoreVerifier().run_drill(
                snapshot.manifest,
                snapshot.target,
                snapshot.restore,
                verified_at=now,
            )
        except ObservabilityError as exc:
            return _blocked(
                self.name,
                "backup-recovery",
                f"the restore drill did not re-prove the backup: {exc}",
            )
        return _cleared(
            self.name,
            "backup-recovery",
            "the restore drill re-proved every component digest against the "
            "restored bytes; a backup existing is not a recovery, and this "
            "drill proved one",
        )


@dataclass(frozen=True)
class CapacitySnapshot:
    """Declared capacity minimums beside what was actually measured.

    Dimension names are deployment labels (``concurrent_sessions``,
    ``ingest_bytes_per_second``); units and what deserves a dimension stay
    with the application.
    """

    declared_minimums: Mapping[str, int]
    measured: Mapping[str, int]

    def __post_init__(self) -> None:
        if not isinstance(self.declared_minimums, Mapping) or not (
            self.declared_minimums
        ):
            raise ReleaseGateMalformed(
                "declared capacity minimums must be a non-empty mapping"
            )
        if not isinstance(self.measured, Mapping):
            raise ReleaseGateMalformed("measured capacity must be a mapping")
        declared: dict[str, int] = {}
        for dimension, value in self.declared_minimums.items():
            _require_text(dimension, field_name="capacity dimension")
            declared[dimension] = _require_non_negative_int(
                value, field_name=f"declared minimum for {dimension!r}"
            )
        measured: dict[str, int] = {}
        for dimension, value in self.measured.items():
            _require_text(dimension, field_name="measured capacity dimension")
            measured[dimension] = _require_non_negative_int(
                value, field_name=f"measured value for {dimension!r}"
            )
        object.__setattr__(self, "declared_minimums", declared)
        object.__setattr__(self, "measured", measured)


class CapacityValidator:
    """Compares measured capacity against the declared minimums."""

    name = "capacity"

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if not isinstance(snapshot, CapacitySnapshot):
            raise ReleaseGateMalformed(
                "capacity validation requires a CapacitySnapshot"
            )
        unmeasured = sorted(
            dimension
            for dimension in snapshot.declared_minimums
            if dimension not in snapshot.measured
        )
        if unmeasured:
            return _blocked(
                self.name,
                "capacity",
                f"declared dimension(s) {unmeasured} were never measured; "
                "absent evidence is blocking, never a pass",
            )
        for dimension in sorted(snapshot.declared_minimums):
            declared = snapshot.declared_minimums[dimension]
            actual = snapshot.measured[dimension]
            if actual < declared:
                return _blocked(
                    self.name,
                    "capacity",
                    f"measured {actual} for {dimension!r} is below the declared "
                    f"minimum {declared}",
                )
        return _cleared(
            self.name,
            "capacity",
            f"every declared capacity dimension meets or exceeds its minimum "
            f"({len(snapshot.declared_minimums)} measured)",
        )


@dataclass(frozen=True)
class ProductProfiles:
    """The product profiles a release claims to serve.

    A single product profile is release-ready only when explicitly marked
    ``provisional`` -- the same single-consumer rule the vendored cloud
    default follows.  ``release_supported`` states the answer; the gate
    turns a ``False`` into a blocking refusal.
    """

    profiles: tuple[ProductRegistration, ...]
    provisional: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.provisional, bool):
            raise ReleaseGateMalformed("provisional must be a boolean")
        if not self.profiles:
            raise ReleaseGateMalformed(
                "at least one product profile is required; a release that "
                "serves nothing proves nothing"
            )
        product_ids: list[str] = []
        for profile in self.profiles:
            if not isinstance(profile, ProductRegistration):
                raise ReleaseGateMalformed(
                    "product profiles must be ProductRegistration entries"
                )
            product_ids.append(profile.product_id)
        if len(set(product_ids)) != len(product_ids):
            raise ReleaseGateMalformed("product ids must be unique within a release")

    @property
    def release_supported(self) -> bool:
        return len(self.profiles) >= 2 or self.provisional


@dataclass(frozen=True)
class ReleaseReceipt:
    """The redacted, immutable record of one gate evaluation.

    Built by :meth:`ReleaseGate.evaluate`; the decision must follow the
    blocking findings, so a receipt cannot claim a conclusion its own
    conclusions contradict.  Serialization is a whitelist (see
    ``to_document``); reasons and all evidence detail stay in process.
    """

    decision: GateDecision
    evidence_tier: EvidenceTier
    release_version: str
    evaluated_at: datetime
    results: tuple[ValidationResult, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.decision, GateDecision):
            raise ReleaseGateMalformed("decision must be a GateDecision")
        if not isinstance(self.evidence_tier, EvidenceTier):
            raise ReleaseGateMalformed("evidence_tier must be an EvidenceTier")
        _require_text(self.release_version, field_name="release version")
        _require_aware(self.evaluated_at, field_name="evaluated_at")
        if not self.results:
            raise ReleaseGateMalformed(
                "a receipt must record at least one validator conclusion; "
                "a receipt that asserts nothing proves nothing"
            )
        names = [result.validator for result in self.results]
        if len(set(names)) != len(names):
            raise ReleaseGateMalformed(
                "each validator may record exactly one conclusion"
            )
        expected = (
            GateDecision.REFUSED
            if any(result.is_blocking_failure for result in self.results)
            else GateDecision.APPROVED
        )
        if self.decision is not expected:
            raise ReleaseGateMalformed(
                "the receipt decision must follow its blocking findings; a "
                "receipt cannot claim a decision its own conclusions contradict"
            )

    @property
    def production_ready(self) -> bool:
        """Whether this receipt may claim production readiness.

        Structural by construction: only a ``production``-tier receipt with
        no blocking failure answers True, so local and seed evidence can
        never announce production readiness no matter how it is built.
        """

        return (
            self.evidence_tier is EvidenceTier.PRODUCTION
            and self.decision is GateDecision.APPROVED
        )

    @property
    def blocking_failures(self) -> tuple[ValidationResult, ...]:
        return tuple(result for result in self.results if result.is_blocking_failure)

    def to_document(self) -> dict[str, Any]:
        """The whitelisted, JSON-safe document; anything else never serializes."""
        return {
            "schema_version": RELEASE_RECEIPT_SCHEMA_VERSION,
            "decision": str(self.decision),
            "evidence_tier": str(self.evidence_tier),
            "release_version": self.release_version,
            "evaluated_at": self.evaluated_at.isoformat(),
            "validators": [
                {
                    "validator": result.validator,
                    "component": result.component,
                    "passed": result.passed,
                    "level": str(result.level),
                }
                for result in self.results
            ],
        }

    def canonical_bytes(self) -> bytes:
        """Reproducible byte form; two equal receipts serialize identically."""
        return json.dumps(
            self.to_document(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def digest(self) -> str:
        """Complete SHA-256 over the canonical form, for evidence anchoring."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @staticmethod
    def from_document(document: Any) -> ReleaseReceipt:
        """Parse a receipt document, refusing anything outside the whitelist.

        Reasons never serialize, so the conclusions a document carries are
        rebuilt with a placeholder reason; the canonical bytes are the
        contract, and they round-trip exactly.
        """

        if not isinstance(document, Mapping):
            raise ReleaseGateMalformed("release receipt document must be a mapping")
        unknown = sorted(str(key) for key in set(document) - _RECEIPT_FIELDS)
        if unknown:
            sensitive = [key for key in unknown if _SENSITIVE_KEY_RE.search(key)]
            if sensitive:
                raise ReleaseGateMalformed(
                    f"release receipt document carries field(s) {sensitive}; a "
                    "redacted receipt serializes a whitelist only -- credentials, "
                    "endpoints, bucket names, DSNs, and customer data never "
                    "appear on one"
                )
            raise ReleaseGateMalformed(
                f"release receipt document carries unknown field(s) {unknown}; "
                "unknown fields are refused, never guessed"
            )
        schema_version = document.get("schema_version")
        if schema_version != RELEASE_RECEIPT_SCHEMA_VERSION:
            raise ReleaseGateVersionUnsupported(
                f"schema_version {schema_version!r} is not supported; this build "
                f"accepts only {RELEASE_RECEIPT_SCHEMA_VERSION!r}"
            )
        try:
            decision = GateDecision(
                _require_text(document.get("decision"), field_name="decision")
            )
            tier = EvidenceTier(
                _require_text(
                    document.get("evidence_tier"), field_name="evidence_tier"
                )
            )
        except ValueError as exc:
            raise ReleaseGateMalformed(
                "decision and evidence_tier must be declared members"
            ) from exc
        raw_evaluated = document.get("evaluated_at")
        if not isinstance(raw_evaluated, str):
            raise ReleaseGateMalformed("evaluated_at must be an ISO-8601 timestamp")
        try:
            evaluated_at = datetime.fromisoformat(raw_evaluated)
        except ValueError as exc:
            raise ReleaseGateMalformed(
                "evaluated_at must be an ISO-8601 timestamp"
            ) from exc
        entries = document.get("validators")
        if not isinstance(entries, list) or not entries:
            raise ReleaseGateMalformed(
                "validators must be a non-empty list of conclusions"
            )
        results: list[ValidationResult] = []
        for index, entry in enumerate(entries):
            context = f"validators[{index}]"
            if not isinstance(entry, Mapping):
                raise ReleaseGateMalformed(f"{context} must be an object")
            entry_unknown = sorted(str(key) for key in set(entry) - _RECEIPT_ENTRY_FIELDS)
            if entry_unknown:
                raise ReleaseGateMalformed(
                    f"{context} carries unknown field(s) {entry_unknown}; receipt "
                    "entries serialize a whitelist only"
                )
            missing = sorted(_RECEIPT_ENTRY_FIELDS - set(entry))
            if missing:
                raise ReleaseGateMalformed(
                    f"{context} is missing field(s) {missing}; missing fields are "
                    "refused, never guessed"
                )
            try:
                level = FindingLevel(entry["level"])
            except ValueError as exc:
                raise ReleaseGateMalformed(
                    f"{context}.level must be a FindingLevel"
                ) from exc
            passed = entry["passed"]
            if not isinstance(passed, bool):
                raise ReleaseGateMalformed(f"{context}.passed must be a boolean")
            results.append(
                ValidationResult(
                    validator=_require_text(
                        entry["validator"], field_name=f"{context}.validator"
                    ),
                    component=_require_text(
                        entry["component"], field_name=f"{context}.component"
                    ),
                    level=level,
                    passed=passed,
                    reason="redacted: reasons never serialize on receipts",
                )
            )
        return ReleaseReceipt(
            decision=decision,
            evidence_tier=tier,
            release_version=_require_text(
                document.get("release_version"), field_name="release version"
            ),
            evaluated_at=evaluated_at,
            results=tuple(results),
        )


class ReleaseGate:
    """Composes named validators over snapshot evidence.

    Each registered validator is offered the snapshot carried under its
    name.  A validator with no snapshot records a blocking failure, a
    validator that crashes records a blocking failure, and any blocking
    failure refuses the release.  The product-profile rule is decided
    alongside the validators, and the whole evaluation lands on one
    redacted :class:`ReleaseReceipt`.
    """

    _PRODUCT_PROFILE_VALIDATOR = "product_profiles"

    def __init__(self, validators: Iterable[ReleaseValidator]) -> None:
        catalog: dict[str, ReleaseValidator] = {}
        for validator in tuple(validators):
            name = getattr(validator, "name", None)
            if not isinstance(name, str) or not name.strip():
                raise ReleaseGateMalformed(
                    "every validator must carry a non-empty name"
                )
            if name == self._PRODUCT_PROFILE_VALIDATOR:
                raise ReleaseGateMalformed(
                    f"the validator name {name!r} is reserved for the gate's "
                    "product-profile conclusion"
                )
            if name in catalog:
                raise ReleaseGateMalformed(
                    f"validator name {name!r} is registered twice; a name maps "
                    "to exactly one validator"
                )
            catalog[name] = validator
        if not catalog:
            raise ReleaseGateMalformed(
                "a release gate with no validators would approve by silence; "
                "absent evidence is never a pass"
            )
        self._validators = catalog

    @property
    def validator_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._validators))

    def evaluate(
        self,
        *,
        snapshots: Mapping[str, Any],
        tier: EvidenceTier,
        product_profiles: ProductProfiles,
        release_version: str,
        now: datetime,
    ) -> ReleaseReceipt:
        """Run every validator over its snapshot and issue one redacted receipt."""
        _require_aware(now, field_name="now")
        if not isinstance(tier, EvidenceTier):
            raise ReleaseGateMalformed("tier must be an EvidenceTier")
        if not isinstance(product_profiles, ProductProfiles):
            raise ReleaseGateMalformed(
                "evaluation requires a ProductProfiles set"
            )
        _require_text(release_version, field_name="release version")
        if not isinstance(snapshots, Mapping):
            raise ReleaseGateMalformed("snapshots must be a mapping")
        unknown = sorted(
            str(key) for key in set(snapshots) - set(self._validators)
        )
        if unknown:
            raise ReleaseGateMalformed(
                f"snapshot name(s) {unknown} name no registered validator; "
                "unknown names are refused, never guessed"
            )
        results: list[ValidationResult] = []
        for name in sorted(self._validators):
            snapshot = snapshots.get(name)
            if snapshot is None:
                results.append(
                    _blocked(
                        name,
                        name,
                        "no snapshot was provided for this validator; absent "
                        "evidence is blocking, never a pass",
                    )
                )
                continue
            try:
                result = self._validators[name].validate(snapshot, now=now)
            except ReleaseGateMalformed:
                raise
            except Exception as exc:
                results.append(
                    _blocked(
                        name,
                        name,
                        f"validator raised {type(exc).__name__}; a crashed "
                        "validator refuses the release, never passes it",
                    )
                )
                continue
            if not isinstance(result, ValidationResult):
                raise ReleaseGateMalformed(
                    f"validator {name!r} must return a ValidationResult"
                )
            if result.validator != name:
                raise ReleaseGateMalformed(
                    f"validator {name!r} returned a result naming "
                    f"{result.validator!r}; a validator speaks only for itself"
                )
            results.append(result)
        if product_profiles.release_supported:
            if len(product_profiles.profiles) >= 2:
                profile_reason = (
                    f"{len(product_profiles.profiles)} product profiles are "
                    "registered"
                )
            else:
                profile_reason = (
                    "the single product profile is explicitly marked provisional"
                )
            results.append(
                _cleared(self._PRODUCT_PROFILE_VALIDATOR, "product-profiles", profile_reason)
            )
        else:
            results.append(
                _blocked(
                    self._PRODUCT_PROFILE_VALIDATOR,
                    "product-profiles",
                    "a single product profile is not marked provisional; "
                    "evidence from one consumer is provisional by rule and "
                    "must say so",
                )
            )
        results.sort(key=lambda result: result.validator)
        decision = (
            GateDecision.REFUSED
            if any(result.is_blocking_failure for result in results)
            else GateDecision.APPROVED
        )
        return ReleaseReceipt(
            decision=decision,
            evidence_tier=tier,
            release_version=release_version,
            evaluated_at=now,
            results=tuple(results),
        )
