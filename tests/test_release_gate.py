from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from techflex_cloud_foundation import (
    ArtifactReceipt,
    BackupComponent,
    BackupManifest,
    BucketPolicyValidator,
    CapacitySnapshot,
    CapacityValidator,
    DeploymentProfileValidator,
    EvidenceTier,
    FindingLevel,
    GateDecision,
    HmacTokenCodec,
    IngestionReceiptSnapshot,
    IngestionReceiptValidator,
    InMemoryRestoreTarget,
    LicenseKeysetSnapshot,
    LicenseKeysetValidator,
    OrgLoginSnapshot,
    OrgLoginValidator,
    PlatformPrincipal,
    ProductProfiles,
    ProductRegistration,
    RealmTokenAuthority,
    RecoveryDrillSnapshot,
    RecoveryDrillValidator,
    ReleaseGate,
    ReleaseGateMalformed,
    ReleaseGateVersionUnsupported,
    ReleaseReceipt,
    RlsContract,
    RlsSnapshotValidator,
    TenantIsolationSnapshot,
    TenantIsolationValidator,
    TenantPrincipal,
    TenantProbeResult,
    ValidationResult,
)
from techflex_cloud_foundation.platform_config import PLATFORM_CONFIG_SCHEMA_VERSION

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
DATABASE_BYTES = b"pg dump bytes"
OBJECTS_BYTES = b"tarred objects"
PLATFORM_SECRET = b"platform-signing-secret-32-bytes!"
TENANT_SECRET = b"tenant-signing-secret-32-bytes!!!"
TENANT_SETTING = "app.tenant_id"

REDACTED_REASON = "redacted: reasons never serialize on receipts"


class _StubValidator:
    """Custom-validator test double; the framework owes strangers nothing less."""

    def __init__(
        self,
        name: str,
        result: ValidationResult | None = None,
        *,
        raises: Exception | None = None,
        returns: Any = None,
    ) -> None:
        self.name = name
        self._result = result
        self._raises = raises
        self._returns = returns

    def validate(self, snapshot: Any, *, now: datetime) -> ValidationResult:
        if self._raises is not None:
            raise self._raises
        if self._returns is not None:
            return self._returns
        assert self._result is not None
        return self._result


def _profile_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": PLATFORM_CONFIG_SCHEMA_VERSION,
        "environment": "integration",
        "region": "cn-beijing",
        "ingress": {
            "public_base_url": "https://39.105.216.113:7443",
            "port": 7443,
            "public_ca": False,
        },
        "kms": {"provider": "kms", "locator": "alias/platform"},
        "databases": {
            "migration": {"provider": "env", "locator": "PLATFORM_MIGRATION_DSN"},
            "serving": {"provider": "env", "locator": "PLATFORM_SERVING_DSN"},
        },
        "buckets": [
            {
                "role": "raw-immutable",
                "physical_bucket": "raw-bucket",
                "policy": {
                    "encryption": "sse-kms",
                    "versioning": True,
                    "retention": "archival",
                },
            },
            {
                "role": "derived",
                "physical_bucket": "derived-bucket",
                "policy": {
                    "encryption": "sse-aes256",
                    "versioning": False,
                    "retention": "ephemeral",
                },
            },
        ],
        "products": [
            {
                "product_id": "feetforceplate",
                "supported_schema_versions": ["feetforceplate-client-cloud-default/1"],
            }
        ],
    }
    document.update(overrides)
    return document


def _rls_contract() -> RlsContract:
    return RlsContract(
        tenant_setting=TENANT_SETTING,
        required_tables=("artifact_registry.artifact",),
    )


def _rls_snapshot_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "application_role": {
            "name": "platform_app",
            "is_superuser": False,
            "bypasses_rls": False,
            "owned_tables": (),
        },
        "tables": [
            {
                "schema": "artifact_registry",
                "table": "artifact",
                "rls_enabled": True,
                "rls_forced": True,
                "owner": "platform_migrator",
                "policies": [
                    {
                        "name": "tenant_isolation",
                        "command": "ALL",
                        "using_expression": (
                            "tenant_id = current_setting('app.tenant_id')"
                        ),
                        "check_expression": (
                            "tenant_id = current_setting('app.tenant_id')"
                        ),
                    }
                ],
            }
        ],
    }
    document.update(overrides)
    return document


def _ed25519_public_bytes() -> bytes:
    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def _license_snapshot(**overrides: object) -> LicenseKeysetSnapshot:
    values: dict[str, object] = {
        "revision": 3,
        "active_key_id": "license-2026-a",
        "public_keys": {
            "license-2026-a": _ed25519_public_bytes(),
            "license-2025-a": _ed25519_public_bytes(),
        },
        "revoked_key_ids": ("license-2025-a",),
    }
    values.update(overrides)
    return LicenseKeysetSnapshot(**values)  # type: ignore[arg-type]


def _token_expiry() -> datetime:
    """A token expiry valid for issuance and for verification at NOW.

    ``HmacTokenCodec.issue`` checks ``expires_at`` against the real clock,
    while the gate verifies at the fixed ``NOW``; taking the max of the two
    keeps the tokens issuable and unexpired no matter how the machine clock
    sits relative to the fixture date.
    """

    return max(NOW, datetime.now(UTC)) + timedelta(hours=1)


def _authority() -> RealmTokenAuthority:
    return RealmTokenAuthority(
        platform_codec=HmacTokenCodec(
            secret=PLATFORM_SECRET, key_id="k1", token_type="access", audience="platform"
        ),
        tenant_codec=HmacTokenCodec(
            secret=TENANT_SECRET, key_id="k1", token_type="access", audience="tenant"
        ),
    )


def _org_login_snapshot(**overrides: object) -> OrgLoginSnapshot:
    authority = _authority()
    tenant_token = authority.issue_tenant(
        TenantPrincipal(
            tenant_id="tenant-a", operator_id="operator-1", role_names=frozenset()
        ),
        expires_at=_token_expiry(),
    )
    platform_token = authority.issue_platform(
        PlatformPrincipal(subject_id="platform-ops", role_names=frozenset()),
        expires_at=_token_expiry(),
    )
    values: dict[str, object] = {
        "tenant_access_token": tenant_token,
        "expected_tenant_id": "tenant-a",
        "expected_operator_id": "operator-1",
        "platform_access_token": platform_token,
    }
    values.update(overrides)
    return OrgLoginSnapshot(**values)  # type: ignore[arg-type]


def _ingestion_snapshot(**overrides: object) -> IngestionReceiptSnapshot:
    receipt = ArtifactReceipt(
        session_id=uuid4(),
        manifest_digest=hashlib.sha256(b"manifest bytes").hexdigest(),
        manifest_object_key="tenant-a/session/manifest",
        eligibility_reason="application allowed the upload",
        eligibility_policy_version="policy-1",
        completed_at=NOW,
        idempotency_key="complete-1",
    )
    values: dict[str, object] = {
        "receipt": receipt,
        "expected_digest": receipt.digest(),
        "expected_canonical_bytes": receipt.canonical_bytes(),
    }
    values.update(overrides)
    return IngestionReceiptSnapshot(**values)  # type: ignore[arg-type]


def _tenant_isolation_snapshot(**overrides: object) -> TenantIsolationSnapshot:
    values: dict[str, object] = {
        "required_tenant_ids": frozenset({"tenant-a", "tenant-b"}),
        "results": (
            TenantProbeResult(tenant_id="tenant-a", probes_executed=4),
            TenantProbeResult(tenant_id="tenant-b", probes_executed=5),
        ),
    }
    values.update(overrides)
    return TenantIsolationSnapshot(**values)  # type: ignore[arg-type]


def _backup_manifest() -> BackupManifest:
    return BackupManifest(
        components=(
            BackupComponent(
                name="database",
                sha256=hashlib.sha256(DATABASE_BYTES).hexdigest(),
                size_bytes=len(DATABASE_BYTES),
                key_reference="backup/age-key-1",
            ),
            BackupComponent(
                name="objects",
                sha256=hashlib.sha256(OBJECTS_BYTES).hexdigest(),
                size_bytes=len(OBJECTS_BYTES),
            ),
        ),
        tenant_count=2,
        source_version="schema-0006",
        created_at=NOW,
    )


def _recovery_snapshot(**overrides: object) -> RecoveryDrillSnapshot:
    manifest = _backup_manifest()
    target = InMemoryRestoreTarget()

    def restore() -> None:
        target.load(
            {"database": DATABASE_BYTES, "objects": OBJECTS_BYTES},
            tenant_count=2,
            version="schema-0006",
            key_references=("backup/age-key-1",),
        )

    values: dict[str, object] = {
        "manifest": manifest,
        "target": target,
        "restore": restore,
    }
    values.update(overrides)
    return RecoveryDrillSnapshot(**values)  # type: ignore[arg-type]


def _capacity_snapshot(**overrides: object) -> CapacitySnapshot:
    values: dict[str, object] = {
        "declared_minimums": {"concurrent_sessions": 100, "ingest_bytes_per_second": 10},
        "measured": {"concurrent_sessions": 120, "ingest_bytes_per_second": 10},
    }
    values.update(overrides)
    return CapacitySnapshot(**values)  # type: ignore[arg-type]


def _product_profiles(
    count: int = 2, *, provisional: bool = False
) -> ProductProfiles:
    registrations = [
        ProductRegistration(
            product_id="feetforceplate",
            supported_schema_versions=("feetforceplate-client-cloud-default/1",),
        ),
        ProductRegistration(
            product_id="gait-lab",
            supported_schema_versions=("gait-lab-payload/1",),
        ),
    ][:count]
    return ProductProfiles(profiles=tuple(registrations), provisional=provisional)


def _gate() -> ReleaseGate:
    return ReleaseGate(
        [
            DeploymentProfileValidator(),
            BucketPolicyValidator(),
            RlsSnapshotValidator(_rls_contract()),
            LicenseKeysetValidator(),
            OrgLoginValidator(_authority()),
            IngestionReceiptValidator(),
            TenantIsolationValidator(),
            RecoveryDrillValidator(),
            CapacityValidator(),
        ]
    )


def _snapshots() -> dict[str, Any]:
    return {
        "deployment_profile": _profile_document(),
        "bucket_policy": _profile_document(),
        "rls_snapshot": _rls_snapshot_document(),
        "license_keyset": _license_snapshot(),
        "org_login": _org_login_snapshot(),
        "ingestion_receipt": _ingestion_snapshot(),
        "tenant_isolation": _tenant_isolation_snapshot(),
        "backup_recovery": _recovery_snapshot(),
        "capacity": _capacity_snapshot(),
    }


def _evaluate(
    tier: EvidenceTier = EvidenceTier.PRODUCTION,
    *,
    snapshots: dict[str, Any] | None = None,
    profiles: ProductProfiles | None = None,
    release_version: str = "2026.09.0",
) -> ReleaseReceipt:
    return _gate().evaluate(
        snapshots=snapshots if snapshots is not None else _snapshots(),
        tier=tier,
        product_profiles=profiles if profiles is not None else _product_profiles(),
        release_version=release_version,
        now=NOW,
    )


# --------------------------------------------------------------------------
# Gate composition
# --------------------------------------------------------------------------


def test_a_green_gate_approves_and_a_production_receipt_claims_readiness() -> None:
    receipt = _evaluate()

    assert receipt.decision is GateDecision.APPROVED
    assert receipt.production_ready is True
    assert receipt.blocking_failures == ()
    assert receipt.digest() == hashlib.sha256(receipt.canonical_bytes()).hexdigest()


def test_every_validator_and_the_product_profile_check_record_a_conclusion() -> None:
    receipt = _evaluate()
    names = [result.validator for result in receipt.results]

    assert names == sorted(names)
    assert set(names) == {
        "deployment_profile",
        "bucket_policy",
        "rls_snapshot",
        "license_keyset",
        "org_login",
        "ingestion_receipt",
        "tenant_isolation",
        "backup_recovery",
        "capacity",
        "product_profiles",
    }


def test_any_blocking_failure_refuses_the_release() -> None:
    snapshots = _snapshots()
    snapshots["capacity"] = CapacitySnapshot(
        declared_minimums={"concurrent_sessions": 100},
        measured={"concurrent_sessions": 40},
    )

    receipt = _evaluate(snapshots=snapshots)

    assert receipt.decision is GateDecision.REFUSED
    assert receipt.production_ready is False
    assert [result.validator for result in receipt.blocking_failures] == ["capacity"]


def test_a_warning_failure_is_recorded_but_never_blocks() -> None:
    advisory = ValidationResult(
        validator="advisory",
        component="advisory",
        level=FindingLevel.WARNING,
        passed=False,
        reason="advisory finding",
    )
    gate = ReleaseGate([_StubValidator("advisory", advisory)])

    receipt = gate.evaluate(
        snapshots={"advisory": object()},
        tier=EvidenceTier.PRODUCTION,
        product_profiles=_product_profiles(),
        release_version="v1",
        now=NOW,
    )

    assert receipt.decision is GateDecision.APPROVED
    assert receipt.production_ready is True
    assert any(not result.passed for result in receipt.results)


def test_a_missing_snapshot_is_a_blocking_failure() -> None:
    snapshots = _snapshots()
    del snapshots["rls_snapshot"]

    receipt = _evaluate(snapshots=snapshots)

    assert receipt.decision is GateDecision.REFUSED
    assert "rls_snapshot" in [result.validator for result in receipt.blocking_failures]


def test_an_unknown_snapshot_name_is_refused() -> None:
    snapshots = _snapshots() | {"mystery": object()}

    with pytest.raises(ReleaseGateMalformed, match="unknown"):
        _evaluate(snapshots=snapshots)


def test_a_gate_with_no_validators_is_refused() -> None:
    with pytest.raises(ReleaseGateMalformed, match="no validators"):
        ReleaseGate([])


def test_duplicate_validator_names_are_refused() -> None:
    with pytest.raises(ReleaseGateMalformed, match="twice"):
        ReleaseGate([CapacityValidator(), CapacityValidator()])


def test_the_product_profiles_name_is_reserved() -> None:
    with pytest.raises(ReleaseGateMalformed, match="reserved"):
        ReleaseGate([_StubValidator("product_profiles")])


def test_a_crashed_validator_refuses_the_release() -> None:
    gate = ReleaseGate([_StubValidator("boom", raises=RuntimeError("wired wrong"))])

    receipt = gate.evaluate(
        snapshots={"boom": object()},
        tier=EvidenceTier.LOCAL,
        product_profiles=_product_profiles(),
        release_version="v1",
        now=NOW,
    )

    assert receipt.decision is GateDecision.REFUSED
    assert "RuntimeError" in receipt.blocking_failures[0].reason


def test_a_validator_must_return_a_validation_result() -> None:
    gate = ReleaseGate([_StubValidator("liar", returns=True)])

    with pytest.raises(ReleaseGateMalformed, match="ValidationResult"):
        gate.evaluate(
            snapshots={"liar": object()},
            tier=EvidenceTier.LOCAL,
            product_profiles=_product_profiles(),
            release_version="v1",
            now=NOW,
        )


def test_a_validator_may_not_speak_for_another_name() -> None:
    result = ValidationResult(
        validator="someone-else",
        component="c",
        level=FindingLevel.BLOCKING,
        passed=True,
        reason="r",
    )
    gate = ReleaseGate([_StubValidator("real", result)])

    with pytest.raises(ReleaseGateMalformed, match="naming"):
        gate.evaluate(
            snapshots={"real": object()},
            tier=EvidenceTier.LOCAL,
            product_profiles=_product_profiles(),
            release_version="v1",
            now=NOW,
        )


# --------------------------------------------------------------------------
# Built-in validators
# --------------------------------------------------------------------------


class TestDeploymentProfileValidator:
    def test_a_valid_profile_document_passes(self) -> None:
        result = DeploymentProfileValidator().validate(_profile_document(), now=NOW)

        assert result.passed
        assert result.level is FindingLevel.BLOCKING

    def test_a_malformed_profile_document_is_blocking(self) -> None:
        result = DeploymentProfileValidator().validate(
            _profile_document(region="changeme"), now=NOW
        )

        assert result.is_blocking_failure

    def test_the_production_domain_invariant_is_enforced(self) -> None:
        document = _profile_document(environment="production")
        document["ingress"] = {
            "public_base_url": "https://203.0.113.10",
            "port": 443,
            "public_ca": True,
        }

        result = DeploymentProfileValidator().validate(document, now=NOW)

        assert result.is_blocking_failure
        assert "hostname" in result.reason

    def test_a_non_document_snapshot_is_refused(self) -> None:
        with pytest.raises(ReleaseGateMalformed):
            DeploymentProfileValidator().validate("not-a-document", now=NOW)


class TestRlsSnapshotValidator:
    def test_a_compliant_snapshot_passes(self) -> None:
        result = RlsSnapshotValidator(_rls_contract()).validate(
            _rls_snapshot_document(), now=NOW
        )

        assert result.passed

    def test_a_snapshot_that_breaks_the_contract_is_blocking(self) -> None:
        document = _rls_snapshot_document()
        document["tables"][0]["rls_enabled"] = False  # type: ignore[index]

        result = RlsSnapshotValidator(_rls_contract()).validate(document, now=NOW)

        assert result.is_blocking_failure
        assert "rls_disabled" in result.reason

    def test_a_malformed_snapshot_document_is_blocking(self) -> None:
        document = _rls_snapshot_document() | {"dsn": "postgres://u:p@host/db"}

        result = RlsSnapshotValidator(_rls_contract()).validate(document, now=NOW)

        assert result.is_blocking_failure


class TestBucketPolicyValidator:
    def test_a_valid_binding_set_passes(self) -> None:
        result = BucketPolicyValidator().validate(_profile_document(), now=NOW)

        assert result.passed

    def test_raw_immutable_without_versioning_is_blocking(self) -> None:
        document = _profile_document()
        document["buckets"][0]["policy"]["versioning"] = False  # type: ignore[index]

        result = BucketPolicyValidator().validate(document, now=NOW)

        assert result.is_blocking_failure
        assert "versioning" in result.reason

    def test_no_bucket_bindings_at_all_is_blocking(self) -> None:
        document = _profile_document()
        document["buckets"] = []

        result = BucketPolicyValidator().validate(document, now=NOW)

        assert result.is_blocking_failure
        assert "at least one bucket binding" in result.reason


class TestLicenseKeysetValidator:
    def test_a_valid_keyset_snapshot_passes(self) -> None:
        result = LicenseKeysetValidator().validate(_license_snapshot(), now=NOW)

        assert result.passed

    def test_a_revoked_active_key_is_blocking(self) -> None:
        result = LicenseKeysetValidator().validate(
            _license_snapshot(active_key_id="license-2025-a"), now=NOW
        )

        assert result.is_blocking_failure

    def test_non_key_active_material_is_blocking(self) -> None:
        result = LicenseKeysetValidator().validate(
            _license_snapshot(
                public_keys={"license-2026-a": b"not-thirty-two-bytes"}
            ),
            now=NOW,
        )

        assert result.is_blocking_failure
        assert "ed25519" in result.reason


class TestOrgLoginValidator:
    def test_a_clean_login_drill_passes(self) -> None:
        result = OrgLoginValidator(_authority()).validate(
            _org_login_snapshot(), now=NOW
        )

        assert result.passed

    def test_an_expired_tenant_token_is_blocking(self) -> None:
        authority = _authority()
        issued_at = max(NOW, datetime.now(UTC))
        expired = authority.issue_tenant(
            TenantPrincipal(
                tenant_id="tenant-a", operator_id="operator-1", role_names=frozenset()
            ),
            expires_at=issued_at + timedelta(hours=1),
        )
        snapshot = _org_login_snapshot(tenant_access_token=expired)

        result = OrgLoginValidator(authority).validate(
            snapshot, now=issued_at + timedelta(hours=2)
        )

        assert result.is_blocking_failure

    def test_a_mismatched_principal_is_blocking(self) -> None:
        snapshot = _org_login_snapshot(expected_tenant_id="tenant-b")

        result = OrgLoginValidator(_authority()).validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "does not match" in result.reason

    def test_a_platform_token_authenticating_in_the_tenant_realm_is_blocking(
        self,
    ) -> None:
        # A misconfigured "platform" issuer sharing the tenant realm's secret
        # and audience: its token verifies in the tenant realm, which is
        # exactly the separation failure this validator exists to catch.
        crossing_codec = HmacTokenCodec(
            secret=TENANT_SECRET, key_id="k1", token_type="access", audience="tenant"
        )
        crossing = crossing_codec.issue(
            {"sub": "platform-ops", "tenant_id": "tenant-a"},
            expires_at=_token_expiry(),
        )
        snapshot = _org_login_snapshot(platform_access_token=crossing)

        result = OrgLoginValidator(_authority()).validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "tenant realm" in result.reason


class TestIngestionReceiptValidator:
    def test_a_replaying_receipt_passes(self) -> None:
        result = IngestionReceiptValidator().validate(_ingestion_snapshot(), now=NOW)

        assert result.passed

    def test_a_digest_that_does_not_replay_is_blocking(self) -> None:
        snapshot = _ingestion_snapshot(
            expected_digest=hashlib.sha256(b"different bytes").hexdigest()
        )

        result = IngestionReceiptValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "altered" in result.reason

    def test_canonical_bytes_that_differ_are_blocking(self) -> None:
        snapshot = _ingestion_snapshot(expected_canonical_bytes=b"other bytes")

        result = IngestionReceiptValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "canonical bytes differ" in result.reason


class TestTenantIsolationValidator:
    def test_a_complete_leak_free_probe_set_passes(self) -> None:
        result = TenantIsolationValidator().validate(
            _tenant_isolation_snapshot(), now=NOW
        )

        assert result.passed

    def test_a_missing_required_tenant_is_blocking(self) -> None:
        snapshot = _tenant_isolation_snapshot(
            required_tenant_ids=frozenset({"tenant-a", "tenant-b", "tenant-c"})
        )

        result = TenantIsolationValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "no probe result" in result.reason

    def test_any_cross_tenant_leak_is_blocking(self) -> None:
        snapshot = _tenant_isolation_snapshot(
            results=(
                TenantProbeResult(tenant_id="tenant-a", probes_executed=4),
                TenantProbeResult(
                    tenant_id="tenant-b",
                    probes_executed=5,
                    cross_tenant_leaks=("probe:read-visible-rows",),
                ),
            )
        )

        result = TenantIsolationValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "leakage" in result.reason

    def test_a_tenant_with_zero_probes_is_blocking(self) -> None:
        snapshot = _tenant_isolation_snapshot(
            results=(
                TenantProbeResult(tenant_id="tenant-a", probes_executed=4),
                TenantProbeResult(tenant_id="tenant-b", probes_executed=0),
            )
        )

        result = TenantIsolationValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "no isolation probes ran" in result.reason

    def test_ambiguous_duplicate_results_are_blocking(self) -> None:
        snapshot = _tenant_isolation_snapshot(
            results=(
                TenantProbeResult(tenant_id="tenant-a", probes_executed=4),
                TenantProbeResult(tenant_id="tenant-a", probes_executed=2),
                TenantProbeResult(tenant_id="tenant-b", probes_executed=5),
            )
        )

        result = TenantIsolationValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "twice" in result.reason


class TestRecoveryDrillValidator:
    def test_a_successful_drill_passes(self) -> None:
        result = RecoveryDrillValidator().validate(_recovery_snapshot(), now=NOW)

        assert result.passed

    def test_a_drill_that_fails_re_verification_is_blocking(self) -> None:
        manifest = _backup_manifest()
        target = InMemoryRestoreTarget()

        def restore() -> None:
            target.load(
                # Same length as DATABASE_BYTES, different content, so the
                # drill fails at digest re-evaluation rather than at size.
                {"database": b"x" * len(DATABASE_BYTES), "objects": OBJECTS_BYTES},
                tenant_count=2,
                version="schema-0006",
                key_references=("backup/age-key-1",),
            )

        snapshot = RecoveryDrillSnapshot(
            manifest=manifest, target=target, restore=restore
        )

        result = RecoveryDrillValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "digest mismatch" in result.reason

    def test_a_drill_against_a_non_empty_target_is_blocking(self) -> None:
        target = InMemoryRestoreTarget()
        target.load(
            {"database": DATABASE_BYTES},
            tenant_count=2,
            version="schema-0006",
            key_references=("backup/age-key-1",),
        )

        def restore() -> None:
            return None

        snapshot = RecoveryDrillSnapshot(
            manifest=_backup_manifest(), target=target, restore=restore
        )

        result = RecoveryDrillValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "empty target" in result.reason


class TestCapacityValidator:
    def test_declared_capacity_met_or_exceeded_passes(self) -> None:
        result = CapacityValidator().validate(_capacity_snapshot(), now=NOW)

        assert result.passed

    def test_a_measurement_below_the_declared_minimum_is_blocking(self) -> None:
        snapshot = _capacity_snapshot(
            measured={"concurrent_sessions": 80, "ingest_bytes_per_second": 10}
        )

        result = CapacityValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "below the declared minimum" in result.reason

    def test_an_unmeasured_dimension_is_blocking(self) -> None:
        snapshot = _capacity_snapshot(measured={"concurrent_sessions": 120})

        result = CapacityValidator().validate(snapshot, now=NOW)

        assert result.is_blocking_failure
        assert "never measured" in result.reason


# --------------------------------------------------------------------------
# Product profiles
# --------------------------------------------------------------------------


def test_a_single_non_provisional_product_profile_refuses_the_release() -> None:
    receipt = _evaluate(profiles=_product_profiles(count=1))

    assert receipt.decision is GateDecision.REFUSED
    assert "product_profiles" in [
        result.validator for result in receipt.blocking_failures
    ]


def test_a_single_provisional_product_profile_is_released() -> None:
    receipt = _evaluate(profiles=_product_profiles(count=1, provisional=True))

    assert receipt.decision is GateDecision.APPROVED


def test_two_product_profiles_are_released_without_a_provisional_mark() -> None:
    receipt = _evaluate(profiles=_product_profiles(count=2))

    assert receipt.decision is GateDecision.APPROVED


def test_product_profiles_require_at_least_one_profile() -> None:
    with pytest.raises(ReleaseGateMalformed, match="at least one product profile"):
        ProductProfiles(profiles=(), provisional=True)


def test_product_profiles_refuse_duplicate_product_ids() -> None:
    registration = ProductRegistration(
        product_id="feetforceplate",
        supported_schema_versions=("feetforceplate-client-cloud-default/1",),
    )

    with pytest.raises(ReleaseGateMalformed, match="unique"):
        ProductProfiles(profiles=(registration, registration))


# --------------------------------------------------------------------------
# Receipt redaction, tiers, and reproducibility
# --------------------------------------------------------------------------


@pytest.mark.parametrize("tier", [EvidenceTier.LOCAL, EvidenceTier.SEED])
def test_local_and_seed_tiers_never_claim_production_readiness(
    tier: EvidenceTier,
) -> None:
    receipt = _evaluate(tier=tier)

    assert receipt.decision is GateDecision.APPROVED
    assert receipt.production_ready is False


def test_a_refused_production_receipt_is_not_production_ready() -> None:
    snapshots = _snapshots()
    snapshots["capacity"] = CapacitySnapshot(
        declared_minimums={"concurrent_sessions": 100},
        measured={"concurrent_sessions": 40},
    )

    receipt = _evaluate(snapshots=snapshots)

    assert receipt.evidence_tier is EvidenceTier.PRODUCTION
    assert receipt.production_ready is False


def test_serialization_carries_the_whitelist_only() -> None:
    document = _evaluate().to_document()

    assert set(document) == {
        "schema_version",
        "decision",
        "evidence_tier",
        "release_version",
        "evaluated_at",
        "validators",
    }
    for entry in document["validators"]:
        assert set(entry) == {"validator", "component", "passed", "level"}


def test_a_document_round_trips_through_canonical_bytes() -> None:
    receipt = _evaluate()

    parsed = ReleaseReceipt.from_document(receipt.to_document())

    assert parsed.canonical_bytes() == receipt.canonical_bytes()
    assert parsed.digest() == receipt.digest()
    assert parsed.decision is receipt.decision
    assert parsed.production_ready == receipt.production_ready
    assert all(
        result.reason == REDACTED_REASON for result in parsed.results
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("password", "hunter2"),
        ("dsn", "postgresql://u:p@host/db"),
        ("bucket_name", "raw-bucket"),
        ("api_endpoint", "https://cloud.example.test"),
        ("customer_data", {"who": "someone"}),
    ],
)
def test_a_sensitive_field_is_refused(field: str, value: object) -> None:
    document = _evaluate().to_document() | {field: value}

    with pytest.raises(ReleaseGateMalformed, match="redacted receipt"):
        ReleaseReceipt.from_document(document)


def test_an_unknown_field_is_refused() -> None:
    document = _evaluate().to_document() | {"future_field": 1}

    with pytest.raises(ReleaseGateMalformed, match="unknown field"):
        ReleaseReceipt.from_document(document)


def test_an_unsupported_schema_version_is_refused() -> None:
    document = _evaluate().to_document() | {"schema_version": "techflex-release-receipt/9"}

    with pytest.raises(ReleaseGateVersionUnsupported):
        ReleaseReceipt.from_document(document)


def test_a_receipt_cannot_contradict_its_findings() -> None:
    blocking = ValidationResult(
        validator="v",
        component="c",
        level=FindingLevel.BLOCKING,
        passed=False,
        reason="r",
    )

    with pytest.raises(ReleaseGateMalformed, match="contradict"):
        ReleaseReceipt(
            decision=GateDecision.APPROVED,
            evidence_tier=EvidenceTier.PRODUCTION,
            release_version="v1",
            evaluated_at=NOW,
            results=(blocking,),
        )


def test_a_receipt_must_record_conclusions() -> None:
    with pytest.raises(ReleaseGateMalformed, match="proves nothing"):
        ReleaseReceipt(
            decision=GateDecision.APPROVED,
            evidence_tier=EvidenceTier.PRODUCTION,
            release_version="v1",
            evaluated_at=NOW,
            results=(),
        )


def test_canonical_bytes_and_digest_are_reproducible() -> None:
    first = _evaluate()
    second = _evaluate()

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.digest() == second.digest()


def test_a_different_release_version_changes_the_digest() -> None:
    assert _evaluate().digest() != _evaluate(release_version="2026.10.0").digest()
