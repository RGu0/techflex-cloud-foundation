# Guide: License, Entitlement & Data Lifecycle

Modules: `entitlement`, `lifecycle`, `provenance`.
Reference tests: `tests/test_public_contracts.py`, `tests/test_lifecycle.py`,
`tests/test_provenance.py`.

## When to use

Gating features by license, deciding whether an artifact may upload and how
long it is retained, and recording why a decision was made.

## 1. Trust bundles

The root of license trust is a signed `TrustBundle`: signing keys, revocations,
and policy flags, signed by an Ed25519 root. Verification requires the root
signature and a monotonic revision — a bundle older than `minimum_revision`
is refused, so rollback attacks fail closed
(`test_trust_bundle_requires_root_signature_and_monotonic_revision` in
`tests/test_public_contracts.py`):

```python
from techflex_cloud_foundation import TrustBundleVerifier

bundle = TrustBundleVerifier(root_public_key_bytes).verify(signed, minimum_revision=2)
```

## 2. Entitlement decisions

`EntitlementResolver` (application-implemented protocol) resolves a license
into an immutable, application-scoped `EntitlementDecision`; capability
checks are `decision.allows("screening.start")`
(`test_entitlement_decision_is_immutable_and_application_scoped`).
`LicenseRecord`/`LicenseLifecycle` model the state machine
(`LicenseState`; `activate` binds tenant + account + hardware).

Boundary (RAY-341): the library owns the *mechanism*; SKU, pricing, default
terms, and which capabilities exist are product policy, injected by the
application.

## 3. Upload eligibility & retention

`UploadEligibilityPolicy` declares purposes with default retention classes;
duplicate purpose names are refused
(`test_duplicate_purposes_are_refused` in `tests/test_lifecycle.py`):

```python
from datetime import UTC, datetime

from techflex_cloud_foundation import Purpose, RetentionClass, UploadEligibilityPolicy

policy = UploadEligibilityPolicy(
    purposes=(
        Purpose(name="analysis", default_retention=RetentionClass.STANDARD),
        Purpose(name="diagnostics", default_retention=RetentionClass.EPHEMERAL, upload_allowed=False),
    ),
    policy_version="policy/1",
)
decision = policy.evaluate("diagnostics", decided_at=datetime.now(UTC))
assert not decision.allowed          # purpose forbids upload
assert decision.policy_version == "policy/1"
```

## 4. Deletion is a decision with a receipt

Deletion requires an explicit `DeletionDecision` (reason, decider, timestamp,
policy version); `DeletionReceipt.for_decision` binds the receipt to the
decision's digest (`test_deletion_requires_explicit_decision_and_produces_bound_receipt`).
A server confirmation never by itself authorizes deletion — retention,
consent, legal hold, and audit come first (RAY-341 invariants).

## 5. Provenance & layered validity

`ProvenanceRecord` records a derived artifact's lineage: source digests,
transform + version, and layered `ValidityEvidence`. Unevaluated layers
cannot carry an adjudication, and evaluated layers must
(`src/techflex_cloud_foundation/provenance.py` invariants, exercised in
`tests/test_provenance.py`). Adjudication ("who/what decided, why") is kept
apart from the raw facts.

## Invariants

- License authorizes; it never participates in data key derivation.
- Trust bundle revisions are monotonic; older bundles fail closed.
- Tenant/operator/device/license identities are never interchangeable.
- Eligibility, retention, and deletion are separate explicit decisions, each
  with a policy version and a digest-bound receipt.
