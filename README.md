# Techflex Cloud Foundation

Private reusable cloud, authorization, security, and reliable-operation
foundation for Techflex applications. The public Python API is exposed only
from the `techflex_cloud_foundation` package.

**Consumers start here: [docs/getting-started.md](docs/getting-started.md).**

This repository is governed through Linear delivery scopes and GitHub pull
requests. Application-specific adapters, business schemas, credentials, and
customer data do not belong here. Public material that confirmed requirements
share across environments — CA certificates, license public keys, and default
endpoint configuration — may be vendored under `config/`; private keys,
secrets, and customer data remain prohibited.

## Public cloud defaults

`config/public-cloud-defaults/` vendors the shared default cloud configuration
first proven by FeetForcePlate (schema
`feetforceplate-client-cloud-default/1`):

- `cloud-default.json` selects channel `integration` with
  `api_base_url` pointing at the integration entrypoint;
- `cloud-ca.pem` is the private root CA for that channel;
- `license-public.key` is the raw 32-byte license verification public key.

This is the **integration** channel default, not a production entrypoint: an
integration IP, a private/self-signed CA, and a nonstandard port do not
constitute production ingress (RAY-341 invariants). Evidence currently comes
from a single consumer (FeetForcePlate), so the bundle is **provisional**
until a second consumer confirms it.

The same bundle also ships inside the wheel as package resources, so a
consuming application can develop, test, and run seed-stage integrations with
zero local setup:

```python
from techflex_cloud_foundation import load_default_cloud_config

default = load_default_cloud_config()          # channel="integration"
default.api_base_url                          # integration entrypoint
default.ca_bundle_pem                         # PEM bytes for TLS verification
default.license_public_key                    # raw 32-byte license key
```

Only vendored channels resolve; an unknown channel raises
`CloudConfigChannelUnknown` rather than guessing an endpoint. An application
moving to its own environment validates its own document through
`parse_cloud_default_config` — the same validator the vendored bundle uses —
and supplies its own resource bytes. Production material is never vendored
into this library.

## Platform deployment profiles (CP-01)

`parse_deployment_profile` validates a versioned deployment profile document
(`techflex-platform-deployment/1`) covering environment, region, public
ingress, database roles, KMS reference, logical-bucket mappings, retention
tiers, and registered products. The schema carries **references, never
secrets**: databases, signing keys, and cloud credentials are named through
`SecretRef` (`env` / `file` / `kms` provider + locator); an inline field whose
name implies secret material is refused, as are placeholder values, unknown
fields, and unknown schema versions. Production ingress must be a public-CA
hostname on 443 — an IP literal, private CA, or temporary port is an
integration channel, never production ingress. Logical bucket roles share a
physical bucket only when encryption, versioning, and retention policies are
identical, and `raw-immutable` buckets must keep versioning on. A validated
`DeploymentProfile` is immutable and serializes to a reproducible canonical
form whose complete SHA-256 `digest()` can anchor snapshot receipts. Concrete
deployment values (cloud account, domain, certificate, KMS key, physical
bucket names) stay with the deploying application and are never vendored here.

## Artifact ingestion plane (CP-06)

`IngestionService` is the business-neutral receive skeleton for uploaded
artifacts: `begin_session` → `put_part`… → `list_parts`/`status` → `complete`.
Parts stream through the content-verified `ImmutableObjectStore`; same content
under the same slot replays idempotently, while different content conflicts
and quarantines the slot — originals are never silently overwritten. A session
pins one payload schema and unknown versions are refused. Object keys are
derived server-side from the trusted `IngestionPrincipal` tenant and session
id; request payloads never select tenant, bucket, or key. Completion verifies
the `ArtifactManifest` digest, requires all parts present and unquarantined,
and requires an application-made `EligibilityDecision` — the foundation never
decides whether a payload is VALID or INVALID. Only then does it issue the
final immutable `ArtifactReceipt` (canonical bytes + complete SHA-256
`digest()`), which completion replays under its idempotency key. Session
persistence sits behind the `IngestionSessionStore` protocol; the shipped
`InMemoryIngestionStore` covers tests and integration runs, production binds
PostgreSQL in the application layer.

## Gateway request validation (CP-02)

`RequestValidator` is the framework-neutral server-side counterpart to the
token contracts: one pipeline turns an Authorization header into a
`TrustedRequestContext` — Bearer parsing, signature/audience/key-id/expiry
verification through `HmacTokenCodec`, payload size caps, and token-bucket
rate limiting keyed on the authenticated principal (`RateLimitStore` protocol
with an in-memory reference; production binds shared state). The tenant
invariant is enforced structurally: tenant comes only from token claims, and
a payload naming a different tenant raises `GatewayTenantMismatch` — the
payload never selects the tenant. Every failure renders as a stable
`ErrorEnvelope` (code + message + correlation id, plus the disposition pair
`retryable`/`action` — the action set is the product's own, registered in an
`ErrorActionCatalog`); a well-formed inbound correlation id is kept, anything
else is replaced rather than trusted.
Product routing, DTOs, and audience registration stay with the application.
## Logical bucket catalog and presigned uploads (CP-07)

`BucketCatalog` is the execution layer over a profile's logical-bucket
mappings: it resolves each `BucketRole` binding into a queryable catalog
(unknown roles are refused, never guessed), derives object keys
server-side, and routes immutable publishes through the content-verified
`ImmutableObjectStore` — the same key with different content conflicts,
and originals are never silently overwritten. Object keys are
content-addressed (`role/tenant/artifact/digest`); the tenant id comes
only from the trusted server-side context, the client never chooses
bucket, tenant, or final key, and keys carry opaque identifiers only —
names, archive numbers, and other guessable business identifiers never
appear in a key. `PresignedGrantAuthority` issues and consumes
`PresignedUploadGrant`s so a client can be narrowed to exactly one
artifact without long-term bucket credentials: each grant is HMAC-signed
(signature compared before any claim is trusted), bound to digest, size,
and purpose, short-lived (a bounded TTL), and single-use — expiry,
mismatch, tampering, or replay is refused. Grant consumption sits behind
the `PresignedGrantStore` protocol with an `InMemoryPresignedGrantStore`
reference; provider adapters (Aliyun OSS, S3) stay in the application
layer.
## Product registry and compatibility decisions (CP-12)

`parse_product_catalog` validates a versioned catalog document
(`techflex-product-catalog/1`) into an immutable `ProductCatalog` of
`ProductRecord`s: each record names its supported client/protocol/schema
version sets, declares business adapter **entrypoints by reference** (the
registry hosts entrypoint names, never algorithms), and carries the migration
order and minimum versions that bound what a client may declare. Unknown
schema versions, unknown fields, and duplicate product ids are refused, never
guessed. `ProductRegistry.decide` turns a `ClientDeclaration`
(product/protocol/schema/config versions — every field required) into an
explicit, immutable `CompatibilityDecision`: `COMPATIBLE`,
`MIGRATION_REQUIRED` (carrying the migration path or minimum version),
`REJECTED`, or `QUARANTINED`. Unregistered products and unsupported versions
are always answered explicitly — the registry never silently downgrades.
Version semantics (which version is older, and whether an unsupported version
is rejected or quarantined) are injected through the
`ProductCompatibilityPolicy` protocol; no product-specific rule is hardcoded
here.

## Tenant data plane and RLS contract (CP-08)

`TenantContext.from_request` derives the data-plane tenant from an already
authenticated `TrustedRequestContext` and from nothing else — a payload,
query parameter, or bare tenant string cannot open a scope.
`TenantDataPlane.scope` binds that tenant on a pooled connection for the life
of the work and, on the way out, clears it and **verifies** the clear: a
driver whose reset silently no-ops would otherwise hand the next borrower a
stale `SET`, so a connection that still reports a tenant raises
`TenantContextLeaked` and is withheld from the pool rather than returned. The
session is unusable once its scope closes. `CompositeTenantReference` carries
its tenant alongside the entity id, so a child row can refuse a parent in
another tenant before the query is built — RLS is not the only boundary.
Connections sit behind the `TenantConnection`/`TenantConnectionPool`
protocols with in-memory references; a real pool binds in the deployment.

`RlsContract` states what a compliant deployment must show — row-level
security enabled *and* forced on each required table, every policy
constraining rows by the contract's tenant setting (permissive policies are
OR-ed, so one loose clause widens access), and an application role that is
neither superuser, nor `BYPASSRLS`, nor the owner of a table it must not
escape. It is evaluated against a `DatabaseIntrospectionSnapshot` of catalog
facts rather than a live connection, so the same contract runs in tests, in
CI with no database, and in a deployment's readiness gate through an adapter
that reads `pg_catalog`. `parse_introspection_snapshot` refuses any field the
contract does not know, which is what keeps a DSN or password out of a
snapshot and out of any receipt built from one. A table outside the contract
is not judged: product schemas, their SQL, and their RLS policies stay with
the product. The textual check proves a deployment's policies are written
against the bound tenant setting; proving a predicate *sufficient* needs
cross-tenant tests against a real database and belongs to that deployment's
own acceptance.

## Idempotency, Outbox and reconciliation (CP-08)

`IdempotencyGuard.run` executes a command at most once per key. The same key
with the same request digest replays the stored response without running the
operation; the same key with a *different* digest is an `IdempotencyConflict`,
never a second effect. Underneath sits a second layer that outlives the first:
the idempotency record has a TTL, because keeping every key forever is not
affordable, but the natural uniqueness of the thing the command created does
not expire. A retry arriving after the TTL claims the same natural key, finds
the original effect, and replays it rather than making a duplicate.

`Outbox.append` requires an open `TenantScopedSession` and refuses an event
for any tenant other than the bound one — the enforceable half of "the event
commits with the state change", since an append that cannot name a live scope
has no transaction to join. `OutboxDispatcher` delivers at least once and
holds an aggregate's later versions behind a failed earlier one: delivering
versions out of order would show a consumer a later state before the one it
replaces, which is worse than delivering nothing yet. Other aggregates keep
moving. Because delivery is at least once by construction — a handler that
succeeded and a dispatcher that crashed before marking it published look
identical from the store — `DeduplicatingConsumer` is where a repeat stops
being a repeated effect.

`ArtifactIndexEntry.from_receipt` indexes a completed CP-06 session, committing
to that exact `ArtifactReceipt` rather than minting a second identity.
`object_verified` and `event_published` start false and are set by
observation: a receipt issued at one moment does not say the object is still
there now or that the event ever left. `ReceptionState` has exactly three
members — `RECORDED`, `OBJECT_VERIFIED`, `INGESTED` — and deliberately none
for a finished analysis or report, because a state that could express those
would let `INGESTED` be read as either.

`PartialFailureReconciler` decides what to do when the three writers disagree.
An unpublished event is `REPAIRABLE`: the outbox still holds it. A missing
object is `QUARANTINE`, because the row asserts an artifact whose verified
bytes are gone and writing a replacement would manufacture agreement rather
than restore it; an event already published for a missing object is worse
still, and says so. An object with no row is `REPAIRABLE` — nothing references
it. None of these verdicts is an authorization: reclaiming or deleting
anything still takes an explicit `DeletionDecision` the application makes.

Both stores are protocols with in-memory references. Production binds the
`operations` schema, where the natural-key claim is an insert against a unique
constraint inside the command's own transaction.

## Privacy-safe telemetry and recovery drills (CP-10)

`SafeFieldCatalog` is the whitelist a security event is built against: a
context field can appear in a `SecurityEvent` only when the catalog declared
it, and a field whose name even contains an identity, token, credential,
raw-payload, or object-key marker can never be declared — so no event can
carry one. Secret-like values are refused as well, and events are versioned:
an unknown event version raises `ObservabilityVersionUnsupported` rather
than being guessed at.

`SliThreshold` is a validated alerting contract — metric name, evaluation
window, comparison direction, and bounds. A contradictory threshold (a lower
bound above the upper bound, or a bound the direction does not use) is
refused at construction instead of being silently half-applied. Which SLIs
exist, and what pages whom, stays with the product.

`EventAuditAnchor` anchors an event stream into the tamper-evident
`ChainedAppendLog` from `local_audit`, so the whole stream re-verifies end
to end and `head_digest` is the anchor stored outside the log directory.

`BackupManifest` commits to what a backup must re-prove — component digests
and sizes, tenant count, source version, and the old key references —
without carrying the payloads. `RestoreVerifier.run_drill` refuses a
non-empty target, runs the application's restore step, then **re-evaluates
every component digest against the restored bytes** and re-checks the tenant
count, version, and key references before issuing a `RecoveryReceipt`; any
shortfall raises `RecoveryVerificationFailed` with every failure listed. A
component declared in the manifest but never re-digested fails: "the backup
exists" is not a recovery. Storage sits behind the `RestoredTargetProbe`
protocol with an `InMemoryRestoreTarget` reference.
## Device trust and hardware leases (CP-05)

`DeviceTrustService` keeps three entities deliberately separate — a
`ClientInstallation` (one installed software instance), a `Terminal` (an
operator-facing station), and a `MeasurementDevice` (a physical instrument) —
and an installation never owns a License: entitlement lives in `entitlement`
and is only referenced by product policy, never held here. Installation
credentials are versioned and only their SHA-256 fingerprints are stored,
never the secrets. `rotate_credential` requires the current credential and
refuses the previous version immediately; `revoke_credential` takes effect
the moment it is recorded. Every refusal — unknown installation, revoked
credential, wrong fingerprint — raises the same `DeviceTrustAccessDenied`
with the same message, so the boundary is not an enumeration oracle.

`HardwareLeaseService` runs the acquire/renew/release state machine: an
asset holds at most one effective lease at any moment and concurrent
acquisition is refused atomically by the store; every lease expires against
explicitly injected `now`, an expired or released lease can never be
renewed, and release frees the asset at once. Heartbeats record the
reception timestamp and the declared client/schema versions;
`HeartbeatSummary` and `version_status_directory` expose a queryable status
catalog that carries no credential material and no platform-reported
identifiers.

Platform UUIDs and RSSI readings are advisory hints, never a physical
identity. `bind_device` accepts a `DeviceIdentityClaim` only through the
product-injected `DeviceAttestationProvider` — an attestation that merely
echoes the platform UUID is refused — and the injected
`DeviceCombinationPolicy` decides which device may bind which installation.
Device recognition, calibration, and allowed-combination rules stay with the
product; unknown claim versions are refused, never guessed. Storage sits
behind the `DeviceTrustStore` protocol with an in-memory reference, so CI
never starts a real database.
## License lifecycle (CP-04)

`LicenseLifecycleService` is the server-side issuance and control plane for
licenses: `issue` stocks a license (`ISSUED`), `activate` consumes its
one-time serial and binds tenant, account, and hardware, `renew` extends the
validity window of an `ACTIVE` license, `suspend`/`resume` pause and restore
it, and `revoke` is terminal — a revoked license never moves again, and a
replacement is a new `license_id`, not this record moved backwards. The
lifecycle is a whitelist: every unlisted transition raises
`LicenseTransitionRejected`. Each accepted step appends one immutable
`LicenseLifecycleEvent` (reason plus an explicitly injected `occurred_at`;
nothing reads a real clock) and re-signs the license document. Activation
serials are single-use: a re-presented serial raises `LicenseReplayRejected`,
whether the replay comes from the same account or a different one.
`LicenseDocument`s are ed25519-signed under a versioned `LicenseKeyset`
(active key id plus revoked key ids); a document naming an unknown or revoked
key id is refused, never guessed. A license only authorizes — the module
neither accepts nor emits data-key material. SKU, term, feature set, and
offline grace are product policy injected through the `LicensePolicy`
protocol; `offline_access` answers the grace-aware expiry question
(`ACTIVE` and inside `valid_until + grace`). Persistence sits behind the
`LicenseLifecycleStore` protocol with an `InMemoryLicenseLifecycleStore`
reference; production binds PostgreSQL in the application layer. Client-side
verification stays in `entitlement.py`; this module is the server boundary.

## Cloud release gate and validation receipts (CP-11)

`ReleaseGate` composes named validators over **snapshot evidence** — a
deployment profile document, an RLS introspection snapshot, captured login
tokens, capacity measurements — and refuses the release when any blocking
finding fails. It never connects to a cloud, so the same gate runs in unit
tests, in CI with no infrastructure, and in a deployment's release pipeline.
A warning-level failure is recorded on the receipt but never blocks; a
missing snapshot, a validator that crashes, and a single product profile
that is not explicitly marked provisional (`ProductProfiles`) are all
blocking — absent evidence is never a pass.

The built-in validators delegate to the existing contracts rather than
re-deciding them: `parse_deployment_profile` (production ingress invariants
included), `RlsContract` over an introspection snapshot, `BucketCatalog`
bucket-policy construction (raw-immutable versioning, role uniqueness),
`LicenseKeyset` (key id uniqueness, active key unrevoked and resolvable as
valid ed25519 material), `RealmTokenAuthority` (the login drill's tenant
token verifies for the expected operator and a platform-realm token is
refused in the tenant realm), `ArtifactReceipt` digest/canonical-bytes
replay, tenant isolation probe results (every required tenant probed, any
cross-tenant leak blocking), `RestoreVerifier` recovery drills — a backup
merely existing is not a recovery — and declared-versus-measured capacity
minimums.

The `ReleaseReceipt` is redacted by construction: serialization carries a
field whitelist only (gate decision, evidence tier, per-validator
conclusions, time, version). Credentials, endpoints, bucket names, DSNs,
and customer data have no field to land in, a document carrying an unknown
field is refused, and free-form reasons are never serialized.
`production_ready` is structural — true only for a `production`-tier
receipt with no blocking finding — so `local` and `seed` receipts can never
claim production readiness. Canonical bytes and a complete SHA-256
`digest()` make a receipt reproducible evidence rather than a claim.
## Platform operations console (CP-09)

`OperationsConsole` is the platform-side control plane skeleton: immutable
`OperationsCommand`s over four neutral object kinds — organizations/accounts,
licenses, terminals/devices, product registrations — each with a command id,
an `iam.PlatformPrincipal` operator, a target reference, text parameters, and
an explicitly injected `issued_at`. Commands are value objects, never
persisted: each executes at most once (a retry is a new command), and every
execution appends one immutable `OperationsAuditRecord` — who, when, on what,
with which outcome — carrying the command's SHA-256 digest rather than its
parameters, so secret material never enters the audit trail. Platform and
tenant identities stay separate: a `TenantPrincipal` cannot issue a command,
request a grant, or publish config, and the console never consults tenant
roles.

Destructive operations are gated by short-lived, single-use
`SensitiveAccessGrant`s. Which purposes are sensitive is injected policy
(`command_purpose(CLOSE, LICENSE)` → `"license.close"`); a grant must match
the command's purpose, holder, and target exactly, and a grant that is
missing, expired, already consumed, or issued for anything else is refused —
with a `REFUSED` audit record left behind, because an attempt on a sensitive
operation is itself a security event.

Configuration releases are ed25519-signed under a versioned `OperationsKeyset`
and monotonically forward: `publish_config` refuses any release at or below
the published version for that config id (`OperationsDowngradeRejected` —
releases never roll back), and `verify_config` checks the signature before
any claim. `validate_upgrade_order` decides a declared upgrade against the
product registry's own facts — supported schema versions, minimum versions,
and migration order — answering `ORDERED` with the full path (including
undeclared intermediate steps), or an explicit `REJECTED_INCOMPATIBLE` /
`REJECTED_OUT_OF_ORDER` decision; nothing is silently reordered. Storage sits
behind the `OperationsStore` protocol with an `InMemoryOperationsStore`
reference; production binds a database in the application layer.

## Private package use

Applications consume a released, versioned `techflex-cloud-foundation` wheel
and implement their own business adapters. They must not copy or alter the
foundation’s transport, authorization, credential, trust, or operation-store
implementation. Use `./dev test`, `./dev lint`, and `./dev build` (or
`./dev.ps1 <action>` on Windows) for the locked quality gates.

The build creates only temporary artifacts and redacted release evidence:
revision, dependency inventory, checksums, and benchmark summaries. It never
records credentials, activation material, customer data, or raw frames.
