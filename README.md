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
`ErrorEnvelope` (code + message + correlation id); a well-formed inbound
correlation id is kept, anything else is replaced rather than trusted.
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

## Private package use

Applications consume a released, versioned `techflex-cloud-foundation` wheel
and implement their own business adapters. They must not copy or alter the
foundation’s transport, authorization, credential, trust, or operation-store
implementation. Use `./dev test`, `./dev lint`, and `./dev build` (or
`./dev.ps1 <action>` on Windows) for the locked quality gates.

The build creates only temporary artifacts and redacted release evidence:
revision, dependency inventory, checksums, and benchmark summaries. It never
records credentials, activation material, customer data, or raw frames.
