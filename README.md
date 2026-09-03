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

## Private package use

Applications consume a released, versioned `techflex-cloud-foundation` wheel
and implement their own business adapters. They must not copy or alter the
foundation’s transport, authorization, credential, trust, or operation-store
implementation. Use `./dev test`, `./dev lint`, and `./dev build` (or
`./dev.ps1 <action>` on Windows) for the locked quality gates.

The build creates only temporary artifacts and redacted release evidence:
revision, dependency inventory, checksums, and benchmark summaries. It never
records credentials, activation material, customer data, or raw frames.
