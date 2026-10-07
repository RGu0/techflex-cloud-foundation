# Tenant data and application subject records

RAY-553 R2 separates the foundation contract from the retained application
subject synchronization requirements. This guide describes existing public
mechanisms; it defines no subject DTO, HTTP route, search index or cursor.

## The trusted tenant boundary

Derive `TenantContext.from_request` from an authenticated
`TrustedRequestContext`. Do not let a payload, query parameter or offline
record choose the authorization tenant. A context is not a replacement for
application permission checks on the authenticated subject.

Run data-plane work inside `TenantDataPlane.scope`. A closed session refuses
connection access. The pool adapter sets the tenant and clears it before
release; a leaked context is an error. `CompositeTenantReference.ensure_within`
rejects references belonging to another tenant, independently of SQL filters.
Production adapters must bind real transactions and tenant settings safely;
the reference pool is not evidence of a deployed PostgreSQL configuration.

`RlsContract` validates an introspection snapshot against declared tables,
roles and policies. A successful snapshot check does not create policies or
prove that the deployed role uses them. Obtain current database facts through
authorized tooling and retain redacted role/policy evidence.

See [the public implementation](../../src/techflex_cloud_foundation/tenancy.py),
`tests/test_tenancy.py` and [the API reference](../api-reference.md).
These reference tests do not prove a live database deployment; application
database verification must be recorded separately.

## Idempotency and protected identity responsibilities

`IdempotencyGuard` uses the open tenant scope, idempotency key and canonical
request digest to resolve replay or reject a changed request. Its natural-key
claim prevents duplicate effects even after the request-record TTL. Bind
`ConsistencyStore` to the application's durable transaction; do not treat the
in-memory store as atomic deployed subject creation. See
[consistency.py](../../src/techflex_cloud_foundation/consistency.py) and
`tests/test_consistency.py`.

The package does not expose a subject identity envelope, ProtectedIdentifier
model or name-search index. Its local sealed-store/keystore encryption is not
an institution identity database contract. Applications must retain their
existing identity protection, tenant-bound encryption context, disclosure
permissions and key lifecycle in their own adapters. No public name index,
identity plaintext logging, new encryption format or ProfileValue state
semantics are approved by this guide.

## Application records and synchronization

Subject identifiers, protected identity fields, ProfileValue state semantics,
consents, tags, institution-number uniqueness and conflict resolution belong
to the application. Reuse trusted tenant scoping for all of them, including
search indexes and outbox events. A UUID alone is not authorization.

The library supplies no incremental cursor, subject repository or name-search
scheme. Applications must define ordering, paging consistency, updates and
deletions, retention and protected-field disclosure before publishing those
interfaces. This guide does not approve a plaintext name index, invent a new
route namespace or change the existing business GET/PATCH requirements.
Do not silently replace a locally created subject UUID on an offline conflict
or treat a matching institution number as permission to merge identities.

Business acceptance remains separate: finalized subject/label/search contracts,
A-to-B incremental synchronization in integration, and duplicate offline-record
conflict handling require actual application implementation and deployment
proof. Foundation documentation or an R2 library completion receipt proves
none of those business effects.
