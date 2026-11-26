# Server ingestion and repositories

RAY-830 R3 (`ingestion-repository`) moves the FeetForcePlate cloud's session
ingestion path into `techflex_cloud_foundation.server`. Nothing here is exported
from the package root; import from the modules. It needs the `server` extra
(`asyncpg`) only when a PostgreSQL repository is built.

## Modules

| Module | Role |
|---|---|
| `ingestion_service` | `IngestionService`: create session, put segment, list segments, complete session with a manifest, status. |
| `principal` | `IngestionPrincipal`: who is uploading (terminal or tenant access token), and what they may do. |
| `repository` | `InMemoryPlatformRepository`, the reference adapter for contract and fault tests, and the shared record types. |
| `postgres` | `PostgresPlatformRepository` and `tenant_transaction`: the production adapter, run through tenant-scoped transactions so row-level security applies. |
| `subject_service` | Subject and consent handling with `IdentityProtector`. |
| `auth`, `access_auth` | Terminal and tenant access-token issuers and verifiers. |
| `segment_store` | `SegmentObjectStore`: segment and manifest publication over any `ImmutableObjectStore`. |
| `ingestion_contracts` | Registry validation, explicit legacy compatibility selection, lossless original JSON and registry-derived OpenAPI schemas. |

## Registered products and compatibility (RAY-953 R2)

The default seed and integration assemblies use `default_payload_schema_registry()`:
raw frame segments, insole archives and gait archives. A deployment can inject
`payload_registry` into `IngestionService` to register another product without
editing routes, repositories or SQL. Explicit `supported_payload_schemas` and
`supported_manifest_schemas` still restrict admission when supplied; a registry
does not override these restrictions or authorize a licensed product. The
principal currently carries no trusted product ID: deployments still own product
audience/entitlement separation and the existing license/capability checks.

New insole/gait clients send the published session core: session ID, nullable site
ID, client installation ID, start time, versions (app and payload schema), and
optional config snapshot. The registry rejects undeclared fields. The same
strict admission applies to registered product extensions; their names do not
give them legacy hardware/subject/FK or frame-profile meanings.

Old insole HTTP bodies remain supported through a separate compatibility path.
Presence of any `subject_uuid`, `consent_record_id`, `terminal_id`, `device_id`,
`test_protocol`, or `versions.protocol_profile`/`versions.calibration` selects the
full legacy `SessionCreateRequest` validator. A partial, null, mixed or unknown
field does not fall back to the core validator after failure. Raw requests keep
their existing DTO, authorization, digest and replay behavior. Compatibility has
no removal date: removal requires a later explicit compatibility change and
client migration acceptance.

Core sessions retain exact canonical original JSON separately from operational
database values, including timestamp spelling, omitted optional fields, numeric
config values and declared extensions. Migration `0021_registry_ingestion`
adds text-backed originals/digests and profile-based constraints; older migrations
and rows retain their prior interpretation. Tenant/terminal/site ownership,
active credentials, license capabilities and recovery protection still apply.
Core requests cannot use legacy hardware-bound capture grants/migration permits.
Registered ISO-8601 timestamps may omit an offset. Their original strings and
canonical identity remain unchanged; a missing offset projects to SQL `NULL`
for the operational start/end instant, never an inferred host timezone. Legacy
sessions retain their non-null start-time constraint and existing interpretation.

Completion validates the registry's received-segment set, sizes, hashes, frame
totals and declared offsets under the existing repository transaction. Reusing
the same core segment index/content hash with changed metadata is a conflict.
Raw/insole still require `VALID`; gait's optional quality defaults to `UNKNOWN`
and does not block ingestion. This admission policy is separate from immutable
schema declarations (`quality_gate_schemas`), so adding a product does not invent
a clinical rule. Completion receipts distinguish that policy from legacy gates.

Here, received-segment verification uses the repository's stored metadata. The
upload path verifies incoming bytes through `SegmentObjectStore.put_segment`
and `ImmutableObjectStore.put_verified`; `complete_session` does not re-read
those segment bodies. It publishes the manifest and asks `complete_manifest`
to validate the accepted set and persist completion. In PostgreSQL, receipt,
`INGESTED` and the ingestion outbox event commit together under the session
transaction. This is not the public generic service's stored-content `content/1`
proof, even when the DB manifest record is marked `VERIFIED`.
See [the two-path comparison and future adapter constraints](../boundaries-and-troubleshooting.md#ingestion-guarantees-and-adaptation).

These are repository capabilities and local acceptance checks, not proof of a
deployed consumer or production cutover. The existing frozen vectors remain in
`docs/contracts/`; generated mobile OpenAPI includes both compatibility and
registered core inputs.

## Object keys and headers

`SegmentObjectStore` writes the keys FeetForcePlate wrote, so objects stored
before the migration stay valid:

```text
tenants/<tenant_id>/sessions/<session_id>/segments/<index>-<sha256>.ffps
tenants/<tenant_id>/sessions/<session_id>/manifests/<sha256>.json
```

On an `AliyunOSSObjectStore` it also sets the content types and the
`schema-version` metadata FeetForcePlate used. Store errors map to the platform
errors the HTTP layer already returns: a size or digest mismatch is
`SizeMismatch` / `DigestMismatch` with the expected and actual values, and an
existing key holding other bytes is `SegmentDigestConflict`.

## Object store failures (RAY-1028)

An OSS request that fails before saying anything about the object is translated
at the gateway: no answer because of the network (connection, TLS, DNS, CA
bundle, timeout, also while the body streams) or a 5xx/429 answer is
`ObjectStoreUnavailable`, which the HTTP layer answers with 503 `E-CLD-503`
(`retryable: true`, `RETRY_LATER`). Any other service refusal, such as 403
AccessDenied, and any client-side SDK failure (empty or unfetchable credentials,
an invalid bucket name or parameter) is `ObjectStoreRequestFailed` and stays a
non-retryable 500 `E-CLD-500`. On `head` and `put`, 404 and 409 keep their
meaning (absent key, existing key); on the other calls they are request failures.

Either failure while uploading a segment or completing a manifest is recorded,
best effort and in its own transaction, as an `OBJECT_STORE_FAILURE` row in
`screening.ingest_problems`: one OPEN row per session and segment (a NULL
segment is the manifest), refreshed on repeat. `safe_evidence` holds only the
operation, the category (`transport`/`service`/`client`), the service status and
the service error code; never the key, the message or a credential. If the
database cannot take the record, the client still gets the store's error.
A later successful registration of that segment resolves its row in the same
transaction, as does an upload answered as an idempotent replay because a
duplicate upload registered it first; a completed manifest resolves every OPEN
row of the session. Migration `0023_object_store_failure_problems` grants the
tenant role the four columns this updates and adds the partial unique index
that keeps the OPEN row unique.

**Deploy 0023 before or with this code.** Without it the recording `INSERT ...
ON CONFLICT` has no index to match and fails, and the resolving `UPDATE` is
refused; both are best effort (the resolve runs under a savepoint and is skipped
with a warning), so uploads and completions still succeed and return the same
errors, but no `OBJECT_STORE_FAILURE` row is written until the migration is
applied.

Deleting an unreferenced object after a failed registration is itself best
effort: an object store error there is logged and the original error is raised.

## The ingested event

A completion that reaches `INGESTED` commits exactly one `session.ingested.v1`
event with `session_id`, `manifest_sha256`, `segment_count` and, since RAY-831,
`payload_schema_version`. In PostgreSQL it is a row in `ops.outbox_events`
committed in the same transaction as the receipt; an idempotent replay commits no
second event. Routing it to an analyzer is described in
[Analysis dispatch](analysis-dispatch.md).

## Conflicted sessions

Uploading different content at an accepted segment index marks the session
`CONFLICT`. A session in that state cannot newly complete a manifest, even if
the manifest matches the original accepted segments: the PostgreSQL repository
raises `ManifestConflict` under the session row lock, retains the conflict, and
creates neither a completion receipt nor a `session.ingested.v1` outbox event.
Previously completed manifests retain their existing idempotent replay behavior.

## What did not move

- The seed and integration assembly and the deploy scripts
  (`deploy-cutover`). The HTTP routes, the application factory and the service
  container are in `server.app` (`http-routes`), and the access-control, device,
  inventory, session-hold and report-copy services in `access-plane-services`.
- `analysis` and `reporting`, which stay in FeetForcePlate.
