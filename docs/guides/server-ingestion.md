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
config values and declared extensions. Migration `0020_registry_ingestion`
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
