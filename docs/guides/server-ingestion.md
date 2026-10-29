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

## What did not move

- The seed and integration assembly and the deploy scripts
  (`deploy-cutover`). The HTTP routes, the application factory and the service
  container are in `server.app` (`http-routes`), and the access-control, device,
  inventory, session-hold and report-copy services in `access-plane-services`.
- `analysis` and `reporting`, which stay in FeetForcePlate.
