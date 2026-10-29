# Server HTTP routes

RAY-830 R3 (`http-routes`) moves the FeetForcePlate cloud's HTTP surface into
`techflex_cloud_foundation.server`. The wire format is the one FeetForcePlate
already published; this is a move, not a redesign. Nothing here is exported
from the package root. Import from the modules; they need the `server` extra
(`fastapi`, `asyncpg`).

## Modules

| Module | Role |
|---|---|
| `server.app` | `create_app(ServiceContainer)`: every route, the correlation-ID middleware, the `data`/`meta` and `error`/`meta` envelopes and the exception handlers. |
| `server.operations_auth` | Platform-operations token issuer and context. |
| `server.validation_telemetry` | Validation telemetry service behind the device telemetry route. |
| `server.contract_export` | Builds the published OpenAPI document and the test vectors. |

## Composing an application

`ServiceContainer` is a frozen dataclass whose fields are the services and
token issuers the routes use. What a field left `None` does depends on the
service: for `tenant_access`, `terminal_access`, `insole_inventory`,
`validation_telemetry`, `hardware_leases`, the platform services and
`session_holds` the routes are not registered at all; for the other token
issuers, `operations`, `capture_grants`, `identity_recovery`, `report_copies`,
`devices` and `heartbeats` the route answers `E-CLD-503` (service unavailable).
An application composes only what it serves. The application chooses the repositories (in-memory or PostgreSQL), the
object store (wrapped in `server.segment_store.SegmentObjectStore`) and which
payload and manifest schemas `IngestionService` accepts. Registering
`insole-session-archive/1` and `insole-session-manifest/1` is what makes an
application accept insole sessions.

`ingestion` is used without a `None` check, as FeetForcePlate did: with it
unset the session routes fail with the generic 500 envelope, so an application
that serves them must provide it.

## Published contract

`docs/contracts/mobile/openapi.json` and `vectors.json` are generated from the
route table. The tests fail when the committed files differ from the generator:

```bash
python -m techflex_cloud_foundation.server.contract_export
```

Run it from a source checkout: it writes to the repository's `docs/` tree.

## What did not move

- `local_lab`, the `seed` and `integration` assembly, the deploy scripts and the live
  route smoke scripts moved with `deploy-cutover`; see
  [seed-cutover-runbook](seed-cutover-runbook.md).
- `observability` other than `validation_telemetry`; `analysis` and `reporting`
  stay in FeetForcePlate.
