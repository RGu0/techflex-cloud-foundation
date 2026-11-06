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

## Completion and status receipts

`POST /v1/sessions/{session_id}/complete` returns a `data` envelope containing
`ManifestCompletionResponse`: `session_id`, `ingest_status`, `manifest_sha256`,
`idempotent_replay`, `manifest_object_key`, `eligibility_reason`,
`eligibility_policy_version` and `completed_at`. The eligibility policy version
records admission rules; it is not a content-verification version. The response
has neither `verification_version` nor the generic receipt's `idempotency_key`.
`GET /v1/sessions/{session_id}/status` returns `SessionStatusResponse` with
ingest/validity/analysis/report status fields; it does not return the completion
receipt or manifest digest. Completion retry and status polling are different
reconciliation operations.

These API types are distinct from the package-root `ArtifactReceipt` and
`SessionStatus` described in the generated [public API reference](../api-reference.md).
Do not coerce `INGESTED` into a generic `content/1` receipt or interpret the
published OpenAPI as providing stored-body readback. Upload verification,
completion metadata verification and local retirement are separate boundaries;
see [ingestion guarantees and adaptation](../boundaries-and-troubleshooting.md#ingestion-guarantees-and-adaptation).

## Subject sync and terminal diagnostics (RAY-830 R5)

`server.subject_sync` and `server.terminal_diagnostics` arrived with
`ffp-drift-port`; they were added to FeetForcePlate (RAY-907, RAY-802) while the
other scopes were in flight.

Institutional subject sync is served under `GET /v1/subjects`,
`PATCH /v1/subjects/{subject_uuid}`, `POST /v1/subjects/search-by-name` and
`/v1/subject-tags` to terminal bearer tokens only. Compose it by setting
`ServiceContainer.subject_sync` to a `SubjectSyncService` over
`PostgresSubjectSyncRepository` on the tenant pool, with the same
`IdentityProtector` as subject creation. Migration `0018_subject_sync` must have
run. Reads ignore the License; PATCH and tag creation need a usable one.

Terminal diagnostic packages are uploaded with a terminal access token to
`POST /v1/diagnostics` (mobile contract: `docs/contracts/mobile/README.md`).
Compose it by setting `ServiceContainer.terminal_diagnostics` to a
`TerminalDiagnosticsService` over `PostgresDiagnosticRepository`, with the object
store wrapped in `server.terminal_diagnostics.object_store.DiagnosticPackageStore`
(FeetForcePlate's `put_diagnostic` / `read_diagnostic`). Migration
`0019_terminal_diagnostics` must have run. Records live in
`ops.terminal_diagnostics` (tenant row-level security forced; the activation role
inserts, the platform role reads and may set only `deleted_at`, nobody deletes);
content lives at `diagnostics/{tenant_id}/{diagnostic_id}.ndjson`, encrypted by
the store.

Tenant closure, not part of the mobile contract (RAY-963, carried from FeetForcePlate `52282aa`):

A platform identity with a write role (`PLATFORM_OWNER` or `PLATFORM_OPERATIONS`) closes or
restores a whole tenant with `PATCH /v1/platform/tenants/{tenant_id}` and body
`{"action": "CLOSE" | "RESTORE", "reason_code": "…"}` (`reason_code` is optional, at most 64
characters). `CLOSE` applies to an `ACTIVE` or `SUSPENDED` tenant and `RESTORE` only to a
`CLOSED` one, and always returns it to `ACTIVE`; a `SUSPENDED` tenant that was closed does not
return to `SUSPENDED` (its previous status is kept only in the audit event). Any other
transition answers 409 `E-PLT-409-TENANT-STATE`, and an unknown tenant answers 404. Nothing is
deleted, and the change is audited as `tenant.close` / `tenant.restore`.

While a tenant is `CLOSED`:

- sign-in (`/v1/access/login` and the terminal sign-in `/v1/access/terminal-activate`) and
  activation-code activation of its accounts are rejected with the same answer as wrong
  credentials, and the failed attempt is recorded and rate limited;
- capture grants cannot be issued or retired;
- no new session can be registered, whether bare, grant-authorised or
  migration-permit-authorised. Replaying an already registered session still resolves.

The gates test for `ACTIVE`, not for `CLOSED`: a tenant in any other status, `SUSPENDED`
included, is refused the same way. No platform operation here sets `SUSPENDED`.

Closing revokes nothing that was already issued. Access tokens (15 minutes) and refresh
sessions (30 days idle, 180 days absolute) keep their upload and report access for sessions that
already exist, and grants or migration permits already issued stay in place but cannot start a
session while the tenant is `CLOSED`. These entry points are not gated: token refresh
(`/v1/access/refresh`, `/v1/access/terminal-refresh`), hardware leases, the legacy device
enrolment (`POST /v1/terminals/enroll`, which uses a device activation code, not an account) and
identity-recovery session registration. The status is read, not row-locked, because the
application roles may not lock `iam.tenants`; a sign-in, activation, grant or registration that
read `ACTIVE` just before a close commits can still succeed once. Migration
`0022_tenant_status_gate` gives the tenant role read-only access to `iam.tenants` for the
capture-session check.

Platform support access, not part of the mobile contract:

- `GET /v1/platform/tenants/{tenant_id}/diagnostics?ticket_reference=…` lists
  metadata, newest first, tombstones included.
- `GET /v1/platform/tenants/{tenant_id}/diagnostics/{diagnostic_id}/content?ticket_reference=…`
  returns the body as `application/x-ndjson` with `Cache-Control: no-store` and
  `X-Content-SHA256`.
- Only `PLATFORM_SUPPORT` and `PLATFORM_ENGINEER` are allowed; no
  `SensitiveAccessGrant` is involved, since a package holds no identity by
  construction. Each list and read needs a non-empty `ticket_reference` (at most
  256 characters) and appends `diagnostics.list` / `diagnostics.read` to
  `ops.access_audit_events` before anything is returned. A denial appends
  `diagnostics.deny` with a `reason` (`role_unauthorized`, `ticket_missing`,
  `context_inactive`, `terminal_credential`, `tenant_credential`,
  `tenant_unknown`, `not_found`, `expired`, `deleted`); a read whose stored
  content is missing or fails its digest check appends `diagnostics.read_failed`
  and returns 500.
- Retention is 30 days from upload. On the seed host, with the seed environment,
  run `python -m techflex_cloud_foundation.server.terminal_diagnostics.purge`
  (through `deploy/aliyun/seed/venv-python.sh -m …`). It deletes the content of
  every package past `expires_at` and keeps the row as a tombstone (on a versioned
  OSS bucket the content stays as a noncurrent version until a noncurrent-version
  rule removes it; see the seed README); an interrupted run is safe to repeat. On
  the seed host `feetforceplate-diagnostics-purge.timer` runs it once a day
  (RAY-927); an OSS lifecycle rule on the `diagnostics/` prefix (delete after 31
  days) is the backstop, not the mechanism. See `deploy/aliyun/seed/README.md`,
  which also lists the OSS role grant on `diagnostics/*` (`PutObject`, `GetObject`,
  `DeleteObject`).

## What did not move

- `local_lab`, the `seed` and `integration` assembly, the deploy scripts and the live
  route smoke scripts moved with `deploy-cutover`; see
  [seed-cutover-runbook](seed-cutover-runbook.md).
- `observability` other than `validation_telemetry`; `analysis` and `reporting`
  stay in FeetForcePlate.

## Registered gait ingestion (0.9.1 candidate)

The existing registry now validates neutral session, segment and manifest documents
through the HTTP data plane. Both seed and local integration assembly enable the
gait schema pair. See [registry ingestion](registry-ingestion.md) for credentials,
canonical bytes, completion semantics, migration and the remaining release gate.
