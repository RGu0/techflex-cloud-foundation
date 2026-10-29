# Server access-plane services

RAY-830 R3 (`access-plane-services`) moves the FeetForcePlate cloud's access,
identity, device, inventory, session-hold and report-copy services into
`techflex_cloud_foundation.server`. Nothing here is exported from the package
root; import from the modules. PostgreSQL adapters need the `server` extra
(`asyncpg`).

## Packages

| Package | Role |
|---|---|
| `server.access_control` | Platform and tenant accounts, licences and seats, terminal activation and refresh, capture grants, lease service, password hashing, platform IAM. `repository` is the in-memory reference adapter; `postgres` is the production one. |
| `server.identity_recovery` | Controlled identity recovery cases: create, approve, execute, with the repository and PostgreSQL adapters. |
| `server.device_management` | Terminal enrolment and heartbeat services and the operations service behind the operator views. |
| `server.insole_inventory` | Insole identities and records for the inventory screens. |
| `server.session_hold` | Holds on ingested sessions: apply, disposition, release, and the adapter that lets ingestion refuse held sessions. |
| `server.report_copy` | The cloud copy of a local basic report: contract validation, the private PDF store and the PostgreSQL repository. |

The services take their stores by constructor argument, so an application
composes them with either the in-memory or the PostgreSQL adapters.

## Report PDFs

`report_copy.object_store.LocalBasicPdfStore` writes the PDF through any
`ImmutableObjectStore` under
`tenants/<tenant>/sessions/<session>/basic-report-copies/<uuid>.pdf`. On
`AliyunOSSObjectStore` it sets `Content-Type: application/pdf` and the
`schema-version: local-basic-copy/1` metadata FeetForcePlate used, and reads are
capped at 8 MiB and surface a digest mismatch as `DigestMismatch`. FeetForcePlate's
`put_report_pdf` object-store method is replaced by this adapter.

## What did not move

- The HTTP routes, the application factory, `seed`/`integration` assembly, the
  provider bootstrap CLI (`access_control/cli.py`, which builds the seed app)
  and the tests that build the application (`http-routes`).
- The deploy scripts and their tests (`deploy-cutover`).
- `analysis` and `reporting`, which stay in FeetForcePlate. `observability`
  stays pending decision D4.

## Testing against a real database

The ported live tests read admin, tenant, activation and platform DSNs from the
`FEETFORCEPLATE_TEST_*` variables. `tests/pg_platform.py` starts one throwaway
PostgreSQL cluster per test run, installs the schema, creates least-privilege
login roles for `ffp_tenant_app`, `ffp_activation_app` and `ffp_platform_app`
and exports those variables, so the tests run without an operator-provided
database. They skip where no PostgreSQL server is installed, and DSNs you set
yourself are used as given.
