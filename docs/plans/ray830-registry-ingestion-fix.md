# RAY-830 registry-ingestion-fix plan (R5)

User approved repairing product-neutral HTTP ingestion through persistence, preparing
an immutable successor release; publishing and switching remain separately approved.

Root cause: registry is library-only. HTTP DTOs, seed allowlists, ingestion policy,
repository references and SQL shape checks still assume the two migrated products.

Approach: preserve legacy DTOs/bytes for raw and insole. Add registry-validated JSON
adapters for other registered schemas, keeping original documents for canonical
hashes. Require terminal credentials for neutral sessions, with no fabricated
subject/device rows. Store complete neutral request and segment documents in new
JSONB columns through migration 0020; retain original constraints for legacy rows.
Reuse existing locks, RLS, idempotency, object-store digest checks and completion
receipt transactions. Validate received metadata against the registry before
completion; UNKNOWN quality on gait is ingestion, not a VALID analysis verdict.

- [x] HTTP red tests: registry-valid gait core, multipart/offsets, completion, replay,
      malformed/unknown schema, tenant/terminal mismatch, corruption and conflicts.
- [x] Registry adapters + service/entrypoint wiring; legacy regressions unchanged.
- [x] Migration + PostgreSQL roundtrip and concurrent/idempotent behavior; migrate
      old schema without changing old SQL, test constraints on scratch databases.
- [x] Update API export, vectors/docs and prepare version 0.9.1; no publish or repin.
- [ ] Governed lint/test/build, exact-head independent review and CI; ready PR.

PR #102 remains independent/unmerged; its known-blocker regression must be updated
when both changes are integrated. No claims of host TLS or production acceptance.
