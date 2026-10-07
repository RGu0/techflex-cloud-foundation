# Replay authentication and new-effect admission

RAY-557 R2 documents the existing foundation boundary. The application bug
about checking `allow_new_test` before session replay belongs to the receiving
HTTP service. Foundation defines neither that flag nor its HTTP status policy.

## Authentication still precedes replay

`IngestionService.begin_session` first calls
`IngestionPrincipal.ensure_can_upload(now)`. An expired principal or one with
`allow_upload=False` is refused even when a begin key exists. This is upload
authentication/authorization, not a new-test License check. Moving it behind
replay would weaken the existing security boundary.

After validating the supported payload schema, positive part count and key,
the service looks up an existing begin key inside the principal's tenant.
Its request digest binds `payload_schema` and `part_count`: the same request
returns the existing session ID and `True`; a different digest raises
`IngestionConflict`. This mechanism does not supply a subject/device identity
DTO, an HTTP 200 response or a business License decision.

See [ingestion.py](../../src/techflex_cloud_foundation/ingestion.py) and the
existing `tests/test_ingestion.py` replay, tenant isolation, schema and
expired/disallowed-principal regressions. Those library tests do not prove
that a receiving HTTP adapter preserves this order.

## New-effect policy belongs to the application

`IdempotencyGuard.run` requires an open tenant scope, then reads the
idempotency record. A matching unexpired record returns its stored outcome;
a different request digest is refused. After the request-record TTL, the
natural-key claim still prevents duplicate effects and resolves the original
outcome; a partial claim with no outcome is refused for reconciliation.
The operation callback runs for a new effect, rather than for the
stored-outcome replay. Production stores must
preserve the documented transaction and conflict guarantees; the reference
store is not a deployment transaction receipt.

Applications using that mechanism can keep new-effect admission inside their
transactional operation while preserving authentication and tenant/request
validation for every request. It is not permission to bypass revoked upload
credentials, change the library's digest shape, reuse a key across principals
without application binding, or place a new-test check around all retries.
See [consistency.py](../../src/techflex_cloud_foundation/consistency.py) and
`tests/test_consistency.py`.

The retained business acceptance requires an authenticated request to the
actual service: while new-test License admission is suspended, exact replay
returns the existing session, new creation is denied without persisted effects,
and mismatched request/tenant/identity attempts remain denied. Existing
receiving-service work must be merged and validated there; this library guide
or its R2 completion does not claim that HTTP deployment acceptance passed.
