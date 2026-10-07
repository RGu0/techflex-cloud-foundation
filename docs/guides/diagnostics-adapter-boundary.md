# Diagnostic upload and support-access adapter boundaries

The foundation supplies primitives for application adapters; it does not
provide a ZIP builder, diagnostic upload route, support search service or
archive-retention scheduler. This guide documents the existing mechanisms
for RAY-555 R2, not live diagnostic upload/retrieval acceptance.

## Authenticate uploaders and authorize support separately

[RequestValidator](../../src/techflex_cloud_foundation/gateway.py) verifies
token claims and returns `TrustedRequestContext`. The token selects the
tenant; a disagreeing `payload_tenant` is refused. The configured payload
cap is checked before token verification. `max_payload_bytes` is required:
the library chooses no diagnostic archive-size default. The HTTP adapter
must measure actual bytes, enforce the limit while receiving the body, and
supply `payload_bytes`; an omitted length or untrusted Content-Length is not
a streaming-body limit. Rate policies and their stores are also injected.

Authenticate an installation with
[DeviceTrustService.authenticate](../../src/techflex_cloud_foundation/device_trust.py)
when the application uses installation credentials. Authentication alone
does not grant upload or support access. Bind the resulting trusted tenant
to persisted diagnostic records; never let an archive filename or payload
tenant select ownership.

[RoleCatalog](../../src/techflex_cloud_foundation/iam.py) evaluates only
application-registered roles in the principal's realm. Define distinct
upload and support-read permissions and call `require` for the appropriate
principal; unknown or other-realm roles cannot grant the permission.
The library supplies no diagnostic role names, permission policy or
cross-tenant support entitlement. A platform support permission still needs
an explicit target-tenant/resource access decision in the application.

## Minimize and validate telemetry

[AuditSink and MetricsSink](../../src/techflex_cloud_foundation/diagnostics.py)
are protocols, not implementations. `AuditSink.record` accepts optional
`Mapping[str, int | str]`; string values can still contain secrets or personal
data. A type annotation does not redact log lines, archive members, names,
device identifiers or command output. Applications must redact at collection
and serialization and verify the archive's allowed contents before upload.

[SafeFieldCatalog and SecurityEvent](../../src/techflex_cloud_foundation/observability.py)
offer a narrower structured-event boundary: the catalog permits declared
field names, refuses sensitive name markers, and event validation rejects
secret-like values, including nested values. This is refusal, not rewriting
or sanitization. Direct `SecurityEvent` construction validates values but
does not enforce a catalog whitelist. These rules are not a general-purpose
PII detector or proof that arbitrary diagnostic text is safe.

The sink protocols do not buffer, retry, persist or isolate exceptions.
They have no promised fail-open/fail-closed policy and no built-in
best-effort fallback. Application adapters must explicitly decide what a
failed audit/metrics sink means, how failures are surfaced and retried, and
whether support access is denied when its required audit cannot be recorded.
Do not report an audited read until the chosen audit operation has succeeded.
Keep raw archive bytes and credentials out of telemetry and support-access
records; inject a reviewed safe field catalog rather than recording inputs.

## Prove received bytes and define lifecycle

If the adapter uses
[IngestionService](../../src/techflex_cloud_foundation/ingestion.py), map
archive bytes through `entry-parts/1` and retain the `content/1` receipt.
The [content verification guide](ingestion-content-verification.md) explains
the exact mapping, actual byte checks, immutable completion and migration.
`ResumeDriver.may_retire_local` accepts only a matching verified receipt.
A receipt proves received content, not redaction, support-read permission,
search indexing or permanent retention. Upload success does not grant access
to its archive to a support account.

The application must explicitly provide maximum accepted/compressed and
expanded sizes, accepted formats, archive safety rules, retention periods,
deletion rules, support roles, target-tenant authorization and audit policy.
No size, number of days, seat count or role is selected by this guide.
Storage adapters must exclude deletion/replacement during verification and
finalization; post-completion retention remains application policy.
Actual integration upload, support retrieval and retention/security
acceptance require the business service's own delivery evidence.
