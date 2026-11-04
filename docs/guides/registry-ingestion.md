# Registered payload ingestion — 0.9.1 candidate

RAY-830 R5, scope `registry-ingestion-fix`, connects the existing payload registry
(the RAY-828/829/833 contract) to the HTTP data plane and PostgreSQL repository.
This is a candidate fix, not evidence of publication, host rehearsal, production
TLS acceptance or cutover. The 0.9.0 release and deployed runtime pin are unchanged.

## Wire contract

The seed and local integration applications accept `gait-session-archive/1` with
`gait-session-manifest/1` alongside the existing raw and insole contracts. The
`POST /v1/sessions` gait body contains `session_id`, nullable `site_id`,
`client_installation_id`, `started_at`, optional `config_snapshot`, and `versions`
with `app` and `payload_schema`. It has no invented subject, consent, device,
protocol or calibration fields. The registry rejects undeclared fields.

Use an active terminal bearer credential. Its installation must match the request;
its tenant is authoritative, and terminal sessions require `site_id: null`.
Hardware capture-grant and migration-permit headers cannot authorize these sessions.
The current license controls new sessions; reads/uploads retain existing terminal
ownership, revocation and tenant isolation rules.

Upload bytes to `PUT /v1/sessions/{session_id}/segments/{index}` with the existing
`X-Content-SHA256`, `X-Schema-Version`, and base64url `X-Segment-Metadata` headers.
Registry metadata carries index, size, SHA-256, payload schema and optional offset.
Declared body size and digest are checked by the object store. A registry receipt
binds all metadata: same index and bytes with a different offset is a conflict.
Raw/insole digest-only replay semantics remain unchanged.

`POST /v1/sessions/{session_id}/complete` accepts the registry manifest: segment
count, total bytes, ordered segment descriptors, codec (`gzip`, `bzip2`, `lzma`),
archive SHA-256, archive size and part size. `ended_at` and quality are optional.
The full field contract and examples remain in
[`payload-schema-vectors.json`](../contracts/payload-schema-vectors.json) and the
new `registered_ingestion` section of [mobile vectors](../contracts/mobile/vectors.json).
The OpenAPI adapters refer to the registry rather than duplicate its validation rules.

Canonical hashes use the original JSON document, including omitted fields; defaults
are not injected into signed bytes. Received indices, digests, sizes and declared
profile fields must match. Existing registry offset semantics remain: a manifest
that declares offset must be contiguous and agree with received metadata; omitting
an optional manifest offset does not assert that field. Archive content is opaque:
the server does not decompress it or recompute the archive hash across parts.

Successful completion means `INGESTED`. It preserves the declared quality, defaulting
to `UNKNOWN`, and does not request analysis or generate a report. A stored quality
value is a client declaration, not independent clinical or parent acceptance.

Malformed JSON bodies return 422; malformed metadata headers return 400; byte/size
or receipt-set mismatch uses the existing 422 errors. Changed idempotency input or
conflicting registered metadata returns 409. Unauthorized terminal access returns
403. Consumers should use the existing error code/action envelope.

## Database and upgrade

Migration `0020_registered_ingestion` adds `sessions.registered_document` and
`session_segments.metadata_json` so reads recover the exact accepted documents,
including offsets and omitted fields. A manifest marker distinguishes registry
rows. Legacy measurement columns become nullable only for registry rows; shape
checks continue requiring them on legacy rows. Existing foreign keys, RLS policies
and grants remain in force. SQL files 0001–0019 are unchanged.

Apply the complete migration plan to a restored copy before using the new runtime.
The new SQL converges and the migration ledger pins its checksum. JSON writes use
UTF-8 text without ASCII escapes, including on SQL_ASCII databases. Old runtimes
cannot read neutral sessions after such sessions have been written: rollback needs
the pre-upgrade backup, not merely an executable downgrade.

## Acceptance and next gate

The automated suite exercises the real seed constructor over temporary PostgreSQL
role pools (tenant, activation, platform), in UTF8 and SQL_ASCII: migration/re-run,
HTTP create/replay/upload/complete/replay, full document readback, noncanonical UUID
spelling, Unicode config and tenant RLS. HTTP negatives cover terminal ownership,
unknown schemas, undeclared fields, digest failures, metadata conflicts and offsets.
Legacy raw/insole tests and published contract checks run with the whole suite.

PR #106 merged on 2026-11-03. Before a live switch, release approval, the immutable
0.9.1 artifact,
restored-host rehearsal, three-product regression, diagnostics upload/receipt/replay,
TLS/rollback evidence and a final user confirmation are still required. PR #102 subsequently aligned its in-process gait smoke regression to successful
INGESTED/receipt checks; the original 0.9.0 422 evidence remains historical. This
source regression does not replace released-wheel or remote TLS evidence.
RAY-950 PR #103 independently supplies the PostgreSQL conflict-completion guard;
validate the final merged candidate with that change present.
