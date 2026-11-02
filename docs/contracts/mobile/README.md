# Mobile API contracts

`openapi.json` and `vectors.json` are deterministic public artifacts of the
FeetForcePlate API, which this library serves from `techflex_cloud_foundation.server.app` (RAY-830). They contain no deployment endpoints or real keys.
Regenerate with `python -m techflex_cloud_foundation.server.contract_export` (needs the `server` extra); the test gate detects drift.
Consume the JSON files at a pinned Git commit/tag and retain their SHA-256 with
the client build. Versioned source distributions include these tracked files. This export does not claim that
any route, including the insole inventory routes, hardware registration or
institutional access rules, has been deployed.

The server wraps success in `data` + `meta`; failures use `error` + `meta`.
Since RAY-834 an unexpected server failure uses the same envelope instead of a
bare 500: a database connection or timeout failure is 503 `E-CLD-503`
(`retryable: true`, `RETRY_LATER`); anything else is 500 `E-CLD-500`
(`retryable: false`, `CONTACT_SUPPORT`; vector `errors.internal`). Neither carries
details; quote the `X-Correlation-ID` when reporting one. A response with no
envelope at all comes from the transport or proxy, not the API.
JSON the server stores as sent, such as a basic report copy's `document_json`,
must carry non-ASCII text as raw UTF-8, not `\uXXXX` escapes: the integration
database is `SQL_ASCII` (RAY-835 tracks UTF8) and rejects escaped non-ASCII
characters in JSON. Dart `jsonEncode` already writes raw UTF-8.
Foundation's top-level `ErrorEnvelope` is a different mechanism. Follow both
`retryable` and `action`; equal error codes can have different required actions.
Keep `X-Correlation-ID` a UUID (the business gateway rejects non-UUID values).
Idempotent session/segment creation returns 201 initially and 200 on replay;
reuse the exact idempotency key and request, and treat changed payload as conflict.

For Dart, decode the JSON fixtures directly; do not reconstruct the signed bytes
using default `jsonEncode` ordering. Decode `canonical_hex` and verify the
Ed25519 signature against `public_key_base64`. The example key is synthetic and
untrusted for production. Test tampered document/signature and unknown key id.
Metadata uses unpadded base64url of UTF-8 canonical JSON (sorted object keys,
compact separators, Unicode unescaped, non-finite numbers rejected); array
order is preserved. Binary payload digest is lowercase full SHA-256 over the
bytes before any transport encoding. `payload_base64` is only a fixture carrier,
not the HTTP body; PUT the decoded bytes as `application/octet-stream` and send
`X-Content-SHA256`, `X-Schema-Version`, `X-Segment-Metadata` from the fixture.

RAY-656 adds institutional multi-terminal routes under `/v1/access/terminal-*`
and `/v1/access/terminals`, plus the `terminal` vector section. Activation takes
account + password + terminal name + `client_installation_id` + platform, with no
activation code. Each operation's `x-ffp-error-codes` lists its distinct codes:
revoked, seat limit, refresh replayed, refresh expired, and so on. Branch on
`error.code`; never infer revocation from a bare 401. The signed
`terminal-license/1` document carries `seats` and verifies with the same fixture
key procedure as `license/2`.

Refresh rotation: a rotated token replayed within `replay_grace_seconds` (30,
inclusive) returns the identical successor refresh token and a new access token.
A later replay, or a replay after the successor was used, revokes the whole
family (`E-TRM-401-REFRESH-REPLAYED`). Persist the newest refresh token before
using it, and retry a lost refresh response with the previous token inside the
window. Every `refresh_rotation` and `seats` scenario is replayed against the
server in `tests/test_ffp_terminal_access.py`.

RAY-778 adds institutional insole inventory routes under `/v1/inventory/insoles`
(register, cursor download, report, retire), all authenticated with the terminal
bearer token, plus the `insole_inventory` vector section. These routes are not
part of the `v0.2.0` release assets; pin a commit or a later release.
- Register with an `Idempotency-Key` (scoped to the registering terminal): 201 new,
  200 replay of the same pair at its current revision, `E-API-409` for a changed
  request under the same key. `E-INV-409-IDENTITY-REGISTERED` (same MAC/serial,
  other number) and `E-INV-409-NUMBER-TAKEN` (same number, other identities)
  carry the existing pair in `error.details.existing`. A `mac` identity value must be
  canonical uppercase colon form (`registration.mac_pattern`); other spellings are 422.
- Reports merge `state`, `left` and `right` independently: the newer device-side
  time wins, and an equal time keeps the stored value. Battery carries both raw
  `millivolts` and the client's `percent`; recompute percent from mV when the
  discharge curve changes. `applied` says which groups took effect.
- Download: start without `cursor`, store `next_cursor` from every page, and
  continue while `has_more`. Items are ordered by server `revision`; pairs are
  never deleted and arrive as `retired` instead. On `E-INV-400-CURSOR-INVALID`,
  clear the cursor and download again from the start.
Every `insole_inventory` scenario is replayed against the server in
`tests/test_ffp_insole_inventory_api.py`; client alignment is tracked by
RAY-607.

RAY-728 lets an activated terminal upload with its terminal access token: the
subject, consent and session routes accept it in addition to the hardware
tenant token (vector section `terminal_data_plane`). Not part of `v0.2.0`.
- `X-Terminal-ID` is optional; when sent it must equal `client_installation_id`.
  Terminal status is checked on every request, so a revoked terminal gets
  `E-TRM-401-REVOKED` there too, even with an unexpired access token.
- A session names the caller: `terminal_id` and `client_installation_id` are its
  `client_installation_id`, `site_id` is null, and `device_id` is the `insole_id`
  of a non-retired pair in the institution's inventory. Segments, complete and
  status work only for sessions the calling terminal created. Violations are
  `E-AUT-403`.
- A new session needs the current License ACTIVE, within validity and enabling
  `screening.start`; this is read per request. Segments, complete, subject and
  consent writes need only an ACTIVE terminal, so already captured data still
  uploads after the License stops new tests. `X-Capture-Authorization` and
  `X-Expected-Manifest-SHA256` are not supported for terminals (403).
- Self-revoke (`POST /v1/access/terminals/{own id}/revoke`) is supported: the seat
  is released at once, every refresh session ends, repeats return the revoked
  terminal unchanged. `/v1/access/logout` is for hardware login only. Upload
  pending data before revoking.
- Re-activating the same `client_installation_id` on the same account keeps the
  id, starts a new refresh family, takes a seat again (`E-TRM-409-SEAT-LIMIT` when
  full) and resumes segments and complete of sessions created before the revoke.
  Another account gets `E-TRM-409-INSTALLATION-CONFLICT`.
Every `terminal_data_plane` scenario is replayed against the server in
`tests/test_ffp_terminal_data_plane.py`.

RAY-825 registers the smart-insole payload schema `insole-session-archive/1`
next to the force-plate `raw-segment/1`, which is unchanged (vector section
`insole_session_archive`). Not part of `v0.2.0`.
- Create the session with `versions.payload_schema = insole-session-archive/1`.
  The session is one deterministic tar.gz archive split into parts; the cloud
  verifies only each part's bytes (SHA-256 and size), never their content.
- `X-Segment-Metadata` carries exactly `segment_index`, `size_bytes`, `sha256`
  and `payload_schema_version` (`ArchiveSegmentMetadata`; OpenAPI
  `x-ffp-segment-metadata` on the PUT). Any frame, clock, compression or cipher
  field is rejected with `E-API-400`. `X-Schema-Version` is
  `insole-session-archive/1`.
- Complete with `InsoleSessionManifest` (`schema_version`
  `insole-session-manifest/1`): `segment_count`, `total_bytes`,
  `segments[{index, sha256, size_bytes}]`, `ended_at`, `local_quality_outcome`;
  no frame counts. Each payload schema completes only with its own manifest
  schema (`pairing`); a crossed pair is `E-CLD-422` `UPDATE_CLIENT`.
- `X-Content-SHA256` is the SHA-256 of the canonical JSON the server rebuilds
  from the parsed body, so send `ended_at` already in that form: UTC, `Z`
  suffix, microseconds only when non-zero (`2026-10-25T12:58:00Z`,
  `2026-10-25T12:58:00.250000Z`). Check against `manifest.canonical_hex`. The
  `Idempotency-Key` is the client's own, unique per session and stable across
  retries; the vector headers omit it.
- `local_quality_outcome` is required, and only `VALID` completes to `INGESTED`;
  anything else is `E-CLD-422` `REPEAT_SCREENING`. Send `VALID` only for a session
  that was saved with its archive complete. A manifest that differs from the
  received parts (index, sha256 or size) is `E-CLD-422` `UPLOAD_MISSING_SEGMENTS`.
Every `insole_session_archive` scenario is replayed against the server in
`tests/test_ffp_insole_session_archive.py`; client alignment is tracked by
gait-insole-flutter RAY-624.

RAY-907 adds institutional subject sync (vector section `subject_sync`), all
authenticated with the terminal bearer token. Not part of `v0.2.0`.
- `GET /v1/subjects?cursor=&limit=`: incremental download by server `revision`,
  same paging rules as the insole download. A subject gets a new revision on
  create, any PATCH, archive or restore, consent create or revoke and tag-set
  change. Nothing is deleted; archived subjects arrive with `status: ARCHIVED`.
  The record carries `identity_profile.display_name`, never `contact`, and the
  institution number masked only; resolve a number with `/v1/subjects/resolve`.
  `identity_profile` is absent for `MERGED`/`RESTRICTED` subjects. On
  `E-SUB-400-CURSOR-INVALID` clear the cursor and download from the start.
- `PATCH /v1/subjects/{subject_uuid}` with `Idempotency-Key` and the
  `base_revision` you last saw. A stale one is `E-SUB-409-REVISION-CONFLICT` with
  the current record in `error.details.current`: merge locally and retry with its
  revision; the server never merges. `analysis_profile` merges per field;
  `identity_profile` and `tag_ids` replace the stored value (a replaced identity
  without `contact` drops the stored contact); a new `external_identifier`
  supersedes the old. A replay returns the subject's current record.
  A superseded number never becomes active again (setting the old value back
  creates a new `external_identifier_id`), so a different number strands any
  identity-recovery case of that subject that is not yet registered: compare
  answers 404, register 403 (409 once the receipt has expired), a new case for
  the same session 409, and `POST /v1/sessions` 403, so the session cannot be
  uploaded by any route. The server does not refuse the PATCH. Finish a
  pending recovery registration before changing the subject's number; on those
  responses do not retry, keep the session `BLOCKED` and export diagnostics
  (RAY-933).
- `POST /v1/subjects/search-by-name` `{display_name}`: exact match after NFKC,
  trim and case fold (`name_search.equal_examples`), ACTIVE and ARCHIVED only,
  at most 20. Subjects created before the subject-sync migration (0017 in FeetForcePlate, 0018 here) are found only after their
  identity is next edited.
- `GET /v1/subject-tags` / `POST /v1/subject-tags` `{tag_id, name}`: 201 new; 200
  with `conflict: true` and the existing tag when the normalized name is taken;
  switch to its `tag_id`. Set tags on a subject only through PATCH.
- With an inactive License the three reads keep working and the two writes are
  `E-TRM-403-LICENSE-INACTIVE`; `POST /v1/subjects` is unchanged.
Every `subject_sync` scenario is replayed against the server in
`tests/test_ffp_subject_sync_api.py`; client alignment is tracked by
gait-insole-flutter RAY-592 / RAY-912.

RAY-802 adds the terminal diagnostic package upload `POST /v1/diagnostics` and
the `terminal_diagnostics` vector section. Not part of `v0.2.0`.
- Send the RAY-910 export unchanged as the body: one JSON Lines text,
  `gait-insole-diagnostics/1`, `Content-Type: application/x-ndjson`, at most
  8 MiB (`constants.max_bytes`) uncompressed; `Content-Encoding` is not accepted.
  Headers: terminal bearer token, `Idempotency-Key` (scoped to the uploading
  terminal) and `X-Content-SHA256`, the lowercase SHA-256 of the exact body bytes.
- 201 returns `diagnostic_id, format, size_bytes, sha256, received_at,
  expires_at` (30 days after upload). The same key and digest again returns 200
  with the identical body; the same key with another digest is `E-API-409`.
- Over the limit is 413 `E-DIA-413-TOO-LARGE` (`details.max_bytes`); a digest
  that does not match the body is `E-DIA-422-DIGEST-MISMATCH` (retryable).
- The package is accepted or rejected whole, never repaired:
  `E-DIA-422-CONTENT-REJECTED` with only `details.line` (1-based) and
  `details.reason` (`not_json`, `header_missing`, `format_unsupported`,
  `unknown_kind`, `unknown_field`, `header_mismatch`, `identity_detected`).
  The header's `tenant_id` and `terminal_id` must be the token's tenant and
  `client_installation_id`; each kind's top-level fields are the fixed sets in
  `package.line_fields`. Every string, keys included, at any depth is screened
  with the client `Redactor`'s key and pattern rules: a key the Redactor treats
  as identity holds only `<redacted>`, and no unredacted mobile, landline,
  e-mail or resident ID number may remain. An export produced by the client's
  `DiagnosticsBundle` passes as is. Numbers (JSON numbers, not text) are not
  screened, as the client does not redact them either.
- Write the header's `tenant_id` and `terminal_id` exactly, after redaction: if
  the export's redaction rewrites them (a registered value or pattern that
  happens to match part of a UUID), every upload is `header_mismatch`. The
  server compares them to the token and does not pattern-screen them.
- Package lines in the vectors carry `{tenant_id}` and `{terminal_id}`; substitute
  the uploading terminal's ids (`package.example_*` shows fixed ids).
- There is no terminal or tenant read path; platform support access is outside
  this contract (`docs/guides/server-http-routes.md`).
Every `terminal_diagnostics` scenario is replayed against the server in
`tests/test_ffp_terminal_diagnostics_api.py`; one-tap upload in the client is
gait-insole-flutter RAY-615.

Dart consumption: as of 2026-10-07, RAY-643 (Done) recorded native Dart
consumption of these fixtures in gait-insole-flutter (PR 7). That evidence
predates the RAY-656 `terminal` section; client alignment for it is tracked by
RAY-657. iOS/Android real TLS evidence remains a separate acceptance step, and
no mobile pass is implied by Python export tests.
