# RAY-830 pre-cutover-validation implementation plan

Goal: supply missing smoke tools and a concrete pre-cutover decision checklist under R5.
Authority: user approved this tools/tests/docs scope; no production cutover, business code,
release wheel or runtime lock change. Scope registration is in Linear RAY-830.

Architecture: reuse the existing TLS client, terminal activation and recorder. A single
CLI selects gait ingestion or diagnostic upload; both require an explicit target and
use synthetic data, redact evidence and revoke the temporary terminal. Gait requests
use the product-neutral registered contract, not fabricated legacy pressure fields.
Tech stack: existing Python 3.11 environment, urllib TLS, Pydantic, pytest/ASGI fixtures.

- [ ] Add tests for diagnostic upload/replay/digest, failures, revocation and redaction.
- [ ] Add a gait HTTP acceptance probe using registry-valid core/byte-segment contracts;
      reproduce the current HTTP rejection as an explicit deployment blocker, not xfail.
- [ ] Implement smoke CLI with explicit rehearsal/production target acknowledgement,
      strict HTTPS, no redirects, finite timeouts, redacted JSON and failed cleanup status.
- [ ] Add preflight/rollback checklist and distinguish historical host observations,
      local API tests, required operator rehearsal and production acceptance.
- [ ] Run governed lint/test/build, independent review, fix findings, retain evidence
      and open a PR. Do not merge or cut over without the required authorization.

Review focus: credentials in exceptions/evidence; cleanup after failure; rejected or
incomplete ingestion never passing; mismatched diagnostic receipt/replay; production
writes requiring explicit CLI acknowledgement. Runtime implementation defects are
reported for a separately approved fix/release, never hidden by tool changes.
