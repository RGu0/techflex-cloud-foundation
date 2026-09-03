# Changelog

All notable changes use Semantic Versioning. Breaking public-contract changes
require a new major version; additive capability changes use a minor version;
compatible security and defect fixes use a patch version. Deprecated public
interfaces remain for at least one minor release before a later major removal.

## Unreleased

- **Breaking.** `SecureTransport` can no longer be constructed without TLS
  verification (RAY-371 R2).  `verify: bool | str = True` accepted
  `verify=False`, which turned certificate checking off for every request on
  the client — the edit most likely to be made while debugging a private-CA
  environment and least likely to be reverted afterwards.  The parameter is
  now `verify: bytes | ssl.SSLContext | None = None`: PEM bytes, a prepared
  context, or the system trust store.  A boolean, a path string, or a context
  with `verify_mode=CERT_NONE` or `check_hostname=False` raises the new
  `InsecureTransportRejected` at construction.  A non-`https://` base URL is
  refused for the same reason — every request path, tokens included, is
  relative to it.  Passing PEM bytes also removes the boilerplate that wrote
  `config.ca_bundle_pem` to disk to satisfy httpx's path-only API, which left
  an unowned trust anchor on the filesystem.  Adds `tests/test_transport.py`;
  the module previously had no test file of its own.

  Migration: `verify=False` has no replacement and was never safe.
  `verify="/path/ca.pem"` becomes `verify=Path("/path/ca.pem").read_bytes()`,
  or `verify=config.ca_bundle_pem` directly.


- Adds `lifecycle.py` (PRD F-30): `UploadEligibilityPolicy` with named
  `Purpose`s and neutral `RetentionClass` tiers (unknown purposes never
  silently allowed), plus the explicit `DeletionDecision`/`DeletionReceipt`
  pair — a server confirmation never authorizes deletion; receipts commit
  to the exact decision digest.  Business validity judgments stay with the
  application.


- Adds `provenance.py` (PRD F-28): `ProvenanceRecord` lineage (sources +
  transform + version), layered `ValidityEvidence` (per-level status, never
  one boolean), and `AdjudicationRecord` keeping automatic/manual
  adjudication, rule versions, and adjudicators apart.  Canonical
  serialization with level-normalized ordering; unknown versions refused.


- Adds `manifest.py` (PRD F-27): versioned, content-addressed
  `ArtifactManifest`/`ArtifactEntry`/`ArtifactPart` with reproducible
  canonical serialization, complete-digest addressing (short prefixes
  refused), unknown-version refusal, parent lineage links, and streamed
  payload verification via `verify_entry_payload`.


- Calibrates the performance gate aggregation (RAY-349 R2): timing rounds
  now aggregate with best-of-N (minimum) instead of the median — CPU
  benchmark noise only inflates a round, so the minimum records the
  quietest measurement without relaxing real-regression detection. Peak
  memory keeps the median.  Evidence JSON schema unchanged.


- Stabilizes the release-evidence performance gate (RAY-349): the benchmark
  now measures process CPU time instead of wall-clock time so CI runner
  descheduling no longer appears as a fake P95 regression, the budget check
  re-measures once with diagnostics before failing, and budget errors now
  report the measured values and ratio.  Evidence JSON schema is unchanged.


- Adds `local_sqlite.py`: business-neutral local SQLite durability
  foundation — `LocalSqlitePolicy` (WAL/FULL/busy-timeout/foreign-keys),
  thread-safe `connect_durable`/`DurableConnection`, `inspect_durability`
  self-check reports, and `UserVersionMigrator` with gap-free 1..N
  migrations, transactional rollback, and refusal of newer databases.
- Hardens `SqliteOperationStore` additively: optional durability `policy`,
  `block`, `mark_conflict`, and `block_interrupted_leases` quarantine
  semantics. Existing signatures are unchanged.
- Adds `durability.py`: crash-safe local write primitives (`atomic_write`,
  `StagedAtomicFileWriter` implementing the `AtomicFileWriter` protocol,
  `write_all`, `fsync_directory`, `set_private_file_mode`) for local-first
  persistence ahead of cloud synchronisation, with fault-injection contract
  tests covering fsync failure, disk-full, and short writes.
- Adds `local_audit.py`: `ChainedAppendLog` / `ChainedRecord`, a tamper-evident
  append-only JSONL audit log with hash chaining, bounded generation rotation,
  owner-only permissions, append-time fsync, torn-final-line crash recovery,
  and cross-process write serialisation.

## Unreleased

- Adds `keystore.py`: the at-rest key boundary (`KeyProvider`,
  `KeyProviderUnavailable`, `FileKeyProvider`, `AesGcmBlobCodec` with
  context-bound AES-256-GCM envelopes), so keys are fetched per use and
  never persisted in databases or logs.
- Adds `sealed_store.py`: self-verifying sealed containers
  (`write_sealed`/`read_sealed`/`verify_sealed`, header-as-AAD, tamper
  quarantine via `quarantine_file`), exactly-once `MarkerRegistry`
  registration across crashes, and reversible delete windows
  (`reversible_delete`/`restore_delete`/`finalize_delete`).

## Unreleased

- Adds `techflex_cloud_foundation.testing`: shared, pytest-free fault
  injection for durability tests — `SimulatedPowerLoss` (raise at a chosen
  call boundary), `short_write_os`, `interrupted_replace`, `fsync_failure`,
  `disk_full`, and `KillAndRecoverHarness` (kill a child mid-flight, then
  run the recovery path).  Each fault is a self-restoring context manager.

## Unreleased

- Adds `object_store.py`: `ImmutableObjectStore` protocol with verified,
  atomic publication (`put_verified` streams chunks through SHA-256/size
  checks before a staged atomic rename; replay with identical content is
  idempotent, divergence raises `ObjectConflict`), plus
  `InMemoryObjectStore` and `FileSystemObjectStore` reference
  implementations with path-escape protection and owner-only permissions.

- Adds `tokens.py`: `HmacTokenCodec` (HS256 base64url tokens with pinned
  alg/kid/typ header and aud claim, constant-time signature comparison,
  exp/iat handling) implementing the `TokenIssuer` protocol, with a typed
  `TokenError` hierarchy — the server-side complement to
  `transport.TokenProvider`.

## 0.1.1 - 2026-08-25

- First private, independently buildable distribution of the common secure
  transport, entitlement, reliable-operation, diagnostics, and database
  contracts.
- Adds locked dependency provenance, artifact checksums, SBOM inventory,
  offline benchmark budgets, and built-wheel consumer validation.
