# Changelog

All notable changes use Semantic Versioning. While the major version is `0`,
the public contract is not yet frozen: a breaking change advances the *minor*
version, as SemVer allows for `0.y.z`, and every one is marked **Breaking**
below so a consumer can find them all by reading the release. From `1.0.0`
onward, breaking public-contract changes require a new major version;
additive capability changes use a minor version; compatible security and
defect fixes use a patch version, and deprecated public interfaces remain for
at least one minor release before a later major removal.

## Unreleased

_Nothing yet; entries land here and move into the next release section._

## 0.2.0 - 2026-09-03

### Added

- Documents the full public exception hierarchy in
  `docs/boundaries-and-troubleshooting.md` (RAY-371 R2), and adds the four
  families the error catalogue never covered — `gateway` (with the stable
  `code` each error carries), `ingestion`, `bucket_catalog` and
  `product_registry`.  The tree also records why `TokenError` and
  `SealVerificationError` inherit `ValueError` while ten family bases inherit
  `Exception`, and why `KeyProviderUnavailable` is a `RuntimeError` rather
  than a validation failure.  `tests/test_diagnostics.py` parses that tree and
  checks it against the real `__bases__`, and fails when a new public
  exception is exported without a row — the same drift treatment
  `docs/api-reference.md` already gets.  It also asserts that no public
  callable anywhere in the package carries a mutable default.

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

- Adds `keystore.py`: the at-rest key boundary (`KeyProvider`,
  `KeyProviderUnavailable`, `FileKeyProvider`, `AesGcmBlobCodec` with
  context-bound AES-256-GCM envelopes), so keys are fetched per use and
  never persisted in databases or logs.

- Adds `sealed_store.py`: self-verifying sealed containers
  (`write_sealed`/`read_sealed`/`verify_sealed`, header-as-AAD, tamper
  quarantine via `quarantine_file`), exactly-once `MarkerRegistry`
  registration across crashes, and reversible delete windows
  (`reversible_delete`/`restore_delete`/`finalize_delete`).

- Adds `techflex_cloud_foundation.testing`: shared, pytest-free fault
  injection for durability tests — `SimulatedPowerLoss` (raise at a chosen
  call boundary), `short_write_os`, `interrupted_replace`, `fsync_failure`,
  `disk_full`, and `KillAndRecoverHarness` (kill a child mid-flight, then
  run the recovery path).  Each fault is a self-restoring context manager.

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

### Changed

- Consolidates the changelog and raises the version to `0.2.0`
  (RAY-372 R2).  Four separate `## Unreleased` headings had built up, one per
  merged branch, stacked above `## 0.1.1`; each is a valid heading, so nothing
  complained, and a reader scanning for what changed since `0.1.1` read the
  first block and stopped.  They are now the single categorised release
  section below.

- The versioning policy above now states the `0.y.z` rule explicitly.  The
  release carries breaking public-contract changes while the major version
  is `0`, which SemVer permits and the previous wording ("breaking changes
  require a new major version") flatly contradicted.  Each one is marked
  **Breaking** so they can be found by reading the release.

- Calibrates the performance gate aggregation (RAY-349 R2): timing rounds
  now aggregate with best-of-N (minimum) instead of the median — CPU
  benchmark noise only inflates a round, so the minimum records the
  quietest measurement without relaxing real-regression detection. Peak
  memory keeps the median.  Evidence JSON schema unchanged.

### Breaking

Every entry here changes a public contract. The policy above promises they
are findable by reading the release, which is why they are one subsection
rather than distributed among the modules they touch.

- `MarkerRegistry.begin` validates marker ids against a
  whitelist, `[A-Za-z0-9][A-Za-z0-9._-]*` (RAY-371 R2).  The previous check
  excluded only `/` and `..`, which let through backslash paths (a Windows
  directory separator), NUL bytes, and — worst — a leading dot: `pending()`
  globs `*.marker.json`, `*` does not match hidden files, so a `.session`
  marker existed on disk but was never replayed, silently turning
  exactly-once coupling into at-most-once.
- `LicenseLifecycle.transition` now enforces the license state
  machine as a whitelist (RAY-371 R2).  It previously refused exactly one
  thing — leaving REVOKED — and permitted every other ordered pair by
  omission.  `transition(record, ACTIVE)` on an UNUSED license returned an
  ACTIVE record with `tenant_id`, `account_id` and `hardware_id` all still
  `None`, because only `activate()` binds them; any move back to UNUSED kept
  those bindings on a record whose state means it has none.  The four legal
  moves are ACTIVE⇄SUSPENDED, ACTIVE→REVOKED and SUSPENDED→REVOKED; UNUSED
  is left only through `activate()`, REVOKED is terminal, and a state to
  itself is refused because each call increments `version`.  Every refusal
  carries a message naming the lifecycle rule it protects.  Adds
  `tests/test_entitlement.py` (the module had no test file), which
  enumerates all sixteen ordered pairs.
- `SecureTransport` can no longer be constructed without TLS
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

- `FileKeyProvider.get_key()` no longer generates a key when the key file is
  absent (RAY-370 R2). It raises the new `KeyNotProvisioned` -- a
  `KeyProviderUnavailable` subclass -- and provisioning moved to the new
  explicit `FileKeyProvider.create_key()`. The old behaviour turned the most
  consequential recoverable failure in a local-first system into a silent one:
  a restore that missed the key file left the application running normally on a
  brand-new key, and every existing ciphertext became an undiagnosable
  authentication failure. Callers that relied on lazy creation call
  `create_key()` once at provisioning time.
- `AesGcmBlobCodec.decrypt` raises the new `BlobDecryptionError` instead of
  letting `cryptography`'s `InvalidTag` escape. `sealed_store` already wrapped
  the identical failure as `SealVerificationError`, so one library reported one
  failure two ways and callers had to import from `cryptography` to catch half
  of them. Both are `ValueError` subclasses.

### Fixed

- `write_sealed` now quarantines a container that fails its post-write
  verification instead of deleting it (RAY-371 R2).  The module docstring
  already promised that corrupt artifacts are quarantined, not deleted, and
  the code did the opposite — destroying the only evidence distinguishing a
  failing disk from a filesystem that lied about a flush, without recovering
  the caller's position, since the failure is not in the caller's payload.
  New optional `quarantine_dir` parameter, defaulting to `.quarantine` beside
  the destination; the raised `SealVerificationError` names where the file
  went, and if the move itself fails the file is left in place and said so.

- `quarantine_file`, `reversible_delete` and `restore_delete` no longer check
  `exists()` and then `os.replace` (RAY-371 R2).  Between those two calls a
  second process could take the name just found free, and `os.replace`
  overwrites silently — in a quarantine or trash directory, overwriting the
  evidence that something already went wrong.  The destination name is now
  claimed with `os.link`, which succeeds or fails as one step.  A filesystem
  without hard links raises the new `SealAtomicityUnsupported` rather than
  falling back to the racy path.

- `create_key()` stages the key and publishes it with `os.link`, so concurrent
  first use returns the winner's key instead of raising an uncaught
  `FileExistsError`, and a loser never reads a key file that exists but is
  still empty. The parent directory is fsynced afterwards, without which the
  key file's directory entry could be lost to power failure while the key's own
  bytes were safely on disk.
- `StagedAtomicFileWriter` no longer closes a file descriptor it has already
  released (RAY-370 R2). `commit` closed the descriptor and then called
  `os.replace`; when the rename failed, the error path ran `_discard`, which
  closed the same number again. `os.close` raises `EBADF` only while the number
  is still free -- POSIX hands out the lowest available descriptor, so a thread
  that opened a file in between received that number and the second close shut
  *its* file instead. Ownership is now handed to a sentinel before the close
  call, so every path out of `commit` closes exactly once.
- `FileSystemObjectStore.put_verified` now publishes with `os.link` (RAY-370 R2).
  The previous `if final_path.exists(): ... else: os.replace(...)` left a window
  between the check and the write: two writers carrying different content could
  both find the key free, and the second `os.replace` silently overwrote the
  first writer's object while handing both callers a successful `StoredObject`.
  Linking collapses the check and the write into one operation the kernel
  resolves, so a key that exists is never replaced.
- A storage root that cannot hard-link now raises the new
  `ObjectStoreUnsupported` instead of falling back to a non-atomic publish.
- Replay verification streams the stored object in one-megabyte chunks instead
  of `read_bytes()`, so re-putting a large object no longer loads it into memory.
- `ImmutableObjectStore` documents what `delete` means on an immutable store and
  that `read` is bounded by available memory.
- Object keys are now validated by text rather than by resolving the joined
  path against the storage root (RAY-370 R2).  The old check compared a
  candidate resolved at call time against a root resolved in `__init__`; on
  Windows, `Path.resolve` stops expanding 8.3 short path components when a
  filesystem query fails, which concurrent creation in the same directory makes
  transient, so two writers racing on one key could have a valid key rejected as
  escaping the root.  Keys must now be `/`-separated ordinary names: an empty,
  `.`, or `..` component, a backslash, or a colon is rejected.  This also
  refuses `C:evil` and `object.bin:stream`, which the previous rules let
  through on Windows, and it refuses `./here`, `trailing/`, and `double//slash`,
  which the previous rules accepted and normalized away.
- Unifies the token error contract (RAY-369 R2). `HmacTokenCodec.verify`
  raised two errors that were not `TokenError` at all: a bare
  `UnicodeEncodeError` for any token containing a non-ASCII character, from
  the `.encode("ascii")` that builds the signing input, and a bare
  `ValueError`/`TypeError` from `int(exp)` for a signature-valid token whose
  `exp` claim is not a number. Both are `TokenMalformed` now, matching the
  wrong-segment-count and bad-base64url cases that already reported it. No
  token that verified before verifies differently.
- Fixes `connect_durable(":memory:")` (RAY-369 R2), which raised
  `FileNotFoundError: ':memory:'` instead of returning a connection. The
  owner-only file mode was applied whenever the path did not already exist,
  which is exactly what an in-memory database looks like. The mode is now
  applied only to a newly created file on disk. The docstring records that
  SQLite keeps `journal_mode=MEMORY` for an in-memory database whatever the
  policy requests, so it is not a durability substitute.
- Repairs and bounds the hash-chained audit log (RAY-369 R2), in
  `ChainedAppendLog`:
  - Startup recovery left any unterminated final line in place whenever it
    still parsed as JSON, so the next append concatenated onto it and the whole
    generation became unverifiable from that line onward. Recovery now checks
    the record: a complete one with a correct digest that chains onto its
    predecessor is completed with its newline and kept, and anything else is
    truncated as a torn write.
  - Appending re-read and split the entire active generation to find the chain
    tail, making each append O(n) in the generation's length. The tail digest
    is cached, keyed on the active file's identity so another process's append
    or a rotation still invalidates it; a miss reads only the end of the file.
  - Adds `ChainedAppendLog.head_digest()`, the digest of the oldest surviving
    record, for callers to anchor outside the log directory. Nothing inside the
    directory can detect its wholesale replacement by a self-consistent
    forgery. `docs/boundaries-and-troubleshooting.md` gains an audit-log trust
    boundary section covering the anchor, what rotation does to it, and the
    fact that recovery can drop a record whose `append()` had returned.
- Hardens the durable operation store (RAY-369 R2). Four defects, all in
  `SqliteOperationStore` and `RetryPolicy`:
  - Retry backoff built the full `base_delay * 2 ** (attempt_count - 1)`
    product before clamping it to `cap_delay`, so a queue that never drains
    raised `OverflowError` from attempt 45 onward instead of retrying at the
    cap. The exponent is now clamped first; `RetryPolicy.delay_for` exposes
    the delay on its own.
  - `enqueue` used `INSERT OR IGNORE`, which cannot tell a safe retry from an
    idempotency-key collision. Reusing a key for different content now raises
    the new `OperationConflict` instead of returning success with nothing
    queued; re-enqueuing identical content stays a no-op.
  - `lease_due` selected the due row and claimed it in two statements, with no
    write lock held in between, so two workers on one database could lease the
    same operation. It is now a single conditional `UPDATE ... RETURNING`.
  - `defer`, `confirm`, `block`, and `mark_conflict` returned `None` whether or
    not their state guard held. They now return `bool`, matching
    `block_interrupted_leases`, which already returned a count. This widens the
    return type and does not change any existing call.
- Adds a merge-freshness check to CI (RAY-368 R2): a pull request now fails
  when its branch does not already contain the base tip.  A `pull_request` run
  validates the merge of the branch with the base as it stood when the run
  started, and nothing re-tests it if the base advances, so a PR can be green
  against a base that no longer exists.  `main` went red on merge three times
  that way.  The check produces the signal only; making it binding also
  requires marking it required in branch protection, which is a repository
  settings change and is not made from the workflow.
- Stops the release-evidence performance gate from failing on hosted-runner
  jitter (RAY-368 R2): the p95 budget now requires a regression to clear both
  the 5% relative threshold and a 100us absolute floor.  At the sub-millisecond
  p95 this benchmark records, scheduler jitter alone spans tens of
  microseconds, so the relative term fired on noise — the macOS job on
  `d6416b7` failed at ratio 1.082 over a 35us gap, and the re-measurement
  reproduced it.  Larger baselines stay governed by the 5% term; the peak
  memory budget is unchanged.
- `AuditSink.record` declares `fields: Mapping[str, int | str] | None = None`
  instead of a `{}` default (RAY-371 R2).  A Protocol's signature is copied
  into every implementation, so the literal became one dict shared across all
  calls to each implementing method — while the annotation says `Mapping`,
  which is exactly the promise that stops an implementer from wondering
  whether mutating it is safe.  An implementation that enriched the argument
  or stored it would leak fields between audited events, silently and only
  under load.  Implementations should accept `None` as "no additional
  fields".

- Stabilizes the release-evidence performance gate (RAY-349): the benchmark
  now measures process CPU time instead of wall-clock time so CI runner
  descheduling no longer appears as a fake P95 regression, the budget check
  re-measures once with diagnostics before failing, and budget errors now
  report the measured values and ratio.  Evidence JSON schema is unchanged.

## 0.1.1 - 2026-08-25

- First private, independently buildable distribution of the common secure
  transport, entitlement, reliable-operation, diagnostics, and database
  contracts.
- Adds locked dependency provenance, artifact checksums, SBOM inventory,
  offline benchmark budgets, and built-wheel consumer validation.
