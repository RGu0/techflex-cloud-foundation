# Changelog

All notable changes use Semantic Versioning. Breaking public-contract changes
require a new major version; additive capability changes use a minor version;
compatible security and defect fixes use a patch version. Deprecated public
interfaces remain for at least one minor release before a later major removal.

## Unreleased

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

## 0.1.1 - 2026-08-25

- First private, independently buildable distribution of the common secure
  transport, entitlement, reliable-operation, diagnostics, and database
  contracts.
- Adds locked dependency provenance, artifact checksums, SBOM inventory,
  offline benchmark budgets, and built-wheel consumer validation.
