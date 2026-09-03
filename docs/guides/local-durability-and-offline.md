# Guide: Local Durability & Offline Operation

Modules: `durability`, `local_sqlite`, `keystore`, `sealed_store`.
Reference tests: `tests/test_durability.py`, `tests/test_local_sqlite.py`,
`tests/test_sealed_store.py`, `tests/test_testing_fixtures.py`.

## When to use

Anything the client must not lose: staged payloads, local state databases,
key material, and data that must survive a crash or power cut at any point.

## 1. Crash-safe file writes

`atomic_write(destination, payload)` stages to an `O_EXCL` temp file in the
same directory, fsyncs, atomically renames, then fsyncs the directory. A
crash leaves either the old file or the new file, never a partial one.
Destination files are created owner-only (`0o600`) by default
(`tests/test_durability.py`).

For streaming, use the `AtomicFileWriter` protocol; the default
implementation is `StagedAtomicFileWriter` (`write` → `commit`/`abort`).

## 2. Durable local state

`connect_durable(path)` opens SQLite with the durability policy applied:
WAL journal, `synchronous=FULL`, foreign keys on, busy timeout, file mode
`0o600` (`tests/test_local_sqlite.py`). Verify at startup:

```python
from techflex_cloud_foundation import connect_durable, inspect_durability

connection = connect_durable("state.sqlite3")
status = inspect_durability(connection)
assert status.journal_mode == "WAL"
```

Schema evolution uses `UserVersionMigrator` with ordered `Migration` steps;
the migrator refuses gaps and downgrades instead of guessing.

## 3. Local key material

`FileKeyProvider(key_file)` yields a 32-byte key, creating the file
atomically with owner-only permissions on first use
(`src/techflex_cloud_foundation/keystore.py`). `KeyProviderUnavailable` is
raised when the key cannot be obtained — handle it as "user intervention
required", not as a retryable error.

## 4. Sealed artifacts at rest

`write_sealed` encrypts a payload with AES-256-GCM, binding the header as
authenticated data; `read_sealed` verifies before decrypting and raises
`SealVerificationError` on any tamper (`tests/test_sealed_store.py`):

```python
from techflex_cloud_foundation import AesGcmSealEncryptor, FileKeyProvider, read_sealed, write_sealed

encryptor = AesGcmSealEncryptor(FileKeyProvider("local.key"))
write_sealed("payload.sealed", payload, header={"artifact_digest": digest}, encryptor=encryptor)
header, plaintext = read_sealed("payload.sealed", encryptor)
```

Deletion is deliberate: `reversible_delete` (quarantine), `finalize_delete`,
`restore_delete`; `quarantine_file` isolates suspect files. Exactly-once
coupling between a filesystem action and its bookkeeping is what
`MarkerRegistry` is for (`begin` writes a durable marker *before* the risky
action; leftover markers at startup must be replayed).

## 5. Prove it: fault injection

`techflex_cloud_foundation.testing` ships the harness the library's own
durability guarantees are tested with: `short_write_os`, `interrupted_replace`,
`fsync_failure`, `disk_full`, `SimulatedPowerLoss`, and the
`KillAndRecoverHarness` subprocess killer
(`tests/test_testing_fixtures.py`). Use them in your application's tests to
prove *your* crash windows are covered.

## Invariants

- No partial final files, ever; crash windows are closed by ordering
  (fsync file → rename → fsync directory).
- Local databases are WAL + FULL sync + owner-only.
- Sealed containers are verified before decryption; tamper is an exception,
  never wrong bytes.
- Recovery replays bookkeeping exactly once via markers.
