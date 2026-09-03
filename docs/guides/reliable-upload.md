# Guide: Reliable Upload & Background Queue

Modules: `reliability`, `manifest`, `object_store`.
Reference tests: `tests/test_public_contracts.py`, `tests/test_manifest.py`,
`tests/test_object_store.py`.

## When to use

Uploading artifacts to the cloud in the presence of crashes, network loss,
and retries — the path from "payload staged locally" to "server confirmed".

## 1. Describe the payload: content-addressed manifest

`ArtifactManifest` commits to every byte via complete SHA-256 digests.
`manifest.digest()` — SHA-256 of the canonical bytes — is the artifact's own
address (`tests/test_manifest.py`):

```python
from techflex_cloud_foundation import ArtifactEntry, ArtifactManifest, verify_entry_payload

manifest = ArtifactManifest(
    entries=(ArtifactEntry(path="payload.bin", size=len(payload), sha256=sha256_of(payload)),),
    artifact_kind="example.measurement",
)
verify_entry_payload(manifest.entries[0], [payload])   # raises ManifestIntegrityError on mismatch
artifact_address = manifest.digest()
```

Rules enforced by construction: complete 64-hex digests only (prefixes never
carry security integrity), entry paths relative and contained, unknown
format/schema versions refused (`ManifestVersionUnsupported`), canonical
bytes reproducible.

## 2. Queue the upload as a reliable operation

`SqliteOperationStore` persists operations locally; `ReliableOperation.create`
requires kind, payload reference, full digest, and an idempotency key. Lease
interrupted operations are recovered to READY on restart
(`test_operation_store_recovers_only_interrupted_leases` in
`tests/test_public_contracts.py`):

```python
from techflex_cloud_foundation import ReliableOperation, SqliteOperationStore

store = SqliteOperationStore("operations.sqlite3")
operation = ReliableOperation.create(
    kind="example.upload",
    payload_ref="spool/session-1",
    payload_digest=manifest.digest(),
    idempotency_key=f"example:{manifest.digest()}",
)
store.enqueue(operation)
```

Worker loop: `lease_due(now=...)` → attempt → complete or
`mark_conflict`/`mark_*` with an error code. `RetryPolicy` computes backoff;
a server-supplied `Retry-After` is honoured even beyond the deadline
(`test_retry_policy_keeps_server_retry_after_deadline`).

## 3. Stage objects: immutable object store contract

`ImmutableObjectStore` is the provider-neutral contract; the library ships
`InMemoryObjectStore` (tests) and `FileSystemObjectStore` (local staging).
Both share one contract test suite (`tests/test_object_store.py`), which is
the spec:

- `put_verified(key, chunks, expected_sha256=..., expected_size=...)`
  streams and verifies digest and size; mismatch raises
  `ObjectDigestMismatch` / `ObjectSizeMismatch`.
- Same key + same content is idempotent; same key + different content raises
  `ObjectConflict`. Raw artifacts are never silently overwritten.
- Keys are relative and contained; absolute paths and traversal are refused.

## Invariants

- HTTP 200, object write, DB commit, INGESTED, and "analysis done" are
  distinct facts — the queue tracks the operation, the server receipt is the
  only confirmation.
- Idempotency keys derive from the content digest, so retries after a crash
  re-present the same upload instead of duplicating it.
- Digests are always complete SHA-256; versions are refused, not guessed.
