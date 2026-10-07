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

## 4. Application-owned status reconciliation

Business status preflight belongs to the application. It decides what its wire
states mean (for example `INGESTED` plus `VALID`), authenticates the response,
binds it to the institution and expected session, and obtains the authoritative
receipt. These business fields are not foundation `SessionState` values.
`ResumeDriver` has no business status hook and does not interpret them.

When a prior completion response was lost, the application can ask status for
the existing session instead of beginning or uploading again. A successful
status response or a part acknowledgement alone is insufficient. The local
manifest, queued operation, returned session, and final receipt must agree.
The application owns deletion of local bytes after queue confirmation; SQLite
`confirm()` itself knows no receipt and must never be called before verification.

The following application example is executed against the actual public
`IngestionService`, `ResumeDriver` validation and durable `SqliteOperationStore`
in `tests/test_upload_status_orchestration.py`. It is not a new library API or
evidence that an external application's migration has finished.

```python
from techflex_cloud_foundation import ResumeDriver, SessionState


async def reconcile_completed_upload(endpoint, session_id, manifest, queue, operation, *, now):
    if operation.payload_digest != manifest.digest():
        return None
    status = await endpoint.status(session_id, now=now)
    receipt = status.receipt
    if (
        status.session_id != session_id
        or status.state is not SessionState.COMPLETED
        or receipt is None
        or receipt.session_id != session_id
        or not ResumeDriver.may_retire_local(receipt, manifest)
    ):
        return None
    if not queue.confirm(operation.operation_id):
        return None
    return receipt
```

This path uses only `status`: zero `begin`, `list_parts`, `put_part` or `complete`
calls. Missing/mismatched receipts retain the lease and local bytes so the
application can defer/recover the operation according to its policy; a bare
HTTP 200 never grants local retirement. A confirmed operation is not a lease,
so a repeated queue confirmation cannot authorize a second deletion.

The public retirement predicate requires a receipt verified
under `content/1`, in addition to an exact manifest digest. This example uses
that public predicate rather than duplicating it. Contracts against the
integrated RAY-540 implementation verify that legacy or unknown profiles cannot
confirm or retire bytes. Fetching an immutable receipt from status reconciles
completion; it cannot upgrade an old unverified receipt. See the
[receipt migration guide](ingestion-content-verification.md) for adapter changes.

## Invariants

- HTTP 200, object write, DB commit, INGESTED, and "analysis done" are
  distinct facts — the queue tracks the operation, the server receipt is the
  only confirmation.
- Idempotency keys derive from the content digest, so retries after a crash
  re-present the same upload instead of duplicating it.
- Digests are always complete SHA-256; versions are refused, not guessed.
