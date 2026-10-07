# Stored content verification and receipt migration

RAY-540 introduces a **Breaking** ingestion contract. A completion receipt
proves the original uploaded bytes only when `verification_version` is
`content/1`. Receipt delivery, a part acknowledgement, and an HTTP success
are separate facts. The profile does not prove business eligibility beyond
the application's supplied decision, nor permanent future availability.

## Mapping uploaded slots to entries

Declare `annotations["ingestion_mapping"] = "entry-parts/1"` in the
`ArtifactManifest`. This annotation participates in its canonical digest.
Keep entries in their original order. Within each entry, explicitly list
parts with local indices 0..k-1 and offsets starting at zero and increasing
by the preceding part's size. Ranges must cover the entry exactly. Positive
entries use only positive-size parts. A zero-byte entry uses exactly one
zero-byte part with the SHA-256 of empty bytes. At least one entry is needed.

Upload global index equals the number of parts in preceding entries plus
this part's local index: A parts 0,1 map to slots 0,1; B part 0 maps to slot 2.
Do not sort entries by path or globally reuse local indices. The total part
count and stored index set must match the session exactly. Unknown mapping
profiles, holes, overlaps, duplicate indices and ambiguous declarations fail.

An unmarked legacy manifest is accepted only for one entry and one session
slot. Its parts may be absent (the entry defines the whole slot), or one
explicit part may cover the entire entry. Legacy multipart manifests must
adopt the mapping annotation; already uploaded bytes can be reused if they
match this order, otherwise use a new session.

## Verification, failure and replay

`complete` authenticates, validates eligibility and the manifest digest,
checks mapping, then sequentially streams actual stored bytes. One pass
checks each part's real length/SHA-256 and each concatenated entry's real
length/SHA-256. No decryption or re-encoding occurs. Only after every check
passes may it publish the manifest and atomically finalize the receipt.
Declaration/content conflicts do not permanently quarantine valid stored
parts; a conflicting PUT retains its existing quarantine behavior. Missing
objects and read failures never issue a receipt.

The session store's new `finalize(..., expected_parts=...)` method must lock
the session transaction, recheck quarantine and the exact verified slot
snapshot, and atomically commit/replay the sole immutable receipt. The
in-memory reference has no yield inside its final commit step. Concurrent
same-content completions return the first committed receipt, including its
original time and idempotency key. Response-loss retries replay that receipt.

Object-storage adapters must implement `read_chunks`; whole-object `read`
remains available. Built-in adapters read in 1 MiB chunks. Completion incurs
one extra read of the payload and keeps one chunk plus hashing/manifest state
in working memory. The in-memory adapter still stores all objects in RAM.

**Lifecycle responsibility:** read_chunks and finalize do not provide a
cross-object retention lock. The application and its storage adapter must
prevent deletion/replacement of the session's objects from the first
verification read through finalization (for example, exclude active sessions
from retention and hold a session lifecycle lock). This includes the built-in
adapters: do not concurrently call their `delete` during completion. A raw
object delete-and-republish violates this assumption; it cannot be repaired
by a session database transaction alone. After completion, application
retention governs availability. Never treat a receipt as a perpetual pin.

## Old receipts and consumer rollout

The optional `verification_version` is omitted entirely when None, preserving
historical canonical bytes and digest. New `content/1` includes the field in
canonical bytes/digest. `status` returns old receipts unchanged; `complete`
rejects historical missing/unknown verification versions, without upgrading
or overwriting them. Use a new session for a new proof. A `content/1` receipt
with matching digest and non-conflicting idempotency conditions is replayed
without reading all payload bytes again.

`ResumeDriver.may_retire_local` requires both `content/1` and this manifest's
full digest. Missing/unknown versions return False. All consumers responsible
for local deletion must deploy this gate before relying on the new service;
old clients that ignore this field remain unsafe. Inventory every external
object-store/session-store adapter and update its streaming/finalization
protocol. Cross-language parsers must preserve the optional field and reject
unknown versions for retirement. No external application deployment is
performed by this repository's implementation.

Portable examples and canonical SHA-256 values are in
[ingestion-content-vectors.json](../contracts/ingestion-content-vectors.json).
Python executes these fixtures against the real service; another-language
execution belongs to that consumer's own authorized delivery.
