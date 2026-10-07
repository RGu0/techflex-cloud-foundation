"""Business-neutral artifact ingestion plane (CP-06).

The receive skeleton for uploaded artifacts: a session state machine
(``begin`` → ``put_part`` … → ``complete``), resumable part tracking with
``list_parts``/``status``, and a final immutable receipt.  It composes the
foundation's content-verified object store and manifest contracts without
binding any product DTO, quality judgment, database, or cloud SDK.

Invariants carried over from RAY-341 and the reference implementation:

- HTTP 200, object write, and the final receipt are different facts; only
  ``complete`` issues an `ArtifactReceipt`, and it is immutable.
- Same content replays idempotently; same slot with different content is a
  conflict and the slot is quarantined — originals are never silently
  overwritten.
- A session pins one payload schema; unknown versions are refused, never
  guessed, and a part that disagrees with its session is refused.
- The foundation never decides whether a payload is VALID or INVALID:
  ``complete`` requires the application to supply an `EligibilityDecision`
  it made itself.
- Object keys are derived server-side from the trusted tenant context and
  the session id; the client never chooses bucket, tenant, or key.
- tenant comes only from the authenticated principal; nothing in a request
  payload can select it.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib
import json
from typing import Any, Protocol
from uuid import UUID, uuid4

from .lifecycle import EligibilityDecision
from .manifest import ArtifactManifest, ArtifactPart, _require_digest, _require_text
from .object_store import ImmutableObjectStore, ObjectStoreError


class IngestionError(Exception):
    """Base class for ingestion plane failures."""


class IngestionMalformed(IngestionError):
    """A request or record is structurally invalid."""


class IngestionSchemaUnsupported(IngestionError):
    """The declared payload schema version is not served by this deployment."""


class IngestionConflict(IngestionError):
    """A slot or idempotency key already holds different content."""


class IngestionStateError(IngestionError):
    """The session state does not allow this operation."""


class IngestionAccessDenied(IngestionError):
    """The principal may not perform this operation."""


class IngestionEligibilityRejected(IngestionError):
    """Completion was attempted without an allowing eligibility decision."""


def _require_aware(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None:
        raise IngestionMalformed(f"{field_name} must be timezone-aware")


class SessionState(StrEnum):
    OPEN = "open"
    COMPLETED = "completed"


@dataclass(frozen=True)
class IngestionPrincipal:
    """Narrow data-plane principal derived from trusted authentication."""

    tenant_id: str
    uploader_id: str
    allow_upload: bool
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.uploader_id, field_name="uploader id")
        if not isinstance(self.allow_upload, bool):
            raise IngestionMalformed("allow_upload must be a boolean")
        _require_aware(self.expires_at, field_name="expires_at")

    def ensure_can_upload(self, now: datetime) -> None:
        _require_aware(now, field_name="now")
        if self.expires_at <= now:
            raise IngestionAccessDenied("data access credential has expired")
        if not self.allow_upload:
            raise IngestionAccessDenied("this principal is not allowed to upload")


@dataclass(frozen=True)
class PartMetadata:
    """Client-declared facts about one part; verified against actual bytes."""

    index: int
    sha256: str
    size: int
    payload_schema: str

    def __post_init__(self) -> None:
        if not isinstance(self.index, int) or isinstance(self.index, bool) or self.index < 0:
            raise IngestionMalformed("part index must be a non-negative integer")
        _require_digest(self.sha256, field_name="part sha256")
        if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size < 0:
            raise IngestionMalformed("part size must be a non-negative integer")
        _require_text(self.payload_schema, field_name="part payload schema")


@dataclass(frozen=True)
class PartAcknowledgement:
    """Per-part receipt; a part ack is not session completion."""

    session_id: UUID
    index: int
    sha256: str
    object_key: str
    idempotent_replay: bool = False


@dataclass(frozen=True)
class PartListResponse:
    session_id: UUID
    received: tuple[PartAcknowledgement, ...]
    missing: tuple[int, ...]


@dataclass(frozen=True)
class ArtifactReceipt:
    """The final, immutable completion receipt for one ingestion session."""

    session_id: UUID
    manifest_digest: str
    manifest_object_key: str
    eligibility_reason: str
    eligibility_policy_version: str
    completed_at: datetime
    idempotency_key: str
    verification_version: str | None = None

    def __post_init__(self) -> None:
        _require_digest(self.manifest_digest, field_name="manifest digest")
        _require_text(self.manifest_object_key, field_name="manifest object key")
        _require_text(self.eligibility_reason, field_name="eligibility reason")
        _require_text(self.eligibility_policy_version, field_name="eligibility policy version")
        _require_aware(self.completed_at, field_name="completed_at")
        _require_text(self.idempotency_key, field_name="idempotency key")
        if self.verification_version is not None:
            _require_text(self.verification_version, field_name="verification version")

    def canonical_bytes(self) -> bytes:
        document = {
            "completed_at": self.completed_at.isoformat(),
            "eligibility_policy_version": self.eligibility_policy_version,
            "eligibility_reason": self.eligibility_reason,
            "idempotency_key": self.idempotency_key,
            "manifest_digest": self.manifest_digest,
            "manifest_object_key": self.manifest_object_key,
            "session_id": str(self.session_id),
        }
        if self.verification_version is not None:
            document["verification_version"] = self.verification_version
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class SessionStatus:
    session_id: UUID
    state: SessionState
    payload_schema: str
    part_count: int
    received_count: int
    conflicted_indices: tuple[int, ...]
    receipt: ArtifactReceipt | None


@dataclass
class _SessionRecord:
    tenant_id: str
    session_id: UUID
    payload_schema: str
    part_count: int
    begin_key: str
    begin_request_digest: str
    parts: dict[int, PartAcknowledgement]
    conflicted: set[int]
    receipt: ArtifactReceipt | None = None
    completion_keys: dict[str, str] | None = None

    @property
    def state(self) -> SessionState:
        return SessionState.COMPLETED if self.receipt is not None else SessionState.OPEN


class IngestionSessionStore(Protocol):
    """Persistence boundary; production binds PostgreSQL, tests use memory."""

    async def get(self, tenant_id: str, session_id: UUID) -> _SessionRecord: ...

    async def find_by_begin_key(self, tenant_id: str, begin_key: str) -> _SessionRecord | None: ...

    async def insert(self, record: _SessionRecord) -> None: ...

    async def finalize(
        self,
        tenant_id: str,
        session_id: UUID,
        receipt: ArtifactReceipt,
        *,
        expected_parts: tuple[PartAcknowledgement, ...],
    ) -> ArtifactReceipt:
        """Atomically refuse conflicts or commit/replay the sole final receipt.

        Production adapters lock the session and check its quarantine, current
        receipt, completion-key digest and exact verified part snapshot before
        commit, using the transaction that persists the receipt. Concurrent same-content calls
        return the previously committed receipt unchanged.
        """
        ...


class InMemoryIngestionStore:
    """Volatile reference store, suitable for tests and integration runs."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, UUID], _SessionRecord] = {}

    async def get(self, tenant_id: str, session_id: UUID) -> _SessionRecord:
        try:
            return self._records[(tenant_id, session_id)]
        except KeyError:
            raise IngestionMalformed(f"unknown session {session_id} for this tenant") from None

    async def find_by_begin_key(self, tenant_id: str, begin_key: str) -> _SessionRecord | None:
        for (tenant, _), record in self._records.items():
            if tenant == tenant_id and record.begin_key == begin_key:
                return record
        return None

    async def insert(self, record: _SessionRecord) -> None:
        key = (record.tenant_id, record.session_id)
        if key in self._records:
            raise IngestionConflict(f"session {record.session_id} already exists")
        self._records[key] = record

    async def finalize(
        self,
        tenant_id: str,
        session_id: UUID,
        receipt: ArtifactReceipt,
        *,
        expected_parts: tuple[PartAcknowledgement, ...],
    ) -> ArtifactReceipt:
        record = await self.get(tenant_id, session_id)
        # No await after lookup: this reference implementation commits as one
        # event-loop step. Persistent adapters require a database transaction.
        if record.conflicted:
            raise IngestionStateError("session has quarantined parts; cannot complete")
        current = _completion_replay(record, receipt.manifest_digest, receipt.idempotency_key)
        if current is not None:
            return current
        if (
            len(expected_parts) != record.part_count
            or set(record.parts) != set(range(record.part_count))
            or any(record.parts[part.index] != part for part in expected_parts)
        ):
            raise IngestionStateError("verified part snapshot changed before finalization")
        record.receipt = receipt
        if record.completion_keys is None:
            record.completion_keys = {}
        record.completion_keys[receipt.idempotency_key] = receipt.manifest_digest
        return receipt


def _completion_replay(session: _SessionRecord, digest: str, key: str) -> ArtifactReceipt | None:
    if session.completion_keys and key in session.completion_keys:
        if session.completion_keys[key] != digest:
            raise IngestionConflict("completion idempotency key used with a different manifest")
    receipt = session.receipt
    if receipt is None:
        return None
    if receipt.verification_version != "content/1":
        raise IngestionStateError("historical_receipt_unverified: verification version unsupported")
    if receipt.manifest_digest != digest:
        raise IngestionConflict("completed sessions are immutable; different manifest")
    return receipt


def _mapped_parts(
    manifest: ArtifactManifest, part_count: int
) -> tuple[tuple[ArtifactPart, ...], ...]:
    """Validate original entry order and contiguous local ranges; never sort."""
    mapping = manifest.annotations.get("ingestion_mapping")
    if mapping not in (None, "entry-parts/1"):
        raise IngestionMalformed("unknown ingestion mapping")
    if not manifest.entries:
        raise IngestionMalformed("ingestion requires at least one entry")
    if mapping is None and (len(manifest.entries) != 1 or part_count != 1):
        raise IngestionMalformed("legacy ingestion requires one entry and one slot")
    result = []
    for entry in manifest.entries:
        parts = entry.parts
        if not parts and mapping is None:
            parts = (ArtifactPart(0, 0, entry.size, entry.sha256),)
        if not parts:
            raise IngestionMalformed("entry-parts/1 requires explicit parts")
        if entry.size == 0 and len(parts) != 1:
            raise IngestionMalformed("empty entry requires exactly one empty part")
        offset = 0
        for index, part in enumerate(parts):
            if part.index != index or part.offset != offset:
                raise IngestionMalformed("entry parts must have contiguous indices and offsets")
            if entry.size > 0 and part.size == 0:
                raise IngestionMalformed("nonempty entry requires positive-size parts")
            if entry.size == 0 and part.sha256 != hashlib.sha256(b"").hexdigest():
                raise IngestionMalformed("empty part must declare the empty digest")
            offset += part.size
        if offset != entry.size:
            raise IngestionMalformed("entry parts must completely cover the entry")
        result.append(parts)
    if sum(len(parts) for parts in result) != part_count:
        raise IngestionMalformed("mapped part count differs from session")
    return tuple(result)


def _request_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class IngestionService:
    """Orchestrates sessions, verified parts, and the final receipt."""

    def __init__(
        self,
        objects: ImmutableObjectStore,
        sessions: IngestionSessionStore,
        *,
        supported_payload_schemas: frozenset[str],
    ) -> None:
        if not supported_payload_schemas:
            raise IngestionMalformed("at least one supported payload schema is required")
        self._objects = objects
        self._sessions = sessions
        self._payload_schemas = supported_payload_schemas

    @staticmethod
    def _part_key(tenant_id: str, session_id: UUID, index: int) -> str:
        return f"{tenant_id}/{session_id}/parts/{index:06d}"

    @staticmethod
    def _manifest_key(tenant_id: str, session_id: UUID) -> str:
        return f"{tenant_id}/{session_id}/manifest"

    def _require_schema(self, schema: str) -> None:
        if schema not in self._payload_schemas:
            raise IngestionSchemaUnsupported(
                f"payload schema {schema!r} is not supported by this deployment; "
                "unknown versions are refused, never guessed"
            )

    async def begin_session(
        self,
        principal: IngestionPrincipal,
        *,
        payload_schema: str,
        part_count: int,
        idempotency_key: str,
        now: datetime,
    ) -> tuple[UUID, bool]:
        """Open a session; the same key with the same request replays."""
        principal.ensure_can_upload(now)
        _require_text(payload_schema, field_name="payload schema")
        self._require_schema(payload_schema)
        _require_text(idempotency_key, field_name="idempotency key")
        if not isinstance(part_count, int) or isinstance(part_count, bool) or part_count <= 0:
            raise IngestionMalformed("part count must be a positive integer")
        request_digest = _request_digest(
            {"part_count": part_count, "payload_schema": payload_schema}
        )
        existing = await self._sessions.find_by_begin_key(principal.tenant_id, idempotency_key)
        if existing is not None:
            if existing.begin_request_digest != request_digest:
                raise IngestionConflict("idempotency key was already used with a different request")
            return existing.session_id, True
        record = _SessionRecord(
            tenant_id=principal.tenant_id,
            session_id=uuid4(),
            payload_schema=payload_schema,
            part_count=part_count,
            begin_key=idempotency_key,
            begin_request_digest=request_digest,
            parts={},
            conflicted=set(),
            completion_keys={},
        )
        await self._sessions.insert(record)
        return record.session_id, False

    async def put_part(
        self,
        principal: IngestionPrincipal,
        session_id: UUID,
        metadata: PartMetadata,
        chunks: AsyncIterable[bytes],
        *,
        now: datetime,
    ) -> PartAcknowledgement:
        principal.ensure_can_upload(now)
        session = await self._sessions.get(principal.tenant_id, session_id)
        if session.state is SessionState.COMPLETED:
            raise IngestionStateError("completed sessions are immutable")
        if metadata.index in session.conflicted:
            raise IngestionConflict(f"part index {metadata.index} is quarantined after a conflict")
        if metadata.index >= session.part_count:
            raise IngestionMalformed(
                f"part index {metadata.index} exceeds the declared part count {session.part_count}"
            )
        self._require_schema(metadata.payload_schema)
        if metadata.payload_schema != session.payload_schema:
            raise IngestionSchemaUnsupported(
                "part schema disagrees with the schema pinned at begin"
            )
        existing = session.parts.get(metadata.index)
        if existing is not None:
            if existing.sha256 != metadata.sha256 or existing.index != metadata.index:
                session.conflicted.add(metadata.index)
                raise IngestionConflict(
                    f"part index {metadata.index} already holds different content; "
                    "the slot is quarantined"
                )
            return PartAcknowledgement(
                session_id=session_id,
                index=metadata.index,
                sha256=metadata.sha256,
                object_key=existing.object_key,
                idempotent_replay=True,
            )
        object_key = self._part_key(principal.tenant_id, session_id, metadata.index)
        try:
            await self._objects.put_verified(
                object_key,
                chunks,
                expected_sha256=metadata.sha256,
                expected_size=metadata.size,
            )
        except ObjectStoreError:
            raise
        ack = PartAcknowledgement(
            session_id=session_id,
            index=metadata.index,
            sha256=metadata.sha256,
            object_key=object_key,
        )
        session.parts[metadata.index] = ack
        return ack

    async def list_parts(
        self, principal: IngestionPrincipal, session_id: UUID, *, now: datetime
    ) -> PartListResponse:
        principal.ensure_can_upload(now)
        session = await self._sessions.get(principal.tenant_id, session_id)
        received = tuple(session.parts[index] for index in sorted(session.parts))
        missing = tuple(
            index
            for index in range(session.part_count)
            if index not in session.parts and index not in session.conflicted
        )
        return PartListResponse(session_id=session_id, received=received, missing=missing)

    async def complete(
        self,
        principal: IngestionPrincipal,
        session_id: UUID,
        *,
        manifest: ArtifactManifest,
        expected_manifest_digest: str,
        eligibility: EligibilityDecision,
        idempotency_key: str,
        now: datetime,
    ) -> ArtifactReceipt:
        """Finalize a session and issue the one immutable receipt."""
        principal.ensure_can_upload(now)
        _require_digest(expected_manifest_digest, field_name="expected manifest digest")
        _require_text(idempotency_key, field_name="idempotency key")
        if not isinstance(eligibility, EligibilityDecision):
            raise IngestionMalformed(
                "completion requires an EligibilityDecision made by the application"
            )
        if not eligibility.allowed:
            raise IngestionEligibilityRejected(
                f"the application's eligibility decision refuses completion: {eligibility.reason}"
            )
        if not isinstance(manifest, ArtifactManifest):
            raise IngestionMalformed("manifest must be an ArtifactManifest")
        actual_digest = manifest.digest()
        if actual_digest != expected_manifest_digest:
            raise IngestionMalformed(
                f"manifest digest {actual_digest} differs from the declared "
                f"{expected_manifest_digest}"
            )
        session = await self._sessions.get(principal.tenant_id, session_id)
        mapped = _mapped_parts(manifest, session.part_count)
        replay = _completion_replay(session, actual_digest, idempotency_key)
        if replay is not None:
            return replay
        if session.conflicted:
            raise IngestionStateError(
                f"session has quarantined part(s) {sorted(session.conflicted)}; "
                "it can never complete"
            )
        missing = [index for index in range(session.part_count) if index not in session.parts]
        if missing:
            raise IngestionStateError(f"session is incomplete; missing part indices {missing}")
        if set(session.parts) != set(range(session.part_count)):
            raise IngestionStateError("stored part indices differ from mapped slots")
        verified_parts = tuple(session.parts[index] for index in range(session.part_count))
        global_index = 0
        for entry, parts in zip(manifest.entries, mapped, strict=True):
            entry_digest = hashlib.sha256()
            entry_size = 0
            for part in parts:
                ack = verified_parts[global_index]
                if ack.sha256 != part.sha256:
                    raise IngestionConflict("manifest part digest differs from stored slot")
                part_digest = hashlib.sha256()
                part_size = 0
                async for chunk in self._objects.read_chunks(ack.object_key):
                    part_size += len(chunk)
                    if part_size > part.size:
                        raise IngestionConflict("stored part size exceeds manifest")
                    part_digest.update(chunk)
                    entry_digest.update(chunk)
                    entry_size += len(chunk)
                if part_size != part.size or part_digest.hexdigest() != part.sha256:
                    raise IngestionConflict("stored part content differs from manifest")
                global_index += 1
            if entry_size != entry.size or entry_digest.hexdigest() != entry.sha256:
                raise IngestionConflict("stored entry content differs from manifest")
        manifest_key = self._manifest_key(principal.tenant_id, session_id)
        manifest_bytes = manifest.to_canonical_bytes()

        async def _once() -> AsyncIterable[bytes]:
            yield manifest_bytes

        await self._objects.put_verified(
            manifest_key,
            _once(),
            expected_sha256=actual_digest,
            expected_size=len(manifest_bytes),
        )
        receipt = ArtifactReceipt(
            session_id=session_id,
            manifest_digest=actual_digest,
            manifest_object_key=manifest_key,
            eligibility_reason=eligibility.reason,
            eligibility_policy_version=eligibility.policy_version,
            completed_at=now,
            idempotency_key=idempotency_key,
            verification_version="content/1",
        )
        return await self._sessions.finalize(
            principal.tenant_id, session_id, receipt, expected_parts=verified_parts
        )

    async def status(
        self, principal: IngestionPrincipal, session_id: UUID, *, now: datetime
    ) -> SessionStatus:
        principal.ensure_can_upload(now)
        session = await self._sessions.get(principal.tenant_id, session_id)
        return SessionStatus(
            session_id=session_id,
            state=session.state,
            payload_schema=session.payload_schema,
            part_count=session.part_count,
            received_count=len(session.parts),
            conflicted_indices=tuple(sorted(session.conflicted)),
            receipt=session.receipt,
        )
