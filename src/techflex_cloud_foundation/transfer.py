"""Client-side resumable artifact transfer driver (PRD F-29, RAY-425 R2).

The server-side ingestion plane (``ingestion.py``) owns sessions, conflicts,
and the immutable receipt.  This module is the client half: given local
parts and a remote ``TransferEndpoint``, it resumes instead of restarting,
retries only transient failures, and treats the returned
``ingestion.ArtifactReceipt`` as the *only* credential that lets the caller
retire local bytes under normal policy.  The driver itself never deletes
anything.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from .ingestion import (
    ArtifactReceipt,
    PartAcknowledgement,
    PartListResponse,
    PartMetadata,
    SessionStatus,
)
from .lifecycle import EligibilityDecision
from .manifest import ArtifactManifest


class TransferError(Exception):
    """Base class for client-side transfer failures."""


class TransferRetryable(TransferError):
    """Transient failure; the driver retries these, bounded by attempts."""


class TransferQuarantined(TransferError):
    """The session has quarantined parts and can never complete."""


class TransferExhausted(TransferError):
    """A part kept failing past the attempt budget."""


class TransferEndpoint(Protocol):
    """Client view of the remote ingestion plane.

    Production binds the HTTP API; tests and in-process deployments may bind
    ``ingestion.IngestionService`` through a thin principal-injecting shim.
    """

    async def begin_session(
        self, *, payload_schema: str, part_count: int, idempotency_key: str, now: datetime
    ) -> tuple[UUID, bool]:
        """Open or replay a session; returns (session_id, replayed)."""
        ...

    async def list_parts(self, session_id: UUID, *, now: datetime) -> PartListResponse:
        ...

    async def put_part(
        self, session_id: UUID, metadata: PartMetadata, chunks: AsyncIterable[bytes]
    ) -> PartAcknowledgement:
        ...

    async def status(self, session_id: UUID, *, now: datetime) -> SessionStatus:
        ...

    async def complete(
        self,
        session_id: UUID,
        *,
        manifest: ArtifactManifest,
        expected_manifest_digest: str,
        eligibility: EligibilityDecision,
        idempotency_key: str,
        now: datetime,
    ) -> ArtifactReceipt:
        ...


@dataclass(frozen=True)
class PartSource:
    """One local part: declared metadata plus a re-openable chunk source.

    The chunk source must be re-openable because a retry re-reads the bytes.
    """

    metadata: PartMetadata
    open_chunks: Callable[[], AsyncIterable[bytes]]

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, PartMetadata):
            raise TransferError("part source metadata must be PartMetadata")
        if not callable(self.open_chunks):
            raise TransferError("part source open_chunks must be callable")


def default_begin_key(manifest: ArtifactManifest) -> str:
    """Deterministic begin key: re-running the same upload replays the session."""
    return f"transfer-begin:{manifest.digest()}"


def default_completion_key(manifest: ArtifactManifest) -> str:
    """Deterministic completion key bound to the exact manifest."""
    return f"transfer-complete:{manifest.digest()}"


class ResumeDriver:
    """Drive one manifest's parts to completion, resuming whatever is held."""

    def __init__(
        self,
        endpoint: TransferEndpoint,
        *,
        max_part_attempts: int = 3,
        is_retryable: Callable[[Exception], bool] | None = None,
    ) -> None:
        if not isinstance(max_part_attempts, int) or max_part_attempts < 1:
            raise TransferError("max_part_attempts must be a positive integer")
        self._endpoint = endpoint
        self._max_part_attempts = max_part_attempts
        self._is_retryable = is_retryable or (lambda exc: isinstance(exc, TransferRetryable))

    async def upload(
        self,
        *,
        manifest: ArtifactManifest,
        parts: tuple[PartSource, ...],
        eligibility: EligibilityDecision,
        now: datetime,
        begin_key: str | None = None,
        completion_key: str | None = None,
    ) -> ArtifactReceipt:
        """Upload every part, then complete; safe to re-run after any failure."""
        if not isinstance(manifest, ArtifactManifest):
            raise TransferError("manifest must be an ArtifactManifest")
        if not isinstance(eligibility, EligibilityDecision):
            raise TransferError(
                "completion eligibility must be decided by the application"
            )
        by_index = {source.metadata.index: source for source in parts}
        if len(by_index) != len(parts):
            raise TransferError("part sources must have unique indices")

        session_id, _replayed = await self._endpoint.begin_session(
            payload_schema=manifest.artifact_kind,
            part_count=len(parts),
            idempotency_key=begin_key or default_begin_key(manifest),
            now=now,
        )
        await self._refuse_quarantined(session_id, now=now)

        listing = await self._endpoint.list_parts(session_id, now=now)
        held = {ack.index for ack in listing.received}
        for index in sorted(by_index):
            if index in held:
                continue
            source = by_index[index]
            await self._put_with_retry(session_id, source)

        return await self._endpoint.complete(
            session_id,
            manifest=manifest,
            expected_manifest_digest=manifest.digest(),
            eligibility=eligibility,
            idempotency_key=completion_key or default_completion_key(manifest),
            now=now,
        )

    async def _refuse_quarantined(self, session_id: UUID, *, now: datetime) -> None:
        status = await self._endpoint.status(session_id, now=now)
        if status.conflicted_indices:
            raise TransferQuarantined(
                f"session has quarantined part(s) {list(status.conflicted_indices)}; "
                "start a new session instead of retrying this one"
            )

    async def _put_with_retry(self, session_id: UUID, source: PartSource) -> None:
        attempts = 0
        while True:
            attempts += 1
            try:
                await self._endpoint.put_part(
                    session_id, source.metadata, source.open_chunks()
                )
                return
            except Exception as exc:
                if not self._is_retryable(exc):
                    raise
                if attempts >= self._max_part_attempts:
                    raise TransferExhausted(
                        f"part {source.metadata.index} failed {attempts} attempts"
                    ) from exc

    @staticmethod
    def may_retire_local(receipt: ArtifactReceipt, manifest: ArtifactManifest) -> bool:
        """The receipt is the sole credential for retiring local bytes.

        True only when the receipt commits to this exact manifest digest; an
        acknowledgement, a status, or a 200 response is never enough.
        """
        if not isinstance(receipt, ArtifactReceipt) or not isinstance(
            manifest, ArtifactManifest
        ):
            return False
        return receipt.manifest_digest == manifest.digest()
