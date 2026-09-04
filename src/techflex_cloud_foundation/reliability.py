"""Durable, business-neutral operation scheduling primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
import sqlite3
from typing import Protocol
from uuid import UUID, uuid4

from .local_sqlite import LocalSqlitePolicy, connect_durable


class OperationConflict(RuntimeError):
    """An idempotency key was reused for different operation content."""


class OperationState(StrEnum):
    READY = "READY"
    LEASED = "LEASED"
    RETRY_WAIT = "RETRY_WAIT"
    CONFIRMED = "CONFIRMED"
    BLOCKED = "BLOCKED"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class ReliableOperation:
    operation_id: UUID
    kind: str
    payload_ref: str
    payload_digest: str
    idempotency_key: str
    created_at: datetime

    @classmethod
    def create(
        cls, *, kind: str, payload_ref: str, payload_digest: str, idempotency_key: str
    ) -> "ReliableOperation":
        if not kind or not payload_ref or len(payload_digest) != 64 or not idempotency_key:
            raise ValueError("operation requires kind, payload reference, sha256 digest, and idempotency key")
        return cls(uuid4(), kind, payload_ref, payload_digest, idempotency_key, datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class StoredOperation:
    operation: ReliableOperation
    state: OperationState
    attempt_count: int
    next_attempt_at: datetime | None
    error_code: str | None


class OperationStore(Protocol):
    def enqueue(self, operation: ReliableOperation) -> None: ...

    def lease_due(self, *, now: datetime) -> ReliableOperation | None: ...

    def recover_interrupted_leases(self, *, now: datetime) -> None: ...


class OperationHandler(Protocol):
    def execute(self, operation: ReliableOperation) -> None: ...


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    base_delay: timedelta = timedelta(seconds=5)
    cap_delay: timedelta = timedelta(minutes=15)

    def next_attempt_at(
        self, *, now: datetime, attempt_count: int, retry_after: timedelta | None = None
    ) -> datetime:
        if attempt_count < 1:
            raise ValueError("attempt_count must be positive")
        if retry_after is not None:
            if retry_after < timedelta(0):
                raise ValueError("retry_after must not be negative")
            return now + retry_after
        return now + self.delay_for(attempt_count)

    def delay_for(self, attempt_count: int) -> timedelta:
        """Backoff delay for ``attempt_count``, saturating at ``cap_delay``.

        The exponent is clamped before the multiplication rather than the
        product after it.  Multiplying first lets ``attempt_count`` set the
        size of an unbounded Python integer, which overflows the timedelta
        long before any caller could reach that many retries: at the default
        five-second base, attempt 45 raises ``OverflowError`` and attempt 100
        fails inside C converting the int.  Only a handful of doublings are
        needed to pass ``cap_delay``, so clamping the exponent there is exact
        below the cap and saturating above it.
        """

        if attempt_count < 1:
            raise ValueError("attempt_count must be positive")
        if self.base_delay <= timedelta(0):
            return max(timedelta(0), min(self.base_delay, self.cap_delay))
        return min(self.base_delay * (2 ** min(attempt_count - 1, self._saturating_shift())), self.cap_delay)

    def _saturating_shift(self) -> int:
        """Doublings after which ``base_delay`` is certain to exceed the cap."""

        if self.base_delay >= self.cap_delay:
            return 0
        # bit_length on the floor ratio never underestimates ceil(log2(ratio)),
        # and overshooting by at most one doubling costs nothing because the
        # caller clamps to cap_delay anyway.
        return int(self.cap_delay // self.base_delay).bit_length()


class SqliteOperationStore:
    """Reference durable store for new applications; no application schema dependency."""

    def __init__(self, path: str | Path, *, policy: LocalSqlitePolicy | None = None) -> None:
        self._connection = connect_durable(path, policy=policy or LocalSqlitePolicy())
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS foundation_operations (
                operation_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                payload_ref TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                state TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                error_code TEXT
            );
            """
        )
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def enqueue(self, operation: ReliableOperation) -> None:
        """Enqueue idempotently; re-enqueuing identical content is a no-op.

        Reusing an idempotency key for *different* content raises rather than
        being dropped.  Plain ``INSERT OR IGNORE`` cannot tell the two apart,
        so the caller of a mis-keyed enqueue got a success return and no
        queued work.
        """

        with self._connection:
            cursor = self._connection.execute(
                """INSERT OR IGNORE INTO foundation_operations
                (operation_id, kind, payload_ref, payload_digest, idempotency_key, created_at, state)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(operation.operation_id), operation.kind, operation.payload_ref,
                    operation.payload_digest, operation.idempotency_key,
                    _encode(operation.created_at), OperationState.READY,
                ),
            )
            if cursor.rowcount == 1:
                return
            existing = self._connection.execute(
                """SELECT kind, payload_ref, payload_digest FROM foundation_operations
                WHERE idempotency_key=?""",
                (operation.idempotency_key,),
            ).fetchone()
            if existing is None:
                raise OperationConflict(
                    f"operation id {operation.operation_id} is already stored under a different idempotency key"
                )
            if (existing["kind"], existing["payload_ref"], existing["payload_digest"]) != (
                operation.kind, operation.payload_ref, operation.payload_digest,
            ):
                raise OperationConflict(
                    f"idempotency key {operation.idempotency_key!r} is already queued with different content"
                )

    def lease_due(self, *, now: datetime) -> ReliableOperation | None:
        """Lease the oldest due operation, or return None when none is due.

        Selection and claim are one statement.  Split across a SELECT and a
        later UPDATE they were not atomic against a second process: sqlite3
        takes the write lock only at the UPDATE, so two workers sharing a
        database could read the same due row and both lease it.
        """

        encoded_now = _encode(now)
        with self._connection:
            row = self._connection.execute(
                """UPDATE foundation_operations
                SET state=?, attempt_count=attempt_count+1
                WHERE operation_id = (
                    SELECT operation_id FROM foundation_operations
                    WHERE state = ? OR (state = ? AND next_attempt_at <= ?)
                    ORDER BY created_at LIMIT 1
                )
                RETURNING *""",
                (
                    OperationState.LEASED, OperationState.READY,
                    OperationState.RETRY_WAIT, encoded_now,
                ),
            ).fetchone()
        if row is None:
            return None
        return _operation_from_row(row)

    def defer(self, operation_id: UUID, *, next_attempt_at: datetime, error_code: str) -> bool:
        """Return whether the operation was LEASED and is now RETRY_WAIT."""

        with self._connection:
            cursor = self._connection.execute(
                """UPDATE foundation_operations SET state=?, next_attempt_at=?, error_code=?
                WHERE operation_id=? AND state=?""",
                (OperationState.RETRY_WAIT, _encode(next_attempt_at), error_code, str(operation_id), OperationState.LEASED),
            )
            return cursor.rowcount == 1

    def confirm(self, operation_id: UUID) -> bool:
        """Return whether the operation was LEASED and is now CONFIRMED."""

        with self._connection:
            cursor = self._connection.execute(
                "UPDATE foundation_operations SET state=?, error_code=NULL WHERE operation_id=? AND state=?",
                (OperationState.CONFIRMED, str(operation_id), OperationState.LEASED),
            )
            return cursor.rowcount == 1

    def recover_interrupted_leases(self, *, now: datetime) -> None:
        del now
        with self._connection:
            self._connection.execute(
                "UPDATE foundation_operations SET state=? WHERE state=?",
                (OperationState.READY, OperationState.LEASED),
            )

    def block_interrupted_leases(self) -> int:
        """Move leases left over from a crashed process to BLOCKED.

        Unlike ``recover_interrupted_leases``, which retries interrupted work,
        this quarantines it for operator review.  Returns the blocked count.
        """

        with self._connection:
            cursor = self._connection.execute(
                "UPDATE foundation_operations SET state=? WHERE state=?",
                (OperationState.BLOCKED, OperationState.LEASED),
            )
            return cursor.rowcount

    def block(self, operation_id: UUID, *, error_code: str) -> bool:
        """Park a READY or LEASED operation as BLOCKED (state-guarded).

        Returns whether the guard held.  A caller that parks an operation
        already CONFIRMED by another worker needs to see that it did not.
        """

        with self._connection:
            cursor = self._connection.execute(
                "UPDATE foundation_operations SET state=?, error_code=? "
                "WHERE operation_id=? AND state IN (?, ?)",
                (OperationState.BLOCKED, error_code, str(operation_id),
                 OperationState.READY, OperationState.LEASED),
            )
            return cursor.rowcount == 1

    def mark_conflict(self, operation_id: UUID, *, error_code: str) -> bool:
        """Mark a LEASED operation as CONFLICT (terminal, state-guarded).

        Returns whether the guard held.
        """

        with self._connection:
            cursor = self._connection.execute(
                "UPDATE foundation_operations SET state=?, error_code=? "
                "WHERE operation_id=? AND state=?",
                (OperationState.CONFLICT, error_code, str(operation_id), OperationState.LEASED),
            )
            return cursor.rowcount == 1

    def get(self, operation_id: UUID) -> StoredOperation:
        row = self._connection.execute(
            "SELECT * FROM foundation_operations WHERE operation_id=?", (str(operation_id),)
        ).fetchone()
        if row is None:
            raise KeyError(str(operation_id))
        return StoredOperation(
            _operation_from_row(row), OperationState(row["state"]), row["attempt_count"],
            _decode(row["next_attempt_at"]), row["error_code"],
        )


def _operation_from_row(row: sqlite3.Row) -> ReliableOperation:
    created_at = _decode(row["created_at"])
    if created_at is None:
        raise ValueError("stored operation requires created_at")
    return ReliableOperation(
        UUID(row["operation_id"]), row["kind"], row["payload_ref"], row["payload_digest"],
        row["idempotency_key"], created_at,
    )


def _encode(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _decode(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
