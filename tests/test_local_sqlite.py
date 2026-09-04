"""Public contract tests for the local SQLite durability policy."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from techflex_cloud_foundation import (
    LocalSqlitePolicy,
    Migration,
    OperationConflict,
    OperationState,
    ReliableOperation,
    SqliteOperationStore,
    RetryPolicy,
    UserVersionMigrator,
    connect_durable,
    inspect_durability,
)
from datetime import UTC, datetime, timedelta


def _make_operation(key: str = "example:op-1") -> ReliableOperation:
    return ReliableOperation.create(
        kind="example.upload",
        payload_ref="spool/session-1",
        payload_digest="b" * 64,
        idempotency_key=key,
    )


def test_connect_durable_applies_default_policy(tmp_path: Path) -> None:
    connection = connect_durable(tmp_path / "state.sqlite3")
    try:
        status = inspect_durability(connection)
    finally:
        connection.close()

    assert status.journal_mode == "WAL"
    assert status.synchronous == "FULL"
    assert status.busy_timeout_ms == 5000
    assert status.foreign_keys is True
    assert status.schema_version == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode")
def test_connect_durable_applies_private_file_mode(tmp_path: Path) -> None:
    target = tmp_path / "state.sqlite3"
    connect_durable(target).close()

    assert (target.stat().st_mode & 0o777) == 0o600


def test_connect_durable_honours_custom_policy(tmp_path: Path) -> None:
    policy = LocalSqlitePolicy(busy_timeout_ms=250, foreign_keys=False)
    connection = connect_durable(tmp_path / "state.sqlite3", policy=policy)
    try:
        status = inspect_durability(connection)
    finally:
        connection.close()

    assert status.busy_timeout_ms == 250
    assert status.foreign_keys is False


def test_policy_rejects_negative_busy_timeout() -> None:
    with pytest.raises(ValueError, match="busy_timeout_ms"):
        LocalSqlitePolicy(busy_timeout_ms=-1)


def test_migrator_applies_pending_migrations_in_order(tmp_path: Path) -> None:
    connection = connect_durable(tmp_path / "state.sqlite3")
    migrator = UserVersionMigrator(
        [
            Migration(1, lambda c: c.execute("CREATE TABLE items (id TEXT PRIMARY KEY)")),
            Migration(2, lambda c: c.execute("ALTER TABLE items ADD COLUMN note TEXT")),
        ]
    )

    assert migrator.migrate(connection) == 2
    assert inspect_durability(connection).schema_version == 2
    connection.execute("INSERT INTO items (id, note) VALUES ('a', 'kept')")

    assert migrator.migrate(connection) == 2
    assert connection.execute("SELECT note FROM items WHERE id='a'").fetchone()[0] == "kept"
    connection.close()


def test_migrator_refuses_newer_database(tmp_path: Path) -> None:
    connection = connect_durable(tmp_path / "state.sqlite3")
    connection.execute("PRAGMA user_version=99")

    with pytest.raises(ValueError, match="newer than supported"):
        UserVersionMigrator([Migration(1, lambda c: None)]).migrate(connection)
    connection.close()


def test_migrator_rolls_back_failed_migration(tmp_path: Path) -> None:
    connection = connect_durable(tmp_path / "state.sqlite3")

    def broken(target: sqlite3.Connection) -> None:
        target.execute("CREATE TABLE partial (id TEXT)")
        raise RuntimeError("migration blew up")

    migrator = UserVersionMigrator([Migration(1, broken)])

    with pytest.raises(RuntimeError, match="blew up"):
        migrator.migrate(connection)

    assert inspect_durability(connection).schema_version == 0
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='partial'"
    ).fetchone() is None
    connection.close()


def test_migrator_rejects_gapped_versions() -> None:
    with pytest.raises(ValueError, match="1..N without gaps"):
        UserVersionMigrator([Migration(1, lambda c: None), Migration(3, lambda c: None)])
    with pytest.raises(ValueError, match="1..N without gaps"):
        UserVersionMigrator([Migration(1, lambda c: None), Migration(1, lambda c: None)])


def test_operation_store_uses_durable_policy(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    try:
        status = inspect_durability(store._connection)
    finally:
        store.close()

    assert status.journal_mode == "WAL"
    assert status.synchronous == "FULL"
    assert status.busy_timeout_ms == 5000


def test_block_interrupted_leases_quarantines_leftover_work(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    first = _make_operation("example:op-1")
    second = _make_operation("example:op-2")
    store.enqueue(first)
    store.enqueue(second)
    store.lease_due(now=datetime.now(UTC))

    assert store.block_interrupted_leases() == 1

    assert store.get(first.operation_id).state == OperationState.BLOCKED
    assert store.get(second.operation_id).state == OperationState.READY
    store.close()


def test_block_is_state_guarded(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    ready = _make_operation("example:ready")
    store.enqueue(ready)

    store.block(ready.operation_id, error_code="operator-hold")
    assert store.get(ready.operation_id).state == OperationState.BLOCKED
    assert store.get(ready.operation_id).error_code == "operator-hold"

    store.block(ready.operation_id, error_code="second-attempt")
    assert store.get(ready.operation_id).error_code == "operator-hold"
    store.close()


def test_mark_conflict_only_from_leased(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    operation = _make_operation()
    store.enqueue(operation)

    store.mark_conflict(operation.operation_id, error_code="digest-mismatch")
    assert store.get(operation.operation_id).state == OperationState.READY

    store.lease_due(now=datetime.now(UTC))
    store.mark_conflict(operation.operation_id, error_code="digest-mismatch")
    stored = store.get(operation.operation_id)
    assert stored.state == OperationState.CONFLICT
    assert stored.error_code == "digest-mismatch"
    store.close()


def test_retry_backoff_is_exact_below_the_cap() -> None:
    policy = RetryPolicy(base_delay=timedelta(seconds=5), cap_delay=timedelta(minutes=15))

    assert [policy.delay_for(n) for n in (1, 2, 3, 4)] == [
        timedelta(seconds=5),
        timedelta(seconds=10),
        timedelta(seconds=20),
        timedelta(seconds=40),
    ]


def test_retry_backoff_saturates_instead_of_overflowing() -> None:
    """A high attempt count must reach the cap, not raise OverflowError.

    ``base_delay * 2 ** (attempt_count - 1)`` builds the full product before
    clamping, so the attempt count sizes an unbounded Python int: at the
    default five-second base, attempt 45 overflows timedelta and attempt 100
    fails inside C.  A store that never drains -- a permanently blocked
    endpoint, or a lease recovered on every restart -- reaches those counts.
    """

    policy = RetryPolicy()
    now = datetime.now(UTC)

    for attempt_count in (45, 100, 10_000):
        assert policy.delay_for(attempt_count) == policy.cap_delay
        assert policy.next_attempt_at(now=now, attempt_count=attempt_count) == now + policy.cap_delay


def test_retry_backoff_saturates_for_a_base_larger_than_the_cap() -> None:
    policy = RetryPolicy(base_delay=timedelta(minutes=30), cap_delay=timedelta(minutes=15))

    assert policy.delay_for(1) == timedelta(minutes=15)
    assert policy.delay_for(50) == timedelta(minutes=15)


def test_enqueue_is_idempotent_for_identical_content(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    operation = _make_operation("example:retry-safe")
    store.enqueue(operation)
    store.enqueue(operation)

    assert store.get(operation.operation_id).state == OperationState.READY
    store.close()


def test_enqueue_rejects_a_reused_key_carrying_different_content(tmp_path: Path) -> None:
    """A mis-keyed enqueue must not be silently dropped.

    ``INSERT OR IGNORE`` cannot distinguish a safe retry from a key collision,
    so the caller got a success return with nothing queued -- the work was
    lost with no signal anywhere.
    """

    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    first = _make_operation("example:shared-key")
    store.enqueue(first)

    second = ReliableOperation.create(
        kind="example.upload",
        payload_ref="spool/session-2",
        payload_digest="c" * 64,
        idempotency_key="example:shared-key",
    )
    with pytest.raises(OperationConflict):
        store.enqueue(second)

    assert store.get(first.operation_id).operation.payload_ref == "spool/session-1"
    with pytest.raises(KeyError):
        store.get(second.operation_id)
    store.close()


def test_lease_due_selects_and_claims_in_one_statement(tmp_path: Path) -> None:
    """Selection and claim must not straddle a window with no write lock.

    sqlite3 takes the write lock at the UPDATE, not at a preceding SELECT, so
    two workers on one database could read the same due row and both lease it.
    Tracing the statements is what makes the fix testable: a returning SELECT
    here would mean the window is back.
    """

    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    store.enqueue(_make_operation("example:only"))

    traced: list[str] = []
    store._connection.raw.set_trace_callback(traced.append)
    leased = store.lease_due(now=datetime.now(UTC))
    store._connection.raw.set_trace_callback(None)

    assert leased is not None
    assert [line for line in traced if line.lstrip().upper().startswith("SELECT")] == []
    store.close()


def test_lease_due_hands_a_row_to_only_one_caller(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    other = SqliteOperationStore(tmp_path / "operations.sqlite3")
    store.enqueue(_make_operation("example:contended"))

    now = datetime.now(UTC)
    first = store.lease_due(now=now)
    second = other.lease_due(now=now)

    assert first is not None
    assert second is None
    store.close()
    other.close()


def test_guarded_transitions_report_whether_the_guard_held(tmp_path: Path) -> None:
    """A refused transition has to be visible to its caller.

    These returned None whether or not the row moved, so a worker whose lease
    had already been recovered by ``block_interrupted_leases`` confirmed into
    the void and reported success.
    """

    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    operation = _make_operation("example:guarded")
    store.enqueue(operation)
    later = datetime.now(UTC) + timedelta(minutes=1)

    assert store.confirm(operation.operation_id) is False
    assert store.defer(operation.operation_id, next_attempt_at=later, error_code="busy") is False
    assert store.mark_conflict(operation.operation_id, error_code="digest-mismatch") is False
    assert store.block(operation.operation_id, error_code="operator-hold") is True
    assert store.block(operation.operation_id, error_code="second-attempt") is False

    store.close()


def test_confirm_reports_success_from_a_lease(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    operation = _make_operation("example:confirmed")
    store.enqueue(operation)
    store.lease_due(now=datetime.now(UTC))

    assert store.confirm(operation.operation_id) is True
    assert store.confirm(operation.operation_id) is False
    assert store.get(operation.operation_id).state == OperationState.CONFIRMED
    store.close()
