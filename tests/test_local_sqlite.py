"""Public contract tests for the local SQLite durability policy."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from techflex_cloud_foundation import (
    LocalSqlitePolicy,
    Migration,
    OperationState,
    ReliableOperation,
    SqliteOperationStore,
    UserVersionMigrator,
    connect_durable,
    inspect_durability,
)
from datetime import UTC, datetime


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


def test_connect_durable_supports_an_in_memory_database() -> None:
    """``":memory:"`` has to open, not raise on a file that will never exist.

    The owner-only step keyed off "the path does not exist", which is exactly
    what an in-memory database looks like, so ``os.chmod`` raised
    ``FileNotFoundError: ':memory:'`` before the caller saw the connection.
    """

    connection = connect_durable(":memory:")
    try:
        connection.execute("CREATE TABLE example (value INTEGER NOT NULL)")
        connection.execute("INSERT INTO example VALUES (?)", (7,))
        assert connection.execute("SELECT value FROM example").fetchone()["value"] == 7
    finally:
        connection.close()


def test_in_memory_database_reports_what_sqlite_applied() -> None:
    """An in-memory database is not a durability substitute, and says so."""

    connection = connect_durable(":memory:")
    try:
        status = inspect_durability(connection)
    finally:
        connection.close()

    # The policy asked for WAL; SQLite keeps MEMORY for an in-memory database.
    assert status.journal_mode == "MEMORY"
    assert status.synchronous == "FULL"
    assert status.busy_timeout_ms == 5000


def test_in_memory_databases_are_not_shared(tmp_path: Path) -> None:
    del tmp_path
    first = connect_durable(":memory:")
    second = connect_durable(":memory:")
    try:
        first.execute("CREATE TABLE example (value INTEGER NOT NULL)")
        with pytest.raises(sqlite3.OperationalError):
            second.execute("SELECT value FROM example")
    finally:
        first.close()
        second.close()


def test_connect_durable_still_restricts_a_new_file(tmp_path: Path) -> None:
    """The in-memory path must not weaken the file path it shares."""

    target = tmp_path / "fresh.sqlite3"
    connection = connect_durable(target)
    connection.close()

    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600
