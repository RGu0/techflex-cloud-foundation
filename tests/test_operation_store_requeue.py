"""RAY-959: guarded requeue and caller-owned connections for SqliteOperationStore."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3

import pytest

from techflex_cloud_foundation import (
    OperationState,
    ReliableOperation,
    SqliteOperationStore,
)

NOW = datetime(2026, 11, 4, 9, 0, tzinfo=UTC)


def _operation(key: str = "example:op-1") -> ReliableOperation:
    return ReliableOperation.create(
        kind="example.upload",
        payload_ref="spool/session-1",
        payload_digest="c" * 64,
        idempotency_key=key,
    )


def _leased(store: SqliteOperationStore, operation: ReliableOperation) -> None:
    store.enqueue(operation)
    assert store.lease_due(now=NOW) is not None


def test_requeue_returns_a_blocked_operation_to_ready(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "ops.sqlite3")
    operation = _operation()
    _leased(store, operation)
    assert store.block(operation.operation_id, error_code="E-AUT-403")

    assert store.requeue(operation.operation_id, expected_error_code="E-AUT-403") is True

    stored = store.get(operation.operation_id)
    assert stored.state is OperationState.READY
    assert stored.error_code is None
    assert stored.next_attempt_at is None
    assert stored.attempt_count == 1
    leased = store.lease_due(now=NOW)
    assert leased is not None and leased.operation_id == operation.operation_id
    assert store.get(operation.operation_id).attempt_count == 2


def test_requeue_returns_a_conflicted_operation_to_ready(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "ops.sqlite3")
    operation = _operation()
    _leased(store, operation)
    assert store.mark_conflict(operation.operation_id, error_code="E-SUB-409")

    assert store.requeue(operation.operation_id, expected_error_code="E-SUB-409") is True
    assert store.get(operation.operation_id).state is OperationState.READY


def test_requeue_refuses_a_different_error_code(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "ops.sqlite3")
    operation = _operation()
    _leased(store, operation)
    assert store.block(operation.operation_id, error_code="E-AUT-403")

    assert store.requeue(operation.operation_id, expected_error_code="E-SUB-409") is False

    stored = store.get(operation.operation_id)
    assert stored.state is OperationState.BLOCKED
    assert stored.error_code == "E-AUT-403"


@pytest.mark.parametrize("state", ["READY", "LEASED", "RETRY_WAIT", "CONFIRMED"])
def test_requeue_refuses_states_other_than_blocked_or_conflict(
    tmp_path: Path, state: str
) -> None:
    store = SqliteOperationStore(tmp_path / "ops.sqlite3")
    operation = _operation()
    store.enqueue(operation)
    if state != "READY":
        assert store.lease_due(now=NOW) is not None
    if state == "RETRY_WAIT":
        assert store.defer(
            operation.operation_id, next_attempt_at=NOW + timedelta(hours=1),
            error_code="E-NET-503",
        )
    if state == "CONFIRMED":
        assert store.confirm(operation.operation_id)

    assert store.requeue(operation.operation_id, expected_error_code="E-NET-503") is False
    assert store.get(operation.operation_id).state is OperationState(state)


def test_requeue_of_an_unknown_operation_is_false(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "ops.sqlite3")
    assert store.requeue(_operation().operation_id, expected_error_code="E-AUT-403") is False


def test_requeue_is_single_winner_across_two_stores(tmp_path: Path) -> None:
    path = tmp_path / "ops.sqlite3"
    first = SqliteOperationStore(path)
    second = SqliteOperationStore(path)
    operation = _operation()
    _leased(first, operation)
    assert first.block(operation.operation_id, error_code="E-AUT-403")

    results = [
        first.requeue(operation.operation_id, expected_error_code="E-AUT-403"),
        second.requeue(operation.operation_id, expected_error_code="E-AUT-403"),
    ]

    assert results == [True, False]


def _application_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)  # plain connection: no Row factory, caller-owned
    connection.execute("CREATE TABLE IF NOT EXISTS consents (consent_id TEXT PRIMARY KEY)")
    connection.commit()
    return connection


def _consent_count(path: Path) -> int:
    reader = sqlite3.connect(path)
    try:
        return int(reader.execute("SELECT COUNT(*) FROM consents").fetchone()[0])
    finally:
        reader.close()


def test_attached_store_commits_with_the_callers_transaction(tmp_path: Path) -> None:
    path = tmp_path / "app.sqlite3"
    connection = _application_connection(path)
    store = SqliteOperationStore.attach(connection)
    operation = _operation()
    store.enqueue(operation)
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    assert store.lease_due(now=NOW) is not None
    assert store.block(operation.operation_id, error_code="E-AUT-403")
    connection.commit()

    connection.execute("BEGIN IMMEDIATE")
    connection.execute("INSERT INTO consents VALUES ('consent-1')")
    assert store.requeue(operation.operation_id, expected_error_code="E-AUT-403")
    connection.commit()

    assert _consent_count(path) == 1
    assert store.get(operation.operation_id).state is OperationState.READY
    connection.close()


def test_attached_store_rolls_back_with_the_callers_transaction(tmp_path: Path) -> None:
    path = tmp_path / "app.sqlite3"
    connection = _application_connection(path)
    store = SqliteOperationStore.attach(connection)
    operation = _operation()
    store.enqueue(operation)
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    assert store.lease_due(now=NOW) is not None
    assert store.block(operation.operation_id, error_code="E-AUT-403")
    connection.commit()

    connection.execute("BEGIN IMMEDIATE")
    connection.execute("INSERT INTO consents VALUES ('consent-1')")
    assert store.requeue(operation.operation_id, expected_error_code="E-AUT-403")
    connection.rollback()  # simulated crash before commit

    assert _consent_count(path) == 0
    stored = store.get(operation.operation_id)
    assert stored.state is OperationState.BLOCKED
    assert stored.error_code == "E-AUT-403"
    connection.close()


def test_attached_store_does_not_commit_on_its_own(tmp_path: Path) -> None:
    path = tmp_path / "app.sqlite3"
    connection = _application_connection(path)
    store = SqliteOperationStore.attach(connection)
    store.enqueue(_operation())
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    connection.execute("INSERT INTO consents VALUES ('consent-1')")
    store.enqueue(_operation("example:op-2"))
    assert connection.in_transaction  # the store left the caller's transaction open

    connection.rollback()

    assert _consent_count(path) == 0
    other = SqliteOperationStore(path)
    assert other.lease_due(now=NOW) is not None  # op-1 survived
    assert other.lease_due(now=NOW) is None  # op-2 was rolled back
    connection.close()


def test_attached_store_does_not_close_or_reconfigure_the_connection(tmp_path: Path) -> None:
    connection = _application_connection(tmp_path / "app.sqlite3")
    factory_before = connection.row_factory
    store = SqliteOperationStore.attach(connection)
    store.enqueue(_operation())
    connection.commit()

    store.close()

    assert connection.row_factory is factory_before
    assert connection.execute("SELECT COUNT(*) FROM consents").fetchone() == (0,)
    connection.close()


def test_path_constructor_behavior_is_unchanged(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "ops.sqlite3")
    operation = _operation()
    store.enqueue(operation)
    store.close()

    reopened = SqliteOperationStore(tmp_path / "ops.sqlite3")
    assert reopened.get(operation.operation_id).state is OperationState.READY
