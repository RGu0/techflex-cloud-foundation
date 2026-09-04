"""Business-neutral local SQLite durability policy, connections, and migrations."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import threading
from types import TracebackType
from typing import Any

_JOURNAL_MODES = frozenset({"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"})
_SYNCHRONOUS_MODES = frozenset({"OFF", "NORMAL", "FULL", "EXTRA"})
_SYNCHRONOUS_NAMES = ("OFF", "NORMAL", "FULL", "EXTRA")
_MEMORY_DATABASE = ":memory:"


@dataclass(frozen=True, slots=True)
class LocalSqlitePolicy:
    """Durability pragmas applied to a local SQLite connection."""

    journal_mode: str = "WAL"
    synchronous: str = "FULL"
    busy_timeout_ms: int = 5000
    foreign_keys: bool = True

    def __post_init__(self) -> None:
        journal_mode = self.journal_mode.upper()
        if journal_mode not in _JOURNAL_MODES:
            raise ValueError(f"unsupported journal_mode: {self.journal_mode!r}")
        object.__setattr__(self, "journal_mode", journal_mode)
        synchronous = self.synchronous.upper()
        if synchronous not in _SYNCHRONOUS_MODES:
            raise ValueError(f"unsupported synchronous: {self.synchronous!r}")
        object.__setattr__(self, "synchronous", synchronous)
        if self.busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must not be negative")


class DurableConnection:
    """Thread-safe wrapper around an SQLite connection.

    All statements are serialized through a re-entrant lock. Callers that
    need multi-statement atomicity serialize via ``with connection:``, which
    holds the lock for the duration of the SQLite transaction. Use ``raw``
    to reach the underlying :class:`sqlite3.Connection` (for example with
    :func:`pragma_report` or :class:`UserVersionMigrator`).
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._lock = threading.RLock()

    @property
    def raw(self) -> sqlite3.Connection:
        return self._connection

    def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
        with self._lock:
            return self._connection.execute(sql, parameters)

    def executemany(self, sql: str, parameters: Any, /) -> sqlite3.Cursor:
        with self._lock:
            return self._connection.executemany(sql, parameters)

    def executescript(self, script: str, /) -> sqlite3.Cursor:
        with self._lock:
            return self._connection.executescript(script)

    def commit(self) -> None:
        with self._lock:
            self._connection.commit()

    def rollback(self) -> None:
        with self._lock:
            self._connection.rollback()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "DurableConnection":
        self._lock.acquire()
        try:
            self._connection.__enter__()
        except BaseException:
            self._lock.release()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self._connection.__exit__(exc_type, exc, tb)
        finally:
            self._lock.release()


#: Shared default for :func:`connect_durable`.  Safe to share because
#: ``LocalSqlitePolicy`` is frozen; naming it makes that a property of the
#: module rather than something every caller re-derives from the signature.
DEFAULT_POLICY = LocalSqlitePolicy()


def connect_durable(
    path: str | Path, policy: LocalSqlitePolicy = DEFAULT_POLICY
) -> DurableConnection:
    """Open a local SQLite database with the durability policy applied.

    A newly created database file is restricted to owner-only (0o600) on
    POSIX; on Windows the directory ACL governs access instead.

    ``":memory:"`` opens a private in-memory database.  There is no file to
    restrict, and SQLite keeps ``journal_mode=MEMORY`` whatever the policy
    asks for, so an in-memory connection exercises this module's API but is
    not a durability substitute -- ``inspect_durability`` reports what SQLite
    actually applied, not what was requested.
    """

    target = os.fspath(path)
    # ":memory:" names no file. The owner-only step used to run on it because
    # the path does not exist, which is exactly the condition that marks a
    # database as newly created, and os.chmod then raised FileNotFoundError
    # before the caller ever saw the connection.
    file_target = None if target == _MEMORY_DATABASE else Path(target)
    created = file_target is not None and not file_target.exists()
    connection = sqlite3.connect(target, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA journal_mode={policy.journal_mode}")
    connection.execute(f"PRAGMA synchronous={policy.synchronous}")
    connection.execute(f"PRAGMA busy_timeout={policy.busy_timeout_ms}")
    connection.execute(f"PRAGMA foreign_keys={'ON' if policy.foreign_keys else 'OFF'}")
    if created and file_target is not None and os.name != "nt":
        os.chmod(file_target, 0o600)
    return DurableConnection(connection)


def _raw(connection: sqlite3.Connection | DurableConnection) -> sqlite3.Connection:
    return connection.raw if isinstance(connection, DurableConnection) else connection


@dataclass(frozen=True, slots=True)
class LocalSqliteStatus:
    """Live PRAGMA values read back from a connection for self-checks."""

    journal_mode: str
    synchronous: str
    busy_timeout_ms: int
    foreign_keys: bool
    schema_version: int


def inspect_durability(
    connection: sqlite3.Connection | DurableConnection,
) -> LocalSqliteStatus:
    """Read the live durability pragmas and schema version of a connection."""

    raw = _raw(connection)
    journal_mode = str(raw.execute("PRAGMA journal_mode").fetchone()[0]).upper()
    synchronous_level = int(raw.execute("PRAGMA synchronous").fetchone()[0])
    synchronous = (
        _SYNCHRONOUS_NAMES[synchronous_level]
        if 0 <= synchronous_level < len(_SYNCHRONOUS_NAMES)
        else str(synchronous_level)
    )
    busy_timeout_ms = int(raw.execute("PRAGMA busy_timeout").fetchone()[0])
    foreign_keys = bool(raw.execute("PRAGMA foreign_keys").fetchone()[0])
    schema_version = int(raw.execute("PRAGMA user_version").fetchone()[0])
    return LocalSqliteStatus(
        journal_mode, synchronous, busy_timeout_ms, foreign_keys, schema_version
    )


@dataclass(frozen=True, slots=True)
class Migration:
    """A single user_version migration applied to a connection."""

    version: int
    apply: Callable[[sqlite3.Connection], None]

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("migration version must be positive")


class UserVersionMigrator:
    """Applies ordered PRAGMA user_version migrations, each in a transaction.

    Migrations must be numbered 1..N without gaps.  A database whose
    user_version is newer than the migrator's maximum version is refused
    with ValueError; a newer database is never opened silently.
    """

    def __init__(self, migrations: Iterable[Migration]) -> None:
        ordered = tuple(migrations)
        versions = [migration.version for migration in ordered]
        if versions != list(range(1, len(ordered) + 1)):
            raise ValueError("migration versions must be 1..N without gaps")
        self._migrations = ordered

    @property
    def max_version(self) -> int:
        return len(self._migrations)

    def migrate(self, connection: sqlite3.Connection | DurableConnection) -> int:
        """Apply pending migrations and return the resulting schema version."""

        raw = _raw(connection)
        current = int(raw.execute("PRAGMA user_version").fetchone()[0])
        if current > self.max_version:
            raise ValueError(
                f"database schema version {current} is newer than supported "
                f"maximum {self.max_version}"
            )
        for migration in self._migrations:
            if migration.version <= current:
                continue
            # Explicit transaction: Python's sqlite3 legacy mode does not
            # wrap DDL (CREATE/ALTER) in an implicit transaction, so a bare
            # ``with connection:`` block would not roll back a failed DDL
            # migration.  Migrations must not commit or roll back themselves.
            with connection:
                try:
                    raw.execute("BEGIN IMMEDIATE")
                    migration.apply(raw)
                    raw.execute(f"PRAGMA user_version={migration.version}")
                    raw.commit()
                except BaseException:
                    raw.rollback()
                    raise
        return self.max_version
