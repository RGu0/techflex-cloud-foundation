"""Apply the migration plan to a database and keep the ledger of what ran.

A database installed by the FeetForcePlate installer has no ledger. The first
run adopts it: each step whose probe finds its objects is recorded as
``baseline`` without executing, every other step is executed and recorded as
``applied``, and steps that converge but have no probe are executed once more,
as the installer did on every install. Once the ledger exists a recorded step is
skipped, and a recorded checksum that differs from the plan is refused.

Until the ledger exists (0017 runs last of the shipped steps) the probes are the
only memory, exactly as under the installer; a run that stops half way is
finished by running again.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .plan import DEFAULT_PLAN, MigrationStep, load_step_sql

LEDGER = "ops.schema_migrations"
_LOCK_KEY = 7_201_830_017  # advisory lock: one runner per database


class MigrationError(Exception):
    """A migration run stopped; the message says why."""


class ChecksumMismatch(MigrationError):
    """A recorded migration differs from the one this plan ships."""


class RoleMissing(MigrationError):
    """A step needs a database role the deployment has not created yet."""


class Connection(Protocol):
    """The slice of an asyncpg connection the runner uses."""

    async def execute(self, query: str, *args: Any) -> str: ...

    async def fetchval(self, query: str, *args: Any) -> Any: ...

    async def fetch(self, query: str, *args: Any) -> Sequence[Any]: ...

    def is_in_transaction(self) -> bool: ...


@dataclass(slots=True)
class MigrationReport:
    """What a run did, by step id, in plan order."""

    applied: list[str] = field(default_factory=list)
    baseline: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.applied or self.baseline)


async def _relation_exists(conn: Connection, name: str) -> bool:
    return bool(await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", name))


async def _probe_says_applied(conn: Connection, step: MigrationStep) -> bool:
    probe = step.probe
    if probe is None:
        return False
    if probe.relation is not None:
        return await _relation_exists(conn, probe.relation)
    assert probe.column is not None
    schema, table, column = probe.column
    return bool(
        await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = $1 AND table_name = $2 AND column_name = $3)",
            schema,
            table,
            column,
        )
    )


async def _missing_roles(conn: Connection, step: MigrationStep) -> list[str]:
    return [
        role
        for role in step.requires_roles
        if not await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", role
        )
    ]


async def _ledger(conn: Connection) -> dict[str, str] | None:
    if not await _relation_exists(conn, LEDGER):
        return None
    rows = await conn.fetch(f"SELECT migration_id, sha256 FROM {LEDGER}")
    return {row["migration_id"]: row["sha256"] for row in rows}


async def _record(conn: Connection, step: MigrationStep, method: str) -> None:
    await conn.execute(
        f"INSERT INTO {LEDGER} (migration_id, sha256, method) VALUES ($1, $2, $3) "
        "ON CONFLICT (migration_id) DO NOTHING",
        step.step_id,
        step.sha256,
        method,
    )


async def migration_status(
    conn: Connection, plan: Sequence[MigrationStep] = DEFAULT_PLAN
) -> MigrationReport:
    """Report the plan against the ledger without changing the database."""
    report = MigrationReport()
    ledger = await _ledger(conn) or {}
    for step in plan:
        recorded = ledger.get(step.step_id)
        if recorded is None:
            report.pending.append(step.step_id)
        elif recorded != step.sha256:
            raise ChecksumMismatch(f"{step.step_id}: ledger {recorded} differs from plan")
        else:
            report.skipped.append(step.step_id)
    return report


async def apply_migrations(
    conn: Connection, plan: Sequence[MigrationStep] = DEFAULT_PLAN
) -> MigrationReport:
    """Bring the database to the end of ``plan``; safe to run again at any point."""
    for step in plan:
        load_step_sql(step)  # refuse a changed file before touching the database

    if conn.is_in_transaction():
        # Every shipped file carries its own BEGIN/COMMIT, which would commit
        # the caller's transaction.
        raise MigrationError("run migrations on a connection outside a transaction")

    report = MigrationReport()
    await conn.execute("SELECT pg_advisory_lock($1)", _LOCK_KEY)
    try:
        ledger = await _ledger(conn) or {}
        unrecorded: list[tuple[MigrationStep, str]] = []
        for step in plan:
            recorded = ledger.get(step.step_id)
            if recorded is not None:
                if recorded != step.sha256:
                    raise ChecksumMismatch(
                        f"{step.step_id}: ledger {recorded} differs from plan {step.sha256}"
                    )
                report.skipped.append(step.step_id)
                continue

            if await _probe_says_applied(conn, step):
                method = "baseline"
                report.baseline.append(step.step_id)
            else:
                missing = await _missing_roles(conn, step)
                if missing:
                    raise RoleMissing(
                        f"{step.step_id} needs role(s) {', '.join(missing)}; create them "
                        "(deployment role step) and run again. Earlier steps are applied."
                    )
                await conn.execute(load_step_sql(step))
                method = "applied"
                report.applied.append(step.step_id)

            unrecorded.append((step, method))
            if await _relation_exists(conn, LEDGER):
                for pending_step, pending_method in unrecorded:
                    await _record(conn, pending_step, pending_method)
                unrecorded = []
        report.pending.extend(step.step_id for step, _ in unrecorded)
    finally:
        if conn.is_in_transaction():
            # A failed file leaves its own BEGIN open and the session aborted;
            # without this the unlock fails, hides the real error and the lock
            # stays held on a pooled connection.
            await conn.execute("ROLLBACK")
        await conn.execute("SELECT pg_advisory_unlock($1)", _LOCK_KEY)
    return report
