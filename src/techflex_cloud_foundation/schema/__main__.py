"""Command line for the migration runner: ``python -m techflex_cloud_foundation.schema``.

Exit status: 0 done, 1 failed, 2 usage, 3 a step needs a database role the
deployment has not created yet (create the roles, then run again).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from .runner import MigrationError, RoleMissing, apply_migrations, migration_status

EXIT_FAILED = 1
EXIT_ROLE_MISSING = 3


async def _run(command: str, dsn: str) -> dict[str, Any]:
    import asyncpg  # type: ignore[import-untyped]

    connection = await asyncpg.connect(dsn)
    try:
        if command == "apply":
            report = await apply_migrations(connection)
        else:
            report = await migration_status(connection)
    finally:
        await connection.close()
    return {
        "applied": report.applied,
        "baseline": report.baseline,
        "skipped": report.skipped,
        "pending": report.pending,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m techflex_cloud_foundation.schema")
    parser.add_argument("command", choices=("apply", "status"))
    parser.add_argument(
        "--dsn",
        required=True,
        help="connection string of the migration role; for the installer, a Unix-socket "
        "connection as the PostgreSQL superuser, never an application role",
    )
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(_run(args.command, args.dsn))
    except RoleMissing as error:
        print(f"role-missing: {error}", file=sys.stderr)
        return EXIT_ROLE_MISSING
    except MigrationError as error:
        print(f"migration-failed: {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_FAILED
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
