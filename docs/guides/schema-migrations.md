# Database schema and migrations

RAY-830 R3 (`db-migrations`) moves the FeetForcePlate cloud schema into this
library as `techflex_cloud_foundation.schema`. The SQL under `schema/sql/` is
`cloud/migrations` of ffp `origin/master` at 2c61523 byte for byte, 0001 to
0016, plus `0017_schema_migrations.sql`. Nothing in 0001-0016 was edited, and
0016 is the only migration that relaxed the frame, clock, compression and
cipher columns (RAY-825); no later migration may relax them again.

## What ships

- `DEFAULT_PLAN`: the steps in the order `install-seed-release.sh` applied them.
  Each step pins the SHA-256 of its SQL; a changed file is refused before the
  database is touched. Two filenames repeat in the shipped history (`0009` and
  `0010` each name two migrations); they keep their full names and their place.
- `apply_migrations(connection)` and `migration_status(connection)`: the runner,
  written against an asyncpg connection. Applying takes a session advisory lock,
  so two runners cannot interleave.
- `ops.schema_migrations` (0017): migration id, SHA-256, and whether the step was
  `applied` by the runner or adopted as `baseline`.

New migrations take the next number (0018 onward) and are appended to the plan
with either a probe (a relation or column that exists once it ran) or an
explicit `converges=True` (safe to run again). A step with neither is rejected.

## Roles

0003 creates the `ffp_tenant_app`, `ffp_activation_app` and `ffp_platform_app`
group roles. The login roles `ffp_seed_*` are a deployment concern and are not
created here: the deployment creates them after `0010_session_expected_manifest`
and before `0008_activation_projection_grants`, as the installer did. A step
that needs `ffp_seed_backup` (`0010_local_basic_report_copies` and the grants
that follow the later migrations) stops with `RoleMissing` when it is absent;
create the roles and run again. Steps already applied stay applied.

## Upgrade

1. Take a backup (`deploy/aliyun/seed/backup.sh` today) and keep it until the
   upgrade is verified.
2. Run `apply_migrations` as the migration role, never as an application role.
3. On a database installed by the old installer there is no ledger. Each step
   whose objects already exist is recorded `baseline` without running; steps with
   no probe (0004, 0008, 0015, 0016 and the grants) run once more, exactly as the
   installer ran them on every install; 0017 then creates the ledger and every
   step is recorded. Verify with `migration_status`: nothing pending.
4. A run that stops before 0017 has no ledger yet, so the probes are the only
   memory, as under the installer. Fix the cause and run again.

A database that has the ledger is never re-adopted: a recorded step is skipped,
and a recorded checksum that differs from the plan raises `ChecksumMismatch`.
Do not edit a shipped file to fix a migration; add a new one.

## Rollback

The migrations are forward-only; there are no down scripts, and 0016 widens
what the tables accept. The rollback is to restore the backup taken in step 1
and run the previous release against it. The one reversible change this scope
adds is the ledger: `DROP TABLE ops.schema_migrations;` returns a database to
the state the old installer expects, and the next run re-adopts it. Rows are
never deleted from the ledger to force a re-run.

## SQL_ASCII databases

A `SQL_ASCII` database stores raw UTF-8 text in `jsonb` unchanged but rejects
`\uXXXX` escapes of non-ASCII characters (RAY-834). The schema applies there;
repositories must write JSON with `ensure_ascii=False`. The test suite runs the
plan against a `SQL_ASCII` database and checks both behaviours.

## Tests

`tests/test_schema_migrations.py` runs the plan on an ephemeral PostgreSQL
cluster (Unix socket only, removed afterwards) when a server installation is
found, and skips otherwise: an empty database, a database installed the old way
(the final schema, constraints, indexes, policies and grants equal a fresh run),
a tampered ledger, a missing role, and `SQL_ASCII`. The ffp migration content
tests that need only the SQL (`tests/test_ffp_migration*.py`,
`test_ffp_operations_migration.py`) are carried over; the installer assertions of
those tests move with the deployment scope.
