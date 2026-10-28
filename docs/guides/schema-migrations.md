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
group roles. The rest of the role step is a deployment concern and is not run
here: `deploy/aliyun/seed/postgresql-role-grants.sql` creates the `ffp_seed_*`
login roles and also grants things no migration grants (`SELECT` on every table
and `USAGE` on the schemas to `ffp_seed_backup`, table rights on `sales` to the
platform and activation roles, and the activation role's rights on
`device.devices`, `device.terminals`, `device.terminal_device_bindings`,
`iam.tenants`, `iam.account_login_directory` and `device.license_entitlements`).
A database built by `apply_migrations` alone lacks those grants.

The installer re-ran that file on every install, so its `GRANT SELECT ON ALL
TABLES` also covered tables created after its first run: the four
`ops.session_hold*` tables get their backup read access only that way. Run the
role step again after `apply_migrations`, as every install did; it is idempotent.

The runner pauses where the installer ran that step: `0008_activation_projection_grants`
(which needs no role itself) and `0010_local_basic_report_copies` name
`ffp_seed_backup`, so the run raises `RoleMissing` before 0008 when the role is
absent. Run the role step, then run again. The steps before the pause are
already applied; with no ledger yet, the next run finds them by their probes and
records them as `baseline`, and applies 0008 onward.

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

## Limits

- A step's SQL and its ledger row are written in separate transactions (each
  shipped file carries its own `BEGIN`/`COMMIT`). A crash between them leaves the
  step recorded as `baseline` on the next run instead of `applied`.
- Once the ledger exists, an unrecorded step whose probe already finds its object
  is adopted as `baseline` without running. A new migration must therefore probe
  an object only that migration creates.
- The digest of an inline grant step is computed from its own text, so it does not
  catch an edit to that text; the ledger catches drift on databases that have one.
- `apply_migrations` refuses a connection inside a transaction, because the
  shipped files commit. If a file fails, the session is rolled back and the
  advisory lock released before the original error is raised.

## SQL_ASCII databases

A `SQL_ASCII` database stores raw UTF-8 text in `jsonb` unchanged but rejects
`\uXXXX` escapes of non-ASCII characters (RAY-834). The schema applies there;
repositories must write JSON with `ensure_ascii=False`. The test suite runs the
plan against a `SQL_ASCII` database and checks both behaviours.

## Tests

`tests/test_schema_migrations.py` runs the plan on an ephemeral PostgreSQL
cluster (Unix socket only, removed afterwards) when a server installation is
found, and skips otherwise: an empty database including the pause for the role
step, a database installed by replaying the installer's own sequence (its
schemas, relations and their privileges, columns, constraints, indexes, policies,
functions, triggers and roles equal a fresh run's), a failing step, a tampered
ledger, and `SQL_ASCII`. Sequences, ownership beyond the owner column and default
privileges are not compared. The ffp migration content
tests that need only the SQL (`tests/test_ffp_migration*.py`,
`test_ffp_operations_migration.py`) are carried over; the installer assertions of
those tests move with the deployment scope.
