# PostgreSQL validation in CI

The `ubuntu-latest / test` Quality check runs on Ubuntu 24.04 and installs the
PostgreSQL **16** package. The major is fixed; the distribution supplies patch
updates. `FFP_POSTGRES_BIN=/usr/lib/postgresql/16/bin` selects that installation
without falling back to another installed major. `FFP_POSTGRES_MAJOR=16` verifies
its reported version; `FFP_REQUIRE_POSTGRES=1` makes missing server binaries or
`asyncpg` a failure, including during collection of migration/registry tests.
The workflow logs the actual version. Tests create disposable, Unix-socket-only
clusters and least-privilege role pools; no production DSNs or secrets are needed.

The job runs the full governed test action and retains
`postgres-test-results/postgres-tests.xml` as a GitHub Actions artifact. Its result
checker rejects failures, unexpected skips, empty reports and missing passed
witnesses for migrations, SQL_ASCII, registry upgrades, tenant RLS and subject
migration backfill. A binary discovery success alone is not database evidence.
The subject backfill test provisions its own cluster through migration 0017;
an explicitly supplied `FEETFORCEPLATE_TEST_PRE0017_ADMIN_DSN` still selects an
operator-owned disposable database and retains its pre-0018 safety assertion.

Only these exact tests may skip in that full Linux job:

- `tests.test_ffp_local_controlled_integration_lab_script::test_bootstrap_applies_to_opt_in_local_postgres`:
  a separate local fault-lab experiment requiring `FFP_LOCAL_LAB_LIVE_DSN`.
- `tests.test_release_server_wheel::test_retained_server_wheel`: separate retained
  artifact acceptance requiring `FOUNDATION_CANDIDATE_WHEEL`. Its absence does
  not count as wheel or release acceptance; this is outside ordinary source PG
  migration/RLS coverage.

Missing ordinary PostgreSQL role DSNs are supplied by isolated test helpers;
ordinary migration, RLS, registry and subject-sync tests are not exceptions.
Optional developer/macOS/Windows jobs may still skip unavailable local PostgreSQL.
An explicit `FFP_POSTGRES_BIN` is authoritative even there, so an invalid override
does not silently select a different installation.

## Local evidence

Use the registered worktree's Python environment and command gateway. For a full
PostgreSQL-required run, set `FFP_REQUIRE_POSTGRES=1`, optionally set
`FFP_POSTGRES_BIN` and `FFP_POSTGRES_MAJOR` to the actual local installation, and
set `PYTEST_ADDOPTS=--junitxml=<retained-results.xml>` before the governed `test`
action. `scripts/check_postgres_ci_evidence.py <retained-results.xml>` is the
same report checker used by CI. A newer local PostgreSQL run is additional
coverage, not a substitute for the pinned CI major.

## Repository protection

On 2026-11-04, a read of GitHub main protection showed `strict=true` with only
`Merge freshness` required. This workflow preserves existing check names and
does not change protection settings. To enforce the PostgreSQL check as a merge
gate, an authorized repository administrator must add `ubuntu-latest / test`
to required status checks while retaining `Merge freshness` and strict freshness.
Do not claim that setting is active without a subsequent GitHub readback.
Workflow success, repository protection, release acceptance and live deployment
remain separate evidence.
