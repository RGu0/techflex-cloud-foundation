# Integration endpoint: release, cutover and rollback

RAY-830 R4. `deploy-cutover` (this change) delivers everything below that can be
checked without touching the host. `release-cutover` publishes the release and
runs the host steps; those need the user's approval, `sudo`, and read-only SQL
that the user runs. Nothing in this guide has been run on the host.

## What runs on the host after the cutover

The integration endpoint (`https://39.105.216.113:7443`, Nginx TLS in front of a
loopback Uvicorn on 8743) runs a **foundation release**, not a FeetForcePlate
checkout:

- `/opt/feetforceplate/releases/<foundation-commit>/` holds `deploy/`, `scripts/`
  and `tests/` of this repository (names and paths are unchanged: decision D6).
- `deploy/aliyun/seed/runtime/` is the pinned environment. Its `pyproject.toml`
  depends on `techflex-cloud-foundation[server]==<version>`; its `uv.lock` pins the
  released wheel by URL and SHA-256 and every third-party package by digest.
- `run-seed.sh` brings `/var/lib/feetforceplate/runtime/venv` in line with that
  lock (`uv sync --frozen --no-dev`, offline from the service user's uv cache) and
  starts `python -m techflex_cloud_foundation.server.seed`.
- The schema is applied by `python -m techflex_cloud_foundation.schema`, never by
  ad-hoc `psql -f`.

FeetForcePlate's `analysis` and `reporting` are not part of the running service
(the seed composition does not import them); RAY-831 attaches analyzers later.

## Before the release exists

Everything is reviewable now: `pytest` covers the scripts' structure, the
installer's schema sequence on a scratch PostgreSQL (an empty database, a
database left by the old installer, and the rollback of the ledger), the
runtime-lock verifier, and the pin script.

## Publishing the release (release-cutover, needs approval)

1. Merge `deploy-cutover`. Rename the changelog's `Unreleased` heading to
   `0.8.0 - pending release` only in the release commit, as for earlier versions.
2. Follow [foundation-release](foundation-release.md): governed build from the
   exact merged commit, retain wheel, sdist and `release-evidence.json`, review CI,
   then (authorised) tag `v0.8.0` and attach both assets.
3. Pin the runtime to the published asset and commit the result:

   ```bash
   python3 scripts/pin_seed_runtime.py --version 0.8.0 --wheel <retained wheel>
   ```

   It refuses unless the digest `uv` records for the published asset equals the
   retained wheel's. Commit `deploy/aliyun/seed/runtime/uv.lock`; the installer
   refuses a release without it.

## Facts to establish first (user runs read-only commands)

The migration plan assumes the host already runs the persistent seed stack.
Confirm, and record in the evidence directory:

- what owns 7443 (`ss -ltnp '( sport = :7443 )'` and the command line): the
  installer only stops a listener whose command line is
  `uvicorn cloud.api.integration:app_from_environment`; any other owner stops it.
- the installed release (`cat /opt/feetforceplate/app/.release-sha`) and that the
  newest encrypted backup has a verified sidecar.
- that the service user's uv cache can resolve the new lock offline. The
  installer proves it before changing anything and stops with "nothing was
  changed" otherwise; warm the cache from a host with package-index access first.
- that the `postgres` OS user can run the migration environment (the installer
  also checks this before any change).

## Rehearsal on the host (release-cutover)

1. Take a backup (`backup.sh`) and run `run-restore-drill.sh`; the restored copy
   is the rehearsal database.
2. Start the new release on a loopback-only port against the restored copy and a
   scratch object root (the same `seed.env` with DSNs, object root and bind port
   overridden). Do not bind 7443 or 8743.
3. Run the three TLS smokes against it: force plate (`scripts/run_ray785_route_smoke.py`
   and `run_ray815_data_plane_smoke.py`), insole regression
   (`run_ray825_insole_archive_smoke.py`) and gait-IMU, each with a terminal token
   and ending at `INGESTED`. Record redacted output.
4. Stop and delete the rehearsal instance, database and objects.

## Cutover (needs the user's approval for the moment, and sudo)

```bash
deploy/aliyun/seed/deploy-sales-inventory-release.sh <ssh-host>
```

The operator machine builds a `git archive` of `deploy scripts tests`, downloads
the locked wheel and checks its digest, uploads both, and runs the wrapper under
`sudo`. On the host the installer, in this order and stopping at the first
failure:

1. checks the archive and wheel digests and that a pinned runtime lock exists;
2. rebuilds the runtime offline in a scratch directory and checks the `postgres`
   OS user can run it - nothing has changed yet;
3. creates `seed.env` secrets if absent, creates the database if absent;
4. runs the schema runner; when it pauses for a missing role (exit 3) applies the
   role step and runs again; applies the role step once more; requires no
   pending step;
5. installs `pg_hba.conf` and restarts PostgreSQL;
6. installs the release, restarts the service and waits for `/health/ready` on
   8743;
7. brings Nginx up on 17443 and checks `/health/ready` there;
8. verifies the 7443 listener is the legacy process, stops it, brings Nginx up on
   7443, checks readiness and runs a backup.

Then run the live acceptance (`run-live-acceptance.sh`) and the three smokes
against 7443.

## Rollback

- **Schema.** Migrations are forward-only. The one reversible change is the
  ledger: `DROP TABLE ops.schema_migrations;` returns the database to the shape the
  old installer expects (rehearsed on a scratch cluster by
  `tests/test_ffp_seed_installer_schema.py`). To undo a migration's effect, restore
  the backup taken before the cutover.
- **Application.** `/opt/feetforceplate/app` is a symlink to a release directory;
  point it back at the previous release, `daemon-reload`, restart
  `feetforceplate-seed.service`. Releases are never deleted by the installer.
- **Legacy process.** The installer stops the legacy listener only after the new
  stack answered on 8743 and 17443. Restarting the legacy process, if it is wanted
  again, uses the previous release's `run-integration.sh` and its environment file.
- Do not run a mixed state for long: the previous release does not know the ledger
  but tolerates it; it does not know anything newer than migration 0016.

## Not rehearsed until the host is touched

- the uv offline cache covering every third-party package of the new lock;
- the interpreter the service user's uv selects on the host;
- `postgres` OS user access to the migration environment;
- TLS smokes through Nginx with the production certificate.
