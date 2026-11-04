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

The plan in this tree includes `0018_subject_sync` and `0019_terminal_diagnostics`
(RAY-830 R5, version 0.9.0). The host applies migrations from the pinned runtime
wheel, so a host whose runtime is still pinned to 0.8.0 stops at `0017` and serves
neither route set. 0.9.0 was published on 2026-11-02 and the runtime lock is
pinned to it, so a deployment archive cut from this tree matches the wheel;
`backup.sh` records the migrations of the tree, not of the pinned wheel. `release-cutover`
published 0.9.0 (v0.8.0 is an undeployed intermediate release).

Terminal diagnostic packages (`diagnostics/...` objects on OSS) are not part of
`oss_backup_export.py`, which exports segments, manifests and report copies only,
as in FeetForcePlate. A restore therefore has the diagnostic records without their
content; the packages are 30-day support data.

1. Merge `ffp-drift-port`. Then, on `release-cutover`, the changelog's
   `0.9.0 - pending release` section is the release commit. (`0.8.0` was published
   from the earlier release commit and is not deployed.)
2. Follow [foundation-release](foundation-release.md): governed build from that
   release commit (done 2026-11-02: tag `v0.9.0` at `afd69da`, an ancestor of the
   scope's merge commit; as for `v0.8.0` the tag precedes the merge to `main`),
   retain wheel, sdist and `release-evidence.json`, review CI, then (authorised)
   tag `v0.9.0` and attach both assets.
3. Pin the runtime to the published asset and commit the result:

   ```bash
   python3 scripts/pin_seed_runtime.py --version 0.9.0 --wheel <retained wheel>
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

The scripts live in `deploy/aliyun/seed/rehearsal/`. All run as root on the host and
write only a scratch directory (`/var/lib/feetforceplate/.rehearsal`), a rehearsal
database and, in step 3, tagged `pg_hba` lines and two rehearsal processes. They
never bind 7443 or 8743 and never touch `feetforceplate_seed`.

1. `run-restore-drill.sh` (the installed release's copy) with the age identity placed
   under `shared/incoming/` proves the newest backup restores. It drops its copy on
   success, so the rehearsal restores its own.
2. `rehearse-1-runtime.sh ARCHIVE ARCHIVE_SHA256 WHEEL` unpacks the deployment archive
   (`git archive <release commit> deploy scripts tests`), puts the digest-checked
   wheel in the service uv cache and rebuilds the locked runtime offline, then checks
   the `postgres` OS user can import the migration runner. If the cache lacks
   third-party wheels (see below) it stops here with uv's "not found in the cache".
3. `rehearse-2-restore-migrate.sh AGE_IDENTITY` restores the newest backup into the
   kept database `feetforceplate_rehearsal` and runs the release's schema runner on
   it, compares production counts before and after, and prints the migration status.
4. `rehearse-2b-acl.sh` copies the ACL entries of the live schema-only dump onto the
   copy. The drill restores with `pg_restore --no-privileges`, and migrations 0001 to
   0014 are adopted as baseline rather than re-run, so the copy has the data but none
   of the application roles' `GRANT`s; without this step the first smoke fails with
   `permission denied for schema ops`. Production keeps its grants.
5. `rehearse-3-up.sh` adds four tagged `pg_hba` lines for the rehearsal database
   (original saved, `reload` not restart), generates a throwaway CA and a leaf for
   127.0.0.1, starts the seed on 127.0.0.1:28743 as the transient unit
   `ffp-rehearsal-seed` with the production secrets, the rehearsal DSNs, filesystem
   objects and every `OSS_*` and `BACKUP_*` variable removed, and a second Nginx (own
   config and pid) on 127.0.0.1:27443.
6. Run the TLS smokes from the release directory as the service user, one at a time,
   each prompting for the test institution password:
   `python -m scripts.run_ray785_route_smoke`, `run_ray815_data_plane_smoke`,
   `run_ray825_insole_archive_smoke` and `run_ray907_subject_sync_smoke`, all with
   `--base-url https://127.0.0.1:27443 --ca-file <rehearsal>/tls/ca.pem
   --account-name <test institution> --output <rehearsal>/evidence/<name>.json`.
   Copy the redacted JSON to `shared/evidence/` before the next step.
7. `rehearse-3-down.sh` stops both processes, restores `pg_hba` byte for byte (it
   verifies with `cmp` and requires PostgreSQL to accept the reload), verifies
   both rehearsal listeners are gone, drops the database and verifies its absence
   before deleting the scratch directory. Only then does it print
   `rehearsal_down=done`.

   On any critical failure it exits nonzero and retains the scratch directory and
   `pg_hba.conf.orig` for recovery. Do not delete that directory or run step 3-up
   again: inspect the failed command, correct the permission/service/database
   issue, and retry 3-down. A stop can have succeeded before a later failure;
   an already-unloaded transient seed unit and an already-dropped database are
   safe to retry. If nginx left a stale PID file, verify that the recorded process
   is gone and port 27443 is closed before removing only that stale PID file and
   retrying. Never signal an unrelated process to make cleanup pass. Missing
   `pg_hba.conf.orig` with tagged rehearsal rules requires operator recovery from
   a verified original; the script refuses to guess. A reload error may leave the
   restored file on disk while PostgreSQL still uses its prior configuration:
   keep the original and resolve the reload failure before retrying. These local
   fault tests do not establish a production teardown or cutover acceptance.

Not covered by any smoke script: `POST /v1/diagnostics` and gait-IMU ingestion. The
repository has no smoke for either; the diagnostics route is covered by the ported
tests and the byte-identical contracts only.

### Warming the uv cache on a host without internet

The seed and backup services run with `UV_OFFLINE=1`, so the service user's cache
must hold every wheel of the runtime lock before the installer's offline proof.
On 2026-11-02 the cache lacked `cryptography==50.0.2` and others. The service user's
`uv.toml` sets `https://mirrors.aliyun.com/pypi/simple/` as the default index and the
host reaches that mirror directly, but not `files.pythonhosted.org`, where the lock
points. `allowlist_proxy.py` is a CONNECT-only tunnel for `files.pythonhosted.org:443`
that never terminates TLS; run it on the operator machine and expose it to the host
with `ssh -R 18080:127.0.0.1:18080`, then `rehearse-1b-warm.sh` runs `uv sync
--frozen` through it with `NO_PROXY=mirrors.aliyun.com` and rebuilds once with
`UV_OFFLINE=1` to prove the cache is complete. uv checks every lock hash. One residual:
`alibabacloud-tea` is source-only, so its build fetches `setuptools` from the mirror;
that build dependency is not in the lock. Stop the proxy when the script ends.

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
  point it back at the previous release. The installer also overwrote
  `/etc/systemd/system/feetforceplate-{seed,backup}.service`, the backup timer and
  `nginx.conf` with the new release's copies, and the new seed unit's `ExecStart`
  (`deploy/aliyun/seed/run-seed.sh`) does not exist in an ffp release. So reinstall
  the units and `nginx.conf` from the previous release (the original Nginx file is
  kept as `nginx.conf.pre-seed`), re-sync the shared `runtime/venv` to the previous
  release's lock offline, `daemon-reload`, then restart `feetforceplate-seed.service`.
  Releases are never deleted by the installer.
- **Legacy process.** The installer stops the legacy listener only after the new
  stack answered on 8743 and 17443. Restarting the legacy process, if it is wanted
  again, uses the previous release's `run-integration.sh` and its environment file.
- Do not run a mixed state for long: the previous release does not know the ledger
  but tolerates it; it does not know anything newer than migration 0016.

## Not rehearsed until the cutover

Rehearsed on 2026-11-02 (see above): the uv offline cache and the `acceptance`
dependency group for the 0.9.0 lock, the interpreter uv selected (CPython 3.11), the
`postgres` OS user's access to the migration environment, migrations 0017 to 0019 on a
restored copy and the four smokes through a second Nginx. Observed that day: Nginx
held 7443 (the installer stops Nginx before it checks the listener, so that is
accepted), and the database had already run FeetForcePlate's 0017 and 0018, which the
probes adopted as `0018_subject_sync` and `0019_terminal_diagnostics`.

Still not rehearsed:

- TLS smokes through the production Nginx on 7443 with the production certificate;
- running `install-seed-release.sh` itself as root, including the Nginx stop and start
  and the `pg_hba.conf` replacement;
- the diagnostics route and gait-IMU, which have no smoke script.

Left behind on purpose: the integration public-bundle publisher and the mobile
trust anchor (they need the FeetForcePlate client) stay in FeetForcePlate, and
`scripts/production_acceptance` still expects the old layout; neither is part of
this cutover.
