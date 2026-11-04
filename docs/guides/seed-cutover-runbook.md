# Integration endpoint: release, cutover and rollback

RAY-830 R5. `deploy-cutover` delivered the offline deployment preparation;
`release-cutover` published 0.9.0 and retains the host cutover acceptance.
On 2026-11-04 the runtime lock was re-pinned to the published 0.9.1 wheel
(`runtime-pin-091`); the 2026-11-02 rehearsal below was run against 0.9.0.
Host observations below are dated; they do not establish current production
acceptance. The switch needs the user's approval, `sudo`, and user-run read-only SQL.

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

On 2026-11-02, `release-cutover` published 0.9.0 with migrations through
`0019_terminal_diagnostics`; its runtime lock remains unchanged. PR #106 later
added `0020_registered_ingestion` and prepared 0.9.1. **The current source tree
and the deployed runtime pin therefore do not yet describe the same release.**
The host migrates using its pinned wheel, while `backup.sh` records the source
plan. Do not deploy an archive assembled from this candidate until the successor
release and matching hash-pinned runtime have been separately approved and prepared.
v0.8.0 remains an undeployed intermediate release.

Terminal diagnostic packages (`diagnostics/...` objects on OSS) are not part of
`oss_backup_export.py`, which exports segments, manifests and report copies only,
as in FeetForcePlate. A restore therefore has the diagnostic records without their
content; the packages are 30-day support data.

1. In `release-cutover`, identify the exact reviewed 0.9.1 release commit and
   obtain publication approval. Follow [foundation-release](foundation-release.md)
   to build and retain wheel, sdist and `release-evidence.json`; check version,
   source SHA, CI and artifact hashes. Do not reuse or overwrite v0.9.0 assets.
2. Only after approval, publish the immutable successor tag/assets. The earlier
   v0.9.0 publication at `afd69da` is historical evidence, not approval for 0.9.1.
3. Pin the runtime to that published asset and commit the result (not executed by
   this tools-only scope):

   ```bash
   python3 scripts/pin_seed_runtime.py --version 0.9.1 --wheel <retained wheel>
   ```

   The pin tool refuses unless the digest `uv` records for the published asset
   equals the retained wheel's. Review the deployment archive source and runtime
   lock together, then run restored-copy migration 0020 and fresh TLS/rollback
   rehearsal before separately requesting the formal cutover.

## Facts to establish first (user runs read-only commands)

The migration plan assumes the host already runs the persistent seed stack.
Confirm, and record in the evidence directory:

- what owns 7443 (`ss -ltnp '( sport = :7443 )'` and the command line): the
  installer accepts the managed Nginx master reported by systemd, or an empty
  port. An unmanaged listener (including the old Uvicorn process) is refused
  before database/configuration changes; arrange a separately approved manual
  cutover with a known restart procedure instead of automatically killing it.
- the installed release (`cat /opt/feetforceplate/app/.release-sha`) and that the
  newest encrypted backup has a verified sidecar.
- that the service user's uv cache can resolve the new lock offline. The
  installer proves it before live configuration/database changes; the cache may
  already have been warmed when this proof fails; warm the cache from a host with package-index access first.
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

   Any failure before scratch deletion exits nonzero and retains the scratch
   directory and `pg_hba.conf.orig` for recovery. Deletion itself can partially
   fail; that also exits nonzero without reporting success, but cannot guarantee
   retention of every scratch file. Do not delete retained recovery material or run step 3-up
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

The 2026-11-02 rehearsal did not cover diagnostics or gait-IMU. New tools and
the repaired gait source path and outstanding release/TLS gates are documented in
[pre-cutover validation](pre-cutover-validation.md); neither has host TLS
acceptance yet.

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
   OS user can run it; only scratch files and the runtime cache may change;
   validates the 7443 owner and saves root-only recovery material before live changes;
3. creates `seed.env` secrets if absent, creates the database if absent;
4. runs the schema runner; when it pauses for a missing role (exit 3) applies the
   role step and runs again; applies the role step once more; requires no
   pending step;
5. installs `pg_hba.conf` and restarts PostgreSQL;
6. installs the release (units for the seed, the backup and, from RAY-927, the daily
   diagnostics purge, whose timer is enabled), restarts the service and waits for
   `/health/ready` on 8743;
7. brings Nginx up on 17443 and checks `/health/ready` there;
8. requires 7443 to be vacant after stopping the managed Nginx, brings Nginx up
   on 7443, checks readiness and runs a backup. A listener that appeared meanwhile
   is never killed. Any failure exits nonzero and attempts reversible-state recovery.

Then run the live acceptance (`run-live-acceptance.sh`) and the three smokes
against 7443.

## Failure recovery (RAY-952 R1)

Run only one installer at a time, with no concurrent service/configuration edits.
Keep `installer-recovery.sh` beside the installer (the deployment archive and
server wrapper already carry both). The installer records preflight, forward-schema, PostgreSQL configuration,
application, Nginx preflight, ingress and backup stages. Before stopping the backup
timer or changing live state it snapshots the application symlink, PG `pg_hba.conf`
and `postgresql.auto.conf`, Nginx main/site configuration, TLS files, all five
application unit files (seed, backup service and timer, diagnostics purge service and
timer), the shared runtime venv, and each affected unit's active
and enabled state. Missing paths/units are recorded as absent. Snapshots preserve
ownership, modes and symlinks. A running backup, unstable service state, unsupported
unit enablement (for example masked), a running diagnostics purge, or an unmanaged
7443 listener stops preflight.

On failure or INT/TERM, the EXIT handler stops runtime consumers, restores saved
paths (removing newly created paths), reloads systemd, and restores enablement and
active/inactive state. It never explicitly reruns the backup service (restoring an active timer resumes its schedule). If consumers cannot stop, it
leaves the runtime in place rather than copying over a running process. It retains
`/var/lib/feetforceplate/.seed-recovery.XXXXXX/` on every failed transaction, even
when reversible recovery succeeds. The directory is root-only and contains private
keys and possibly credentials: **never upload its contents as evidence**. Successful
installs remove this snapshot. Release directories and generated backup artifacts
are retained. Scratch install/offline-check directories are cleaned separately.

**Database boundary:** SQL migrations, role/password/grant changes, newly created
databases and secrets, objects, and backup output are not undone. Restoring the old
application/configuration is not a database rollback and does not prove that the
old application is compatible with the forward schema. Do not drop the migration
ledger to claim recovery. A database restore requires a separately approved plan,
a verified pre-cutover backup and explicit treatment of writes made since it.

If output says `manual recovery required`, keep the host out of service until an
operator completes these steps under the applicable host-operation authorization:

1. Read the retained `status`, `services`, and `paths` files locally as root. `files/N`
   is the saved value of the zero-based Nth line in `paths`; no `files/N` means that
   path was absent. Do not expose file contents in chat/log evidence.
2. Stop the backup and diagnostics purge timers and services, Nginx and the seed
   service. Resolve any failure
   to stop consumers before replacing the shared runtime. Restore each path from
   its saved copy with ownership/mode preserved; remove a current path only when
   its recorded original was absent. Keep the snapshot until validation finishes.
3. Restore systemd enablement from `services` (remove newly enabled links for
   originally absent units before deleting their new unit files), run
   `systemctl daemon-reload`, and restore prior active/inactive states, PostgreSQL
   first, seed backend next, then Nginx and the timer. Do not start an originally
   absent or inactive backup service just to match the installer's failed command.
4. Check PostgreSQL, backend readiness, TLS ingress and the old application's
   compatibility with the retained forward schema. Record failures honestly. Use a
   separately approved backup restore only if application recovery is insufficient.

SIGKILL, power loss and concurrent administrator changes cannot be recovered by a
shell EXIT trap; use the retained snapshot and these manual steps. Tests execute the
installer with temporary paths and command doubles, including a managed Nginx
already on 7443 and several injected failures. They do not establish live recovery
or authorize deployment.

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
- the diagnostics route and gait-IMU; tools and the PR #106 service fix arrived later,
  and need fresh candidate-specific TLS evidence.

Left behind on purpose: the integration public-bundle publisher and the mobile
trust anchor (they need the FeetForcePlate client) stay in FeetForcePlate, and
`scripts/production_acceptance` still expects the old layout; neither is part of
this cutover.

## Current pre-cutover gate (2026-11-03 America/Los_Angeles)

See [pre-cutover validation](pre-cutover-validation.md) for the gait/diagnostics
smoke CLI, evidence matrix and approval packet. On 2026-11-03, PR #106 merged the
service repair; the 0.9.1 source candidate passes the actual in-process gait probe.
The original 0.9.0 HTTP 422 evidence remains historical. **Do not cut over as
R5-complete** until the repaired release is approved/published/pinned, migration
0020 and rollback are rehearsed on a restored copy, and all required TLS acceptance
is recorded. No published 0.9.0 artifact or deployment lock changed in this scope.
Update 2026-11-04: v0.9.1 is published and pinned; the restored-copy rehearsal,
rollback evidence and TLS acceptance listed above are still owed on the 0.9.1 set.
