# Aliyun seed-pilot deployment

This directory installs a controlled integration endpoint, not a production
commercial ingress. Public traffic reaches Nginx TLS on 7443; Uvicorn listens
only on `127.0.0.1:8743`; PostgreSQL listens only on loopback. Formal customer
rollout still requires a domain, public-CA certificate, port 443, customer
onboarding evidence, and the applicable compliance review.

## Required host layout

- `/opt/feetforceplate/releases/<commit-sha>`: immutable application release;
- `/opt/feetforceplate/app`: symlink to the current release;
- `/etc/feetforceplate/seed.env`: service-user-owned mode `0600` secrets;
- `/etc/feetforceplate/tls`: Nginx-readable certificate and private key;
- `/var/lib/feetforceplate/objects`: service-user-owned mode `0700` objects;
- `/var/lib/feetforceplate/backups`: service-user-owned mode `0700` backups.

Create the dedicated system user with no interactive login, install PostgreSQL
and Nginx from the OS package manager, and ensure 5432 and 8743 are not admitted
by the cloud security group or host firewall. The schema is applied as the
PostgreSQL superuser over the Unix socket by `python -m
techflex_cloud_foundation.schema apply`, which pauses (exit 3) before the first
step that names a role the installer creates; application LOGIN roles are created
by `postgresql-role-grants.sql` using `psql` variables supplied outside shell
history. No application role is an owner, superuser, or `BYPASSRLS` role.

The migration plan keeps the order the old installer applied (hold and report-copy
migrations 0009 and 0010 before controlled identity recovery 0011). A successful
installer run does not itself establish the real incident hold or prove a
backup restore; record those as separate acceptance evidence.

The release is a foundation release: the archive carries `deploy/`, `scripts/` and
`tests/`, and `runtime/` pins the released wheel. See
[seed-cutover-runbook](../../../docs/guides/seed-cutover-runbook.md).

Since RAY-830 R5 the plan also applies `0018_subject_sync` (RAY-907: revisions
for every existing subject in creation order, revision triggers, name lookup
column, tag tables) and `0019_terminal_diagnostics` (RAY-802), each followed by
the backup-role grant; `backup.sh` records them in `metadata.json`
`schema_versions`. Both were FeetForcePlate 0017 and 0018. 0018 is additive but
not reversible by the installer, so take a backup and pass `run-restore-drill.sh`
before deploying it.

The host cannot reach github.com. `deploy-sales-inventory-release.sh` downloads
the foundation wheel on the operator machine, checks it against
`runtime/uv.lock`, and
uploads it with the archive; the installer re-checks the digest, seeds the
service user's uv cache from the uploaded wheel (`warm_foundation_wheel_cache.py`,
a loopback endpoint that serves only the locked URL, so a fresh host or a
foundation upgrade needs no prior cache), and proves the new release resolves
dependencies offline (`UV_OFFLINE=1`) before any migration. The seed and backup services run with `UV_OFFLINE=1`.

On a new Alibaba Cloud Linux host, run the reviewed prerequisite script once as
root. It is idempotent and deliberately does not stop or reconfigure the
existing 7443 process, so the later cutover remains reversible:

```bash
sudo bash deploy/aliyun/seed/host-prerequisites.sh \
  /home/rui/apps/feetforceplate-seed/tools/age-v1.3.1
```

The block below is the manual outline for a first install. `install-seed-release.sh`
supersedes it (lock check, offline runtime proof, schema runner, cutover) and is
what the deploy driver runs.

After reviewing paths and certificate names:

```bash
sudo ./deploy/aliyun/seed/install-layout.sh /tmp/ffp-release "$RELEASE_SHA"
sudo install -o root -g root -m 0644 deploy/aliyun/seed/feetforceplate-seed.service \
  /etc/systemd/system/feetforceplate-seed.service
sudo install -o root -g root -m 0644 deploy/aliyun/seed/nginx-feetforceplate-seed.conf \
  /etc/nginx/conf.d/feetforceplate-seed.conf
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable --now feetforceplate-seed.service nginx
```

Readiness returns only `postgres` and `object_store` states. Logs contain method,
URI, status, byte count, remote address and request ID; they exclude request
bodies and Authorization headers. Never put DSNs, passwords, activation codes,
private keys, raw identities, or full hardware serials in deployment evidence.

## Partial installation failures

Ship `install-seed-release.sh` together with its sibling `installer-recovery.sh`;
the normal deployment archive/wrapper includes both. Do not copy a standalone
installer to the host.

RAY-952 adds staged recovery of application/configuration/runtime and systemd
state. It accepts a systemd-managed Nginx listener on 7443, and refuses unmanaged
listeners before live changes. On failure it exits nonzero and retains root-only
`.seed-recovery.*` material under `/var/lib/feetforceplate`; failed restoration
requires the operator steps in the [cutover runbook](../../../docs/guides/seed-cutover-runbook.md#failure-recovery-ray-952-r1).
Forward SQL, role changes, new secrets, data and backup artifacts are never
automatically rolled back. Use exclusive installation access; a successful offline
fault-injection test is not host acceptance or permission to deploy.

## Diagnostic package purge and OSS backstop (RAY-927)

Carried from FeetForcePlate `e42c0aa` (PR #92). `0019_terminal_diagnostics` is applied
once, while `ops.terminal_diagnostics` is absent, and its grant lets the backup role
`SELECT` it. Packages are kept 30 days from upload (`expires_at`).

`feetforceplate-diagnostics-purge.timer` runs
`feetforceplate-diagnostics-purge.service` once a day (03:30 host time plus up
to 20 minutes; `Persistent=true` catches up a missed run after downtime). The
service runs as `feetforceplate` with `seed.env`, offline from the service uv
cache like the seed and backup services, and executes
`deploy/aliyun/seed/venv-python.sh -m techflex_cloud_foundation.server.terminal_diagnostics.purge`.
It deletes the content of every expired package and keeps the row as a tombstone
with `deleted_at`; an interrupted run is safe to repeat. Its stdout is only
`{"purged": <count>}`; the journal also gets `uv sync` progress lines, and on
failure a Python traceback that holds no DSN or credential but may name an object
key (which contains a tenant UUID), so read a failed run's journal before quoting
it in evidence. A start timeout of 30 minutes stops a hung run from blocking the
next day's. With the OSS backend the purge calls `DeleteObject`, so the ECS RAM
role must allow `oss:DeleteObject` on `diagnostics/*` in the bucket; one manual run
(below) after each first install proves it, as nothing alerts on a failed nightly
run. `install-seed-release.sh` installs both units, enables and starts the timer,
stops it while it replaces the shared runtime, and refuses to start while a purge
is running; `installer-recovery.sh` snapshots and restores both units like the
backup ones. To run it once by hand and read the result:

```bash
sudo systemctl start feetforceplate-diagnostics-purge.service
sudo journalctl -u feetforceplate-diagnostics-purge.service -n 5 --no-pager
systemctl list-timers feetforceplate-diagnostics-purge.timer --no-pager
```

The purge is the mechanism. With `FEETFORCEPLATE_OBJECT_BACKEND=aliyun-oss` the
bucket also carries a lifecycle backstop for content the purge missed (for example
while the timer was broken):

- one rule, prefix `diagnostics/` only, current-version objects expire 31 days
  after last modification: not earlier than the 30-day retention, with a day of
  margin for time zones and clock skew;
- set by the operator in the Aliyun OSS console (bucket, Data Management,
  Lifecycle). Before saving, review every existing rule on the bucket: none may
  cover `diagnostics/` with a shorter expiry (an empty-prefix whole-bucket rule
  counts) and the new rule must not cover any other prefix. Note whether the
  bucket has versioning enabled: then a purge or expiry leaves a noncurrent
  version behind, which needs its own decision before the rule is saved;
- record only the rule's description (prefix, action, days, the review of
  existing rules) in evidence; never an AccessKey, STS token or console
  credential. The rule needs no change to the service's ECS RAM role (the
  role's `oss:DeleteObject` on `diagnostics/*`, above, is a separate check).

With the filesystem backend there is no backstop; the purge alone deletes content
under `/var/lib/feetforceplate/objects/diagnostics/`.

### Diagnostics TLS smoke and a support identity

`scripts/run_ray802_diagnostics_smoke.py` is the real-TLS smoke of the diagnostic
routes (upload and replay, a conflicting replay, a planted-identity rejection, the
`PLATFORM_SUPPORT` list and read, and the owner and terminal refusals). It asks for
three passwords with getpass and writes redacted JSON. It records the run's
`ticket_reference`; the audit rows the support list/read and the two refusals
produced are checked read-only on the host with that value:

```bash
sudo -u postgres psql -d feetforceplate_seed -Atc "select action, coalesce(details->>'actor_kind',''), coalesce(details->>'reason',''), count(*) from ops.access_audit_events where details->>'ticket_reference' = '<ticket_reference>' group by 1,2,3 order by 1,2,3"
# expect diagnostics.deny|platform|role_unauthorized|1, diagnostics.deny|terminal|terminal_credential|1,
#        diagnostics.list|platform||1, diagnostics.read|platform||1
```

The smoke needs a `PLATFORM_SUPPORT` login. `python -m techflex_cloud_foundation.server.access_control.cli create-platform-identity --platform-login <owner> --login-name <name> --display-name <text> --roles PLATFORM_SUPPORT`
lets the Platform owner add one: it reads the owner password and the new password
(twice) with getpass, is audited as `platform-identity.create` and prints only the
new id and roles. There is no command yet to suspend a Platform identity
(`rotate-platform-role` needs at least one role), so a support login created for a
smoke keeps its access: give it a unique strong password, create it on integration
only, and track its retirement separately.

