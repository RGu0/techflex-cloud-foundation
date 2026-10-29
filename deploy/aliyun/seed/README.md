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
