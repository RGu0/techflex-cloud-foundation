#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
    echo "resume-seed-cutover.sh must run as root" >&2
    exit 1
fi
release_root="$(readlink -f /opt/feetforceplate/app)"
if [[ ! -f "$release_root/.release-sha" ]]; then
    echo "installed seed release is missing" >&2
    exit 1
fi
if ! curl -fsS http://127.0.0.1:8743/health/ready >/dev/null; then
    echo "persistent backend is not ready; legacy 7443 was not changed" >&2
    exit 1
fi

install -o root -g root -m 0644 "$release_root/deploy/aliyun/seed/nginx.conf" /etc/nginx/nginx.conf
preflight_conf="$(mktemp /etc/nginx/conf.d/.feetforceplate-preflight.XXXXXX.conf)"
cleanup() {
    rm -f -- "$preflight_conf"
}
trap cleanup EXIT
sed -e 's/listen 7443 ssl;/listen 17443 ssl;/' \
    -e 's/listen \[::\]:7443 ssl;/listen [::]:17443 ssl;/' \
    "$release_root/deploy/aliyun/seed/nginx-feetforceplate-seed.conf" >"$preflight_conf"
chmod 0644 "$preflight_conf"
nginx -t
systemctl restart nginx
curl -kfsS https://127.0.0.1:17443/health/ready >/dev/null
systemctl stop nginx
rm -f -- "$preflight_conf"
trap - EXIT
install -o root -g root -m 0644 \
    "$release_root/deploy/aliyun/seed/nginx-feetforceplate-seed.conf" \
    /etc/nginx/conf.d/feetforceplate-seed.conf
nginx -t

old_pid="$(ss -ltnp '( sport = :7443 )' | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -1)"
if [[ -n "$old_pid" ]]; then
    old_command="$(tr '\0' ' ' <"/proc/$old_pid/cmdline")"
    if [[ "$old_command" != *"uvicorn cloud.api.integration:app_from_environment"* ]]; then
        echo "7443 is owned by an unexpected process; refusing cutover" >&2
        exit 1
    fi
    kill -TERM "$old_pid"
    for _ in $(seq 1 30); do
        kill -0 "$old_pid" >/dev/null 2>&1 || break
        sleep 1
    done
    if kill -0 "$old_pid" >/dev/null 2>&1; then
        echo "legacy 7443 process did not stop cleanly" >&2
        exit 1
    fi
fi

systemctl start nginx
health="$(curl -kfsS https://127.0.0.1:7443/health/ready)"
if [[ "$health" != *'"postgres":"ready"'* || "$health" != *'"object_store":"ready"'* ]]; then
    echo "new 7443 ingress did not return persistent readiness" >&2
    exit 1
fi
systemctl start feetforceplate-backup.service
systemctl start feetforceplate-backup.timer

printf 'seed_release=%s backend=ready ingress=7443 backup=verified-once secrets=not-printed\n' \
    "$(cat "$release_root/.release-sha")"
