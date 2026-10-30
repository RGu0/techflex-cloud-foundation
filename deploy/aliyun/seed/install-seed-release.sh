#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
    echo "install-seed-release.sh must run as root" >&2
    exit 1
fi
# The caller's directory (an operator home) is not readable by the service or postgres users.
cd /
if [[ "$#" -ne 8 ]]; then
    echo "usage: install-seed-release.sh RELEASE_ARCHIVE RELEASE_SHA ARCHIVE_SHA256 TLS_CERT TLS_KEY PUBLIC_BASE_URL AGE_RECIPIENT FOUNDATION_WHEEL" >&2
    exit 2
fi

release_archive="$1"
release_sha="$2"
archive_sha256="$3"
tls_certificate="$4"
tls_private_key="$5"
public_base_url="$6"
age_recipient="$7"
foundation_wheel_source="$8"
service_user="feetforceplate"
service_group="feetforceplate"
database_name="feetforceplate_seed"
secret_file="/etc/feetforceplate/seed.env"

if [[ ! "$release_sha" =~ ^[0-9a-f]{40}$ || ! "$archive_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "release and archive SHA values are invalid" >&2
    exit 2
fi
if [[ ! -f "$release_archive" || ! -f "$tls_certificate" || ! -f "$tls_private_key" || ! -f "$foundation_wheel_source" ]]; then
    echo "release archive, foundation wheel and TLS source files must exist" >&2
    exit 2
fi
if [[ ! "$public_base_url" =~ ^https://[^/]+:7443$ ]]; then
    echo "public base URL must be an HTTPS 7443 origin" >&2
    exit 2
fi
if [[ ! "$age_recipient" =~ ^age1[0-9a-z]+$ ]]; then
    echo "age recipient is invalid" >&2
    exit 2
fi
if [[ "$(sha256sum "$release_archive" | sed 's/ .*//')" != "$archive_sha256" ]]; then
    echo "release archive checksum mismatch" >&2
    exit 1
fi
for command_name in age curl nginx openssl pg_isready psql python3 runuser systemctl tar uv; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "required command is missing: $command_name" >&2
        exit 1
    }
done
id "$service_user" >/dev/null 2>&1 || {
    echo "dedicated service identity is missing" >&2
    exit 1
}

install_root="$(mktemp -d /var/lib/feetforceplate/.install-seed.XXXXXX)"
chown root:postgres "$install_root"
chmod 0710 "$install_root"
# The service user never reaches install_root: root later executes files from
# release/, so the offline check runs on a separate copy (RAY-814).
offline_check_root="$(mktemp -d /var/lib/feetforceplate/.offline-check.XXXXXX)"
chmod 0711 "$offline_check_root"
cleanup() {
    rm -rf -- "$install_root" "$offline_check_root"
}
trap cleanup EXIT
release_source="$install_root/release"
install -d -o "$service_user" -g "$service_group" -m 0700 "$release_source"
tar -xzf "$release_archive" -C "$release_source"
runtime_project="$release_source/deploy/aliyun/seed/runtime"
if [[ ! -f "$runtime_project/pyproject.toml" || ! -f "$runtime_project/uv.lock" ]]; then
    echo "release has no pinned runtime project (deploy/aliyun/seed/runtime/uv.lock); nothing was changed" >&2
    exit 1
fi
foundation_info="$(python3 "$release_source/deploy/aliyun/seed/verify_foundation_release_lock.py" \
    "$runtime_project/pyproject.toml" "$runtime_project/uv.lock")"
read -r foundation_url foundation_sha256 <<<"$foundation_info"
# The host never fetches the wheel: the operator downloads it and uploads it with
# the archive, and the lock digest is checked again here (RAY-814).
foundation_wheel="$install_root/foundation-release.whl"
install -m 0600 "$foundation_wheel_source" "$foundation_wheel"
if [[ "$(sha256sum "$foundation_wheel" | sed 's/ .*//')" != "$foundation_sha256" ]]; then
    echo "foundation release wheel digest mismatch" >&2
    exit 1
fi
chown -R "$service_user:$service_group" "$release_source"
chmod -R a+rX "$release_source"
chmod 0755 \
    "$release_source/deploy/aliyun/seed/run-seed.sh" \
    "$release_source/deploy/aliyun/seed/venv-python.sh" \
    "$release_source/deploy/aliyun/seed/resume-seed-cutover.sh" \
    "$release_source/deploy/aliyun/seed/backup.sh" \
    "$release_source/deploy/aliyun/seed/check-secrets.sh" \
    "$release_source/deploy/aliyun/seed/configure-oss.sh" \
    "$release_source/deploy/aliyun/seed/restore-verify.sh" \
    "$release_source/deploy/aliyun/seed/run-restore-drill.sh" \
    "$release_source/deploy/aliyun/seed/run-live-acceptance.sh" \
    "$release_source/deploy/aliyun/seed/install-layout.sh"

# The seed and backup services resolve dependencies offline from the host uv
# cache, so prove the new release can before any migration or cutover.
cp -a "$release_source" "$offline_check_root/release"
chown -R "$service_user:$service_group" "$offline_check_root/release"
# The locked wheel is cached under its GitHub URL, which the host cannot reach.
# Hand the digest-checked upload to uv through a loopback endpoint that serves
# only that URL, so fresh hosts and foundation upgrades need no prior cache (RAY-836).
install -m 0644 "$foundation_wheel" "$offline_check_root/foundation-release.whl"
if ! runuser -u "$service_user" -- env \
    XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache \
    python3 "$offline_check_root/release/deploy/aliyun/seed/warm_foundation_wheel_cache.py" \
    "$offline_check_root/foundation-release.whl" "$foundation_url" "$foundation_sha256" "$(command -v uv)" >/dev/null; then
    echo "foundation release wheel could not be placed in the uv cache; nothing was changed" >&2
    exit 1
fi
# The runtime venv is rebuilt from the pinned runtime project, exactly as
# run-seed.sh does at service start, so a bad lock or cache fails here.
migration_venv="$offline_check_root/venv"
install -d -o "$service_user" -g "$service_group" -m 0755 "$migration_venv"
if ! runuser -u "$service_user" -- env UV_OFFLINE=1 \
    XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache \
    UV_PROJECT_ENVIRONMENT="$migration_venv" \
    uv sync --frozen --no-dev --group acceptance --project "$offline_check_root/release/deploy/aliyun/seed/runtime" >/dev/null; then
    echo "new release cannot resolve its locked dependencies offline; nothing was changed" >&2
    exit 1
fi
rm -rf -- "$offline_check_root/release"
# The migration runner connects as the PostgreSQL superuser over the Unix
# socket (peer authentication), so that OS user must be able to run it.
chmod -R a+rX "$migration_venv"
migration_python="$migration_venv/bin/python"
if ! runuser -u postgres -- "$migration_python" -c 'import asyncpg, techflex_cloud_foundation.schema.__main__' >/dev/null; then
    echo "the postgres OS user cannot run the migration runtime; nothing was changed" >&2
    exit 1
fi

if [[ ! -f "$secret_file" ]]; then
    tenant_password="$(openssl rand -hex 32)"
    activation_password="$(openssl rand -hex 32)"
    platform_password="$(openssl rand -hex 32)"
    backup_password="$(openssl rand -hex 32)"
    install -o "$service_user" -g "$service_group" -m 0600 /dev/null "$secret_file"
    {
        printf 'FEETFORCEPLATE_MIGRATION_DSN=postgresql://migration-disabled@127.0.0.1:5432/%s\n' "$database_name"
        printf 'FEETFORCEPLATE_TENANT_DSN=postgresql://ffp_seed_tenant:%s@127.0.0.1:5432/%s\n' "$tenant_password" "$database_name"
        printf 'FEETFORCEPLATE_ACTIVATION_DSN=postgresql://ffp_seed_activation:%s@127.0.0.1:5432/%s\n' "$activation_password" "$database_name"
        printf 'FEETFORCEPLATE_PLATFORM_DSN=postgresql://ffp_seed_platform:%s@127.0.0.1:5432/%s\n' "$platform_password" "$database_name"
        printf 'FEETFORCEPLATE_BACKUP_DSN=postgresql://ffp_seed_backup:%s@127.0.0.1:5432/%s\n' "$backup_password" "$database_name"
        printf 'FEETFORCEPLATE_TENANT_TOKEN_SECRET=%s\n' "$(openssl rand -hex 32)"
        printf 'FEETFORCEPLATE_PLATFORM_TOKEN_SECRET=%s\n' "$(openssl rand -hex 32)"
        printf 'FEETFORCEPLATE_TENANT_REFRESH_HMAC_KEY=%s\n' "$(openssl rand -hex 32)"
        printf 'FEETFORCEPLATE_PLATFORM_REFRESH_HMAC_KEY=%s\n' "$(openssl rand -hex 32)"
        printf 'FEETFORCEPLATE_TENANT_LOGIN_HMAC_KEY=%s\n' "$(openssl rand -hex 32)"
        printf 'FEETFORCEPLATE_PLATFORM_LOGIN_HMAC_KEY=%s\n' "$(openssl rand -hex 32)"
        printf 'FEETFORCEPLATE_ACTIVATION_HMAC_KEY=%s\n' "$(openssl rand -hex 32)"
        printf 'FEETFORCEPLATE_IDENTITY_LOOKUP_HMAC_KEY=%s\n' "$(openssl rand -hex 32)"
        printf 'FEETFORCEPLATE_IDENTITY_ENCRYPTION_KEY_B64=%s\n' "$(openssl rand -base64 32 | tr -d '\n')"
        printf 'FEETFORCEPLATE_LICENSE_PRIVATE_KEY_B64=%s\n' "$(openssl rand -base64 32 | tr -d '\n')"
        printf 'FEETFORCEPLATE_LICENSE_KEY_ID=license/1\n'
        printf 'FEETFORCEPLATE_TENANT_TOKEN_KEY_ID=tenant/1\n'
        printf 'FEETFORCEPLATE_PLATFORM_TOKEN_KEY_ID=platform/1\n'
        printf 'FEETFORCEPLATE_IDENTITY_KEY_VERSION=identity/1\n'
        printf 'FEETFORCEPLATE_OBJECT_ROOT=/var/lib/feetforceplate/objects\n'
        printf 'FEETFORCEPLATE_BACKUP_ROOT=/var/lib/feetforceplate/backups\n'
        printf 'FEETFORCEPLATE_BACKUP_AGE_RECIPIENT=%s\n' "$age_recipient"
        printf 'FEETFORCEPLATE_BACKUP_RETENTION_DAYS=30\n'
        printf 'FEETFORCEPLATE_PUBLIC_BASE_URL=%s\n' "$public_base_url"
        printf 'FEETFORCEPLATE_TRUSTED_PROXIES=127.0.0.1\n'
        printf 'FEETFORCEPLATE_SEED_ENV_FILE=%s\n' "$secret_file"
    } >"$secret_file"
    chown "$service_user:$service_group" "$secret_file"
    chmod 0600 "$secret_file"
else
    [[ "$(stat -c '%U:%G %a' "$secret_file")" == "$service_user:$service_group 600" ]] || {
        echo "existing seed.env has unsafe ownership or permissions" >&2
        exit 1
    }
    env_value() {
        sed -n "s/^$1=//p" "$secret_file"
    }
    tenant_dsn="$(env_value FEETFORCEPLATE_TENANT_DSN)"
    activation_dsn="$(env_value FEETFORCEPLATE_ACTIVATION_DSN)"
    platform_dsn="$(env_value FEETFORCEPLATE_PLATFORM_DSN)"
    backup_dsn="$(env_value FEETFORCEPLATE_BACKUP_DSN)"
    tenant_password="${tenant_dsn#postgresql://ffp_seed_tenant:}"
    tenant_password="${tenant_password%@127.0.0.1:5432/*}"
    activation_password="${activation_dsn#postgresql://ffp_seed_activation:}"
    activation_password="${activation_password%@127.0.0.1:5432/*}"
    platform_password="${platform_dsn#postgresql://ffp_seed_platform:}"
    platform_password="${platform_password%@127.0.0.1:5432/*}"
    backup_password="${backup_dsn#postgresql://ffp_seed_backup:}"
    backup_password="${backup_password%@127.0.0.1:5432/*}"
fi

if [[ "$(runuser -u postgres -- psql -Atqc "SELECT count(*) FROM pg_database WHERE datname='$database_name'")" == "0" ]]; then
    runuser -u postgres -- createdb "$database_name"
fi
socket_dir="$(runuser -u postgres -- psql -Atqc 'SHOW unix_socket_directories' | cut -d, -f1 | tr -d ' ')"
socket_dir="${socket_dir:-/var/run/postgresql}"
database_dsn="postgresql://postgres@/${database_name}?host=${socket_dir}"
run_schema() {
    runuser -u postgres -- "$migration_python" -m techflex_cloud_foundation.schema "$1" --dsn "$database_dsn"
}
role_wrapper="$install_root/roles.sql"
{
    printf "\\set database_name '%s'\n" "$database_name"
    printf "\\set tenant_password '%s'\n" "$tenant_password"
    printf "\\set activation_password '%s'\n" "$activation_password"
    printf "\\set platform_password '%s'\n" "$platform_password"
    printf "\\set backup_password '%s'\n" "$backup_password"
    printf "\\ir '%s'\n" "$release_source/deploy/aliyun/seed/postgresql-role-grants.sql"
} >"$role_wrapper"
chown postgres:postgres "$role_wrapper"
chmod 0600 "$role_wrapper"
apply_roles() {
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d "$database_name" -f "$role_wrapper"
}
# The runner pauses (exit 3) before the first step that names a role the
# deployment creates; create the roles and run again. The role step also grants
# on tables created by later migrations, so it runs once more after the last one.
set +e
run_schema apply
schema_status=$?
set -e
if [[ "$schema_status" -eq 3 ]]; then
    apply_roles
    run_schema apply
elif [[ "$schema_status" -ne 0 ]]; then
    echo "schema migration failed; see the message above" >&2
    exit 1
fi
apply_roles
if [[ "$(run_schema status)" != *'"pending": []'* ]]; then
    echo "schema migration left steps pending" >&2
    exit 1
fi

cp -a /var/lib/pgsql/data/pg_hba.conf "/var/lib/pgsql/data/pg_hba.conf.pre-seed.$(date -u +%Y%m%dT%H%M%SZ)"
install -o postgres -g postgres -m 0600 \
    "$release_source/deploy/aliyun/seed/pg_hba.conf" /var/lib/pgsql/data/pg_hba.conf
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -Atqc "ALTER SYSTEM SET password_encryption = 'scram-sha-256'"
systemctl restart postgresql
pg_isready -h 127.0.0.1 -p 5432 >/dev/null

release_target="/opt/feetforceplate/releases/$release_sha"
if [[ ! -d "$release_target" ]]; then
    bash "$release_source/deploy/aliyun/seed/install-layout.sh" "$release_source" "$release_sha"
elif [[ ! -f "$release_target/.release-sha" || "$(cat "$release_target/.release-sha")" != "$release_sha" ]]; then
    echo "existing release target does not match the requested SHA" >&2
    exit 1
else
    ln -sfn "$release_target" /opt/feetforceplate/app.next
    mv -Tf /opt/feetforceplate/app.next /opt/feetforceplate/app
fi

install_tls_file() {
    local source_path="$1"
    local target_path="$2"
    local mode="$3"
    if [[ "$(readlink -f "$source_path")" == "$(readlink -f "$target_path")" ]]; then
        chown root:root "$target_path"
        chmod "$mode" "$target_path"
    else
        install -o root -g root -m "$mode" "$source_path" "$target_path"
    fi
}
install_tls_file "$tls_private_key" /etc/feetforceplate/tls/seed.key 0600
install_tls_file "$tls_certificate" /etc/feetforceplate/tls/seed.crt 0644
if [[ ! -f /etc/nginx/nginx.conf.pre-seed ]]; then
    cp -a /etc/nginx/nginx.conf /etc/nginx/nginx.conf.pre-seed
fi
install -o root -g root -m 0644 "$release_target/deploy/aliyun/seed/nginx.conf" /etc/nginx/nginx.conf
install -o root -g root -m 0644 "$release_target/deploy/aliyun/seed/feetforceplate-seed.service" \
    /etc/systemd/system/feetforceplate-seed.service
install -o root -g root -m 0644 "$release_target/deploy/aliyun/seed/feetforceplate-backup.service" \
    /etc/systemd/system/feetforceplate-backup.service
install -o root -g root -m 0644 "$release_target/deploy/aliyun/seed/feetforceplate-backup.timer" \
    /etc/systemd/system/feetforceplate-backup.timer
systemctl daemon-reload
systemctl enable feetforceplate-seed.service feetforceplate-backup.timer nginx
systemctl restart feetforceplate-seed.service

backend_ready=false
for _ in $(seq 1 90); do
    if curl -fsS http://127.0.0.1:8743/health/ready >/dev/null; then
        backend_ready=true
        break
    fi
    sleep 2
done
if [[ "$backend_ready" != "true" ]]; then
    journalctl -u feetforceplate-seed.service -n 80 --no-pager >&2
    echo "seed backend did not become ready; existing 7443 service was not changed" >&2
    exit 1
fi

preflight_conf="$install_root/nginx-preflight.conf"
sed -e 's/listen 7443 ssl;/listen 17443 ssl;/' \
    -e 's/listen \[::\]:7443 ssl;/listen [::]:17443 ssl;/' \
    "$release_target/deploy/aliyun/seed/nginx-feetforceplate-seed.conf" >"$preflight_conf"
install -o root -g root -m 0644 "$preflight_conf" /etc/nginx/conf.d/feetforceplate-seed.conf
nginx -t
systemctl restart nginx
curl -kfsS https://127.0.0.1:17443/health/ready >/dev/null
systemctl stop nginx
install -o root -g root -m 0644 \
    "$release_target/deploy/aliyun/seed/nginx-feetforceplate-seed.conf" \
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
curl -kfsS https://127.0.0.1:7443/health/ready >/dev/null
systemctl start feetforceplate-backup.service
systemctl start feetforceplate-backup.timer

printf 'seed_release=%s backend=ready ingress=7443 backup=verified-once secrets=not-printed\n' "$release_sha"
