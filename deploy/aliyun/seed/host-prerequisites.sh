#!/usr/bin/env bash
set -euo pipefail

service_user="feetforceplate"
service_group="feetforceplate"
age_source_dir="${1:-/home/rui/apps/feetforceplate-seed/tools/age-v1.3.1}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "host-prerequisites.sh must run as root" >&2
    exit 1
fi
if [[ ! -x "$age_source_dir/age" || ! -x "$age_source_dir/age-keygen" ]]; then
    echo "verified age and age-keygen binaries are required in $age_source_dir" >&2
    exit 1
fi

dnf install -y nginx postgresql-server postgresql-contrib

if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
    postgresql-setup --initdb
fi
systemctl enable --now postgresql

if ! getent group "$service_group" >/dev/null 2>&1; then
    groupadd --system "$service_group"
fi
if ! id "$service_user" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /var/lib/feetforceplate \
        --shell /sbin/nologin --gid "$service_group" "$service_user"
fi

install -d -o root -g root -m 0755 /opt/feetforceplate/releases
install -d -o root -g root -m 0755 /etc/feetforceplate /etc/feetforceplate/tls
install -d -o "$service_user" -g "$service_group" -m 0700 \
    /var/lib/feetforceplate/objects \
    /var/lib/feetforceplate/backups \
    /var/lib/feetforceplate/runtime

install -o root -g root -m 0755 "$age_source_dir/age" /usr/local/bin/age
install -o root -g root -m 0755 "$age_source_dir/age-keygen" /usr/local/bin/age-keygen

echo "host prerequisites ready; existing 7443 service was not changed"
