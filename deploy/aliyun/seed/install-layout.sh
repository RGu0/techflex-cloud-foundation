#!/usr/bin/env bash
set -euo pipefail

service_user="feetforceplate"
service_group="feetforceplate"
releases_root="/opt/feetforceplate/releases"
current_link="/opt/feetforceplate/app"
secret_file="/etc/feetforceplate/seed.env"
objects_root="/var/lib/feetforceplate/objects"
backups_root="/var/lib/feetforceplate/backups"
validation_telemetry_root="/var/lib/feetforceplate/validation-telemetry"
runtime_root="/var/lib/feetforceplate/runtime"

if [[ "${EUID}" -ne 0 ]]; then
    echo "install-layout.sh must run as root" >&2
    exit 1
fi
if [[ "$#" -ne 2 ]]; then
    echo "usage: install-layout.sh RELEASE_SOURCE RELEASE_SHA" >&2
    exit 2
fi
release_source="$1"
release_sha="$2"
if [[ ! "$release_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "release SHA must contain 40 lowercase hexadecimal characters" >&2
    exit 2
fi
if [[ ! -d "$release_source" ]]; then
    echo "release source must be a directory" >&2
    exit 2
fi
if find "$release_source" -user root -print -quit | grep -q .; then
    echo "release source files must not be root-owned" >&2
    exit 1
fi
if ! id "$service_user" >/dev/null 2>&1; then
    echo "dedicated service user feetforceplate does not exist" >&2
    exit 1
fi
if [[ ! -f "$secret_file" ]]; then
    echo "missing /etc/feetforceplate/seed.env" >&2
    exit 1
fi
secret_mode="$(stat -c '%a' "$secret_file")"
if [[ "$secret_mode" != "600" ]]; then
    echo "seed.env must have mode 0600" >&2
    exit 1
fi

install -d -o "$service_user" -g "$service_group" -m 0755 "$releases_root"
install -d -o "$service_user" -g "$service_group" -m 0700 \
    "$objects_root" "$backups_root" "$validation_telemetry_root"
install -d -o "$service_user" -g "$service_group" -m 0700 "$runtime_root"
release_target="$releases_root/$release_sha"
if [[ -e "$release_target" ]]; then
    echo "release target already exists" >&2
    exit 1
fi
cp -a "$release_source" "$release_target"
chown -R "$service_user:$service_group" "$release_target"
printf '%s\n' "$release_sha" >"$release_target/.release-sha"
chown "$service_user:$service_group" "$release_target/.release-sha"
chmod -R a-w "$release_target"
ln -sfn "$release_target" "$current_link.next"
mv -Tf "$current_link.next" "$current_link"
printf 'installed release %s\n' "$release_sha"
