#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
    echo "run as root: sudo bash /home/rui/feetforceplate-sales-inventory-server.sh PLATFORM_LOGIN" >&2
    exit 2
fi
if [[ "$#" -ne 1 ]]; then
    echo "usage: $0 PLATFORM_LOGIN" >&2
    exit 2
fi

platform_login="$1"
release_manifest="/home/rui/feetforceplate-sales-inventory-release.env"
if [[ ! -r "$release_manifest" ]]; then
    echo "release manifest is missing or unreadable: $release_manifest" >&2
    exit 1
fi
source "$release_manifest"
release_sha="${RELEASE_SHA:?missing RELEASE_SHA}"
archive_sha="${ARCHIVE_SHA256:?missing ARCHIVE_SHA256}"
archive="${ARCHIVE_PATH:?missing ARCHIVE_PATH}"
foundation_wheel="${FOUNDATION_WHEEL_PATH:?missing FOUNDATION_WHEEL_PATH}"
if [[ ! "$release_sha" =~ ^[0-9a-f]{40}$ ]] || [[ ! "$archive_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "release manifest contains an invalid checksum or release identifier" >&2
    exit 1
fi
if [[ "$archive" != /home/rui/* ]]; then
    echo "release archive must be located under /home/rui" >&2
    exit 1
fi
work_root="/tmp/feetforceplate-sales-inventory-$release_sha"
delivery_root="/var/lib/feetforceplate/delivery"
database_name="feetforceplate_seed"

if [[ "$foundation_wheel" != /home/rui/* || ! -f "$foundation_wheel" ]]; then
    echo "foundation wheel is missing or not under /home/rui" >&2
    exit 1
fi
if [[ ! -f "$archive" ]]; then
    echo "release archive is missing: $archive" >&2
    exit 1
fi
if [[ "$(sha256sum "$archive" | awk '{print $1}')" != "$archive_sha" ]]; then
    echo "release archive checksum mismatch" >&2
    exit 1
fi
rm -rf -- "$work_root"
install -d -m 0700 "$work_root"
trap 'rm -rf -- "$work_root"' EXIT
tar -xzf "$archive" -C "$work_root"
install -m 0644 /etc/feetforceplate/tls/seed.crt "$work_root/seed.crt"
install -m 0600 /etc/feetforceplate/tls/seed.key "$work_root/seed.key"

source /etc/feetforceplate/seed.env
cd /
bash "$work_root/deploy/aliyun/seed/install-seed-release.sh" \
    "$archive" "$release_sha" "$archive_sha" \
    "$work_root/seed.crt" \
    "$work_root/seed.key" \
    "$FEETFORCEPLATE_PUBLIC_BASE_URL" \
    "$FEETFORCEPLATE_BACKUP_AGE_RECIPIENT" \
    "$foundation_wheel"

install -d -o feetforceplate -g feetforceplate -m 0700 "$delivery_root"
delivery_file="$delivery_root/sales-inventory-$(date -u +%Y%m%dT%H%M%SZ).json"
runuser -u feetforceplate -- bash -c '
    set -euo pipefail
    cd /opt/feetforceplate/app
    export FEETFORCEPLATE_VENV=/var/lib/feetforceplate/runtime/venv
    export XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache
    set -a
    source /etc/feetforceplate/seed.env
    set +a
    exec ./deploy/aliyun/seed/venv-python.sh -m techflex_cloud_foundation.server.access_control.cli create-sales-inventory \
        --platform-login "$1" --quantity 10 --output "$2"
' bash "$platform_login" "$delivery_file"

batch_id="$(runuser -u postgres -- psql -d "$database_name" -Atqc \
    "SELECT inventory_batch_id FROM sales.inventory_batches ORDER BY created_at DESC LIMIT 1")"
if [[ ! "$batch_id" =~ ^[0-9a-f-]{36}$ ]]; then
    echo "unable to resolve generated inventory batch" >&2
    exit 1
fi
runuser -u postgres -- psql -d "$database_name" -Atqc \
    "SELECT 'batch_id=' || '$batch_id'
       UNION ALL SELECT 'asset_in_stock=' || count(*) FROM sales.device_inventory
        WHERE inventory_batch_id='$batch_id' AND status='IN_STOCK'
       UNION ALL SELECT 'license_unused=' || count(*) FROM sales.license_inventory
        WHERE inventory_batch_id='$batch_id' AND status='UNUSED'
       UNION ALL SELECT 'license_period_months=' || license_period_months
        FROM sales.inventory_batches WHERE inventory_batch_id='$batch_id'
       UNION ALL SELECT 'prebound_pairs=' || count(*) FROM sales.inventory_activations
        WHERE device_inventory_id IN (
          SELECT device_inventory_id FROM sales.device_inventory
          WHERE inventory_batch_id='$batch_id'
        )"
printf 'delivery_file=written owner=feetforceplate mode=%s codes=not-printed\n' \
    "$(stat -c '%a' "$delivery_file")"
