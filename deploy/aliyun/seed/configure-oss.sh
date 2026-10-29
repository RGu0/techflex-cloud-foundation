#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
    echo "configure-oss.sh must run as root" >&2
    exit 1
fi
if [[ "$#" -lt 4 || "$#" -gt 5 ]]; then
    echo "usage: configure-oss.sh REGION BUCKET INTERNAL_ENDPOINT ECS_RAM_ROLE [KMS|AES256]" >&2
    exit 2
fi

region="$1"
bucket="$2"
endpoint="$3"
ecs_ram_role="$4"
server_side_encryption="${5:-KMS}"
secret_file="/etc/feetforceplate/seed.env"
service_user="feetforceplate"
service_group="feetforceplate"
validation_telemetry_root="/var/lib/feetforceplate/validation-telemetry"

if [[ ! "$region" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    echo "OSS region is invalid" >&2
    exit 2
fi
if [[ ! "$bucket" =~ ^[a-z0-9][a-z0-9-]{2,62}$ ]]; then
    echo "OSS bucket name is invalid" >&2
    exit 2
fi
if [[ "$endpoint" != "https://oss-${region}-internal.aliyuncs.com" ]]; then
    echo "OSS endpoint must be the region internal HTTPS endpoint" >&2
    exit 2
fi
if [[ ! "$ecs_ram_role" =~ ^[A-Za-z0-9_@.-]{1,64}$ ]]; then
    echo "ECS RAM role name is invalid" >&2
    exit 2
fi
if [[ "$server_side_encryption" != "KMS" && "$server_side_encryption" != "AES256" ]]; then
    echo "OSS server-side encryption must be KMS or AES256" >&2
    exit 2
fi
if [[ ! -f "$secret_file" ]]; then
    echo "missing /etc/feetforceplate/seed.env" >&2
    exit 1
fi
if [[ "$(stat -c '%U:%G %a' "$secret_file")" != "$service_user:$service_group 600" ]]; then
    echo "seed.env has unsafe ownership or permissions" >&2
    exit 1
fi

temporary_file="$(mktemp "${secret_file}.tmp.XXXXXX")"
cleanup() {
    rm -f -- "$temporary_file"
}
trap cleanup EXIT

while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
        FEETFORCEPLATE_OBJECT_BACKEND=* | \
        FEETFORCEPLATE_OSS_REGION=* | \
        FEETFORCEPLATE_OSS_BUCKET=* | \
        FEETFORCEPLATE_OSS_ENDPOINT=* | \
        FEETFORCEPLATE_OSS_SERVER_SIDE_ENCRYPTION=* | \
        FEETFORCEPLATE_OSS_ECS_RAM_ROLE=* | \
        FEETFORCEPLATE_VALIDATION_TELEMETRY_ROOT=*)
            ;;
        *)
            printf '%s\n' "$line" >>"$temporary_file"
            ;;
    esac
done <"$secret_file"

{
    printf 'FEETFORCEPLATE_OBJECT_BACKEND=aliyun-oss\n'
    printf 'FEETFORCEPLATE_OSS_REGION=%s\n' "$region"
    printf 'FEETFORCEPLATE_OSS_BUCKET=%s\n' "$bucket"
    printf 'FEETFORCEPLATE_OSS_ENDPOINT=%s\n' "$endpoint"
    printf 'FEETFORCEPLATE_OSS_SERVER_SIDE_ENCRYPTION=%s\n' "$server_side_encryption"
    printf 'FEETFORCEPLATE_OSS_ECS_RAM_ROLE=%s\n' "$ecs_ram_role"
    printf 'FEETFORCEPLATE_VALIDATION_TELEMETRY_ROOT=%s\n' "$validation_telemetry_root"
} >>"$temporary_file"

chown "$service_user:$service_group" "$temporary_file"
chmod 0600 "$temporary_file"
mv -f -- "$temporary_file" "$secret_file"
trap - EXIT
printf 'oss_configuration=updated values=not-printed credentials=ecs-ram-role\n'
