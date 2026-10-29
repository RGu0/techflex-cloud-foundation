#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${FEETFORCEPLATE_BACKUP_DSN:?live/source backup DSN is required for safety comparison}"
: "${FEETFORCEPLATE_OBJECT_ROOT:?live object root is required for safety comparison}"
: "${FEETFORCEPLATE_RESTORE_DSN:?restore target DSN is required}"
: "${FEETFORCEPLATE_RESTORE_OBJECT_ROOT:?restore target object root is required}"
: "${FEETFORCEPLATE_BACKUP_AGE_IDENTITY_FILE:?age identity file is required}"

if [[ "$#" -ne 1 || ! -f "$1" ]]; then
    echo "usage: restore-verify.sh ENCRYPTED_BACKUP" >&2
    exit 2
fi
bundle="$1"
if [[ "$FEETFORCEPLATE_RESTORE_DSN" == "$FEETFORCEPLATE_BACKUP_DSN" ]]; then
    echo "restore DSN must differ from the live DSN" >&2
    exit 2
fi
if [[ "$FEETFORCEPLATE_RESTORE_OBJECT_ROOT" == "$FEETFORCEPLATE_OBJECT_ROOT" ]]; then
    echo "restore object root must differ from the live object root" >&2
    exit 2
fi
schema_count="$(psql "$FEETFORCEPLATE_RESTORE_DSN" -Atqc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')")"
if [[ "$schema_count" != "0" ]]; then
    echo "target database must be empty" >&2
    exit 2
fi
mkdir -p "$FEETFORCEPLATE_RESTORE_OBJECT_ROOT"
if find "$FEETFORCEPLATE_RESTORE_OBJECT_ROOT" -mindepth 1 -print -quit | grep -q .; then
    echo "target object root must be empty" >&2
    exit 2
fi

work="$(mktemp -d)"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
age --decrypt --identity "$FEETFORCEPLATE_BACKUP_AGE_IDENTITY_FILE" \
    --output "$work/backup.tar" "$bundle"
tar -C "$work" -xf "$work/backup.tar"
pg_restore --no-owner --no-privileges --exit-on-error \
    --dbname="$FEETFORCEPLATE_RESTORE_DSN" "$work/database.dump"
tar -C "$FEETFORCEPLATE_RESTORE_OBJECT_ROOT" -xf "$work/objects.tar"
(
    cd "$FEETFORCEPLATE_RESTORE_OBJECT_ROOT"
    sha256sum --check --quiet "$work/object-manifest.sha256"
)
printf 'objects_verified=%s\n' "$(wc -l <"$work/object-manifest.sha256" | tr -d ' ')"
psql "$FEETFORCEPLATE_RESTORE_DSN" -v ON_ERROR_STOP=1 -Atqc \
    "SELECT 'tenants=' || count(*) FROM iam.tenants;
     SELECT 'licenses=' || count(*) FROM device.license_entitlements;
     SELECT 'rls=' || count(*) FROM pg_class WHERE relrowsecurity AND relforcerowsecurity;"
printf 'restore_verified bundle_sha256=%s\n' "$(sha256sum "$bundle" | sed 's/ .*//')"
