#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "run-restore-drill.sh must run as root" >&2
    exit 2
fi
if [[ "$#" -ne 2 || ! -f "$1" ]]; then
    echo "usage: run-restore-drill.sh AGE_IDENTITY_SOURCE REDACTED_OUTPUT" >&2
    exit 2
fi

identity_source="$1"
redacted_output="$2"
case "$identity_source" in
    /home/rui/apps/feetforceplate-network/shared/incoming/*) ;;
    *) echo "age identity source must be in the protected incoming directory" >&2; exit 2 ;;
esac
case "$redacted_output" in
    /home/rui/apps/feetforceplate-network/shared/evidence/*) ;;
    *) echo "redacted output must be in the shared evidence directory" >&2; exit 2 ;;
esac

release_sha="$(cat /opt/feetforceplate/app/.release-sha)"
if [[ ! "$release_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "installed release SHA is invalid" >&2
    exit 2
fi
release_short="${release_sha:0:12}"
restore_database="feetforceplate_restore_${release_short}"
work_root="/var/lib/pgsql/feetforceplate-restore-${release_short}"
restore_object_root="$work_root/objects"
identity_file="$work_root/backup.agekey"
bundle_copy="$work_root/backup.tar.age"
private_evidence="$work_root/restore-evidence.txt"
backup_root="/var/lib/feetforceplate/backups"
live_database="feetforceplate_seed"
live_object_root="/var/lib/feetforceplate/objects"

cleanup() {
    set +e
    runuser -u postgres -- dropdb --if-exists "$restore_database" >/dev/null 2>&1
    rm -rf -- "$work_root"
    rm -f -- "$identity_source"
}
trap cleanup EXIT

runuser -u postgres -- dropdb --if-exists "$restore_database" >/dev/null
rm -rf -- "$work_root"
install -d -o postgres -g postgres -m 0700 "$work_root" "$restore_object_root"
install -o postgres -g postgres -m 0600 "$identity_source" "$identity_file"

mapfile -t backup_candidates < <(
    find "$backup_root" -maxdepth 1 -type f -name '*.tar.age' -printf '%T@ %p\n' \
        | sort -nr
)
if [[ "${#backup_candidates[@]}" -eq 0 ]]; then
    echo "no encrypted backup bundle is available" >&2
    exit 1
fi
bundle="${backup_candidates[0]#* }"
sidecar="$bundle.sha256"
if [[ ! -f "$sidecar" ]]; then
    echo "newest backup has no SHA-256 sidecar" >&2
    exit 1
fi
read -r expected_bundle_sha _ <"$sidecar"
actual_bundle_sha="$(sha256sum "$bundle" | sed 's/ .*//')"
if [[ ! "$expected_bundle_sha" =~ ^[0-9a-f]{64}$ || "$actual_bundle_sha" != "$expected_bundle_sha" ]]; then
    echo "encrypted backup SHA-256 verification failed" >&2
    exit 1
fi
install -o postgres -g postgres -m 0600 "$bundle" "$bundle_copy"

live_database_before="$(runuser -u postgres -- psql -d "$live_database" -Atqc \
    "SELECT count(*) || ':' || (SELECT count(*) FROM device.license_entitlements) FROM iam.tenants")"
live_objects_before="$(find "$live_object_root" -type f | wc -l | tr -d ' ')"

runuser -u postgres -- createdb "$restore_database"
runuser -u postgres -- env \
    FEETFORCEPLATE_BACKUP_DSN="postgresql:///$live_database" \
    FEETFORCEPLATE_OBJECT_ROOT="$live_object_root" \
    FEETFORCEPLATE_RESTORE_DSN="postgresql:///$restore_database" \
    FEETFORCEPLATE_RESTORE_OBJECT_ROOT="$restore_object_root" \
    FEETFORCEPLATE_BACKUP_AGE_IDENTITY_FILE="$identity_file" \
    bash /opt/feetforceplate/app/deploy/aliyun/seed/restore-verify.sh \
    "$bundle_copy" >"$private_evidence"

live_database_after="$(runuser -u postgres -- psql -d "$live_database" -Atqc \
    "SELECT count(*) || ':' || (SELECT count(*) FROM device.license_entitlements) FROM iam.tenants")"
live_objects_after="$(find "$live_object_root" -type f | wc -l | tr -d ' ')"
if [[ "$live_database_before" != "$live_database_after" || "$live_objects_before" != "$live_objects_after" ]]; then
    echo "production state changed during isolated restore" >&2
    exit 1
fi

output_owner="${SUDO_USER:-root}"
output_group="$(id -gn "$output_owner")"
install -D -o "$output_owner" -g "$output_group" -m 0644 \
    "$private_evidence" "$redacted_output"
cleanup
trap - EXIT

if [[ -d "$work_root" || -e "$identity_source" ]]; then
    echo "restore drill cleanup did not remove private material" >&2
    exit 1
fi
if [[ "$(runuser -u postgres -- psql -Atqc \
    "SELECT count(*) FROM pg_database WHERE datname='$restore_database'")" != "0" ]]; then
    echo "restore drill cleanup did not remove the temporary database" >&2
    exit 1
fi

summary="restore_drill=passed production_unchanged=true cleanup=verified release=$release_sha bundle_sha256=$actual_bundle_sha"
printf '%s\n' "$summary" | tee -a "$redacted_output"
