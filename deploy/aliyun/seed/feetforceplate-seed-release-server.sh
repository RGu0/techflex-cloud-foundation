#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
    echo "run as root: sudo bash /home/rui/feetforceplate-seed-release-server.sh ARCHIVE RELEASE_SHA ARCHIVE_SHA256 FOUNDATION_WHEEL" >&2
    exit 2
fi
if [[ "$#" -ne 4 ]]; then
    echo "usage: $0 ARCHIVE RELEASE_SHA ARCHIVE_SHA256 FOUNDATION_WHEEL" >&2
    exit 2
fi

archive="$1"
release_sha="$2"
archive_sha="$3"
foundation_wheel="$4"
if [[ "$foundation_wheel" != /home/rui/techflex_cloud_foundation-*.whl || ! -f "$foundation_wheel" ]]; then
    echo "foundation wheel must be uploaded under /home/rui" >&2
    exit 2
fi
if [[ "$archive" != /home/rui/feetforceplate-*.tar.gz ]]; then
    echo "release archive must be located under /home/rui" >&2
    exit 2
fi
if [[ ! "$release_sha" =~ ^[0-9a-f]{40}$ || ! "$archive_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "release archive identifiers are invalid" >&2
    exit 2
fi
if [[ ! -f "$archive" ]]; then
    echo "release archive is missing" >&2
    exit 1
fi
if [[ "$(sha256sum "$archive" | awk '{print $1}')" != "$archive_sha" ]]; then
    echo "release archive checksum mismatch" >&2
    exit 1
fi

work_root="$(mktemp -d "/tmp/feetforceplate-release-${release_sha}.XXXXXX")"
cleanup() {
    rm -rf -- "$work_root"
}
trap cleanup EXIT

tar -xzf "$archive" -C "$work_root"
source /etc/feetforceplate/seed.env
bash "$work_root/deploy/aliyun/seed/install-seed-release.sh" \
    "$archive" "$release_sha" "$archive_sha" \
    /etc/feetforceplate/tls/seed.crt \
    /etc/feetforceplate/tls/seed.key \
    "$FEETFORCEPLATE_PUBLIC_BASE_URL" \
    "$FEETFORCEPLATE_BACKUP_AGE_RECIPIENT" \
    "$foundation_wheel"

printf 'release=%s deployment=completed secrets=not-printed\n' "$release_sha"
