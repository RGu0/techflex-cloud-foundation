#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
server="${1:-aliyun-agentic}"
release_sha="$(git -C "$repo_root" rev-parse HEAD)"
archive="${TMPDIR:-/private/tmp}/feetforceplate-${release_sha}.tar.gz"
remote_archive="/home/rui/$(basename "$archive")"
remote_wrapper_source="$repo_root/deploy/aliyun/seed/feetforceplate-seed-release-server.sh"
remote_wrapper="/home/rui/$(basename "$remote_wrapper_source")"

cleanup() {
    rm -f -- "$archive" "${foundation_wheel:-}"
}
trap cleanup EXIT

git -C "$repo_root" diff --quiet
git -C "$repo_root" diff --cached --quiet
# The host cannot reach github.com, so the operator downloads the foundation wheel,
# checks it against the runtime lock, and uploads it with the archive (RAY-814).
git -C "$repo_root" archive --format=tar.gz --output="$archive" "$release_sha" deploy scripts tests
archive_sha="$(shasum -a 256 "$archive" | awk '{print $1}')"
read -r foundation_url foundation_sha256 < <(python3 \
    "$repo_root/deploy/aliyun/seed/verify_foundation_release_lock.py" \
    "$repo_root/deploy/aliyun/seed/runtime/pyproject.toml" \
    "$repo_root/deploy/aliyun/seed/runtime/uv.lock")
foundation_wheel="${TMPDIR:-/private/tmp}/$(basename "$foundation_url")"
curl --fail --location --silent --show-error --retry 5 --proto '=https' \
    --proto-redir '=https' --output "$foundation_wheel" "$foundation_url"
if [[ "$(shasum -a 256 "$foundation_wheel" | awk '{print $1}')" != "$foundation_sha256" ]]; then
    echo "foundation release wheel digest mismatch" >&2
    rm -f -- "$foundation_wheel"
    exit 1
fi
remote_foundation_wheel="/home/rui/$(basename "$foundation_wheel")"

scp "$archive" "$foundation_wheel" "$remote_wrapper_source" "$server:/home/rui/"

ssh -tt "$server" sudo /bin/bash "$remote_wrapper" \
    "$remote_archive" "$release_sha" "$archive_sha" "$remote_foundation_wheel"

printf 'release=%s archive_sha256=%s deployment=completed\n' "$release_sha" "$archive_sha"
