#!/usr/bin/env bash
# Rehearsal step 1: prove the release in ARCHIVE resolves its locked runtime offline on this
# host, as install-seed-release.sh does before it changes anything. Touches only a
# scratch directory and adds the digest-checked wheel to the service uv cache.
set -euo pipefail
umask 077
[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ "$#" -eq 3 ]] || { echo "usage: $0 ARCHIVE ARCHIVE_SHA256 WHEEL" >&2; exit 2; }
archive="$1"
want_archive="$2"
wheel="$3"
[[ "$(sha256sum "$archive" | cut -d' ' -f1)" == "$want_archive" ]] || { echo "archive digest mismatch" >&2; exit 1; }
rehearsal=/var/lib/feetforceplate/.rehearsal
rm -rf -- "$rehearsal"
install -d -m 0711 "$rehearsal"
install -d -o feetforceplate -g feetforceplate -m 0755 "$rehearsal/release"
tar -xzf "$archive" -C "$rehearsal/release"
chown -R feetforceplate:feetforceplate "$rehearsal/release"
chmod -R a+rX "$rehearsal/release"
rt="$rehearsal/release/deploy/aliyun/seed/runtime"
read -r url sha < <(python3 "$rehearsal/release/deploy/aliyun/seed/verify_foundation_release_lock.py" "$rt/pyproject.toml" "$rt/uv.lock")
[[ "$(sha256sum "$wheel" | cut -d' ' -f1)" == "$sha" ]] || { echo "wheel digest differs from the runtime lock" >&2; exit 1; }
install -m 0644 "$wheel" "$rehearsal/foundation-release.whl"
runuser -u feetforceplate -- env XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache \
  python3 "$rehearsal/release/deploy/aliyun/seed/warm_foundation_wheel_cache.py" \
  "$rehearsal/foundation-release.whl" "$url" "$sha" "$(command -v uv)" >/dev/null
install -d -o feetforceplate -g feetforceplate -m 0755 "$rehearsal/venv"
runuser -u feetforceplate -- env UV_OFFLINE=1 XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache \
  UV_PROJECT_ENVIRONMENT="$rehearsal/venv" \
  uv sync --frozen --no-dev --group acceptance --project "$rt" >/dev/null
chmod -R a+rX "$rehearsal/venv"
runuser -u postgres -- "$rehearsal/venv/bin/python" -c 'import asyncpg, techflex_cloud_foundation.schema.__main__'
"$rehearsal/venv/bin/python" -c 'import importlib.metadata as m; print("foundation", m.version("techflex-cloud-foundation"))'
echo "rehearsal_step1=passed runtime_offline=ok postgres_user=ok scratch=$rehearsal"
