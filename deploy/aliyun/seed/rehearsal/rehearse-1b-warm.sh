#!/usr/bin/env bash
# Rehearsal step 1b: fill the service uv cache with the third-party wheels of the release
# lock, fetched through a loopback proxy at 127.0.0.1:18080 (an `ssh -R` tunnel to the
# operator's allowlist proxy: files.pythonhosted.org only). uv verifies every lock hash.
# Then prove the runtime resolves with the network off, as the installer and the service do.
set -euo pipefail
umask 077
[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
rehearsal=/var/lib/feetforceplate/.rehearsal
rt="$rehearsal/release/deploy/aliyun/seed/runtime"
[[ -d "$rt" ]] || { echo "run rehearse-1-runtime.sh first" >&2; exit 1; }
curl -sS -o /dev/null -x http://127.0.0.1:18080 https://files.pythonhosted.org/ || { echo "proxy tunnel not reachable on 127.0.0.1:18080" >&2; exit 1; }
rm -rf -- "$rehearsal/venv"
install -d -o feetforceplate -g feetforceplate -m 0755 "$rehearsal/venv"
runuser -u feetforceplate -- env -u UV_OFFLINE HTTPS_PROXY=http://127.0.0.1:18080 NO_PROXY=mirrors.aliyun.com \
  XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache UV_PROJECT_ENVIRONMENT="$rehearsal/venv" \
  uv sync --frozen --no-dev --group acceptance --project "$rt" >/dev/null
rm -rf -- "$rehearsal/venv"
install -d -o feetforceplate -g feetforceplate -m 0755 "$rehearsal/venv"
runuser -u feetforceplate -- env UV_OFFLINE=1 \
  XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache UV_PROJECT_ENVIRONMENT="$rehearsal/venv" \
  uv sync --frozen --no-dev --group acceptance --project "$rt" >/dev/null
chmod -R a+rX "$rehearsal/venv"
runuser -u postgres -- "$rehearsal/venv/bin/python" -c 'import asyncpg, techflex_cloud_foundation.schema.__main__'
"$rehearsal/venv/bin/python" -c 'import importlib.metadata as m; print("foundation", m.version("techflex-cloud-foundation"))'
echo "rehearsal_step1=passed runtime_offline=ok postgres_user=ok scratch=$rehearsal"
