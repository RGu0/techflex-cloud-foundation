#!/usr/bin/env bash
# Run the pinned seed runtime's Python from FEETFORCEPLATE_VENV.
#
# RAY-1029: only a caller that owns the environment may change it.
#   FEETFORCEPLATE_VENV_SYNC=1  bring the venv in line with the release's runtime
#                               lock (offline from the uv cache), then record the
#                               lock digest in the venv.  The seed service start
#                               (run-seed.sh) and live acceptance's private venv
#                               do this.
#   unset (default)             verify only: the venv must already record the
#                               current lock's digest.  Nothing is synced or
#                               installed, so timers and CLIs never modify the
#                               environment the API is running from; a stale or
#                               unsynced venv is refused instead.
# FEETFORCEPLATE_ACCEPTANCE=1 adds the acceptance dependency group and is allowed
# only with FEETFORCEPLATE_VENV_SYNC=1, i.e. only for a venv the caller owns.
set -euo pipefail

release_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${FEETFORCEPLATE_VENV:?missing FEETFORCEPLATE_VENV}"
runtime_project="$release_root/deploy/aliyun/seed/runtime"
lock_file="$runtime_project/uv.lock"
stamp_file="$FEETFORCEPLATE_VENV/.feetforceplate-runtime-lock.sha256"
python="$FEETFORCEPLATE_VENV/bin/python"

lock_digest() {
    "$python" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
        "$lock_file"
}

if [[ "${FEETFORCEPLATE_VENV_SYNC:-}" == "1" ]]; then
    export UV_PROJECT_ENVIRONMENT="$FEETFORCEPLATE_VENV"
    # The host has no package index; the units set this too, the acceptance wrappers rely on it.
    export UV_OFFLINE="${UV_OFFLINE:-1}"
    groups=()
    if [[ "${FEETFORCEPLATE_ACCEPTANCE:-}" == "1" ]]; then
        groups=(--group acceptance)
    fi
    uv sync --frozen --no-dev ${groups[@]+"${groups[@]}"} --quiet --project "$runtime_project"
    digest="$(lock_digest)"
    printf '%s\n' "$digest" > "$stamp_file.tmp"
    mv -f -- "$stamp_file.tmp" "$stamp_file"
else
    if [[ "${FEETFORCEPLATE_ACCEPTANCE:-}" == "1" ]]; then
        echo "venv-python.sh: the acceptance group needs FEETFORCEPLATE_VENV_SYNC=1 on a private venv; the runtime venv is never modified here" >&2
        exit 2
    fi
    if [[ ! -x "$python" || ! -f "$stamp_file" ]]; then
        echo "venv-python.sh: $FEETFORCEPLATE_VENV has not been synced by the seed service; start or restart feetforceplate-seed first (nothing was changed)" >&2
        exit 3
    fi
    if [[ "$(< "$stamp_file")" != "$(lock_digest)" ]]; then
        echo "venv-python.sh: $FEETFORCEPLATE_VENV does not match this release's runtime lock; restart feetforceplate-seed to sync it (nothing was changed)" >&2
        exit 3
    fi
fi
cd "$release_root"
exec "$python" "$@"
