#!/usr/bin/env bash
# Run the pinned seed runtime's Python: bring the service venv in line with the
# release's runtime lock (offline from the uv cache), then exec it.
set -euo pipefail

release_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${FEETFORCEPLATE_VENV:?missing FEETFORCEPLATE_VENV}"
export UV_PROJECT_ENVIRONMENT="$FEETFORCEPLATE_VENV"
# The host has no package index; the units set this too, the acceptance wrappers rely on it.
export UV_OFFLINE="${UV_OFFLINE:-1}"
groups=()
if [[ "${FEETFORCEPLATE_ACCEPTANCE:-}" == "1" ]]; then
    groups=(--group acceptance)
fi
uv sync --frozen --no-dev ${groups[@]+"${groups[@]}"} --quiet \
    --project "$release_root/deploy/aliyun/seed/runtime"
cd "$release_root"
exec "$FEETFORCEPLATE_VENV/bin/python" "$@"
