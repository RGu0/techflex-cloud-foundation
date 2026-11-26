#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# RAY-1029: the service start is the one entry that syncs the runtime venv it runs
# from; every other entry only verifies it (see venv-python.sh).
export FEETFORCEPLATE_VENV_SYNC=1
exec "$here/venv-python.sh" -m techflex_cloud_foundation.server.seed
