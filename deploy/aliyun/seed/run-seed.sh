#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$here/venv-python.sh" -m techflex_cloud_foundation.server.seed
