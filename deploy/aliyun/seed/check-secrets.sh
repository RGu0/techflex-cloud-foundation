#!/usr/bin/env bash
set -euo pipefail

secret_file="${1:-/etc/feetforceplate/seed.env}"
if [[ ! -f "$secret_file" ]]; then
    echo "seed environment file is missing" >&2
    exit 1
fi
mode="$(stat -c '%a' "$secret_file")"
owner="$(stat -c '%U:%G' "$secret_file")"
if [[ "$mode" != "600" ]]; then
    echo "seed environment file must have mode 0600" >&2
    exit 1
fi
printf 'secret_file=seed.env owner=%s mode=%s values=not-inspected\n' "$owner" "$mode"
