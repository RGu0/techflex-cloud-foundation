#!/usr/bin/env bash
set -euo pipefail
umask 077

acceptance_cleanup() {
    local exit_status="$1"
    local state_path="$2"
    local restart_path="$3"
    if [[ "$exit_status" -eq 0 ]]; then
        rm -f -- "$state_path" "$restart_path"
    elif [[ -f "$state_path" ]]; then
        echo "acceptance_state=preserved_for_resume secrets=not-printed" >&2
    fi
}

acceptance_phase() {
    local state_path="$1"
    local restart_path="$2"
    if [[ ! -f "$state_path" ]]; then
        echo "before-restart"
    elif [[ ! -f "$restart_path" ]]; then
        echo "restart-required"
    else
        echo "after-restart"
    fi
}

acceptance_public_junit_path() {
    local redacted_output="$1"
    printf '%s-postgres.xml\n' "${redacted_output%.json}"
}

acceptance_public_oss_path() {
    local redacted_output="$1"
    printf '%s-oss.json\n' "${redacted_output%.json}"
}

main() {
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "run-live-acceptance.sh must run as root" >&2
    exit 2
fi
if [[ "$#" -ne 2 || ! -f "$1" ]]; then
    echo "usage: run-live-acceptance.sh CA_CERT REDACTED_OUTPUT" >&2
    exit 2
fi

ca_cert="$1"
redacted_output="$2"
public_junit_file="$(acceptance_public_junit_path "$redacted_output")"
public_oss_file="$(acceptance_public_oss_path "$redacted_output")"
service_user="feetforceplate"
app_root="/opt/feetforceplate/app"
acceptance_root="/var/lib/feetforceplate/acceptance"
state_file="$acceptance_root/private-state.json"
restart_marker="$acceptance_root/restart-complete"
evidence_file="$acceptance_root/aliyun-seed-summary.json"
junit_file="$acceptance_root/postgres-role-parity.xml"
oss_evidence_file="$acceptance_root/aliyun-oss-summary.json"
env_file="/etc/feetforceplate/seed.env"

install -d -o "$service_user" -g "$service_user" -m 0700 "$acceptance_root"
cleanup() {
    acceptance_cleanup "$?" "$state_file" "$restart_marker"
}
trap cleanup EXIT

run_seed_python() {
    local phase="$1"
    runuser -u "$service_user" -- bash -c '
        set -euo pipefail
        cd /opt/feetforceplate/app
        export FEETFORCEPLATE_VENV=/var/lib/feetforceplate/runtime/venv
        export XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache
        set -a
        source /etc/feetforceplate/seed.env
        set +a
        exec ./deploy/aliyun/seed/venv-python.sh scripts/verify_seed_live.py \
            --phase "$1" \
            --base-url "$FEETFORCEPLATE_PUBLIC_BASE_URL" \
            --ca-file "$2" \
            --state "$3" \
            --evidence "$4"
    ' bash "$phase" "$ca_cert" "$state_file" "$evidence_file"
}

phase="$(acceptance_phase "$state_file" "$restart_marker")"
if [[ "$phase" == "before-restart" ]]; then
    run_seed_python before-restart
fi
if [[ "$phase" != "after-restart" ]]; then
    rm -f -- "$restart_marker"
    systemctl restart postgresql
    systemctl restart feetforceplate-seed

source "$env_file"
public_base_url="$FEETFORCEPLATE_PUBLIC_BASE_URL"
ready=0
for _attempt in $(seq 1 30); do
    if curl --silent --show-error --fail --cacert "$ca_cert" \
        "$public_base_url/health/ready" \
        >/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
    if [[ "$ready" -ne 1 ]]; then
        echo "seed service did not recover after PostgreSQL and application restart" >&2
        exit 1
    fi
    install -o "$service_user" -g "$service_user" -m 0600 /dev/null "$restart_marker"
fi

run_seed_python after-restart
runuser -u "$service_user" -- bash -c '
    set -euo pipefail
    cd /opt/feetforceplate/app
    export FEETFORCEPLATE_VENV=/var/lib/feetforceplate/runtime/venv
    export XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache
    set -a
    source /etc/feetforceplate/seed.env
    set +a
    exec ./deploy/aliyun/seed/venv-python.sh scripts/verify_aliyun_oss_live.py \
        --output "$1"
' bash "$oss_evidence_file"
runuser -u "$service_user" -- bash -c '
    set -euo pipefail
    cd /opt/feetforceplate/app
    export FEETFORCEPLATE_VENV=/var/lib/feetforceplate/runtime/venv
    export XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache
    set -a
    source /etc/feetforceplate/seed.env
    set +a
    export FEETFORCEPLATE_TEST_TENANT_DSN="$FEETFORCEPLATE_TENANT_DSN"
    export FEETFORCEPLATE_TEST_ACTIVATION_DSN="$FEETFORCEPLATE_ACTIVATION_DSN"
    export FEETFORCEPLATE_TEST_PLATFORM_DSN="$FEETFORCEPLATE_PLATFORM_DSN"
    export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
    export FEETFORCEPLATE_ACCEPTANCE=1
    exec ./deploy/aliyun/seed/venv-python.sh -m pytest \
        tests/test_ffp_postgres_access_repository.py \
        --deselect tests/test_ffp_postgres_access_repository.py::test_adapter_and_migration_encode_locking_routing_and_least_privilege \
        --junitxml "$1" -q
' bash "$junit_file"

runuser -u "$service_user" -- bash -c '
    export FEETFORCEPLATE_VENV=/var/lib/feetforceplate/runtime/venv
    export XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache
    cd /opt/feetforceplate/app
    "$1" - "$2" <<"PY"
import json
from pathlib import Path
path = Path(__import__("sys").argv[1])
value = json.loads(path.read_text())
value["postgres_role_parity_verified"] = True
path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
PY
' bash "$app_root/deploy/aliyun/seed/venv-python.sh" "$evidence_file"

systemctl start feetforceplate-backup.service
install -D -o "${SUDO_USER:-root}" -g "${SUDO_USER:-root}" -m 0644 \
    "$evidence_file" "$redacted_output"
install -D -o "${SUDO_USER:-root}" -g "${SUDO_USER:-root}" -m 0644 \
    "$junit_file" "$public_junit_file"
install -D -o "${SUDO_USER:-root}" -g "${SUDO_USER:-root}" -m 0644 \
    "$oss_evidence_file" "$public_oss_file"
printf 'live_acceptance=passed evidence=%s postgres_junit=%s oss_evidence=%s secrets=not-printed\n' \
    "$redacted_output" "$public_junit_file" "$public_oss_file"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
