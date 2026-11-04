#!/usr/bin/env bash
# Sourced by install-seed-release.sh. No SQL or data rollback belongs here.
recovery_root=""
recovery_armed=false
cutover_stage=preflight
recovery_paths=(
    /opt/feetforceplate/app
    /var/lib/pgsql/data/pg_hba.conf
    /var/lib/pgsql/data/postgresql.auto.conf
    /etc/nginx/nginx.conf
    /etc/nginx/conf.d/feetforceplate-seed.conf
    /etc/feetforceplate/tls/seed.key
    /etc/feetforceplate/tls/seed.crt
    /etc/systemd/system/feetforceplate-seed.service
    /etc/systemd/system/feetforceplate-backup.service
    /etc/systemd/system/feetforceplate-backup.timer
    /var/lib/feetforceplate/runtime/venv
)
recovery_units=(postgresql feetforceplate-seed.service nginx feetforceplate-backup.service feetforceplate-backup.timer)

prepare_recovery() {
    local path index=0 unit active enabled listener command_line main_pid
    # An unmanaged process has no reproducible restart context. Do not kill it.
    listener="$(ss -Hltnp '( sport = :7443 )')"
    if [[ -n "$listener" ]]; then
        main_pid="$(systemctl show nginx --property=MainPID --value)"
        if [[ ! "$main_pid" =~ ^[1-9][0-9]*$ || "$listener" != *"pid=$main_pid,"* ]]; then
            echo "7443 is not the managed nginx master; arrange an approved manual cutover before retrying" >&2
            return 1
        fi
        command_line="$(tr '\0' ' ' <"/proc/$main_pid/cmdline")"
        if [[ "$command_line" != nginx:* ]]; then
            echo "7443 is not the managed nginx master; arrange an approved manual cutover before retrying" >&2
            return 1
        fi
    fi
    if [[ -e /opt/feetforceplate/app && ! -L /opt/feetforceplate/app ]]; then
        echo "app must be a symlink before cutover" >&2
        return 1
    fi
    recovery_root="$(mktemp -d /var/lib/feetforceplate/.seed-recovery.XXXXXX)"
    chmod 0700 "$recovery_root"
    mkdir "$recovery_root/files"
    : >"$recovery_root/services"
    for unit in "${recovery_units[@]}"; do
        active="$(systemctl is-active "$unit" || true)"
        enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        case "$active" in active|inactive|unknown) ;; *) echo "unstable service state: $unit $active" >&2; return 1;; esac
        case "$enabled" in enabled|disabled|static|not-found) ;; *) echo "unsupported enable state: $unit $enabled" >&2; return 1;; esac
        if [[ "$active" == unknown && "$enabled" != not-found ]]; then
            echo "unknown activity for installed unit: $unit" >&2
            return 1
        fi
        if [[ "$unit" == feetforceplate-backup.service && "$active" == active ]]; then
            echo "wait for the running backup to finish before installing" >&2
            return 1
        fi
        printf '%s %s %s\n' "$unit" "$active" "$enabled" >>"$recovery_root/services"
    done
    : >"$recovery_root/paths"
    for path in "${recovery_paths[@]}"; do
        printf '%s\n' "$path" >>"$recovery_root/paths"
        if [[ -e "$path" || -L "$path" ]]; then
            cp -a -- "$path" "$recovery_root/files/$index"
        fi
        index=$((index + 1))
    done
    # Copies retain uid/gid/mode and symlink identity. Absent paths are recorded too.
    printf '%s\n' 'Prepared; forward SQL, roles, newly created secrets and data are NEVER undone.' >"$recovery_root/status"
    recovery_armed=true
}

recover_cutover() {
    local failed=0 stopped=true index=0 path unit active enabled
    # Stop writers before replacing the shared venv. Never rerun the backup.
    for unit in feetforceplate-backup.timer feetforceplate-backup.service nginx feetforceplate-seed.service; do
        active="$(systemctl is-active "$unit" || true)"
        if [[ "$active" == unknown ]]; then
            # A missing unit is harmless; an unreadable installed unit may still
            # own the shared runtime. Do not replace it on an unknown answer.
            if [[ "$(systemctl is-enabled "$unit" 2>/dev/null || true)" != not-found ]]; then
                failed=1
                stopped=false
            fi
        elif [[ "$active" != inactive ]]; then
            if ! systemctl stop "$unit"; then failed=1; stopped=false; fi
        fi
    done
    if [[ "$stopped" != true ]]; then
        echo "could not stop consumers; files retained rather than replacing a live runtime" >&2
        return 1
    fi
    # Disable new links while the installed unit files still exist.
    while read -r unit active enabled; do
        if [[ "$enabled" == not-found && "$(systemctl is-enabled "$unit" 2>/dev/null || true)" != not-found ]]; then
            systemctl disable "$unit" || failed=1
        fi
    done <"$recovery_root/services"
    for path in "${recovery_paths[@]}"; do
        if [[ -e "$recovery_root/files/$index" || -L "$recovery_root/files/$index" ]]; then
            # Keep the saved copy even if installation of a restored path fails.
            rm -rf -- "$path" && cp -a -- "$recovery_root/files/$index" "$path" || failed=1
        else
            rm -rf -- "$path" || failed=1
        fi
        index=$((index + 1))
    done
    systemctl daemon-reload || failed=1
    while read -r unit active enabled; do
        case "$enabled" in
            enabled) systemctl enable "$unit" || failed=1 ;;
            disabled) systemctl disable "$unit" || failed=1 ;;
        esac
    done <"$recovery_root/services"
    # A failed restore must not start a mixed configuration.
    [[ "$failed" -eq 0 ]] || return 1
    while read -r unit active enabled; do
        if [[ "$active" == active ]]; then
            systemctl restart "$unit" || failed=1
            [[ "$(systemctl is-active "$unit" || true)" == active ]] || failed=1
        elif [[ "$active" != unknown ]]; then
            systemctl stop "$unit" || failed=1
        fi
    done <"$recovery_root/services"
    return "$failed"
}

finish_install() {
    local status=$?
    trap - EXIT
    trap '' INT TERM
    set +e
    if [[ "$status" -ne 0 && "$recovery_armed" == true ]]; then
        echo "installer failed during $cutover_stage; recovering reversible host state; forward SQL/data remain" >&2
        printf 'failed stage=%s exit=%s\n' "$cutover_stage" "$status" >>"$recovery_root/status"
        if recover_cutover; then
            echo "reversible host state restored; validate compatibility with the retained forward schema" >&2
            printf 'reversible-state-restored\n' >>"$recovery_root/status"
        else
            echo "manual recovery required: use $recovery_root/paths, files/, services and status; see seed-cutover-runbook.md" >&2
            printf 'manual-recovery-required\n' >>"$recovery_root/status"
        fi
        echo "recovery material retained at $recovery_root (root-only); do not publish its contents" >&2
    elif [[ -n "$recovery_root" && "$status" -eq 0 ]]; then
        rm -rf -- "$recovery_root"
    fi
    rm -rf -- "$install_root" "$offline_check_root"
    exit "$status"
}
