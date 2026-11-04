#!/usr/bin/env bash
# Rehearsal step 2: restore the newest backup into a KEPT scratch database and run the
# release's schema runner on that copy (0017 ledger adoption, 0018, 0019 and the grants),
# exactly as install-seed-release.sh would on production. Production is not written:
# before/after counts are compared. Usage: rehearse-2-restore-migrate.sh AGE_IDENTITY
set -euo pipefail
umask 077
[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
identity_source="${1:?usage: $0 AGE_IDENTITY (under shared/incoming)}"
case "$identity_source" in
  /home/rui/apps/feetforceplate-network/shared/incoming/*) ;;
  *) echo "age identity must be in the protected incoming directory" >&2; exit 2 ;;
esac
rehearsal=/var/lib/feetforceplate/.rehearsal
rt_release="$rehearsal/release"
python="$rehearsal/venv/bin/python"
[[ -x "$python" ]] || { echo "run step 1 first" >&2; exit 1; }
db=feetforceplate_rehearsal
live=feetforceplate_seed
objects="$rehearsal/objects"
work="$rehearsal/work"
env_file=/etc/feetforceplate/seed.env
cleanup() { set +e; rm -rf -- "$work"; rm -f -- "$identity_source"; }
trap cleanup EXIT

runuser -u postgres -- dropdb --if-exists "$db" >/dev/null
rm -rf -- "$objects" "$work"
install -d -o postgres -g postgres -m 0700 "$objects" "$work"
install -o postgres -g postgres -m 0600 "$identity_source" "$work/backup.agekey"

bundle="$(find /var/lib/feetforceplate/backups -maxdepth 1 -type f -name '*.tar.age' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
read -r want _ <"$bundle.sha256"
[[ "$(sha256sum "$bundle" | cut -d' ' -f1)" == "$want" ]] || { echo "backup digest mismatch" >&2; exit 1; }
install -o postgres -g postgres -m 0600 "$bundle" "$work/backup.tar.age"

counts() { runuser -u postgres -- psql -d "$live" -Atqc "SELECT count(*) || ':' || (SELECT count(*) FROM device.license_entitlements) FROM iam.tenants"; }
before="$(counts)|$(find /var/lib/feetforceplate/objects -type f | wc -l | tr -d ' ')"

runuser -u postgres -- createdb "$db"
runuser -u postgres -- env FEETFORCEPLATE_BACKUP_DSN="postgresql:///$live" \
  FEETFORCEPLATE_OBJECT_ROOT=/var/lib/feetforceplate/objects \
  FEETFORCEPLATE_RESTORE_DSN="postgresql:///$db" FEETFORCEPLATE_RESTORE_OBJECT_ROOT="$objects" \
  FEETFORCEPLATE_BACKUP_AGE_IDENTITY_FILE="$work/backup.agekey" \
  bash /opt/feetforceplate/app/deploy/aliyun/seed/restore-verify.sh "$work/backup.tar.age" \
  | sed -E 's/^(restore_verified).*/\1/'

socket_dir="$(runuser -u postgres -- psql -Atqc 'SHOW unix_socket_directories' | cut -d, -f1 | tr -d ' ')"
dsn="postgresql://postgres@/${db}?host=${socket_dir:-/var/run/postgresql}"
schema() { runuser -u postgres -- "$python" -m techflex_cloud_foundation.schema "$1" --dsn "$dsn"; }

ev() { sed -n "s/^$1=//p" "$env_file"; }
pw() { local v; v="$(ev "$1")"; v="${v#postgresql://$2:}"; echo "${v%@127.0.0.1:5432/*}"; }
roles="$rehearsal/roles.sql"
{
  printf "\\\\set database_name '%s'\n" "$db"
  printf "\\\\set tenant_password '%s'\n" "$(pw FEETFORCEPLATE_TENANT_DSN ffp_seed_tenant)"
  printf "\\\\set activation_password '%s'\n" "$(pw FEETFORCEPLATE_ACTIVATION_DSN ffp_seed_activation)"
  printf "\\\\set platform_password '%s'\n" "$(pw FEETFORCEPLATE_PLATFORM_DSN ffp_seed_platform)"
  printf "\\\\set backup_password '%s'\n" "$(pw FEETFORCEPLATE_BACKUP_DSN ffp_seed_backup)"
  printf "\\\\ir '%s'\n" "$rt_release/deploy/aliyun/seed/postgresql-role-grants.sql"
} >"$roles"
chown postgres:postgres "$roles"; chmod 0600 "$roles"
apply_roles() { runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q -d "$db" -f "$roles" >/dev/null; }

echo "--- status before"; schema status || true
set +e; schema apply; rc=$?; set -e
if [[ $rc -eq 3 ]]; then apply_roles; schema apply
elif [[ $rc -ne 0 ]]; then echo "schema apply failed rc=$rc" >&2; exit 1; fi
apply_roles
echo "--- status after"; schema status
[[ "$(schema status)" == *'"pending": []'* ]] || { echo "steps left pending" >&2; exit 1; }

after="$(counts)|$(find /var/lib/feetforceplate/objects -type f | wc -l | tr -d ' ')"
[[ "$before" == "$after" ]] || { echo "PRODUCTION CHANGED: $before -> $after" >&2; exit 1; }
runuser -u postgres -- psql -d "$db" -Atqc "select 'subjects.revision', count(*) from information_schema.columns where table_schema='subject' and table_name='subjects' and column_name='revision'; select 'terminal_diagnostics', to_regclass('ops.terminal_diagnostics'); select 'ledger_rows', count(*) from ops.schema_migrations"
echo "rehearsal_step2=passed production_unchanged=true db=$db objects=$objects"
