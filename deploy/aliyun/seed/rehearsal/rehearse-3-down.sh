#!/usr/bin/env bash
# Rehearsal teardown: stop the rehearsal nginx and seed, restore pg_hba byte for byte,
# drop the rehearsal database, delete the scratch directory. Production is untouched.
set -Eeuo pipefail
[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
r=/var/lib/feetforceplate/.rehearsal
db=feetforceplate_rehearsal
hba=/var/lib/pgsql/data/pg_hba.conf
trap 'echo "rehearsal_down=failed; retain recovery material at $r; inspect the error and retry" >&2' ERR
fail() { echo "$*" >&2; return 1; }
if [[ -f "$r/nginx/nginx.pid" ]]; then
  pid="$(cat "$r/nginx/nginx.pid")"
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || fail "invalid rehearsal nginx PID"
  process="$(ps -p "$pid" -o args=)"
  [[ "$process" == *'nginx: master process '* && " $process " == *" -c $r/nginx/nginx.conf "* ]] \
    || fail "PID does not identify the rehearsal nginx master; inspect the stale PID file"
  kill -TERM "$pid"
fi
# A successful previous stop may unload the transient unit. Query failure is
# not evidence of absence, and an existing unit's stop failure is fatal.
unit_state="$(systemctl show ffp-rehearsal-seed --property=LoadState --value)"
case "$unit_state" in
  not-found) ;;
  loaded) systemctl stop ffp-rehearsal-seed ;;
  *) fail "cannot safely stop rehearsal seed: LoadState=$unit_state" ;;
esac
sleep 2
if [[ -f "$r/pg_hba.conf.orig" ]]; then
  install -o postgres -g postgres -m 0600 "$r/pg_hba.conf.orig" "$hba"
  cmp "$r/pg_hba.conf.orig" "$hba"
  reloaded="$(runuser -u postgres -- psql -Atqc "select pg_reload_conf()")"
  [[ "$reloaded" == t ]] || fail "PostgreSQL did not accept the reload request"
  echo "pg_hba restored byte for byte"
else
  # Step 3 may never have started, or a prior teardown already finished.
  # Never discard a tagged configuration whose original is missing.
  config="$(cat "$hba")"
  [[ "$config" != *'# rehearsal'* ]] || fail "tagged pg_hba has no recovery original"
fi
listeners="$(ss -ltn)"
if grep -Eq ':(27443|28743)\b' <<<"$listeners"; then
  fail "rehearsal listeners remain; retry after both processes stop"
fi
runuser -u postgres -- dropdb --if-exists "$db"
rows="$(runuser -u postgres -- psql -Atqc "select count(*) from pg_database where datname='$db'")"
[[ "$rows" == 0 ]] || fail "rehearsal database still exists"
# Delete recovery files only after every critical operation and check succeeds.
rm -rf -- "$r"
[[ ! -e "$r" ]] || fail "scratch directory remains"
echo "--- remaining"
echo "no rehearsal listeners"
echo "rehearsal db rows: 0"
echo "scratch removed"
echo "rehearsal_down=done"
