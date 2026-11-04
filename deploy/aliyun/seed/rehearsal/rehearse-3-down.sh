#!/usr/bin/env bash
# Rehearsal teardown: stop the rehearsal nginx and seed, restore pg_hba byte for byte,
# drop the rehearsal database, delete the scratch directory. Production is untouched.
set -uo pipefail
[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
r=/var/lib/feetforceplate/.rehearsal
db=feetforceplate_rehearsal
hba=/var/lib/pgsql/data/pg_hba.conf
[[ -f "$r/nginx/nginx.pid" ]] && kill -TERM "$(cat "$r/nginx/nginx.pid")" 2>/dev/null
systemctl stop ffp-rehearsal-seed 2>/dev/null; systemctl reset-failed ffp-rehearsal-seed 2>/dev/null
sleep 2
if [[ -f "$r/pg_hba.conf.orig" ]]; then
  install -o postgres -g postgres -m 0600 "$r/pg_hba.conf.orig" "$hba"
  runuser -u postgres -- psql -Atqc "select pg_reload_conf()" >/dev/null
  grep -q 'rehearsal' "$hba" && echo "WARNING: rehearsal pg_hba lines still present" >&2
  cmp "$r/pg_hba.conf.orig" "$hba" && echo "pg_hba restored byte for byte"
fi
runuser -u postgres -- dropdb --if-exists "$db"
rm -rf -- "$r"
echo "--- remaining"
ss -ltn | grep -E ':(27443|28743)\b' || echo "no rehearsal listeners"
runuser -u postgres -- psql -Atqc "select count(*) from pg_database where datname='$db'" | sed 's/^/rehearsal db rows: /'
ls -d "$r" 2>/dev/null || echo "scratch removed"
echo "rehearsal_down=done"
