#!/usr/bin/env bash
# Rehearsal step 2b: the restore drill uses pg_restore --no-privileges, so the copy has the
# data but none of the schema/table GRANTs that migrations 0003..0014 gave the application
# roles (and those migrations were adopted as baseline, not re-run). Copy the ACL entries
# from the live database's schema-only dump onto the copy. Reads production, writes only
# the rehearsal database.
set -euo pipefail
umask 077
[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
r=/var/lib/feetforceplate/.rehearsal
live=feetforceplate_seed
db=feetforceplate_rehearsal
install -d -o postgres -g postgres -m 0700 "$r/acl"
pg() { runuser -u postgres -- "$@"; }
pg pg_dump -Fc -s --no-owner -d "$live" -f "$r/acl/live-schema.dump"
pg pg_restore -l "$r/acl/live-schema.dump" | grep -E '; [0-9]+ [0-9]+ (ACL|DEFAULT ACL) ' >"$r/acl/acl.list" || true
chown postgres:postgres "$r/acl/acl.list"
echo "acl entries: $(wc -l <"$r/acl/acl.list" | tr -d ' ')"
pg pg_restore --no-owner -L "$r/acl/acl.list" -d "$db" "$r/acl/live-schema.dump"
q="select grantee, count(*) from information_schema.role_table_grants where grantee like 'ffp_%' group by 1 order by 1"
diff <(pg psql -d "$live" -Atqc "$q") <(pg psql -d "$db" -Atqc "$q") && echo "table grants equal between live and copy"
q2="select count(*) from information_schema.usage_privileges where grantee like 'ffp_%'"
echo "usage_privileges live/copy: $(pg psql -d "$live" -Atqc "$q2") / $(pg psql -d "$db" -Atqc "$q2")"
echo "rehearsal_step2b=passed"
