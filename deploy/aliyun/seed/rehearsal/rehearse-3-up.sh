#!/usr/bin/env bash
# Rehearsal step 3: run the release in the rehearsal directory on the restored copy, loopback only.
# - temporary pg_hba lines (tagged, original saved) for the rehearsal database only
# - throwaway private CA + leaf for 127.0.0.1
# - seed on 127.0.0.1:28743 (systemd-run unit ffp-rehearsal-seed), filesystem objects,
#   OSS variables removed so production OSS is never touched
# - a second nginx (own config/pid) on 127.0.0.1:27443. 7443 and 8743 are not touched.
set -euo pipefail
umask 077
[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
r=/var/lib/feetforceplate/.rehearsal
db=feetforceplate_rehearsal
hba=/var/lib/pgsql/data/pg_hba.conf
tag='# rehearsal'
[[ -x "$r/venv/bin/python" && -d "$r/objects" ]] || { echo "run steps 1 and 2 first" >&2; exit 1; }
[[ "$(runuser -u postgres -- psql -Atqc "select count(*) from pg_database where datname='$db'")" == 1 ]] || { echo "rehearsal database missing" >&2; exit 1; }
for p in 27443 28743; do ss -ltn "( sport = :$p )" | grep -q LISTEN && { echo "port $p already in use" >&2; exit 1; }; done
! grep -q "$tag" "$hba" || { echo "rehearsal pg_hba lines already present; run rehearse-3-down.sh" >&2; exit 1; }

# 1. pg_hba: four loopback SCRAM lines for the rehearsal database, before the reject-all line
cp -a "$hba" "$r/pg_hba.conf.orig"
awk -v db="$db" -v tag="$tag" '
  !done && $1=="host" && $2=="all" && $3=="all" && $4=="127.0.0.1/32" && $5=="reject" {
    for (i=1;i<=4;i++) printf "host    %s     %s       127.0.0.1/32      scram-sha-256 %s\n", db, (i==1?"ffp_seed_tenant":i==2?"ffp_seed_activation":i==3?"ffp_seed_platform":"ffp_seed_backup"), tag
    done=1 }
  { print }
  END { if (!done) exit 3 }' "$r/pg_hba.conf.orig" >"$r/pg_hba.conf.new" || { echo "reject-all line not found; pg_hba unchanged" >&2; exit 1; }
install -o postgres -g postgres -m 0600 "$r/pg_hba.conf.new" "$hba"
runuser -u postgres -- psql -Atqc "select pg_reload_conf()" >/dev/null
sleep 1
echo "--- pg_hba diff"; diff "$r/pg_hba.conf.orig" "$hba" || true
bad="$(runuser -u postgres -- psql -Atqc "select count(*) from pg_hba_file_rules where error is not null")"
[[ "$bad" == 0 ]] || { echo "pg_hba has errors; run rehearse-3-down.sh" >&2; exit 1; }

# 2. throwaway TLS
install -d -m 0755 "$r/tls"
openssl ecparam -name prime256v1 -genkey -noout -out "$r/tls/ca.key" 2>/dev/null
openssl req -x509 -new -key "$r/tls/ca.key" -days 1 -subj "/CN=rehearsal-ca" -out "$r/tls/ca.pem" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$r/tls/leaf.key" 2>/dev/null
openssl req -new -key "$r/tls/leaf.key" -subj "/CN=127.0.0.1" -out "$r/tls/leaf.csr" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\n' >"$r/tls/leaf.ext"
openssl x509 -req -in "$r/tls/leaf.csr" -CA "$r/tls/ca.pem" -CAkey "$r/tls/ca.key" -CAcreateserial -days 1 \
  -extfile "$r/tls/leaf.ext" -out "$r/tls/leaf.pem" 2>/dev/null
chmod 0644 "$r/tls/ca.pem" "$r/tls/leaf.pem"; chmod 0600 "$r/tls/leaf.key"

# 3. environment: production secrets, rehearsal database/objects/URL, no OSS
install -d -o feetforceplate -g feetforceplate -m 0700 "$r/telemetry"
chown -R feetforceplate:feetforceplate "$r/objects" "$r/venv"
env_out="$r/rehearsal.env"
{
  grep -vE '^FEETFORCEPLATE_(OBJECT_ROOT|PUBLIC_BASE_URL|TRUSTED_PROXIES|OBJECT_BACKEND|VALIDATION_TELEMETRY_ROOT|SEED_ENV_FILE|BACKUP_[A-Z_]*|OSS_[A-Z_]*)=' /etc/feetforceplate/seed.env \
    | sed -E "s#/feetforceplate_seed\$#/$db#"
  printf 'FEETFORCEPLATE_OBJECT_ROOT=%s\n' "$r/objects"
  printf 'FEETFORCEPLATE_PUBLIC_BASE_URL=https://127.0.0.1:27443\n'
  printf 'FEETFORCEPLATE_TRUSTED_PROXIES=127.0.0.1\n'
  printf 'FEETFORCEPLATE_OBJECT_BACKEND=filesystem\n'
  printf 'FEETFORCEPLATE_VALIDATION_TELEMETRY_ROOT=%s\n' "$r/telemetry"
  printf 'FEETFORCEPLATE_SEED_ENV_FILE=%s\n' "$env_out"
  printf 'FEETFORCEPLATE_BIND_HOST=127.0.0.1\nFEETFORCEPLATE_BIND_PORT=28743\n'
  printf 'FEETFORCEPLATE_VENV=%s\nXDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache\nUV_OFFLINE=1\n' "$r/venv"
} >"$env_out"
chown feetforceplate:feetforceplate "$env_out"; chmod 0600 "$env_out"
grep -q '^FEETFORCEPLATE_OSS_' "$env_out" && { echo "OSS variables leaked into rehearsal env" >&2; exit 1; }
grep -c "/$db\$" "$env_out" | sed 's/^/rehearsal DSNs: /'

# 4. seed on 28743
systemd-run --quiet --unit=ffp-rehearsal-seed --uid=feetforceplate --gid=feetforceplate \
  --working-directory="$r/release" -p EnvironmentFile="$env_out" -p UMask=0077 -p NoNewPrivileges=yes \
  -p ProtectSystem=strict -p "ReadWritePaths=$r /var/lib/feetforceplate/runtime" \
  "$r/release/deploy/aliyun/seed/run-seed.sh"
for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:28743/health/ready >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:28743/health/ready >/dev/null || { journalctl -u ffp-rehearsal-seed -n 30 --no-pager >&2; echo "rehearsal seed not ready" >&2; exit 1; }

# 5. second nginx on 27443
install -d -m 0755 "$r/nginx" "$r/nginx/tmp"
sed -e 's/listen 7443 ssl;/listen 127.0.0.1:27443 ssl;/' -e '/listen \[::\]:7443 ssl;/d' \
    -e "s#/etc/feetforceplate/tls/seed.crt#$r/tls/leaf.pem#" -e "s#/etc/feetforceplate/tls/seed.key#$r/tls/leaf.key#" \
    -e "s#/var/log/nginx/feetforceplate-seed.access.log#$r/nginx/access.log#" \
    -e "s#/var/log/nginx/feetforceplate-seed.error.log#$r/nginx/error.log#" \
    -e 's#127.0.0.1:8743#127.0.0.1:28743#' \
    "$r/release/deploy/aliyun/seed/nginx-feetforceplate-seed.conf" >"$r/nginx/site.conf"
cat >"$r/nginx/nginx.conf" <<NG
worker_processes 1;
error_log $r/nginx/main-error.log notice;
pid $r/nginx/nginx.pid;
events { worker_connections 256; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    client_body_temp_path $r/nginx/tmp/body; proxy_temp_path $r/nginx/tmp/proxy;
    fastcgi_temp_path $r/nginx/tmp/fcgi; uwsgi_temp_path $r/nginx/tmp/uwsgi; scgi_temp_path $r/nginx/tmp/scgi;
    include $r/nginx/site.conf;
}
NG
nginx -t -c "$r/nginx/nginx.conf" -p "$r/nginx/"
nginx -c "$r/nginx/nginx.conf" -p "$r/nginx/"
for _ in $(seq 1 20); do curl -fsS --cacert "$r/tls/ca.pem" https://127.0.0.1:27443/health/ready >/dev/null 2>&1 && break; sleep 1; done
curl -fsS --cacert "$r/tls/ca.pem" https://127.0.0.1:27443/health/ready >/dev/null
ss -ltnp | grep -E ':(7443|8743|27443|28743)\b' | awk '{print $4, $6}'
echo "rehearsal_step3_up=passed base_url=https://127.0.0.1:27443 ca=$r/tls/ca.pem"
