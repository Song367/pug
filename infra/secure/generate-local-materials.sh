#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
local_dir="$script_dir/.local"
env_file="$local_dir/pug-l1.env"
session_env_file="$local_dir/session-gateway.env"

if [ -e "$env_file" ] || [ -e "$session_env_file" ] || [ -e "$local_dir/tls" ]; then
  echo "refusing to overwrite existing L1 materials under $local_dir" >&2
  exit 1
fi

mkdir -p "$local_dir"
work_dir=$(mktemp -d "$local_dir/.generate.XXXXXX")
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -m 0700 "$work_dir/bootstrap" "$work_dir/tls"

postgres_password=$(openssl rand -hex 32)
nats_password=$(openssl rand -hex 32)
clickhouse_password=$(openssl rand -hex 32)
dragonfly_password=$(openssl rand -hex 32)
jwt_secret=$(openssl rand -hex 48)
session_encryption_key=$(openssl rand -hex 32)

{
  echo "# Generated local-only L1 credentials. Never commit or reuse remotely."
  echo "PUG_L1_HOST_UID=$(id -u)"
  echo "PUG_L1_HOST_GID=$(id -g)"
  echo "PUG_L1_POSTGRES_DB=pug_l1"
  echo "PUG_L1_POSTGRES_USER=pug_l1"
  echo "PUG_L1_POSTGRES_PASSWORD=$postgres_password"
  echo "PUG_L1_NATS_USER=pug_l1"
  echo "PUG_L1_NATS_PASSWORD=$nats_password"
  echo "PUG_L1_CLICKHOUSE_DB=pug_l1"
  echo "PUG_L1_CLICKHOUSE_USER=pug_l1"
  echo "PUG_L1_CLICKHOUSE_PASSWORD=$clickhouse_password"
  echo "PUG_L1_DRAGONFLY_PASSWORD=$dragonfly_password"
  echo "PUG_L1_JWT_SECRET=$jwt_secret"
  echo "PUG_L1_CORS_ORIGINS=https://localhost:15443"
  echo "PUG_L1_COLLECTOR_HTTP_PORT=18081"
  echo "PUG_L1_COLLECTOR_HTTPS_PORT=18443"
  echo "PUG_L1_DASHBOARD_HTTPS_PORT=15443"
  echo "PUG_L1_BOOTSTRAP_EMAIL=operator@pug-l1.local"
  echo "PUG_L1_BOOTSTRAP_DISPLAY_NAME=OnlyF Local Operator"
  echo "PUG_L1_BOOTSTRAP_ORG_NAME=OnlyF Local L1"
  echo "PUG_L1_BOOTSTRAP_PROJECT_NAME=onlyf-local-l1"
} > "$work_dir/pug-l1.env"
chmod 0600 "$work_dir/pug-l1.env"

{
  echo "# Generated local-only Dashboard session encryption key. Never commit or reuse remotely."
  echo "PUG_SESSION_ENCRYPTION_KEY=$session_encryption_key"
} > "$work_dir/session-gateway.env"
chmod 0600 "$work_dir/session-gateway.env"

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$work_dir/tls/localhost.key" \
  -out "$work_dir/tls/localhost.crt" >/dev/null 2>&1
chmod 0600 "$work_dir/tls/localhost.key"
chmod 0644 "$work_dir/tls/localhost.crt"

mv "$work_dir/pug-l1.env" "$env_file"
mv "$work_dir/session-gateway.env" "$session_env_file"
mv "$work_dir/bootstrap" "$local_dir/bootstrap"
mv "$work_dir/tls" "$local_dir/tls"

echo "created local L1 env, session key, TLS certificate, and protected bootstrap output directory"
echo "env: $env_file"
