#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
local_dir="$script_dir/.local"
base_env_file="$local_dir/pug-l1.env"
tls_dir="$local_dir/tls"
session_env_file="$local_dir/session-gateway.env"

if [ ! -f "$base_env_file" ] || [ ! -d "$tls_dir" ]; then
  echo "base L1 materials are missing; run generate-local-materials.sh first" >&2
  exit 1
fi
if [ -e "$session_env_file" ]; then
  echo "refusing to overwrite existing session material: $session_env_file" >&2
  exit 1
fi

work_file=$(mktemp "$local_dir/.session-gateway.XXXXXX")
cleanup() {
  rm -f -- "$work_file"
}
trap cleanup EXIT HUP INT TERM

session_encryption_key=$(openssl rand -hex 32)
{
  echo "# Generated local-only Dashboard session encryption key. Never commit or reuse remotely."
  echo "PUG_SESSION_ENCRYPTION_KEY=$session_encryption_key"
} > "$work_file"
chmod 0600 "$work_file"
mv "$work_file" "$session_env_file"
trap - EXIT HUP INT TERM

echo "created protected local Dashboard session material"
echo "env: $session_env_file"
