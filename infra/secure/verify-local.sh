#!/usr/bin/env bash

set -euo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
env_file="${script_dir}/.local/pug-l1.env"
session_env_file="${script_dir}/.local/session-gateway.env"
credentials_file="${script_dir}/.local/bootstrap/operator.json"
ca_file="${script_dir}/.local/tls/localhost.crt"
compose_file="${script_dir}/docker-compose.yaml"
dashboard_verifier="${script_dir}/verify-dashboard-session.sh"

for command_name in awk curl docker grep jq uuidgen; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "missing required command: ${command_name}" >&2
    exit 1
  fi
done

for required_file in "${env_file}" "${session_env_file}" "${credentials_file}" "${ca_file}" "${dashboard_verifier}"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "missing L1 material: ${required_file}" >&2
    exit 1
  fi
done

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

if [[ "$(file_mode "${env_file}")" != "600" || "$(file_mode "${session_env_file}")" != "600" || "$(file_mode "${credentials_file}")" != "600" ]]; then
  echo "L1 env, session key, and bootstrap credentials must all be mode 0600" >&2
  exit 1
fi

env_value() {
  awk -v wanted="$1" '
    index($0, wanted "=") == 1 {
      sub(/^[^=]*=/, "")
      sub(/\r$/, "")
      print
      exit
    }
  ' "${env_file}"
}

https_port="$(env_value PUG_L1_COLLECTOR_HTTPS_PORT)"
http_port="$(env_value PUG_L1_COLLECTOR_HTTP_PORT)"
https_port="${https_port:-18443}"
http_port="${http_port:-18081}"
collector_url="https://localhost:${https_port}"
batch_path="/sdk.events.v1.EventsService/BatchCreate"
compose=(docker compose --env-file "${env_file}" -p pug-l1 -f "${compose_file}")

expect_status() {
  local want="$1"
  shift
  local got
  got="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$@")"
  if [[ "${got}" != "${want}" ]]; then
    echo "unexpected HTTP status: got ${got}, want ${want}" >&2
    exit 1
  fi
}

curl --fail --silent --show-error --cacert "${ca_file}" "${collector_url}/healthz" >/dev/null
expect_status 404 --cacert "${ca_file}" --request POST "${collector_url}/not-a-collector-route"
expect_status 405 --cacert "${ca_file}" "${collector_url}${batch_path}"
expect_status 401 --cacert "${ca_file}" --request POST --header 'Content-Type: application/json' \
  --data '{"events":[]}' "${collector_url}${batch_path}"

redirect_location="$(
  curl --silent --show-error --dump-header - --output /dev/null \
    --header 'Host: attacker.invalid' "http://127.0.0.1:${http_port}/probe?q=1" |
    awk 'BEGIN { IGNORECASE=1 } /^Location:/ { sub(/\r$/, "", $2); print $2 }'
)"
if [[ "${redirect_location}" != "https://localhost:${https_port}/probe?q=1" ]]; then
  echo "redirect authority was not fixed to the configured public host" >&2
  exit 1
fi

public_key="$(jq -er '.public_api_key | select(type == "string" and length > 0)' "${credentials_file}")"
event_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
session_id="$(uuidgen | tr '[:upper:]' '[:lower:]')"
occur_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

response="$(
  jq -nc \
    --arg event_id "${event_id}" \
    --arg session_id "${session_id}" \
    --arg occur_time "${occur_time}" \
    '{events:[{eventId:$event_id,distinctId:"l1-local-verifier",kind:"l1_security_smoke",occurTime:$occur_time,sessionId:$session_id}]}' |
    curl --fail --silent --show-error --cacert "${ca_file}" \
      --request POST \
      --header 'Content-Type: application/json' \
      --header "X-Api-Key: ${public_key}" \
      --header 'Authorization: Bearer must-not-pass' \
      --header 'Cookie: session=must-not-pass' \
      --header 'CF-Connecting-IP: 203.0.113.7' \
      --header 'True-Client-IP: 203.0.113.8' \
      --header 'X-Forwarded-For: 203.0.113.9' \
      --data-binary @- \
      "${collector_url}${batch_path}"
)"

if [[ "$(jq -r '.accepted' <<<"${response}")" != "1" || "$(jq -r '.dropped' <<<"${response}")" != "0" ]]; then
  echo "collector did not accept exactly one smoke event" >&2
  exit 1
fi

stored=""
for _ in $(seq 1 40); do
  stored="$(
    "${compose[@]}" exec -T -e PUG_VERIFY_EVENT_ID="${event_id}" clickhouse sh -ec \
      'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$CLICKHOUSE_DB" --param_event_id "$PUG_VERIFY_EVENT_ID" --query "SELECT count(), countIf(mapContains(auto_properties, '\''\$ip'\'')) FROM events WHERE event_id = {event_id:UUID} FORMAT TabSeparatedRaw"' \
      2>/dev/null || true
  )"
  if [[ "${stored}" == $'1\t0' ]]; then
    break
  fi
  sleep 0.25
done
if [[ "${stored}" != $'1\t0' ]]; then
  echo "smoke event was not stored exactly once, or a spoofed IP reached ClickHouse" >&2
  exit 1
fi

oversized_status="$(
  head -c 1048577 /dev/zero |
    tr '\0' x |
    curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
      --cacert "${ca_file}" \
      --request POST \
      --header 'Content-Type: application/json' \
      --header "X-Api-Key: ${public_key}" \
      --data-binary @- \
      "${collector_url}${batch_path}"
)"
if [[ "${oversized_status}" != "413" ]]; then
  echo "oversized request status was ${oversized_status}, want 413" >&2
  exit 1
fi

for service in postgres nats clickhouse dragonfly server worker-events ingress dashboard session-gateway; do
  container_id="$("${compose[@]}" ps -q "${service}")"
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}")"
  if [[ "${health}" != "healthy" ]]; then
    echo "service ${service} is ${health}, want healthy" >&2
    exit 1
  fi
done

"${dashboard_verifier}"

logs_file="$(mktemp "${TMPDIR:-/tmp}/pug-l1-logs.XXXXXX")"
trap 'rm -f -- "${logs_file}"' EXIT
"${compose[@]}" logs --no-color >"${logs_file}"

for secret_file in "${env_file}" "${session_env_file}"; do
  while IFS='=' read -r name value; do
    value="${value%$'\r'}"
    case "${name}" in
      *_KEY | *_PASSWORD | *_SECRET)
        if [[ -n "${value}" ]] && grep -Fq -- "${value}" "${logs_file}"; then
          echo "current secret from ${name} appears in Compose logs" >&2
          exit 1
        fi
        ;;
    esac
  done <"${secret_file}"
done

for json_key in password private_api_key; do
  secret_value="$(jq -er --arg key "${json_key}" '.[$key]' "${credentials_file}")"
  if grep -Fq -- "${secret_value}" "${logs_file}"; then
    echo "bootstrap ${json_key} appears in Compose logs" >&2
    exit 1
  fi
done

echo "L1 local verification passed: collector and Dashboard routes, auth, session/CSRF isolation, limits, header stripping, ingestion, storage, health, and log redaction"
