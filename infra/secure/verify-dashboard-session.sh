#!/usr/bin/env bash

set -euo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
env_file="${script_dir}/.local/pug-l1.env"
credentials_file="${script_dir}/.local/bootstrap/operator.json"
ca_file="${script_dir}/.local/tls/localhost.crt"

for command_name in curl jq awk grep mktemp; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "missing required command: ${command_name}" >&2
    exit 1
  fi
done

for required_file in "${env_file}" "${credentials_file}" "${ca_file}"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "missing L1 material: ${required_file}" >&2
    exit 1
  fi
done

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

dashboard_port="$(env_value PUG_L1_DASHBOARD_HTTPS_PORT)"
dashboard_port="${dashboard_port:-15443}"
origin="https://localhost:${dashboard_port}"
sign_in_path="/public.auth.v1.AuthService/SignInWithEmail"
sign_out_path="/public.auth.v1.AuthService/SignOut"
get_me_path="/dashboard.customers.v1.CustomersService/GetMe"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/pug-l1-dashboard-session.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT
cookie_jar="${work_dir}/cookies.txt"
stolen_cookie_jar="${work_dir}/stolen-cookies.txt"
login_headers="${work_dir}/login.headers"
login_body="${work_dir}/login.json"
status_body="${work_dir}/status.json"
me_body="${work_dir}/me.json"
signout_headers="${work_dir}/signout.headers"

connect_headers=(
  --header 'Content-Type: application/json'
  --header 'Connect-Protocol-Version: 1'
  --header "Origin: ${origin}"
  --header 'Sec-Fetch-Site: same-origin'
)

jq -c '{email, password}' "${credentials_file}" |
  curl --fail --silent --show-error --cacert "${ca_file}" \
    --request POST \
    "${connect_headers[@]}" \
    --cookie-jar "${cookie_jar}" \
    --dump-header "${login_headers}" \
    --output "${login_body}" \
    --data-binary @- \
    "${origin}${sign_in_path}"

if jq -e 'has("token") or has("refreshToken")' "${login_body}" >/dev/null; then
  echo "login response exposed an upstream token" >&2
  exit 1
fi
set_cookie="$(awk 'tolower($0) ~ /^set-cookie:/ { sub(/\r$/, ""); print }' "${login_headers}")"
for required in '__Host-pug_session=' 'Path=/' 'HttpOnly' 'Secure' 'SameSite=Strict'; do
  if [[ "${set_cookie}" != *"${required}"* ]]; then
    echo "session cookie is missing ${required}" >&2
    exit 1
  fi
done
if ! awk -F '\t' '$1 == "#HttpOnly_localhost" && $3 == "/" && $4 == "TRUE" && $6 == "__Host-pug_session" { found=1 } END { exit !found }' "${cookie_jar}"; then
  echo "curl cookie jar did not receive the secure HttpOnly host cookie" >&2
  exit 1
fi

curl --fail --silent --show-error --cacert "${ca_file}" \
  --cookie "${cookie_jar}" \
  --output "${status_body}" \
  "${origin}/_pug/session"
if [[ "$(jq -r '.authenticated' "${status_body}")" != "true" ]]; then
  echo "gateway did not report an authenticated session" >&2
  exit 1
fi
if [[ "$(jq -r '.demo | type' "${status_body}")" != "boolean" || "$(jq -r '.demo' "${status_body}")" != "false" ]]; then
  echo "gateway session status did not carry an explicit non-demo flag" >&2
  exit 1
fi
if jq -e 'has("token") or has("refreshToken") or has("accessToken")' "${status_body}" >/dev/null; then
  echo "session status exposed an upstream token" >&2
  exit 1
fi
customer_id="$(jq -er '.customerId | select(type == "string" and length > 0)' "${status_body}")"
csrf_token="$(jq -er '.csrfToken | select(type == "string")' "${status_body}")"
if [[ ! "${csrf_token}" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
  echo "gateway returned a malformed CSRF token" >&2
  exit 1
fi

curl --fail --silent --show-error --cacert "${ca_file}" \
  --request POST \
  "${connect_headers[@]}" \
  --header "X-Pug-CSRF-Token: ${csrf_token}" \
  --header 'Authorization: Bearer browser-must-not-control-upstream-auth' \
  --cookie "${cookie_jar}" \
  --output "${me_body}" \
  --data '{}' \
  "${origin}${get_me_path}"
if [[ "$(jq -r '.customerId' "${me_body}")" != "${customer_id}" ]]; then
  echo "authenticated RPC did not use the gateway session identity" >&2
  exit 1
fi
if [[ "$(jq -r '.email' "${me_body}")" != "$(jq -r '.email' "${credentials_file}")" ]]; then
  echo "GetMe returned an unexpected operator identity" >&2
  exit 1
fi

missing_csrf_status="$(
  curl --silent --show-error --cacert "${ca_file}" \
    --request POST \
    "${connect_headers[@]}" \
    --cookie "${cookie_jar}" \
    --output /dev/null \
    --write-out '%{http_code}' \
    --data '{}' \
    "${origin}${get_me_path}"
)"
if [[ "${missing_csrf_status}" != "403" ]]; then
  echo "missing-CSRF RPC status was ${missing_csrf_status}, want 403" >&2
  exit 1
fi

cross_origin_status="$(
  curl --silent --show-error --cacert "${ca_file}" \
    --request POST \
    --header 'Content-Type: application/json' \
    --header 'Connect-Protocol-Version: 1' \
    --header 'Origin: https://attacker.invalid' \
    --header 'Sec-Fetch-Site: cross-site' \
    --header "X-Pug-CSRF-Token: ${csrf_token}" \
    --cookie "${cookie_jar}" \
    --output /dev/null \
    --write-out '%{http_code}' \
    --data '{}' \
    "${origin}${get_me_path}"
)"
if [[ "${cross_origin_status}" != "403" ]]; then
  echo "cross-origin RPC status was ${cross_origin_status}, want 403" >&2
  exit 1
fi

for forbidden_path in '/mcp' '/sdk.events.v1.EventsService/BatchCreate'; do
  forbidden_status="$(
    curl --silent --show-error --cacert "${ca_file}" \
      --output /dev/null \
      --write-out '%{http_code}' \
      "${origin}${forbidden_path}"
  )"
  if [[ "${forbidden_status}" != "404" ]]; then
    echo "dashboard gateway exposed forbidden path ${forbidden_path}" >&2
    exit 1
  fi
done

header_probe="${work_dir}/root.headers"
curl --fail --silent --show-error --cacert "${ca_file}" --head --dump-header "${header_probe}" --output /dev/null "${origin}/"
if [[ "$(awk 'tolower($0) ~ /^strict-transport-security:/ { count++ } END { print count + 0 }' "${header_probe}")" != "1" ]]; then
  echo "gateway did not emit exactly one HSTS header" >&2
  exit 1
fi
if awk 'tolower($0) ~ /^server:/ { found=1 } END { exit !found }' "${header_probe}"; then
  echo "static upstream server header reached the browser" >&2
  exit 1
fi

cp "${cookie_jar}" "${stolen_cookie_jar}"
curl --fail --silent --show-error --cacert "${ca_file}" \
  --request POST \
  "${connect_headers[@]}" \
  --header "X-Pug-CSRF-Token: ${csrf_token}" \
  --cookie "${cookie_jar}" \
  --cookie-jar "${cookie_jar}" \
  --dump-header "${signout_headers}" \
  --output /dev/null \
  --data '{}' \
  "${origin}${sign_out_path}"
if ! awk 'tolower($0) ~ /^set-cookie:/ && $0 ~ /Max-Age=0/ { found=1 } END { exit !found }' "${signout_headers}"; then
  echo "sign-out did not expire the HttpOnly session cookie" >&2
  exit 1
fi

curl --fail --silent --show-error --cacert "${ca_file}" \
  --cookie "${stolen_cookie_jar}" \
  --output "${status_body}" \
  "${origin}/_pug/session"
if [[ "$(jq -r '.authenticated' "${status_body}")" != "false" ]]; then
  echo "server-side session survived sign-out" >&2
  exit 1
fi

echo "Dashboard session verification passed: same-origin login, HttpOnly cookie, token isolation, CSRF/origin enforcement, protected RPC, forbidden routes, headers, and server-side sign-out"
