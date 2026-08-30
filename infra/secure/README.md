# Local Phase L1 secure stack

This Compose project is the production-style **local validation** stack. It is
separate from `infra/dev/docker-compose.yaml`, uses synthetic data only, and is
not a remote deployment manifest.

## Security properties

- Only the collector and Dashboard Session Gateway publish host ports, all bound
  to `127.0.0.1`; the Dashboard static container itself has no host port.
- PostgreSQL, NATS, ClickHouse, Dragonfly, Pug server, and the events worker stay
  on an internal Docker network with no host port.
- Every Pug process is non-root, read-only, capability-free, and bounded by
  process, memory, and CPU limits.
- PostgreSQL, NATS, ClickHouse, and Dragonfly use separate randomly generated
  local credentials.
- Dragonfly has no persistent volume and starts with an empty `--dbfilename=`,
  no snapshot schedule, no replica, no HTTP API, and no version phone-home.
- The public collector accepts only `BatchCreate`, caps request bodies at 1 MiB,
  strips untrusted proxy headers, and terminates TLS.
- Collector responses advertise the exact corresponding backend source through
  `rel="source"`; `/source` and `/.well-known/source-code` redirect to the same
  immutable public release tag without touching the analytics upstream.
- The Dashboard is served through a same-origin TLS Session Gateway. Raw
  access/refresh tokens are encrypted in Dragonfly; the browser receives only
  a `Secure`, `HttpOnly`, `SameSite=Strict` `__Host-pug_session` cookie, and
  protected RPCs require both a same-origin request and an in-memory CSRF token.
- Dashboard routing exposes only the required Dashboard/Public services. SDK
  ingestion, MCP, reflection, and unknown dotted service paths are not reachable
  through the Dashboard origin.
- The Dashboard sign-in surface and authenticated sidebar link to the public
  `/source` page, which lists the exact backend and Dashboard release tags and
  the bundled GNU AGPL license. Update both source URLs for every promoted image.
- Demo and destructive seed modes are disabled. Operator bootstrap is an
  explicit, one-shot profile that refuses a non-empty database.
- Every upstream data image is pinned by multi-platform repository digest.

Internal database connections intentionally do not use TLS in this single-host
local validation stack. A remote Test deployment must inject secrets from its
secret manager and add service TLS or equivalent private transport controls.

## Start

```bash
cd /Users/wadesong/workplace/porn-all/pug-app
docker build -t pug-l1/dashboard:local .

cd /Users/wadesong/workplace/porn-all/pug
./infra/secure/generate-local-materials.sh
./infra/secure/generate-local-session-materials.sh

docker compose \
  --env-file infra/secure/.local/pug-l1.env \
  -p pug-l1 \
  -f infra/secure/docker-compose.yaml \
  up -d --build
```

Both generators refuse to overwrite existing material. The base env, Session
Gateway encryption key, TLS private key, and bootstrap result are mode `0600`,
and the entire `.local` directory is ignored by Git. The Dashboard image is
built separately because its source lives in the sibling `pug-app` repository;
Compose uses `pull_policy: never` so it cannot silently pull an unrelated image.

Create the first operator, org, project, and keys exactly once:

```bash
docker compose \
  --env-file infra/secure/.local/pug-l1.env \
  -p pug-l1 \
  -f infra/secure/docker-compose.yaml \
  --profile bootstrap run --rm bootstrap
```

The one-time output is `infra/secure/.local/bootstrap/operator.json` with mode
`0600`. It contains the only plaintext copy of the private key. Do not print,
log, or commit this file.

Check the stack without rendering interpolated secrets:

```bash
docker compose \
  --env-file infra/secure/.local/pug-l1.env \
  -p pug-l1 \
  -f infra/secure/docker-compose.yaml \
  ps

curl --fail --silent --show-error \
  --cacert infra/secure/.local/tls/localhost.crt \
  https://localhost:18443/healthz
```

Run the repeatable end-to-end and malicious-input smoke check:

```bash
./infra/secure/verify-local.sh
```

The verifier never prints the API key, operator credentials, session cookie,
CSRF token, or encryption key. It checks fixed redirect authority,
route/method allowlisting, missing-key rejection, the 1 MiB body limit,
proxy/credential header stripping, one accepted event reaching ClickHouse
exactly once without a spoofed `$ip`, and health of every long-lived service.
It also performs a real same-origin Dashboard login, proves raw tokens do not
reach the browser, enforces Origin/CSRF and forbidden routes, verifies
server-side sign-out, and compares every current secret against Compose logs
without printing either the logs or the secret values.

After the stack is healthy, the local Dashboard is available only at:

```text
https://localhost:15443
```

Trust the generated local certificate only for this isolated validation
environment. Do not publish this port or reuse the local certificate or secrets.

Do not paste the output of `docker compose config`, `docker inspect`, or the
generated env/bootstrap files into logs: Docker Compose necessarily expands the
local connection credentials into container configuration.

## Stop or remove

`stop` preserves the local L1 PostgreSQL, NATS, and ClickHouse volumes:

```bash
docker compose --env-file infra/secure/.local/pug-l1.env -p pug-l1 \
  -f infra/secure/docker-compose.yaml stop
```

Removing volumes destroys only this Compose project's synthetic L1 data. Review
the project name and volume list before running a volume-removal command.

## Pinned upstream images

| Service | Immutable reference |
| --- | --- |
| PostgreSQL | `postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280` |
| NATS | `nats@sha256:ad7a43eb7e3337c3c38ce5d784d1461791f95f730f252d2b25eee699752a0ca3` |
| ClickHouse | `clickhouse/clickhouse-server@sha256:84d05b9c205e8de9d8e471fc8fbb3aaf0c07a8bec1bd57ac3a4a4ac2399abe38` |
| Dragonfly | `docker.dragonflydb.io/dragonflydb/dragonfly@sha256:baf70ba7ad182a992b988497cfa31a488978c8fab7712079784c2401f447e402` |

Digest updates are deliberate supply-chain changes: inspect the upstream
release, update the digest, rebuild every Pug role, regenerate SBOMs, rerun
Trivy/govulncheck/tests, and repeat the malicious-input and restart checks.
