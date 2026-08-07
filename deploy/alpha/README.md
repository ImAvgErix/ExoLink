# Single-region alpha deployment

This is the intentionally small production topology for 100–1,000 registered
friends/testers:

- Caddy 2.11.4 for automatic HTTPS and WebSocket proxying;
- one Exocord API/gateway container;
- PostgreSQL 17.10;
- five GiB of encrypted attachment storage on the API volume;
- a separate LiveKit 1.13.x VM (or LiveKit Cloud).

It does not deploy NATS, Dragonfly, Meilisearch, Kubernetes, or multi-region
services.

## 1. Voice first

LiveKit recommends its official VM generator for a production Docker
Compose/Caddy/TURN setup:

```bash
docker pull livekit/generate
docker run --rm -it -v"$PWD:/output" livekit/generate
```

Give voice and TURN separate DNS names and follow the generated firewall rules.
At minimum, the official VM guide requires TCP 80/443/7881, UDP 3478, and UDP
50000–60000. Do not put the media UDP range behind an HTTP proxy. Record the
generated `wss://` URL and API key pair for the Exocord environment.

Official references:

- https://docs.livekit.io/transport/self-hosting/vm/
- https://docs.livekit.io/transport/self-hosting/ports-firewall/
- https://docs.livekit.io/transport/self-hosting/benchmark

## 2. Configure the API host

Use an Ubuntu/Debian VM with Docker Engine and the Compose plugin. Clone the
source, then:

```bash
cd deploy/alpha
cp .env.example .env
chmod 600 .env
```

Fill every required value. Generate each 32-byte base64url secret independently:

```bash
bash scripts/init-secrets.sh
```

The script generates the PostgreSQL password, message-franking key, attachment
capability/object keys, report-operator token, and optional Apple
provider-encryption key without printing them. Fill the two LiveKit credential files listed in
`secrets/README.md`. Compose mounts every credential from `/run/secrets`;
database passwords, LiveKit keys, and server encryption keys do not appear in
`docker inspect`.

Use [`../../scripts/triage-alpha-reports.ps1`](../../scripts/triage-alpha-reports.ps1)
from the operator PC to review and resolve user reports. The tool retrieves the
separate operator token through pinned SSH for each run, calls only the
least-privilege report endpoints over HTTPS, and does not persist the token.

Host the privacy and optional terms pages named in `.env` before inviting
testers. The operator name, privacy URL, support email, and abuse email are
public API metadata shown before login and under **Privacy & interface**. They
must identify the person or organization actually operating this alpha; the
example values are placeholders. The monolith serves dependency-free starter
pages at `/privacy` and `/terms`; review them against the actual deployment and
operator before use. See [`docs/alpha-policies.md`](../../docs/alpha-policies.md).

The production CORS allowlist defaults to the Windows Tauri origin
`http://tauri.localhost`. Do not add ordinary websites unless Exocord gains an
intentional web client with its own security review.

Point `EXOCORD_DOMAIN` at this VM before starting Caddy. The API and PostgreSQL
have no published host ports; only Caddy exposes 80/443.

## 3. Attachment storage

The base alpha stores attachments under the persistent `api-state` volume and
serves them through unguessable HMAC capability URLs. Private-channel and DM
attachment bytes are encrypted by the client before upload. The five GiB
default quota prevents one tester from filling the 50 GB Oracle boot disk.
Backups stop the API briefly and include this volume, so copy completed backup
sets off the VM every day.

R2 remains an optional later scaling step. Append the values from
`.env.r2.example` to `.env`, fill the two R2 secret files, attach
`EXOCORD_CDN_URL` as a custom bucket domain, and apply
[`r2-cors.json`](r2-cors.json). Then pass `--r2` to deployment and rollback
commands. Do not use the rate-limited `r2.dev` URL.

## 4. Start and verify

Validate the checked-in deployment without exposing any provider secrets:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/validate-alpha-deployment.ps1
```

For the first deployment, leave `EXOCORD_IMAGE_TAG=bootstrap-unbuilt` in
`.env`, choose a unique tag for the source being deployed, and run:

```bash
bash scripts/deploy-alpha.sh git-$(git rev-parse --short=12 HEAD)
docker compose --env-file .env ps
docker compose --env-file .env logs --tail=100 api
```

The deployment wrapper validates and builds before changing the active tag. On
later releases, it replaces only the API and automatically restores the
previous tagged image if `/ready` does not recover within 60 seconds. Add
`--r2` and/or `--apple` when those overlays are enabled.

From a different network:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/alpha-preflight.ps1 `
  -ApiUrl https://alpha.example.com `
  -VoiceUrl wss://voice.example.com
```

Only distribute a Windows installer built with that same API URL after the
preflight passes.

## 5. Apple (optional)

Email login is mandatory. To add Apple, put the `.p8` key at
`deploy/alpha/secrets/apple-private-key.p8`, fill the three non-secret Apple
identifiers in `.env`, and use both Compose files:

```bash
docker compose --env-file .env \
  -f compose.yaml -f compose.apple.yaml up -d
```

The Apple callback is `https://<EXOCORD_DOMAIN>/v1/auth/apple/callback`.

## 6. Backups and restore

Install the supplied root-owned systemd units after placing the source at
`/opt/exocord`:

```bash
sudo install -d -m 0700 /var/backups/exocord-alpha
sudo install -m 0644 systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start exocord-alpha-backup.service
sudo systemctl enable --now \
  exocord-alpha-backup.timer \
  exocord-alpha-backup-freshness.timer
sudo systemctl list-timers 'exocord-alpha-*'
```

The daily job takes a short API write pause, captures PostgreSQL plus the
auth/identity SQLite state volume, verifies both archives, writes one SHA-256
manifest, and waits for API readiness before completing. The six-hour
freshness check fails if the latest set is older than 36 hours or either
checksum fails. Alert on failed units and copy all three files plus separately
managed encryption secrets to a different failure domain. A local archive on
the same VM is not a backup.

At least weekly, run:

```bash
bash scripts/restore-drill.sh \
  /absolute/path/to/exocord-YYYYMMDDTHHMMSSZ.sha256
```

The drill verifies the manifest, restores into an isolated temporary PostgreSQL
container, requires the exact source migration count, restores the state
archive into a disposable volume, and runs SQLite integrity checking. It never
writes to the production database or volume.

## 7. Upgrade and rollback

Every release uses a new immutable application image tag:

```bash
bash scripts/deploy-alpha.sh git-$(git rev-parse --short=12 HEAD)
```

If a healthy but behaviorally incorrect release must be reversed, choose an
existing local tag:

```bash
docker image ls exocord-api
bash scripts/rollback-alpha.sh git-PREVIOUS12
```

The rollback wrapper refuses an absent image, changes only the API, verifies
`/ready`, and restores the current image if the target does not become ready.
Database migrations are forward-only; confirm the chosen binary supports the
current schema before a manual rollback. See
[`OPERATIONS.md`](OPERATIONS.md) for the complete release and recovery runbook.

## 8. Firewall and operations

API host inbound: TCP 22 from the owner/VPN only, TCP 80/443 publicly. Voice
host inbound: exactly the ports emitted by LiveKit's generator. PostgreSQL and
the API port remain private.

Before expanding beyond friends:

- automate off-host backups and exercise one restore;
- monitor `/ready`, Postgres connections, disk, gateway fan-out latency,
  LiveKit CPU/egress/packet loss, and TURN relay percentage;
- test email, voice, and screen sharing from two unrelated networks;
- define a tester support/abuse address and a short privacy notice;
- obtain an Authenticode certificate if the SmartScreen warning is unacceptable.

Caddy access logs deliberately omit request URIs and fingerprinting headers and
hash client addresses. This prevents login/search query values, invite
capabilities, raw IP addresses, and user-agent fingerprints from entering the
container log stream while retaining status/latency and pseudonymous
correlation. Container logs use bounded local rotation.
