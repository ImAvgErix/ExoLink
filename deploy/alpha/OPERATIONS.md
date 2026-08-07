# Alpha operations runbook

This runbook is for the single-region, single-API deployment in this directory.
It assumes the source is root-owned at `/opt/exocord`, provider credentials are
file-mounted from `deploy/alpha/secrets`, and backups are written to
`/var/backups/exocord-alpha`.

## Routine checks

At least daily:

```bash
cd /opt/exocord/deploy/alpha
docker compose --env-file .env ps
docker compose --env-file .env logs --since=24h api caddy postgres
systemctl --failed
systemctl status exocord-alpha-backup-freshness.service
df -h / /var/lib/docker /var/backups/exocord-alpha
```

From a Windows machine on a different network:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/alpha-preflight.ps1 `
  -ApiUrl https://alpha.example.com `
  -VoiceUrl wss://voice.example.com
```

Alert on `/ready` failure, backup freshness failure, certificate expiry,
filesystem pressure, PostgreSQL restarts, sustained API latency, LiveKit CPU,
packet loss, egress, and TURN relay percentage. Caddy logs intentionally omit
URIs, raw client addresses, and client fingerprint headers.

## Report triage

Review open reports from the pinned operator PC:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha
```

After recording the minimum operational decision, resolve one report:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -ReportId REPORT_ID `
  -Disposition actioned `
  -Note "Account restriction applied." `
  -Confirm:$false
```

Use `dismissed` only after review. The command retrieves the operator token
from the root-owned deployment directory over SSH, keeps it only in process
memory, and never prints or stores it on Windows. Normal Exocord access tokens
cannot reach these endpoints. See
[`../../docs/report-triage.md`](../../docs/report-triage.md).

For a platform-level safety decision, first inspect the account:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -UserId USER_ID `
  -AccountAction status
```

Suspend only after recording a scoped reason and, when applicable, binding the
reported message author:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -UserId USER_ID `
  -AccountAction suspend `
  -ReportId REPORT_ID `
  -Reason "Credible severe-abuse report." `
  -Confirm:$false
```

Suspension revokes all sessions and current gateway/voice access. Reinstatement
uses `-AccountAction reinstate -Reason "..."`; the tester must sign in again.
Never treat a server owner's moderation decision as authority for a
platform-wide suspension. Preserve the append-only result and provide a
support/appeal path.

## Release

1. Record the current tag and verify the old deployment.
2. Create a verified backup.
3. Deploy a new, source-specific image tag.
4. Run external preflight and a two-user message/attachment/voice call.
5. Keep the prior image until the new release has been healthy for at least one
   backup cycle.

```bash
cd /opt/exocord/deploy/alpha
grep '^EXOCORD_IMAGE_TAG=' .env
sudo bash scripts/backup-alpha.sh /var/backups/exocord-alpha
bash scripts/deploy-alpha.sh git-$(git rev-parse --short=12 HEAD)
```

Use `--apple` on every Compose wrapper command if Apple login is enabled.
`deploy-alpha.sh` builds and validates before changing `.env`; if the new API
cannot reach `/ready` in 60 seconds, it restores the previous image
automatically.

## Application rollback

List the retained immutable images and select the known-good tag:

```bash
docker image ls exocord-api
bash scripts/rollback-alpha.sh git-PREVIOUS12
```

The wrapper verifies the local image exists and performs a readiness-gated
rollback. Do not roll back across an incompatible database migration. The
current migrations are additive, but compatibility must be checked for every
future release rather than assumed.

## Backup response

Inspect the last runs:

```bash
journalctl -u exocord-alpha-backup.service -n 200 --no-pager
journalctl -u exocord-alpha-backup-freshness.service -n 200 --no-pager
bash scripts/verify-backup-freshness.sh /var/backups/exocord-alpha 129600
```

For every backup set, move the `.dump`, `.state.tar.gz`, and `.sha256` files
together to storage outside the VM. The base rotation keeps exactly three
daily sets because the state archive includes locally stored encrypted
attachment objects. Store
the LiveKit, attachment, franking, report-operator, Apple, database, and optional R2 secrets in
a separate encrypted backup. The attachment capability/object keys are
required to preserve existing attachment URLs and object addressing; losing
the provider-token key forces Apple users to reauthenticate.

Run the isolated restore drill at least weekly and after every migration:

```bash
bash scripts/restore-drill.sh \
  /var/backups/exocord-alpha/exocord-YYYYMMDDTHHMMSSZ.sha256
```

Do not improvise a production restore before the drill succeeds. For a real
host loss, create a clean replacement VM, install the same source revision and
secret set, restore PostgreSQL and the `exocord-alpha-api-state` volume while
the API is stopped, then run the external preflight before changing DNS. Keep
the failed host or disks intact until account login, messages, attachments, and
voice have all been accepted from the replacement.

Copy every daily set off the API VM. From the pinned Windows operator PC:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sync-oracle-backup.ps1 `
  -ApiHost API_PUBLIC_IP `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -RetentionSets 7 `
  -Confirm:$false
```

Add `-CreateFreshBackup` for a release/restore checkpoint; it briefly stops the
API while producing a consistent new set. The command accepts only the pinned
Oracle host key, stages root-only files in a random mode-0700 remote directory,
downloads the dump/state/manifest trio, verifies both SHA-256 entries locally,
and removes incomplete staging data. Its default destination is
`%LOCALAPPDATA%\ExocordOperator\backups`. Keep that folder on a BitLocker
volume or copy it to an encrypted external drive; the PostgreSQL dump can
contain public-server message content.

## Incident containment

For an application exploit or credential leak:

1. Remove public access at the firewall or stop Caddy.
2. Preserve Docker logs and a filesystem snapshot; do not post secrets into a
   chat or issue.
3. Revoke the affected provider credential at Cloudflare, LiveKit, or Apple.
4. Replace the matching file in `secrets/`, restart only the dependent
   services, and verify readiness.
5. If the franking key or attachment-object key leaked, treat existing
   signatures or encrypted metadata as compromised and plan an explicit
   application-level rotation before reopening.
6. Run account/session revocation if authentication material may have been
   exposed.

For abuse rather than infrastructure compromise, preserve only the scoped,
franked report and audit evidence needed for review. Do not expand routine
logging to message content, login links, invite codes, search terms, raw IP
addresses, or user-agent fingerprints.
