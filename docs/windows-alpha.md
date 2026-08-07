# Windows friends-and-testers alpha

This milestone targets 100–1,000 registered testers, not 1,000 simultaneous
voice publishers. The initial operating envelope is one durable API instance,
one PostgreSQL database, quota-bounded local attachment storage, and one properly
configured LiveKit/TURN deployment. Keep the architecture single-region until
measurement shows a real bottleneck.

## What testers receive

Prefer the NSIS `x64-setup.exe`. It installs per user, needs no administrator
access, creates an uninstaller, and downloads WebView2 only when Windows does
not already provide it. The portable zip is for troubleshooting. Extract the
entire folder before opening `Exocord.exe`; `WebView2Loader.dll` must remain
beside it. The app is intentionally not distributed as a misleading standalone
portable executable.

If the installer was built with an alpha API URL, the first screen is
email/password account access. That embedded address overrides an older saved
preview or localhost address; `EXOCORD_API_URL` remains the explicit
development override. A generic build instead shows one focused
**Connect your alpha** screen:
paste the HTTPS URL shared by the alpha owner, test it, then choose
**Use & restart**. Exocord saves only the server address in
`%APPDATA%\app.exocord.desktop\settings.json`. Session, cache, and MLS keys stay
in account-specific Windows Credential Manager entries. Each signed-in account
uses `%APPDATA%\app.exocord.desktop\accounts\<user-id>\client.sqlite3`; the
client verifies that the restored server session, secure-vault account, and
cache account are identical before synchronization.

The current artifacts are not code signed. Windows SmartScreen may therefore
show an unknown-publisher warning. SHA-256 checksums prove that a downloaded
file matches the owner’s published artifact, but they do not replace an
Authenticode certificate.

## Build the Windows download

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-windows-alpha.ps1 `
  -ApiUrl https://alpha.example.com
```

Omit `-ApiUrl` to produce a generic installer with first-run network setup.
The script runs renderer tests, all Rust tests, strict Clippy, and a Tauri/NSIS
release build. It writes the installer, portable zip, guide, and
`SHA256SUMS.txt` under `artifacts/windows-alpha/<version>/`.

`-SkipChecks` exists only for a repeat packaging pass after the same source
state already completed all checks.

## Server preflight

Start from the checked-in
[single-region alpha deployment](../deploy/alpha/README.md). Production startup
fails closed unless PostgreSQL, an explicit local-or-R2 attachment mode,
LiveKit, and the message-franking key are configured. Email/password login is
mandatory; Apple login is optional, and a partial Apple configuration is
rejected.
The operator name, HTTPS privacy notice, tester-support email, and abuse email
are also mandatory public metadata. The app shows them before login and under
**Settings → Privacy & security**; the deployment serves hardened `/privacy` and `/terms`
starter pages with no scripts, analytics, or external assets.

The API needs a persistent `EXOCORD_STATE_DIR` even with PostgreSQL. It contains
the encrypted-provider/auth SQLite database and, in the base alpha, encrypted
attachment objects. Back up that directory together with PostgreSQL. Never
place it on ephemeral container storage.

The Windows off-host backup command refuses a destination that is not protected
with NTFS EFS. On a machine without BitLocker, create the destination once and
run `cipher /E /A <backup-directory>` before the first sync. Export and protect
the EFS certificate separately; losing the Windows profile and certificate
makes those off-host backup files unreadable.

The production operator task runs daily at 03:30 and catches up when the PC is
next available. Its tested Windows PowerShell action uses `-Command` so that
`-Confirm:$false` is parsed as a Boolean; passing that switch after `-File`
under Windows PowerShell 5 is not equivalent and causes the task to fail.

Before deploying, run the configuration validator:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/validate-alpha-deployment.ps1
```

Before distributing the installer, check the public HTTPS origin:

```powershell
$origin = "https://alpha.example.com"
Invoke-RestMethod "$origin/health"
Invoke-RestMethod "$origin/ready"
Invoke-RestMethod "$origin/v1/auth/providers"
Invoke-RestMethod "$origin/v1/meta/capabilities"
```

The Windows client independently requires all of the following before it will
save a remote network:

- `/health` returns `ok` and `/ready` returns `ready: true`;
- storage is `postgres`;
- email/password auth is enabled;
- attachments are not disabled;
- native voice is configured;
- the operator identity, privacy page, support contact, and abuse contact are
  reachable;
- `conversation_actions` matches this client protocol.

Terminate TLS at a reverse proxy, forward only to the private API listener, and
strip untrusted forwarding headers. Set `EXOCORD_TRUST_PROXY_HEADERS=1` only
when the API can be reached exclusively through that trusted proxy.

## Alpha capacity boundary

Treat registered accounts and concurrency as different numbers. For the first
100–1,000 accounts, measure these gates:

- concurrent gateway sockets and event fan-out latency;
- p95 REST and database latency during message bursts;
- active voice participants, forwarded tracks, packet loss, and SFU egress;
- TURN relay percentage and bandwidth;
- password-hash latency and login rate limits;
- Postgres connections, storage growth, backup completion, and restore time.

Do not add NATS, Dragonfly, sharding, multi-region routing, or mobile clients
for this alpha. Add capacity only when a measured gate is consistently close
to its limit. Voice bandwidth normally becomes the first expensive constraint.

## Clean-machine acceptance

Use a Windows account that has never run Exocord:

1. Verify the installer SHA-256 against `SHA256SUMS.txt`.
2. Install without administrator elevation and launch from the Start menu.
3. Confirm the preconfigured network, or complete first-run HTTPS setup.
4. Sign in by email, create and join a server, send/reply/edit/react/delete,
   upload a file, open a DM, and restart the app.
5. Join voice with two Windows machines, test mute/deafen/push-to-talk and
   screen sharing, then revoke one device.
6. Confirm queued messages recover after a brief network interruption.
7. Sign out, sign in as a second account on the same PC, and confirm none of
   the first account's DMs, search results, profile, or cached state appears.
   Sign back into the first account and confirm its own state returns.
8. Uninstall and confirm the application binary is removed, then delete the
   Exocord application-data directory to simulate a clean Windows install.
   Reinstall and sign in; confirm servers, relationships, messages, and
   archived encrypted DM history restore from the account. Repeat once with a
   recovery code and a new password.
9. Confirm a recovery code, key, or archive copied from the other test account
   cannot decrypt or replace this account's history.

Do not widen the alpha until email, backup restore, HTTPS renewal, LiveKit/TURN,
crash reporting without message content, and an abuse-report contact have each
been exercised at least once.
