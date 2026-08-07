# Oracle Always Free alpha hosts

This is the console handoff for the two hosts needed by the Windows friends
alpha. It contains no Oracle credentials or application secrets.

## Capacity boundary

Oracle's current Always Free documentation provides 2 Ampere A1 OCPUs and
12 GB memory total in the tenancy home region. Allocate that as two
`VM.Standard.A1.Flex` instances with 1 OCPU and 6 GB each:

| Instance | Shape | Boot volume | Purpose |
|---|---:|---:|---|
| `exocord-alpha-api` | 1 OCPU / 6 GB | 50 GB | Caddy, API/gateway, PostgreSQL |
| `exocord-alpha-voice` | 1 OCPU / 6 GB | 50 GB | LiveKit, embedded TURN, Redis, Caddy |

Both instances must show **Always Free eligible** before creation. Do not use a
paid shape or enable a paid upgrade. This is enough for 100–1,000 registered
alpha accounts with modest simultaneous voice usage; concurrency, not account
count, is the limit.

## Console values

1. Work only in the tenancy's **home region**.
2. Use **Compute → Instances → Create instance**.
3. Select Canonical Ubuntu 24.04 Minimal, `aarch64`.
4. Select `VM.Standard.A1.Flex`, 1 OCPU, 6 GB memory, and a 50 GB boot volume.
5. Use a public subnet and assign a public IPv4 address.
6. Add the same OpenSSH public key to both instances. Keep the private key only
   on the operator's Windows PC.
7. Under **Advanced options → Management → Initialization script**, upload
   `api-cloud-init.yaml` for the API instance. Oracle accepts the file directly;
   it must not be base64 encoded.
8. Upload `voice-cloud-init.yaml` for the voice instance. It hardens SSH and
   opens only the host-level ports required by LiveKit. The official
   `livekit/generate` image is run on the Docker-ready API bootstrap host after
   both instances and DNS exist; its generated `init_script.sh` performs the
   actual LiveKit installation.

Do not put provider keys, passwords, domains containing private tokens, or
other secrets in Oracle user data.

## Network security groups

Create separate NSGs so the broad media range never reaches the API host.
Rules are stateful. Source port is **All**.

`exocord-api-nsg` ingress:

- TCP 22 from the operator's current public IPv4 address as `/32`;
- TCP 80 from `0.0.0.0/0`;
- TCP 443 from `0.0.0.0/0`.

`exocord-voice-nsg` ingress:

- TCP 22 from the operator's current public IPv4 address as `/32`;
- TCP 80 from `0.0.0.0/0`;
- TCP 443 from `0.0.0.0/0`;
- UDP 443 from `0.0.0.0/0`;
- TCP 7881 from `0.0.0.0/0`;
- UDP 3478 from `0.0.0.0/0`;
- UDP 50000–60000 from `0.0.0.0/0`.

Keep normal outbound access. Do not expose PostgreSQL 5432, the Exocord
container port 4100, LiveKit API port 7880, Docker, or SSH to the whole
internet.

## DNS names before deployment

For the friends alpha, a purchased domain is optional. The one-command installer
can derive temporary names such as `api-203-0-113-10.sslip.io` directly from
the assigned public IPs. [sslip.io](https://sslip.io/) resolves hostnames with
embedded IP addresses and supports normal per-host TLS certificates through
HTTP-01. This removes DNS setup from Phase 0, but it is a third-party DNS
dependency; move to names under an Exocord-owned domain before a public launch.

For an owned domain, create these records after Oracle assigns the public IPs:

- the Exocord API name points to the API public IP;
- both the LiveKit primary name and TURN name point to the voice public IP;
- an attachment media name is needed only if the optional R2 overlay is added.

Wait for public DNS to resolve before starting Caddy or the LiveKit cloud-init
deployment. The generated LiveKit configuration obtains TLS automatically and
requires both its primary and TURN DNS records.

## First readiness checks

After the API host reaches **Running**, wait for cloud-init and verify over SSH:

```bash
cloud-init status --wait
sudo cat /var/lib/exocord-bootstrap-ready
docker version
docker compose version
sudo ufw status verbose
```

The application source and secret files are transferred only after these
checks pass. Production deployment then follows `deploy/alpha/README.md`, and
the public gate is `scripts/alpha-preflight.ps1`.

## Automated host handoff

After both instances are running, the checked-in PowerShell handoff uses
Windows OpenSSH and a dedicated pinned `known_hosts` file. The fastest
no-domain Phase 0 path is one command:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install-oracle-alpha.ps1 `
  -ApiHost API_PUBLIC_IP `
  -VoiceHost VOICE_PUBLIC_IP `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -AcmeEmail owner@example.com `
  -SupportEmail help@example.com `
  -AbuseEmail abuse@example.com `
  -UseTemporarySslipDomains `
  -AcceptNewHostKey `
  -Confirm:$false
```

For owned domains, pass `-ApiDomain`, `-VoiceDomain`, and `-TurnDomain` to that
same command instead. The two lower-level commands remain available for
recovery or an intentionally staged deployment:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install-oracle-livekit.ps1 `
  -GeneratorHost API_PUBLIC_IP `
  -VoiceHost VOICE_PUBLIC_IP `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -PrimaryDomain voice.example.com `
  -TurnDomain turn.example.com `
  -AcceptNewHostKey `
  -Confirm:$false

powershell -ExecutionPolicy Bypass -File scripts/install-oracle-api.ps1 `
  -ApiHost API_PUBLIC_IP `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -ApiDomain alpha.example.com `
  -VoiceUrl wss://voice.example.com `
  -AcmeEmail owner@example.com `
  -SupportEmail help@example.com `
  -AbuseEmail abuse@example.com `
  -UseGeneratedLiveKitCredentials `
  -Confirm:$false
```

The first command runs LiveKit's official interactive generator inside Docker
on the API bootstrap host, suppresses credential output, checksum-verifies its
generated startup script, installs it on the voice host, and verifies TLS for
both names. The second verifies the Exocord source bundle hash, transfers no
secret in a command argument, builds the API, waits for public HTTPS, creates
the first verified backup, and enables backup monitoring.

After the API is live, review the report queue without copying its operator
credential off-host:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha
```

The command retrieves the secret through the same pinned SSH trust boundary
for that invocation and calls the report-only HTTPS API.

Use `-AcceptNewHostKey` only on the first connection immediately after Oracle
assigns the instances and the SSH NSGs are restricted to the operator's
current `/32`. Later runs require the pinned keys in
`outputs/oracle-alpha/known_hosts`.

Official references:

- Oracle Always Free resources:
  https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
- Oracle instance creation and initialization scripts:
  https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/launchinginstance.htm
- Oracle security-list rules:
  https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/creating-securitylist.htm
- LiveKit production VM generator:
  https://docs.livekit.io/transport/self-hosting/vm/
- LiveKit firewall ports:
  https://docs.livekit.io/transport/self-hosting/ports-firewall/
