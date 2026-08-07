# Operator report triage

The friends alpha has a deliberately narrow operator surface for reports. It
is separate from server-owner moderation and from ordinary Exocord accounts.

## Security boundary

- Production requires `EXOCORD_OPERATOR_TOKEN`, normally file-mounted at
  `/run/secrets/operator-token`.
- The token contains 32 random bytes after the `exo_op_` prefix. Only its
  SHA-256 digest is kept in application state, and comparisons are
  constant-time.
- A normal account, including an administrator or server owner, cannot use the
  operator endpoints.
- Responses are `Cache-Control: no-store, private`. List and resolution calls
  have separate operator-scoped rate limits.
- The Windows command reads the token through pinned SSH for each invocation.
  It does not print, write, or accept the credential as a command-line
  parameter.

The report endpoints are:

```text
GET /v1/operator/reports?status=open&limit=50
PUT /v1/operator/reports/{report_id}
```

List status may be `open`, `actioned`, `dismissed`, or `all`; the limit is
1–100. A resolution body is:

```json
{
  "status": "actioned",
  "note": "Account restriction applied."
}
```

Only `actioned` and `dismissed` are accepted. Resolution is one-way and
atomic: a second attempt returns a conflict instead of rewriting the first
operator decision.

## Platform account enforcement

Server-owner moderation remains server-scoped. Only the separate operator
credential can inspect or change a platform account suspension:

```text
GET    /v1/operator/users/{user_id}/suspension
PUT    /v1/operator/users/{user_id}/suspension
DELETE /v1/operator/users/{user_id}/suspension
```

`PUT` suspends and `DELETE` reinstates. Both require a non-empty reason. They
may also include the ID of the report that supports the decision:

```json
{
  "reason": "Credible severe-abuse report.",
  "reportId": "142000000000000001"
}
```

When supplied, the report must identify that account as the reported message
author. Suspension atomically revokes every access and refresh session, blocks
password, Apple, recovery, email-code, and refresh login issuance, disconnects
live gateways, and evicts the account from voice. Reinstatement permits a new
login but never restores the revoked sessions.

Every suspend and reinstate decision is append-only account-enforcement
history with operator, reason, optional report, and time. Duplicate state
changes return a conflict. Status and mutation responses are bounded,
operator-authenticated, rate-limited, and `Cache-Control: no-store, private`.
An account's machine-readable export includes its own enforcement history.

## Evidence boundary

For plaintext messages, the report stores the server-readable selected
message. For an MLS-encrypted message, submission must include a valid
franking opening and the original server-authenticated tag. The API verifies
both before accepting the report.

The persisted operator evidence contains only:

- the selected message plaintext;
- whether it came from an encrypted channel and whether verification passed;
- attachment IDs, names, content types, sizes, and submitted hashes;
- reporter, author, channel, server, category, detail, and timestamps;
- a non-secret hexadecimal copy of the server franking tag.

The opening secret is discarded immediately after verification and is absent
from both storage and the operator response. The integration test submits a
real OpenMLS message, rejects altered evidence, confirms the secret is absent
from the queue response, resolves once, and rejects a second resolution.

## Windows workflow

List open reports:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha
```

Use `-AsJson` for an archival or review format. To record a decision:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -ReportId REPORT_ID `
  -Disposition dismissed `
  -Note "Reviewed; no terms violation." `
  -Confirm:$false
```

Inspect an account, suspend it from a report, and later reinstate it:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -UserId USER_ID `
  -AccountAction status

powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -UserId USER_ID `
  -AccountAction suspend `
  -ReportId REPORT_ID `
  -Reason "Credible severe-abuse report." `
  -Confirm:$false

powershell -ExecutionPolicy Bypass -File scripts/triage-alpha-reports.ps1 `
  -ApiHost API_PUBLIC_IP `
  -ApiUrl https://alpha.example.com `
  -SshPrivateKey C:\Users\you\.ssh\exocord-oracle-alpha `
  -UserId USER_ID `
  -AccountAction reinstate `
  -Reason "Appeal accepted after review." `
  -Confirm:$false
```

Use `-AcceptNewHostKey` only on the first connection immediately after the
Oracle instance is created and SSH ingress is limited to the operator's
current `/32`. Later calls must use the pinned key in
`outputs/oracle-alpha/known_hosts`.

## Operational limit

This queue makes alpha reports reviewable; it does not create a staffed safety
operation. Before public or child-accessible signup, define escalation,
appeal, evidence-retention, lawful-request, emergency, and CSAM handling with
qualified counsel and at least two trained humans. Do not place report content
or credentials in general application logs or informal chats.
