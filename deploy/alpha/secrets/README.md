# Alpha secret files

Run `../scripts/init-secrets.sh` from this deployment directory. It creates
random local keys and empty credential files with owner-only permissions.

Fill these files with provider credentials before starting Compose:

- `livekit-api-key`
- `livekit-api-secret`

Fill `r2-access-key-id` and `r2-secret-access-key` only when enabling the
optional R2 storage overlay.

Email/password accounts do not require an email provider. Resend is needed only
if the optional legacy email-code endpoints are enabled outside this base
deployment.

The script generates these values locally and never prints them:

- `postgres-password`
- `attachment-capability-key`
- `attachment-object-key`
- `franking-key`
- `operator-token`
- `provider-token-key`

`operator-token` is the separate high-entropy credential used by the local
report-triage tool. It is not an Exocord account token. Keep it on the API host;
the Oracle triage command reads it over the pinned SSH connection for each
operation and never saves or prints it on Windows.

`apple-private-key.p8` is optional and must contain the Apple private key when
the Apple Compose overlay is enabled. Never commit or place any file from this
directory inside a Docker build context.
