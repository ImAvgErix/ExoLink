# Sign in with Apple setup

Exocord keeps the Apple flow server-side. The desktop opens the system browser,
polls a state-bound one-time handoff, and receives only an Exocord session.
Apple authorization codes, identity tokens, and refresh tokens never enter the
React renderer.

## Apple Developer configuration

1. Enable Sign in with Apple on a primary App ID.
2. Create a Services ID for the Exocord web flow and associate it with that
   primary App ID.
3. Register and verify the production domain.
4. Register this exact return URL:
   `https://YOUR_DOMAIN/v1/auth/apple/callback`
5. Create a Sign in with Apple private key and securely download its `.p8`
   file. Record the Team ID and key ID.

Apple requires the return URL to be HTTPS with a domain; it cannot be an IP
address or `localhost`. Local development therefore uses email login unless a
public HTTPS development callback is configured.

## Server environment

All six values are required together. If all are absent, Apple remains
intentionally disabled and the desktop button is unavailable. If only some are
present, production startup fails instead of silently shipping a broken login
button.

```dotenv
EXOCORD_APPLE_CLIENT_ID=com.example.exocord.web
EXOCORD_APPLE_TEAM_ID=ABCDE12345
EXOCORD_APPLE_KEY_ID=ZYXWV98765
EXOCORD_APPLE_PRIVATE_KEY_FILE=/run/secrets/AuthKey_ZYXWV98765.p8
EXOCORD_APPLE_REDIRECT_URI=https://chat.example.com/v1/auth/apple/callback
EXOCORD_PROVIDER_TOKEN_KEY_FILE=/run/secrets/provider-token-key
```

Generate the provider-token-key file from 32 cryptographically random bytes
encoded as unpadded base64url. It encrypts Apple refresh tokens and native
handoff payloads with XChaCha20-Poly1305. Mount it from the deployment secret
manager, not source control. Rotating it requires reauthentication for existing
Apple identities.

## Implemented verification

- ES256 client secret with Apple Team ID, key ID, Services ID, five-minute
  expiry, and Apple audience.
- Authorization-code exchange at Apple’s token endpoint.
- Apple JWKS lookup by matching `kid`.
- Strict RS256 signature, issuer, audience, expiry, subject, verified-email,
  and constant-time nonce validation.
- One-time, ten-minute state record.
- Encrypted Apple refresh token storage.
- Encrypted, one-time desktop session handoff.
- Cancellation and failed verification consume the flow without exposing
  provider tokens.
- A verified Apple email can attach to an existing account only when that
  account's email was previously verified. An unverified password account with
  the same address fails closed and must sign in through its existing password
  path; Exocord never treats matching email text alone as proof of ownership.
- A signed-in password account can explicitly connect Apple from Settings.
  Starting that flow requires the current password, and the one-time browser
  handoff is bound to the same Exocord user and session that started it.
- Apple cannot be connected if its subject already belongs to another Exocord
  account. Connecting never replaces the account email or display name.
- Disconnecting Apple also requires the current password and deletes the
  encrypted provider token. Apple-only accounts cannot disconnect their only
  durable sign-in method.

The mock-Apple test suite covers accepted signatures and rejects incorrect
audience and nonce values. Auth and HTTP tests also prove that an unverified
password email cannot be silently linked, a verified address can be linked,
explicit linking is password-verified and session-bound, one Apple identity
cannot belong to two accounts, and the only login method cannot be removed. A
live Apple-account smoke test still requires the project’s real Apple Developer
credentials and registered HTTPS domain.
