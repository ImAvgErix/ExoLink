# Voice and screen sharing

Exocord voice uses a self-hosted LiveKit SFU. The Exocord backend remains the
authorization authority: LiveKit never decides server membership, role
permissions, timeouts, or channel overwrites.

Encrypted voice channels use both WebRTC transport protection and
client-side frame encryption. The native core derives the media key from the
channel's authenticated MLS epoch and supplies it directly to LiveKit's E2EE
worker. The raw backend grant does not contain a key and therefore reports
`endToEndEncrypted: false`; the trusted native bridge changes that to `true`
only after it has derived and attached the device-local key.

## Join path

1. The membership-filtered sync response exposes only voice channels the
   current user can view.
2. The client requests `POST /v1/channels/{channel_id}/voice-token`.
3. The repository resolves the member's current role, overwrite, owner, and
   timeout state.
4. `VIEW_CHANNEL` and `CONNECT` are both required. Missing access is concealed
   as a missing channel.
5. The backend signs a 60-second LiveKit JWT for one exact room and one exact
   participant identity.
6. The native core ensures the channel MLS group is current and exports a
   domain-separated 32-byte frame key for this channel and epoch.
7. The renderer lazy-loads `livekit-client`, imports the key through its
   external E2EE provider/worker, connects, and reflects participant and media
   state from the SFU rather than optimistic mock state.

The token response is `Cache-Control: no-store, private`. The LiveKit API
secret never enters the renderer, desktop SQLite cache, logs, or response.

The grant is intentionally narrow:

- subscription is enabled;
- microphone publication requires both `SPEAK` and `USE_VAD`;
- screen and screen-audio publication require `STREAM`;
- arbitrary data publication is disabled;
- participant metadata mutation is disabled;
- the room name is fixed to
  `exo-{guild_id}-voice-{channel_id}`.

## Runtime behavior

The client currently supports:

- join and explicit leave;
- receive-only joins when microphone capture is unavailable;
- mute and deafen, including restoration of the pre-deafen microphone state;
- input and output device discovery and switching;
- remote audio attachment and cleanup;
- active-speaker, mute, screen-share, and connection-quality state;
- screen sharing with system audio where the operating system supports it;
- reconnecting/reconnected/failed UI;
- autoplay recovery without claiming audio is playing when it is blocked;
- lazy media SDK loading, keeping the normal chat startup bundle small.

Capture defaults enable the browser/WebView's echo cancellation, noise
suppression, and automatic gain control. These are helpful defaults, not a
claim that RNNoise or a custom DSP pipeline has been implemented.

## Revocation

A short token is not enough by itself because an already connected peer could
otherwise remain in a room. Exocord therefore enforces access on both planes:

- the gateway emits an authorization-change event; the compliant client mints
  a fresh grant, immediately stops newly forbidden microphone/screen tracks,
  or leaves if access disappeared;
- the backend uses LiveKit's room-control API to remove the affected
  participant and revoke previously issued token timestamps after role
  assignment changes, timeouts, kicks, and bans;
- member overwrite changes remove that participant from the room;
- role overwrite and role-definition changes reset affected rooms so every
  participant must authorize again;
- deleting a voice channel deletes its active media room.

The room-control call is bounded by a two-second timeout and runs outside the
moderation request path. Moderation remains available if the SFU is temporarily
unreachable; the client's authorization event still fails closed.

## Development

The development backend defaults to:

```text
URL:        ws://127.0.0.1:7880
API key:    devkey
API secret: secret
```

Those values are LiveKit's documented local-development pair and are never
accepted for a non-loopback plaintext WebSocket URL.

With Docker installed:

```powershell
docker compose up -d livekit
cargo run --package exo-monolith
pnpm --dir apps/desktop tauri dev
```

The Compose service exposes:

- `7880/tcp` for signaling and the room-control API;
- `7881/tcp` for WebRTC TCP fallback;
- `7882/udp` for WebRTC media.

To override the development defaults, or to enable voice in production, set
all three values together:

```powershell
$env:EXOCORD_LIVEKIT_URL="wss://voice.example.com"
$env:EXOCORD_LIVEKIT_API_KEY="..."
$env:EXOCORD_LIVEKIT_API_SECRET="..."
```

Partial configuration is rejected. In production, leaving all three unset
keeps the rest of Exocord available but reports voice as `not_configured`.

The development-only integration page at
`/qa/voice-e2e.html?api=http://127.0.0.1:4188` creates two disposable users,
joins them through a real invite, publishes synthetic microphone and
screen-share tracks through the SFU, applies a timeout, and verifies forced
eviction plus denied reminting. It requires the development email-code preview
and must not be exposed as a production route.

## Production gate

The development `--dev` server is not a production deployment. Before public
voice traffic:

1. Serve signaling only through `wss://` with a publicly trusted certificate.
2. Generate unique high-entropy API keys/secrets and keep them only in the
   backend secret store.
3. Deploy LiveKit's embedded TURN/TLS path so restrictive networks and VPNs
   have a relay fallback.
4. Open and monitor the documented signaling, WebRTC TCP, UDP, and TURN ports.
5. Put the SFU in the intended data-residency region and document its metadata,
   log, and metric retention.
6. Load-test realistic fan-out, screen-share bitrate, packet loss, reconnect,
   and room-size profiles.
7. Alert on join latency, publish/subscription failures, ICE failure,
   packet-loss/jitter, control-plane eviction failures, and CPU saturation.
8. Run the two-client integration test against staging after every LiveKit or
   client SDK update.
9. Complete an abuse, privacy, and external security review.

LiveKit's official production deployment guidance is at
<https://docs.livekit.io/transport/self-hosting/deployment/>.

## Privacy boundary

The current Exocord deployment does not configure LiveKit Egress or recording,
and the monolith does not receive or store media packets. For an encrypted
voice channel, the native Rust core exports an epoch-bound key from that
channel's MLS group. LiveKit's external E2EE key provider and dedicated worker
apply frame encryption, and the client fails closed when the key or worker is
missing.

The SFU can still observe room membership, timing, packet sizes, IP/network
metadata, and aggregate quality. Device removal/rekeying, recovery, and an
external security audit remain production gates. See
[end-to-end encryption](end-to-end-encryption.md).
