# Implementation status

## Working and verified

- Tauri v2 shell with a React/Vite renderer and custom native window chrome.
- Windows NSIS per-user installation plus a portable troubleshooting build.
  Alpha releases can embed one HTTPS API URL at compile time; generic builds
  show a focused first-run network screen. Runtime environment overrides and
  saved settings have explicit precedence, remote HTTP is rejected, and the
  client probes health, readiness, auth, durable storage, attachments, native
  voice, and conversation protocol compatibility before saving and restarting.
- The user-supplied v14 prototype is now the canonical client shell: a 52 px
  profile/space/channel bar with no permanent server rail, centered 900 px
  hour-grouped message surface, a 52 px low-chrome composer, profile/space
  popovers, and a 252 px real voice dock that collapses to a 56 px participant
  rail.
- Geist Sans and Geist Mono are bundled locally, preserving the
  prototype's typography without a third-party font request.
- Messages now opens to a real inbox home with recent DMs, unread state,
  friend/request summaries, and one-click conversation creation. The legacy
  device-only workspace remains an internal offline cache primitive and is no
  longer exposed as a destination.
- Settings is a viewport-bounded two-pane control surface with direct section
  navigation. Durable profile editing supports unique case-insensitive
  usernames, display names, and verified versioned PNG/JPEG/WebP avatars with a
  512 KiB and 32–1024 px boundary.
- Sign-in, registration, and first-run network setup now share the same
  monochrome shell, self-hosted typography, spacing, and interaction language
  as the client. Registration keeps the primary email/password action above
  the fold.
- The complete supplied UI/motion reference set has an explicit
  adopt/defer/reject audit. The active-speaker state now uses a bounded
  background-position beam, adds no renderer dependency, and inherits the
  global reduced-motion cutoff.
- Functional local server creation, server/channel switching, message sending,
  compact mode, and privacy settings.
- Real LiveKit voice with short-lived exact-room grants, membership/overwrite/
  timeout permission resolution, source-scoped publication, receive-only
  fallback, mute/deafen restoration, input/output device switching, remote
  audio, active-speaker/quality state, reconnect UI, and screen sharing.
- Authorization-change revalidation plus server-side LiveKit eviction for role
  changes, overwrites, timeouts, kicks, bans, and channel deletion. Revoked
  token timestamps prevent an evicted client from reusing an old grant.
- Signing out leaves local media first, revokes the session, evicts the member
  from every server voice room, clears the signed-in view model, and returns to
  onboarding.
- The media SDK is loaded on demand: the production chat/server entry chunk is
  388.03 kB (114.21 kB gzip), while LiveKit remains in a separate voice-only
  chunk.
- Direct attachment reservations for up to ten 25 MiB files, browser-side
  SHA-256, short-lived local/R2 upload capabilities, HMAC content-addressed
  object names, server-side hash/size/magic-MIME verification, guarded image
  dimensions, active-document rejection, and atomic message linking.
- Responsive image/video/audio/file rendering with reserved dimensions,
  composer upload progress, verified attachment trays, removal, and
  attachment-only messages.
- Native exact-handle relationships with transactional incoming/outgoing/
  friend/blocked states, crossed-request acceptance, private asymmetric
  blocking, pair-scoped concurrency locks, and no public account enumeration.
- Canonical one-to-one DM channels with exact recipients, idempotent concurrent
  opens, attachment/outbox support, retained history after unfriend/block, and
  friendship-gated new sends.
- Native OpenMLS 1.0 suite-1 device identities, signed one-time KeyPackages,
  opaque ciphertext storage, context-bound application messages, sealed
  restart-safe group state, copyable fingerprints, and no server key escrow.
- Transactional initial group bootstrap and future-epoch device admission.
  Existing devices receive durable targeted Commits, new devices receive an
  MLS Welcome, and the new device receives only future MLS epoch keys.
- Per-account Windows Credential Manager slots and SQLCipher cache directories
  prevent one signed-in account from opening another account's session, MLS
  state, cache key, history key, or local messages. Signed-out startup uses an
  in-memory store.
- Clean-install private-DM recovery with a random account history key wrapped
  separately by the password and eight one-time recovery codes. The backend
  keeps opaque key wrappers and recipient-scoped XChaCha20-Poly1305 archives;
  reinstalling the app or Windows restores synced account data and archived DM
  display history without restoring or escrow-ing old MLS epoch keys.
- Two-phase recovery-code rotation preserves the older set until all new
  wrappers are validated and activated atomically. Password changes commit the
  new password hash and replacement history-key wrapper in one transaction,
  and password recovery refuses to destroy history when a legacy code lacks a
  usable wrapper.
- Two-step device revocation with account-wide session eviction for the
  selected installation, gateway cutoff, KeyPackage invalidation, voice
  eviction, durable re-login denial for that installation ID, explicit current
  MLS membership, RFC 9420 Remove Commits, and durable reconnect-time removal
  discovery. Removed devices cannot derive the next epoch.
- AES-256-GCM encrypted attachment uploads for encrypted channels. Keys,
  original metadata, and plaintext hashes remain inside the authenticated MLS
  envelope; recipients verify ciphertext and plaintext hashes.
- MLS-exported voice frame keys wired into LiveKit's external E2EE provider and
  worker, with fail-closed production joins.
- One-message abuse reports backed by device-key-sealed franking openings,
  server-authenticated tags, and rejection of altered evidence.
- A separate least-privilege operator report queue with constant-time
  high-entropy bearer authentication, status filters, bounded responses,
  no-store headers, rate limits, and one-way action/dismiss resolution.
  Accepted encrypted evidence is sanitized before persistence: the selected
  verified plaintext and attachment hashes remain, while the franking opening
  secret is discarded. The Windows triage command retrieves its credential
  through pinned SSH for each operation and never accepts, prints, or persists
  it locally.
- Durable operator account suspension/reinstatement with an append-only
  enforcement audit. Suspension revokes every session, blocks password,
  recovery, refresh, email, and Apple session issuance, cuts off the gateway,
  and evicts every active voice room. Reinstatement never revives an old
  session. The pinned-SSH Windows triage command can inspect and apply the
  boundary without exposing the operator token.
- Durable per-account read state with message/channel validation, monotonic
  acknowledgements, SQLite persistence, native unread badges, and private
  account-only gateway updates.
- Connection-derived presence scoped to friends/shared servers plus
  permission-checked eight-second typing leases. Both are memory-only,
  reconnect-aware, and removed locally on expiry/disconnect.
- A dedicated Messages UI and full Friends panel for request, accept, decline,
  cancel, message, remove, block, and unblock, with exact-handle entry and
  honest transport-versus-E2EE labels.
- Global fail-closed push to talk (hold Space outside text fields), alongside
  WebRTC echo cancellation, automatic gain, browser noise suppression, and
  LiveKit active-speaker/VAD behavior.
- Hourly orphan cleanup removes expired unlinked uploads while preserving
  deduplicated objects that still have a live reservation or message. Postgres
  advisory locks close the reservation-versus-delete race across instances.
- Permission-scoped PostgreSQL plaintext search plus native SQLite FTS5 search
  for locally available encrypted messages and DMs. Private DM queries never
  leave the device; server search retains explicit excluded-channel reporting
  and bounded around-message hydration when opening an older hit.
- Permanent 2026-epoch Snowflake generator with string-safe JSON encoding and
  a monotonic logical clock that absorbs wall-clock regressions and sequence
  pressure without duplicate IDs or process panics.
- Permanent sparse `u64` permission allocation and ordered resolver, including
  everyone/role/member overwrites, timeout stripping, and implied permissions.
- Eight-byte little-endian gateway header, optional 16-byte plaintext routing
  extension, MessagePack payloads, and stateless per-frame zstd.
- Dual repository monolith: a fast seeded in-memory backend for UI development
  and a SQLx/Postgres 17 backend for durable production data.
- Startup migration runner and readiness probe. Production requires
  `EXOCORD_DATABASE_URL` and never falls back to process memory.
- Transactional server creation writes the owner membership, permanent
  `@everyone` role, and default text/voice channels as one commit.
- Membership-scoped server/channel/sync/message reads, owner-gated channel
  creation, default-role message permissions, timeout enforcement, and
  membership-filtered WebSocket fan-out.
- Owner-created, SHA-256-at-rest server invites with bounded expiry/use limits,
  public privacy-minimal previews, transactional and idempotent acceptance,
  shared-server profile hydration, and membership-scoped member lists.
- Durable role CRUD and member assignment with same-server foreign keys,
  hierarchy enforcement, permission-subset anti-escalation, managed/default
  role protections, and transactional audit entries.
- Effective assigned-role permissions now gate invites, member visibility,
  channel creation/listing, history, and sending. Permission changes publish a
  guild refresh and are persisted in the desktop SQLite cache for capability-
  accurate controls.
- Native role editor with grouped capabilities, role colors, member assignment,
  explicit save, and two-step deletion.
- Durable channel lifecycle and role/member overwrites now gate sync,
  visibility, history, and sends through one resolver. PostgreSQL validates
  same-server targets and cleans polymorphic targets after role/member removal.
- Hierarchy-safe timeouts, kicks, permanent/temporary bans, ban listing,
  unbanning, invite re-entry blocking, and transactional moderation audits.
- Native channel/access and moderation editors with tri-state overrides,
  timeout state, optional reasons, two-step destructive actions, and active
  ban management.
- Durable server automod rules with compiled keyword, bounded-regex, invite,
  mention, repeat, new-account-link, and Zalgo triggers. Flag, block, timeout,
  kick, and temporary-ban actions are enforced before message storage, with
  server-owner protection and transactional system audit entries.
- Native Safety & moderation rule editor and permission-scoped audit timeline,
  including enable/pause, validated thresholds and explanations, two-step
  deletion, and cache invalidation after every mutation.
- Adaptive, IP-bound, five-minute, single-use SHA-256 proof-of-work for
  production email and Apple login starts. The native Rust client solves it
  transparently outside the async runtime.
- GCRA rate limiting for the global REST surface, auth, messages, typing,
  server/channel/role/invite creation, and attachments, with exact bursts,
  stable buckets, standard headers, and structured HTTP 429 responses.
- Bearer-only, versioned machine-readable account export covering profile,
  identity/session metadata, servers, relationships, DMs, authored messages,
  attachments, read state, devices, and reports while excluding every usable
  credential. The native client saves unique flushed JSON files in Downloads.
- Idempotent 30-day account deletion scheduling with immediate all-session
  revocation, gateway cutoff, voice eviction, exact native confirmation,
  reauthentication-only cancellation, a restricted grace-period UI, and an
  hourly retry-safe anonymization worker. Finalization destroys auth/provider
  secrets, relationships, read state, device/MLS access, and profile PII while
  preserving shared messages under a Deleted User tombstone.
- Owner-only server transfer and exact-name server retirement are atomic in
  both repositories, emit targeted topology updates, reset active voice rooms,
  revoke invites, and write durable audit actions. Multi-member ownership is a
  hard account-deletion blocker; sole-member servers freeze during grace and
  retire at final anonymization. Reauthenticated grace-period accounts are
  server-restricted to export, status, cancellation, and logout.
- Native Ownership & deletion controls list eligible current members, require
  the exact server name for transfer and retirement, remove authority after a
  successful handoff, and connect account-deletion blockers directly to the
  responsible server.
- Durable same-channel replies, author-only inline edits, author-or-moderator
  server deletion, author-only DM deletion, and idempotent Unicode reactions.
  Plaintext edits are rechecked by automod; MLS edits produce fresh ciphertext
  and franking state without changing encryption mode. Message/reaction
  lifecycle events are audience-filtered through the binary gateway.
- Native hover/focus actions, reply composer context, inline Enter/Escape
  editing, visible edited state, aggregate reaction pills with per-account
  toggles, and exact two-step deletion. The SQLCipher cache persists reply and
  reaction state, merges edits, removes deletes, and carries reply targets
  through restart-safe outbox delivery.
- Message deletion removes reaction state, recomputes the channel tail, and
  detaches linked uploads for seven-day grace-period cleanup while preserving
  any deduplicated object still referenced elsewhere.
- Partition-compatible message nonce coordination with concurrent retry
  idempotency, cursor windows, durable messages, and restart-safe sequence
  recovery.
- Production-shaped Postgres 17 schema with partition-ready messages, passkey
  and session tables, MLS opaque storage, audit logs, reports, and Snowflake IDs.
- Client-core view-model/delta types, a 100-row window invariant, local SQLite
  schema, outbox, FTS5, and explicit known-range/gap tracking.
- Versioned native IPC deltas with monotonically increasing revisions for live
  messages, presence, typing, read state, connection state, and successful
  outbox acknowledgements. The renderer rejects unknown versions or revision
  gaps, recovers through a full snapshot, batches valid bursts into one React
  update per animation frame, preserves untouched object identities, and
  retains only the newest 100 message rows per channel.
- The native desktop opens and migrates one SQLite store per account under the
  OS application-data directory, with WAL mode, bounded per-channel reads,
  stable client keys, persistent active context, and a restart-safe outbox.
- The complete SQLite cache, FTS index, outbox, and WAL are encrypted by
  SQLCipher. Each installation receives a random 256-bit cache key kept
  separately in the operating-system credential vault. Startup applies the key
  before schema access, validates the cipher and database integrity, exports a
  detected legacy plaintext cache through a verified same-directory atomic
  swap, recovers interrupted swaps, and fails closed without deleting data
  when the vault, key, or cache is unavailable.
- A native cache-recovery mode now boots only an in-memory renderer model and
  pauses synchronization, login restoration, and outbox work. It supports a
  no-write restart/retry, opening the cache folder, and an exact-phrase
  preserve-before-reset action. Reset moves the database, WAL/SHM/journal, and
  migration artifacts into a timestamped recovery set with a manifest before
  clearing the vault key; preservation and key-clear failures roll files back.
  Failures that a reset cannot repair deliberately omit the reset action.
- Optimistic message sends are inserted locally before the network request.
  REST acknowledgement replaces the temporary ID without replacing the React
  row key; retryable failures remain queued and permanent 4xx failures become
  visible failed rows.
- Typed REST synchronization hydrates only the current member’s servers,
  channels, and newest 100 messages per visible channel. The binary WebSocket
  gateway filters live server, channel, routed message, presence, typing, DM,
  and read-state events by current channel access or exact recipient set.
- Honest connection UI for offline, connecting, catching-up, queued, delivered,
  and failed states, plus a local-only device channel that works without the
  backend.
- Discord capability boundary and PKCE authorization URL builder that never
  represents normal OAuth as friend/DM/voice access.
- Local Postgres, NATS, Dragonfly, and LiveKit topology.
- Native icon assets derived from the same vector spark used by the UI.
- Email/password onboarding with normalized identities, uniquely salted
  Argon2id hashes, generic credential errors, independent IP/account throttles,
  proof-of-work, and device-bound sessions. Legacy one-time email challenges
  remain development/recovery compatible but are not required for the alpha.
- Full password lifecycle: authenticated password changes revoke every other
  session; registration and recovery issue eight one-time high-entropy recovery
  codes; only domain-separated hashes are stored; successful recovery revokes
  every old session and rotates the entire set; signed-in replacement requires
  the current password. The Windows UI includes one-time code presentation,
  recovery, password change, and code replacement.
- Durable SQLite WAL auth storage, opaque 15-minute access tokens, rotating
  30-day refresh tokens, session logout, and refresh-reuse family revocation.
- Production startup fails closed when LiveKit, an explicit local-or-R2
  attachment mode, or PostgreSQL are missing instead of advertising a
  partially working alpha. Local production storage requires independent
  capability/object keys, an exact HTTPS origin, and a bounded quota.
- Complete credential-gated Sign in with Apple: ES256 client-secret signing,
  authorization-code exchange, Apple JWKS/RS256 identity verification,
  issuer/audience/expiry/verified-email/nonce checks, encrypted provider
  refresh tokens, and a one-time encrypted desktop polling handoff.
- Apple email linking is fail-closed: Apple may reuse an existing account only
  after that email has been verified. It never silently attaches to an
  unverified password account with the same address.
- Settings exposes the account's actual password and Apple methods. Explicit
  Apple linking requires the current password, binds the browser handoff to
  the same active session, preserves the Exocord email and display name, and
  rejects an Apple subject linked elsewhere. Disconnecting also requires the
  current password and is refused when Apple is the account's only durable
  login.
- Native session persistence in the operating-system credential vault with
  startup refresh rotation, automatic access-token refresh, and local
  credential removal even when server logout cannot be reached.
- A second production-shaped Postgres migration for email challenges,
  external identities, refresh-token reuse history, Apple login flows, and
  account-wide token versions.
- A third migration for durable gateway message sequences, plus an
  unpartitioned nonce-coordination table required for global idempotency across
  monthly message partitions.
- A fourth migration for capability-style server invites. Only code hashes are
  stored; accepting an invite locks its row so concurrent joins cannot exceed
  its use limit.
- A fifth migration adds composite role/server integrity for member
  assignments. The desktop's third local migration persists each signed-in
  member's effective server permissions.
- A sixth migration validates channel-overwrite targets and removes stale
  role/member overwrite rows after their target is deleted.
- A seventh migration persists attachment reservations and verification
  metadata, adds orphan/message indexes, and installs the partial GIN index
  used by permission-scoped plaintext message search.
- An eighth migration adds directed relationship state, canonical DM pairs,
  exact channel recipients, activity indexes, and normalized unique visible
  handles. The desktop's fourth local migration persists relationships, DM
  metadata, and read state.
- A ninth migration persists validated automod rules with server-scoped lookup
  indexes; the existing audit table stores rule mutations and enforcement.
- A tenth migration binds registered device identities, one-time KeyPackages,
  MLS delivery, ciphertext/franking fields, and attachment ownership. An
  eleventh migration makes membership-update Commits durable per target
  device. A twelfth migration adds explicit current MLS membership and removal
  epochs. A thirteenth migration adds the owner-deletion preparation marker and
  its active-owner index. A fourteenth migration gives Unicode reactions—and
  the future custom-emoji shape—one stable nullable-safe key and indexes reply
  references. A fifteenth migration adds the indexed operator report lifecycle
  and sanitized evidence column. The desktop's fifth migration stores sealed
  report openings; its sixth persists reply targets.
- A sixteenth server migration stores one bounded verified avatar per account;
  immutable content-hash URLs allow long-lived caching without stale profile
  pictures.
- A seventeenth server migration stores recipient-scoped encrypted
  private-history archives with paginated account-only reads and exact DM
  participant authorization. Account-key wrappers remain in the durable auth
  store and are never written to PostgreSQL as plaintext.

Validation completed on Windows:

- frontend type-check;
- 31 frontend unit tests, including stable-key acknowledgement, gateway-echo
  deduplication, immutable hot-path updates, and a 10,000-message delta burst
  that remains bounded to 100 renderer rows, plus the exact reset-confirmation
  boundary;
- optimized Vite production build;
- published 0.1.13 x64 NSIS installer (6,881,921 bytes, SHA-256
  `fce833f2fc69ce612e38d1b05ae9222742f40bbdc97550a96b4fb395b441bbaf`) at
  `https://api-193-122-221-77.sslip.io/downloads/Exocord-0.1.13-alpha-x64-setup.exe`;
  the public `downloads/latest.json` manifest reports version `0.1.13`. The
  installer is unsigned (`NotSigned`), and 0.1.9 clients require a manual
  update;
- live `?refractiveGlass=proof` verification rendered `WEBGL2 · 2 PLANES`;
- installed-build checks covered signed-in session restore, singleton launch,
  close/reopen restore, and no desktop shortcut while retaining the Start Menu
  shortcut. System, Refractive, and Solid appearance modes changed live and
  persisted;
- native and browser visual checks of the rebuilt v14 shell, including its exact
  top-bar geometry, centered message/composer width, populated hour group, local
  font rendering, no-call layout, legacy-cache author fallback, the DM inbox
  home, the two-pane profile/settings editor, and the compact sign-up flow;
- browser visual and interaction checks, including server creation/join tabs,
  invite-link normalization, preview-before-join, server switching, owner
  invite generation, clipboard copy, channel creation/rename/two-step deletion,
  persisted tri-state access rules, timeouts, two-step bans, and unbanning with
  no console warnings, plus voice join/leave, mute/deafen restoration, device
  selection, screen-share stage, and clean media teardown;
- browser checks for Messages navigation, DM unread clearing, request
  acceptance without context jumps, the complete Friends panel, and compact
  1024×700 layout with no overflow or console warnings;
- browser checks for the Safety & moderation panel, rule creation and editing,
  the rule/audit tab flow, and clean modal spacing with no console warnings;
- browser visual/layout checks for the real SQLCipher/vault status in Privacy &
  interface at 1280×720, with viewport-bounded document dimensions and
  panel-local scrolling;
- browser visual/interaction checks for recoverable and non-resettable cache
  failures at 1280×720: no viewport overflow, normal controls remain blocked,
  the destructive action stays disabled for the wrong phrase, and failures
  that require a valid encrypted build expose no reset action;
- browser visual/interaction checks for account export and erasure at
  1280×720: export-first action hierarchy, exact-phrase gating, modal-local
  scrolling, immediate signed-out recovery notice, and the restricted
  grace-period screen;
- browser visual/interaction checks for owner-only transfer, exact
  case-sensitive transfer/deletion guards, post-transfer authority removal,
  server retirement with fallback navigation, account ownership blockers, and
  direct blocker-to-server resolution at 1280×720;
- browser visual/interaction checks for inline edit, reply composition and
  preview, reaction add/remove, two-step message deletion, and clean 1280×720
  layout with no interaction alerts;
- browser visual/interaction checks for first-run alpha setup at 1280×720:
  focused no-scroll layout, compatible HTTPS probe feedback, and rejection of
  insecure remote HTTP before persistence;
- a real LiveKit 1.9.7 two-client run with 9/9 checks covering email login,
  invite membership, exact-room grants, peer discovery, synthetic microphone
  and screen-share subscription, forced timeout eviction, and denied reminting;
- a public browser WebRTC connection to the Oracle LiveKit deployment over
  TLS, including the `connecting` to `connected` transition and an assigned
  participant SID;
- a deterministic LiveKit control-plane test covering logout-driven eviction
  from every joined server room;
- all 148 routine Rust unit, persistence, API, security, repository, and
  end-to-end gateway tests,
  including attachment validation/cleanup, plaintext/encrypted search,
  relationship/DM/block/read-state privacy, exact-audience presence/typing
  delivery, hidden-channel gateway filtering, mock-Apple signature/audience/
  nonce rejection, proof-of-work binding/reuse, exact GCRA bursts, automod
  enforcement/auditing, real two/three-device OpenMLS exchange, MLS state
  restart, device admission, device-session eviction, durable pending removal,
  removal-epoch forward secrecy, attachment/franking tamper rejection, and a
  real encrypted-report operator listing/resolution boundary that rejects
  ordinary sessions and never returns the submitted opening secret, plus
  durable account suspension/reinstatement, all-session revocation, blocked
  session rotation, voice/gateway cutoff, and enforcement-audit persistence,
  plus
  encrypted-cache header/content/WAL secrecy, wrong-key and unkeyed rejection,
  encrypted FTS/outbox reopen, plaintext export, interrupted-swap recovery, and
  Windows Credential Manager session/cache-key round trips, plus exact native
  reset confirmation and lossless cache/sidecar preservation with rollback;
- an ignored-on-routine-runs lifecycle test that downloaded and started a real
  PostgreSQL 17 process, applied every migration, exercised transactional
  server creation, membership isolation, invite preview, idempotent acceptance,
  role CRUD/assignment/removal, channel overwrite integrity and cleanup,
  timeout/ban persistence, invite re-entry blocking, anti-escalation, audit
  records, member/profile visibility, nonce retry, attachment
  reserve/verification/linking, relationship acceptance, canonical DM open,
  private encrypted message/read state, durable MLS Welcome/Commit delivery,
  new-device epoch advancement, explicit membership, durable pending device
  removal, removal-epoch advancement, block enforcement, automod rule CRUD,
  enforcement/audit persistence, and migration state, then reopened the pool
  and verified durable server/DM/rule state, ownership transfer, exact-name
  server retirement, ownership audits, sole-owner invite freeze, and
  account-erasure server retirement, sanitized report persistence,
  operator listing, atomic resolution, conflict-on-rewrite, and durable
  resolved state after restart;
- the Tauri targets;
- strict Clippy with warnings denied for the full workspace;
- native Windows Tauri executable with vendored SQLCipher/OpenSSL (20.06 MiB,
  SHA-256
  `31F351741BB972B4ACE3D619F063AD64B4F1970D0F15BAF5CBB9ECE79A518E98`)
  and the required x64 `WebView2Loader.dll` (156.56 KiB, SHA-256
  `8427B1FC58EC707813E5C0A51EB5D69397BB333250A7B891BE4D3B123F1E0F1C`);
- Earlier alpha packaging checks: unsigned NSIS alpha installer (6.45 MiB, SHA-256
  `E445C64A4EA0653F1AC563A590AE199079D1D122AD98B9F46D510AA7FAAB9319`)
  and three-file portable zip (8.88 MiB, SHA-256
  `AECB808D4914C1C00A13EF0932214C8AEC44C1D0B68B76048786E3C0D51F95F2`).
  The installer and ZIP both place the architecture-matched WebView2 loader
  beside the executable; the ZIP also includes its launch guide. Real native
  launches of both payloads reached the `Exocord` window. A silent replacement
  cycle also verified current-user registration, version, matching loader
  bytes, and preservation of the pre-existing encrypted application profile;
- optimized monolith release build (17.69 MiB, SHA-256
  `7E6C44889078DE772391F3BFB01308B5C96EAADD9AB22D9EEB53B93DEC4547B8`),
  successful health/readiness/capability, proof-of-work, native-launch, and
  voice-grant smoke tests, a real reserve/upload/verify/attach/serve/search
  HTTP run, a release reply/edit/reaction/delete HTTP round trip, and verified
  production refusal when email, voice, attachment storage, the message
  franking key, or a complete database configuration is absent, when Apple is
  partially configured, when operator/privacy/abuse metadata is absent, and
  when the report-operator token is absent or malformed, and when direct/file
  secret sources conflict. The release smoke also verifies escaped,
  CSP-hardened privacy/terms pages, public operator metadata, and the
  report-only credential boundary. It also suspends a fresh account, verifies
  old-session revocation and blocked re-login, inspects the audit record,
  reinstates the account, and proves that only a newly authenticated session
  works;
- production deployment validation against Docker Compose 5.1.4, Caddy 2.11.4,
  ShellCheck 0.11.0, and Hadolint 2.14.0, covering an internal database
  network, file-mounted secrets, exact Windows-origin CORS, privacy-filtered
  access logs, immutable API tags, readiness-gated rollback, daily verified
  backups, isolated PostgreSQL/SQLite restore drills, and file-mounted
  report-operator credentials;
- deterministic 0.1.5 Oracle API source bundle (192 entries, 1,261,300 bytes,
  SHA-256
  `0BF911F7F4BCB63DF3819CD72F01EE342F88DF8BA2720E02DBDA1F1AAA05AA7B`);
- production deployment of that exact bundle on the Oracle Docker host as
  `exocord-api:bundle-0bf911f7f4bc`, with PostgreSQL 17 migrations 1–17
  applied, public HTTPS readiness and alpha preflight passing, and
  readiness-gated rollback preserved;
- verified post-upgrade PostgreSQL/application-state backup
  `exocord-20260730T104722Z`, copied into an NTFS EFS-encrypted Windows
  directory with matching SHA-256 values. The daily 03:30 off-host task was
  run through Task Scheduler and completed with result `0`.

Docker was not installed on the local Windows verification machine. PostgreSQL
was tested there as a real child process using the same major version as
`compose.yaml`; the exact release bundle was then built and run as a tagged
Docker image on Oracle. LiveKit was tested locally with its checksum-verified
official Windows server binary and through the public Oracle WebRTC endpoint.
NATS and Dragonfly remain unstarted in this pass.

## Deliberately not represented as complete

- NATS multi-instance fan-out, Dragonfly GCRA/résumé state, and a Meilisearch
  mirror for search volume beyond the current PostgreSQL GIN path.
- Thumbnail generation, malware scanning, GIF-to-WebM conversion, video
  transcoding, and a credentialed production R2 integration run. R2 SigV4
  construction is unit-tested; quota-bounded local object storage is the
  production alpha default and is end-to-end tested.
- Passkey registration/login, MFA, and a future migration from database-backed
  opaque access tokens to the specified PASETO v4.local format.
- Daily Apple refresh-token validation and Apple server-to-server
  account-change notifications.
- A proprietary Discord Social SDK adapter or Discord production approval.
  Standard OAuth account linking is modeled; friends/DMs/lobby voice remain
  gated by the capability matrix.
- An external cryptographic audit of MLS, key wrapping, history recovery,
  attachment encryption, and voice frame encryption.
- RNNoise and a production-tested forced TURN-relay path.
- Mobile bindings, content-free APNs/FCM, and CallKit/ConnectionService.
- Staffed legal-response, appeals, emergency, and CSAM handling workflows.
- OpenTofu/Ansible multi-host reprovisioning, a rehearsed replacement-host
  restore from the off-host copy, and staffed on-call.

## Honest prototype boundary

The desktop bridge uses `exo-client` SQLite and the real REST/WebSocket data
path. Auth identities and session families survive backend restarts. Chat state
and attachment metadata also survive when PostgreSQL is configured; the seeded
in-memory repository is development-only and production refuses to start
without PostgreSQL.
Authentication storage is still a single-node SQLite WAL database, so the
current production path is durable but not yet horizontally scalable.
GCRA counters, proof-of-work challenges, and repeated-content windows are also
single-instance, in-process state; move them to Dragonfly before horizontal
scale. See [abuse controls](abuse-controls.md).
Hot renderer updates use typed revisioned deltas; server, permission, and
relationship topology mutations deliberately retain full snapshots because
they are infrequent and touch several dependent collections. Unknown delta
versions, missing revisions, and failed delta delivery recover through the same
bounded snapshot path. OpenMLS, verification UI, encrypted attachments, voice
frame encryption, and franked single-message reports are connected, but they
are not independently audited.
The SQLCipher cache protects closed local database files, indexes, and WAL from
casual disk inspection. It does not protect plaintext in process memory while
the app is running, and best-effort legacy-file overwrite cannot guarantee
removal from SSD remapping, filesystem snapshots, or journal history. Full-disk
encryption remains recommended; see
[local cache encryption](local-cache-encryption.md).
An independent audit of encrypted history recovery and the wider cryptographic
boundary remains an explicit public-launch gate; see the
[end-to-end encryption boundary](end-to-end-encryption.md).
