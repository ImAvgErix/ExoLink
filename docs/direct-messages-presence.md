# Relationships, direct messages, presence, and typing

This phase adds a native social graph and one-to-one conversations. It does not
depend on Discord approval and it does not imply access to a person's Discord
friends or DMs.

## Relationship contract

Accounts are addressed by their exact, case-insensitive visible handle. There
is no public directory, prefix search, suggestion endpoint, or contact upload.
The four directed states are:

| State | Meaning |
|---|---|
| `outgoing` | The current user sent a request. |
| `incoming` | The other account sent a request. |
| `friend` | Both directed rows agree that the relationship is accepted. |
| `blocked` | The current user blocked the other account. |

Sending a request writes both the outgoing and incoming rows in one
transaction. Accepting locks the pair and promotes both rows to `friend`.
Crossed requests auto-accept. Pair-scoped PostgreSQL advisory locks prevent two
concurrent requests or DM opens from creating inconsistent state.

Blocking is intentionally asymmetric and private. The blocker sees a
`blocked` row; the other account's reciprocal row is removed, so the API does
not announce who blocked them. Decline, cancel, unfriend, and unblock use the
same relationship deletion endpoint but preserve a target's independent block.

## Direct-message contract

`POST /v1/users/@me/channels` opens a canonical channel for one accepted friend.
The ordered user pair has one unique `dm_pairs` row, so retries and simultaneous
opens return the same channel. A DM has:

- `guild_id = NULL` and channel type `1`;
- exactly two rows in `channel_recipients`;
- no server roles or permission overwrites;
- a stable Snowflake channel ID;
- bounded newest-100 message hydration through the normal sync path.

Both participants may read retained history after an unfriend or block. New
sends, typing events, and new DM creation require a current mutual friendship.
Unrelated users receive `404`, not a participant-disclosing error. Attachments,
nonce idempotency, bounded message windows, and the durable outbox use the same
code path as server text channels.

The UI exposes DMs as a dedicated Messages space, not a fake server. The
Friends panel supports exact-handle request, accept, decline, cancel, message,
remove, block, and unblock actions. Opening a friend is idempotent and switches
the durable native context to the canonical DM.

## Read state

`PUT /v1/channels/{channel_id}/read-state` accepts an actual message ID in that
channel. Updates are monotonic and participant/permission checked. The server
stores one row per user and channel; the desktop mirrors it in SQLite and
derives DM unread badges from `last_message_id > last_read_message_id`.

Only the account changing its read state receives the gateway refresh. This
phase does not expose read receipts to the other participant.

## Private history search

The Messages search button and Ctrl+K query SQLite FTS5 on the current device.
The FTS index, source message rows, and WAL are inside the SQLCipher-encrypted
cache, whose separate random key is held by the operating-system credential
vault. DM query terms are never sent to the backend, and results are explicitly
labelled `this device`. Search covers the bounded history already synchronized
into the local cache; opening a hit switches to its conversation without
performing a remote around-message lookup.

The server search endpoint never receives DM query terms or DM plaintext.
Messages decrypted on this device are indexed in the local SQLite FTS table.

## Presence and typing

Presence is ephemeral process state derived from active gateway connections.
The first connection publishes `online`; the last disconnect publishes
`offline`. An account receives presence only for friends and people sharing a
server. Sync includes currently online visible accounts so reconnect does not
wait for another transition. No last-seen timestamp is stored.

Typing uses `POST /v1/channels/{channel_id}/typing` and an eight-second gateway
lease. The same send permission/friendship check used by messages gates the
event. The desktop throttles requests to one per four seconds and the backend
coalesces repeated leases inside three seconds. Indicators stay only in memory
and are removed on expiry or disconnect.

Routed gateway events are checked against current channel visibility at
delivery time. Server membership alone is not enough to receive a hidden
channel's messages or typing events. DMs additionally carry an exact recipient
set, and tests keep a third gateway connected to prove it receives nothing.

## Renderer synchronization

The native core sends versioned, monotonically revisioned deltas for live
messages, presence, typing, read-state, connection-state, and successful outbox
acknowledgements. The React renderer coalesces valid bursts into one update per
animation frame and changes only the affected collection. Message upserts match
the stable client key or final server ID, so a REST acknowledgement and its
later gateway echo cannot create duplicate rows.

Every channel remains hard-bounded to its newest 100 rendered messages. An
unknown delta version, a missing revision, or a delta received before bootstrap
triggers a fresh bounded snapshot instead of applying potentially inconsistent
state. Infrequent server, permission, and relationship topology changes also
use a full snapshot because they affect several dependent collections.

## Voice input mode

Voice retains WebRTC echo cancellation, automatic gain control, browser-native
noise suppression, and LiveKit's active-speaker/VAD behavior. Users can enable
global push to talk in Privacy & interface and hold Space outside a text field
to transmit. Enabling the mode mutes immediately; key release, window blur,
unmount, and deafen all fail closed.

RNNoise is not represented as implemented. A dedicated audio worklet/processor
and performance validation on low-end hardware are still required before
making that claim.

## Encryption boundary

Native DMs set `DirectChannel.encrypted = true`. The desktop creates a durable
per-device Ed25519 identity, publishes one-time MLS KeyPackages, and establishes
an OpenMLS 1.0 group using suite 1 (X25519, AES-128-GCM, SHA-256, Ed25519).
The server stores and fans out opaque MLS ciphertext, group commits, Welcomes,
and a message-franking commitment; it does not receive message plaintext.

An already trusted device admits a later device and advances the group epoch.
Existing devices receive a durable targeted Commit and the new device receives
a Welcome. The new device receives only future MLS epoch keys. Previously
decrypted DM display history is restored through a separate per-account archive
encrypted by the client; old MLS epoch keys are never copied to the new device.
The native settings panel exposes device fingerprints and accurately describes
that recovery boundary.

Registration generates a random account history key and wraps it separately
with the password and all eight one-time recovery codes. The server stores the
opaque wrappers and one XChaCha20-Poly1305 archive per user/message pair, never
the history key or archived plaintext. Archive access is authenticated to the
signed-in account and DM recipient, so the two DM participants do not share an
archive row. On a clean installation, the client restores normal server data,
unwraps its account key, pages through its own archive, and writes recovered
plaintext only into that account's SQLCipher cache.

Another active device can revoke a lost installation through a two-step
Settings action. All sessions for that installation are invalidated, its MLS
inbox and send rights are denied, and remaining group members advance each
affected conversation to a removal epoch. Pending removals are durable and are
rediscovered when an offline trusted member reconnects; the removed device
cannot decrypt ciphertext created in the new epoch.

Encrypted attachments use independent AES-256-GCM keys generated in the
renderer. Their keys, original names/types, sizes, and plaintext hashes are
authenticated inside the MLS message. Reports reveal one selected message
through a verified franking opening; they do not reveal the conversation.
See [end-to-end encryption](end-to-end-encryption.md) for the full boundary.

## Persistence and validation

Backend migration `0008_relationships_direct_messages.sql` adds directed
relationships, canonical DM pairs, recipients, activity indexes, and normalized
unique visible handles. Desktop migration `0004_relationships_direct_messages.sql`
adds relationship, DM metadata, and read-state cache tables. Backend migrations
`0010` and `0011` bind device identities and MLS delivery to channels and make
membership-update Commits durable per target device. Migration `0012` adds the
explicit current-membership ledger required to represent removal epochs and
offline rekey work. Desktop migration `0005` stores only device-key-sealed
franking openings. Backend migration `0017_private_history_recovery.sql` adds
recipient-scoped opaque history archives; the authentication store keeps
password- and recovery-code-wrapped account keys.

Coverage includes:

- the full relationship/DM/block/read-state HTTP lifecycle;
- password and recovery-code history-key restoration, safe two-phase recovery
  code rotation, paginated archive hydration, and wrong-account/wrong-key
  rejection;
- exact-recipient gateway delivery for messages, typing, read state, and
  presence, with an outsider timeout assertion;
- SQLite close/reopen with a DM, friend, message, read state, and local FTS
  lookup;
- real PostgreSQL 17 migration, pair idempotency, private history, read-state
  durability, restart, block enforcement, and retained-history behavior;
- browser interaction and visual checks at 1440×900 and 1024×700 with no
  console warnings or document overflow.
