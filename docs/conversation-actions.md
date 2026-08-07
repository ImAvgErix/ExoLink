# Conversation actions

This phase makes replies, edits, message deletion, and Unicode reactions part
of Exocord's native data path. They are not renderer-only effects: every action
is permission checked, durable in PostgreSQL, synchronized through the binary
gateway, persisted in the SQLCipher cache, and exposed through revisioned
native deltas.

## User experience

- Reply opens a compact composer banner and stores a reference to an existing
  message in the same channel. Sent replies render an author/content preview.
  If the referenced row is no longer in the bounded local window, the UI says
  that the message is unavailable on this device instead of inventing content.
- A message author can edit inline. Enter saves, Escape cancels, and a
  successful edit receives an `edited` marker.
- An author can delete their own message. A member with `MANAGE_MESSAGES` can
  also delete another member's server message. Direct messages remain
  author-delete-only. The UI requires a second, explicit `delete?` action.
- Quick reactions currently expose thumbs-up, heart, and laughing emoji. The
  same reaction pill toggles the current account's reaction and shows the
  aggregate count.
- Actions are permission aware and available in the local device-only channel
  as well as remote server and DM conversations.

## API and gateway contract

| Action | HTTP contract | Gateway event |
|---|---|---|
| Create reply | `POST /v1/channels/{channel}/messages` with `reply_to` | `MESSAGE_CREATE` (`300`) |
| Edit | `PATCH /v1/channels/{channel}/messages/{message}` | `MESSAGE_UPDATE` (`301`) |
| Delete | `DELETE /v1/channels/{channel}/messages/{message}` | `MESSAGE_DELETE` (`302`) |
| Add reaction | `PUT /v1/channels/{channel}/messages/{message}/reactions` | `REACTION_ADD` (`400`) |
| Remove reaction | `DELETE /v1/channels/{channel}/messages/{message}/reactions` | `REACTION_REMOVE` (`401`) |

Reaction mutation bodies are `{ "emoji": "…" }`. The current implementation
accepts one bounded non-ASCII Unicode sequence: at most 64 UTF-8 bytes and 16
Unicode scalar values, with no whitespace or control characters. Custom server
emoji are deliberately not represented as complete yet.

Gateway delivery uses the same audience resolver as message creation. Server
events reach only members who can currently view the channel; direct-message
events reach only the exact recipient pair. Idempotent reaction retries return
the current count but do not publish duplicate events.

`GET /v1/meta/capabilities` advertises
`conversation_actions: replies_edits_deletes_unicode_reactions`.

## Correctness and authorization

- A reply target must exist, must not be deleted, and must belong to the same
  channel. Only its Snowflake ID is stored; no quoted plaintext is duplicated.
- Only the original author can edit. An edit cannot switch a message between
  plaintext and MLS-encrypted modes.
- Plaintext server edits pass through the active automod rules before storage.
- Adding a server reaction requires `ADD_REACTIONS`; removing one's own
  reaction remains possible without that grant. Adds and removes are
  idempotent.
- Message deletion removes its reactions and recomputes the channel's
  `last_message_id`. PostgreSQL soft-deletes the message so current moderation
  and legal-retention policy can be applied, but normal message windows,
  synchronization, and search do not return it.
- Attached uploads are detached when their message is deleted and become
  eligible for cleanup after seven days. The object is deleted only when no
  other live reservation or message references the same content-addressed
  object. The grace period is a storage-safety measure; there is no user-facing
  message-restore endpoint yet.

## Encrypted conversations

Replies intentionally expose only the referenced message ID as routing
metadata. The server does not receive a quoted reply body.

An edit to an MLS message creates fresh application ciphertext and a fresh
message-franking commitment/opening. The native client persists the advanced
OpenMLS state before publishing the visible update. The server enforces that
the sender device is current and that the encryption mode did not change.

Reactions are **not end-to-end encrypted**. The service sees the reacting
account, emoji, channel/message IDs, action, aggregate count, and timing even
when the message body is MLS encrypted. Edit and delete timing plus reply
relationships are also visible metadata. This is an explicit product/privacy
boundary, not an accidental promise of content secrecy.

## Persistence and renderer flow

PostgreSQL migration `0014_message_conversations.sql` repairs the original
nullable custom-emoji primary-key shape, adds one stable `emoji_key`, and adds
message/reply lookup indexes. Existing message reference columns store replies.

Desktop migration `0006_conversation_actions.sql` adds `reply_to_id`; reactions
remain compact MessagePack/JSON-shaped cache state alongside each message.
Edits update the cached row, deletes remove it, and reaction gateway events
merge counts while retaining the local account's `me` state. Pending replies
also keep their target through outbox retries and restarts.

The renderer receives bounded `message_upsert` or `message_delete` changes
through the existing versioned delta stream. It does not open a second socket
or maintain an independent conversation database.

## Deliberate next boundaries

- custom server emoji, an emoji picker, and recently used emoji;
- edit history and a user-facing restore flow;
- pins, threads, message links, forwarding, and bulk moderation deletion;
- a finalized public retention policy and report-triage access to soft-deleted
  plaintext;
- attachment-CDN cache invalidation guarantees for a production R2 deployment.
