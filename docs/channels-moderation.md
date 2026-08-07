# Channels, access, and moderation

Channel privacy and member moderation are enforced by the Rust repository and
PostgreSQL transactions. React only presents controls; it is not an
authorization boundary.

## Channel lifecycle

The channel surface is:

- `GET/POST /v1/guilds/{guild_id}/channels`;
- `PATCH/DELETE /v1/channels/{channel_id}`;
- `GET /v1/channels/{channel_id}/overwrites`;
- `PUT/DELETE
  /v1/channels/{channel_id}/overwrites/{role|member}/{target_id}`.

Creating, renaming, and deleting requires `MANAGE_CHANNELS`. A server must keep
at least one text channel. Production mutations lock the server and affected
channel, write an audit entry in the same transaction, and publish a gateway
event or server refresh. Deletion is soft in PostgreSQL so references remain
auditable; active overwrites are removed immediately.

## Effective channel permissions

Resolution is shared by snapshot hydration, channel lists, message history,
and sends:

1. Combine `@everyone` and assigned roles.
2. An administrator bypasses channel overrides. An active timeout still
   reduces the result to view/history.
3. Apply the channel's `@everyone` overwrite.
4. Combine all matching role denies, then role allows.
5. Apply the member-specific deny and allow.
6. Apply timeout stripping and implied-permission cleanup.

An owner bypasses every role and channel restriction. A hidden channel is
returned as not-found for history and send requests to resist ID probing.
Idempotent message retries recheck current access before returning the original
message.

Overwrite bitfields are decimal strings in JSON. Allow and deny cannot overlap,
and a non-owner cannot grant bits they do not possess. Targets are validated
in the repository and by PostgreSQL trigger: a role or member from another
server cannot be referenced. Deleting a role or membership also removes its
polymorphic channel targets.

## Moderation

The moderation surface is:

- `PATCH/DELETE /v1/guilds/{guild_id}/members/{member_id}` for timeout/clear
  and kick;
- `GET /v1/guilds/{guild_id}/bans`;
- `PUT/DELETE /v1/guilds/{guild_id}/bans/{member_id}` for ban and unban.

Timeouts are limited to 28 days. Temporary bans are limited to one year.
Reasons are optional and capped at 512 characters. Successful production
actions use audit action types 40–43 and store the reason in the dedicated
audit column.

Every action checks its specific permission and role hierarchy. A non-owner
cannot act on themselves, the owner, or a member whose highest role is equal
to or above their own. Kicks and bans remove the membership, assigned roles,
timeouts, and member channel overrides transactionally. Bans may be permanent
or expiring; an active ban blocks invite acceptance without consuming an
invite use. Unbanning does not silently restore membership.

The gateway rechecks membership for every server event, including connections
that previously belonged to that server. A kicked or banned client therefore
stops receiving server payloads immediately.

## Desktop behavior

The native server controls include:

- text and voice channel creation, rename, and two-step deletion;
- per-role or per-member tri-state access (`inherit`, `allow`, `deny`);
- active timeout visibility and one-click timeout clearing;
- optional moderation reasons and temporary/permanent ban duration;
- two-step remove and ban confirmation;
- active ban listing and unban.

The desktop bridge calls typed `exo-client` methods and resynchronizes the
SQLite cache after mutations. Browser preview mocks implement the same
interaction contract for deterministic rendered testing.

## Verified failure cases

Automated and rendered tests cover:

- channel hiding across sync, listing, history, and send;
- member allow overriding role deny;
- administrator bypass and timeout precedence;
- non-manager and cross-server overwrite rejection;
- final-text-channel deletion protection;
- hierarchy anti-escalation;
- timeout persistence and send suppression;
- ban persistence, invite re-entry blocking, and unban;
- trigger cleanup after role/member deletion;
- gateway membership revalidation;
- PostgreSQL restart persistence for permissions, timeouts, bans, audits, and
  message idempotency;
- channel create/delete, override persistence, timeout/clear, two-step ban, ban
  list, and unban in the rendered desktop UI.
