# Roles and permissions

Exocord roles are enforced by the backend. The desktop editor is a view over
the same repository methods used by REST clients; hiding a control in React is
never treated as authorization.

## Wire contract

Permission allocation remains the permanent sparse `u64` layout in
`exo-domain`. JSON represents every permission bitfield as a decimal string.
This avoids precision loss in JavaScript while preserving the fixed allocation
for native clients.

The role surface is:

- `GET/POST /v1/guilds/{guild_id}/roles`;
- `PATCH/DELETE /v1/guilds/{guild_id}/roles/{role_id}`;
- `PUT/DELETE
  /v1/guilds/{guild_id}/members/{member_id}/roles/{role_id}`.

The bounded sync response includes the signed-in member's effective
permissions for each visible server. The native client stores those bits in
SQLite and converts them to named capabilities before exposing them to React.
`GUILD_UPDATE` causes connected clients to resynchronize after a role or
assignment mutation.

## Resolution

Resolution is deterministic:

1. The server owner receives every allocated permission.
2. `@everyone` permissions are applied.
3. Assigned role permissions are combined.
4. `ADMINISTRATOR` expands to all guild permissions except the separately
   gated E2EE administration bits and bypasses channel overwrites.
5. Channel `@everyone`, combined role, and member overwrites are applied in
   that order for non-administrators.
6. Timeouts reduce access to channel visibility and history, including for an
   administrator.

Channel listing, history, sending, channel creation, invite creation, and
member-list access all use this effective result. A missing permission is
returned as not-found for channel reads to avoid resource enumeration.

## Hierarchy invariants

- `@everyone` has the same ID as its server, is implicit for every member, and
  cannot be assigned or deleted.
- Managed integration roles cannot be edited, assigned, or deleted manually.
- A non-owner needs `MANAGE_ROLES` and can change only roles below their
  highest assigned role.
- A non-owner cannot grant permissions they do not effectively possess.
- A non-owner cannot change themselves, the owner, or a member whose highest
  role is equal to or above their own.
- Member-role rows have a composite foreign key to a role in the same server,
  preventing cross-server assignment even if an application bug supplies
  mismatched IDs.

Creation, update, deletion, assignment, and removal run in transactions.
Successful production mutations also insert an `audit_log` entry in that same
transaction. Idempotent repeated assignments do not create duplicate audit
events.

## Desktop behavior

The server control surface exposes:

- role creation and color;
- grouped community, conversation, voice, security, and automation
  permissions;
- member assignment;
- explicit saving;
- two-step role deletion.

The editor preserves permission keys that are not currently presented as a
toggle, so a newer server capability is not silently stripped by an older
desktop client.

Channel-specific rules and moderation hierarchy are documented separately in
[channels, access, and moderation](channels-moderation.md).

## Verified failure cases

Automated tests cover:

- lossy-number-safe JSON round trips;
- a delegated role authorizing channel and invite creation;
- rejection of an attempted administrator escalation;
- access disappearing immediately after assignment removal;
- role and assignment persistence after reconnecting a new PostgreSQL pool;
- cascading assignment removal after role deletion;
- transactional audit counts;
- create/edit/assign/two-step-delete behavior in the rendered editor.
