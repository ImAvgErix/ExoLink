# Server ownership lifecycle

Every active Exocord server has exactly one active owner. Ownership is not an
ordinary permission: administrator roles cannot transfer ownership or delete
the server, and the owner cannot leave an operational server without first
resolving that responsibility.

## Invariants

- Only the current owner may transfer or delete a server.
- A transfer target must be a current, non-deleted member.
- The old owner remains a normal member after transfer.
- Transfer and deletion lock the server row in PostgreSQL, so two owners cannot
  win a race.
- Deleted servers are immediately inaccessible to every former member.
- A server whose owner has scheduled account deletion cannot create or accept
  invites.
- An account cannot schedule deletion while it owns a server with another
  member.
- A sole-member owned server is frozen during the account grace period and
  retired when account erasure completes.

The in-memory development repository implements the same state transitions and
permission failures as PostgreSQL.

## API

`PUT /v1/guilds/{guild_id}/owner`

```json
{
  "ownerId": "123456789012345678"
}
```

The operation is owner-only, limited to five attempts per account per day, and
returns the updated server. It clears any owner-deletion preparation marker and
writes audit action `70` with the old and new owner IDs.

`DELETE /v1/guilds/{guild_id}`

```json
{
  "confirmation": "Exact Server Name"
}
```

The server name is case- and whitespace-sensitive. The operation is owner-only,
limited to five attempts per account per day, writes audit action `71`, revokes
all invite capabilities, retires all channels, and marks the server deleted in
one transaction.

Deletion is immediately permanent from the product surface: former members
cannot list, synchronize, search, message, join voice, or reuse an invite for
the server. Rows are soft-retained so retention, legal-hold, and backup policy
can be applied centrally instead of being bypassed by a user-facing cascade.
A future retention worker may physically purge eligible records after the
published retention period.

## Realtime and voice behavior

Ownership transfer publishes `GUILD_UPDATE` through the normal membership-
scoped gateway path.

Deletion captures the member audience before access is removed, then publishes
a targeted `GUILD_DELETE` without a guild routing scope. This matters because a
normal guild-scoped event would correctly fail the post-deletion membership
check and never reach former members. Native clients understand
`GUILD_DELETE`, resynchronize, and remove the server.

Every known voice room is reset after the transaction commits. Current
participants are disconnected and old room grants cannot be minted again
because channel and server access now fail closed.

## Account deletion coupling

`GET /v1/users/@me/deletion` includes every active owned server and its member
count. The native account panel lists multi-member blockers and opens the
corresponding ownership controls directly.

When `DELETE /v1/users/@me` is requested:

1. PostgreSQL locks every active server owned by the account.
2. If any has more than one member, the request returns HTTP 409 and changes
   neither the account nor server state.
3. Sole-member servers receive `owner_deletion_pending_at`; all invites are
   revoked before auth sessions are revoked.
4. During the 30-day grace period, normal REST, device, and gateway access
   returns HTTP 403. Export, deletion status, cancellation, and logout remain
   available.
5. Cancellation clears the pending markers. Previously revoked capability
   links stay revoked; the owner may create new invites.
6. At final erasure, sole-member servers and channels are retired, all owner
   memberships are removed, and audit action `72` records the system reason.

Finalization independently rechecks member counts under row locks. Even if an
unexpected caller bypassed preparation, the worker returns a conflict rather
than orphaning a multi-member server.

## Native controls

The server menu shows **Ownership & deletion** only to the synchronized owner
and never for a local-only preview server.

Transfer requires choosing a current member and typing the exact server name.
Deletion separately requires the exact server name and explains immediate
member removal, voice disconnection, and policy-governed retained records.
Successful actions synchronize the native cache before the dialog closes.

The account-deletion panel disables its final action while ownership blockers
exist. Selecting a blocker switches to that server and opens the same ownership
dialog, avoiding a dead-end settings error.

## Verification

Automated coverage proves:

- multi-member ownership blocks account deletion;
- transfer requires the current owner and a current member;
- the old owner is no longer authoritative after transfer;
- pending owner deletion freezes invite creation and acceptance;
- cancellation restores server use without restoring old invite capabilities;
- exact-name deletion removes access for all members and writes audit records;
- sole-owner account erasure retires its server without deleting shared message
  records;
- grace-period accounts cannot use normal APIs through a custom client;
- the PostgreSQL 17 lifecycle survives migrations and repository restart.

Renderer tests cover exact server-name confirmation. Browser interaction checks
cover transfer, post-transfer authority removal, deletion, fallback navigation,
account blocker presentation, and the blocker-to-server resolution path.
