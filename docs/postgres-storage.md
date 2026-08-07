# PostgreSQL storage

Exocord has two server repositories:

- a seeded in-memory repository for UI development and fast unit tests;
- PostgreSQL 17 for durable or production operation.

Production never falls back to memory. `EXOCORD_ENV=production` without either
`EXOCORD_DATABASE_URL` (or `_FILE`) or the complete host/port/user/name/
password component form exits before binding the HTTP listener. Direct and
file-based values for the same secret are mutually exclusive.

## Local start

```powershell
docker compose up -d postgres
$env:EXOCORD_DATABASE_URL="postgres://exocord:exocord@127.0.0.1:5432/exocord"
$env:EXOCORD_DATABASE_MAX_CONNECTIONS="20"
cargo run --package exo-monolith
```

`GET /ready` runs a live `SELECT 1` and reports the active storage backend.
Migrations embedded into the server binary run before readiness or traffic.

## Transaction and privacy invariants

- Server creation inserts the server, owner membership, permanent `@everyone`
  role, and default text/voice channels in one transaction.
- Server lists are selected through `guild_members`.
- Channel and message reads require both membership and the relevant default
  role permissions. Non-members receive the same not-found response as an
  unknown resource to avoid enumeration.
- Channel creation requires `MANAGE_CHANNELS`; the server owner has the
  explicit bypass.
- Role-aware permission checks authorize channel creation, invites, member
  lists, channel/history visibility, and sending. The owner bypass remains
  explicit; other members are resolved through `@everyone`, assigned roles,
  administrator expansion, and timeout stripping.
- Member-role rows carry a composite same-server foreign key. Role hierarchy,
  permission-subset checks, and assignment changes are evaluated while the
  server row is locked.
- Role creation, updates, deletion, assignment, and removal append an
  `audit_log` entry in the same transaction. Idempotent assignment retries do
  not duplicate audit entries.
- Timed-out members cannot send.
- Invite plaintext is returned once and never written to PostgreSQL. Lookup
  uses a SHA-256 code hash.
- Invite acceptance locks the invite row, enforces expiry and use limits, and
  inserts membership in the same transaction. Reaccepting as an existing
  member is idempotent and does not consume another use.
- Public invite previews expose only the server identity, member count, expiry,
  and use-limit state. Member lists and shared member profiles require
  membership.
- Message retries reserve `(channel_id, author_id, nonce)` in an
  unpartitioned coordination table. This preserves uniqueness across all
  monthly message partitions; a retry returns the original row.
- WebSocket events carry a server-side audience key and are sent only to
  connections with that server membership.

## Real database test

Routine workspace tests skip the database download. Run the lifecycle test
when migrations or repositories change:

```powershell
cargo test -p exo-monolith --test postgres_repository -- --ignored --nocapture
```

The test starts a disposable PostgreSQL 17 process, migrates a blank database,
exercises transactions, membership isolation, invite concurrency invariants,
role hierarchy and removal, transactional audits, member visibility, and retry
idempotency, reconnects a fresh pool, and verifies durability. PostgreSQL
binaries are cached outside the repository after the first run.

## Current scaling boundary

PostgreSQL is now the source of truth for core chat state. Gateway fan-out is
still process-local, and authentication sessions remain in a SQLite WAL file.
Before running multiple API instances, move fan-out/resume state to NATS and
Dragonfly and move the authentication repository behind the same durable
database boundary.
