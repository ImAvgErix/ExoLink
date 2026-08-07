# Abuse controls

This document describes the Phase 5 controls that are implemented in the
monolith and native desktop. They reduce routine abuse and now include a
least-privilege operator report queue; they do not replace a staffed response
process, legal response, CSAM handling, or an external security review.

## Server safety rules

Rules are durable PostgreSQL records and are compiled into a per-server matcher
cache. Updating, disabling, or deleting a rule invalidates that cache before
the next message evaluation.

Supported triggers:

- case-insensitive keyword sets compiled with Aho-Corasick;
- bounded, linear-time regular-expression sets;
- Discord invite links;
- mass mentions;
- repeated content within a configured window;
- links from accounts newer than a configured age;
- excessive Unicode combining marks (Zalgo).

Keyword and regular-expression rules accept at most 32 patterns, with each
pattern capped at 4,096 bytes. Regex compilation has explicit size limits.
Thresholds, durations, names, and author-facing explanations are validated in
the shared Rust safety crate before a rule is saved.

Supported actions, in enforcement order, are ban, kick, timeout, block, and
flag. Flag records the match and allows the message. The other actions reject
the matching message; timeout, kick, and ban also update membership state in
the same repository transaction. A destructive rule that matches the server
owner is safely reduced to block.

The native **Safety & moderation** panel exposes rule creation, editing,
enable/pause, two-step deletion, and the audit timeline. `MANAGE_GUILD` is
required to mutate rules. `VIEW_AUDIT_LOG` is required to read the timeline.

API surface:

```text
GET  /v1/guilds/{guild_id}/automod/rules
POST /v1/guilds/{guild_id}/automod/rules
PATCH /v1/guilds/{guild_id}/automod/rules/{rule_id}
DELETE /v1/guilds/{guild_id}/automod/rules/{rule_id}
GET  /v1/guilds/{guild_id}/audit-log?before={snowflake}&limit={1..100}
```

## Audit records

Audit target IDs are returned as decimal strings so JavaScript never rounds a
Snowflake. Automod rule mutations use action types 50–52. Message flag, block,
timeout, kick, and ban use 60–64. Automated enforcement records a null actor,
the matched rule and requested/applied action, the public explanation, and any
duration. Existing channel, role, overwrite, and member moderation actions are
shown in the same native timeline.

Audit access is server- and permission-scoped. The API does not return another
server's records or permit an unprivileged member to enumerate them.

## Signup proof of work

`GET /v1/auth/challenge` issues a random, five-minute SHA-256 challenge bound to
the request's client IP. A solution is valid once only. Production email-code
requests and Apple sign-in starts require a fresh solution. The Rust client
fetches and solves it off the async runtime, so normal native login remains
transparent.

Production starts at 18 leading zero bits and adapts up to 24 for a client that
repeatedly requests challenges. Development uses 8 bits to keep local tests
fast. Challenges are also limited to 20 per minute per IP.

The TCP peer address is authoritative by default. Set
`EXOCORD_TRUST_PROXY_HEADERS=1` only when the service is reachable exclusively
through a trusted reverse proxy; this enables `CF-Connecting-IP` and the first
valid `X-Forwarded-For` address. `X-Exocord-Client-IP` works only with
development auth and exists for deterministic tests.

## Rate limits

The limiter uses GCRA, preserving an exact initial burst while smoothing
continued traffic.

| Operation | Limit | Scope |
|---|---:|---|
| All `/v1/` requests | 50/second | authenticated user, otherwise IP |
| Challenge issue | 20/minute | IP |
| Email/Apple login start | 5/15 minutes | IP |
| Email login start | 10/hour | normalized-email hash |
| Email code verification | 5/15 minutes | IP + challenge |
| Send message | 5/5 seconds | user + channel |
| Typing signal | 1/8 seconds | user + channel |
| Create server | 10/day | user |
| Create channel | 5/10 seconds | user + server |
| Role mutations | 10/10 seconds | user + server |
| Create invite | 10/10 minutes | user |
| Reserve attachments | 20/minute | user |

Every `/v1/` response carries `X-RateLimit-Limit`, `Remaining`, `Reset`,
`Reset-After`, `Bucket`, and `Scope`. A rejection is HTTP 429 with
`Retry-After` plus JSON `retryAfter` and `global`.

## Deployment boundary

For Phase 0, proof-of-work challenges, recent request pressure, automod's
repeated-content windows, and GCRA counters are intentionally in-process.
Durable rules and audit records survive restarts; those short-lived controls do
not. Before horizontally scaling the monolith, move limiter and challenge state
to Dragonfly and define a bounded shared repeated-content window so users
cannot evade controls by landing on another instance.

Automod currently evaluates plaintext server messages. End-to-end encrypted
rooms use participant-selected, verified franked reports rather than
server-side content inspection. Accepted evidence is sanitized before storage:
the server keeps the selected plaintext and attachment hashes, never the
franking opening secret. See [`report-triage.md`](report-triage.md).
