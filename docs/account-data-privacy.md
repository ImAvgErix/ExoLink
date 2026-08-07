# Account data export and erasure

Exocord implements an authenticated, end-to-end account data flow instead of
requiring a manual support ticket. The design supports access and portability
requests while keeping destructive behavior explicit and recoverable.

This document describes product behavior and engineering boundaries. It is not
a substitute for a reviewed privacy policy, DPIA, or legal advice.

## Export

`GET /v1/users/@me/data-export` requires a real bearer session. Development
identity headers are intentionally insufficient.

The response is versioned machine-readable JSON and includes:

- profile and account creation metadata;
- linked identity metadata, including Apple identity data where present;
- session metadata without access tokens, refresh tokens, token hashes, or
  encrypted provider credentials;
- append-only account suspension and reinstatement history, including the
  operator, reason, optional supporting report ID, and time;
- servers, relationships, and direct-channel metadata visible to the account;
- every message authored by the account;
- owned attachment metadata, read state, registered-device metadata, and
  submitted reports;
- any pending deletion request and its deadline.

The endpoint sends `Cache-Control: private, no-store`, supplies a safe
attachment filename, permits two exports per account per hour, and never puts
credentials in the export. The native client writes pretty-printed JSON to a
unique file in the operating-system Downloads folder with `create_new`
semantics and flushes the file before reporting success.

A suspended account cannot authenticate to the self-service export endpoint.
The operator must provide a support channel for access requests during a
suspension; reinstatement permits a fresh login without restoring revoked
sessions.

The current direct response avoids object-storage cost and signed-link
complexity at early scale. Accounts whose exports no longer fit a bounded HTTP
request should move to an asynchronous job and short-lived download
capability without changing the JSON format.

## Scheduling deletion

`DELETE /v1/users/@me` schedules deletion for 30 days after the first request.
Repeated requests are idempotent and cannot extend the deadline.

Scheduling immediately:

1. locks and checks every active server owned by the account;
2. blocks with HTTP 409 if any owned server has another member;
3. freezes sole-member owned servers and revokes their invites;
4. revokes every current refresh/access session for the account;
5. marks known gateway devices for disconnect;
6. evicts the account from its current voice rooms;
7. clears the native in-memory session and operating-system vault credential;
8. leaves the encrypted local cache untouched and clearly says so.

The native UI requires the exact phrase `DELETE MY ACCOUNT` before calling the
bearer-token API. Because Exocord uses bearer headers rather than ambient
cookies, a third-party page cannot trigger this endpoint through cookie CSRF.
The backend separately limits scheduling to two requests per account per day.

The signed-out screen remembers only the deadline for the current renderer
session and explains how to recover. Reauthentication during the grace period
opens a restricted screen: the user may export data, cancel deletion, or sign
out, but cannot return to normal chat until cancellation succeeds. The backend
enforces the same restriction for normal REST, device, and gateway access, so a
custom client cannot create a new ownership problem during the grace period.

`GET /v1/users/@me/deletion` returns the current schedule plus active owned
servers and their member counts.
`DELETE /v1/users/@me/deletion` cancels it after reauthentication. Cancellation
clears owner-deletion markers, rotates the restored session, synchronizes the
native model, and removes the restricted state. Invite capability links revoked
when scheduling began remain revoked.

## Due-date worker

The monolith runs an immediate cleanup pass at startup and then once per hour.
Each pass claims at most 100 due accounts. The claim prevents a cancellation
race; due accounts with an earlier interrupted claim remain eligible so the
next pass can retry. Repository anonymization and auth-secret destruction are
idempotent, making repeated worker runs safe.

At finalization Exocord:

- replaces the handle and display name with a non-routable tombstone and
  `Deleted User #<suffix>`;
- nulls profile PII, disables the durable account, and increments its token
  version;
- destroys email challenges, sessions, token history, external identity
  records, and encrypted Apple provider credentials;
- removes relationships, read state, all memberships, member roles,
  member-specific permission overwrites, and timeouts;
- revokes device identities, clears their friendly names, deletes MLS
  KeyPackages and targeted pending MLS delivery, and removes the devices from
  current MLS membership;
- retires every sole-member owned server and its channels, revokes its invites,
  removes the final owner membership, and records the system reason.

Device private keys never reach the server. Revoked public signing identities
remain where existing message foreign keys or verification history require
them.

## Retained shared data

Message content and attachment records remain attached to the anonymized user
record. Removing one participant's half of a group conversation would also
destroy context belonging to the other participants. The product explains
this before confirmation and on the grace-period screen; it must also be
stated in the reviewed privacy policy.

The local SQLCipher cache is installation data and is not silently erased by a
remote account request. A user may separately use the explicit preserve-before-
reset cache flow or remove the application data after they no longer need a
local copy.

Multi-member servers must be transferred to a current member or explicitly
deleted before account deletion can be scheduled. The account UI links each
blocker to its owner-only transfer/delete controls. A sole-member server is
frozen during the grace period and retired at finalization.

Server retirement removes access immediately but soft-retains rows for the
published retention, legal-hold, and backup policy. Shared messages continue to
reference the anonymized author. The full concurrency and event behavior is in
[server ownership lifecycle](server-ownership-lifecycle.md).

## Verification

Automated coverage proves:

- exports contain expected account, message, relationship, device, and auth
  metadata while excluding usable credentials;
- scheduling revokes old sessions immediately;
- suspension revokes every old session, blocks all new session issuance, and
  preserves suspend/reinstate events in the export;
- reauthentication exposes the deadline and cancellation clears it;
- finalization destroys identity/session secrets and releases the original
  email for a new account;
- relationships and cryptographic delivery state are removed while authored
  messages remain under the tombstone;
- the hourly coordinator is idempotent;
- multi-member ownership blocks scheduling until transfer or server deletion;
- grace-period accounts are restricted by the server as well as the UI;
- sole-member servers freeze during grace and retire at finalization;
- both native and renderer confirmation helpers reject partial or
  case-insensitive phrases.

The renderer flow was also exercised visually and interactively at 1280x720,
including export-first hierarchy, disabled destructive actions, the exact
phrase, signed-out recovery notice, and the restricted grace-period screen.
The owner resolution path was separately exercised through transfer,
exact-name server deletion, post-transfer authority removal, and
blocker-to-server navigation.

## Legal review pointers

The relevant source texts include the official
[GDPR regulation](https://eur-lex.europa.eu/eli/reg/2016/679/ojv), the EDPB's
[data-subject rights overview](https://www.edpb.europa.eu/topics/key-gdpr-concepts/data-subject-rights_en),
and its
[right-to-data-portability guidance](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/right-data-portability_en).
Counsel still needs to review Exocord's retention basis, user-facing notices,
soft-retired server purge timing, and request-response procedures before public
signup.
