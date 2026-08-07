# Attachments, media, and search

This phase adds real attachment delivery and two honest search paths without
putting file bytes through the chat request.

## Upload contract

1. The client computes SHA-256 before upload and reserves one or more files
   against a text channel.
2. The server checks membership, `VIEW_CHANNEL`, `SEND_MESSAGES`, filename,
   declared size, count, and type. It returns a short-lived direct-upload URL
   and the exact signed headers.
3. The client uploads directly to local server storage or optional Cloudflare R2.
4. Completion makes the server fetch/read the stored bytes and independently
   verify size, SHA-256, magic MIME, and image dimensions.
5. Only a verified reservation owned by the sender and scoped to that channel
   can be attached to a message. Linking happens in the same transaction as
   message creation, including nonce-idempotent retries.

Messages may contain text, up to ten attachments, or attachments without text.
Each file is capped at 25 MiB. Image decoding is guarded at 16,384 pixels per
edge and 40 megapixels. HTML, SVG, script-like active documents, MIME
mismatches, zero-byte files, and unsupported formats are rejected. Local
responses include `X-Content-Type-Options: nosniff`.

Object names are content-addressed, but not raw hashes. They use
`HMAC-SHA256(EXOCORD_ATTACHMENT_OBJECT_KEY, file_sha256)`, so repeated content
deduplicates without exposing a confirmation oracle for known files.
`If-None-Match: *` prevents replacement of an existing R2 object.

## Storage modes

The base production alpha and development both use persistent files under
`EXOCORD_STATE_DIR/attachments`. Upload and read URLs are HMAC capabilities
bound to the complete reservation. Production requires separately mounted
capability and object-addressing keys, an exact public HTTPS API origin, and a
quota. The Oracle profile defaults to five GiB so attachments plus rotating
backups cannot silently consume the entire 50 GB boot disk. This mode uses no
additional cloud account and keeps attachment delivery on the Exocord host.

Cloudflare R2 is an optional scaling overlay. The backend generates AWS
Signature V4 URLs for direct PUT, validation GET, and cleanup DELETE requests;
bucket credentials never enter the renderer. `EXOCORD_CDN_URL` should be a
dedicated custom media domain, not the R2 API endpoint.

The R2 bucket CORS policy must allow the deployed app origins, `PUT` and `GET`,
and the request headers `Content-Type` and `If-None-Match`. For native Windows
development, include the actual Tauri origin observed by the WebView
(`http://tauri.localhost`; older configurations may use `tauri://localhost`).
The web preview origin must be listed separately.

Cloudflare documents the same SigV4 direct-upload pattern, the `auto` region,
the seven-day maximum signature lifetime, and the need for bucket CORS:

- <https://developers.cloudflare.com/r2/api/s3/presigned-urls/>
- <https://developers.cloudflare.com/r2/buckets/cors/>

## Orphan retention

Reservations expire after 15 minutes. An hourly worker removes expired,
unlinked reservation rows and their objects in batches. Content-addressed
objects can be shared, so cleanup first checks for a live reservation or
message reference.

PostgreSQL advisory locks serialize cleanup with a new reservation for the
same object. The object is deleted while that lock is held, so another worker
cannot create a reservation in the check/delete gap. Local in-memory
development uses the repository write lock for the same invariant. A failed
storage deletion leaves metadata available for the next cleanup pass.

## Search contract

Plaintext channel messages use permission-scoped server search. The current
implementation uses PostgreSQL `websearch_to_tsquery`, a partial GIN index,
ranking, snippets, and a bounded result set. This avoids operating
Meilisearch before measured load needs it; the API response is shaped so a
future Meilisearch mirror does not change the desktop contract.

Encrypted-channel content is never sent to server search. The native core
indexes locally available encrypted messages in SQLite FTS5 and merges those
device-only hits with the server result. The dialog explicitly reports:

- encrypted channels searched only on this device;
- channels excluded because the member cannot read them;
- the difference between local matches and server-reported totals.

Opening an older server hit fetches a bounded window around its message,
persists that window in the local cache, switches channel context, and focuses
the exact row. Search never grants visibility: the same channel permission
resolver used by history and sync determines the searchable set.

## Deferred media work

Encrypted attachment envelopes are implemented for MLS channels: encryption
happens before upload and the key/original metadata remain inside the
authenticated MLS message. Dedicated thumbnail generation, malware scanning,
GIF-to-WebM conversion, video transcoding, and a credentialed production R2
integration run remain deferred. Those require dedicated workers or external
services. The local storage path, signature construction, real PostgreSQL
durability, validation rules, cleanup invariants, and desktop upload/search
flow are covered by tests.
