# End-to-end encryption

Exocord's native desktop path uses OpenMLS 1.0 for encrypted DMs and private
server/voice channels. It is implemented in the Rust core rather than the React
renderer. The operating-system credential vault holds separate random 256-bit
keys for sealed MLS state and the SQLCipher desktop cache, as well as the
refresh session. Cache encryption protects local files at rest; it does not
change the end-to-end trust model or give the server an MLS key.

## Trust and device model

- Every installation creates a durable Ed25519 device identity and displays a
  human-comparable fingerprint.
- Devices publish signed, one-time MLS KeyPackages. The delivery service checks
  that a claimed package belongs to its registered device identity.
- Initial group creation, later membership updates, epoch ordering, and exact
  Welcome-to-KeyPackage matching are transactionally enforced.
- A later device requests admission. An existing group member creates the MLS
  Commit and Welcome; the server cannot add the device or manufacture a valid
  Welcome itself.
- Existing devices receive targeted, durable Commits. The admitted device gets
  future MLS keys from its Welcome epoch, not old epoch keys. Previously
  decrypted DM content can be restored independently through the account's
  client-encrypted private-history archive.
- Revoking another device immediately invalidates every session bound to it,
  closes its event stream before the rekey event, burns its unused
  KeyPackages, blocks that installation ID from signing in again, and evicts
  account voice participants. A reset installation receives a new device ID
  and must be admitted normally. The server records the removal as durable
  pending maintenance until a remaining group member publishes the RFC 9420
  Remove Commit.
- Current MLS membership is stored explicitly rather than inferred from old
  delivery rows. Remove Commits advance the epoch, are sent only to remaining
  members, and make the revoked leaf unable to derive future message or voice
  keys. Online clients race safely; a losing client restores its sealed state
  and applies the winner's durable Commit.
- Offline groups are not forgotten. Every active device asks for pending
  removal work during synchronization, so a trusted member that returns later
  finishes the rekey.
- There is no server key escrow. Each account receives a random 256-bit history
  key that is wrapped independently with its password and each one-time
  recovery code. The service stores only the opaque wrappers and per-account
  history ciphertext. A password sign-in or recovery code can therefore
  restore archived DM content after an app/Windows reinstall without giving
  the service the key or any archived plaintext.

The server still controls account and channel authorization. Account IDs and
message IDs are authenticated into every history archive, and reads/writes are
authorized for only that signed-in DM recipient. An independent security audit
remains a public-launch gate.

## Private-history recovery

For each decrypted direct message, the desktop serializes the display content
and attachment descriptors, encrypts that archive with XChaCha20-Poly1305, and
uploads it under the current user's account and message ID. Each DM recipient
has a separate archive row and ciphertext; one recipient can neither read nor
replace the other recipient's copy.

On a clean installation, normal server synchronization restores account,
server, channel, relationship, and message metadata. If old MLS epoch material
is unavailable, the desktop pages through that account's private-history
archive and decrypts it locally. The recovered plaintext is written only to
that account's SQLCipher cache. Wrong-account keys, wrong passwords, wrong
recovery codes, and swapped message/account identifiers fail authentication.

Password changes rewrap the same history key and commit the password hash and
replacement wrapper in one database transaction. Recovery-code replacement
stages the new hashes first, uploads all corresponding key wrappers, and
activates the new set atomically; the older codes are not removed until that
completes.

## Messages and attachments

Message content and attachment descriptors are authenticated inside MLS
application messages. The context binds channel, author, and retry nonce, so a
ciphertext cannot be replayed into another message context. The server stores
only ciphertext plus a commitment and server-authenticated franking tag.

For an encrypted attachment, WebCrypto generates an AES-256-GCM key and nonce,
encrypts bytes before upload, and sends the server an opaque random filename,
`application/octet-stream`, and ciphertext. The MLS envelope contains the
original metadata, key, nonce, and plaintext/ciphertext SHA-256 values.
Recipients verify the ciphertext hash, decrypt, then verify the plaintext hash
before creating a local Blob URL.

Plaintext server channels intentionally keep the server-readable,
hash-validated attachment and search path. Search for encrypted channels and
DMs runs only over locally decrypted SQLite content.

## Voice and screen sharing

Before joining an encrypted voice channel, the Rust core exports 32 bytes from
the current MLS epoch using label `EXOCORD_SFRAME_V1` and the channel ID as
context. The renderer imports that key into LiveKit's external E2EE key
provider and dedicated worker. A production join fails closed if the key or
worker is unavailable.

The SFU can observe room membership, timing, packet size, and network metadata,
but it does not receive the exported MLS secret. Permission changes still
revoke the short-lived room grant and evict the participant at the LiveKit
control plane.

## Abuse reports

Each encrypted message carries a client commitment over the plaintext and
attachment hashes. The desktop retains the opening only as an
OS-device-key-sealed local record. Reporting decrypts that one opening, and the
server verifies both the client commitment and its own stored authentication
tag before accepting the evidence. Altered content, keys, hashes, or tags fail.
After verification, the server stores only the selected plaintext, attachment
metadata and hashes, and verification result. It does not persist or return the
franking opening secret.

The separate operator API can list and resolve this scoped evidence through a
high-entropy credential that normal Exocord sessions cannot use. This gives
the safety team one user-selected, verifiable message. It is not a general
conversation-decryption mechanism and it does not provide automated
encrypted-content scanning.

## Verification

The automated gate covers real two- and three-device OpenMLS exchange,
restart-safe sealed state, context/commitment tampering, attachment descriptor
authentication, singleton voice groups, future-epoch device admission,
per-account cache/vault isolation, password and recovery-code key wrapping,
cross-account archive denial, clean-install history restoration,
device-session eviction, durable pending removal discovery, removal-epoch
forward secrecy, franking evidence and tamper rejection, full workspace tests,
strict Clippy, the optimized desktop build with its E2EE worker chunk, and a
real PostgreSQL 17 migration/restart run.
