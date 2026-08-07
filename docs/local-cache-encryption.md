# Local cache encryption

The native desktop cache is a SQLCipher database, not plaintext SQLite. It
contains synchronized message windows, locally decrypted search content,
relationships, read state, attachment metadata, active context, sealed
franking openings, and the restart-safe outbox. Encrypting only selected
columns would leave indexes, FTS terms, row counts, and journal content
exposed, so Exocord encrypts the complete database and its WAL.

## Key ownership and startup

Each account on an installation generates a random 32-byte cache key with the
operating system's secure random source. Its database lives under
`accounts/<user-id>/client.sqlite3`, and its key uses an account-ID-scoped slot
in the platform credential vault:

- Windows Credential Manager on Windows;
- Keychain on macOS;
- the platform Secret Service on supported Linux desktops.

The cache key is distinct from that account's refresh session, history key, and
the key that seals MLS state. It is never written to SQLite, renderer storage,
logs, or source configuration. A separate active-account marker identifies the
only cache eligible for session restoration; the client rejects a restored
session whose server user ID does not match that marker and cache directory.
Signed-out startup uses an in-memory store.

Startup is intentionally fail-closed:

1. Resolve the authenticated account, verify it matches the active-account
   marker, and open only that account's operating-system vault slots.
2. Load or create that account's cache key.
3. Apply the raw SQLCipher key before any schema read.
4. Enable cipher memory security and keep SQLite temporary storage in memory.
5. Confirm that SQLCipher is linked and run an integrity check.
6. Only then migrate the application schema and expose the native view model.

If the vault is unavailable, the key is malformed, SQLCipher is absent, or the
database cannot be authenticated, startup enters a blocking recovery view
backed by an empty in-memory store. Synchronization, session restoration, and
outbox delivery stay paused. It does not retry as plaintext, expose normal app
controls, or erase the file.

The settings panel reports the linked SQLCipher version rather than a
hard-coded marketing value. SQLCipher 4's default format uses AES-256 page
encryption with per-page authentication; the exact linked version remains
visible for diagnostics.

## Legacy plaintext migration

An existing cache is considered plaintext only when its main file has the
standard SQLite header. Migration then:

1. opens the legacy database and checkpoints/truncates its WAL;
2. attaches a keyed temporary database and copies all schema/data with
   `sqlcipher_export`;
3. preserves `user_version`, closes both databases, and verifies that the
   temporary file is encrypted and passes an integrity check with the key;
4. renames the original to a same-directory backup and atomically promotes the
   encrypted temporary file;
5. reopens and verifies the promoted database before best-effort overwriting
   and deleting the plaintext backup and sidecars.

The temporary and backup names are deterministic so startup can recover a
process or power failure during the swap. A valid encrypted main file always
wins. If the main file is missing, a verified encrypted temporary file is
promoted; otherwise the plaintext backup is restored and migration safely
restarts. Ambiguous or invalid states fail without deleting either candidate.

SQLCipher's documented plaintext-to-encrypted export flow is the basis for the
copy: <https://www.zetetic.net/sqlcipher/encrypting-plaintext-databases/>.

## Recovery and forensic boundary

Losing the operating-system-vault key makes the cache cryptographically
unreadable. The recovery view identifies the failure without exposing cache
contents and offers:

- **Restart and retry**, which changes no files;
- **Show cache folder**, for deliberate support or backup handling;
- **Start with a fresh cache**, only for key/read/corruption/migration failures
  that a reset can repair.

Starting fresh is a two-step destructive action. The user must open the reset
panel and type `RESET LOCAL CACHE` exactly. Before the vault key is removed,
the main database, WAL, SHM, rollback journal, migration temporary file, and
plaintext backup are moved into a unique timestamped `cache-recovery`
directory. A `recovery.json` record captures the reason, original path, and
preserved filenames. If preservation or vault-key removal fails, the move is
rolled back and startup remains blocked. Exocord never performs this reset
automatically.

After an explicit reset and restart, a user can sign in and synchronize
server-retained state into a new cache. Account-encrypted direct-message
archives are decrypted locally with the restored account history key. Unsent
outbox rows, genuinely local-only history, and locally retained cryptographic
evidence in the preserved encrypted cache remain inaccessible without the
original cache key.

Encryption covers the database, indexes, FTS content, and WAL while the app is
closed. It does not protect plaintext already rendered or held in process
memory, screen contents, compromised endpoints, or account metadata visible to
the service. Best-effort overwrite of a migrated plaintext file also cannot
guarantee removal from SSD remapping, copy-on-write filesystems, journal
history, cloud backups, or snapshots. Full-disk encryption remains recommended
from first install.

## Verification

Automated coverage proves that:

- the main database and WAL do not expose a SQLite header or known message
  text;
- an unkeyed SQLite connection and a wrong key cannot read the cache;
- an authenticated-page modification is rejected while the original file is
  preserved rather than reset or deleted;
- the correct key reopens messages, FTS results, attachments, and queued
  outbox work;
- a plaintext cache is exported without losing data;
- a simulated interruption between backup and promotion recovers correctly;
- the random cache key survives a real Windows Credential Manager round trip;
- two accounts use distinct credential names and cache directories, and
  restoring one account cannot return the other account's keys or data;
- every cache and migration sidecar is preserved before reset and can be
  rolled back without loss;
- both the renderer and native command require the exact, case-sensitive reset
  phrase;
- the Tauri test harness and production executable receive the same Windows
  Common Controls activation manifest.

The Rust binding is compiled with its vendored SQLCipher/OpenSSL feature. See
the upstream feature matrix at <https://github.com/rusqlite/rusqlite> and the
SQLCipher API reference at
<https://www.zetetic.net/sqlcipher/sqlcipher-api/>.
