use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use chrono::{DateTime, Utc};
use exo_domain::{
    ChannelId, ChannelKind, Message, MessageAttachment, MessageId, MessageReaction,
    MessageReactionEvent, ReadState, RelationshipKind, SyncSnapshot,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const LOCAL_SCHEMA_V1: &str = include_str!("../migrations/0001_local.sql");
const LOCAL_SCHEMA_V2: &str = include_str!("../migrations/0002_sync.sql");
const LOCAL_SCHEMA_V3: &str = include_str!("../migrations/0003_guild_access.sql");
const LOCAL_SCHEMA_V4: &str = include_str!("../migrations/0004_relationships_direct_messages.sql");
const LOCAL_SCHEMA_V5: &str = include_str!("../migrations/0005_franking_openings.sql");
const LOCAL_SCHEMA_V6: &str = include_str!("../migrations/0006_conversation_actions.sql");
const LOCAL_SCHEMA_V7: &str = include_str!("../migrations/0007_private_history_outbox.sql");
const LOCAL_SCHEMA_V8: &str = include_str!("../migrations/0008_guild_members.sql");
const LOCAL_SCHEMA_V9: &str = include_str!("../migrations/0009_retry_schedule.sql");
const CURRENT_SCHEMA_VERSION: i64 = 9;
const SQLITE_PLAINTEXT_HEADER: &[u8; 16] = b"SQLite format 3\0";
const ENCRYPTION_TEMP_SUFFIX: &str = ".encrypted-migrating";
const PLAINTEXT_BACKUP_SUFFIX: &str = ".plaintext-backup";
const SCRUB_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageState {
    Sent,
    Pending,
    Failed,
}

impl MessageState {
    const fn as_i64(self) -> i64 {
        match self {
            Self::Sent => 0,
            Self::Pending => 1,
            Self::Failed => 2,
        }
    }

    fn from_i64(value: i64) -> Result<Self, StoreError> {
        match value {
            0 => Ok(Self::Sent),
            1 => Ok(Self::Pending),
            2 => Ok(Self::Failed),
            other => Err(StoreError::InvalidMessageState(other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedUser {
    pub id: u64,
    pub handle: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub origin_remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedGuild {
    pub id: u64,
    pub owner_id: u64,
    pub name: String,
    pub accent: u32,
    pub created_at: String,
    pub current_permissions: u64,
    pub origin_remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedChannel {
    pub id: u64,
    pub guild_id: u64,
    pub name: String,
    pub kind: ChannelKind,
    pub position: i32,
    pub encrypted: bool,
    pub created_at: String,
    pub origin_remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedMessage {
    pub id: u64,
    pub client_key: String,
    pub channel_id: u64,
    pub author_id: u64,
    pub reply_to: Option<u64>,
    pub content: String,
    pub attachments: Vec<MessageAttachment>,
    pub reactions: Vec<MessageReaction>,
    pub sequence: u64,
    pub created_at: String,
    pub edited_at: Option<String>,
    pub state: MessageState,
    pub nonce: Option<String>,
    pub origin_remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedRelationship {
    pub user_id: u64,
    pub kind: RelationshipKind,
    pub since: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedDirectChannel {
    pub id: u64,
    pub recipient_ids: Vec<u64>,
    pub last_message_id: Option<u64>,
    pub encrypted: bool,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachedGuildMember {
    pub guild_id: u64,
    pub user_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingMessage {
    pub temporary_id: u64,
    pub nonce: String,
    pub channel_id: u64,
    pub reply_to: Option<u64>,
    pub content: String,
    pub attachments: Vec<MessageAttachment>,
    pub attempts: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CacheSnapshot {
    pub current_user_id: Option<u64>,
    pub active_guild_id: Option<u64>,
    pub active_channel_id: Option<u64>,
    pub active_voice_channel_id: Option<u64>,
    pub last_sequence: u32,
    pub users: Vec<CachedUser>,
    pub guilds: Vec<CachedGuild>,
    pub channels: Vec<CachedChannel>,
    pub direct_channels: Vec<CachedDirectChannel>,
    pub guild_members: Vec<CachedGuildMember>,
    pub relationships: Vec<CachedRelationship>,
    pub read_states: Vec<ReadState>,
    pub messages: Vec<CachedMessage>,
    pub pending_outbox: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("SQLite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("local cache filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("local store mutex is unavailable")]
    LockUnavailable,
    #[error("identifier {0} does not fit SQLite's signed integer representation")]
    IdentifierRange(u64),
    #[error("stored message state {0} is unknown")]
    InvalidMessageState(i64),
    #[error("stored channel kind {0} is unknown")]
    InvalidChannelKind(i64),
    #[error("stored relationship kind {0} is unknown")]
    InvalidRelationshipKind(i64),
    #[error("stored client state {0} is invalid")]
    InvalidState(&'static str),
    #[error("the local cache path has no database filename")]
    InvalidDatabasePath,
    #[error("SQLCipher is unavailable in this desktop build")]
    EncryptionUnavailable,
    #[error("the encrypted local cache could not be unlocked or is corrupt")]
    CacheUnlockFailed,
    #[error("the encrypted local cache failed its integrity check")]
    CacheIntegrityFailed,
    #[error("the existing local cache could not be migrated safely")]
    CacheMigrationFailed,
    #[error("outbox payload is invalid: {0}")]
    InvalidOutbox(#[from] serde_json::Error),
}

/// The durable, thread-safe client cache. The renderer never touches this
/// connection directly.
pub struct LocalStore {
    connection: Mutex<Connection>,
    cipher_version: Option<String>,
}

// All store operations can surface the compact `StoreError` variants above;
// individual methods document their semantic guarantees instead.
#[allow(clippy::missing_errors_doc)]
impl LocalStore {
    /// Opens and migrates a plaintext on-disk client database.
    ///
    /// Desktop production code must use [`Self::open_encrypted`]. This entry
    /// point remains available for explicit migration and compatibility tests.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        Self::from_connection(connection, None)
    }

    /// Opens an AES-256 `SQLCipher` cache with a raw random key supplied by the
    /// native credential vault. Existing plaintext caches are exported into a
    /// verified encrypted copy before the original path is replaced.
    pub fn open_encrypted(path: impl AsRef<Path>, key: &[u8; 32]) -> Result<Self, StoreError> {
        let path = path.as_ref();
        recover_interrupted_cache_migration(path, key)?;
        if is_plaintext_sqlite(path)? {
            encrypt_plaintext_cache(path, key)?;
        }
        let (connection, cipher_version) = open_keyed_connection(path, key)?;
        verify_cache_integrity(&connection)?;
        Self::from_connection(connection, Some(cipher_version))
    }

    /// Opens a fully migrated in-memory database, primarily for tests.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?, None)
    }

    fn from_connection(
        connection: Connection,
        cipher_version: Option<String>,
    ) -> Result<Self, StoreError> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&connection)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA secure_delete = ON;",
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            cipher_version,
        })
    }

    /// Reports the linked `SQLCipher` version for an encrypted cache.
    #[must_use]
    pub fn cipher_version(&self) -> Option<&str> {
        self.cipher_version.as_deref()
    }

    pub fn is_empty(&self) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM guilds", [], |row| row.get(0))?;
        Ok(count == 0)
    }

    pub fn put_user(&self, user: &CachedUser) -> Result<(), StoreError> {
        let connection = self.lock()?;
        upsert_user(&connection, user)
    }

    pub fn put_guild(&self, guild: &CachedGuild) -> Result<(), StoreError> {
        let connection = self.lock()?;
        upsert_guild(&connection, guild)
    }

    pub fn put_channel(&self, channel: &CachedChannel) -> Result<(), StoreError> {
        let connection = self.lock()?;
        upsert_channel(&connection, channel)
    }

    pub fn put_message(&self, message: &CachedMessage) -> Result<(), StoreError> {
        let connection = self.lock()?;
        upsert_message(&connection, message)
    }

    pub fn message_by_id(&self, message_id: u64) -> Result<Option<CachedMessage>, StoreError> {
        Ok(self
            .snapshot()?
            .messages
            .into_iter()
            .find(|message| message.id == message_id))
    }

    pub fn merge_remote_message_update(
        &self,
        message: &Message,
        decrypted_content: Option<&str>,
    ) -> Result<CachedMessage, StoreError> {
        let existing = self.message_by_id(message.id.raw())?;
        let mut cached = cached_remote_message(
            message,
            existing.as_ref().map(|value| value.client_key.clone()),
        );
        if let Some(existing) = existing {
            cached.reactions = existing.reactions;
            if message.encryption.is_some() {
                cached.attachments = existing.attachments;
                if decrypted_content.is_none() {
                    cached.content = existing.content;
                }
            }
        }
        if let Some(content) = decrypted_content {
            content.clone_into(&mut cached.content);
        }
        self.put_message(&cached)?;
        Ok(cached)
    }

    pub fn edit_local_message(
        &self,
        message_id: u64,
        author_id: u64,
        content: &str,
    ) -> Result<CachedMessage, StoreError> {
        let mut message = self
            .message_by_id(message_id)?
            .ok_or(StoreError::InvalidState("message"))?;
        if message.origin_remote || message.author_id != author_id {
            return Err(StoreError::InvalidState("local message ownership"));
        }
        content.clone_into(&mut message.content);
        message.edited_at = Some(Utc::now().to_rfc3339());
        self.put_message(&message)?;
        Ok(message)
    }

    pub fn mark_message_deleted(&self, message_id: u64, channel_id: u64) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "UPDATE messages SET deleted = 1
             WHERE id = ?1 AND channel_id = ?2",
            params![to_i64(message_id)?, to_i64(channel_id)?],
        )?;
        connection.execute(
            "DELETE FROM message_franking_openings WHERE message_id = ?1",
            [to_i64(message_id)?],
        )?;
        Ok(())
    }

    pub fn apply_reaction_event(
        &self,
        event: &MessageReactionEvent,
        current_user_id: u64,
    ) -> Result<Option<CachedMessage>, StoreError> {
        let Some(mut message) = self.message_by_id(event.message_id.raw())? else {
            return Ok(None);
        };
        if message.channel_id != event.channel_id.raw() || message.state != MessageState::Sent {
            return Ok(None);
        }
        if event.count == 0 {
            message
                .reactions
                .retain(|reaction| reaction.emoji != event.emoji);
        } else if let Some(reaction) = message
            .reactions
            .iter_mut()
            .find(|reaction| reaction.emoji == event.emoji)
        {
            reaction.count = event.count;
            if event.user_id.raw() == current_user_id {
                reaction.me = event.added;
            }
        } else {
            message.reactions.push(MessageReaction {
                emoji: event.emoji.clone(),
                count: event.count,
                me: event.user_id.raw() == current_user_id && event.added,
            });
            message
                .reactions
                .sort_by(|left, right| left.emoji.cmp(&right.emoji));
        }
        self.put_message(&message)?;
        Ok(Some(message))
    }

    pub fn put_read_state(&self, state: &ReadState) -> Result<(), StoreError> {
        let connection = self.lock()?;
        upsert_read_state(&connection, state)
    }

    pub fn direct_unread_state(&self, channel_id: u64) -> Result<Option<(bool, u32)>, StoreError> {
        let connection = self.lock()?;
        let state = connection
            .query_row(
                "SELECT direct.last_message_id, read_state.last_read_id
                 FROM direct_channels direct
                 LEFT JOIN read_state
                   ON read_state.channel_id = direct.channel_id
                 WHERE direct.channel_id = ?1",
                [to_i64(channel_id)?],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()?;
        let Some((last_message_id, last_read_id)) = state else {
            return Ok(None);
        };
        let unread =
            last_message_id.is_some_and(|last| last_read_id.is_none_or(|read| last > read));
        let unread_count: i64 = connection.query_row(
            "SELECT COUNT(*)
             FROM direct_channels direct
             LEFT JOIN read_state
               ON read_state.channel_id = direct.channel_id
             WHERE direct.last_message_id IS NOT NULL
               AND (
                 read_state.last_read_id IS NULL
                 OR direct.last_message_id > read_state.last_read_id
               )",
            [],
            |row| row.get(0),
        )?;
        Ok(Some((
            unread,
            u32::try_from(unread_count).unwrap_or(u32::MAX),
        )))
    }

    pub fn set_current_user(&self, user_id: u64) -> Result<(), StoreError> {
        let connection = self.lock()?;
        set_state(&connection, "current_user_id", &user_id.to_string())
    }

    pub fn current_user_id(&self) -> Result<Option<u64>, StoreError> {
        let connection = self.lock()?;
        get_state(&connection, "current_user_id")?
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| StoreError::InvalidState("current_user_id"))
            })
            .transpose()
    }

    pub fn set_active_context(
        &self,
        guild_id: u64,
        channel_id: u64,
        voice_channel_id: Option<u64>,
    ) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let transaction = connection.unchecked_transaction()?;
        set_state(&transaction, "active_guild_id", &guild_id.to_string())?;
        set_state(&transaction, "active_channel_id", &channel_id.to_string())?;
        match voice_channel_id {
            Some(id) => set_state(&transaction, "active_voice_channel_id", &id.to_string())?,
            None => {
                transaction.execute(
                    "DELETE FROM app_state WHERE key = 'active_voice_channel_id'",
                    [],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Atomically replaces the remote portion of the cache with a bounded
    /// server snapshot while preserving local-only data and the outbox.
    #[allow(clippy::too_many_lines)]
    pub fn apply_remote_snapshot(&self, snapshot: &SyncSnapshot) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM messages WHERE origin = 1", [])?;
        transaction.execute("DELETE FROM channels WHERE origin = 1", [])?;
        transaction.execute("DELETE FROM guilds WHERE origin = 1", [])?;
        transaction.execute("DELETE FROM users WHERE origin = 1", [])?;
        transaction.execute("DELETE FROM direct_channels", [])?;
        transaction.execute("DELETE FROM guild_member_users", [])?;
        transaction.execute("DELETE FROM relationships", [])?;
        transaction.execute("DELETE FROM read_state", [])?;

        let user = CachedUser {
            id: snapshot.current_user.id.raw(),
            handle: snapshot.current_user.handle.clone(),
            display_name: snapshot.current_user.display_name.clone(),
            avatar_url: snapshot.current_user.avatar_url.clone(),
            origin_remote: true,
        };
        upsert_user(&transaction, &user)?;
        for user in &snapshot.users {
            upsert_user(
                &transaction,
                &CachedUser {
                    id: user.id.raw(),
                    handle: user.handle.clone(),
                    display_name: user.display_name.clone(),
                    avatar_url: user.avatar_url.clone(),
                    origin_remote: true,
                },
            )?;
        }
        for guild in &snapshot.guilds {
            let current_permissions = snapshot
                .guild_access
                .iter()
                .find(|access| access.guild_id == guild.id)
                .map_or(0, |access| access.permissions.bits());
            upsert_guild(
                &transaction,
                &CachedGuild {
                    id: guild.id.raw(),
                    owner_id: guild.owner_id.raw(),
                    name: guild.name.clone(),
                    accent: guild.accent,
                    created_at: guild.created_at.to_rfc3339(),
                    current_permissions,
                    origin_remote: true,
                },
            )?;
        }
        for channel in &snapshot.channels {
            upsert_channel(
                &transaction,
                &CachedChannel {
                    id: channel.id.raw(),
                    guild_id: channel.guild_id.raw(),
                    name: channel.name.clone(),
                    kind: channel.kind,
                    position: channel.position,
                    encrypted: channel.encrypted,
                    created_at: channel.created_at.to_rfc3339(),
                    origin_remote: true,
                },
            )?;
        }
        for member in &snapshot.guild_members {
            transaction.execute(
                "INSERT INTO guild_member_users (guild_id, user_id) VALUES (?1, ?2)",
                params![
                    to_i64(member.guild_id.raw())?,
                    to_i64(member.user_id.raw())?
                ],
            )?;
        }
        upsert_remote_social_state(&transaction, snapshot)?;
        for message in &snapshot.messages {
            upsert_message(&transaction, &cached_remote_message(message, None))?;
        }
        set_state(
            &transaction,
            "current_user_id",
            &snapshot.current_user.id.to_string(),
        )?;
        set_state(
            &transaction,
            "last_sequence",
            &snapshot.last_sequence.to_string(),
        )?;
        if get_state(&transaction, "active_guild_id")?.is_none()
            && let Some(guild) = snapshot.guilds.first()
        {
            set_state(&transaction, "active_guild_id", &guild.id.to_string())?;
            if let Some(channel) = snapshot
                .channels
                .iter()
                .find(|channel| channel.guild_id == guild.id && channel.kind == ChannelKind::Text)
            {
                set_state(&transaction, "active_channel_id", &channel.id.to_string())?;
            }
        } else if get_state(&transaction, "active_guild_id")?.is_none()
            && let Some(channel) = snapshot.direct_channels.first()
        {
            set_state(&transaction, "active_guild_id", "0")?;
            set_state(&transaction, "active_channel_id", &channel.id.to_string())?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_remote_message(&self, message: &Message) -> Result<CachedMessage, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let cached =
            cached_remote_message(message, stored_client_key(&transaction, message.id.raw())?);
        upsert_message(&transaction, &cached)?;
        advance_direct_channel(&transaction, &cached)?;
        transaction.commit()?;
        Ok(cached)
    }

    pub fn upsert_decrypted_remote_message(
        &self,
        message: &Message,
        plaintext: &str,
        attachments: &[MessageAttachment],
    ) -> Result<CachedMessage, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut cached =
            cached_remote_message(message, stored_client_key(&transaction, message.id.raw())?);
        plaintext.clone_into(&mut cached.content);
        cached.attachments = attachments.to_vec();
        upsert_message(&transaction, &cached)?;
        advance_direct_channel(&transaction, &cached)?;
        transaction.commit()?;
        Ok(cached)
    }

    /// Restores a client-authenticated private-history record that is older
    /// than the server's bounded bootstrap window.
    pub fn upsert_restored_private_message(
        &self,
        message: &CachedMessage,
    ) -> Result<CachedMessage, StoreError> {
        let mut restored = message.clone();
        restored.client_key = restored.id.to_string();
        restored.state = MessageState::Sent;
        restored.nonce = None;
        restored.origin_remote = true;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        upsert_message(&transaction, &restored)?;
        advance_direct_channel(&transaction, &restored)?;
        transaction.commit()?;
        Ok(restored)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_message(
        &self,
        temporary_id: u64,
        nonce: &str,
        channel_id: u64,
        author_id: u64,
        reply_to: Option<u64>,
        content: &str,
        attachments: &[MessageAttachment],
        created_at: DateTime<Utc>,
    ) -> Result<CachedMessage, StoreError> {
        #[derive(Serialize)]
        struct OutboxPayload<'a> {
            content: &'a str,
            reply_to: Option<u64>,
            attachments: &'a [MessageAttachment],
        }

        let message = CachedMessage {
            id: temporary_id,
            client_key: nonce.to_owned(),
            channel_id,
            author_id,
            reply_to,
            content: content.to_owned(),
            attachments: attachments.to_vec(),
            reactions: Vec::new(),
            sequence: 0,
            created_at: created_at.to_rfc3339(),
            edited_at: None,
            state: MessageState::Pending,
            nonce: Some(nonce.to_owned()),
            origin_remote: false,
        };
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        upsert_message(&transaction, &message)?;
        transaction.execute(
            "INSERT INTO outbox (nonce, channel_id, payload, created_at, attempts)
             VALUES (?1, ?2, ?3, ?4, 0)
             ON CONFLICT(nonce) DO NOTHING",
            params![
                nonce,
                to_i64(channel_id)?,
                serde_json::to_vec(&OutboxPayload {
                    content,
                    reply_to,
                    attachments,
                })?,
                created_at.timestamp_millis()
            ],
        )?;
        transaction.commit()?;
        Ok(message)
    }

    pub fn insert_local_message(
        &self,
        id: u64,
        channel_id: u64,
        author_id: u64,
        reply_to: Option<u64>,
        content: &str,
        created_at: DateTime<Utc>,
    ) -> Result<CachedMessage, StoreError> {
        let message = CachedMessage {
            id,
            client_key: id.to_string(),
            channel_id,
            author_id,
            reply_to,
            content: content.to_owned(),
            attachments: Vec::new(),
            reactions: Vec::new(),
            sequence: 0,
            created_at: created_at.to_rfc3339(),
            edited_at: None,
            state: MessageState::Sent,
            nonce: None,
            origin_remote: false,
        };
        self.put_message(&message)?;
        Ok(message)
    }

    pub fn acknowledge_message(
        &self,
        nonce: &str,
        server_message: &Message,
    ) -> Result<CachedMessage, StoreError> {
        self.acknowledge_message_with_plaintext(nonce, server_message, None)
    }

    pub fn acknowledge_encrypted_message(
        &self,
        nonce: &str,
        server_message: &Message,
        plaintext: &str,
        attachments: &[MessageAttachment],
    ) -> Result<CachedMessage, StoreError> {
        self.acknowledge_message_with_plaintext(
            nonce,
            server_message,
            Some((plaintext, attachments)),
        )
    }

    fn acknowledge_message_with_plaintext(
        &self,
        nonce: &str,
        server_message: &Message,
        decrypted: Option<(&str, &[MessageAttachment])>,
    ) -> Result<CachedMessage, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let client_key = transaction
            .query_row(
                "SELECT client_key FROM messages WHERE nonce = ?1",
                [nonce],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .unwrap_or_else(|| nonce.to_owned());
        transaction.execute("DELETE FROM messages WHERE nonce = ?1", [nonce])?;
        let mut cached = cached_remote_message(server_message, Some(client_key));
        if let Some((plaintext, attachments)) = decrypted {
            plaintext.clone_into(&mut cached.content);
            cached.attachments = attachments.to_vec();
        }
        upsert_message(&transaction, &cached)?;
        advance_direct_channel(&transaction, &cached)?;
        transaction.execute("DELETE FROM outbox WHERE nonce = ?1", [nonce])?;
        transaction.commit()?;
        Ok(cached)
    }

    pub fn search_encrypted_messages(
        &self,
        guild_id: u64,
        query: &str,
        limit: usize,
    ) -> Result<Vec<CachedMessage>, StoreError> {
        self.search_local_messages(guild_id, query, limit, true)
    }

    pub fn search_cached_messages(
        &self,
        guild_id: u64,
        query: &str,
        limit: usize,
    ) -> Result<Vec<CachedMessage>, StoreError> {
        self.search_local_messages(guild_id, query, limit, false)
    }

    fn search_local_messages(
        &self,
        guild_id: u64,
        query: &str,
        limit: usize,
        encrypted_only: bool,
    ) -> Result<Vec<CachedMessage>, StoreError> {
        let fts_query = query
            .split_whitespace()
            .filter(|term| !term.is_empty())
            .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" AND ");
        if fts_query.is_empty() {
            return Ok(Vec::new());
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT m.id, m.client_key, m.channel_id, m.author_id, m.content,
                    m.attachments, m.reactions, m.reply_to_id, m.edited_at,
                    m.sequence, m.created_at, m.local_state, m.nonce, m.origin
             FROM messages_fts
             JOIN messages m ON m.id = messages_fts.rowid
             JOIN channels c ON c.id = m.channel_id
             WHERE messages_fts MATCH ?1
               AND c.guild_id = ?2
               AND (?3 = 0 OR c.encrypted = 1)
               AND m.deleted = 0
             ORDER BY bm25(messages_fts), m.id DESC
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                fts_query,
                to_i64(guild_id)?,
                i64::from(encrypted_only),
                i64::try_from(limit).map_err(|_| StoreError::IdentifierRange(limit as u64))?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    row.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default(),
                    row.get::<_, Option<Vec<u8>>>(6)?.unwrap_or_default(),
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Option<String>>(10)?.unwrap_or_default(),
                    row.get::<_, i64>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, i64>(13)? == 1,
                ))
            },
        )?;
        let mut messages = Vec::new();
        for row in rows {
            let (
                id,
                client_key,
                channel_id,
                author_id,
                content,
                attachments,
                reactions,
                reply_to,
                edited_at,
                sequence,
                created_at,
                state,
                nonce,
                origin_remote,
            ) = row?;
            let id = from_i64(id)?;
            messages.push(CachedMessage {
                id,
                client_key: client_key.unwrap_or_else(|| id.to_string()),
                channel_id: from_i64(channel_id)?,
                author_id: from_i64(author_id)?,
                reply_to: reply_to.map(from_i64).transpose()?,
                content,
                attachments: if attachments.is_empty() {
                    Vec::new()
                } else {
                    serde_json::from_slice(&attachments)?
                },
                reactions: if reactions.is_empty() {
                    Vec::new()
                } else {
                    serde_json::from_slice(&reactions)?
                },
                sequence: from_i64(sequence)?,
                created_at,
                edited_at,
                state: MessageState::from_i64(state)?,
                nonce,
                origin_remote,
            });
        }
        Ok(messages)
    }

    pub fn pending_messages(&self) -> Result<Vec<PendingMessage>, StoreError> {
        #[derive(Deserialize)]
        struct OutboxPayload {
            content: String,
            #[serde(default)]
            reply_to: Option<u64>,
            #[serde(default)]
            attachments: Vec<MessageAttachment>,
        }

        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT m.id, o.nonce, o.channel_id, o.payload, o.attempts
             FROM outbox o
             JOIN messages m ON m.nonce = o.nonce
             WHERE m.local_state = 1
               AND o.next_attempt_at <= ?1
             ORDER BY o.next_attempt_at ASC, o.created_at ASC",
        )?;
        let rows = statement.query_map([Utc::now().timestamp_millis()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, u32>(4)?,
            ))
        })?;
        let mut pending = Vec::new();
        for row in rows {
            let (temporary_id, nonce, channel_id, payload, attempts) = row?;
            let payload: OutboxPayload = serde_json::from_slice(&payload)?;
            pending.push(PendingMessage {
                temporary_id: from_i64(temporary_id)?,
                nonce,
                channel_id: from_i64(channel_id)?,
                reply_to: payload.reply_to,
                content: payload.content,
                attachments: payload.attachments,
                attempts,
            });
        }
        Ok(pending)
    }

    pub fn record_attempt(&self, nonce: &str) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let attempts = connection
            .query_row(
                "SELECT attempts FROM outbox WHERE nonce = ?1",
                [nonce],
                |row| row.get::<_, u32>(0),
            )
            .optional()?;
        let Some(attempts) = attempts else {
            return Ok(());
        };
        let attempts = attempts.saturating_add(1);
        let next_attempt_at = Utc::now()
            .timestamp_millis()
            .saturating_add(retry_delay_millis(attempts));
        connection.execute(
            "UPDATE outbox
                SET attempts = ?2, next_attempt_at = ?3
              WHERE nonce = ?1",
            params![nonce, attempts, next_attempt_at],
        )?;
        Ok(())
    }

    pub fn mark_failed(&self, nonce: &str) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "UPDATE messages SET local_state = ?2 WHERE nonce = ?1",
            params![nonce, MessageState::Failed.as_i64()],
        )?;
        Ok(())
    }

    pub fn requeue_failed_messages(&self) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE messages
                SET local_state = ?1
              WHERE local_state = ?2
                AND nonce IN (SELECT nonce FROM outbox)",
            params![
                MessageState::Pending.as_i64(),
                MessageState::Failed.as_i64()
            ],
        )?;
        transaction.execute(
            "UPDATE outbox
                SET attempts = 0, next_attempt_at = 0
              WHERE nonce IN (
                    SELECT nonce FROM messages WHERE local_state = ?1
              )",
            [MessageState::Pending.as_i64()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn queue_private_history_archive(&self, message_id: u64) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO private_history_outbox (message_id, queued_at, attempts)
             VALUES (?1, ?2, 0)
             ON CONFLICT(message_id) DO NOTHING",
            params![to_i64(message_id)?, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub fn pending_private_history_archives(&self, limit: usize) -> Result<Vec<u64>, StoreError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT message_id
               FROM private_history_outbox
              WHERE next_attempt_at <= ?1
              ORDER BY next_attempt_at ASC, attempts ASC, queued_at ASC
              LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![
                Utc::now().timestamp_millis(),
                i64::try_from(limit).map_err(|_| StoreError::IdentifierRange(limit as u64))?
            ],
            |row| row.get::<_, i64>(0),
        )?;
        rows.map(|row| row.and_then(from_i64))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn record_private_history_attempt(&self, message_id: u64) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "UPDATE private_history_outbox
                SET attempts = attempts + 1,
                    next_attempt_at = ?2
              WHERE message_id = ?1",
            params![to_i64(message_id)?, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub fn complete_private_history_archive(&self, message_id: u64) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM private_history_outbox WHERE message_id = ?1",
            [to_i64(message_id)?],
        )?;
        Ok(())
    }

    pub fn is_remote_channel(&self, channel_id: u64) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        Ok(connection
            .query_row(
                "SELECT origin FROM channels WHERE id = ?1
                 UNION ALL
                 SELECT 1 FROM direct_channels WHERE channel_id = ?1
                 LIMIT 1",
                [to_i64(channel_id)?],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|origin| origin == 1))
    }

    pub fn is_encrypted_channel(&self, channel_id: u64) -> Result<bool, StoreError> {
        Ok(self.channel_encryption(channel_id)?.unwrap_or(false))
    }

    pub fn channel_encryption(&self, channel_id: u64) -> Result<Option<bool>, StoreError> {
        let connection = self.lock()?;
        Ok(connection
            .query_row(
                "SELECT encrypted FROM channels WHERE id = ?1
                 UNION ALL
                 SELECT encrypted FROM direct_channels WHERE channel_id = ?1
                 LIMIT 1",
                [to_i64(channel_id)?],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|encrypted| encrypted == 1))
    }

    pub fn load_mls_state(&self, state_id: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT state FROM mls_state WHERE group_id = ?1",
                [state_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn save_mls_state(
        &self,
        state_id: &[u8],
        state: &[u8],
        epoch: u64,
    ) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO mls_state (group_id, state, epoch)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id) DO UPDATE SET
               state = excluded.state,
               epoch = excluded.epoch",
            params![
                state_id,
                state,
                i64::try_from(epoch).map_err(|_| StoreError::IdentifierRange(epoch))?
            ],
        )?;
        Ok(())
    }

    pub fn save_franking_opening(
        &self,
        message_id: u64,
        sealed_opening: &[u8],
    ) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO message_franking_openings
               (message_id, sealed_opening, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(message_id) DO UPDATE SET
               sealed_opening = excluded.sealed_opening",
            params![
                to_i64(message_id)?,
                sealed_opening,
                Utc::now().timestamp_millis()
            ],
        )?;
        Ok(())
    }

    pub fn load_franking_opening(&self, message_id: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT sealed_opening
                 FROM message_franking_openings
                 WHERE message_id = ?1",
                [to_i64(message_id)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn has_decrypted_message(&self, message_id: u64) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        Ok(connection
            .query_row(
                "SELECT content FROM messages WHERE id = ?1",
                [to_i64(message_id)?],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .is_some_and(|content| !content.is_empty()))
    }

    pub fn snapshot(&self) -> Result<CacheSnapshot, StoreError> {
        let connection = self.lock()?;
        let users = query_users(&connection)?;
        let guilds = query_guilds(&connection)?;
        let channels = query_channels(&connection)?;
        let direct_channels = query_direct_channels(&connection)?;
        let guild_members = query_guild_members(&connection)?;
        let relationships = query_relationships(&connection)?;
        let read_states = query_read_states(&connection)?;
        let messages = query_messages(&connection)?;
        let pending_outbox = connection.query_row(
            "SELECT COUNT(*)
               FROM outbox
               JOIN messages ON messages.nonce = outbox.nonce
              WHERE messages.local_state = ?1",
            [MessageState::Pending.as_i64()],
            |row| row.get::<_, u32>(0),
        )?;
        Ok(CacheSnapshot {
            current_user_id: state_u64(&connection, "current_user_id")?,
            active_guild_id: state_u64(&connection, "active_guild_id")?,
            active_channel_id: state_u64(&connection, "active_channel_id")?,
            active_voice_channel_id: state_u64(&connection, "active_voice_channel_id")?,
            last_sequence: get_state(&connection, "last_sequence")?
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            users,
            guilds,
            channels,
            direct_channels,
            guild_members,
            relationships,
            read_states,
            messages,
            pending_outbox,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.connection
            .lock()
            .map_err(|_| StoreError::LockUnavailable)
    }
}

fn open_keyed_connection(path: &Path, key: &[u8; 32]) -> Result<(Connection, String), StoreError> {
    let connection = Connection::open(path)?;
    let cipher_version = connection
        .pragma_query_value(None, "cipher_version", |row| row.get::<_, String>(0))
        .map_err(|_| StoreError::EncryptionUnavailable)?;
    if cipher_version.trim().is_empty() {
        return Err(StoreError::EncryptionUnavailable);
    }
    apply_raw_cache_key(&connection, key)?;
    connection.execute_batch(
        "PRAGMA cipher_memory_security = ON;
         PRAGMA temp_store = MEMORY;",
    )?;
    connection
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| StoreError::CacheUnlockFailed)?;
    Ok((connection, cipher_version))
}

fn apply_raw_cache_key(connection: &Connection, key: &[u8; 32]) -> Result<(), StoreError> {
    let encoded_key = Zeroizing::new(hex::encode(key));
    let statement = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", encoded_key.as_str()));
    connection
        .execute_batch(statement.as_str())
        .map_err(|_| StoreError::CacheUnlockFailed)
}

fn verify_cache_integrity(connection: &Connection) -> Result<(), StoreError> {
    let result = connection
        .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
        .map_err(|_| StoreError::CacheIntegrityFailed)?;
    if result == "ok" {
        Ok(())
    } else {
        Err(StoreError::CacheIntegrityFailed)
    }
}

fn encrypt_plaintext_cache(path: &Path, key: &[u8; 32]) -> Result<(), StoreError> {
    let temporary = companion_path(path, ENCRYPTION_TEMP_SUFFIX)?;
    let backup = companion_path(path, PLAINTEXT_BACKUP_SUFFIX)?;
    remove_file_if_exists(&temporary)?;
    if backup.exists() {
        scrub_and_remove(&backup)?;
    }

    let source = Connection::open(path)?;
    source.busy_timeout(std::time::Duration::from_secs(5))?;
    source
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| StoreError::CacheMigrationFailed)?;
    let _: (i64, i64, i64) = source
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|_| StoreError::CacheMigrationFailed)?;
    source
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| StoreError::CacheMigrationFailed)?;
    let schema_version: i64 = source
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| StoreError::CacheMigrationFailed)?;
    let temporary_text = temporary.to_string_lossy();
    let encoded_key = Zeroizing::new(hex::encode(key));
    let attach = Zeroizing::new(format!(
        "ATTACH DATABASE ?1 AS encrypted KEY \"x'{}'\"",
        encoded_key.as_str()
    ));
    let export_result = (|| -> Result<(), StoreError> {
        source
            .execute(attach.as_str(), [temporary_text.as_ref()])
            .map_err(|_| StoreError::CacheMigrationFailed)?;
        source
            .execute_batch(
                "PRAGMA encrypted.cipher_memory_security = ON;
                 SELECT sqlcipher_export('encrypted');",
            )
            .map_err(|_| StoreError::CacheMigrationFailed)?;
        source
            .execute_batch(&format!(
                "PRAGMA encrypted.user_version = {schema_version};"
            ))
            .map_err(|_| StoreError::CacheMigrationFailed)?;
        source
            .execute_batch("DETACH DATABASE encrypted;")
            .map_err(|_| StoreError::CacheMigrationFailed)?;
        Ok(())
    })();
    if export_result.is_err() {
        let _ = source.execute_batch("DETACH DATABASE encrypted;");
    }
    drop(source);
    if let Err(error) = export_result {
        remove_file_if_exists(&temporary)?;
        return Err(error);
    }

    let (encrypted, _) = open_keyed_connection(&temporary, key)?;
    verify_cache_integrity(&encrypted)?;
    drop(encrypted);

    remove_sqlite_sidecars(path, true)?;
    fs::rename(path, &backup)?;
    if let Err(error) = fs::rename(&temporary, path) {
        if fs::rename(&backup, path).is_err() {
            return Err(StoreError::CacheMigrationFailed);
        }
        return Err(error.into());
    }

    let final_check = open_keyed_connection(path, key)
        .and_then(|(connection, _)| verify_cache_integrity(&connection));
    if let Err(error) = final_check {
        remove_file_if_exists(path)?;
        fs::rename(&backup, path)?;
        return Err(error);
    }

    scrub_and_remove(&backup)?;
    Ok(())
}

fn recover_interrupted_cache_migration(path: &Path, key: &[u8; 32]) -> Result<(), StoreError> {
    let temporary = companion_path(path, ENCRYPTION_TEMP_SUFFIX)?;
    let backup = companion_path(path, PLAINTEXT_BACKUP_SUFFIX)?;

    if !path.exists() {
        if backup.exists() {
            remove_file_if_exists(&temporary)?;
            fs::rename(&backup, path)?;
        } else if temporary.exists() {
            let (connection, _) = open_keyed_connection(&temporary, key)?;
            verify_cache_integrity(&connection)?;
            drop(connection);
            fs::rename(&temporary, path)?;
        }
        return Ok(());
    }

    if is_plaintext_sqlite(path)? {
        remove_file_if_exists(&temporary)?;
        if backup.exists() {
            scrub_and_remove(&backup)?;
        }
        return Ok(());
    }

    if temporary.exists() || backup.exists() {
        let (connection, _) = open_keyed_connection(path, key)?;
        verify_cache_integrity(&connection)?;
        drop(connection);
        remove_file_if_exists(&temporary)?;
        if backup.exists() {
            scrub_and_remove(&backup)?;
        }
    }
    Ok(())
}

fn companion_path(path: &Path, suffix: &str) -> Result<PathBuf, StoreError> {
    let mut filename = path
        .file_name()
        .map(OsString::from)
        .ok_or(StoreError::InvalidDatabasePath)?;
    filename.push(suffix);
    Ok(path.with_file_name(filename))
}

fn is_plaintext_sqlite(path: &Path) -> Result<bool, StoreError> {
    if !path.exists() || path.metadata()?.len() == 0 {
        return Ok(false);
    }
    let mut header = [0_u8; SQLITE_PLAINTEXT_HEADER.len()];
    let mut file = File::open(path)?;
    if file.read(&mut header)? != header.len() {
        return Ok(false);
    }
    Ok(&header == SQLITE_PLAINTEXT_HEADER)
}

fn remove_sqlite_sidecars(path: &Path, scrub: bool) -> Result<(), StoreError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = companion_path(path, suffix)?;
        if !sidecar.exists() {
            continue;
        }
        if scrub {
            scrub_and_remove(&sidecar)?;
        } else {
            remove_file_if_exists(&sidecar)?;
        }
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn scrub_and_remove(path: &Path) -> Result<(), StoreError> {
    let length = path.metadata()?.len();
    if length > 0 {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let mut random = vec![0_u8; SCRUB_BUFFER_BYTES];
        getrandom::fill(&mut random)
            .map_err(|_| StoreError::InvalidState("secure randomness is unavailable"))?;
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = length;
        while remaining > 0 {
            let count = usize::try_from(remaining.min(random.len() as u64))
                .map_err(|_| StoreError::CacheMigrationFailed)?;
            file.write_all(&random[..count])?;
            remaining -= count as u64;
        }
        file.sync_all()?;
        file.set_len(0)?;
    }
    remove_file_if_exists(path)
}

fn migrate(connection: &Connection) -> Result<(), StoreError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version < 1 {
        connection.execute_batch(LOCAL_SCHEMA_V1)?;
        connection.pragma_update(None, "user_version", 1)?;
    }
    if version < 2 {
        connection.execute_batch(LOCAL_SCHEMA_V2)?;
        connection.pragma_update(None, "user_version", 2)?;
    }
    if version < 3 {
        connection.execute_batch(LOCAL_SCHEMA_V3)?;
        connection.pragma_update(None, "user_version", 3)?;
    }
    if version < 4 {
        connection.execute_batch(LOCAL_SCHEMA_V4)?;
        connection.pragma_update(None, "user_version", 4)?;
    }
    if version < 5 {
        connection.execute_batch(LOCAL_SCHEMA_V5)?;
        connection.pragma_update(None, "user_version", 5)?;
    }
    if version < 6 {
        connection.execute_batch(LOCAL_SCHEMA_V6)?;
        connection.pragma_update(None, "user_version", 6)?;
    }
    if version < 7 {
        connection.execute_batch(LOCAL_SCHEMA_V7)?;
        connection.pragma_update(None, "user_version", 7)?;
    }
    if version < 8 {
        connection.execute_batch(LOCAL_SCHEMA_V8)?;
        connection.pragma_update(None, "user_version", 8)?;
    }
    if version < 9 {
        connection.execute_batch(LOCAL_SCHEMA_V9)?;
        connection.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    }
    Ok(())
}

fn cached_remote_message(message: &Message, client_key: Option<String>) -> CachedMessage {
    CachedMessage {
        id: message.id.raw(),
        client_key: client_key.unwrap_or_else(|| message.id.to_string()),
        channel_id: message.channel_id.raw(),
        author_id: message.author_id.raw(),
        reply_to: message.reply_to.map(MessageId::raw),
        content: message.content.clone(),
        attachments: message.attachments.clone(),
        reactions: message.reactions.clone(),
        sequence: message.sequence,
        created_at: message.created_at.to_rfc3339(),
        edited_at: message.edited_at.map(|value| value.to_rfc3339()),
        state: MessageState::Sent,
        nonce: None,
        origin_remote: true,
    }
}

fn stored_client_key(
    connection: &Connection,
    message_id: u64,
) -> Result<Option<String>, StoreError> {
    connection
        .query_row(
            "SELECT client_key FROM messages WHERE id = ?1",
            [to_i64(message_id)?],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn upsert_user(connection: &Connection, user: &CachedUser) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO users (id, username, display_name, avatar_hash, updated_at, origin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET
           username = excluded.username,
           display_name = excluded.display_name,
           avatar_hash = excluded.avatar_hash,
           updated_at = excluded.updated_at,
           origin = excluded.origin",
        params![
            to_i64(user.id)?,
            user.handle,
            user.display_name,
            user.avatar_url,
            Utc::now().timestamp_millis(),
            i64::from(user.origin_remote)
        ],
    )?;
    Ok(())
}

fn upsert_guild(connection: &Connection, guild: &CachedGuild) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO guilds
           (id, owner_id, name, accent, created_at, current_permissions, origin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO UPDATE SET
           owner_id = excluded.owner_id,
           name = excluded.name,
           accent = excluded.accent,
           created_at = excluded.created_at,
           current_permissions = excluded.current_permissions,
           origin = excluded.origin",
        params![
            to_i64(guild.id)?,
            to_i64(guild.owner_id)?,
            guild.name,
            i64::from(guild.accent),
            guild.created_at,
            i64::try_from(guild.current_permissions)
                .map_err(|_| StoreError::IdentifierRange(guild.current_permissions))?,
            i64::from(guild.origin_remote)
        ],
    )?;
    Ok(())
}

fn upsert_channel(connection: &Connection, channel: &CachedChannel) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO channels
           (id, guild_id, name, type, position, e2ee, encrypted, created_at, origin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8)
         ON CONFLICT(id) DO UPDATE SET
           guild_id = excluded.guild_id,
           name = excluded.name,
           type = excluded.type,
           position = excluded.position,
           e2ee = excluded.e2ee,
           encrypted = excluded.encrypted,
           created_at = excluded.created_at,
           origin = excluded.origin",
        params![
            to_i64(channel.id)?,
            to_i64(channel.guild_id)?,
            channel.name,
            channel_kind_to_i64(channel.kind),
            channel.position,
            i64::from(channel.encrypted),
            channel.created_at,
            i64::from(channel.origin_remote)
        ],
    )?;
    Ok(())
}

fn upsert_direct_channel(
    connection: &Connection,
    channel: &CachedDirectChannel,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO direct_channels
           (channel_id, recipient_ids, last_message_id, encrypted, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(channel_id) DO UPDATE SET
           recipient_ids = excluded.recipient_ids,
           last_message_id = excluded.last_message_id,
           encrypted = excluded.encrypted,
           created_at = excluded.created_at",
        params![
            to_i64(channel.id)?,
            serde_json::to_vec(&channel.recipient_ids)?,
            channel.last_message_id.map(to_i64).transpose()?,
            i64::from(channel.encrypted),
            channel.created_at,
        ],
    )?;
    Ok(())
}

fn upsert_remote_social_state(
    connection: &Connection,
    snapshot: &SyncSnapshot,
) -> Result<(), StoreError> {
    for direct in &snapshot.direct_channels {
        let recipient_ids = direct
            .recipients
            .iter()
            .map(|recipient| recipient.id.raw())
            .collect::<Vec<_>>();
        upsert_direct_channel(
            connection,
            &CachedDirectChannel {
                id: direct.id.raw(),
                recipient_ids,
                last_message_id: direct.last_message_id.map(MessageId::raw),
                encrypted: direct.encrypted,
                created_at: direct.created_at.to_rfc3339(),
            },
        )?;
        let other = direct
            .recipients
            .iter()
            .find(|recipient| recipient.id != snapshot.current_user.id)
            .or_else(|| direct.recipients.first());
        upsert_channel(
            connection,
            &CachedChannel {
                id: direct.id.raw(),
                guild_id: 0,
                name: other.map_or_else(
                    || "Direct message".to_owned(),
                    |recipient| {
                        if recipient.display_name.is_empty() {
                            recipient.handle.clone()
                        } else {
                            recipient.display_name.clone()
                        }
                    },
                ),
                kind: ChannelKind::Text,
                position: 0,
                encrypted: direct.encrypted,
                created_at: direct.created_at.to_rfc3339(),
                origin_remote: true,
            },
        )?;
    }
    for relationship in &snapshot.relationships {
        upsert_relationship(
            connection,
            &CachedRelationship {
                user_id: relationship.user.id.raw(),
                kind: relationship.kind,
                since: relationship.since.to_rfc3339(),
            },
        )?;
    }
    for read_state in &snapshot.read_states {
        upsert_read_state(connection, read_state)?;
    }
    Ok(())
}

fn upsert_relationship(
    connection: &Connection,
    relationship: &CachedRelationship,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO relationships (user_id, kind, since)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id) DO UPDATE SET
           kind = excluded.kind,
           since = excluded.since",
        params![
            to_i64(relationship.user_id)?,
            relationship_kind_to_i64(relationship.kind),
            relationship.since,
        ],
    )?;
    Ok(())
}

fn upsert_read_state(connection: &Connection, state: &ReadState) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO read_state (channel_id, last_read_id, mention_count)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(channel_id) DO UPDATE SET
           last_read_id = CASE
             WHEN read_state.last_read_id IS NULL THEN excluded.last_read_id
             WHEN excluded.last_read_id IS NULL THEN read_state.last_read_id
             ELSE MAX(read_state.last_read_id, excluded.last_read_id)
           END,
           mention_count = excluded.mention_count",
        params![
            to_i64(state.channel_id.raw())?,
            state
                .last_message_id
                .map(|message_id| to_i64(message_id.raw()))
                .transpose()?,
            i64::from(state.mention_count),
        ],
    )?;
    Ok(())
}

fn upsert_message(connection: &Connection, message: &CachedMessage) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO messages
           (id, channel_id, author_id, content, attachments, reactions, edited_at,
            reply_to_id, local_state, nonce, client_key, created_at, sequence, origin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
         ON CONFLICT(id) DO UPDATE SET
           channel_id = excluded.channel_id,
           author_id = excluded.author_id,
           reply_to_id = excluded.reply_to_id,
           content = CASE
             WHEN excluded.content = '' AND messages.content <> ''
               THEN messages.content
             ELSE excluded.content
           END,
           attachments = excluded.attachments,
           reactions = excluded.reactions,
           edited_at = excluded.edited_at,
           local_state = excluded.local_state,
           nonce = excluded.nonce,
           client_key = excluded.client_key,
           created_at = excluded.created_at,
           sequence = excluded.sequence,
           origin = excluded.origin",
        params![
            to_i64(message.id)?,
            to_i64(message.channel_id)?,
            to_i64(message.author_id)?,
            message.content,
            serde_json::to_vec(&message.attachments)?,
            serde_json::to_vec(&message.reactions)?,
            message.edited_at,
            message.reply_to.map(to_i64).transpose()?,
            message.state.as_i64(),
            message.nonce,
            message.client_key,
            message.created_at,
            i64::try_from(message.sequence)
                .map_err(|_| StoreError::IdentifierRange(message.sequence))?,
            i64::from(message.origin_remote),
        ],
    )?;
    Ok(())
}

fn advance_direct_channel(
    connection: &Connection,
    message: &CachedMessage,
) -> Result<(), StoreError> {
    connection.execute(
        "UPDATE direct_channels
         SET last_message_id = CASE
           WHEN last_message_id IS NULL OR last_message_id < ?1 THEN ?1
           ELSE last_message_id
         END
         WHERE channel_id = ?2",
        params![to_i64(message.id)?, to_i64(message.channel_id)?],
    )?;
    Ok(())
}

fn query_users(connection: &Connection) -> Result<Vec<CachedUser>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT id, username, display_name, avatar_hash, origin
         FROM users ORDER BY id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(CachedUser {
            id: from_i64(row.get(0)?)?,
            handle: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            display_name: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            avatar_url: row.get(3)?,
            origin_remote: row.get::<_, i64>(4)? == 1,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn query_guilds(connection: &Connection) -> Result<Vec<CachedGuild>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT id, owner_id, name, accent, created_at, current_permissions, origin
         FROM guilds ORDER BY created_at ASC, id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(CachedGuild {
            id: from_i64(row.get(0)?)?,
            owner_id: from_i64(row.get(1)?)?,
            name: row.get(2)?,
            accent: row.get(3)?,
            created_at: row.get(4)?,
            current_permissions: from_i64(row.get(5)?)?,
            origin_remote: row.get::<_, i64>(6)? == 1,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn query_channels(connection: &Connection) -> Result<Vec<CachedChannel>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT id, guild_id, name, type, position, encrypted, created_at, origin
         FROM channels ORDER BY guild_id ASC, position ASC, id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        let kind = channel_kind_from_i64(row.get(3)?);
        Ok((
            from_i64(row.get(0)?)?,
            from_i64(row.get(1)?)?,
            row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            kind,
            row.get::<_, Option<i32>>(4)?.unwrap_or_default(),
            row.get::<_, i64>(5)? == 1,
            row.get::<_, Option<String>>(6)?.unwrap_or_default(),
            row.get::<_, i64>(7)? == 1,
        ))
    })?;
    let mut channels = Vec::new();
    for row in rows {
        let (id, guild_id, name, kind, position, encrypted, created_at, origin_remote) = row?;
        channels.push(CachedChannel {
            id,
            guild_id,
            name,
            kind: kind?,
            position,
            encrypted,
            created_at,
            origin_remote,
        });
    }
    Ok(channels)
}

fn query_direct_channels(connection: &Connection) -> Result<Vec<CachedDirectChannel>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT channel_id, recipient_ids, last_message_id, encrypted, created_at
         FROM direct_channels
         ORDER BY last_message_id DESC, created_at DESC, channel_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            from_i64(row.get(0)?)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Option<i64>>(2)?.map(from_i64).transpose()?,
            row.get::<_, i64>(3)? == 1,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut channels = Vec::new();
    for row in rows {
        let (id, recipient_ids, last_message_id, encrypted, created_at) = row?;
        channels.push(CachedDirectChannel {
            id,
            recipient_ids: serde_json::from_slice(&recipient_ids)?,
            last_message_id,
            encrypted,
            created_at,
        });
    }
    Ok(channels)
}

fn query_guild_members(connection: &Connection) -> Result<Vec<CachedGuildMember>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT guild_id, user_id
         FROM guild_member_users
         ORDER BY guild_id, user_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(CachedGuildMember {
            guild_id: from_i64(row.get(0)?)?,
            user_id: from_i64(row.get(1)?)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn query_relationships(connection: &Connection) -> Result<Vec<CachedRelationship>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT user_id, kind, since
         FROM relationships
         ORDER BY kind, user_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            from_i64(row.get(0)?)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut relationships = Vec::new();
    for row in rows {
        let (user_id, kind, since) = row?;
        relationships.push(CachedRelationship {
            user_id,
            kind: relationship_kind_from_i64(kind)?,
            since,
        });
    }
    Ok(relationships)
}

fn query_read_states(connection: &Connection) -> Result<Vec<ReadState>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT channel_id, last_read_id, mention_count
         FROM read_state ORDER BY channel_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            from_i64(row.get(0)?)?,
            row.get::<_, Option<i64>>(1)?.map(from_i64).transpose()?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut states = Vec::new();
    for row in rows {
        let (channel_id, last_message_id, mention_count) = row?;
        states.push(ReadState {
            channel_id: ChannelId::from_raw(channel_id)
                .map_err(|_| StoreError::IdentifierRange(channel_id))?,
            last_message_id: last_message_id
                .map(|message_id| {
                    MessageId::from_raw(message_id)
                        .map_err(|_| StoreError::IdentifierRange(message_id))
                })
                .transpose()?,
            mention_count: u32::try_from(mention_count)
                .map_err(|_| StoreError::IdentifierRange(mention_count.unsigned_abs()))?,
        });
    }
    Ok(states)
}

fn query_messages(connection: &Connection) -> Result<Vec<CachedMessage>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT id, client_key, channel_id, author_id, content, attachments, reactions,
                reply_to_id, edited_at, sequence, created_at, local_state, nonce, origin
         FROM (
           SELECT id, client_key, channel_id, author_id, content, attachments, reactions,
                  reply_to_id, edited_at, sequence, created_at, local_state, nonce, origin,
                  ROW_NUMBER() OVER (PARTITION BY channel_id ORDER BY id DESC) AS row_number
           FROM messages
           WHERE deleted = 0
         )
         WHERE row_number <= 100
         ORDER BY channel_id ASC, id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            from_i64(row.get(0)?)?,
            row.get::<_, Option<String>>(1)?,
            from_i64(row.get(2)?)?,
            from_i64(row.get(3)?)?,
            row.get::<_, Option<String>>(4)?.unwrap_or_default(),
            row.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default(),
            row.get::<_, Option<Vec<u8>>>(6)?.unwrap_or_default(),
            row.get::<_, Option<i64>>(7)?.map(from_i64).transpose()?,
            row.get::<_, Option<String>>(8)?,
            from_i64(row.get(9)?)?,
            row.get::<_, Option<String>>(10)?.unwrap_or_default(),
            row.get::<_, i64>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, i64>(13)? == 1,
        ))
    })?;
    let mut messages = Vec::new();
    for row in rows {
        let (
            id,
            client_key,
            channel_id,
            author_id,
            content,
            attachments,
            reactions,
            reply_to,
            edited_at,
            sequence,
            created_at,
            state,
            nonce,
            origin_remote,
        ) = row?;
        messages.push(CachedMessage {
            id,
            client_key: client_key.unwrap_or_else(|| id.to_string()),
            channel_id,
            author_id,
            reply_to,
            content,
            attachments: if attachments.is_empty() {
                Vec::new()
            } else {
                serde_json::from_slice(&attachments)?
            },
            reactions: if reactions.is_empty() {
                Vec::new()
            } else {
                serde_json::from_slice(&reactions)?
            },
            sequence,
            created_at,
            edited_at,
            state: MessageState::from_i64(state)?,
            nonce,
            origin_remote,
        });
    }
    Ok(messages)
}

fn channel_kind_to_i64(kind: ChannelKind) -> i64 {
    match kind {
        ChannelKind::Text => 0,
        ChannelKind::Voice => 1,
    }
}

fn channel_kind_from_i64(value: i64) -> Result<ChannelKind, StoreError> {
    match value {
        0 => Ok(ChannelKind::Text),
        1 => Ok(ChannelKind::Voice),
        other => Err(StoreError::InvalidChannelKind(other)),
    }
}

const fn relationship_kind_to_i64(kind: RelationshipKind) -> i64 {
    match kind {
        RelationshipKind::Incoming => 0,
        RelationshipKind::Outgoing => 1,
        RelationshipKind::Friend => 2,
        RelationshipKind::Blocked => 3,
    }
}

fn relationship_kind_from_i64(value: i64) -> Result<RelationshipKind, StoreError> {
    match value {
        0 => Ok(RelationshipKind::Incoming),
        1 => Ok(RelationshipKind::Outgoing),
        2 => Ok(RelationshipKind::Friend),
        3 => Ok(RelationshipKind::Blocked),
        other => Err(StoreError::InvalidRelationshipKind(other)),
    }
}

fn set_state(connection: &Connection, key: &str, value: &str) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO app_state (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn get_state(connection: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    connection
        .query_row("SELECT value FROM app_state WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()
        .map_err(Into::into)
}

fn state_u64(connection: &Connection, key: &str) -> Result<Option<u64>, StoreError> {
    get_state(connection, key)?
        .map(|value| {
            value
                .parse()
                .map_err(|_| StoreError::InvalidState("stored identifier is invalid"))
        })
        .transpose()
}

fn to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::IdentifierRange(value))
}

fn retry_delay_millis(attempts: u32) -> i64 {
    let shift = attempts.saturating_sub(1).min(6);
    (1_i64 << shift).saturating_mul(1_000).min(60_000)
}

fn from_i64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

#[cfg(test)]
mod tests {
    use exo_domain::{
        AttachmentId, ChannelId, DirectChannel, MessageId, ReadState, Relationship,
        RelationshipKind, SyncSnapshot, User, UserId,
    };

    use super::*;

    fn seed_identity(store: &LocalStore) {
        store
            .put_user(&CachedUser {
                id: 1,
                handle: "erix".into(),
                display_name: "Erix".into(),
                avatar_url: None,
                origin_remote: false,
            })
            .unwrap();
        store
            .put_guild(&CachedGuild {
                id: 10,
                owner_id: 1,
                name: "On this device".into(),
                accent: 0x008B_7CFF,
                created_at: Utc::now().to_rfc3339(),
                current_permissions: 0,
                origin_remote: false,
            })
            .unwrap();
        store
            .put_channel(&CachedChannel {
                id: 11,
                guild_id: 10,
                name: "notes".into(),
                kind: ChannelKind::Text,
                position: 0,
                encrypted: false,
                created_at: Utc::now().to_rfc3339(),
                origin_remote: false,
            })
            .unwrap();
        store.set_current_user(1).unwrap();
        store.set_active_context(10, 11, None).unwrap();
    }

    #[test]
    fn channel_encryption_distinguishes_plaintext_encrypted_missing_and_invalid_ids() {
        let store = LocalStore::open_in_memory().unwrap();
        seed_identity(&store);
        assert_eq!(store.channel_encryption(11).unwrap(), Some(false));
        store
            .put_channel(&CachedChannel {
                id: 12,
                guild_id: 10,
                name: "private".into(),
                kind: ChannelKind::Text,
                position: 1,
                encrypted: true,
                created_at: Utc::now().to_rfc3339(),
                origin_remote: true,
            })
            .unwrap();
        assert_eq!(store.channel_encryption(12).unwrap(), Some(true));
        assert_eq!(store.channel_encryption(99).unwrap(), None);
        assert!(matches!(
            store.channel_encryption(u64::MAX),
            Err(StoreError::IdentifierRange(u64::MAX))
        ));
    }

    #[test]
    fn corrupted_negative_and_text_identifiers_fail_closed() {
        assert!(from_i64(-1).is_err());

        let store = LocalStore::open_in_memory().unwrap();
        seed_identity(&store);
        {
            let connection = store.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO users (id, username, display_name, avatar_hash, origin)
                     VALUES (-1, 'corrupt', 'Corrupt', NULL, 1)",
                    [],
                )
                .unwrap();
        }
        assert!(matches!(store.snapshot(), Err(StoreError::Sqlite(_))));

        let store = LocalStore::open_in_memory().unwrap();
        seed_identity(&store);
        {
            let connection = store.lock().unwrap();
            set_state(&connection, "current_user_id", "not-an-id").unwrap();
        }
        assert!(matches!(
            store.snapshot(),
            Err(StoreError::InvalidState("stored identifier is invalid"))
        ));
    }

    #[test]
    fn private_history_archive_queue_is_durable_until_completion() {
        let store = LocalStore::open_in_memory().unwrap();
        store.queue_private_history_archive(42).unwrap();
        store.queue_private_history_archive(42).unwrap();
        store.record_private_history_attempt(42).unwrap();
        assert_eq!(
            store.pending_private_history_archives(20).unwrap(),
            vec![42]
        );
        store.complete_private_history_archive(42).unwrap();
        assert!(
            store
                .pending_private_history_archives(20)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn outbox_survives_reopening_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.sqlite3");
        {
            let store = LocalStore::open(&path).unwrap();
            seed_identity(&store);
            store
                .enqueue_message(12, "nonce-1", 11, 1, None, "offline", &[], Utc::now())
                .unwrap();
        }
        let reopened = LocalStore::open(&path).unwrap();
        assert_eq!(reopened.pending_messages().unwrap().len(), 1);
        assert_eq!(reopened.snapshot().unwrap().pending_outbox, 1);
        assert_eq!(
            reopened.snapshot().unwrap().messages[0].state,
            MessageState::Pending
        );
    }

    #[test]
    fn encrypted_cache_hides_content_and_rejects_the_wrong_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.sqlite3");
        let key = [7_u8; 32];
        let private_text = "violet submarine cache sentinel";
        {
            let store = LocalStore::open_encrypted(&path, &key).unwrap();
            assert!(store.cipher_version().is_some());
            seed_identity(&store);
            store
                .enqueue_message(
                    12,
                    "sealed-outbox",
                    11,
                    1,
                    None,
                    private_text,
                    &[],
                    Utc::now(),
                )
                .unwrap();
        }

        let bytes = fs::read(&path).unwrap();
        assert_ne!(
            bytes.get(..SQLITE_PLAINTEXT_HEADER.len()),
            Some(SQLITE_PLAINTEXT_HEADER.as_slice())
        );
        assert!(
            !bytes
                .windows(private_text.len())
                .any(|window| window == private_text.as_bytes())
        );
        for suffix in ["-wal", "-shm"] {
            let sidecar = companion_path(&path, suffix).unwrap();
            if sidecar.exists() {
                assert!(
                    !fs::read(sidecar)
                        .unwrap()
                        .windows(private_text.len())
                        .any(|window| window == private_text.as_bytes())
                );
            }
        }

        let raw = Connection::open(&path).unwrap();
        assert!(
            raw.query_row("SELECT COUNT(*) FROM messages", [], |row| row
                .get::<_, i64>(0))
                .is_err()
        );
        drop(raw);
        assert!(matches!(
            LocalStore::open_encrypted(&path, &[8_u8; 32]),
            Err(StoreError::CacheUnlockFailed)
        ));

        let reopened = LocalStore::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            reopened.pending_messages().unwrap()[0].content,
            private_text
        );
        assert_eq!(
            reopened
                .search_cached_messages(10, "submarine", 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn encrypted_cache_rejects_page_tampering_without_resetting_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.sqlite3");
        let key = [9_u8; 32];
        {
            let store = LocalStore::open_encrypted(&path, &key).unwrap();
            seed_identity(&store);
            store
                .enqueue_message(
                    12,
                    "tamper-outbox",
                    11,
                    1,
                    None,
                    "authenticated page sentinel",
                    &[],
                    Utc::now(),
                )
                .unwrap();
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(200)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(200)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let tampered_length = path.metadata().unwrap().len();

        assert!(matches!(
            LocalStore::open_encrypted(&path, &key),
            Err(StoreError::CacheUnlockFailed | StoreError::CacheIntegrityFailed)
        ));
        assert!(path.exists());
        assert_eq!(path.metadata().unwrap().len(), tampered_length);
    }

    #[test]
    fn plaintext_cache_is_exported_and_interrupted_swap_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.sqlite3");
        let key = [11_u8; 32];
        let private_text = "migration keeps the durable outbox";
        {
            let store = LocalStore::open(&path).unwrap();
            seed_identity(&store);
            store
                .enqueue_message(
                    12,
                    "migration-outbox",
                    11,
                    1,
                    None,
                    private_text,
                    &[],
                    Utc::now(),
                )
                .unwrap();
        }
        assert!(is_plaintext_sqlite(&path).unwrap());

        let backup = companion_path(&path, PLAINTEXT_BACKUP_SUFFIX).unwrap();
        fs::rename(&path, &backup).unwrap();
        let stale_temporary = companion_path(&path, ENCRYPTION_TEMP_SUFFIX).unwrap();
        fs::write(&stale_temporary, b"incomplete encrypted export").unwrap();

        let migrated = LocalStore::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            migrated.pending_messages().unwrap()[0].content,
            private_text
        );
        assert!(migrated.cipher_version().is_some());
        drop(migrated);

        assert!(!is_plaintext_sqlite(&path).unwrap());
        assert!(!backup.exists());
        assert!(!stale_temporary.exists());
        assert!(
            !fs::read(&path)
                .unwrap()
                .windows(private_text.len())
                .any(|window| window == private_text.as_bytes())
        );
    }

    #[test]
    fn sealed_franking_opening_survives_reopening_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.sqlite3");
        let sealed = b"opaque-device-bound-report-opening";
        {
            let store = LocalStore::open(&path).unwrap();
            store.save_franking_opening(41, sealed).unwrap();
        }
        let reopened = LocalStore::open(&path).unwrap();
        assert_eq!(
            reopened.load_franking_opening(41).unwrap(),
            Some(sealed.to_vec())
        );
        assert_eq!(reopened.load_franking_opening(42).unwrap(), None);
    }

    #[test]
    fn acknowledgement_replaces_the_temporary_id_but_keeps_the_client_key() {
        let store = LocalStore::open_in_memory().unwrap();
        seed_identity(&store);
        store
            .enqueue_message(12, "stable-key", 11, 1, None, "hello", &[], Utc::now())
            .unwrap();
        let message = Message {
            id: MessageId::from_raw(99).unwrap(),
            channel_id: ChannelId::from_raw(11).unwrap(),
            author_id: UserId::from_raw(1).unwrap(),
            reply_to: None,
            content: "hello".into(),
            encryption: None,
            attachments: Vec::new(),
            reactions: Vec::new(),
            sequence: 4,
            created_at: Utc::now(),
            edited_at: None,
        };
        let acknowledged = store.acknowledge_message("stable-key", &message).unwrap();

        assert_eq!(acknowledged.id, 99);
        assert_eq!(acknowledged.client_key, "stable-key");
        assert_eq!(store.snapshot().unwrap().pending_outbox, 0);
        assert_eq!(store.snapshot().unwrap().messages.len(), 1);
        assert_eq!(
            store.upsert_remote_message(&message).unwrap().client_key,
            "stable-key"
        );
    }

    #[test]
    fn message_windows_never_exceed_one_hundred_rows_per_channel() {
        let store = LocalStore::open_in_memory().unwrap();
        seed_identity(&store);
        for id in 100..=225 {
            store
                .insert_local_message(id, 11, 1, None, &format!("message {id}"), Utc::now())
                .unwrap();
        }
        assert_eq!(store.snapshot().unwrap().messages.len(), 100);
    }

    #[test]
    fn restored_private_history_is_durable_and_searchable_beyond_the_view_window() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.sqlite3");
        {
            let store = LocalStore::open(&path).unwrap();
            seed_identity(&store);
            for id in 100..=225 {
                store
                    .upsert_restored_private_message(&CachedMessage {
                        id,
                        client_key: "untrusted-archive-key".into(),
                        channel_id: 11,
                        author_id: 1,
                        reply_to: None,
                        content: format!("restored private history sentinel {id}"),
                        attachments: Vec::new(),
                        reactions: Vec::new(),
                        sequence: id,
                        created_at: Utc::now().to_rfc3339(),
                        edited_at: None,
                        state: MessageState::Pending,
                        nonce: Some("must-not-survive".into()),
                        origin_remote: false,
                    })
                    .unwrap();
            }
            assert_eq!(store.snapshot().unwrap().messages.len(), 100);
            assert_eq!(
                store
                    .search_cached_messages(10, "sentinel 100", 10)
                    .unwrap()
                    .len(),
                1
            );
        }

        let reopened = LocalStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .search_cached_messages(10, "sentinel 100", 10)
                .unwrap()
                .len(),
            1
        );
        let newest = reopened.snapshot().unwrap().messages;
        assert!(newest.iter().all(|message| {
            message.state == MessageState::Sent && message.nonce.is_none() && message.origin_remote
        }));
    }

    #[test]
    fn encrypted_search_and_attachment_outbox_survive_locally() {
        let store = LocalStore::open_in_memory().unwrap();
        seed_identity(&store);
        store
            .put_channel(&CachedChannel {
                id: 11,
                guild_id: 10,
                name: "sealed".into(),
                kind: ChannelKind::Text,
                position: 0,
                encrypted: true,
                created_at: Utc::now().to_rfc3339(),
                origin_remote: true,
            })
            .unwrap();
        let attachment = MessageAttachment {
            id: AttachmentId::from_raw(77).unwrap(),
            filename: "proof.txt".into(),
            content_type: "text/plain".into(),
            size: 5,
            url: "https://cdn.example/proof".into(),
            width: None,
            height: None,
            animated: false,
            encryption: None,
        };
        store
            .enqueue_message(
                12,
                "attachment-outbox",
                11,
                1,
                None,
                "locally searchable phrase",
                std::slice::from_ref(&attachment),
                Utc::now(),
            )
            .unwrap();
        let matches = store
            .search_encrypted_messages(10, "searchable phrase", 20)
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].attachments, vec![attachment.clone()]);
        assert_eq!(
            store.pending_messages().unwrap()[0].attachments,
            vec![attachment]
        );
    }

    #[test]
    fn relationships_direct_messages_and_read_state_survive_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.sqlite3");
        let now = Utc::now();
        let current_user = User {
            id: UserId::from_raw(1).unwrap(),
            handle: "erix".into(),
            display_name: "Erix".into(),
            avatar_url: None,
            created_at: now,
        };
        let friend = User {
            id: UserId::from_raw(2).unwrap(),
            handle: "marin".into(),
            display_name: "Marin".into(),
            avatar_url: None,
            created_at: now,
        };
        let channel_id = ChannelId::from_raw(20).unwrap();
        let message_id = MessageId::from_raw(21).unwrap();
        let snapshot = SyncSnapshot {
            current_user: current_user.clone(),
            users: vec![friend.clone()],
            guilds: Vec::new(),
            guild_access: Vec::new(),
            guild_members: Vec::new(),
            channels: Vec::new(),
            direct_channels: vec![DirectChannel {
                id: channel_id,
                recipients: vec![current_user.clone(), friend.clone()],
                last_message_id: Some(message_id),
                encrypted: false,
                created_at: now,
            }],
            relationships: vec![Relationship {
                user: friend.clone(),
                kind: RelationshipKind::Friend,
                since: now,
            }],
            read_states: vec![ReadState {
                channel_id,
                last_message_id: Some(message_id),
                mention_count: 0,
            }],
            presences: Vec::new(),
            messages: vec![Message {
                id: message_id,
                channel_id,
                author_id: friend.id,
                reply_to: None,
                content: "durable direct message".into(),
                encryption: None,
                attachments: Vec::new(),
                reactions: Vec::new(),
                sequence: 7,
                created_at: now,
                edited_at: None,
            }],
            last_sequence: 7,
        };
        {
            let store = LocalStore::open(&path).unwrap();
            store.apply_remote_snapshot(&snapshot).unwrap();
        }

        let reopened = LocalStore::open(&path).unwrap();
        let cached = reopened.snapshot().unwrap();
        assert_eq!(cached.active_guild_id, Some(0));
        assert_eq!(cached.active_channel_id, Some(channel_id.raw()));
        assert_eq!(cached.direct_channels.len(), 1);
        assert_eq!(
            cached.direct_channels[0].last_message_id,
            Some(message_id.raw())
        );
        assert_eq!(cached.relationships.len(), 1);
        assert_eq!(cached.relationships[0].kind, RelationshipKind::Friend);
        assert_eq!(cached.read_states[0].last_message_id, Some(message_id));
        assert_eq!(cached.messages[0].content, "durable direct message");
        let matches = reopened
            .search_cached_messages(0, "durable direct", 20)
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].channel_id, channel_id.raw());
    }

    #[test]
    fn direct_unread_summary_advances_with_live_messages_and_read_state() {
        let store = LocalStore::open_in_memory().unwrap();
        seed_identity(&store);
        let now = Utc::now();
        let channel_id = ChannelId::from_raw(20).unwrap();
        {
            let connection = store.lock().unwrap();
            upsert_direct_channel(
                &connection,
                &CachedDirectChannel {
                    id: channel_id.raw(),
                    recipient_ids: vec![1, 2],
                    last_message_id: Some(21),
                    encrypted: true,
                    created_at: now.to_rfc3339(),
                },
            )
            .unwrap();
        }
        store
            .put_read_state(&ReadState {
                channel_id,
                last_message_id: Some(MessageId::from_raw(21).unwrap()),
                mention_count: 0,
            })
            .unwrap();
        let next_message_id = MessageId::from_raw(22).unwrap();
        store
            .upsert_remote_message(&Message {
                id: next_message_id,
                channel_id,
                author_id: UserId::from_raw(2).unwrap(),
                reply_to: None,
                content: "new unread message".into(),
                encryption: None,
                attachments: Vec::new(),
                reactions: Vec::new(),
                sequence: 8,
                created_at: now,
                edited_at: None,
            })
            .unwrap();
        assert_eq!(
            store.direct_unread_state(channel_id.raw()).unwrap(),
            Some((true, 1))
        );
        store
            .put_read_state(&ReadState {
                channel_id,
                last_message_id: Some(next_message_id),
                mention_count: 0,
            })
            .unwrap();
        assert_eq!(
            store.direct_unread_state(channel_id.raw()).unwrap(),
            Some((false, 0))
        );
    }

    #[test]
    fn reply_edit_delete_and_reaction_state_survive_cache_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("conversation-actions.sqlite3");
        {
            let store = LocalStore::open(&path).unwrap();
            seed_identity(&store);
            store
                .insert_local_message(41, 11, 1, None, "first", Utc::now())
                .unwrap();
            store
                .insert_local_message(42, 11, 1, Some(41), "reply", Utc::now())
                .unwrap();
            let edited = store.edit_local_message(42, 1, "edited reply").unwrap();
            assert!(edited.edited_at.is_some());
            let reaction = MessageReactionEvent {
                message_id: MessageId::from_raw(42).unwrap(),
                channel_id: ChannelId::from_raw(11).unwrap(),
                user_id: UserId::from_raw(1).unwrap(),
                emoji: "👍".into(),
                count: 1,
                added: true,
            };
            store.apply_reaction_event(&reaction, 1).unwrap();
        }
        let reopened = LocalStore::open(&path).unwrap();
        let reply = reopened.message_by_id(42).unwrap().unwrap();
        assert_eq!(reply.reply_to, Some(41));
        assert_eq!(reply.content, "edited reply");
        assert!(reply.edited_at.is_some());
        assert_eq!(
            reply.reactions,
            vec![MessageReaction {
                emoji: "👍".into(),
                count: 1,
                me: true,
            }]
        );
        reopened.mark_message_deleted(41, 11).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert!(!snapshot.messages.iter().any(|message| message.id == 41));
        assert_eq!(
            snapshot
                .messages
                .iter()
                .find(|message| message.id == 42)
                .and_then(|message| message.reply_to),
            Some(41)
        );
    }

    #[test]
    fn pending_or_cross_channel_reactions_are_ignored() {
        let store = LocalStore::open_in_memory().unwrap();
        seed_identity(&store);
        store
            .enqueue_message(
                51,
                "pending-reaction",
                11,
                1,
                None,
                "queued",
                &[],
                Utc::now(),
            )
            .unwrap();
        let pending_event = MessageReactionEvent {
            message_id: MessageId::from_raw(51).unwrap(),
            channel_id: ChannelId::from_raw(11).unwrap(),
            user_id: UserId::from_raw(1).unwrap(),
            emoji: "👍".into(),
            count: 1,
            added: true,
        };
        assert!(
            store
                .apply_reaction_event(&pending_event, 1)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .message_by_id(51)
                .unwrap()
                .unwrap()
                .reactions
                .is_empty()
        );

        store
            .insert_local_message(52, 11, 1, None, "delivered", Utc::now())
            .unwrap();
        let wrong_channel = MessageReactionEvent {
            message_id: MessageId::from_raw(52).unwrap(),
            channel_id: ChannelId::from_raw(12).unwrap(),
            user_id: UserId::from_raw(1).unwrap(),
            emoji: "👍".into(),
            count: 1,
            added: true,
        };
        assert!(
            store
                .apply_reaction_event(&wrong_channel, 1)
                .unwrap()
                .is_none()
        );
    }
}
