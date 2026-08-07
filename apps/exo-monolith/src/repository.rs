use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::{Arc, OnceLock},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use exo_domain::{
    AttachmentId, AuditLogEntry, AuditLogId, AutomodAction, AutomodRule, AutomodRuleId,
    AutomodTrigger, Channel, ChannelId, ChannelKind, ChannelOverride, ChannelPermissionOverwrite,
    CreateAutomodRule, DirectChannel, Guild, GuildAccess, GuildBan, GuildId, GuildInvite,
    GuildMember, GuildMemberReference, GuildPermissions, InvitePreview, Message, MessageAttachment,
    MessageDeleteEvent, MessageEncryption, MessageId, MessageReaction, MessageReactionEvent,
    MessageSearchResult, OverwriteTargetKind, PermissionContext, PermissionResolver,
    PrivateHistoryArchive, ReadState, Relationship, RelationshipKind, ReportCategory, ReportId,
    ReportReceipt, Role, RoleGrant, RoleId, SearchExcludedChannel, SearchExclusionReason,
    SearchHit, SyncSnapshot, UpdateAutomodRule, User, UserId,
};
use exo_safety::{AutomodMatch, validate_rule};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{
    PgPool, Row,
    migrate::{MigrateError, Migration, MigrationType, Migrator},
    postgres::{PgPoolOptions, PgRow},
};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::media::AttachmentService;

const AUDIT_GUILD_OWNERSHIP_TRANSFER: i16 = 70;
const AUDIT_GUILD_DELETE: i16 = 71;
const AUDIT_GUILD_OWNER_ACCOUNT_DELETE: i16 = 72;

fn migrator() -> &'static Migrator {
    static MIGRATOR: OnceLock<Migrator> = OnceLock::new();
    MIGRATOR.get_or_init(|| Migrator {
        migrations: Cow::Owned(vec![
            Migration::new(
                1,
                Cow::Borrowed("initial"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0001_initial.sql")),
                false,
            ),
            Migration::new(
                2,
                Cow::Borrowed("auth identity"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0002_auth_identity.sql")),
                false,
            ),
            Migration::new(
                3,
                Cow::Borrowed("durable gateway sequence"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0003_durable_gateway_sequence.sql"
                )),
                false,
            ),
            Migration::new(
                4,
                Cow::Borrowed("guild invites"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0004_guild_invites.sql")),
                false,
            ),
            Migration::new(
                5,
                Cow::Borrowed("role integrity"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0005_role_integrity.sql")),
                false,
            ),
            Migration::new(
                6,
                Cow::Borrowed("channel overwrite integrity"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0006_channel_overwrite_integrity.sql"
                )),
                false,
            ),
            Migration::new(
                7,
                Cow::Borrowed("attachments search"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0007_attachments_search.sql")),
                false,
            ),
            Migration::new(
                8,
                Cow::Borrowed("relationships direct messages"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0008_relationships_direct_messages.sql"
                )),
                false,
            ),
            Migration::new(
                9,
                Cow::Borrowed("abuse controls"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0009_abuse_controls.sql")),
                false,
            ),
            Migration::new(
                10,
                Cow::Borrowed("end to end encryption"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0010_end_to_end_encryption.sql")),
                false,
            ),
            Migration::new(
                11,
                Cow::Borrowed("targeted mls commits"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0011_targeted_mls_commits.sql")),
                false,
            ),
            Migration::new(
                12,
                Cow::Borrowed("current mls membership"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0012_current_mls_membership.sql"
                )),
                false,
            ),
            Migration::new(
                13,
                Cow::Borrowed("guild owner lifecycle"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0013_guild_owner_lifecycle.sql")),
                false,
            ),
            Migration::new(
                14,
                Cow::Borrowed("message conversations"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0014_message_conversations.sql")),
                false,
            ),
            Migration::new(
                15,
                Cow::Borrowed("operator report triage"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0015_operator_report_triage.sql"
                )),
                false,
            ),
            Migration::new(
                16,
                Cow::Borrowed("user profile avatar"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0016_user_profile_avatar.sql")),
                false,
            ),
            Migration::new(
                17,
                Cow::Borrowed("private history recovery"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0017_private_history_recovery.sql"
                )),
                false,
            ),
        ]),
        ..Migrator::DEFAULT
    })
}

#[derive(Clone)]
pub struct Repository(RepositoryBackend);

#[derive(Clone)]
enum RepositoryBackend {
    Memory(Arc<RwLock<MemoryStore>>),
    Postgres(PgPool),
}

#[derive(Default)]
struct MemoryStore {
    users: HashMap<UserId, User>,
    avatars: HashMap<UserId, UserAvatarRecord>,
    guilds: HashMap<GuildId, Guild>,
    deleted_guilds: HashSet<GuildId>,
    owner_deletion_pending: HashSet<GuildId>,
    channels: HashMap<ChannelId, Channel>,
    messages: HashMap<ChannelId, Vec<Message>>,
    reactions: HashSet<(MessageId, ChannelId, UserId, String)>,
    memberships: HashSet<(GuildId, UserId)>,
    roles: HashMap<RoleId, Role>,
    member_roles: HashSet<(GuildId, UserId, RoleId)>,
    channel_overwrites: HashMap<(ChannelId, OverwriteTargetKind, u64), MemoryOverwrite>,
    timeouts: HashMap<(GuildId, UserId), chrono::DateTime<Utc>>,
    bans: HashMap<(GuildId, UserId), MemoryBan>,
    message_nonces: HashMap<(ChannelId, UserId, String), Message>,
    attachments: HashMap<AttachmentId, AttachmentRecord>,
    relationships: HashMap<(UserId, UserId), MemoryRelationship>,
    direct_channels: HashMap<ChannelId, MemoryDirectChannel>,
    direct_pairs: HashMap<(UserId, UserId), ChannelId>,
    read_states: HashMap<(UserId, ChannelId), ReadState>,
    invites: HashMap<Vec<u8>, MemoryInvite>,
    automod_rules: HashMap<AutomodRuleId, AutomodRule>,
    audit_entries: Vec<AuditLogEntry>,
    device_identities: HashMap<Uuid, DeviceIdentityRecord>,
    mls_key_packages: HashMap<[u8; 32], MlsKeyPackageRecord>,
    mls_deliveries: Vec<MlsDeliveryRecord>,
    channel_mls_groups: HashMap<ChannelId, (Vec<u8>, u64)>,
    channel_mls_members: HashMap<ChannelId, HashSet<Uuid>>,
    reports: Vec<ReportRecord>,
    private_history: HashMap<(UserId, MessageId), PrivateHistoryArchive>,
}

#[derive(Clone, Debug)]
pub struct UserAvatarRecord {
    pub content_type: String,
    pub content: Vec<u8>,
    pub content_sha256: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug)]
pub enum UserAvatarUpdate {
    Keep,
    Remove,
    Set(UserAvatarRecord),
}

#[derive(Clone)]
struct MemoryRelationship {
    kind: RelationshipKind,
    since: chrono::DateTime<Utc>,
}

#[derive(Clone)]
struct MemoryDirectChannel {
    id: ChannelId,
    recipients: [UserId; 2],
    last_message_id: Option<MessageId>,
    encrypted: bool,
    mls_group_id: Option<Vec<u8>>,
    mls_epoch: u64,
    created_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct DeviceIdentityRecord {
    pub device_id: Uuid,
    pub user_id: UserId,
    pub signature_key: [u8; 32],
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct MlsKeyPackageRecord {
    pub id: u64,
    pub user_id: UserId,
    pub device_id: Uuid,
    pub reference: [u8; 32],
    pub key_package: Vec<u8>,
    pub cipher_suite: u16,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub claimed_by_device: Option<Uuid>,
    pub claimed_for_channel: Option<ChannelId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsDeliveryRecordKind {
    Welcome,
    Commit,
    Proposal,
}

#[derive(Clone, Debug)]
pub struct MlsDeliveryRecord {
    pub channel_id: ChannelId,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sequence: u64,
    pub kind: MlsDeliveryRecordKind,
    pub sender_device_id: Uuid,
    pub target_device_id: Option<Uuid>,
    pub payload: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct MlsWelcomeRecord {
    pub device_id: Uuid,
    pub key_package_reference: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Clone)]
struct MemoryInvite {
    guild_id: GuildId,
    uses: u32,
    max_uses: Option<u32>,
    expires_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone)]
struct MemoryOverwrite {
    target_kind: OverwriteTargetKind,
    target_id: u64,
    allow: GuildPermissions,
    deny: GuildPermissions,
}

#[derive(Clone)]
struct MemoryBan {
    actor_id: Option<UserId>,
    reason: Option<String>,
    expires_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MessageWindow {
    pub before: Option<u64>,
    pub after: Option<u64>,
    pub around: Option<u64>,
    pub limit: usize,
}

#[derive(Debug)]
pub struct CreatedGuild {
    pub guild: Guild,
    pub channels: Vec<Channel>,
}

#[derive(Clone, Debug)]
pub struct OwnedGuildRecord {
    pub guild: Guild,
    pub member_count: u32,
}

#[derive(Clone, Debug)]
pub struct DeletedGuildRecord {
    pub guild: Guild,
    pub member_ids: Vec<UserId>,
    pub voice_channel_ids: Vec<ChannelId>,
}

#[derive(Debug)]
pub struct CreatedMessage {
    pub message: Message,
    pub audience: MessageAudience,
    pub created: bool,
}

#[derive(Debug)]
pub struct UpdatedMessage {
    pub message: Message,
    pub audience: MessageAudience,
}

#[derive(Debug)]
pub struct DeletedMessage {
    pub event: MessageDeleteEvent,
    pub audience: MessageAudience,
}

#[derive(Debug)]
pub struct UpdatedReaction {
    pub event: MessageReactionEvent,
    pub audience: MessageAudience,
    pub changed: bool,
}

#[derive(Clone, Debug)]
pub struct MessageSafetyContext {
    pub guild_id: Option<GuildId>,
    pub account_created_at: chrono::DateTime<Utc>,
    pub existing_message: Option<Message>,
    pub encrypted: bool,
    pub mls_ready: bool,
}

#[derive(Clone, Debug)]
pub struct NewMessageEncryption {
    pub ciphertext: Vec<u8>,
    pub franking_commitment: [u8; 32],
    pub franking_tag: [u8; 32],
    pub sender_device_id: Uuid,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ReportRecord {
    receipt: ReportReceipt,
    reporter_id: UserId,
    message_id: MessageId,
    channel_id: ChannelId,
    author_id: UserId,
    guild_id: Option<GuildId>,
    category: ReportCategory,
    detail: Option<String>,
    evidence_payload: Vec<u8>,
    frank_tag: Option<[u8; 32]>,
    handled_by_operator: Option<String>,
    handled_at: Option<DateTime<Utc>>,
    resolution_note: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomodEnforcement {
    pub applied_action: AutomodAction,
    pub removed_from_guild: bool,
}

#[derive(Clone, Debug)]
pub enum MessageAudience {
    Guild(GuildId),
    Users(Vec<UserId>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationshipAction {
    Accept,
    Block,
}

#[derive(Clone, Debug)]
pub struct AttachmentRecord {
    pub id: AttachmentId,
    pub channel_id: ChannelId,
    pub owner_id: UserId,
    pub filename: String,
    pub declared_content_type: String,
    pub verified_content_type: Option<String>,
    pub file_size: u64,
    pub claimed_sha256: [u8; 32],
    pub verified_sha256: Option<[u8; 32]>,
    pub object_key: String,
    pub public_url: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub animated: bool,
    pub ready: bool,
    pub message_id: Option<MessageId>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct NewAttachment {
    pub id: AttachmentId,
    pub channel_id: ChannelId,
    pub owner_id: UserId,
    pub filename: String,
    pub declared_content_type: String,
    pub file_size: u64,
    pub claimed_sha256: [u8; 32],
    pub object_key: String,
    pub public_url: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct VerifiedAttachment {
    pub content_type: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub animated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AttachmentCleanup {
    pub reservations: u64,
    pub objects: u64,
}

#[derive(Clone, Debug)]
pub struct VoiceAccess {
    pub channel_id: ChannelId,
    pub guild_id: Option<GuildId>,
    pub user: User,
    pub permissions: GuildPermissions,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryDataExport {
    pub profile: User,
    pub guilds: Vec<Guild>,
    pub relationships: Vec<Relationship>,
    pub direct_channels: Vec<DirectChannel>,
    pub messages: Vec<Message>,
    pub attachments: Vec<ExportAttachment>,
    pub read_states: Vec<ReadState>,
    pub devices: Vec<ExportDevice>,
    pub reports: Vec<ExportReport>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportAttachment {
    pub id: AttachmentId,
    pub channel_id: ChannelId,
    pub message_id: Option<MessageId>,
    pub filename: String,
    pub declared_content_type: String,
    pub verified_content_type: Option<String>,
    pub file_size: u64,
    pub claimed_sha256: String,
    pub verified_sha256: Option<String>,
    pub public_url: String,
    pub ready: bool,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportDevice {
    pub device_id: Uuid,
    pub signature_key: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReport {
    pub id: ReportId,
    pub message_id: MessageId,
    pub category: ReportCategory,
    pub detail: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorReportStatus {
    Open,
    Actioned,
    Dismissed,
}

impl OperatorReportStatus {
    const fn database_value(self) -> i16 {
        match self {
            Self::Open => 0,
            Self::Actioned => 1,
            Self::Dismissed => 2,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Actioned => "actioned",
            Self::Dismissed => "dismissed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportEvidenceAttachment {
    pub id: AttachmentId,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportEvidence {
    pub content: String,
    pub encrypted: bool,
    pub verified: bool,
    pub attachments: Vec<ReportEvidenceAttachment>,
    pub attachment_sha256: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorReportIdentity {
    pub id: UserId,
    pub handle: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorReport {
    pub id: ReportId,
    pub status: String,
    pub category: ReportCategory,
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
    pub handled_at: Option<DateTime<Utc>>,
    pub handled_by_operator: Option<String>,
    pub resolution_note: Option<String>,
    pub guild_id: Option<GuildId>,
    pub guild_name: Option<String>,
    pub channel_id: Option<ChannelId>,
    pub message_id: MessageId,
    pub reporter: OperatorReportIdentity,
    pub author: OperatorReportIdentity,
    pub evidence: ReportEvidence,
    pub franking_tag: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("{0} was not found")]
    NotFound(&'static str),
    #[error("you do not have permission to perform this action")]
    Forbidden,
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("{0}")]
    Validation(String),
    #[error("generated value collided and should be retried")]
    Conflict,
    #[error("the invite is invalid, expired, revoked, or exhausted")]
    InviteUnavailable,
    #[error("stored data is invalid: {0}")]
    InvalidData(&'static str),
    #[error("attachment storage operation failed: {0}")]
    AttachmentStorage(String),
    #[error("database migration failed")]
    Migration(#[from] MigrateError),
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
}

impl Repository {
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "the fixed nonzero development IDs are compile-time invariants"
    )]
    pub fn seeded() -> Self {
        let owner_id = UserId::from_raw(1).expect("one is a valid development user id");
        let owner = User {
            id: owner_id,
            handle: "erix".into(),
            display_name: "Erix".into(),
            avatar_url: None,
            created_at: Utc::now(),
        };
        let guild = Guild {
            id: GuildId::new(),
            owner_id,
            name: "Exocord Builders".into(),
            accent: 0x8B7CFF,
            created_at: Utc::now(),
        };
        let general = Channel {
            id: ChannelId::new(),
            guild_id: guild.id,
            name: "general".into(),
            kind: ChannelKind::Text,
            position: 0,
            encrypted: false,
            created_at: Utc::now(),
        };
        let voice = Channel {
            id: ChannelId::new(),
            guild_id: guild.id,
            name: "Lounge".into(),
            kind: ChannelKind::Voice,
            position: 1,
            encrypted: true,
            created_at: Utc::now(),
        };
        let messages = vec![
            Message {
                id: MessageId::new(),
                channel_id: general.id,
                author_id: owner_id,
                reply_to: None,
                content: "The fast client starts with a quiet, dependable core.".into(),
                encryption: None,
                attachments: Vec::new(),
                reactions: Vec::new(),
                sequence: 1,
                created_at: Utc::now(),
                edited_at: None,
            },
            Message {
                id: MessageId::new(),
                channel_id: general.id,
                author_id: owner_id,
                reply_to: None,
                content: "Create a server, open a channel, and keep the protocol boring.".into(),
                encryption: None,
                attachments: Vec::new(),
                reactions: Vec::new(),
                sequence: 2,
                created_at: Utc::now(),
                edited_at: None,
            },
        ];
        let mut store = MemoryStore::default();
        store.users.insert(owner.id, owner);
        store.guilds.insert(guild.id, guild.clone());
        store.channels.insert(general.id, general);
        store.channels.insert(voice.id, voice);
        store.memberships.insert((guild.id, owner_id));
        let everyone_id =
            RoleId::from_raw(guild.id.raw()).expect("a server id is also a valid role id");
        store.roles.insert(
            everyone_id,
            Role {
                id: everyone_id,
                guild_id: guild.id,
                name: "@everyone".into(),
                color: 0,
                position: 0,
                permissions: GuildPermissions::MEMBER_DEFAULT,
                managed: false,
            },
        );
        store.messages.insert(messages[0].channel_id, messages);
        Self(RepositoryBackend::Memory(Arc::new(RwLock::new(store))))
    }

    pub async fn connect_postgres(
        database_url: &str,
        max_connections: u32,
    ) -> Result<(Self, u32), RepositoryError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await?;
        migrator().run(&pool).await?;
        let maximum: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM messages")
            .fetch_one(&pool)
            .await?;
        let next_sequence = u32::try_from(maximum)
            .unwrap_or(u32::MAX.saturating_sub(1))
            .saturating_add(1);
        Ok((Self(RepositoryBackend::Postgres(pool)), next_sequence))
    }

    #[must_use]
    pub const fn storage_name(&self) -> &'static str {
        match &self.0 {
            RepositoryBackend::Memory(_) => "memory",
            RepositoryBackend::Postgres(_) => "postgres",
        }
    }

    pub async fn ready(&self) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(_) => Ok(()),
            RepositoryBackend::Postgres(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
                Ok(())
            }
        }
    }

    pub async fn put_private_history(
        &self,
        user_id: UserId,
        archive: PrivateHistoryArchive,
    ) -> Result<(), RepositoryError> {
        let nonce = URL_SAFE_NO_PAD
            .decode(&archive.nonce)
            .map_err(|_| RepositoryError::BadRequest("private history nonce is invalid"))?;
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| RepositoryError::BadRequest("private history nonce is invalid"))?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&archive.ciphertext)
            .map_err(|_| RepositoryError::BadRequest("private history ciphertext is invalid"))?;
        if !(17..=131_072).contains(&ciphertext.len()) {
            return Err(RepositoryError::BadRequest(
                "private history ciphertext is invalid",
            ));
        }
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let direct = store
                    .direct_channels
                    .get(&archive.channel_id)
                    .is_some_and(|channel| channel.recipients.contains(&user_id));
                let encrypted_message = store
                    .messages
                    .get(&archive.channel_id)
                    .and_then(|messages| {
                        messages
                            .iter()
                            .find(|message| message.id == archive.message_id)
                    })
                    .is_some_and(|message| message.encryption.is_some());
                if !direct || !encrypted_message {
                    return Err(RepositoryError::Forbidden);
                }
                store
                    .private_history
                    .insert((user_id, archive.message_id), archive);
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let allowed: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                       SELECT 1
                         FROM messages m
                         JOIN channel_recipients recipient
                           ON recipient.channel_id = m.channel_id
                        WHERE m.id = $1
                          AND m.channel_id = $2
                          AND m.deleted_at IS NULL
                          AND m.ciphertext IS NOT NULL
                          AND recipient.user_id = $3
                     )",
                )
                .bind(db_id(archive.message_id.raw())?)
                .bind(db_id(archive.channel_id.raw())?)
                .bind(db_id(user_id.raw())?)
                .fetch_one(pool)
                .await?;
                if !allowed {
                    return Err(RepositoryError::Forbidden);
                }
                sqlx::query(
                    "INSERT INTO private_message_archives
                       (user_id, message_id, channel_id, nonce, ciphertext, updated_at)
                     VALUES ($1, $2, $3, $4, $5, now())
                     ON CONFLICT (user_id, message_id) DO UPDATE SET
                       channel_id = excluded.channel_id,
                       nonce = excluded.nonce,
                       ciphertext = excluded.ciphertext,
                       updated_at = now()",
                )
                .bind(db_id(user_id.raw())?)
                .bind(db_id(archive.message_id.raw())?)
                .bind(db_id(archive.channel_id.raw())?)
                .bind(nonce.as_slice())
                .bind(ciphertext)
                .execute(pool)
                .await?;
                Ok(())
            }
        }
    }

    pub async fn private_history(
        &self,
        user_id: UserId,
        before: Option<MessageId>,
        limit: usize,
    ) -> Result<Vec<PrivateHistoryArchive>, RepositoryError> {
        let limit = limit.clamp(1, 1_000);
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let mut archives = store
                    .private_history
                    .iter()
                    .filter_map(|((owner_id, _), archive)| {
                        (*owner_id == user_id
                            && before.is_none_or(|cursor| archive.message_id < cursor))
                        .then_some(archive.clone())
                    })
                    .collect::<Vec<_>>();
                archives.sort_by_key(|archive| std::cmp::Reverse(archive.message_id));
                archives.truncate(limit);
                Ok(archives)
            }
            RepositoryBackend::Postgres(pool) => {
                let rows =
                    sqlx::query(
                        "SELECT message_id, channel_id, nonce, ciphertext
                       FROM private_message_archives
                      WHERE user_id = $1
                        AND ($2::bigint IS NULL OR message_id < $2)
                      ORDER BY message_id DESC
                      LIMIT $3",
                    )
                    .bind(db_id(user_id.raw())?)
                    .bind(before.map(|value| db_id(value.raw())).transpose()?)
                    .bind(i64::try_from(limit).map_err(|_| {
                        RepositoryError::BadRequest("invalid private history limit")
                    })?)
                    .fetch_all(pool)
                    .await?;
                rows.iter()
                    .map(|row| {
                        Ok(PrivateHistoryArchive {
                            message_id: message_id_from_db(row.try_get("message_id")?)?,
                            channel_id: channel_id_from_db(row.try_get("channel_id")?)?,
                            nonce: URL_SAFE_NO_PAD.encode(row.try_get::<Vec<u8>, _>("nonce")?),
                            ciphertext: URL_SAFE_NO_PAD
                                .encode(row.try_get::<Vec<u8>, _>("ciphertext")?),
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn ensure_user(
        &self,
        user: User,
        email: Option<&str>,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                store.write().await.users.entry(user.id).or_insert(user);
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let id = db_id(user.id.raw())?;
                let base_username = normalized_handle(&user.handle);
                let collision: bool = sqlx::query_scalar(
                    "SELECT EXISTS (
                       SELECT 1 FROM users
                       WHERE lower(username) = lower($1)
                         AND id <> $2
                         AND deleted_at IS NULL
                     )",
                )
                .bind(&base_username)
                .bind(id)
                .fetch_one(pool)
                .await?;
                let username = if collision {
                    let suffix = format!("-{:06x}", user.id.raw() & 0xFF_FFFF);
                    format!(
                        "{}{suffix}",
                        truncate_chars(&base_username, 32 - suffix.len())
                    )
                } else {
                    base_username
                };
                let display_name = truncate_chars(&user.display_name, 32);
                let username_key = username.to_lowercase();
                sqlx::query(
                    "INSERT INTO users
                       (id, username, username_key, display_name, email, email_key,
                        email_verified, created_at)
                     VALUES ($1, $2, $3, $4, $5, lower($5), $6, $7)
                    ON CONFLICT (id) DO UPDATE SET
                       email = COALESCE(EXCLUDED.email, users.email),
                       email_key = COALESCE(EXCLUDED.email_key, users.email_key),
                       email_verified = users.email_verified OR EXCLUDED.email_verified",
                )
                .bind(id)
                .bind(username)
                .bind(username_key)
                .bind(display_name)
                .bind(email)
                .bind(email.is_some())
                .bind(user.created_at)
                .execute(pool)
                .await?;
                Ok(())
            }
        }
    }

    pub async fn username_available(
        &self,
        handle: &str,
        account_id: Option<UserId>,
    ) -> Result<bool, RepositoryError> {
        let handle = normalized_handle(handle);
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                Ok(!store.read().await.users.values().any(|user| {
                    Some(user.id) != account_id && user.handle.eq_ignore_ascii_case(&handle)
                }))
            }
            RepositoryBackend::Postgres(pool) => {
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (
                       SELECT 1 FROM users
                        WHERE lower(username) = lower($1)
                          AND ($2::bigint IS NULL OR id <> $2)
                          AND deleted_at IS NULL
                     )",
                )
                .bind(handle)
                .bind(account_id.map(UserId::raw).map(db_id).transpose()?)
                .fetch_one(pool)
                .await?;
                Ok(!exists)
            }
        }
    }

    pub async fn update_profile(
        &self,
        user_id: UserId,
        handle: &str,
        display_name: &str,
        avatar: UserAvatarUpdate,
    ) -> Result<User, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                if store.users.values().any(|candidate| {
                    candidate.id != user_id && candidate.handle.eq_ignore_ascii_case(handle)
                }) {
                    return Err(RepositoryError::Conflict);
                }
                let avatar_url = match avatar {
                    UserAvatarUpdate::Keep => store
                        .users
                        .get(&user_id)
                        .and_then(|user| user.avatar_url.clone()),
                    UserAvatarUpdate::Remove => {
                        store.avatars.remove(&user_id);
                        None
                    }
                    UserAvatarUpdate::Set(record) => {
                        let hash = record.content_sha256.clone();
                        store.avatars.insert(user_id, record);
                        Some(format!("/v1/users/{user_id}/avatar/{hash}"))
                    }
                };
                let user = store
                    .users
                    .get_mut(&user_id)
                    .ok_or(RepositoryError::NotFound("user"))?;
                user.handle = handle.to_owned();
                user.display_name = display_name.to_owned();
                user.avatar_url = avatar_url;
                Ok(user.clone())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let id = db_id(user_id.raw())?;
                let avatar_hash =
                    match avatar {
                        UserAvatarUpdate::Keep => sqlx::query_scalar::<_, Option<String>>(
                            "SELECT avatar_hash FROM users
                              WHERE id = $1 AND deleted_at IS NULL",
                        )
                        .bind(id)
                        .fetch_optional(&mut *transaction)
                        .await?
                        .ok_or(RepositoryError::NotFound("user"))?,
                        UserAvatarUpdate::Remove => {
                            sqlx::query("DELETE FROM user_avatars WHERE user_id = $1")
                                .bind(id)
                                .execute(&mut *transaction)
                                .await?;
                            None
                        }
                        UserAvatarUpdate::Set(record) => {
                            sqlx::query(
                                "INSERT INTO user_avatars
                               (user_id, content_type, content, content_sha256,
                                width, height, updated_at)
                             VALUES ($1, $2, $3, $4, $5, $6, now())
                             ON CONFLICT (user_id) DO UPDATE SET
                               content_type = EXCLUDED.content_type,
                               content = EXCLUDED.content,
                               content_sha256 = EXCLUDED.content_sha256,
                               width = EXCLUDED.width,
                               height = EXCLUDED.height,
                               updated_at = now()",
                            )
                            .bind(id)
                            .bind(&record.content_type)
                            .bind(&record.content)
                            .bind(&record.content_sha256)
                            .bind(i32::try_from(record.width).map_err(|_| {
                                RepositoryError::InvalidData("avatar width is invalid")
                            })?)
                            .bind(i32::try_from(record.height).map_err(|_| {
                                RepositoryError::InvalidData("avatar height is invalid")
                            })?)
                            .execute(&mut *transaction)
                            .await?;
                            Some(record.content_sha256)
                        }
                    };
                let row = sqlx::query(
                    "UPDATE users
                        SET username = $1,
                            username_key = lower($1),
                            display_name = $2,
                            avatar_hash = $3
                      WHERE id = $4 AND deleted_at IS NULL
                    RETURNING id, username, display_name, avatar_hash, created_at",
                )
                .bind(handle)
                .bind(display_name)
                .bind(avatar_hash)
                .bind(id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| {
                    if error
                        .as_database_error()
                        .is_some_and(|database| database.is_unique_violation())
                    {
                        RepositoryError::Conflict
                    } else {
                        RepositoryError::Database(error)
                    }
                })?
                .ok_or(RepositoryError::NotFound("user"))?;
                let user = user_from_row(&row)?;
                transaction.commit().await?;
                Ok(user)
            }
        }
    }

    pub async fn user_avatar(
        &self,
        user_id: UserId,
        hash: &str,
    ) -> Result<UserAvatarRecord, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => store
                .read()
                .await
                .avatars
                .get(&user_id)
                .filter(|avatar| avatar.content_sha256 == hash)
                .cloned()
                .ok_or(RepositoryError::NotFound("avatar")),
            RepositoryBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT content_type, content, content_sha256, width, height
                       FROM user_avatars
                      WHERE user_id = $1 AND content_sha256 = $2",
                )
                .bind(db_id(user_id.raw())?)
                .bind(hash)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("avatar"))?;
                Ok(UserAvatarRecord {
                    content_type: row.try_get("content_type")?,
                    content: row.try_get("content")?,
                    content_sha256: row.try_get("content_sha256")?,
                    width: u32::try_from(row.try_get::<i32, _>("width")?)
                        .map_err(|_| RepositoryError::InvalidData("avatar width is invalid"))?,
                    height: u32::try_from(row.try_get::<i32, _>("height")?)
                        .map_err(|_| RepositoryError::InvalidData("avatar height is invalid"))?,
                })
            }
        }
    }

    pub async fn account_data_export(
        &self,
        user_id: UserId,
    ) -> Result<RepositoryDataExport, RepositoryError> {
        let guilds = self.list_guilds(user_id).await?;
        let relationships = self.list_relationships(user_id).await?;
        let direct_channels = self.list_direct_channels(user_id).await?;
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let profile = store
                    .users
                    .get(&user_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("user"))?;
                let mut messages = store
                    .messages
                    .values()
                    .flatten()
                    .filter(|message| message.author_id == user_id)
                    .cloned()
                    .collect::<Vec<_>>();
                messages.sort_by_key(|message| message.id);
                let mut attachments = store
                    .attachments
                    .values()
                    .filter(|attachment| attachment.owner_id == user_id)
                    .map(export_attachment)
                    .collect::<Vec<_>>();
                attachments.sort_by_key(|attachment| attachment.id);
                let mut read_states = store
                    .read_states
                    .iter()
                    .filter_map(|((owner_id, _), state)| {
                        (*owner_id == user_id).then_some(state.clone())
                    })
                    .collect::<Vec<_>>();
                read_states.sort_by_key(|state| state.channel_id);
                let mut devices = store
                    .device_identities
                    .values()
                    .filter(|identity| identity.user_id == user_id)
                    .map(export_device)
                    .collect::<Vec<_>>();
                devices.sort_by_key(|device| device.device_id);
                let mut reports = store
                    .reports
                    .iter()
                    .filter(|report| report.reporter_id == user_id)
                    .map(|report| ExportReport {
                        id: report.receipt.id,
                        message_id: report.message_id,
                        category: report.category,
                        detail: report.detail.clone(),
                        status: report.receipt.status.clone(),
                        created_at: report.receipt.created_at,
                    })
                    .collect::<Vec<_>>();
                reports.sort_by_key(|report| report.id);
                Ok(RepositoryDataExport {
                    profile,
                    guilds,
                    relationships,
                    direct_channels,
                    messages,
                    attachments,
                    read_states,
                    devices,
                    reports,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let profile = sqlx::query(
                    "SELECT id, username, display_name, avatar_hash, created_at
                       FROM users
                      WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_optional(pool)
                .await?
                .as_ref()
                .map(user_from_row)
                .transpose()?
                .ok_or(RepositoryError::NotFound("user"))?;
                let message_rows = sqlx::query(
                    "SELECT m.id, m.channel_id, m.author_id,
                            COALESCE(m.content, '') AS content, m.ciphertext,
                            m.frank_commit, m.frank_tag, m.sender_device_id, m.nonce,
                            m.attachments, m.reference_id, m.sequence,
                            snowflake_to_timestamp(m.id) AS created_at, m.edited_at
                       FROM messages m
                      WHERE m.author_id = $1
                      ORDER BY m.id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let messages = message_rows
                    .iter()
                    .map(message_from_row)
                    .collect::<Result<Vec<_>, _>>()?;
                let attachment_rows = sqlx::query(
                    "SELECT id, channel_id, owner_id, message_id, filename,
                            declared_content_type, verified_content_type, file_size,
                            claimed_sha256, verified_sha256, object_key, public_url,
                            width, height, animated, state, expires_at
                       FROM attachment_uploads
                      WHERE owner_id = $1
                      ORDER BY id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let attachments = attachment_rows
                    .iter()
                    .map(attachment_record_from_row)
                    .map(|record| record.map(|record| export_attachment(&record)))
                    .collect::<Result<Vec<_>, _>>()?;
                let read_rows = sqlx::query(
                    "SELECT channel_id, NULLIF(last_message_id, 0) AS last_message_id,
                            mention_count
                       FROM read_state
                      WHERE user_id = $1
                      ORDER BY channel_id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let read_states = read_rows
                    .iter()
                    .map(read_state_from_row)
                    .collect::<Result<Vec<_>, _>>()?;
                let device_rows = sqlx::query(
                    "SELECT device_id, user_id, signature_key, name, created_at, revoked_at
                       FROM device_identities
                      WHERE user_id = $1
                      ORDER BY created_at, device_id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let devices = device_rows
                    .iter()
                    .map(device_identity_from_row)
                    .map(|identity| identity.map(|identity| export_device(&identity)))
                    .collect::<Result<Vec<_>, _>>()?;
                let report_rows = sqlx::query(
                    "SELECT id, target_id, category, detail, status, created_at
                       FROM reports
                      WHERE reporter_id = $1 AND target_type = 0
                      ORDER BY id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let reports = report_rows
                    .iter()
                    .map(export_report_from_row)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(RepositoryDataExport {
                    profile,
                    guilds,
                    relationships,
                    direct_channels,
                    messages,
                    attachments,
                    read_states,
                    devices,
                    reports,
                })
            }
        }
    }

    pub async fn anonymize_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        let suffix = format!("{:016x}", user_id.raw());
        let handle = format!("deleted-{suffix}");
        let display_name = format!("Deleted User #{}", &suffix[suffix.len() - 6..]);
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let owned_guilds = store
                    .guilds
                    .values()
                    .filter_map(|guild| {
                        (guild.owner_id == user_id && !store.deleted_guilds.contains(&guild.id))
                            .then_some(guild.id)
                    })
                    .collect::<Vec<_>>();
                if owned_guilds.iter().any(|guild_id| {
                    store
                        .memberships
                        .iter()
                        .filter(|(candidate, _)| candidate == guild_id)
                        .count()
                        > 1
                }) {
                    return Err(RepositoryError::Conflict);
                }
                for guild_id in &owned_guilds {
                    store.deleted_guilds.insert(*guild_id);
                    store.owner_deletion_pending.remove(guild_id);
                    store
                        .invites
                        .retain(|_, invite| invite.guild_id != *guild_id);
                    push_memory_audit_entry(
                        &mut store,
                        *guild_id,
                        None,
                        Some(user_id.raw()),
                        AUDIT_GUILD_OWNER_ACCOUNT_DELETE,
                        serde_json::json!({
                            "deletedAt": now,
                            "reason": "owner_account_deletion"
                        }),
                        Some("Server retired when its sole owner's account was deleted".into()),
                    );
                }
                let user = store
                    .users
                    .get_mut(&user_id)
                    .ok_or(RepositoryError::NotFound("user"))?;
                user.handle.clone_from(&handle);
                user.display_name.clone_from(&display_name);
                user.avatar_url = None;
                store
                    .memberships
                    .retain(|(_, member_id)| *member_id != user_id);
                store
                    .member_roles
                    .retain(|(_, member_id, _)| *member_id != user_id);
                store.relationships.retain(|(owner_id, target_id), _| {
                    *owner_id != user_id && *target_id != user_id
                });
                store
                    .read_states
                    .retain(|(owner_id, _), _| *owner_id != user_id);
                store
                    .timeouts
                    .retain(|(_, member_id), _| *member_id != user_id);
                store
                    .channel_overwrites
                    .retain(|(_, target_kind, target_id), _| {
                        *target_kind != OverwriteTargetKind::Member || *target_id != user_id.raw()
                    });
                let device_ids = store
                    .device_identities
                    .values_mut()
                    .filter_map(|identity| {
                        if identity.user_id != user_id {
                            return None;
                        }
                        identity.name = None;
                        identity.revoked_at.get_or_insert(now);
                        Some(identity.device_id)
                    })
                    .collect::<HashSet<_>>();
                store
                    .mls_key_packages
                    .retain(|_, package| package.user_id != user_id);
                store.mls_deliveries.retain(|delivery| {
                    delivery
                        .target_device_id
                        .is_none_or(|id| !device_ids.contains(&id))
                });
                for members in store.channel_mls_members.values_mut() {
                    members.retain(|device_id| !device_ids.contains(device_id));
                }
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
                        .bind(db_id(user_id.raw())?)
                        .fetch_one(&mut *transaction)
                        .await?;
                if !exists {
                    return Err(RepositoryError::NotFound("user"));
                }
                let owned_rows = sqlx::query(
                    "SELECT id, owner_id, name, accent, created_at
                       FROM guilds
                      WHERE owner_id = $1 AND deleted_at IS NULL
                      ORDER BY id
                      FOR UPDATE",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(&mut *transaction)
                .await?;
                let mut owned_guilds = Vec::with_capacity(owned_rows.len());
                for row in &owned_rows {
                    let guild = guild_from_row(row)?;
                    let member_count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM guild_members WHERE guild_id = $1",
                    )
                    .bind(db_id(guild.id.raw())?)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if member_count > 1 {
                        return Err(RepositoryError::Conflict);
                    }
                    owned_guilds.push(guild);
                }
                for guild in &owned_guilds {
                    insert_system_audit_entry(
                        &mut transaction,
                        guild.id,
                        user_id,
                        AUDIT_GUILD_OWNER_ACCOUNT_DELETE,
                        serde_json::json!({
                            "deletedAt": now,
                            "reason": "owner_account_deletion"
                        }),
                        "Server retired when its sole owner's account was deleted",
                    )
                    .await?;
                    sqlx::query(
                        "UPDATE channels
                            SET deleted_at = COALESCE(deleted_at, $1)
                          WHERE guild_id = $2",
                    )
                    .bind(now)
                    .bind(db_id(guild.id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    sqlx::query(
                        "UPDATE guild_invites
                            SET revoked_at = COALESCE(revoked_at, $1)
                          WHERE guild_id = $2",
                    )
                    .bind(now)
                    .bind(db_id(guild.id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    sqlx::query(
                        "UPDATE guilds
                            SET deleted_at = COALESCE(deleted_at, $1),
                                owner_deletion_pending_at = NULL
                          WHERE id = $2",
                    )
                    .bind(now)
                    .bind(db_id(guild.id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                }
                let devices = sqlx::query_scalar::<_, Uuid>(
                    "SELECT device_id FROM device_identities WHERE user_id = $1",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(&mut *transaction)
                .await?;
                sqlx::query(
                    "DELETE FROM mls_messages
                      WHERE target_device = ANY($1)",
                )
                .bind(&devices)
                .execute(&mut *transaction)
                .await?;
                sqlx::query("DELETE FROM channel_mls_members WHERE device_id = ANY($1)")
                    .bind(&devices)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query("DELETE FROM mls_key_packages WHERE user_id = $1")
                    .bind(db_id(user_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(
                    "UPDATE device_identities
                        SET revoked_at = COALESCE(revoked_at, $1), name = NULL
                      WHERE user_id = $2",
                )
                .bind(now)
                .bind(db_id(user_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "DELETE FROM user_relationships
                      WHERE user_id = $1 OR target_id = $1",
                )
                .bind(db_id(user_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                sqlx::query("DELETE FROM read_state WHERE user_id = $1")
                    .bind(db_id(user_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query("DELETE FROM member_roles WHERE user_id = $1")
                    .bind(db_id(user_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query("DELETE FROM guild_members WHERE user_id = $1")
                    .bind(db_id(user_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(
                    "DELETE FROM channel_overwrites
                      WHERE target_type = 1 AND target_id = $1",
                )
                .bind(db_id(user_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                sqlx::query("DELETE FROM user_credentials WHERE user_id = $1")
                    .bind(db_id(user_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(
                    "DELETE FROM session_refresh_tokens
                      WHERE session_id IN (
                        SELECT id FROM sessions WHERE user_id = $1
                      )",
                )
                .bind(db_id(user_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                    .bind(db_id(user_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query("DELETE FROM external_identities WHERE user_id = $1")
                    .bind(db_id(user_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(
                    "UPDATE users
                        SET username = $1,
                            username_key = $1,
                            display_name = $2,
                            avatar_hash = NULL,
                            banner_hash = NULL,
                            bio = NULL,
                            accent_color = NULL,
                            email = NULL,
                            email_key = NULL,
                            email_verified = FALSE,
                            password_hash = NULL,
                            password_changed_at = NULL,
                            mfa_enabled = FALSE,
                            totp_secret_enc = NULL,
                            backup_codes = NULL,
                            phone_hash = NULL,
                            disabled_at = COALESCE(disabled_at, $3),
                            deleted_at = COALESCE(deleted_at, $3),
                            token_version = token_version + 1
                      WHERE id = $4",
                )
                .bind(handle)
                .bind(display_name)
                .bind(now)
                .bind(db_id(user_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn list_relationships(
        &self,
        user_id: UserId,
    ) -> Result<Vec<Relationship>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let mut relationships = store
                    .relationships
                    .iter()
                    .filter_map(|((owner_id, target_id), relationship)| {
                        if *owner_id != user_id {
                            return None;
                        }
                        store
                            .users
                            .get(target_id)
                            .cloned()
                            .map(|user| Relationship {
                                user,
                                kind: relationship.kind,
                                since: relationship.since,
                            })
                    })
                    .collect::<Vec<_>>();
                sort_relationships(&mut relationships);
                Ok(relationships)
            }
            RepositoryBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT u.id, u.username, u.display_name, u.avatar_hash, u.created_at,
                            r.state, r.updated_at AS relationship_since
                     FROM user_relationships r
                     JOIN users u ON u.id = r.target_id
                     WHERE r.user_id = $1 AND u.deleted_at IS NULL
                     ORDER BY r.state, lower(u.username), u.id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter().map(relationship_from_row).collect()
            }
        }
    }

    async fn relationship(
        &self,
        user_id: UserId,
        target_id: UserId,
    ) -> Result<Relationship, RepositoryError> {
        self.list_relationships(user_id)
            .await?
            .into_iter()
            .find(|relationship| relationship.user.id == target_id)
            .ok_or(RepositoryError::NotFound("relationship"))
    }

    pub async fn request_relationship(
        &self,
        user_id: UserId,
        handle: &str,
    ) -> Result<Relationship, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let target = store
                    .users
                    .values()
                    .find(|user| user.handle.eq_ignore_ascii_case(handle))
                    .cloned()
                    .ok_or(RepositoryError::NotFound("user"))?;
                if target.id == user_id {
                    return Err(RepositoryError::BadRequest(
                        "you cannot send a friend request to yourself",
                    ));
                }
                let now = Utc::now();
                let mine = store.relationships.get(&(user_id, target.id)).cloned();
                let theirs = store.relationships.get(&(target.id, user_id)).cloned();
                if mine
                    .as_ref()
                    .is_some_and(|value| matches!(value.kind, RelationshipKind::Blocked))
                    || theirs
                        .as_ref()
                        .is_some_and(|value| matches!(value.kind, RelationshipKind::Blocked))
                {
                    return Err(RepositoryError::NotFound("user"));
                }
                let kind = if mine
                    .as_ref()
                    .is_some_and(|value| value.kind == RelationshipKind::Incoming)
                {
                    store.relationships.insert(
                        (user_id, target.id),
                        MemoryRelationship {
                            kind: RelationshipKind::Friend,
                            since: now,
                        },
                    );
                    store.relationships.insert(
                        (target.id, user_id),
                        MemoryRelationship {
                            kind: RelationshipKind::Friend,
                            since: now,
                        },
                    );
                    RelationshipKind::Friend
                } else if let Some(mine) = mine {
                    mine.kind
                } else {
                    store.relationships.insert(
                        (user_id, target.id),
                        MemoryRelationship {
                            kind: RelationshipKind::Outgoing,
                            since: now,
                        },
                    );
                    store.relationships.insert(
                        (target.id, user_id),
                        MemoryRelationship {
                            kind: RelationshipKind::Incoming,
                            since: now,
                        },
                    );
                    RelationshipKind::Outgoing
                };
                let since = store
                    .relationships
                    .get(&(user_id, target.id))
                    .map_or(now, |relationship| relationship.since);
                Ok(Relationship {
                    user: target,
                    kind,
                    since,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let target_row = sqlx::query(
                    "SELECT id, username, display_name, avatar_hash, created_at
                     FROM users
                     WHERE (lower(username) = lower($1) OR id::text = $1)
                       AND deleted_at IS NULL
                     LIMIT 1",
                )
                .bind(handle)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("user"))?;
                let target = user_from_row(&target_row)?;
                if target.id == user_id {
                    return Err(RepositoryError::BadRequest(
                        "you cannot send a friend request to yourself",
                    ));
                }
                let mut transaction = pool.begin().await?;
                lock_user_pair(&mut transaction, user_id, target.id).await?;
                let mine = relationship_state(&mut transaction, user_id, target.id).await?;
                let theirs = relationship_state(&mut transaction, target.id, user_id).await?;
                if mine == Some(3) || theirs == Some(3) {
                    return Err(RepositoryError::NotFound("user"));
                }
                match mine {
                    Some(0) => {
                        sqlx::query(
                            "UPDATE user_relationships
                             SET state = 2, updated_at = now()
                             WHERE (user_id = $1 AND target_id = $2)
                                OR (user_id = $2 AND target_id = $1)",
                        )
                        .bind(db_id(user_id.raw())?)
                        .bind(db_id(target.id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                    }
                    Some(1 | 2) => {}
                    Some(_) => return Err(RepositoryError::NotFound("user")),
                    None => {
                        sqlx::query(
                            "INSERT INTO user_relationships
                               (user_id, target_id, state)
                             VALUES ($1, $2, 1), ($2, $1, 0)",
                        )
                        .bind(db_id(user_id.raw())?)
                        .bind(db_id(target.id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                    }
                }
                transaction.commit().await?;
                self.relationship(user_id, target.id).await
            }
        }
    }

    pub async fn update_relationship(
        &self,
        user_id: UserId,
        target_id: UserId,
        action: RelationshipAction,
    ) -> Result<Relationship, RepositoryError> {
        if user_id == target_id {
            return Err(RepositoryError::BadRequest(
                "you cannot change a relationship with yourself",
            ));
        }
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let target = store
                    .users
                    .get(&target_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("user"))?;
                let now = Utc::now();
                let kind = match action {
                    RelationshipAction::Accept => {
                        if !store
                            .relationships
                            .get(&(user_id, target_id))
                            .is_some_and(|value| value.kind == RelationshipKind::Incoming)
                        {
                            return Err(RepositoryError::BadRequest(
                                "there is no incoming friend request to accept",
                            ));
                        }
                        store.relationships.insert(
                            (user_id, target_id),
                            MemoryRelationship {
                                kind: RelationshipKind::Friend,
                                since: now,
                            },
                        );
                        store.relationships.insert(
                            (target_id, user_id),
                            MemoryRelationship {
                                kind: RelationshipKind::Friend,
                                since: now,
                            },
                        );
                        RelationshipKind::Friend
                    }
                    RelationshipAction::Block => {
                        store.relationships.remove(&(target_id, user_id));
                        store.relationships.insert(
                            (user_id, target_id),
                            MemoryRelationship {
                                kind: RelationshipKind::Blocked,
                                since: now,
                            },
                        );
                        RelationshipKind::Blocked
                    }
                };
                Ok(Relationship {
                    user: target,
                    kind,
                    since: now,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let target = postgres_user(pool, target_id).await?;
                let mut transaction = pool.begin().await?;
                lock_user_pair(&mut transaction, user_id, target_id).await?;
                match action {
                    RelationshipAction::Accept => {
                        if relationship_state(&mut transaction, user_id, target_id).await?
                            != Some(0)
                            || relationship_state(&mut transaction, target_id, user_id).await?
                                != Some(1)
                        {
                            return Err(RepositoryError::BadRequest(
                                "there is no incoming friend request to accept",
                            ));
                        }
                        sqlx::query(
                            "UPDATE user_relationships
                             SET state = 2, updated_at = now()
                             WHERE (user_id = $1 AND target_id = $2)
                                OR (user_id = $2 AND target_id = $1)",
                        )
                        .bind(db_id(user_id.raw())?)
                        .bind(db_id(target_id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                    }
                    RelationshipAction::Block => {
                        sqlx::query(
                            "DELETE FROM user_relationships
                             WHERE user_id = $2 AND target_id = $1",
                        )
                        .bind(db_id(user_id.raw())?)
                        .bind(db_id(target_id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                        sqlx::query(
                            "INSERT INTO user_relationships
                               (user_id, target_id, state)
                             VALUES ($1, $2, 3)
                             ON CONFLICT (user_id, target_id) DO UPDATE
                               SET state = 3, updated_at = now()",
                        )
                        .bind(db_id(user_id.raw())?)
                        .bind(db_id(target_id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                    }
                }
                transaction.commit().await?;
                Ok(Relationship {
                    user: target,
                    kind: match action {
                        RelationshipAction::Accept => RelationshipKind::Friend,
                        RelationshipAction::Block => RelationshipKind::Blocked,
                    },
                    since: Utc::now(),
                })
            }
        }
    }

    pub async fn delete_relationship(
        &self,
        user_id: UserId,
        target_id: UserId,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let removed = store.relationships.remove(&(user_id, target_id));
                if !store
                    .relationships
                    .get(&(target_id, user_id))
                    .is_some_and(|value| value.kind == RelationshipKind::Blocked)
                {
                    store.relationships.remove(&(target_id, user_id));
                }
                removed
                    .map(|_| ())
                    .ok_or(RepositoryError::NotFound("relationship"))
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                lock_user_pair(&mut transaction, user_id, target_id).await?;
                let deleted = sqlx::query(
                    "DELETE FROM user_relationships
                     WHERE (user_id = $1 AND target_id = $2)
                        OR (user_id = $2 AND target_id = $1 AND state <> 3)",
                )
                .bind(db_id(user_id.raw())?)
                .bind(db_id(target_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                if deleted.rows_affected() == 0 {
                    return Err(RepositoryError::NotFound("relationship"));
                }
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn list_direct_channels(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DirectChannel>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let mut channels = store
                    .direct_channels
                    .values()
                    .filter(|channel| channel.recipients.contains(&user_id))
                    .map(|channel| memory_direct_channel(&store, channel))
                    .collect::<Result<Vec<_>, _>>()?;
                sort_direct_channels(&mut channels);
                Ok(channels)
            }
            RepositoryBackend::Postgres(pool) => postgres_direct_channels(pool, user_id).await,
        }
    }

    pub async fn register_device_identity(
        &self,
        user_id: UserId,
        device_id: Uuid,
        signature_key: [u8; 32],
        name: Option<String>,
    ) -> Result<DeviceIdentityRecord, RepositoryError> {
        let now = Utc::now();
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                if !store.users.contains_key(&user_id) {
                    return Err(RepositoryError::NotFound("user"));
                }
                if let Some(identity) = store.device_identities.get_mut(&device_id) {
                    if identity.user_id != user_id || identity.signature_key != signature_key {
                        return Err(RepositoryError::Conflict);
                    }
                    if identity.revoked_at.is_some() {
                        return Err(RepositoryError::Forbidden);
                    }
                    identity.name = name;
                    return Ok(identity.clone());
                }
                let identity = DeviceIdentityRecord {
                    device_id,
                    user_id,
                    signature_key,
                    name,
                    created_at: now,
                    revoked_at: None,
                };
                store.device_identities.insert(device_id, identity.clone());
                Ok(identity)
            }
            RepositoryBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "INSERT INTO device_identities
                       (device_id, user_id, signature_key, name, created_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (device_id) DO UPDATE SET
                       name = EXCLUDED.name
                     WHERE device_identities.user_id = EXCLUDED.user_id
                       AND device_identities.signature_key = EXCLUDED.signature_key
                       AND device_identities.revoked_at IS NULL
                     RETURNING device_id, user_id, signature_key, name, created_at, revoked_at",
                )
                .bind(device_id)
                .bind(db_id(user_id.raw())?)
                .bind(signature_key.as_slice())
                .bind(name)
                .bind(now)
                .fetch_optional(pool)
                .await?;
                match row {
                    Some(row) => device_identity_from_row(&row),
                    None => Err(RepositoryError::Conflict),
                }
            }
        }
    }

    pub async fn list_device_identities(
        &self,
        requester_id: UserId,
        target_id: UserId,
    ) -> Result<Vec<DeviceIdentityRecord>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                if requester_id != target_id
                    && !store
                        .relationships
                        .get(&(requester_id, target_id))
                        .is_some_and(|relationship| relationship.kind == RelationshipKind::Friend)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let mut identities = store
                    .device_identities
                    .values()
                    .filter(|identity| identity.user_id == target_id)
                    .cloned()
                    .collect::<Vec<_>>();
                identities.sort_by_key(|identity| identity.created_at);
                Ok(identities)
            }
            RepositoryBackend::Postgres(pool) => {
                if requester_id != target_id {
                    let allowed: bool = sqlx::query_scalar(
                        "SELECT EXISTS(
                           SELECT 1
                           FROM user_relationships
                           WHERE user_id = $1 AND target_id = $2 AND state = 2
                         ) OR EXISTS(
                           SELECT 1
                           FROM channel_recipients mine
                           JOIN channel_recipients theirs
                             ON theirs.channel_id = mine.channel_id
                           WHERE mine.user_id = $1 AND theirs.user_id = $2
                         )",
                    )
                    .bind(db_id(requester_id.raw())?)
                    .bind(db_id(target_id.raw())?)
                    .fetch_one(pool)
                    .await?;
                    if !allowed {
                        return Err(RepositoryError::Forbidden);
                    }
                }
                let rows = sqlx::query(
                    "SELECT device_id, user_id, signature_key, name, created_at, revoked_at
                     FROM device_identities
                     WHERE user_id = $1
                     ORDER BY created_at, device_id",
                )
                .bind(db_id(target_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter().map(device_identity_from_row).collect()
            }
        }
    }

    pub async fn revoke_device_identity(
        &self,
        user_id: UserId,
        device_id: Uuid,
    ) -> Result<Vec<ChannelId>, RepositoryError> {
        let now = Utc::now();
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let identity = store
                    .device_identities
                    .get_mut(&device_id)
                    .ok_or(RepositoryError::NotFound("device identity"))?;
                if identity.user_id != user_id {
                    return Err(RepositoryError::Forbidden);
                }
                identity.revoked_at.get_or_insert(now);
                for package in store
                    .mls_key_packages
                    .values_mut()
                    .filter(|package| package.device_id == device_id)
                {
                    package.consumed_at.get_or_insert(now);
                }
                let mut channels = store
                    .channel_mls_members
                    .iter()
                    .filter_map(|(channel_id, members)| {
                        members.contains(&device_id).then_some(*channel_id)
                    })
                    .collect::<Vec<_>>();
                channels.sort_unstable();
                Ok(channels)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let owner: Option<i64> = sqlx::query_scalar(
                    "SELECT user_id
                     FROM device_identities
                     WHERE device_id = $1
                     FOR UPDATE",
                )
                .bind(device_id)
                .fetch_optional(&mut *transaction)
                .await?;
                let owner = owner.ok_or(RepositoryError::NotFound("device identity"))?;
                if user_id_from_db(owner)? != user_id {
                    return Err(RepositoryError::Forbidden);
                }
                sqlx::query(
                    "UPDATE device_identities
                     SET revoked_at = COALESCE(revoked_at, $1)
                     WHERE device_id = $2",
                )
                .bind(now)
                .bind(device_id)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "UPDATE mls_key_packages
                     SET consumed_at = COALESCE(consumed_at, $1)
                     WHERE device_id = $2",
                )
                .bind(now)
                .bind(device_id)
                .execute(&mut *transaction)
                .await?;
                let rows = sqlx::query(
                    "SELECT channel_id
                     FROM channel_mls_members
                     WHERE device_id = $1 AND removed_epoch IS NULL
                     ORDER BY channel_id",
                )
                .bind(device_id)
                .fetch_all(&mut *transaction)
                .await?;
                let channels = rows
                    .iter()
                    .map(|row| channel_id_from_db(row.try_get("channel_id")?))
                    .collect::<Result<Vec<_>, RepositoryError>>()?;
                transaction.commit().await?;
                Ok(channels)
            }
        }
    }

    pub async fn pending_mls_removals(
        &self,
        user_id: UserId,
        device_id: Uuid,
    ) -> Result<Vec<(ChannelId, Vec<Uuid>)>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let identity = store
                    .device_identities
                    .get(&device_id)
                    .ok_or(RepositoryError::NotFound("device identity"))?;
                if identity.user_id != user_id || identity.revoked_at.is_some() {
                    return Err(RepositoryError::Forbidden);
                }
                let now = Utc::now();
                let mut pending = Vec::new();
                for (channel_id, members) in &store.channel_mls_members {
                    if !members.contains(&device_id)
                        || memory_mls_channel_users(&store, user_id, *channel_id).is_err()
                    {
                        continue;
                    }
                    let mut revoked = members
                        .iter()
                        .filter(|member_id| {
                            store
                                .device_identities
                                .get(member_id)
                                .is_some_and(|member| member.revoked_at.is_some())
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    revoked.sort_unstable();
                    if !revoked.is_empty() {
                        pending.push((*channel_id, revoked));
                        continue;
                    }
                    // A membership-needed gateway event is best effort.  If
                    // the current device was offline when a newcomer
                    // published its KeyPackage, expose a durable empty hint
                    // so the next maintenance pass can claim and Add it.
                    let Ok(recipient_users) =
                        memory_mls_channel_users(&store, user_id, *channel_id)
                    else {
                        continue;
                    };
                    let has_pending_addition = store
                        .device_identities
                        .values()
                        .filter(|candidate| {
                            recipient_users.contains(&candidate.user_id)
                                && candidate.revoked_at.is_none()
                                && !members.contains(&candidate.device_id)
                        })
                        .any(|candidate| {
                            store.mls_key_packages.values().any(|package| {
                                package.device_id == candidate.device_id
                                    && package.expires_at > now
                                    && (package.consumed_at.is_none()
                                        || (package.claimed_by_device == Some(device_id)
                                            && package.claimed_for_channel == Some(*channel_id)))
                            })
                        });
                    if has_pending_addition {
                        pending.push((*channel_id, Vec::new()));
                    }
                }
                pending.sort_by_key(|(channel_id, _)| *channel_id);
                Ok(pending)
            }
            RepositoryBackend::Postgres(pool) => {
                let active: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                       SELECT 1 FROM device_identities
                       WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
                     )",
                )
                .bind(device_id)
                .bind(db_id(user_id.raw())?)
                .fetch_one(pool)
                .await?;
                if !active {
                    return Err(RepositoryError::Forbidden);
                }
                let rows = sqlx::query(
                    "SELECT current.channel_id, revoked.device_id
                     FROM channel_mls_members current
                     JOIN channel_mls_members target
                       ON target.channel_id = current.channel_id
                      AND target.removed_epoch IS NULL
                     JOIN device_identities revoked
                       ON revoked.device_id = target.device_id
                      AND revoked.revoked_at IS NOT NULL
                     WHERE current.device_id = $1
                       AND current.removed_epoch IS NULL
                     ORDER BY current.channel_id, revoked.device_id",
                )
                .bind(device_id)
                .fetch_all(pool)
                .await?;
                let mut pending = Vec::<(ChannelId, Vec<Uuid>)>::new();
                for row in rows {
                    let channel_id = channel_id_from_db(row.try_get("channel_id")?)?;
                    let device_id = row.try_get("device_id")?;
                    match pending.last_mut() {
                        Some((last_channel_id, device_ids)) if *last_channel_id == channel_id => {
                            device_ids.push(device_id);
                        }
                        _ => pending.push((channel_id, vec![device_id])),
                    }
                }
                let mut authorized = Vec::with_capacity(pending.len());
                for entry in pending {
                    if postgres_mls_channel_users(pool, user_id, entry.0)
                        .await
                        .is_ok()
                    {
                        authorized.push(entry);
                    }
                }
                let addition_rows = sqlx::query(
                    "SELECT DISTINCT current.channel_id
                     FROM channel_mls_members current
                     JOIN channels channel
                       ON channel.id = current.channel_id
                      AND channel.deleted_at IS NULL
                     JOIN device_identities candidate
                       ON candidate.revoked_at IS NULL
                     JOIN mls_key_packages package
                       ON package.device_id = candidate.device_id
                      AND package.expires_at > $2
                     WHERE current.device_id = $1
                       AND current.removed_epoch IS NULL
                       AND NOT EXISTS(
                         SELECT 1
                         FROM channel_mls_members existing
                         WHERE existing.channel_id = current.channel_id
                           AND existing.device_id = candidate.device_id
                           AND existing.removed_epoch IS NULL
                       )
                       AND (
                         package.consumed_at IS NULL
                         OR (
                           package.claimed_by_device = $1
                           AND package.claimed_for_channel = current.channel_id
                         )
                       )
                     ORDER BY current.channel_id",
                )
                .bind(device_id)
                .bind(Utc::now())
                .fetch_all(pool)
                .await?;
                for row in addition_rows {
                    let channel_id = channel_id_from_db(row.try_get("channel_id")?)?;
                    if authorized
                        .iter()
                        .any(|(pending_channel, _)| *pending_channel == channel_id)
                    {
                        continue;
                    }
                    if postgres_mls_channel_users(pool, user_id, channel_id)
                        .await
                        .is_ok()
                    {
                        authorized.push((channel_id, Vec::new()));
                    }
                }
                authorized.sort_by_key(|(channel_id, _)| *channel_id);
                Ok(authorized)
            }
        }
    }

    pub async fn publish_mls_key_packages(
        &self,
        user_id: UserId,
        device_id: Uuid,
        packages: Vec<([u8; 32], Vec<u8>, u16)>,
    ) -> Result<Vec<MlsKeyPackageRecord>, RepositoryError> {
        let now = Utc::now();
        let expires_at = now + chrono::TimeDelta::days(30);
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let identity = store
                    .device_identities
                    .get(&device_id)
                    .ok_or(RepositoryError::NotFound("device identity"))?;
                if identity.user_id != user_id || identity.revoked_at.is_some() {
                    return Err(RepositoryError::Forbidden);
                }
                let mut published = Vec::with_capacity(packages.len());
                for (reference, key_package, cipher_suite) in packages {
                    if let Some(existing) = store.mls_key_packages.get(&reference) {
                        if existing.user_id != user_id
                            || existing.device_id != device_id
                            || existing.key_package != key_package
                            || existing.cipher_suite != cipher_suite
                        {
                            return Err(RepositoryError::Conflict);
                        }
                        published.push(existing.clone());
                        continue;
                    }
                    let package = MlsKeyPackageRecord {
                        id: MessageId::new().raw(),
                        user_id,
                        device_id,
                        reference,
                        key_package,
                        cipher_suite,
                        expires_at,
                        consumed_at: None,
                        claimed_by_device: None,
                        claimed_for_channel: None,
                    };
                    store.mls_key_packages.insert(reference, package.clone());
                    published.push(package);
                }
                Ok(published)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let identity_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                       SELECT 1 FROM device_identities
                       WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
                     )",
                )
                .bind(device_id)
                .bind(db_id(user_id.raw())?)
                .fetch_one(&mut *transaction)
                .await?;
                if !identity_exists {
                    return Err(RepositoryError::Forbidden);
                }
                let mut published = Vec::with_capacity(packages.len());
                for (reference, key_package, cipher_suite) in packages {
                    let package_id = MessageId::new().raw();
                    sqlx::query(
                        "INSERT INTO mls_key_packages
                           (id, user_id, device_id, key_package, key_package_ref,
                            cipher_suite, created_at, expires_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                         ON CONFLICT (key_package_ref)
                           WHERE key_package_ref IS NOT NULL
                         DO NOTHING",
                    )
                    .bind(db_id(package_id)?)
                    .bind(db_id(user_id.raw())?)
                    .bind(device_id)
                    .bind(&key_package)
                    .bind(reference.as_slice())
                    .bind(i16::try_from(cipher_suite).map_err(|_| {
                        RepositoryError::InvalidData("MLS cipher suite does not fit smallint")
                    })?)
                    .bind(now)
                    .bind(expires_at)
                    .execute(&mut *transaction)
                    .await?;
                    let row = sqlx::query(
                        "SELECT id, user_id, device_id, key_package_ref, key_package,
                                cipher_suite, expires_at, consumed_at,
                                claimed_by_device, claimed_for_channel
                         FROM mls_key_packages
                         WHERE key_package_ref = $1",
                    )
                    .bind(reference.as_slice())
                    .fetch_one(&mut *transaction)
                    .await?;
                    let stored = mls_key_package_from_row(&row)?;
                    if stored.user_id != user_id
                        || stored.device_id != device_id
                        || stored.key_package != key_package
                        || stored.cipher_suite != cipher_suite
                    {
                        return Err(RepositoryError::Conflict);
                    }
                    published.push(stored);
                }
                transaction.commit().await?;
                Ok(published)
            }
        }
    }

    pub async fn claim_mls_key_packages(
        &self,
        user_id: UserId,
        claiming_device_id: Uuid,
        channel_id: ChannelId,
    ) -> Result<Vec<MlsKeyPackageRecord>, RepositoryError> {
        let now = Utc::now();
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let recipient_users = memory_mls_channel_users(&store, user_id, channel_id)?;
                let group = store
                    .direct_channels
                    .get(&channel_id)
                    .and_then(|channel| {
                        channel
                            .mls_group_id
                            .as_ref()
                            .map(|group_id| (group_id.clone(), channel.mls_epoch))
                    })
                    .or_else(|| store.channel_mls_groups.get(&channel_id).cloned());
                let member_devices = store
                    .channel_mls_members
                    .get(&channel_id)
                    .cloned()
                    .unwrap_or_default();
                if group.is_some() && !member_devices.contains(&claiming_device_id) {
                    // An existing group is authoritative.  A device that is
                    // not yet a member must wait for an existing trusted
                    // member to commit an Add and deliver its Welcome.  Do
                    // not reset a live voice group here: doing so forks every
                    // already-connected client onto a different MLS/SFrame
                    // epoch and destroys the durable inbox needed for
                    // convergence.
                    return Err(RepositoryError::Conflict);
                }
                let existing_claims = store
                    .mls_key_packages
                    .values()
                    .filter(|package| {
                        package.claimed_by_device == Some(claiming_device_id)
                            && package.claimed_for_channel == Some(channel_id)
                            && !member_devices.contains(&package.device_id)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if !existing_claims.is_empty() {
                    return Ok(existing_claims);
                }
                let mut target_devices = store
                    .device_identities
                    .values()
                    .filter(|identity| {
                        recipient_users.contains(&identity.user_id)
                            && identity.device_id != claiming_device_id
                            && !member_devices.contains(&identity.device_id)
                            && identity.revoked_at.is_none()
                    })
                    .map(|identity| identity.device_id)
                    .collect::<Vec<_>>();
                target_devices.sort_unstable();
                if target_devices.is_empty() {
                    if group.is_none() && store.direct_channels.contains_key(&channel_id) {
                        return Err(RepositoryError::Validation(
                            "no other active device has published an encryption identity".into(),
                        ));
                    }
                    return Ok(Vec::new());
                }
                let mut references = Vec::with_capacity(target_devices.len());
                for device_id in target_devices {
                    let reference = store
                        .mls_key_packages
                        .values()
                        .filter(|package| {
                            package.device_id == device_id
                                && package.consumed_at.is_none()
                                && package.expires_at > now
                        })
                        .min_by_key(|package| package.id)
                        .map(|package| package.reference)
                        .ok_or_else(|| {
                            RepositoryError::Validation(format!(
                                "device {device_id} has no available MLS KeyPackage"
                            ))
                        })?;
                    references.push(reference);
                }
                let mut claimed = Vec::with_capacity(references.len());
                for reference in references {
                    let package = store.mls_key_packages.get_mut(&reference).ok_or(
                        RepositoryError::InvalidData("claimed MLS KeyPackage disappeared"),
                    )?;
                    package.consumed_at = Some(now);
                    package.claimed_by_device = Some(claiming_device_id);
                    package.claimed_for_channel = Some(channel_id);
                    claimed.push(package.clone());
                }
                Ok(claimed)
            }
            RepositoryBackend::Postgres(pool) => {
                let recipient_users = postgres_mls_channel_users(pool, user_id, channel_id).await?;
                let mut transaction = pool.begin().await?;
                let channel_row = sqlx::query(
                    "SELECT mls_group_id
                     FROM channels
                     WHERE id = $1 AND deleted_at IS NULL
                     FOR UPDATE",
                )
                .bind(db_id(channel_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                let group_id = channel_row.try_get::<Option<Vec<u8>>, _>("mls_group_id")?;
                let member_devices = if group_id.is_some() {
                    let rows = sqlx::query(
                        "SELECT member.device_id
                         FROM channel_mls_members member
                         JOIN device_identities identity
                           ON identity.device_id = member.device_id
                         WHERE member.channel_id = $1
                           AND member.removed_epoch IS NULL
                           AND identity.revoked_at IS NULL",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .fetch_all(&mut *transaction)
                    .await?;
                    rows.iter()
                        .map(|row| row.try_get::<Uuid, _>("device_id"))
                        .collect::<Result<HashSet<_>, _>>()?
                } else {
                    HashSet::new()
                };
                if group_id.is_some() && !member_devices.contains(&claiming_device_id) {
                    // Keep the server's current group and durable delivery
                    // records intact.  Only an existing member may propose
                    // the next epoch; the newcomer will be admitted through
                    // that serialized Add/Welcome transaction.
                    return Err(RepositoryError::Conflict);
                }
                let existing_claims = sqlx::query(
                    "SELECT id, user_id, device_id, key_package_ref, key_package,
                            cipher_suite, expires_at, consumed_at,
                            claimed_by_device, claimed_for_channel
                     FROM mls_key_packages
                     WHERE claimed_by_device = $1 AND claimed_for_channel = $2
                     ORDER BY device_id, id",
                )
                .bind(claiming_device_id)
                .bind(db_id(channel_id.raw())?)
                .fetch_all(&mut *transaction)
                .await?;
                if !existing_claims.is_empty() {
                    let existing_claims = existing_claims
                        .iter()
                        .map(mls_key_package_from_row)
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .filter(|package| !member_devices.contains(&package.device_id))
                        .collect::<Vec<_>>();
                    if !existing_claims.is_empty() {
                        transaction.commit().await?;
                        return Ok(existing_claims);
                    }
                }
                let devices = sqlx::query(
                    "SELECT di.device_id
                     FROM device_identities di
                     WHERE di.user_id = ANY($1)
                       AND di.device_id <> $2
                       AND di.revoked_at IS NULL
                     ORDER BY di.created_at, di.device_id",
                )
                .bind(
                    recipient_users
                        .iter()
                        .map(|id| db_id(id.raw()))
                        .collect::<Result<Vec<_>, _>>()?,
                )
                .bind(claiming_device_id)
                .fetch_all(&mut *transaction)
                .await?;
                let mut unjoined_devices = Vec::with_capacity(devices.len());
                for device in devices {
                    let device_id = device.try_get::<Uuid, _>("device_id")?;
                    if !member_devices.contains(&device_id) {
                        unjoined_devices.push(device_id);
                    }
                }
                let devices = unjoined_devices;
                if devices.is_empty() {
                    let direct: bool = sqlx::query_scalar(
                        "SELECT guild_id IS NULL AND type = 1
                         FROM channels WHERE id = $1 AND deleted_at IS NULL",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if group_id.is_none() && direct {
                        return Err(RepositoryError::Validation(
                            "no other active device has published an encryption identity".into(),
                        ));
                    }
                    transaction.commit().await?;
                    return Ok(Vec::new());
                }
                let mut claimed = Vec::with_capacity(devices.len());
                for device_id in devices {
                    let row = sqlx::query(
                        "SELECT id, user_id, device_id, key_package_ref, key_package,
                                cipher_suite, expires_at, consumed_at,
                                claimed_by_device, claimed_for_channel
                         FROM mls_key_packages
                         WHERE device_id = $1
                           AND consumed_at IS NULL
                           AND expires_at > $2
                         ORDER BY created_at, id
                         LIMIT 1
                         FOR UPDATE SKIP LOCKED",
                    )
                    .bind(device_id)
                    .bind(now)
                    .fetch_optional(&mut *transaction)
                    .await?
                    .ok_or_else(|| {
                        RepositoryError::Validation(format!(
                            "device {device_id} has no available MLS KeyPackage"
                        ))
                    })?;
                    let package = mls_key_package_from_row(&row)?;
                    sqlx::query(
                        "UPDATE mls_key_packages
                         SET consumed_at = $1,
                             claimed_by_device = $2,
                             claimed_for_channel = $3
                         WHERE key_package_ref = $4",
                    )
                    .bind(now)
                    .bind(claiming_device_id)
                    .bind(db_id(channel_id.raw())?)
                    .bind(package.reference.as_slice())
                    .execute(&mut *transaction)
                    .await?;
                    let mut package = package;
                    package.consumed_at = Some(now);
                    package.claimed_by_device = Some(claiming_device_id);
                    package.claimed_for_channel = Some(channel_id);
                    claimed.push(package);
                }
                transaction.commit().await?;
                Ok(claimed)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn bootstrap_mls_group(
        &self,
        user_id: UserId,
        sender_device_id: Uuid,
        channel_id: ChannelId,
        group_id: Vec<u8>,
        epoch: u64,
        commit: Vec<u8>,
        welcomes: Vec<MlsWelcomeRecord>,
    ) -> Result<Vec<MlsDeliveryRecord>, RepositoryError> {
        let now = Utc::now();
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                memory_mls_channel_users(&store, user_id, channel_id)?;
                let group_exists = store
                    .direct_channels
                    .get(&channel_id)
                    .is_some_and(|channel| channel.mls_group_id.is_some())
                    || store.channel_mls_groups.contains_key(&channel_id);
                if group_exists {
                    return Err(RepositoryError::Conflict);
                }
                let claimed = store
                    .mls_key_packages
                    .values()
                    .filter(|package| {
                        package.claimed_by_device == Some(sender_device_id)
                            && package.claimed_for_channel == Some(channel_id)
                    })
                    .map(|package| (package.reference, package.device_id))
                    .collect::<HashMap<_, _>>();
                validate_welcome_set(&claimed, &welcomes)?;
                let mut member_devices = welcomes
                    .iter()
                    .map(|welcome| welcome.device_id)
                    .collect::<HashSet<_>>();
                member_devices.insert(sender_device_id);
                let mut deliveries = Vec::with_capacity(welcomes.len() + 1);
                deliveries.push(MlsDeliveryRecord {
                    channel_id,
                    group_id: group_id.clone(),
                    epoch,
                    sequence: 0,
                    kind: MlsDeliveryRecordKind::Commit,
                    sender_device_id,
                    target_device_id: None,
                    payload: commit,
                    created_at: now,
                    consumed_at: None,
                });
                for (index, welcome) in welcomes.into_iter().enumerate() {
                    deliveries.push(MlsDeliveryRecord {
                        channel_id,
                        group_id: group_id.clone(),
                        epoch,
                        sequence: u64::try_from(index)
                            .map_err(|_| RepositoryError::InvalidData("MLS sequence overflow"))?
                            + 1,
                        kind: MlsDeliveryRecordKind::Welcome,
                        sender_device_id,
                        target_device_id: Some(welcome.device_id),
                        payload: welcome.payload,
                        created_at: now,
                        consumed_at: None,
                    });
                }
                if let Some(channel) = store.direct_channels.get_mut(&channel_id) {
                    channel.encrypted = true;
                    channel.mls_group_id = Some(group_id);
                    channel.mls_epoch = epoch;
                } else {
                    store
                        .channel_mls_groups
                        .insert(channel_id, (group_id, epoch));
                }
                store.channel_mls_members.insert(channel_id, member_devices);
                store.mls_deliveries.extend(deliveries.iter().cloned());
                Ok(deliveries)
            }
            RepositoryBackend::Postgres(pool) => {
                postgres_mls_channel_users(pool, user_id, channel_id).await?;
                let mut transaction = pool.begin().await?;
                let existing_group: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT mls_group_id
                     FROM channels
                     WHERE id = $1 AND deleted_at IS NULL
                     FOR UPDATE",
                )
                .bind(db_id(channel_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                if existing_group.is_some() {
                    return Err(RepositoryError::Conflict);
                }
                let rows = sqlx::query(
                    "SELECT key_package_ref, device_id
                     FROM mls_key_packages
                     WHERE claimed_by_device = $1 AND claimed_for_channel = $2
                     FOR UPDATE",
                )
                .bind(sender_device_id)
                .bind(db_id(channel_id.raw())?)
                .fetch_all(&mut *transaction)
                .await?;
                let claimed = rows
                    .iter()
                    .map(|row| {
                        let reference = fixed_32(
                            row.try_get::<Vec<u8>, _>("key_package_ref")?,
                            "MLS KeyPackage reference",
                        )?;
                        Ok((reference, row.try_get::<Uuid, _>("device_id")?))
                    })
                    .collect::<Result<HashMap<_, _>, RepositoryError>>()?;
                validate_welcome_set(&claimed, &welcomes)?;
                let mut member_devices = welcomes
                    .iter()
                    .map(|welcome| welcome.device_id)
                    .collect::<HashSet<_>>();
                member_devices.insert(sender_device_id);
                sqlx::query(
                    "UPDATE channels
                     SET e2ee = true, mls_group_id = $1, mls_epoch = $2
                     WHERE id = $3 AND mls_group_id IS NULL",
                )
                .bind(&group_id)
                .bind(db_id(epoch)?)
                .bind(db_id(channel_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                let mut deliveries = Vec::with_capacity(welcomes.len() + 1);
                deliveries.push(MlsDeliveryRecord {
                    channel_id,
                    group_id: group_id.clone(),
                    epoch,
                    sequence: 0,
                    kind: MlsDeliveryRecordKind::Commit,
                    sender_device_id,
                    target_device_id: None,
                    payload: commit,
                    created_at: now,
                    consumed_at: None,
                });
                for (index, welcome) in welcomes.into_iter().enumerate() {
                    deliveries.push(MlsDeliveryRecord {
                        channel_id,
                        group_id: group_id.clone(),
                        epoch,
                        sequence: u64::try_from(index)
                            .map_err(|_| RepositoryError::InvalidData("MLS sequence overflow"))?
                            + 1,
                        kind: MlsDeliveryRecordKind::Welcome,
                        sender_device_id,
                        target_device_id: Some(welcome.device_id),
                        payload: welcome.payload,
                        created_at: now,
                        consumed_at: None,
                    });
                }
                for delivery in &deliveries {
                    sqlx::query(
                        "INSERT INTO mls_messages
                           (group_id, epoch, seq, kind, sender_device, payload,
                            channel_id, target_device, created_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    )
                    .bind(&delivery.group_id)
                    .bind(db_id(delivery.epoch)?)
                    .bind(db_id(delivery.sequence)?)
                    .bind(mls_delivery_kind_to_db(delivery.kind))
                    .bind(delivery.sender_device_id)
                    .bind(&delivery.payload)
                    .bind(db_id(channel_id.raw())?)
                    .bind(delivery.target_device_id)
                    .bind(delivery.created_at)
                    .execute(&mut *transaction)
                    .await?;
                }
                for device_id in member_devices {
                    sqlx::query(
                        "INSERT INTO channel_mls_members
                           (channel_id, device_id, joined_epoch)
                         VALUES ($1, $2, $3)",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(device_id)
                    .bind(db_id(epoch)?)
                    .execute(&mut *transaction)
                    .await?;
                }
                transaction.commit().await?;
                Ok(deliveries)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_mls_group(
        &self,
        user_id: UserId,
        sender_device_id: Uuid,
        channel_id: ChannelId,
        group_id: Vec<u8>,
        epoch: u64,
        commit: Vec<u8>,
        welcomes: Vec<MlsWelcomeRecord>,
        removed_device_ids: Vec<Uuid>,
    ) -> Result<Vec<MlsDeliveryRecord>, RepositoryError> {
        let now = Utc::now();
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let recipient_users = memory_mls_channel_users(&store, user_id, channel_id)?;
                let current = store
                    .direct_channels
                    .get(&channel_id)
                    .and_then(|channel| {
                        channel
                            .mls_group_id
                            .as_ref()
                            .map(|group_id| (group_id.clone(), channel.mls_epoch))
                    })
                    .or_else(|| store.channel_mls_groups.get(&channel_id).cloned())
                    .ok_or(RepositoryError::Conflict)?;
                if current.0 != group_id || current.1.checked_add(1) != Some(epoch) {
                    return Err(RepositoryError::Conflict);
                }
                let member_devices = store
                    .channel_mls_members
                    .get(&channel_id)
                    .cloned()
                    .unwrap_or_default();
                let sender_active =
                    store
                        .device_identities
                        .get(&sender_device_id)
                        .is_some_and(|identity| {
                            identity.user_id == user_id && identity.revoked_at.is_none()
                        });
                if !member_devices.contains(&sender_device_id) || !sender_active {
                    return Err(RepositoryError::Forbidden);
                }
                let removed_devices = removed_device_ids.iter().copied().collect::<HashSet<_>>();
                if removed_devices.len() != removed_device_ids.len()
                    || removed_devices.contains(&sender_device_id)
                    || removed_devices.iter().any(|device_id| {
                        !member_devices.contains(device_id)
                            || store
                                .device_identities
                                .get(device_id)
                                .is_none_or(|identity| identity.revoked_at.is_none())
                    })
                {
                    return Err(RepositoryError::Validation(
                        "MLS removals must identify distinct revoked member devices".into(),
                    ));
                }
                let claimed = store
                    .mls_key_packages
                    .values()
                    .filter(|package| {
                        package.claimed_by_device == Some(sender_device_id)
                            && package.claimed_for_channel == Some(channel_id)
                            && !member_devices.contains(&package.device_id)
                    })
                    .map(|package| (package.reference, package.device_id))
                    .collect::<HashMap<_, _>>();
                if !welcomes.is_empty() {
                    validate_welcome_set(&claimed, &welcomes)?;
                }
                let added_devices = welcomes
                    .iter()
                    .map(|welcome| welcome.device_id)
                    .collect::<Vec<_>>();
                let mut commit_targets = store
                    .device_identities
                    .values()
                    .filter(|identity| {
                        member_devices.contains(&identity.device_id)
                            && identity.device_id != sender_device_id
                            && !removed_devices.contains(&identity.device_id)
                            && recipient_users.contains(&identity.user_id)
                            && identity.revoked_at.is_none()
                    })
                    .map(|identity| identity.device_id)
                    .collect::<Vec<_>>();
                commit_targets.sort_unstable();
                let mut deliveries = Vec::with_capacity(commit_targets.len() + welcomes.len());
                for (index, target_device_id) in commit_targets.into_iter().enumerate() {
                    deliveries.push(MlsDeliveryRecord {
                        channel_id,
                        group_id: group_id.clone(),
                        epoch,
                        sequence: u64::try_from(index)
                            .map_err(|_| RepositoryError::InvalidData("MLS sequence overflow"))?,
                        kind: MlsDeliveryRecordKind::Commit,
                        sender_device_id,
                        target_device_id: Some(target_device_id),
                        payload: commit.clone(),
                        created_at: now,
                        consumed_at: None,
                    });
                }
                let welcome_offset = deliveries.len();
                for (index, welcome) in welcomes.into_iter().enumerate() {
                    deliveries.push(MlsDeliveryRecord {
                        channel_id,
                        group_id: group_id.clone(),
                        epoch,
                        sequence: u64::try_from(welcome_offset + index)
                            .map_err(|_| RepositoryError::InvalidData("MLS sequence overflow"))?,
                        kind: MlsDeliveryRecordKind::Welcome,
                        sender_device_id,
                        target_device_id: Some(welcome.device_id),
                        payload: welcome.payload,
                        created_at: now,
                        consumed_at: None,
                    });
                }
                if let Some(channel) = store.direct_channels.get_mut(&channel_id) {
                    channel.mls_epoch = epoch;
                } else {
                    store
                        .channel_mls_groups
                        .insert(channel_id, (group_id, epoch));
                }
                let current_members = store.channel_mls_members.entry(channel_id).or_default();
                for device_id in removed_devices {
                    current_members.remove(&device_id);
                }
                current_members.extend(added_devices);
                store.mls_deliveries.extend(deliveries.iter().cloned());
                Ok(deliveries)
            }
            RepositoryBackend::Postgres(pool) => {
                let recipient_users = postgres_mls_channel_users(pool, user_id, channel_id).await?;
                let recipient_users = recipient_users
                    .iter()
                    .map(|id| db_id(id.raw()))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut transaction = pool.begin().await?;
                let row = sqlx::query(
                    "SELECT mls_group_id, mls_epoch
                     FROM channels
                     WHERE id = $1 AND deleted_at IS NULL
                     FOR UPDATE",
                )
                .bind(db_id(channel_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                let current_group: Option<Vec<u8>> = row.try_get("mls_group_id")?;
                let current_epoch = u64::try_from(row.try_get::<i64, _>("mls_epoch")?)
                    .map_err(|_| RepositoryError::InvalidData("MLS epoch is negative"))?;
                if current_group.as_deref() != Some(group_id.as_slice())
                    || current_epoch.checked_add(1) != Some(epoch)
                {
                    return Err(RepositoryError::Conflict);
                }
                let rows = sqlx::query(
                    "SELECT member.device_id
                     FROM channel_mls_members member
                     WHERE member.channel_id = $1
                       AND member.removed_epoch IS NULL
                     FOR UPDATE",
                )
                .bind(db_id(channel_id.raw())?)
                .fetch_all(&mut *transaction)
                .await?;
                let member_devices = rows
                    .iter()
                    .map(|row| row.try_get::<Uuid, _>("device_id"))
                    .collect::<Result<HashSet<_>, _>>()?;
                let sender_active: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                       SELECT 1
                       FROM channel_mls_members member
                       JOIN device_identities identity
                         ON identity.device_id = member.device_id
                       WHERE member.channel_id = $1
                         AND member.device_id = $2
                         AND member.removed_epoch IS NULL
                         AND identity.user_id = $3
                         AND identity.revoked_at IS NULL
                     )",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(sender_device_id)
                .bind(db_id(user_id.raw())?)
                .fetch_one(&mut *transaction)
                .await?;
                if !member_devices.contains(&sender_device_id) || !sender_active {
                    return Err(RepositoryError::Forbidden);
                }
                let removed_devices = removed_device_ids.iter().copied().collect::<HashSet<_>>();
                if removed_devices.len() != removed_device_ids.len()
                    || removed_devices.contains(&sender_device_id)
                {
                    return Err(RepositoryError::Validation(
                        "MLS removals must identify distinct revoked member devices".into(),
                    ));
                }
                if !removed_devices.is_empty() {
                    let valid_removals: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*)
                         FROM channel_mls_members member
                         JOIN device_identities identity
                           ON identity.device_id = member.device_id
                         WHERE member.channel_id = $1
                           AND member.device_id = ANY($2)
                           AND member.removed_epoch IS NULL
                           AND identity.revoked_at IS NOT NULL",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(removed_device_ids.clone())
                    .fetch_one(&mut *transaction)
                    .await?;
                    if usize::try_from(valid_removals).ok() != Some(removed_devices.len()) {
                        return Err(RepositoryError::Validation(
                            "MLS removals must identify distinct revoked member devices".into(),
                        ));
                    }
                }
                let rows = sqlx::query(
                    "SELECT key_package_ref, device_id
                     FROM mls_key_packages
                     WHERE claimed_by_device = $1 AND claimed_for_channel = $2
                     FOR UPDATE",
                )
                .bind(sender_device_id)
                .bind(db_id(channel_id.raw())?)
                .fetch_all(&mut *transaction)
                .await?;
                let mut claimed = HashMap::new();
                for row in &rows {
                    let device_id = row.try_get::<Uuid, _>("device_id")?;
                    if member_devices.contains(&device_id) {
                        continue;
                    }
                    let reference = fixed_32(
                        row.try_get::<Vec<u8>, _>("key_package_ref")?,
                        "MLS KeyPackage reference",
                    )?;
                    claimed.insert(reference, device_id);
                }
                if !welcomes.is_empty() {
                    validate_welcome_set(&claimed, &welcomes)?;
                }
                let added_devices = welcomes
                    .iter()
                    .map(|welcome| welcome.device_id)
                    .collect::<Vec<_>>();
                let rows = sqlx::query(
                    "SELECT device_id
                     FROM device_identities
                     WHERE device_id = ANY($1)
                       AND device_id <> $2
                       AND NOT (device_id = ANY($4))
                       AND user_id = ANY($3)
                       AND revoked_at IS NULL
                     ORDER BY created_at, device_id",
                )
                .bind(member_devices.iter().copied().collect::<Vec<_>>())
                .bind(sender_device_id)
                .bind(recipient_users)
                .bind(removed_device_ids.clone())
                .fetch_all(&mut *transaction)
                .await?;
                let commit_targets = rows
                    .iter()
                    .map(|row| row.try_get::<Uuid, _>("device_id"))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut deliveries = Vec::with_capacity(commit_targets.len() + welcomes.len());
                for (index, target_device_id) in commit_targets.into_iter().enumerate() {
                    deliveries.push(MlsDeliveryRecord {
                        channel_id,
                        group_id: group_id.clone(),
                        epoch,
                        sequence: u64::try_from(index)
                            .map_err(|_| RepositoryError::InvalidData("MLS sequence overflow"))?,
                        kind: MlsDeliveryRecordKind::Commit,
                        sender_device_id,
                        target_device_id: Some(target_device_id),
                        payload: commit.clone(),
                        created_at: now,
                        consumed_at: None,
                    });
                }
                let welcome_offset = deliveries.len();
                for (index, welcome) in welcomes.into_iter().enumerate() {
                    deliveries.push(MlsDeliveryRecord {
                        channel_id,
                        group_id: group_id.clone(),
                        epoch,
                        sequence: u64::try_from(welcome_offset + index)
                            .map_err(|_| RepositoryError::InvalidData("MLS sequence overflow"))?,
                        kind: MlsDeliveryRecordKind::Welcome,
                        sender_device_id,
                        target_device_id: Some(welcome.device_id),
                        payload: welcome.payload,
                        created_at: now,
                        consumed_at: None,
                    });
                }
                sqlx::query(
                    "UPDATE channels
                     SET mls_epoch = $1
                     WHERE id = $2 AND mls_group_id = $3 AND mls_epoch = $4",
                )
                .bind(db_id(epoch)?)
                .bind(db_id(channel_id.raw())?)
                .bind(&group_id)
                .bind(db_id(current_epoch)?)
                .execute(&mut *transaction)
                .await?;
                for delivery in &deliveries {
                    sqlx::query(
                        "INSERT INTO mls_messages
                           (group_id, epoch, seq, kind, sender_device, payload,
                            channel_id, target_device, created_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    )
                    .bind(&delivery.group_id)
                    .bind(db_id(delivery.epoch)?)
                    .bind(db_id(delivery.sequence)?)
                    .bind(mls_delivery_kind_to_db(delivery.kind))
                    .bind(delivery.sender_device_id)
                    .bind(&delivery.payload)
                    .bind(db_id(channel_id.raw())?)
                    .bind(delivery.target_device_id)
                    .bind(delivery.created_at)
                    .execute(&mut *transaction)
                    .await?;
                }
                if !removed_device_ids.is_empty() {
                    sqlx::query(
                        "UPDATE channel_mls_members
                         SET removed_epoch = $1
                         WHERE channel_id = $2
                           AND device_id = ANY($3)
                           AND removed_epoch IS NULL",
                    )
                    .bind(db_id(epoch)?)
                    .bind(db_id(channel_id.raw())?)
                    .bind(removed_device_ids)
                    .execute(&mut *transaction)
                    .await?;
                }
                for device_id in added_devices {
                    sqlx::query(
                        "INSERT INTO channel_mls_members
                           (channel_id, device_id, joined_epoch, removed_epoch)
                         VALUES ($1, $2, $3, NULL)
                         ON CONFLICT (channel_id, device_id) DO UPDATE SET
                           joined_epoch = EXCLUDED.joined_epoch,
                           removed_epoch = NULL",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(device_id)
                    .bind(db_id(epoch)?)
                    .execute(&mut *transaction)
                    .await?;
                }
                transaction.commit().await?;
                Ok(deliveries)
            }
        }
    }

    pub async fn mls_inbox(
        &self,
        user_id: UserId,
        device_id: Uuid,
    ) -> Result<Vec<MlsDeliveryRecord>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let identity = store
                    .device_identities
                    .get(&device_id)
                    .ok_or(RepositoryError::NotFound("device identity"))?;
                if identity.user_id != user_id || identity.revoked_at.is_some() {
                    return Err(RepositoryError::Forbidden);
                }
                let mut deliveries = store
                    .mls_deliveries
                    .iter()
                    .filter(|delivery| {
                        delivery.target_device_id == Some(device_id)
                            && delivery.consumed_at.is_none()
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                deliveries.sort_by_key(|delivery| (delivery.created_at, delivery.sequence));
                Ok(deliveries)
            }
            RepositoryBackend::Postgres(pool) => {
                let registered: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                       SELECT 1 FROM device_identities
                       WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
                     )",
                )
                .bind(device_id)
                .bind(db_id(user_id.raw())?)
                .fetch_one(pool)
                .await?;
                if !registered {
                    return Err(RepositoryError::Forbidden);
                }
                let rows = sqlx::query(
                    "SELECT channel_id, group_id, epoch, seq, kind, sender_device,
                            target_device, payload, created_at, consumed_at
                     FROM mls_messages
                     WHERE target_device = $1 AND consumed_at IS NULL
                     ORDER BY created_at, epoch, seq
                     LIMIT 256",
                )
                .bind(device_id)
                .fetch_all(pool)
                .await?;
                rows.iter().map(mls_delivery_from_row).collect()
            }
        }
    }

    pub async fn acknowledge_mls_delivery(
        &self,
        user_id: UserId,
        device_id: Uuid,
        group_id: &[u8],
        epoch: u64,
        sequence: u64,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let identity = store
                    .device_identities
                    .get(&device_id)
                    .ok_or(RepositoryError::NotFound("device identity"))?;
                if identity.user_id != user_id {
                    return Err(RepositoryError::Forbidden);
                }
                let delivery = store
                    .mls_deliveries
                    .iter_mut()
                    .find(|delivery| {
                        delivery.target_device_id == Some(device_id)
                            && delivery.group_id == group_id
                            && delivery.epoch == epoch
                            && delivery.sequence == sequence
                    })
                    .ok_or(RepositoryError::NotFound("MLS delivery"))?;
                delivery.consumed_at = Some(Utc::now());
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let updated = sqlx::query(
                    "UPDATE mls_messages AS message
                     SET consumed_at = COALESCE(consumed_at, now())
                     FROM device_identities AS identity
                     WHERE message.group_id = $1
                       AND message.epoch = $2
                       AND message.seq = $3
                       AND message.target_device = $4
                       AND identity.device_id = message.target_device
                       AND identity.user_id = $5",
                )
                .bind(group_id)
                .bind(db_id(epoch)?)
                .bind(db_id(sequence)?)
                .bind(device_id)
                .bind(db_id(user_id.raw())?)
                .execute(pool)
                .await?;
                if updated.rows_affected() == 0 {
                    return Err(RepositoryError::NotFound("MLS delivery"));
                }
                Ok(())
            }
        }
    }

    pub async fn open_direct_channel(
        &self,
        user_id: UserId,
        target_id: UserId,
    ) -> Result<DirectChannel, RepositoryError> {
        if user_id == target_id {
            return Err(RepositoryError::BadRequest(
                "a direct message requires another user",
            ));
        }
        let pair = ordered_user_pair(user_id, target_id);
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                if !store
                    .relationships
                    .get(&(user_id, target_id))
                    .is_some_and(|value| value.kind == RelationshipKind::Friend)
                {
                    return Err(RepositoryError::Forbidden);
                }
                if let Some(channel_id) = store.direct_pairs.get(&pair) {
                    let channel = store.direct_channels.get(channel_id).ok_or(
                        RepositoryError::InvalidData("direct channel pair is missing its channel"),
                    )?;
                    return memory_direct_channel(&store, channel);
                }
                if !store.users.contains_key(&target_id) {
                    return Err(RepositoryError::NotFound("user"));
                }
                let channel = MemoryDirectChannel {
                    id: ChannelId::new(),
                    recipients: [pair.0, pair.1],
                    last_message_id: None,
                    encrypted: true,
                    mls_group_id: None,
                    mls_epoch: 0,
                    created_at: Utc::now(),
                };
                store.direct_pairs.insert(pair, channel.id);
                store.direct_channels.insert(channel.id, channel.clone());
                memory_direct_channel(&store, &channel)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                lock_user_pair(&mut transaction, user_id, target_id).await?;
                if relationship_state(&mut transaction, user_id, target_id).await? != Some(2)
                    || relationship_state(&mut transaction, target_id, user_id).await? != Some(2)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let existing = sqlx::query_scalar::<_, i64>(
                    "SELECT channel_id FROM dm_pairs
                     WHERE user_low_id = $1 AND user_high_id = $2",
                )
                .bind(db_id(pair.0.raw())?)
                .bind(db_id(pair.1.raw())?)
                .fetch_optional(&mut *transaction)
                .await?;
                let channel_id = if let Some(channel_id) = existing {
                    channel_id_from_db(channel_id)?
                } else {
                    let channel_id = ChannelId::new();
                    sqlx::query(
                        "INSERT INTO channels
                           (id, guild_id, type, name, position, e2ee)
                         VALUES ($1, NULL, 1, NULL, 0, true)",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    sqlx::query(
                        "INSERT INTO dm_pairs
                           (user_low_id, user_high_id, channel_id)
                         VALUES ($1, $2, $3)",
                    )
                    .bind(db_id(pair.0.raw())?)
                    .bind(db_id(pair.1.raw())?)
                    .bind(db_id(channel_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    sqlx::query(
                        "INSERT INTO channel_recipients (channel_id, user_id)
                         VALUES ($1, $2), ($1, $3)",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(db_id(pair.0.raw())?)
                    .bind(db_id(pair.1.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    channel_id
                };
                transaction.commit().await?;
                postgres_direct_channel(pool, user_id, channel_id).await
            }
        }
    }

    pub async fn acknowledge_read_state(
        &self,
        user_id: UserId,
        channel_id: ChannelId,
        message_id: MessageId,
    ) -> Result<ReadState, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                memory_message_audience(&store, user_id, channel_id, false)?;
                if !store
                    .messages
                    .get(&channel_id)
                    .is_some_and(|messages| messages.iter().any(|message| message.id == message_id))
                {
                    return Err(RepositoryError::NotFound("message"));
                }
                let state = store
                    .read_states
                    .entry((user_id, channel_id))
                    .or_insert(ReadState {
                        channel_id,
                        last_message_id: None,
                        mention_count: 0,
                    });
                if state
                    .last_message_id
                    .is_none_or(|current| message_id > current)
                {
                    state.last_message_id = Some(message_id);
                }
                state.mention_count = 0;
                Ok(state.clone())
            }
            RepositoryBackend::Postgres(pool) => {
                require_message_access(pool, user_id, channel_id, false).await?;
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (
                       SELECT 1 FROM messages
                       WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL
                     )",
                )
                .bind(db_id(message_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .fetch_one(pool)
                .await?;
                if !exists {
                    return Err(RepositoryError::NotFound("message"));
                }
                let row = sqlx::query(
                    "INSERT INTO read_state
                       (user_id, channel_id, last_message_id, mention_count, last_ack_at)
                     VALUES ($1, $2, $3, 0, now())
                     ON CONFLICT (user_id, channel_id) DO UPDATE
                       SET last_message_id =
                             GREATEST(read_state.last_message_id, EXCLUDED.last_message_id),
                           mention_count = 0,
                           last_ack_at = now()
                     RETURNING channel_id, last_message_id, mention_count",
                )
                .bind(db_id(user_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(message_id.raw())?)
                .fetch_one(pool)
                .await?;
                read_state_from_row(&row)
            }
        }
    }

    pub async fn snapshot(
        &self,
        user_id: UserId,
        last_sequence: u32,
    ) -> Result<SyncSnapshot, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let current_user = store
                    .users
                    .get(&user_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("user"))?;
                let member_guilds = store
                    .memberships
                    .iter()
                    .filter_map(|(guild_id, member_id)| {
                        (*member_id == user_id).then_some(*guild_id)
                    })
                    .collect::<HashSet<_>>();
                let guild_access = member_guilds
                    .iter()
                    .map(|guild_id| {
                        memory_actor_context(&store, user_id, *guild_id)
                            .map(|access| (*guild_id, access.permissions))
                    })
                    .collect::<Result<HashMap<_, _>, _>>()?;
                let mut guilds = store
                    .guilds
                    .values()
                    .filter(|guild| member_guilds.contains(&guild.id))
                    .cloned()
                    .collect::<Vec<_>>();
                guilds.sort_by_key(|guild| guild.created_at);
                let mut channel_permissions = HashMap::new();
                let mut channels = Vec::new();
                for channel in store
                    .channels
                    .values()
                    .filter(|channel| member_guilds.contains(&channel.guild_id))
                {
                    let permissions = memory_channel_permissions(&store, user_id, channel)?;
                    channel_permissions.insert(channel.id, permissions);
                    if permissions.contains(GuildPermissions::VIEW_CHANNEL) {
                        channels.push(channel.clone());
                    }
                }
                channels.sort_by_key(|channel| (channel.guild_id, channel.position));
                let visible_channels = channels
                    .iter()
                    .filter_map(|channel| {
                        channel_permissions
                            .get(&channel.id)
                            .and_then(|permissions| {
                                permissions
                                    .contains(GuildPermissions::READ_MESSAGE_HISTORY)
                                    .then_some(channel.id)
                            })
                    })
                    .collect::<HashSet<_>>();
                let mut direct_channels = store
                    .direct_channels
                    .values()
                    .filter(|channel| channel.recipients.contains(&user_id))
                    .map(|channel| memory_direct_channel(&store, channel))
                    .collect::<Result<Vec<_>, _>>()?;
                sort_direct_channels(&mut direct_channels);
                let direct_channel_ids = direct_channels
                    .iter()
                    .map(|channel| channel.id)
                    .collect::<HashSet<_>>();
                let mut visible_user_ids = HashSet::from([user_id]);
                visible_user_ids.extend(store.memberships.iter().filter_map(
                    |(guild_id, member_id)| {
                        guild_access.get(guild_id).and_then(|permissions| {
                            permissions
                                .contains(GuildPermissions::VIEW_MEMBER_LIST)
                                .then_some(*member_id)
                        })
                    },
                ));
                let mut messages = Vec::new();
                for (channel_id, channel_messages) in &store.messages {
                    if !visible_channels.contains(channel_id)
                        && !direct_channel_ids.contains(channel_id)
                    {
                        continue;
                    }
                    let mut window = channel_messages.clone();
                    window.sort_by_key(|message| std::cmp::Reverse(message.id.raw()));
                    window.truncate(100);
                    messages.extend(window);
                }
                messages.sort_by_key(|message| (message.channel_id, message.id));
                hydrate_memory_reactions(&store, user_id, &mut messages);
                visible_user_ids.extend(messages.iter().map(|message| message.author_id));
                visible_user_ids.extend(
                    direct_channels
                        .iter()
                        .flat_map(|channel| channel.recipients.iter().map(|user| user.id)),
                );
                let mut relationships = store
                    .relationships
                    .iter()
                    .filter_map(|((owner_id, target_id), relationship)| {
                        if *owner_id != user_id {
                            return None;
                        }
                        store
                            .users
                            .get(target_id)
                            .cloned()
                            .map(|user| Relationship {
                                user,
                                kind: relationship.kind,
                                since: relationship.since,
                            })
                    })
                    .collect::<Vec<_>>();
                sort_relationships(&mut relationships);
                visible_user_ids.extend(relationships.iter().map(|value| value.user.id));
                let mut read_states = store
                    .read_states
                    .iter()
                    .filter_map(|((owner_id, channel_id), read_state)| {
                        (*owner_id == user_id
                            && (visible_channels.contains(channel_id)
                                || direct_channel_ids.contains(channel_id)))
                        .then_some(read_state.clone())
                    })
                    .collect::<Vec<_>>();
                read_states.sort_by_key(|state| state.channel_id);
                let mut users = store
                    .users
                    .values()
                    .filter(|user| visible_user_ids.contains(&user.id))
                    .cloned()
                    .collect::<Vec<_>>();
                users.sort_by_key(|user| user.id);
                let mut guild_members = store
                    .memberships
                    .iter()
                    .filter_map(|(guild_id, member_id)| {
                        guild_access
                            .get(guild_id)
                            .is_some_and(|permissions| {
                                permissions.contains(GuildPermissions::VIEW_MEMBER_LIST)
                            })
                            .then_some(GuildMemberReference {
                                guild_id: *guild_id,
                                user_id: *member_id,
                            })
                    })
                    .collect::<Vec<_>>();
                guild_members.sort_by_key(|member| (member.guild_id, member.user_id));
                Ok(SyncSnapshot {
                    current_user,
                    users,
                    guilds,
                    guild_access: guild_access
                        .into_iter()
                        .map(|(guild_id, permissions)| GuildAccess {
                            guild_id,
                            permissions,
                        })
                        .collect(),
                    guild_members,
                    channels,
                    direct_channels,
                    relationships,
                    read_states,
                    presences: Vec::new(),
                    messages,
                    last_sequence,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let current_user = sqlx::query(
                    "SELECT id, username, display_name, avatar_hash, created_at
                     FROM users WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_optional(pool)
                .await?
                .as_ref()
                .map(user_from_row)
                .transpose()?
                .ok_or(RepositoryError::NotFound("user"))?;
                let guilds = postgres_guilds(pool, user_id).await?;
                let mut guild_access = HashMap::new();
                for guild in &guilds {
                    guild_access.insert(
                        guild.id,
                        postgres_actor_context(pool, user_id, guild.id)
                            .await?
                            .permissions,
                    );
                }
                let user_rows = sqlx::query(
                    "SELECT u.id, u.username, u.display_name, u.avatar_hash, u.created_at,
                            member.guild_id
                     FROM guild_members mine
                     JOIN guild_members member ON member.guild_id = mine.guild_id
                     JOIN users u ON u.id = member.user_id
                     JOIN guilds g ON g.id = mine.guild_id
                     WHERE mine.user_id = $1 AND g.deleted_at IS NULL
                       AND u.deleted_at IS NULL
                     ORDER BY u.id, member.guild_id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let channel_rows = sqlx::query(
                    "SELECT c.id, c.guild_id, c.name, c.type, c.position, c.e2ee, c.created_at
                     FROM channels c
                     JOIN guilds g ON g.id = c.guild_id
                     JOIN guild_members gm ON gm.guild_id = g.id AND gm.user_id = $1
                     WHERE c.deleted_at IS NULL AND g.deleted_at IS NULL
                     ORDER BY c.guild_id, c.position, c.id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let candidate_channels = channel_rows
                    .iter()
                    .map(channel_from_row)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut channel_permissions = HashMap::new();
                for guild in &guilds {
                    let ids = candidate_channels
                        .iter()
                        .filter(|channel| channel.guild_id == guild.id)
                        .map(|channel| channel.id);
                    channel_permissions.extend(
                        postgres_channel_permission_map(pool, user_id, guild.id, ids).await?,
                    );
                }
                let channels = candidate_channels
                    .into_iter()
                    .filter(|channel| {
                        channel_permissions
                            .get(&channel.id)
                            .is_some_and(|permissions| {
                                permissions.contains(GuildPermissions::VIEW_CHANNEL)
                            })
                    })
                    .collect::<Vec<_>>();
                let readable_channel_ids = channels
                    .iter()
                    .filter_map(|channel| {
                        channel_permissions
                            .get(&channel.id)
                            .and_then(|permissions| {
                                permissions
                                    .contains(GuildPermissions::READ_MESSAGE_HISTORY)
                                    .then_some(channel.id)
                            })
                    })
                    .collect::<HashSet<_>>();
                let direct_channels = postgres_direct_channels(pool, user_id).await?;
                let direct_channel_ids = direct_channels
                    .iter()
                    .map(|channel| channel.id)
                    .collect::<HashSet<_>>();
                let message_rows = sqlx::query(
                    "SELECT recent.id, recent.channel_id, recent.author_id, recent.content,
                            recent.ciphertext, recent.frank_commit, recent.frank_tag,
                            recent.sender_device_id, recent.nonce, recent.attachments,
                            recent.reference_id,
                            recent.sequence, recent.created_at, recent.edited_at
                     FROM channels c
                     JOIN guilds g ON g.id = c.guild_id
                     JOIN guild_members gm ON gm.guild_id = g.id AND gm.user_id = $1
                     CROSS JOIN LATERAL (
                       SELECT m.id, m.channel_id, m.author_id,
                              COALESCE(m.content, '') AS content, m.ciphertext,
                              m.frank_commit, m.frank_tag, m.sender_device_id, m.nonce,
                              m.attachments, m.reference_id, m.sequence,
                              snowflake_to_timestamp(m.id) AS created_at, m.edited_at
                       FROM messages m
                       WHERE m.channel_id = c.id AND m.deleted_at IS NULL
                       ORDER BY m.id DESC LIMIT 100
                     ) recent
                     WHERE c.deleted_at IS NULL AND g.deleted_at IS NULL
                     ORDER BY recent.channel_id, recent.id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let mut messages = message_rows
                    .iter()
                    .map(message_from_row)
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|message| readable_channel_ids.contains(&message.channel_id))
                    .collect::<Vec<_>>();
                if !direct_channel_ids.is_empty() {
                    let direct_ids = direct_channel_ids
                        .iter()
                        .map(|channel_id| db_id(channel_id.raw()))
                        .collect::<Result<Vec<_>, _>>()?;
                    let rows = sqlx::query(
                        "SELECT recent.id, recent.channel_id, recent.author_id, recent.content,
                                recent.ciphertext, recent.frank_commit, recent.frank_tag,
                                recent.sender_device_id, recent.nonce, recent.attachments,
                                recent.reference_id,
                                recent.sequence, recent.created_at, recent.edited_at
                         FROM channels c
                         CROSS JOIN LATERAL (
                           SELECT m.id, m.channel_id, m.author_id,
                                  COALESCE(m.content, '') AS content, m.ciphertext,
                                  m.frank_commit, m.frank_tag, m.sender_device_id, m.nonce,
                                  m.attachments, m.reference_id, m.sequence,
                                  snowflake_to_timestamp(m.id) AS created_at, m.edited_at
                           FROM messages m
                           WHERE m.channel_id = c.id AND m.deleted_at IS NULL
                           ORDER BY m.id DESC LIMIT 100
                         ) recent
                         WHERE c.id = ANY($1)
                         ORDER BY recent.channel_id, recent.id",
                    )
                    .bind(&direct_ids)
                    .fetch_all(pool)
                    .await?;
                    messages.extend(
                        rows.iter()
                            .map(message_from_row)
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                }
                messages.sort_by_key(|message| (message.channel_id, message.id));
                hydrate_postgres_reactions(pool, user_id, &mut messages).await?;
                let visible_authors = messages
                    .iter()
                    .map(|message| message.author_id)
                    .chain(std::iter::once(user_id))
                    .collect::<HashSet<_>>();
                let mut users_by_id = HashMap::new();
                let mut guild_members = Vec::new();
                for row in &user_rows {
                    let member = user_from_row(row)?;
                    let guild_id = guild_id_from_db(row.try_get("guild_id")?)?;
                    let can_view_members = guild_access.get(&guild_id).is_some_and(|permissions| {
                        permissions.contains(GuildPermissions::VIEW_MEMBER_LIST)
                    });
                    if can_view_members {
                        guild_members.push(GuildMemberReference {
                            guild_id,
                            user_id: member.id,
                        });
                    }
                    if visible_authors.contains(&member.id) || can_view_members {
                        users_by_id.insert(member.id, member);
                    }
                }
                guild_members.sort_by_key(|member| (member.guild_id, member.user_id));
                guild_members.dedup_by_key(|member| (member.guild_id, member.user_id));
                for channel in &direct_channels {
                    for recipient in &channel.recipients {
                        users_by_id.insert(recipient.id, recipient.clone());
                    }
                }
                let relationships = self.list_relationships(user_id).await?;
                for relationship in &relationships {
                    users_by_id.insert(relationship.user.id, relationship.user.clone());
                }
                let mut visible_channel_ids = readable_channel_ids;
                visible_channel_ids.extend(direct_channel_ids);
                let read_states = postgres_read_states(pool, user_id, &visible_channel_ids).await?;
                let mut users = users_by_id.into_values().collect::<Vec<_>>();
                users.sort_by_key(|user| user.id);
                Ok(SyncSnapshot {
                    current_user,
                    users,
                    guilds,
                    guild_access: guild_access
                        .into_iter()
                        .map(|(guild_id, permissions)| GuildAccess {
                            guild_id,
                            permissions,
                        })
                        .collect(),
                    guild_members,
                    channels,
                    direct_channels,
                    relationships,
                    read_states,
                    presences: Vec::new(),
                    messages,
                    last_sequence,
                })
            }
        }
    }

    pub async fn list_guilds(&self, user_id: UserId) -> Result<Vec<Guild>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let mut guilds = store
                    .guilds
                    .values()
                    .filter(|guild| {
                        !store.deleted_guilds.contains(&guild.id)
                            && store.memberships.contains(&(guild.id, user_id))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                guilds.sort_by_key(|guild| guild.created_at);
                Ok(guilds)
            }
            RepositoryBackend::Postgres(pool) => postgres_guilds(pool, user_id).await,
        }
    }

    pub async fn owned_guilds(
        &self,
        user_id: UserId,
    ) -> Result<Vec<OwnedGuildRecord>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let mut guilds = store
                    .guilds
                    .values()
                    .filter(|guild| {
                        guild.owner_id == user_id && !store.deleted_guilds.contains(&guild.id)
                    })
                    .map(|guild| {
                        let count = store
                            .memberships
                            .iter()
                            .filter(|(guild_id, _)| *guild_id == guild.id)
                            .count();
                        Ok(OwnedGuildRecord {
                            guild: guild.clone(),
                            member_count: u32::try_from(count).map_err(|_| {
                                RepositoryError::InvalidData("member count exceeds u32")
                            })?,
                        })
                    })
                    .collect::<Result<Vec<_>, RepositoryError>>()?;
                guilds.sort_by_key(|record| (record.guild.created_at, record.guild.id));
                Ok(guilds)
            }
            RepositoryBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT g.id, g.owner_id, g.name, g.accent, g.created_at,
                            COUNT(gm.user_id)::bigint AS member_count
                       FROM guilds g
                       LEFT JOIN guild_members gm ON gm.guild_id = g.id
                      WHERE g.owner_id = $1 AND g.deleted_at IS NULL
                      GROUP BY g.id
                      ORDER BY g.created_at, g.id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter()
                    .map(|row| {
                        Ok(OwnedGuildRecord {
                            guild: guild_from_row(row)?,
                            member_count: u32::try_from(row.try_get::<i64, _>("member_count")?)
                                .map_err(|_| {
                                    RepositoryError::InvalidData("member count exceeds u32")
                                })?,
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn prepare_account_deletion(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<Vec<OwnedGuildRecord>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                if !store.users.contains_key(&user_id) {
                    return Err(RepositoryError::NotFound("user"));
                }
                let owned = store
                    .guilds
                    .values()
                    .filter(|guild| {
                        guild.owner_id == user_id && !store.deleted_guilds.contains(&guild.id)
                    })
                    .map(|guild| {
                        let count = store
                            .memberships
                            .iter()
                            .filter(|(candidate, _)| *candidate == guild.id)
                            .count();
                        Ok(OwnedGuildRecord {
                            guild: guild.clone(),
                            member_count: u32::try_from(count).map_err(|_| {
                                RepositoryError::InvalidData("member count exceeds u32")
                            })?,
                        })
                    })
                    .collect::<Result<Vec<_>, RepositoryError>>()?;
                let blockers = owned
                    .iter()
                    .filter(|record| record.member_count > 1)
                    .cloned()
                    .collect::<Vec<_>>();
                if !blockers.is_empty() {
                    return Ok(blockers);
                }
                let guild_ids = owned
                    .iter()
                    .map(|record| record.guild.id)
                    .collect::<HashSet<_>>();
                store
                    .owner_deletion_pending
                    .extend(guild_ids.iter().copied());
                store
                    .invites
                    .retain(|_, invite| !guild_ids.contains(&invite.guild_id));
                Ok(Vec::new())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let rows = sqlx::query(
                    "SELECT id, owner_id, name, accent, created_at
                       FROM guilds
                      WHERE owner_id = $1 AND deleted_at IS NULL
                      ORDER BY id
                      FOR UPDATE",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(&mut *transaction)
                .await?;
                let mut owned = Vec::with_capacity(rows.len());
                for row in &rows {
                    let guild = guild_from_row(row)?;
                    let member_count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM guild_members WHERE guild_id = $1",
                    )
                    .bind(db_id(guild.id.raw())?)
                    .fetch_one(&mut *transaction)
                    .await?;
                    owned.push(OwnedGuildRecord {
                        guild,
                        member_count: u32::try_from(member_count).map_err(|_| {
                            RepositoryError::InvalidData("member count exceeds u32")
                        })?,
                    });
                }
                let blockers = owned
                    .iter()
                    .filter(|record| record.member_count > 1)
                    .cloned()
                    .collect::<Vec<_>>();
                if !blockers.is_empty() {
                    transaction.rollback().await?;
                    return Ok(blockers);
                }
                for record in &owned {
                    sqlx::query(
                        "UPDATE guilds
                            SET owner_deletion_pending_at =
                                COALESCE(owner_deletion_pending_at, $1)
                          WHERE id = $2",
                    )
                    .bind(now)
                    .bind(db_id(record.guild.id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    sqlx::query(
                        "UPDATE guild_invites
                            SET revoked_at = COALESCE(revoked_at, $1)
                          WHERE guild_id = $2",
                    )
                    .bind(now)
                    .bind(db_id(record.guild.id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                }
                transaction.commit().await?;
                Ok(Vec::new())
            }
        }
    }

    pub async fn cancel_account_deletion_preparation(
        &self,
        user_id: UserId,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let owned = store
                    .guilds
                    .values()
                    .filter_map(|guild| {
                        (guild.owner_id == user_id && !store.deleted_guilds.contains(&guild.id))
                            .then_some(guild.id)
                    })
                    .collect::<Vec<_>>();
                for guild_id in owned {
                    store.owner_deletion_pending.remove(&guild_id);
                }
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                sqlx::query(
                    "UPDATE guilds
                        SET owner_deletion_pending_at = NULL
                      WHERE owner_id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(user_id.raw())?)
                .execute(pool)
                .await?;
                Ok(())
            }
        }
    }

    pub async fn transfer_guild_ownership(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        new_owner_id: UserId,
    ) -> Result<Guild, RepositoryError> {
        if actor_id == new_owner_id {
            return Err(RepositoryError::BadRequest(
                "the selected member already owns this server",
            ));
        }
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let guild = store
                    .guilds
                    .get(&guild_id)
                    .filter(|_| !store.deleted_guilds.contains(&guild_id))
                    .cloned()
                    .ok_or(RepositoryError::NotFound("server"))?;
                if guild.owner_id != actor_id {
                    return Err(RepositoryError::Forbidden);
                }
                if !store.memberships.contains(&(guild_id, new_owner_id))
                    || !store.users.contains_key(&new_owner_id)
                {
                    return Err(RepositoryError::NotFound("member"));
                }
                let updated = {
                    let stored = store
                        .guilds
                        .get_mut(&guild_id)
                        .ok_or(RepositoryError::NotFound("server"))?;
                    stored.owner_id = new_owner_id;
                    stored.clone()
                };
                store.owner_deletion_pending.remove(&guild_id);
                push_memory_audit_entry(
                    &mut store,
                    guild_id,
                    Some(actor_id),
                    Some(new_owner_id.raw()),
                    AUDIT_GUILD_OWNERSHIP_TRANSFER,
                    serde_json::json!({
                        "ownerId": {
                            "old": actor_id.to_string(),
                            "new": new_owner_id.to_string()
                        }
                    }),
                    None,
                );
                Ok(updated)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let row = sqlx::query(
                    "SELECT id, owner_id, name, accent, created_at
                       FROM guilds
                      WHERE id = $1 AND deleted_at IS NULL
                      FOR UPDATE",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("server"))?;
                let mut guild = guild_from_row(&row)?;
                if guild.owner_id != actor_id {
                    return Err(RepositoryError::Forbidden);
                }
                let target_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                       SELECT 1
                         FROM guild_members gm
                         JOIN users u ON u.id = gm.user_id
                        WHERE gm.guild_id = $1 AND gm.user_id = $2
                          AND u.deleted_at IS NULL
                     )",
                )
                .bind(db_id(guild_id.raw())?)
                .bind(db_id(new_owner_id.raw())?)
                .fetch_one(&mut *transaction)
                .await?;
                if !target_exists {
                    return Err(RepositoryError::NotFound("member"));
                }
                sqlx::query(
                    "UPDATE guilds
                        SET owner_id = $1, owner_deletion_pending_at = NULL
                      WHERE id = $2",
                )
                .bind(db_id(new_owner_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    new_owner_id.raw(),
                    AUDIT_GUILD_OWNERSHIP_TRANSFER,
                    serde_json::json!({
                        "ownerId": {
                            "old": actor_id.to_string(),
                            "new": new_owner_id.to_string()
                        }
                    }),
                )
                .await?;
                transaction.commit().await?;
                guild.owner_id = new_owner_id;
                Ok(guild)
            }
        }
    }

    pub async fn delete_guild(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        confirmation: &str,
        now: DateTime<Utc>,
    ) -> Result<DeletedGuildRecord, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let guild = store
                    .guilds
                    .get(&guild_id)
                    .filter(|_| !store.deleted_guilds.contains(&guild_id))
                    .cloned()
                    .ok_or(RepositoryError::NotFound("server"))?;
                if guild.owner_id != actor_id {
                    return Err(RepositoryError::Forbidden);
                }
                if confirmation != guild.name {
                    return Err(RepositoryError::Validation(
                        "type the server name exactly to delete it".into(),
                    ));
                }
                let mut member_ids = store
                    .memberships
                    .iter()
                    .filter_map(|(candidate, member_id)| {
                        (*candidate == guild_id).then_some(*member_id)
                    })
                    .collect::<Vec<_>>();
                member_ids.sort_unstable();
                let mut voice_channel_ids = store
                    .channels
                    .values()
                    .filter_map(|channel| {
                        (channel.guild_id == guild_id && channel.kind == ChannelKind::Voice)
                            .then_some(channel.id)
                    })
                    .collect::<Vec<_>>();
                voice_channel_ids.sort_unstable();
                push_memory_audit_entry(
                    &mut store,
                    guild_id,
                    Some(actor_id),
                    Some(guild_id.raw()),
                    AUDIT_GUILD_DELETE,
                    serde_json::json!({ "deletedAt": now }),
                    None,
                );
                store.deleted_guilds.insert(guild_id);
                store.owner_deletion_pending.remove(&guild_id);
                store
                    .invites
                    .retain(|_, invite| invite.guild_id != guild_id);
                Ok(DeletedGuildRecord {
                    guild,
                    member_ids,
                    voice_channel_ids,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let row = sqlx::query(
                    "SELECT id, owner_id, name, accent, created_at
                       FROM guilds
                      WHERE id = $1 AND deleted_at IS NULL
                      FOR UPDATE",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("server"))?;
                let guild = guild_from_row(&row)?;
                if guild.owner_id != actor_id {
                    return Err(RepositoryError::Forbidden);
                }
                if confirmation != guild.name {
                    return Err(RepositoryError::Validation(
                        "type the server name exactly to delete it".into(),
                    ));
                }
                let member_ids = sqlx::query_scalar::<_, i64>(
                    "SELECT user_id
                       FROM guild_members
                      WHERE guild_id = $1
                      ORDER BY user_id",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_all(&mut *transaction)
                .await?
                .into_iter()
                .map(user_id_from_db)
                .collect::<Result<Vec<_>, _>>()?;
                let voice_channel_ids = sqlx::query_scalar::<_, i64>(
                    "SELECT id
                       FROM channels
                      WHERE guild_id = $1 AND type = $2 AND deleted_at IS NULL
                      ORDER BY id",
                )
                .bind(db_id(guild_id.raw())?)
                .bind(channel_kind_to_db(ChannelKind::Voice))
                .fetch_all(&mut *transaction)
                .await?
                .into_iter()
                .map(channel_id_from_db)
                .collect::<Result<Vec<_>, _>>()?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    guild_id.raw(),
                    AUDIT_GUILD_DELETE,
                    serde_json::json!({ "deletedAt": now }),
                )
                .await?;
                sqlx::query(
                    "UPDATE guild_invites
                        SET revoked_at = COALESCE(revoked_at, $1)
                      WHERE guild_id = $2",
                )
                .bind(now)
                .bind(db_id(guild_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "UPDATE channels
                        SET deleted_at = COALESCE(deleted_at, $1)
                      WHERE guild_id = $2",
                )
                .bind(now)
                .bind(db_id(guild_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "UPDATE guilds
                        SET deleted_at = $1, owner_deletion_pending_at = NULL
                      WHERE id = $2",
                )
                .bind(now)
                .bind(db_id(guild_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                Ok(DeletedGuildRecord {
                    guild,
                    member_ids,
                    voice_channel_ids,
                })
            }
        }
    }

    pub async fn is_guild_member(
        &self,
        user_id: UserId,
        guild_id: GuildId,
    ) -> Result<bool, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                Ok(!store.deleted_guilds.contains(&guild_id)
                    && store.memberships.contains(&(guild_id, user_id)))
            }
            RepositoryBackend::Postgres(pool) => sqlx::query_scalar(
                "SELECT EXISTS(
                       SELECT 1 FROM guild_members gm
                       JOIN guilds g ON g.id = gm.guild_id
                       WHERE gm.guild_id = $1 AND gm.user_id = $2
                         AND g.deleted_at IS NULL
                     )",
            )
            .bind(db_id(guild_id.raw())?)
            .bind(db_id(user_id.raw())?)
            .fetch_one(pool)
            .await
            .map_err(Into::into),
        }
    }

    pub async fn channel_guild_id(
        &self,
        channel_id: ChannelId,
    ) -> Result<GuildId, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                store
                    .channels
                    .get(&channel_id)
                    .filter(|channel| !store.deleted_guilds.contains(&channel.guild_id))
                    .map(|channel| channel.guild_id)
                    .ok_or(RepositoryError::NotFound("channel"))
            }
            RepositoryBackend::Postgres(pool) => postgres_channel_guild(pool, channel_id).await,
        }
    }

    pub async fn voice_channel_ids(
        &self,
        guild_id: GuildId,
    ) -> Result<Vec<ChannelId>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                if !store.guilds.contains_key(&guild_id) || store.deleted_guilds.contains(&guild_id)
                {
                    return Err(RepositoryError::NotFound("server"));
                }
                Ok(store
                    .channels
                    .values()
                    .filter(|channel| {
                        channel.guild_id == guild_id && channel.kind == ChannelKind::Voice
                    })
                    .map(|channel| channel.id)
                    .collect())
            }
            RepositoryBackend::Postgres(pool) => {
                let rows = sqlx::query_scalar::<_, i64>(
                    "SELECT c.id
                     FROM channels c
                     JOIN guilds g ON g.id = c.guild_id
                     WHERE c.guild_id = $1 AND c.type = $2
                       AND c.deleted_at IS NULL AND g.deleted_at IS NULL
                     ORDER BY c.position, c.id",
                )
                .bind(db_id(guild_id.raw())?)
                .bind(channel_kind_to_db(ChannelKind::Voice))
                .fetch_all(pool)
                .await?;
                rows.into_iter().map(channel_id_from_db).collect()
            }
        }
    }

    /// Resolves the current member's effective channel permissions immediately
    /// before a media credential is issued.
    pub async fn voice_access(
        &self,
        user_id: UserId,
        channel_id: ChannelId,
    ) -> Result<VoiceAccess, RepositoryError> {
        let required = GuildPermissions::VIEW_CHANNEL | GuildPermissions::CONNECT;
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let Some(channel) = store.channels.get(&channel_id).cloned() else {
                    memory_message_audience(&store, user_id, channel_id, true)?;
                    let user = store
                        .users
                        .get(&user_id)
                        .cloned()
                        .ok_or(RepositoryError::NotFound("user"))?;
                    return Ok(VoiceAccess {
                        channel_id,
                        guild_id: None,
                        user,
                        permissions: GuildPermissions::VIEW_CHANNEL
                            | GuildPermissions::CONNECT
                            | GuildPermissions::SPEAK
                            | GuildPermissions::USE_VAD
                            | GuildPermissions::STREAM,
                    });
                };
                if channel.kind != ChannelKind::Voice {
                    return Err(RepositoryError::BadRequest(
                        "voice grants require a voice channel",
                    ));
                }
                let permissions = memory_channel_permissions(&store, user_id, &channel)?;
                if !permissions.contains(required) {
                    return Err(RepositoryError::NotFound("channel"));
                }
                let user = store
                    .users
                    .get(&user_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("user"))?;
                Ok(VoiceAccess {
                    channel_id: channel.id,
                    guild_id: Some(channel.guild_id),
                    user,
                    permissions,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let base_row = sqlx::query(
                    "SELECT guild_id, type
                       FROM channels
                      WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(channel_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                let base_guild_id = base_row.try_get::<Option<i64>, _>("guild_id")?;
                let base_type = base_row.try_get::<i16, _>("type")?;
                if base_guild_id.is_none() && base_type == 1 {
                    require_message_access(pool, user_id, channel_id, true).await?;
                    let user = sqlx::query(
                        "SELECT id, username, display_name, avatar_hash, created_at
                         FROM users WHERE id = $1 AND deleted_at IS NULL",
                    )
                    .bind(db_id(user_id.raw())?)
                    .fetch_optional(pool)
                    .await?
                    .as_ref()
                    .map(user_from_row)
                    .transpose()?
                    .ok_or(RepositoryError::NotFound("user"))?;
                    return Ok(VoiceAccess {
                        channel_id,
                        guild_id: None,
                        user,
                        permissions: GuildPermissions::VIEW_CHANNEL
                            | GuildPermissions::CONNECT
                            | GuildPermissions::SPEAK
                            | GuildPermissions::USE_VAD
                            | GuildPermissions::STREAM,
                    });
                }
                let channel_row = sqlx::query(
                    "SELECT c.id, c.guild_id, c.name, c.type, c.position, c.e2ee, c.created_at
                     FROM channels c
                     JOIN guilds g ON g.id = c.guild_id
                     JOIN guild_members gm ON gm.guild_id = g.id AND gm.user_id = $2
                     WHERE c.id = $1 AND c.deleted_at IS NULL AND g.deleted_at IS NULL",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(user_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                let channel = channel_from_row(&channel_row)?;
                if channel.kind != ChannelKind::Voice {
                    return Err(RepositoryError::BadRequest(
                        "voice grants require a voice channel",
                    ));
                }
                let permissions =
                    postgres_channel_permission_map(pool, user_id, channel.guild_id, [channel_id])
                        .await?
                        .remove(&channel_id)
                        .ok_or(RepositoryError::NotFound("channel"))?;
                if !permissions.contains(required) {
                    return Err(RepositoryError::NotFound("channel"));
                }
                let user = sqlx::query(
                    "SELECT id, username, display_name, avatar_hash, created_at
                     FROM users WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_optional(pool)
                .await?
                .as_ref()
                .map(user_from_row)
                .transpose()?
                .ok_or(RepositoryError::NotFound("user"))?;
                Ok(VoiceAccess {
                    channel_id: channel.id,
                    guild_id: Some(channel.guild_id),
                    user,
                    permissions,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_invite(
        &self,
        creator_id: UserId,
        guild_id: GuildId,
        code: String,
        code_hash: &[u8],
        max_uses: Option<u32>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<GuildInvite, RepositoryError> {
        let created_at = Utc::now();
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                if store.owner_deletion_pending.contains(&guild_id) {
                    return Err(RepositoryError::Conflict);
                }
                let access = memory_actor_context(&store, creator_id, guild_id)?;
                if !access.permissions.contains(GuildPermissions::CREATE_INVITE) {
                    return Err(RepositoryError::Forbidden);
                }
                if store.invites.contains_key(code_hash) {
                    return Err(RepositoryError::Conflict);
                }
                store.invites.insert(
                    code_hash.to_vec(),
                    MemoryInvite {
                        guild_id,
                        uses: 0,
                        max_uses,
                        expires_at,
                    },
                );
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let access =
                    postgres_actor_context_for_update(&mut transaction, creator_id, guild_id)
                        .await?;
                if !access.permissions.contains(GuildPermissions::CREATE_INVITE) {
                    return Err(RepositoryError::Forbidden);
                }
                let accepting_invites: bool = sqlx::query_scalar(
                    "SELECT owner_deletion_pending_at IS NULL
                       FROM guilds
                      WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_one(&mut *transaction)
                .await?;
                if !accepting_invites {
                    return Err(RepositoryError::Conflict);
                }
                let inserted = sqlx::query(
                    "INSERT INTO guild_invites
                       (code_hash, guild_id, creator_id, max_uses, expires_at, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (code_hash) DO NOTHING",
                )
                .bind(code_hash)
                .bind(db_id(guild_id.raw())?)
                .bind(db_id(creator_id.raw())?)
                .bind(
                    max_uses
                        .map(i32::try_from)
                        .transpose()
                        .map_err(|_| RepositoryError::BadRequest("max uses is too large"))?,
                )
                .bind(expires_at)
                .bind(created_at)
                .execute(&mut *transaction)
                .await?;
                if inserted.rows_affected() == 0 {
                    return Err(RepositoryError::Conflict);
                }
                transaction.commit().await?;
            }
        }
        Ok(GuildInvite {
            code,
            guild_id,
            creator_id,
            uses: 0,
            max_uses,
            expires_at,
            created_at,
        })
    }

    pub async fn preview_invite(
        &self,
        code: String,
        code_hash: &[u8],
    ) -> Result<InvitePreview, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let invite = store
                    .invites
                    .get(code_hash)
                    .filter(|invite| {
                        invite_is_available(invite)
                            && !store.deleted_guilds.contains(&invite.guild_id)
                            && !store.owner_deletion_pending.contains(&invite.guild_id)
                    })
                    .ok_or(RepositoryError::InviteUnavailable)?;
                let guild = store
                    .guilds
                    .get(&invite.guild_id)
                    .cloned()
                    .ok_or(RepositoryError::InviteUnavailable)?;
                let member_count = u32::try_from(
                    store
                        .memberships
                        .iter()
                        .filter(|(guild_id, _)| *guild_id == invite.guild_id)
                        .count(),
                )
                .map_err(|_| RepositoryError::InvalidData("member count exceeds u32"))?;
                Ok(InvitePreview {
                    code,
                    guild,
                    member_count,
                    uses: invite.uses,
                    max_uses: invite.max_uses,
                    expires_at: invite.expires_at,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT i.uses, i.max_uses, i.expires_at,
                            g.id, g.owner_id, g.name, g.accent, g.created_at,
                            g.member_count
                     FROM guild_invites i
                     JOIN guilds g ON g.id = i.guild_id
                     WHERE i.code_hash = $1 AND i.revoked_at IS NULL
                       AND (i.expires_at IS NULL OR i.expires_at > now())
                       AND (i.max_uses IS NULL OR i.uses < i.max_uses)
                       AND g.deleted_at IS NULL
                       AND g.owner_deletion_pending_at IS NULL",
                )
                .bind(code_hash)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::InviteUnavailable)?;
                Ok(InvitePreview {
                    code,
                    guild: guild_from_row(&row)?,
                    member_count: u32::try_from(row.try_get::<i32, _>("member_count")?)
                        .map_err(|_| RepositoryError::InvalidData("member count is negative"))?,
                    uses: u32::try_from(row.try_get::<i32, _>("uses")?)
                        .map_err(|_| RepositoryError::InvalidData("invite uses are negative"))?,
                    max_uses: row
                        .try_get::<Option<i32>, _>("max_uses")?
                        .map(u32::try_from)
                        .transpose()
                        .map_err(|_| {
                            RepositoryError::InvalidData("invite max uses are negative")
                        })?,
                    expires_at: row.try_get("expires_at")?,
                })
            }
        }
    }

    pub async fn accept_invite(
        &self,
        user_id: UserId,
        code_hash: &[u8],
    ) -> Result<Guild, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let invite = store
                    .invites
                    .get(code_hash)
                    .cloned()
                    .ok_or(RepositoryError::InviteUnavailable)?;
                if store.deleted_guilds.contains(&invite.guild_id)
                    || store.owner_deletion_pending.contains(&invite.guild_id)
                {
                    return Err(RepositoryError::InviteUnavailable);
                }
                let already_member = store.memberships.contains(&(invite.guild_id, user_id));
                if !already_member && !invite_is_available(&invite) {
                    return Err(RepositoryError::InviteUnavailable);
                }
                if !already_member {
                    if store
                        .bans
                        .get(&(invite.guild_id, user_id))
                        .is_some_and(|ban| {
                            ban.expires_at.is_none_or(|expires| expires > Utc::now())
                        })
                    {
                        return Err(RepositoryError::Forbidden);
                    }
                    if !store.users.contains_key(&user_id) {
                        return Err(RepositoryError::NotFound("user"));
                    }
                    store.memberships.insert((invite.guild_id, user_id));
                    let record = store
                        .invites
                        .get_mut(code_hash)
                        .ok_or(RepositoryError::InviteUnavailable)?;
                    record.uses = record.uses.saturating_add(1);
                }
                store
                    .guilds
                    .get(&invite.guild_id)
                    .cloned()
                    .ok_or(RepositoryError::InviteUnavailable)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let row = sqlx::query(
                    "SELECT i.guild_id, i.uses, i.max_uses, i.expires_at, i.revoked_at,
                            g.id, g.owner_id, g.name, g.accent, g.created_at
                     FROM guild_invites i
                     JOIN guilds g ON g.id = i.guild_id
                     WHERE i.code_hash = $1 AND g.deleted_at IS NULL
                       AND g.owner_deletion_pending_at IS NULL
                     FOR UPDATE OF i, g",
                )
                .bind(code_hash)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::InviteUnavailable)?;
                let guild = guild_from_row(&row)?;
                let already_member: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                       SELECT 1 FROM guild_members
                       WHERE guild_id = $1 AND user_id = $2
                     )",
                )
                .bind(db_id(guild.id.raw())?)
                .bind(db_id(user_id.raw())?)
                .fetch_one(&mut *transaction)
                .await?;
                let uses: i32 = row.try_get("uses")?;
                let max_uses: Option<i32> = row.try_get("max_uses")?;
                let expires_at: Option<chrono::DateTime<Utc>> = row.try_get("expires_at")?;
                let revoked_at: Option<chrono::DateTime<Utc>> = row.try_get("revoked_at")?;
                let unavailable = revoked_at.is_some()
                    || expires_at.is_some_and(|expiry| expiry <= Utc::now())
                    || max_uses.is_some_and(|maximum| uses >= maximum);
                if !already_member && unavailable {
                    return Err(RepositoryError::InviteUnavailable);
                }
                if !already_member {
                    let banned: bool = sqlx::query_scalar(
                        "SELECT EXISTS(
                           SELECT 1 FROM bans
                           WHERE guild_id = $1 AND user_id = $2
                             AND (expires_at IS NULL OR expires_at > now())
                         )",
                    )
                    .bind(db_id(guild.id.raw())?)
                    .bind(db_id(user_id.raw())?)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if banned {
                        return Err(RepositoryError::Forbidden);
                    }
                    let inserted = sqlx::query(
                        "INSERT INTO guild_members (guild_id, user_id)
                         VALUES ($1, $2)
                         ON CONFLICT (guild_id, user_id) DO NOTHING",
                    )
                    .bind(db_id(guild.id.raw())?)
                    .bind(db_id(user_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    if inserted.rows_affected() == 1 {
                        sqlx::query(
                            "UPDATE guild_invites SET uses = uses + 1 WHERE code_hash = $1",
                        )
                        .bind(code_hash)
                        .execute(&mut *transaction)
                        .await?;
                        sqlx::query(
                            "UPDATE guilds SET member_count = member_count + 1 WHERE id = $1",
                        )
                        .bind(db_id(guild.id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                    }
                }
                transaction.commit().await?;
                Ok(guild)
            }
        }
    }

    pub async fn channel_event_audience(
        &self,
        user_id: UserId,
        channel_id: ChannelId,
        sending: bool,
    ) -> Result<MessageAudience, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                memory_message_audience(&store, user_id, channel_id, sending)
            }
            RepositoryBackend::Postgres(pool) => {
                require_message_access(pool, user_id, channel_id, sending).await
            }
        }
    }

    pub async fn mls_channel_audience(
        &self,
        user_id: UserId,
        channel_id: ChannelId,
    ) -> Result<MessageAudience, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let users = memory_mls_channel_users(&store, user_id, channel_id)?;
                Ok(store.channels.get(&channel_id).map_or_else(
                    || MessageAudience::Users(users),
                    |channel| MessageAudience::Guild(channel.guild_id),
                ))
            }
            RepositoryBackend::Postgres(pool) => {
                let users = postgres_mls_channel_users(pool, user_id, channel_id).await?;
                let guild_id: Option<i64> = sqlx::query_scalar(
                    "SELECT guild_id FROM channels WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(channel_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                guild_id.map_or_else(
                    || Ok(MessageAudience::Users(users)),
                    |id| Ok(MessageAudience::Guild(guild_id_from_db(id)?)),
                )
            }
        }
    }

    pub async fn presence_audience(&self, user_id: UserId) -> Result<Vec<UserId>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                if !store.users.contains_key(&user_id) {
                    return Err(RepositoryError::NotFound("user"));
                }
                let guild_ids = store
                    .memberships
                    .iter()
                    .filter_map(|(guild_id, member_id)| {
                        (*member_id == user_id).then_some(*guild_id)
                    })
                    .collect::<HashSet<_>>();
                let mut audience = HashSet::from([user_id]);
                audience.extend(
                    store
                        .memberships
                        .iter()
                        .filter_map(|(guild_id, member_id)| {
                            guild_ids.contains(guild_id).then_some(*member_id)
                        }),
                );
                audience.extend(store.relationships.iter().filter_map(
                    |((owner_id, target_id), relationship)| {
                        (*owner_id == user_id && relationship.kind == RelationshipKind::Friend)
                            .then_some(*target_id)
                    },
                ));
                audience.extend(store.relationships.iter().filter_map(
                    |((owner_id, target_id), relationship)| {
                        (*target_id == user_id && relationship.kind == RelationshipKind::Friend)
                            .then_some(*owner_id)
                    },
                ));
                let mut audience = audience.into_iter().collect::<Vec<_>>();
                audience.sort_unstable();
                Ok(audience)
            }
            RepositoryBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT DISTINCT audience.user_id
                     FROM (
                       SELECT $1::BIGINT AS user_id
                       UNION
                       SELECT peers.user_id
                       FROM guild_members mine
                       JOIN guild_members peers ON peers.guild_id = mine.guild_id
                       JOIN guilds g ON g.id = mine.guild_id
                       WHERE mine.user_id = $1 AND g.deleted_at IS NULL
                       UNION
                       SELECT target_id
                       FROM user_relationships
                       WHERE user_id = $1 AND state = 2
                       UNION
                       SELECT user_id
                       FROM user_relationships
                       WHERE target_id = $1 AND state = 2
                     ) audience
                     JOIN users u ON u.id = audience.user_id
                     WHERE u.deleted_at IS NULL
                     ORDER BY audience.user_id",
                )
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter()
                    .map(|row| user_id_from_db(row.try_get("user_id")?))
                    .collect()
            }
        }
    }

    pub async fn list_members(
        &self,
        user_id: UserId,
        guild_id: GuildId,
        limit: usize,
    ) -> Result<Vec<GuildMember>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                if !store.memberships.contains(&(guild_id, user_id)) {
                    return Err(RepositoryError::NotFound("server"));
                }
                let access = memory_actor_context(&store, user_id, guild_id)?;
                if !access
                    .permissions
                    .contains(GuildPermissions::VIEW_MEMBER_LIST)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let mut members = store
                    .memberships
                    .iter()
                    .filter_map(|(member_guild, member_id)| {
                        (*member_guild == guild_id)
                            .then(|| store.users.get(member_id))
                            .flatten()
                            .cloned()
                    })
                    .map(|user| GuildMember {
                        joined_at: user.created_at,
                        roles: store
                            .member_roles
                            .iter()
                            .filter_map(|(role_guild, member_id, role_id)| {
                                (*role_guild == guild_id && *member_id == user.id)
                                    .then_some(*role_id)
                            })
                            .collect(),
                        timeout_until: store
                            .timeouts
                            .get(&(guild_id, user.id))
                            .copied()
                            .filter(|timeout| *timeout > Utc::now()),
                        user,
                    })
                    .collect::<Vec<_>>();
                members.sort_by_key(|member| member.user.id);
                members.truncate(limit);
                Ok(members)
            }
            RepositoryBackend::Postgres(pool) => {
                let access = postgres_actor_context(pool, user_id, guild_id).await?;
                if !access
                    .permissions
                    .contains(GuildPermissions::VIEW_MEMBER_LIST)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let rows =
                    sqlx::query(
                        "SELECT u.id, u.username, u.display_name, u.avatar_hash, u.created_at,
                            gm.joined_at, gm.timeout_until,
                            COALESCE(
                              array_agg(mr.role_id ORDER BY r.position, mr.role_id)
                                FILTER (WHERE mr.role_id IS NOT NULL),
                              '{}'::bigint[]
                            ) AS role_ids
                     FROM guild_members viewer
                     JOIN guild_members gm ON gm.guild_id = viewer.guild_id
                     JOIN users u ON u.id = gm.user_id
                     JOIN guilds g ON g.id = viewer.guild_id
                     LEFT JOIN member_roles mr
                       ON mr.guild_id = gm.guild_id AND mr.user_id = gm.user_id
                     LEFT JOIN roles r ON r.id = mr.role_id
                     WHERE viewer.guild_id = $1 AND viewer.user_id = $2
                       AND g.deleted_at IS NULL AND u.deleted_at IS NULL
                     GROUP BY u.id, gm.joined_at, gm.timeout_until
                     ORDER BY gm.joined_at, u.id
                     LIMIT $3",
                    )
                    .bind(db_id(guild_id.raw())?)
                    .bind(db_id(user_id.raw())?)
                    .bind(i64::try_from(limit).map_err(|_| {
                        RepositoryError::InvalidData("member list limit exceeds i64")
                    })?)
                    .fetch_all(pool)
                    .await?;
                if rows.is_empty() && !self.is_guild_member(user_id, guild_id).await? {
                    return Err(RepositoryError::NotFound("server"));
                }
                rows.iter()
                    .map(|row| {
                        let role_ids = row
                            .try_get::<Vec<i64>, _>("role_ids")?
                            .into_iter()
                            .map(role_id_from_db)
                            .collect::<Result<Vec<_>, _>>()?;
                        Ok(GuildMember {
                            user: user_from_row(row)?,
                            joined_at: row.try_get("joined_at")?,
                            roles: role_ids,
                            timeout_until: row.try_get("timeout_until")?,
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn list_automod_rules(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
    ) -> Result<Vec<AutomodRule>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                require_automod_manager(memory_actor_context(&store, actor_id, guild_id)?)?;
                let mut rules = store
                    .automod_rules
                    .values()
                    .filter(|rule| rule.guild_id == guild_id)
                    .cloned()
                    .collect::<Vec<_>>();
                rules.sort_by_key(|rule| rule.id);
                Ok(rules)
            }
            RepositoryBackend::Postgres(pool) => {
                require_automod_manager(postgres_actor_context(pool, actor_id, guild_id).await?)?;
                let rows = sqlx::query(
                    "SELECT id, guild_id, name, enabled, trigger, action,
                            duration_seconds, explanation, created_at, updated_at
                     FROM automod_rules
                     WHERE guild_id = $1
                     ORDER BY id",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter().map(automod_rule_from_row).collect()
            }
        }
    }

    pub async fn active_automod_rules(
        &self,
        guild_id: GuildId,
    ) -> Result<Vec<AutomodRule>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                if !store.guilds.contains_key(&guild_id) {
                    return Err(RepositoryError::NotFound("server"));
                }
                let mut rules = store
                    .automod_rules
                    .values()
                    .filter(|rule| rule.guild_id == guild_id && rule.enabled)
                    .cloned()
                    .collect::<Vec<_>>();
                rules.sort_by_key(|rule| rule.id);
                Ok(rules)
            }
            RepositoryBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT id, guild_id, name, enabled, trigger, action,
                            duration_seconds, explanation, created_at, updated_at
                     FROM automod_rules
                     WHERE guild_id = $1 AND enabled
                     ORDER BY id",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter().map(automod_rule_from_row).collect()
            }
        }
    }

    pub async fn create_automod_rule(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        input: CreateAutomodRule,
    ) -> Result<AutomodRule, RepositoryError> {
        let now = Utc::now();
        let rule = AutomodRule {
            id: AutomodRuleId::new(),
            guild_id,
            name: input.name.trim().to_owned(),
            enabled: input.enabled,
            trigger: input.trigger,
            action: input.action,
            duration_seconds: input.duration_seconds,
            explanation: input.explanation.trim().to_owned(),
            created_at: now,
            updated_at: now,
        };
        validate_rule(&rule).map_err(|error| RepositoryError::Validation(error.to_string()))?;
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                require_automod_manager(memory_actor_context(&store, actor_id, guild_id)?)?;
                store.automod_rules.insert(rule.id, rule.clone());
                push_memory_audit_entry(
                    &mut store,
                    guild_id,
                    Some(actor_id),
                    Some(rule.id.raw()),
                    50,
                    serde_json::json!({
                        "name": rule.name,
                        "enabled": rule.enabled,
                        "trigger": rule.trigger,
                        "action": rule.action
                    }),
                    None,
                );
                Ok(rule)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                require_automod_manager(
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?,
                )?;
                sqlx::query(
                    "INSERT INTO automod_rules
                       (id, guild_id, name, enabled, trigger, action, duration_seconds,
                        explanation, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                )
                .bind(db_id(rule.id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .bind(&rule.name)
                .bind(rule.enabled)
                .bind(serde_json::to_value(&rule.trigger).map_err(|_| {
                    RepositoryError::InvalidData("automod trigger could not be encoded")
                })?)
                .bind(automod_action_to_db(rule.action))
                .bind(
                    rule.duration_seconds
                        .map(i32::try_from)
                        .transpose()
                        .map_err(|_| {
                            RepositoryError::InvalidData("automod duration exceeds i32")
                        })?,
                )
                .bind(&rule.explanation)
                .bind(rule.created_at)
                .bind(rule.updated_at)
                .execute(&mut *transaction)
                .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    rule.id.raw(),
                    50,
                    serde_json::json!({
                        "name": rule.name,
                        "enabled": rule.enabled,
                        "trigger": rule.trigger,
                        "action": rule.action
                    }),
                )
                .await?;
                transaction.commit().await?;
                Ok(rule)
            }
        }
    }

    pub async fn update_automod_rule(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        rule_id: AutomodRuleId,
        input: UpdateAutomodRule,
    ) -> Result<AutomodRule, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                require_automod_manager(memory_actor_context(&store, actor_id, guild_id)?)?;
                let current = store
                    .automod_rules
                    .get(&rule_id)
                    .filter(|rule| rule.guild_id == guild_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("automod rule"))?;
                let updated = apply_automod_update(current.clone(), input)?;
                store.automod_rules.insert(rule_id, updated.clone());
                push_memory_audit_entry(
                    &mut store,
                    guild_id,
                    Some(actor_id),
                    Some(rule_id.raw()),
                    51,
                    serde_json::json!({ "before": current, "after": updated }),
                    None,
                );
                Ok(updated)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                require_automod_manager(
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?,
                )?;
                let row = sqlx::query(
                    "SELECT id, guild_id, name, enabled, trigger, action,
                            duration_seconds, explanation, created_at, updated_at
                     FROM automod_rules
                     WHERE id = $1 AND guild_id = $2
                     FOR UPDATE",
                )
                .bind(db_id(rule_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("automod rule"))?;
                let current = automod_rule_from_row(&row)?;
                let updated = apply_automod_update(current.clone(), input)?;
                sqlx::query(
                    "UPDATE automod_rules
                     SET name = $1, enabled = $2, trigger = $3, action = $4,
                         duration_seconds = $5, explanation = $6, updated_at = $7
                     WHERE id = $8 AND guild_id = $9",
                )
                .bind(&updated.name)
                .bind(updated.enabled)
                .bind(serde_json::to_value(&updated.trigger).map_err(|_| {
                    RepositoryError::InvalidData("automod trigger could not be encoded")
                })?)
                .bind(automod_action_to_db(updated.action))
                .bind(
                    updated
                        .duration_seconds
                        .map(i32::try_from)
                        .transpose()
                        .map_err(|_| {
                            RepositoryError::InvalidData("automod duration exceeds i32")
                        })?,
                )
                .bind(&updated.explanation)
                .bind(updated.updated_at)
                .bind(db_id(rule_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    rule_id.raw(),
                    51,
                    serde_json::json!({ "before": current, "after": updated }),
                )
                .await?;
                transaction.commit().await?;
                Ok(updated)
            }
        }
    }

    pub async fn delete_automod_rule(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        rule_id: AutomodRuleId,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                require_automod_manager(memory_actor_context(&store, actor_id, guild_id)?)?;
                let rule = store
                    .automod_rules
                    .get(&rule_id)
                    .filter(|rule| rule.guild_id == guild_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("automod rule"))?;
                store.automod_rules.remove(&rule_id);
                push_memory_audit_entry(
                    &mut store,
                    guild_id,
                    Some(actor_id),
                    Some(rule_id.raw()),
                    52,
                    serde_json::json!({ "name": rule.name }),
                    None,
                );
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                require_automod_manager(
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?,
                )?;
                let row = sqlx::query(
                    "DELETE FROM automod_rules
                     WHERE id = $1 AND guild_id = $2
                     RETURNING name",
                )
                .bind(db_id(rule_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("automod rule"))?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    rule_id.raw(),
                    52,
                    serde_json::json!({ "name": row.try_get::<String, _>("name")? }),
                )
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn list_audit_log(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        before: Option<AuditLogId>,
        limit: usize,
    ) -> Result<Vec<AuditLogEntry>, RepositoryError> {
        let limit = limit.clamp(1, 100);
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                require_audit_viewer(memory_actor_context(&store, actor_id, guild_id)?)?;
                Ok(store
                    .audit_entries
                    .iter()
                    .rev()
                    .filter(|entry| entry.guild_id == guild_id)
                    .filter(|entry| before.is_none_or(|cursor| entry.id < cursor))
                    .take(limit)
                    .cloned()
                    .collect())
            }
            RepositoryBackend::Postgres(pool) => {
                require_audit_viewer(postgres_actor_context(pool, actor_id, guild_id).await?)?;
                let rows = sqlx::query(
                    "SELECT id, guild_id, actor_id, target_id, action_type, changes,
                            reason, mfa_verified, created_at
                     FROM audit_log
                     WHERE guild_id = $1
                       AND ($2::bigint IS NULL OR id < $2)
                     ORDER BY id DESC
                     LIMIT $3",
                )
                .bind(db_id(guild_id.raw())?)
                .bind(before.map(|value| db_id(value.raw())).transpose()?)
                .bind(
                    i64::try_from(limit)
                        .map_err(|_| RepositoryError::InvalidData("audit log limit exceeds i64"))?,
                )
                .fetch_all(pool)
                .await?;
                rows.iter().map(audit_log_entry_from_row).collect()
            }
        }
    }

    pub async fn list_roles(
        &self,
        user_id: UserId,
        guild_id: GuildId,
    ) -> Result<Vec<Role>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                if !store.memberships.contains(&(guild_id, user_id)) {
                    return Err(RepositoryError::NotFound("server"));
                }
                let mut roles = store
                    .roles
                    .values()
                    .filter(|role| role.guild_id == guild_id)
                    .cloned()
                    .collect::<Vec<_>>();
                roles.sort_by_key(|role| (std::cmp::Reverse(role.position), role.id));
                Ok(roles)
            }
            RepositoryBackend::Postgres(pool) => {
                if !self.is_guild_member(user_id, guild_id).await? {
                    return Err(RepositoryError::NotFound("server"));
                }
                let rows = sqlx::query(
                    "SELECT r.id, r.guild_id, r.name, r.color, r.position,
                            r.permissions, r.managed
                     FROM roles r
                     JOIN guilds g ON g.id = r.guild_id
                     WHERE r.guild_id = $1 AND g.deleted_at IS NULL
                     ORDER BY r.position DESC, r.id",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter()
                    .map(role_from_row)
                    .collect::<Result<Vec<_>, _>>()
            }
        }
    }

    pub async fn create_role(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        name: String,
        color: u32,
        permissions: GuildPermissions,
    ) -> Result<Role, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                require_manageable_permissions(actor, permissions)?;
                let position = if actor.is_owner {
                    store
                        .roles
                        .values()
                        .filter(|role| role.guild_id == guild_id)
                        .map(|role| role.position)
                        .max()
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or(RepositoryError::InvalidData("role position overflow"))?
                } else {
                    let position = delegated_role_position(actor.highest_position)?;
                    let collides = store
                        .roles
                        .values()
                        .any(|role| role.guild_id == guild_id && role.position == position);
                    if collides {
                        let highest_to_shift = store
                            .roles
                            .values()
                            .filter(|role| role.guild_id == guild_id && role.position >= position)
                            .map(|role| role.position)
                            .max()
                            .ok_or(RepositoryError::InvalidData(
                                "role position collision disappeared",
                            ))?;
                        highest_to_shift
                            .checked_add(1)
                            .ok_or(RepositoryError::InvalidData("role position overflow"))?;
                        for role in store
                            .roles
                            .values_mut()
                            .filter(|role| role.guild_id == guild_id && role.position >= position)
                        {
                            role.position = role
                                .position
                                .checked_add(1)
                                .ok_or(RepositoryError::InvalidData("role position overflow"))?;
                        }
                    }
                    position
                };
                if position <= 0 {
                    return Err(RepositoryError::BadRequest(
                        "no manageable role position is available",
                    ));
                }
                let role = Role {
                    id: RoleId::new(),
                    guild_id,
                    name,
                    color,
                    position,
                    permissions,
                    managed: false,
                };
                store.roles.insert(role.id, role.clone());
                Ok(role)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                require_manageable_permissions(actor, permissions)?;
                let position = if actor.is_owner {
                    let highest = sqlx::query_scalar::<_, i32>(
                        "SELECT COALESCE(MAX(position), 0)
                         FROM roles WHERE guild_id = $1",
                    )
                    .bind(db_id(guild_id.raw())?)
                    .fetch_one(&mut *transaction)
                    .await?;
                    highest
                        .checked_add(1)
                        .ok_or(RepositoryError::InvalidData("role position overflow"))?
                } else {
                    let position = delegated_role_position(actor.highest_position)?;
                    let collides = sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(
                           SELECT 1 FROM roles
                           WHERE guild_id = $1 AND position = $2
                         )",
                    )
                    .bind(db_id(guild_id.raw())?)
                    .bind(position)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if collides {
                        let highest_to_shift = sqlx::query_scalar::<_, Option<i32>>(
                            "SELECT MAX(position)
                             FROM roles
                             WHERE guild_id = $1 AND position >= $2",
                        )
                        .bind(db_id(guild_id.raw())?)
                        .bind(position)
                        .fetch_one(&mut *transaction)
                        .await?;
                        if highest_to_shift.is_some_and(|value| value == i32::MAX) {
                            return Err(RepositoryError::InvalidData("role position overflow"));
                        }
                        sqlx::query(
                            "UPDATE roles
                             SET position = position + 1
                             WHERE guild_id = $1 AND position >= $2",
                        )
                        .bind(db_id(guild_id.raw())?)
                        .bind(position)
                        .execute(&mut *transaction)
                        .await?;
                    }
                    position
                };
                if position <= 0 {
                    return Err(RepositoryError::BadRequest(
                        "no manageable role position is available",
                    ));
                }
                let role = Role {
                    id: RoleId::new(),
                    guild_id,
                    name,
                    color,
                    position,
                    permissions,
                    managed: false,
                };
                sqlx::query(
                    "INSERT INTO roles
                       (id, guild_id, name, color, position, permissions, managed)
                     VALUES ($1, $2, $3, $4, $5, $6, false)",
                )
                .bind(db_id(role.id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .bind(&role.name)
                .bind(i32::try_from(color).map_err(|_| {
                    RepositoryError::BadRequest("role color must be a 24-bit RGB value")
                })?)
                .bind(position)
                .bind(permission_bits(permissions)?)
                .execute(&mut *transaction)
                .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    role.id.raw(),
                    20,
                    serde_json::json!({
                        "name": role.name,
                        "color": role.color,
                        "permissions": role.permissions.bits().to_string()
                    }),
                )
                .await?;
                transaction.commit().await?;
                Ok(role)
            }
        }
    }

    pub async fn update_role(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        role_id: RoleId,
        name: String,
        color: u32,
        permissions: GuildPermissions,
    ) -> Result<Role, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                require_manageable_permissions(actor, permissions)?;
                let role = store
                    .roles
                    .get(&role_id)
                    .filter(|role| role.guild_id == guild_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("role"))?;
                require_manageable_role(actor, &role)?;
                let role = store
                    .roles
                    .get_mut(&role_id)
                    .ok_or(RepositoryError::NotFound("role"))?;
                role.name = if role.id.raw() == guild_id.raw() {
                    "@everyone".into()
                } else {
                    name
                };
                role.color = color;
                role.permissions = permissions;
                Ok(role.clone())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                require_manageable_permissions(actor, permissions)?;
                let row = sqlx::query(
                    "SELECT id, guild_id, name, color, position, permissions, managed
                     FROM roles
                     WHERE id = $1 AND guild_id = $2
                     FOR UPDATE",
                )
                .bind(db_id(role_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("role"))?;
                let current = role_from_row(&row)?;
                require_manageable_role(actor, &current)?;
                let effective_name = if role_id.raw() == guild_id.raw() {
                    "@everyone"
                } else {
                    &name
                };
                sqlx::query(
                    "UPDATE roles
                     SET name = $1, color = $2, permissions = $3
                     WHERE id = $4 AND guild_id = $5",
                )
                .bind(effective_name)
                .bind(i32::try_from(color).map_err(|_| {
                    RepositoryError::BadRequest("role color must be a 24-bit RGB value")
                })?)
                .bind(permission_bits(permissions)?)
                .bind(db_id(role_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    role_id.raw(),
                    21,
                    serde_json::json!({
                        "before": {
                            "name": current.name,
                            "color": current.color,
                            "permissions": current.permissions.bits().to_string()
                        },
                        "after": {
                            "name": effective_name,
                            "color": color,
                            "permissions": permissions.bits().to_string()
                        }
                    }),
                )
                .await?;
                transaction.commit().await?;
                Ok(Role {
                    name: effective_name.to_owned(),
                    color,
                    permissions,
                    ..current
                })
            }
        }
    }

    pub async fn delete_role(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        role_id: RoleId,
    ) -> Result<(), RepositoryError> {
        if role_id.raw() == guild_id.raw() {
            return Err(RepositoryError::BadRequest(
                "the @everyone role cannot be deleted",
            ));
        }
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                let role = store
                    .roles
                    .get(&role_id)
                    .filter(|role| role.guild_id == guild_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("role"))?;
                require_manageable_role(actor, &role)?;
                store.roles.remove(&role_id);
                store
                    .member_roles
                    .retain(|(_, _, assigned_role)| *assigned_role != role_id);
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                let row = sqlx::query(
                    "SELECT id, guild_id, name, color, position, permissions, managed
                     FROM roles
                     WHERE id = $1 AND guild_id = $2
                     FOR UPDATE",
                )
                .bind(db_id(role_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("role"))?;
                let role = role_from_row(&row)?;
                require_manageable_role(actor, &role)?;
                sqlx::query("DELETE FROM roles WHERE id = $1 AND guild_id = $2")
                    .bind(db_id(role_id.raw())?)
                    .bind(db_id(guild_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    role_id.raw(),
                    22,
                    serde_json::json!({
                        "name": role.name,
                        "color": role.color,
                        "permissions": role.permissions.bits().to_string()
                    }),
                )
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn set_member_role(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        member_id: UserId,
        role_id: RoleId,
        assigned: bool,
    ) -> Result<(), RepositoryError> {
        if role_id.raw() == guild_id.raw() {
            return Err(RepositoryError::BadRequest(
                "the @everyone role is implicit",
            ));
        }
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                let guild = store
                    .guilds
                    .get(&guild_id)
                    .ok_or(RepositoryError::NotFound("server"))?;
                if !store.memberships.contains(&(guild_id, member_id)) {
                    return Err(RepositoryError::NotFound("member"));
                }
                if !actor.is_owner
                    && (member_id == actor_id
                        || member_id == guild.owner_id
                        || memory_highest_role_position(&store, guild_id, member_id)
                            >= actor.highest_position)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let role = store
                    .roles
                    .get(&role_id)
                    .filter(|role| role.guild_id == guild_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("role"))?;
                require_manageable_role(actor, &role)?;
                if assigned {
                    store.member_roles.insert((guild_id, member_id, role_id));
                } else {
                    store.member_roles.remove(&(guild_id, member_id, role_id));
                }
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                let role_row = sqlx::query(
                    "SELECT id, guild_id, name, color, position, permissions, managed
                     FROM roles
                     WHERE id = $1 AND guild_id = $2
                     FOR UPDATE",
                )
                .bind(db_id(role_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("role"))?;
                require_manageable_role(actor, &role_from_row(&role_row)?)?;
                let target = sqlx::query(
                    "SELECT g.owner_id,
                            COALESCE(MAX(r.position), 0)::integer AS highest_position
                     FROM guild_members gm
                     JOIN guilds g ON g.id = gm.guild_id
                     LEFT JOIN member_roles mr
                       ON mr.guild_id = gm.guild_id AND mr.user_id = gm.user_id
                     LEFT JOIN roles r ON r.id = mr.role_id
                     WHERE gm.guild_id = $1 AND gm.user_id = $2
                       AND g.deleted_at IS NULL
                     GROUP BY g.owner_id",
                )
                .bind(db_id(guild_id.raw())?)
                .bind(db_id(member_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("member"))?;
                let owner_id = user_id_from_db(target.try_get("owner_id")?)?;
                let target_highest: i32 = target.try_get("highest_position")?;
                if !actor.is_owner
                    && (member_id == actor_id
                        || member_id == owner_id
                        || target_highest >= actor.highest_position)
                {
                    return Err(RepositoryError::Forbidden);
                }
                if assigned {
                    let changed = sqlx::query(
                        "INSERT INTO member_roles (guild_id, user_id, role_id)
                         VALUES ($1, $2, $3)
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(db_id(guild_id.raw())?)
                    .bind(db_id(member_id.raw())?)
                    .bind(db_id(role_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    if changed.rows_affected() == 1 {
                        insert_audit_entry(
                            &mut transaction,
                            guild_id,
                            actor_id,
                            member_id.raw(),
                            23,
                            serde_json::json!({ "roleId": role_id.to_string() }),
                        )
                        .await?;
                    }
                } else {
                    let changed = sqlx::query(
                        "DELETE FROM member_roles
                         WHERE guild_id = $1 AND user_id = $2 AND role_id = $3",
                    )
                    .bind(db_id(guild_id.raw())?)
                    .bind(db_id(member_id.raw())?)
                    .bind(db_id(role_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                    if changed.rows_affected() == 1 {
                        insert_audit_entry(
                            &mut transaction,
                            guild_id,
                            actor_id,
                            member_id.raw(),
                            24,
                            serde_json::json!({ "roleId": role_id.to_string() }),
                        )
                        .await?;
                    }
                }
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn timeout_member(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        member_id: UserId,
        timeout_until: Option<chrono::DateTime<Utc>>,
        reason: Option<String>,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                require_moderation_permission(actor, GuildPermissions::MODERATE_MEMBERS)?;
                let target = memory_target_member_context(&store, guild_id, member_id)?
                    .ok_or(RepositoryError::NotFound("member"))?;
                require_moderatable_target(actor, actor_id, member_id, target)?;
                if let Some(timeout) = timeout_until {
                    store.timeouts.insert((guild_id, member_id), timeout);
                } else {
                    store.timeouts.remove(&(guild_id, member_id));
                }
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                require_moderation_permission(actor, GuildPermissions::MODERATE_MEMBERS)?;
                let target = postgres_target_member_context(&mut transaction, guild_id, member_id)
                    .await?
                    .ok_or(RepositoryError::NotFound("member"))?;
                require_moderatable_target(actor, actor_id, member_id, target)?;
                sqlx::query(
                    "UPDATE guild_members SET timeout_until = $1
                     WHERE guild_id = $2 AND user_id = $3",
                )
                .bind(timeout_until)
                .bind(db_id(guild_id.raw())?)
                .bind(db_id(member_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                insert_moderation_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    member_id,
                    40,
                    serde_json::json!({
                        "timeoutUntil": timeout_until.map(|value| value.to_rfc3339())
                    }),
                    reason.as_deref(),
                )
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn kick_member(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        member_id: UserId,
        reason: Option<String>,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                require_moderation_permission(actor, GuildPermissions::KICK_MEMBERS)?;
                let target = memory_target_member_context(&store, guild_id, member_id)?
                    .ok_or(RepositoryError::NotFound("member"))?;
                require_moderatable_target(actor, actor_id, member_id, target)?;
                remove_memory_membership(&mut store, guild_id, member_id);
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                require_moderation_permission(actor, GuildPermissions::KICK_MEMBERS)?;
                let target = postgres_target_member_context(&mut transaction, guild_id, member_id)
                    .await?
                    .ok_or(RepositoryError::NotFound("member"))?;
                require_moderatable_target(actor, actor_id, member_id, target)?;
                let removed =
                    sqlx::query("DELETE FROM guild_members WHERE guild_id = $1 AND user_id = $2")
                        .bind(db_id(guild_id.raw())?)
                        .bind(db_id(member_id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                if removed.rows_affected() == 0 {
                    return Err(RepositoryError::NotFound("member"));
                }
                sqlx::query(
                    "UPDATE guilds
                     SET member_count = GREATEST(member_count - 1, 0)
                     WHERE id = $1",
                )
                .bind(db_id(guild_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                insert_moderation_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    member_id,
                    41,
                    serde_json::json!({}),
                    reason.as_deref(),
                )
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn ban_member(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        member_id: UserId,
        reason: Option<String>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<(), RepositoryError> {
        let created_at = Utc::now();
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                require_moderation_permission(actor, GuildPermissions::BAN_MEMBERS)?;
                if !store.users.contains_key(&member_id) {
                    return Err(RepositoryError::NotFound("user"));
                }
                if let Some(target) = memory_target_member_context(&store, guild_id, member_id)? {
                    require_moderatable_target(actor, actor_id, member_id, target)?;
                    remove_memory_membership(&mut store, guild_id, member_id);
                } else if member_id == actor_id {
                    return Err(RepositoryError::Forbidden);
                }
                store.bans.insert(
                    (guild_id, member_id),
                    MemoryBan {
                        actor_id: Some(actor_id),
                        reason,
                        expires_at,
                        created_at,
                    },
                );
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                require_moderation_permission(actor, GuildPermissions::BAN_MEMBERS)?;
                let user_exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
                        .bind(db_id(member_id.raw())?)
                        .fetch_one(&mut *transaction)
                        .await?;
                if !user_exists {
                    return Err(RepositoryError::NotFound("user"));
                }
                let target =
                    postgres_target_member_context(&mut transaction, guild_id, member_id).await?;
                if let Some(target) = target {
                    require_moderatable_target(actor, actor_id, member_id, target)?;
                } else if member_id == actor_id {
                    return Err(RepositoryError::Forbidden);
                }
                sqlx::query(
                    "INSERT INTO bans
                       (guild_id, user_id, actor_id, reason, expires_at, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (guild_id, user_id) DO UPDATE SET
                       actor_id = EXCLUDED.actor_id,
                       reason = EXCLUDED.reason,
                       expires_at = EXCLUDED.expires_at,
                       created_at = EXCLUDED.created_at",
                )
                .bind(db_id(guild_id.raw())?)
                .bind(db_id(member_id.raw())?)
                .bind(db_id(actor_id.raw())?)
                .bind(reason.as_deref())
                .bind(expires_at)
                .bind(created_at)
                .execute(&mut *transaction)
                .await?;
                let removed =
                    sqlx::query("DELETE FROM guild_members WHERE guild_id = $1 AND user_id = $2")
                        .bind(db_id(guild_id.raw())?)
                        .bind(db_id(member_id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                if removed.rows_affected() == 1 {
                    sqlx::query(
                        "UPDATE guilds
                         SET member_count = GREATEST(member_count - 1, 0)
                         WHERE id = $1",
                    )
                    .bind(db_id(guild_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                }
                insert_moderation_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    member_id,
                    42,
                    serde_json::json!({
                        "expiresAt": expires_at.map(|value| value.to_rfc3339())
                    }),
                    reason.as_deref(),
                )
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn list_bans(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
    ) -> Result<Vec<GuildBan>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                if !actor
                    .permissions
                    .intersects(GuildPermissions::BAN_MEMBERS | GuildPermissions::VIEW_AUDIT_LOG)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let now = Utc::now();
                let mut bans = store
                    .bans
                    .iter()
                    .filter(|((candidate, _), ban)| {
                        *candidate == guild_id && ban.expires_at.is_none_or(|expires| expires > now)
                    })
                    .filter_map(|((_, user_id), ban)| {
                        store.users.get(user_id).cloned().map(|user| GuildBan {
                            user,
                            actor_id: ban.actor_id,
                            reason: ban.reason.clone(),
                            expires_at: ban.expires_at,
                            created_at: ban.created_at,
                        })
                    })
                    .collect::<Vec<_>>();
                bans.sort_by_key(|ban| std::cmp::Reverse(ban.created_at));
                Ok(bans)
            }
            RepositoryBackend::Postgres(pool) => {
                let actor = postgres_actor_context(pool, actor_id, guild_id).await?;
                if !actor
                    .permissions
                    .intersects(GuildPermissions::BAN_MEMBERS | GuildPermissions::VIEW_AUDIT_LOG)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let rows = sqlx::query(
                    "SELECT u.id, u.username, u.display_name, u.avatar_hash, u.created_at,
                            b.actor_id, b.reason, b.expires_at, b.created_at AS ban_created_at
                     FROM bans b
                     JOIN users u ON u.id = b.user_id
                     WHERE b.guild_id = $1
                       AND (b.expires_at IS NULL OR b.expires_at > now())
                     ORDER BY b.created_at DESC, b.user_id",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter()
                    .map(|row| {
                        Ok(GuildBan {
                            user: user_from_row(row)?,
                            actor_id: row
                                .try_get::<Option<i64>, _>("actor_id")?
                                .map(user_id_from_db)
                                .transpose()?,
                            reason: row.try_get("reason")?,
                            expires_at: row.try_get("expires_at")?,
                            created_at: row.try_get("ban_created_at")?,
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn unban_member(
        &self,
        actor_id: UserId,
        guild_id: GuildId,
        member_id: UserId,
        reason: Option<String>,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                require_moderation_permission(actor, GuildPermissions::BAN_MEMBERS)?;
                if store.bans.remove(&(guild_id, member_id)).is_none() {
                    return Err(RepositoryError::NotFound("ban"));
                }
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                require_moderation_permission(actor, GuildPermissions::BAN_MEMBERS)?;
                let deleted = sqlx::query("DELETE FROM bans WHERE guild_id = $1 AND user_id = $2")
                    .bind(db_id(guild_id.raw())?)
                    .bind(db_id(member_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                if deleted.rows_affected() == 0 {
                    return Err(RepositoryError::NotFound("ban"));
                }
                insert_moderation_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    member_id,
                    43,
                    serde_json::json!({}),
                    reason.as_deref(),
                )
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn create_guild(
        &self,
        owner_id: UserId,
        name: String,
        accent: u32,
    ) -> Result<CreatedGuild, RepositoryError> {
        let guild = Guild {
            id: GuildId::new(),
            owner_id,
            name,
            accent,
            created_at: Utc::now(),
        };
        let channels = default_channels(guild.id);
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                if !store.users.contains_key(&owner_id) {
                    return Err(RepositoryError::NotFound("user"));
                }
                store.guilds.insert(guild.id, guild.clone());
                store.memberships.insert((guild.id, owner_id));
                let everyone_id = RoleId::from_raw(guild.id.raw())
                    .map_err(|_| RepositoryError::InvalidData("default role id is invalid"))?;
                store.roles.insert(
                    everyone_id,
                    Role {
                        id: everyone_id,
                        guild_id: guild.id,
                        name: "@everyone".into(),
                        color: 0,
                        position: 0,
                        permissions: GuildPermissions::MEMBER_DEFAULT,
                        managed: false,
                    },
                );
                for channel in &channels {
                    store.channels.insert(channel.id, channel.clone());
                }
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(
                    "INSERT INTO guilds
                       (id, name, owner_id, accent, member_count, created_at)
                     VALUES ($1, $2, $3, $4, 1, $5)",
                )
                .bind(db_id(guild.id.raw())?)
                .bind(&guild.name)
                .bind(db_id(owner_id.raw())?)
                .bind(i32::try_from(accent).map_err(|_| {
                    RepositoryError::InvalidData("server accent exceeds the database range")
                })?)
                .bind(guild.created_at)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "INSERT INTO guild_members (guild_id, user_id, joined_at)
                     VALUES ($1, $2, $3)",
                )
                .bind(db_id(guild.id.raw())?)
                .bind(db_id(owner_id.raw())?)
                .bind(guild.created_at)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "INSERT INTO roles
                       (id, guild_id, name, position, permissions, created_at)
                     VALUES ($1, $1, '@everyone', 0, $2, $3)",
                )
                .bind(db_id(guild.id.raw())?)
                .bind(permission_bits(GuildPermissions::MEMBER_DEFAULT)?)
                .bind(guild.created_at)
                .execute(&mut *transaction)
                .await?;
                for channel in &channels {
                    insert_channel(&mut transaction, channel).await?;
                }
                transaction.commit().await?;
            }
        }
        Ok(CreatedGuild { guild, channels })
    }

    pub async fn list_channels(
        &self,
        user_id: UserId,
        guild_id: GuildId,
    ) -> Result<Vec<Channel>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let permission_inputs = memory_permission_inputs(&store, user_id, guild_id)?;
                let mut channels = Vec::new();
                for channel in store
                    .channels
                    .values()
                    .filter(|channel| channel.guild_id == guild_id)
                {
                    if permission_inputs
                        .resolve(&memory_channel_overrides(&store, channel.id))
                        .contains(GuildPermissions::VIEW_CHANNEL)
                    {
                        channels.push(channel.clone());
                    }
                }
                channels.sort_by_key(|channel| (channel.position, channel.id));
                Ok(channels)
            }
            RepositoryBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT c.id, c.guild_id, c.name, c.type, c.position, c.e2ee, c.created_at
                     FROM channels c
                     JOIN guilds g ON g.id = c.guild_id
                     JOIN guild_members gm ON gm.guild_id = g.id
                                           AND gm.user_id = $2
                     WHERE c.guild_id = $1 AND c.deleted_at IS NULL
                       AND g.deleted_at IS NULL
                     ORDER BY c.position, c.id",
                )
                .bind(db_id(guild_id.raw())?)
                .bind(db_id(user_id.raw())?)
                .fetch_all(pool)
                .await?;
                let channels = rows
                    .iter()
                    .map(channel_from_row)
                    .collect::<Result<Vec<_>, _>>()?;
                let permissions = postgres_channel_permission_map(
                    pool,
                    user_id,
                    guild_id,
                    channels.iter().map(|channel| channel.id),
                )
                .await?;
                Ok(channels
                    .into_iter()
                    .filter(|channel| {
                        permissions.get(&channel.id).is_some_and(|permissions| {
                            permissions.contains(GuildPermissions::VIEW_CHANNEL)
                        })
                    })
                    .collect())
            }
        }
    }

    pub async fn create_channel(
        &self,
        user_id: UserId,
        guild_id: GuildId,
        name: String,
        kind: ChannelKind,
        encrypted: bool,
    ) -> Result<Channel, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let access = memory_actor_context(&store, user_id, guild_id)?;
                if !access
                    .permissions
                    .contains(GuildPermissions::MANAGE_CHANNELS)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let position = i32::try_from(
                    store
                        .channels
                        .values()
                        .filter(|channel| channel.guild_id == guild_id)
                        .count(),
                )
                .map_err(|_| RepositoryError::InvalidData("too many channels"))?;
                let channel = Channel {
                    id: ChannelId::new(),
                    guild_id,
                    name,
                    kind,
                    position,
                    encrypted,
                    created_at: Utc::now(),
                };
                store.channels.insert(channel.id, channel.clone());
                Ok(channel)
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let access =
                    postgres_actor_context_for_update(&mut transaction, user_id, guild_id).await?;
                if !access
                    .permissions
                    .contains(GuildPermissions::MANAGE_CHANNELS)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let position: i32 = sqlx::query_scalar(
                    "SELECT COUNT(*)::integer FROM channels
                     WHERE guild_id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_one(&mut *transaction)
                .await?;
                let channel = Channel {
                    id: ChannelId::new(),
                    guild_id,
                    name,
                    kind,
                    position,
                    encrypted,
                    created_at: Utc::now(),
                };
                insert_channel(&mut transaction, &channel).await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    user_id,
                    channel.id.raw(),
                    10,
                    serde_json::json!({
                        "name": channel.name,
                        "kind": channel.kind,
                        "encrypted": channel.encrypted
                    }),
                )
                .await?;
                transaction.commit().await?;
                Ok(channel)
            }
        }
    }

    pub async fn update_channel(
        &self,
        actor_id: UserId,
        channel_id: ChannelId,
        name: String,
    ) -> Result<Channel, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let current = store
                    .channels
                    .get(&channel_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("channel"))?;
                let actor = memory_actor_context(&store, actor_id, current.guild_id)
                    .map_err(hide_server_as_channel)?;
                if !actor
                    .permissions
                    .contains(GuildPermissions::MANAGE_CHANNELS)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let channel = store
                    .channels
                    .get_mut(&channel_id)
                    .ok_or(RepositoryError::NotFound("channel"))?;
                channel.name = name;
                Ok(channel.clone())
            }
            RepositoryBackend::Postgres(pool) => {
                let guild_id = postgres_channel_guild(pool, channel_id).await?;
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                if !actor
                    .permissions
                    .contains(GuildPermissions::MANAGE_CHANNELS)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let row = sqlx::query(
                    "SELECT c.id, c.guild_id, c.name, c.type, c.position, c.e2ee, c.created_at
                     FROM channels c
                     JOIN guilds g ON g.id = c.guild_id
                     WHERE c.id = $1 AND c.guild_id = $2
                       AND c.deleted_at IS NULL AND g.deleted_at IS NULL
                     FOR UPDATE OF c",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                let mut channel = channel_from_row(&row)?;
                let previous_name = channel.name.clone();
                sqlx::query("UPDATE channels SET name = $1 WHERE id = $2")
                    .bind(&name)
                    .bind(db_id(channel_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    channel_id.raw(),
                    11,
                    serde_json::json!({
                        "before": { "name": previous_name },
                        "after": { "name": name }
                    }),
                )
                .await?;
                transaction.commit().await?;
                channel.name = name;
                Ok(channel)
            }
        }
    }

    pub async fn delete_channel(
        &self,
        actor_id: UserId,
        channel_id: ChannelId,
    ) -> Result<Channel, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let channel = store
                    .channels
                    .get(&channel_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("channel"))?;
                let actor = memory_actor_context(&store, actor_id, channel.guild_id)
                    .map_err(hide_server_as_channel)?;
                if !actor
                    .permissions
                    .contains(GuildPermissions::MANAGE_CHANNELS)
                {
                    return Err(RepositoryError::Forbidden);
                }
                if channel.kind == ChannelKind::Text
                    && store
                        .channels
                        .values()
                        .filter(|candidate| {
                            candidate.guild_id == channel.guild_id
                                && candidate.kind == ChannelKind::Text
                        })
                        .count()
                        <= 1
                {
                    return Err(RepositoryError::BadRequest(
                        "a server must keep at least one text channel",
                    ));
                }
                store.channels.remove(&channel_id);
                store.messages.remove(&channel_id);
                store
                    .message_nonces
                    .retain(|(candidate, _, _), _| *candidate != channel_id);
                store
                    .channel_overwrites
                    .retain(|(candidate, _, _), _| *candidate != channel_id);
                Ok(channel)
            }
            RepositoryBackend::Postgres(pool) => {
                let guild_id = postgres_channel_guild(pool, channel_id).await?;
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                if !actor
                    .permissions
                    .contains(GuildPermissions::MANAGE_CHANNELS)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let row = sqlx::query(
                    "SELECT c.id, c.guild_id, c.name, c.type, c.position, c.e2ee, c.created_at
                     FROM channels c
                     WHERE c.id = $1 AND c.guild_id = $2 AND c.deleted_at IS NULL
                     FOR UPDATE",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                let channel = channel_from_row(&row)?;
                if channel.kind == ChannelKind::Text {
                    let text_count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM channels
                         WHERE guild_id = $1 AND type = $2 AND deleted_at IS NULL",
                    )
                    .bind(db_id(guild_id.raw())?)
                    .bind(channel_kind_to_db(ChannelKind::Text))
                    .fetch_one(&mut *transaction)
                    .await?;
                    if text_count <= 1 {
                        return Err(RepositoryError::BadRequest(
                            "a server must keep at least one text channel",
                        ));
                    }
                }
                sqlx::query("UPDATE channels SET deleted_at = now() WHERE id = $1")
                    .bind(db_id(channel_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query("DELETE FROM channel_overwrites WHERE channel_id = $1")
                    .bind(db_id(channel_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    channel_id.raw(),
                    12,
                    serde_json::json!({
                        "name": channel.name,
                        "kind": channel.kind
                    }),
                )
                .await?;
                transaction.commit().await?;
                Ok(channel)
            }
        }
    }

    pub async fn list_channel_overwrites(
        &self,
        actor_id: UserId,
        channel_id: ChannelId,
    ) -> Result<Vec<ChannelPermissionOverwrite>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let channel = store
                    .channels
                    .get(&channel_id)
                    .ok_or(RepositoryError::NotFound("channel"))?;
                require_channel_manager(memory_actor_context(&store, actor_id, channel.guild_id)?)?;
                let mut overwrites = store
                    .channel_overwrites
                    .iter()
                    .filter(|((candidate, _, _), _)| *candidate == channel_id)
                    .map(|(_, overwrite)| ChannelPermissionOverwrite {
                        channel_id,
                        target_kind: overwrite.target_kind,
                        target_id: overwrite.target_id.to_string(),
                        allow: overwrite.allow,
                        deny: overwrite.deny,
                    })
                    .collect::<Vec<_>>();
                overwrites.sort_by_key(|overwrite| {
                    (
                        overwrite_target_kind_to_db(overwrite.target_kind),
                        overwrite.target_id.parse::<u64>().unwrap_or_default(),
                    )
                });
                Ok(overwrites)
            }
            RepositoryBackend::Postgres(pool) => {
                let guild_id = postgres_channel_guild(pool, channel_id).await?;
                require_channel_manager(postgres_actor_context(pool, actor_id, guild_id).await?)?;
                let rows = sqlx::query(
                    "SELECT channel_id, target_id, target_type, allow_bits, deny_bits
                     FROM channel_overwrites
                     WHERE channel_id = $1
                     ORDER BY target_type, target_id",
                )
                .bind(db_id(channel_id.raw())?)
                .fetch_all(pool)
                .await?;
                rows.iter().map(channel_overwrite_from_row).collect()
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn set_channel_overwrite(
        &self,
        actor_id: UserId,
        channel_id: ChannelId,
        target_kind: OverwriteTargetKind,
        target_id: u64,
        allow: GuildPermissions,
        deny: GuildPermissions,
    ) -> Result<ChannelPermissionOverwrite, RepositoryError> {
        if allow.intersects(deny) {
            return Err(RepositoryError::BadRequest(
                "an overwrite cannot allow and deny the same permission",
            ));
        }
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let guild_id = store
                    .channels
                    .get(&channel_id)
                    .map(|channel| channel.guild_id)
                    .ok_or(RepositoryError::NotFound("channel"))?;
                let actor = memory_actor_context(&store, actor_id, guild_id)?;
                require_channel_manager(actor)?;
                require_overwrite_grant(actor, allow)?;
                validate_memory_overwrite_target(&store, guild_id, target_kind, target_id)?;
                let overwrite = MemoryOverwrite {
                    target_kind,
                    target_id,
                    allow,
                    deny,
                };
                store
                    .channel_overwrites
                    .insert((channel_id, target_kind, target_id), overwrite);
                Ok(ChannelPermissionOverwrite {
                    channel_id,
                    target_kind,
                    target_id: target_id.to_string(),
                    allow,
                    deny,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let guild_id = postgres_channel_guild(pool, channel_id).await?;
                let mut transaction = pool.begin().await?;
                let actor =
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?;
                require_channel_manager(actor)?;
                require_overwrite_grant(actor, allow)?;
                sqlx::query(
                    "SELECT id FROM channels
                     WHERE id = $1 AND guild_id = $2 AND deleted_at IS NULL
                     FOR UPDATE",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                validate_postgres_overwrite_target(
                    &mut transaction,
                    guild_id,
                    target_kind,
                    target_id,
                )
                .await?;
                sqlx::query(
                    "INSERT INTO channel_overwrites
                       (channel_id, target_id, target_type, allow_bits, deny_bits)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (channel_id, target_id, target_type)
                     DO UPDATE SET allow_bits = EXCLUDED.allow_bits,
                                   deny_bits = EXCLUDED.deny_bits",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(target_id)?)
                .bind(overwrite_target_kind_to_db(target_kind))
                .bind(permission_bits(allow)?)
                .bind(permission_bits(deny)?)
                .execute(&mut *transaction)
                .await?;
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    target_id,
                    30,
                    serde_json::json!({
                        "channelId": channel_id.to_string(),
                        "targetKind": target_kind,
                        "allow": allow.bits().to_string(),
                        "deny": deny.bits().to_string()
                    }),
                )
                .await?;
                transaction.commit().await?;
                Ok(ChannelPermissionOverwrite {
                    channel_id,
                    target_kind,
                    target_id: target_id.to_string(),
                    allow,
                    deny,
                })
            }
        }
    }

    pub async fn delete_channel_overwrite(
        &self,
        actor_id: UserId,
        channel_id: ChannelId,
        target_kind: OverwriteTargetKind,
        target_id: u64,
    ) -> Result<(), RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let guild_id = store
                    .channels
                    .get(&channel_id)
                    .map(|channel| channel.guild_id)
                    .ok_or(RepositoryError::NotFound("channel"))?;
                require_channel_manager(memory_actor_context(&store, actor_id, guild_id)?)?;
                if store
                    .channel_overwrites
                    .remove(&(channel_id, target_kind, target_id))
                    .is_none()
                {
                    return Err(RepositoryError::NotFound("channel overwrite"));
                }
                Ok(())
            }
            RepositoryBackend::Postgres(pool) => {
                let guild_id = postgres_channel_guild(pool, channel_id).await?;
                let mut transaction = pool.begin().await?;
                require_channel_manager(
                    postgres_actor_context_for_update(&mut transaction, actor_id, guild_id).await?,
                )?;
                let deleted = sqlx::query(
                    "DELETE FROM channel_overwrites
                     WHERE channel_id = $1 AND target_id = $2 AND target_type = $3",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(target_id)?)
                .bind(overwrite_target_kind_to_db(target_kind))
                .execute(&mut *transaction)
                .await?;
                if deleted.rows_affected() == 0 {
                    return Err(RepositoryError::NotFound("channel overwrite"));
                }
                insert_audit_entry(
                    &mut transaction,
                    guild_id,
                    actor_id,
                    target_id,
                    31,
                    serde_json::json!({
                        "channelId": channel_id.to_string(),
                        "targetKind": target_kind
                    }),
                )
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub async fn reserve_attachment(
        &self,
        attachment: NewAttachment,
    ) -> Result<AttachmentRecord, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                memory_message_audience(&store, attachment.owner_id, attachment.channel_id, true)?;
                if store.attachments.contains_key(&attachment.id) {
                    return Err(RepositoryError::Conflict);
                }
                let record = AttachmentRecord {
                    id: attachment.id,
                    channel_id: attachment.channel_id,
                    owner_id: attachment.owner_id,
                    filename: attachment.filename,
                    declared_content_type: attachment.declared_content_type,
                    verified_content_type: None,
                    file_size: attachment.file_size,
                    claimed_sha256: attachment.claimed_sha256,
                    verified_sha256: None,
                    object_key: attachment.object_key,
                    public_url: attachment.public_url,
                    width: None,
                    height: None,
                    animated: false,
                    ready: false,
                    message_id: None,
                    expires_at: attachment.expires_at,
                };
                store.attachments.insert(record.id, record.clone());
                Ok(record)
            }
            RepositoryBackend::Postgres(pool) => {
                require_message_access(pool, attachment.owner_id, attachment.channel_id, true)
                    .await?;
                let mut transaction = pool.begin().await?;
                lock_attachment_object(&mut transaction, &attachment.object_key).await?;
                sqlx::query(
                    "INSERT INTO attachment_uploads
                       (id, channel_id, owner_id, filename, declared_content_type,
                        file_size, claimed_sha256, object_key, public_url, expires_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                )
                .bind(db_id(attachment.id.raw())?)
                .bind(db_id(attachment.channel_id.raw())?)
                .bind(db_id(attachment.owner_id.raw())?)
                .bind(&attachment.filename)
                .bind(&attachment.declared_content_type)
                .bind(
                    i64::try_from(attachment.file_size)
                        .map_err(|_| RepositoryError::InvalidData("attachment is too large"))?,
                )
                .bind(attachment.claimed_sha256.to_vec())
                .bind(&attachment.object_key)
                .bind(&attachment.public_url)
                .bind(attachment.expires_at)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                Ok(AttachmentRecord {
                    id: attachment.id,
                    channel_id: attachment.channel_id,
                    owner_id: attachment.owner_id,
                    filename: attachment.filename,
                    declared_content_type: attachment.declared_content_type,
                    verified_content_type: None,
                    file_size: attachment.file_size,
                    claimed_sha256: attachment.claimed_sha256,
                    verified_sha256: None,
                    object_key: attachment.object_key,
                    public_url: attachment.public_url,
                    width: None,
                    height: None,
                    animated: false,
                    ready: false,
                    message_id: None,
                    expires_at: attachment.expires_at,
                })
            }
        }
    }

    pub async fn cleanup_expired_attachments(
        &self,
        attachments: &AttachmentService,
        now: chrono::DateTime<Utc>,
        limit: usize,
    ) -> Result<AttachmentCleanup, RepositoryError> {
        let limit = limit.clamp(1, 500);
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let object_keys = store
                    .attachments
                    .values()
                    .filter(|record| record.message_id.is_none() && record.expires_at < now)
                    .map(|record| record.object_key.clone())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .take(limit)
                    .collect::<Vec<_>>();
                let mut cleanup = AttachmentCleanup::default();
                for object_key in object_keys {
                    let has_live_reference = store.attachments.values().any(|record| {
                        record.object_key == object_key
                            && (record.message_id.is_some() || record.expires_at >= now)
                    });
                    if !has_live_reference
                        && attachments
                            .delete_object(&object_key)
                            .await
                            .map_err(|error| {
                                RepositoryError::AttachmentStorage(error.to_string())
                            })?
                    {
                        cleanup.objects += 1;
                    }
                    let before = store.attachments.len();
                    store.attachments.retain(|_, record| {
                        record.object_key != object_key
                            || record.message_id.is_some()
                            || record.expires_at >= now
                    });
                    cleanup.reservations +=
                        u64::try_from(before - store.attachments.len()).unwrap_or(u64::MAX);
                }
                Ok(cleanup)
            }
            RepositoryBackend::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT DISTINCT object_key
                     FROM attachment_uploads
                     WHERE message_id IS NULL AND expires_at < $1
                     ORDER BY object_key
                     LIMIT $2",
                )
                .bind(now)
                .bind(i64::try_from(limit).unwrap_or(500))
                .fetch_all(pool)
                .await?;
                let mut cleanup = AttachmentCleanup::default();
                for row in rows {
                    let object_key: String = row.try_get("object_key")?;
                    let mut transaction = pool.begin().await?;
                    lock_attachment_object(&mut transaction, &object_key).await?;
                    let has_live_reference: bool = sqlx::query_scalar(
                        "SELECT EXISTS (
                           SELECT 1
                           FROM attachment_uploads
                           WHERE object_key = $1
                             AND (message_id IS NOT NULL OR expires_at >= $2)
                         )",
                    )
                    .bind(&object_key)
                    .bind(now)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if !has_live_reference
                        && attachments
                            .delete_object(&object_key)
                            .await
                            .map_err(|error| {
                                RepositoryError::AttachmentStorage(error.to_string())
                            })?
                    {
                        cleanup.objects += 1;
                    }
                    let deleted = sqlx::query(
                        "DELETE FROM attachment_uploads
                         WHERE object_key = $1
                           AND message_id IS NULL
                           AND expires_at < $2",
                    )
                    .bind(&object_key)
                    .bind(now)
                    .execute(&mut *transaction)
                    .await?;
                    cleanup.reservations += deleted.rows_affected();
                    transaction.commit().await?;
                }
                Ok(cleanup)
            }
        }
    }

    pub async fn attachment_record(
        &self,
        attachment_id: AttachmentId,
    ) -> Result<AttachmentRecord, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => store
                .read()
                .await
                .attachments
                .get(&attachment_id)
                .cloned()
                .ok_or(RepositoryError::NotFound("attachment")),
            RepositoryBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, channel_id, owner_id, message_id, filename,
                            declared_content_type, verified_content_type, file_size,
                            claimed_sha256, verified_sha256, object_key, public_url,
                            width, height, animated, state, expires_at
                     FROM attachment_uploads WHERE id = $1",
                )
                .bind(db_id(attachment_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("attachment"))?;
                attachment_record_from_row(&row)
            }
        }
    }

    pub async fn complete_attachment(
        &self,
        owner_id: UserId,
        attachment_id: AttachmentId,
        verified: &VerifiedAttachment,
    ) -> Result<MessageAttachment, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let record = store
                    .attachments
                    .get_mut(&attachment_id)
                    .ok_or(RepositoryError::NotFound("attachment"))?;
                validate_attachment_completion(record, owner_id, verified)?;
                record.verified_content_type = Some(verified.content_type.clone());
                record.verified_sha256 = Some(verified.sha256);
                record.width = verified.width;
                record.height = verified.height;
                record.animated = verified.animated;
                record.ready = true;
                record_to_message_attachment(record)
            }
            RepositoryBackend::Postgres(pool) => {
                let object_key = sqlx::query_scalar::<_, String>(
                    "SELECT object_key FROM attachment_uploads WHERE id = $1",
                )
                .bind(db_id(attachment_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("attachment"))?;
                let mut transaction = pool.begin().await?;
                lock_attachment_object(&mut transaction, &object_key).await?;
                let row = sqlx::query(
                    "SELECT id, channel_id, owner_id, message_id, filename,
                            declared_content_type, verified_content_type, file_size,
                            claimed_sha256, verified_sha256, object_key, public_url,
                            width, height, animated, state, expires_at
                     FROM attachment_uploads WHERE id = $1 FOR UPDATE",
                )
                .bind(db_id(attachment_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("attachment"))?;
                let mut record = attachment_record_from_row(&row)?;
                validate_attachment_completion(&record, owner_id, verified)?;
                sqlx::query(
                    "UPDATE attachment_uploads
                     SET verified_content_type = $2, verified_sha256 = $3,
                         width = $4, height = $5, animated = $6, state = 1,
                         validated_at = now()
                     WHERE id = $1",
                )
                .bind(db_id(attachment_id.raw())?)
                .bind(&verified.content_type)
                .bind(verified.sha256.to_vec())
                .bind(
                    verified.width.map(i32::try_from).transpose().map_err(|_| {
                        RepositoryError::InvalidData("attachment width is too large")
                    })?,
                )
                .bind(
                    verified
                        .height
                        .map(i32::try_from)
                        .transpose()
                        .map_err(|_| {
                            RepositoryError::InvalidData("attachment height is too large")
                        })?,
                )
                .bind(verified.animated)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                record.verified_content_type = Some(verified.content_type.clone());
                record.verified_sha256 = Some(verified.sha256);
                record.width = verified.width;
                record.height = verified.height;
                record.animated = verified.animated;
                record.ready = true;
                record_to_message_attachment(&record)
            }
        }
    }

    pub async fn search_messages(
        &self,
        user_id: UserId,
        guild_id: GuildId,
        query: &str,
        limit: usize,
    ) -> Result<MessageSearchResult, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                if !store.memberships.contains(&(guild_id, user_id)) {
                    return Err(RepositoryError::NotFound("server"));
                }
                let mut searchable = HashMap::new();
                let mut excluded_channels = Vec::new();
                for channel in store.channels.values().filter(|channel| {
                    channel.guild_id == guild_id && channel.kind == ChannelKind::Text
                }) {
                    let permissions = memory_channel_permissions(&store, user_id, channel)?;
                    if !permissions.contains(
                        GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY,
                    ) {
                        excluded_channels.push(SearchExcludedChannel {
                            id: channel.id,
                            name: channel.name.clone(),
                            reason: SearchExclusionReason::NoPermission,
                        });
                    } else if channel.encrypted {
                        excluded_channels.push(SearchExcludedChannel {
                            id: channel.id,
                            name: channel.name.clone(),
                            reason: SearchExclusionReason::E2ee,
                        });
                    } else {
                        searchable.insert(channel.id, channel.name.clone());
                    }
                }
                let terms = search_terms(query);
                let mut hits = store
                    .messages
                    .iter()
                    .filter_map(|(channel_id, messages)| {
                        searchable.get(channel_id).map(|name| (name, messages))
                    })
                    .flat_map(|(channel_name, messages)| {
                        let terms = terms.clone();
                        messages.iter().filter_map(move |message| {
                            let content = message.content.to_lowercase();
                            let matched = terms
                                .iter()
                                .filter(|term| content.contains(term.as_str()))
                                .count();
                            (matched == terms.len()).then(|| SearchHit {
                                message: message.clone(),
                                channel_name: channel_name.clone(),
                                score: matched as f64,
                            })
                        })
                    })
                    .collect::<Vec<_>>();
                hits.sort_by_key(|hit| std::cmp::Reverse(hit.message.id));
                let total = hits.len() as u64;
                hits.truncate(limit);
                sort_exclusions(&mut excluded_channels);
                Ok(MessageSearchResult {
                    total,
                    hits,
                    excluded_channels,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                if !self.is_guild_member(user_id, guild_id).await? {
                    return Err(RepositoryError::NotFound("server"));
                }
                let rows = sqlx::query(
                    "SELECT id, guild_id, name, type, position, e2ee, created_at
                     FROM channels
                     WHERE guild_id = $1 AND deleted_at IS NULL AND type = $2
                     ORDER BY position, id",
                )
                .bind(db_id(guild_id.raw())?)
                .bind(channel_kind_to_db(ChannelKind::Text))
                .fetch_all(pool)
                .await?;
                let channels = rows
                    .iter()
                    .map(channel_from_row)
                    .collect::<Result<Vec<_>, _>>()?;
                let permissions = postgres_channel_permission_map(
                    pool,
                    user_id,
                    guild_id,
                    channels.iter().map(|channel| channel.id),
                )
                .await?;
                let mut searchable_ids = Vec::new();
                let mut excluded_channels = Vec::new();
                for channel in channels {
                    let can_search = permissions.get(&channel.id).is_some_and(|value| {
                        value.contains(
                            GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY,
                        )
                    });
                    if !can_search {
                        excluded_channels.push(SearchExcludedChannel {
                            id: channel.id,
                            name: channel.name,
                            reason: SearchExclusionReason::NoPermission,
                        });
                    } else if channel.encrypted {
                        excluded_channels.push(SearchExcludedChannel {
                            id: channel.id,
                            name: channel.name,
                            reason: SearchExclusionReason::E2ee,
                        });
                    } else {
                        searchable_ids.push(db_id(channel.id.raw())?);
                    }
                }
                let mut hits = Vec::new();
                let mut total = 0;
                if !searchable_ids.is_empty() {
                    let rows =
                        sqlx::query(
                            "SELECT m.id, m.channel_id, m.author_id,
                                COALESCE(m.content, '') AS content, m.ciphertext,
                                m.frank_commit, m.frank_tag, m.sender_device_id, m.nonce,
                                m.attachments,
                                m.sequence, snowflake_to_timestamp(m.id) AS created_at,
                                m.edited_at, c.name AS channel_name,
                                ts_rank_cd(
                                  to_tsvector('simple', COALESCE(m.content, '')),
                                  websearch_to_tsquery('simple', $2)
                                )::float8 AS score,
                                count(*) OVER() AS total
                         FROM messages m
                         JOIN channels c ON c.id = m.channel_id
                         WHERE m.channel_id = ANY($1)
                           AND m.deleted_at IS NULL
                           AND m.ciphertext IS NULL
                           AND to_tsvector('simple', COALESCE(m.content, ''))
                               @@ websearch_to_tsquery('simple', $2)
                         ORDER BY score DESC, m.id DESC
                         LIMIT $3",
                        )
                        .bind(&searchable_ids)
                        .bind(query)
                        .bind(i64::try_from(limit).map_err(|_| {
                            RepositoryError::InvalidData("search limit is too large")
                        })?)
                        .fetch_all(pool)
                        .await?;
                    for row in &rows {
                        let row_total: i64 = row.try_get("total")?;
                        total = u64::try_from(row_total).map_err(|_| {
                            RepositoryError::InvalidData("search total is negative")
                        })?;
                        hits.push(SearchHit {
                            message: message_from_row(row)?,
                            channel_name: row.try_get("channel_name")?,
                            score: row.try_get("score")?,
                        });
                    }
                }
                sort_exclusions(&mut excluded_channels);
                Ok(MessageSearchResult {
                    total,
                    hits,
                    excluded_channels,
                })
            }
        }
    }

    pub async fn list_messages(
        &self,
        user_id: UserId,
        channel_id: ChannelId,
        window: MessageWindow,
    ) -> Result<Vec<Message>, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                memory_message_audience(&store, user_id, channel_id, false)?;
                let mut messages = store.messages.get(&channel_id).cloned().unwrap_or_default();
                apply_memory_window(&mut messages, window);
                hydrate_memory_reactions(&store, user_id, &mut messages);
                Ok(messages)
            }
            RepositoryBackend::Postgres(pool) => {
                require_message_access(pool, user_id, channel_id, false).await?;
                let limit = i64::try_from(window.limit)
                    .map_err(|_| RepositoryError::InvalidData("message window is too large"))?;
                let rows = if let Some(before) = window.before {
                    sqlx::query(
                        "SELECT id, channel_id, author_id, COALESCE(content, '') AS content,
                                ciphertext, frank_commit, frank_tag, sender_device_id, nonce,
                                attachments, reference_id, sequence,
                                snowflake_to_timestamp(id) AS created_at, edited_at
                         FROM messages
                         WHERE channel_id = $1 AND id < $2 AND deleted_at IS NULL
                         ORDER BY id DESC LIMIT $3",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(db_id(before)?)
                    .bind(limit)
                    .fetch_all(pool)
                    .await?
                } else if let Some(after) = window.after {
                    sqlx::query(
                        "SELECT id, channel_id, author_id, COALESCE(content, '') AS content,
                                ciphertext, frank_commit, frank_tag, sender_device_id, nonce,
                                attachments, reference_id, sequence,
                                snowflake_to_timestamp(id) AS created_at, edited_at
                         FROM messages
                         WHERE channel_id = $1 AND id > $2 AND deleted_at IS NULL
                         ORDER BY id ASC LIMIT $3",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(db_id(after)?)
                    .bind(limit)
                    .fetch_all(pool)
                    .await?
                } else if let Some(around) = window.around {
                    sqlx::query(
                        "SELECT id, channel_id, author_id, content, ciphertext,
                                frank_commit, frank_tag, sender_device_id, nonce,
                                attachments, reference_id, sequence, created_at, edited_at
                         FROM (
                           SELECT id, channel_id, author_id, COALESCE(content, '') AS content,
                                  ciphertext, frank_commit, frank_tag, sender_device_id, nonce,
                                  attachments, reference_id, sequence,
                                  snowflake_to_timestamp(id) AS created_at, edited_at
                           FROM messages
                           WHERE channel_id = $1 AND deleted_at IS NULL
                           ORDER BY abs(id - $2) ASC LIMIT $3
                         ) nearest
                         ORDER BY id DESC",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(db_id(around)?)
                    .bind(limit)
                    .fetch_all(pool)
                    .await?
                } else {
                    sqlx::query(
                        "SELECT id, channel_id, author_id, COALESCE(content, '') AS content,
                                ciphertext, frank_commit, frank_tag, sender_device_id, nonce,
                                attachments, reference_id, sequence,
                                snowflake_to_timestamp(id) AS created_at, edited_at
                         FROM messages
                         WHERE channel_id = $1 AND deleted_at IS NULL
                         ORDER BY id DESC LIMIT $2",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(limit)
                    .fetch_all(pool)
                    .await?
                };
                let mut messages = rows
                    .iter()
                    .map(message_from_row)
                    .collect::<Result<Vec<_>, _>>()?;
                hydrate_postgres_reactions(pool, user_id, &mut messages).await?;
                Ok(messages)
            }
        }
    }

    pub async fn message_safety_context(
        &self,
        author_id: UserId,
        channel_id: ChannelId,
        nonce: &str,
    ) -> Result<MessageSafetyContext, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let audience = memory_message_audience(&store, author_id, channel_id, true)?;
                let account_created_at = store
                    .users
                    .get(&author_id)
                    .ok_or(RepositoryError::NotFound("user"))?
                    .created_at;
                let (encrypted, mls_ready) = if let Some(channel) =
                    store.direct_channels.get(&channel_id)
                {
                    (channel.encrypted, channel.mls_group_id.is_some())
                } else {
                    let channel = store
                        .channels
                        .get(&channel_id)
                        .ok_or(RepositoryError::NotFound("channel"))?;
                    (
                        channel.encrypted,
                        !channel.encrypted || store.channel_mls_groups.contains_key(&channel_id),
                    )
                };
                Ok(MessageSafetyContext {
                    guild_id: match audience {
                        MessageAudience::Guild(guild_id) => Some(guild_id),
                        MessageAudience::Users(_) => None,
                    },
                    account_created_at,
                    existing_message: store
                        .message_nonces
                        .get(&(channel_id, author_id, nonce.to_owned()))
                        .cloned(),
                    encrypted,
                    mls_ready,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let audience = require_message_access(pool, author_id, channel_id, true).await?;
                let account_created_at = sqlx::query_scalar(
                    "SELECT created_at FROM users WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(author_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("user"))?;
                let encryption = sqlx::query(
                    "SELECT e2ee, mls_group_id
                     FROM channels
                     WHERE id = $1 AND deleted_at IS NULL",
                )
                .bind(db_id(channel_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("channel"))?;
                let encrypted: bool = encryption.try_get("e2ee")?;
                let mls_group_id: Option<Vec<u8>> = encryption.try_get("mls_group_id")?;
                let existing_message = sqlx::query(
                    "SELECT m.id, m.channel_id, m.author_id,
                            COALESCE(m.content, '') AS content, m.ciphertext,
                            m.frank_commit, m.frank_tag, m.sender_device_id, m.nonce,
                            m.attachments, m.reference_id, m.sequence,
                            snowflake_to_timestamp(m.id) AS created_at, m.edited_at
                     FROM message_nonces n
                     JOIN messages m
                       ON m.id = n.message_id AND m.channel_id = n.channel_id
                     WHERE n.channel_id = $1 AND n.author_id = $2 AND n.nonce = $3
                       AND m.deleted_at IS NULL",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(author_id.raw())?)
                .bind(nonce)
                .fetch_optional(pool)
                .await?
                .as_ref()
                .map(message_from_row)
                .transpose()?;
                Ok(MessageSafetyContext {
                    guild_id: match audience {
                        MessageAudience::Guild(guild_id) => Some(guild_id),
                        MessageAudience::Users(_) => None,
                    },
                    account_created_at,
                    existing_message,
                    encrypted,
                    mls_ready: !encrypted || mls_group_id.is_some(),
                })
            }
        }
    }

    pub async fn reportable_message(
        &self,
        reporter_id: UserId,
        message_id: MessageId,
    ) -> Result<Message, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let message = store
                    .messages
                    .values()
                    .flatten()
                    .find(|message| message.id == message_id)
                    .cloned()
                    .ok_or(RepositoryError::NotFound("message"))?;
                memory_message_audience(&store, reporter_id, message.channel_id, false)?;
                if message.author_id == reporter_id {
                    return Err(RepositoryError::BadRequest(
                        "a member cannot report their own message",
                    ));
                }
                Ok(message)
            }
            RepositoryBackend::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT id, channel_id, author_id,
                            COALESCE(content, '') AS content, ciphertext,
                            frank_commit, frank_tag, sender_device_id, nonce,
                            attachments, reference_id, sequence,
                            snowflake_to_timestamp(id) AS created_at, edited_at
                     FROM messages
                     WHERE id = $1 AND deleted_at IS NULL
                     LIMIT 1",
                )
                .bind(db_id(message_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("message"))?;
                let message = message_from_row(&row)?;
                require_message_access(pool, reporter_id, message.channel_id, false).await?;
                if message.author_id == reporter_id {
                    return Err(RepositoryError::BadRequest(
                        "a member cannot report their own message",
                    ));
                }
                Ok(message)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_message_report(
        &self,
        reporter_id: UserId,
        message_id: MessageId,
        channel_id: ChannelId,
        author_id: UserId,
        guild_id: Option<GuildId>,
        category: ReportCategory,
        detail: Option<String>,
        evidence_payload: Vec<u8>,
        frank_tag: Option<[u8; 32]>,
    ) -> Result<ReportReceipt, RepositoryError> {
        let receipt = ReportReceipt {
            id: ReportId::new(),
            status: "open".into(),
            created_at: Utc::now(),
        };
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                store.write().await.reports.push(ReportRecord {
                    receipt: receipt.clone(),
                    reporter_id,
                    message_id,
                    channel_id,
                    author_id,
                    guild_id,
                    category,
                    detail,
                    evidence_payload,
                    frank_tag,
                    handled_by_operator: None,
                    handled_at: None,
                    resolution_note: None,
                });
            }
            RepositoryBackend::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO reports
                       (id, reporter_id, target_type, target_id, guild_id,
                        category, detail, evidence_payload, frank_tag, created_at)
                     VALUES ($1, $2, 0, $3, $4, $5, $6, $7, $8, $9)",
                )
                .bind(db_id(receipt.id.raw())?)
                .bind(db_id(reporter_id.raw())?)
                .bind(db_id(message_id.raw())?)
                .bind(guild_id.map(|id| db_id(id.raw())).transpose()?)
                .bind(report_category_to_db(category))
                .bind(detail)
                .bind(evidence_payload)
                .bind(frank_tag.map(|tag| tag.to_vec()))
                .bind(receipt.created_at)
                .execute(pool)
                .await?;
            }
        }
        Ok(receipt)
    }

    pub async fn operator_reports(
        &self,
        status: Option<OperatorReportStatus>,
        limit: u32,
    ) -> Result<Vec<OperatorReport>, RepositoryError> {
        let limit = limit.clamp(1, 100) as usize;
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let mut reports = store
                    .reports
                    .iter()
                    .filter(|report| {
                        status.is_none_or(|status| report.receipt.status == status.as_str())
                    })
                    .map(|report| memory_operator_report(&store, report))
                    .collect::<Result<Vec<_>, _>>()?;
                reports.sort_by(|left, right| {
                    right
                        .created_at
                        .cmp(&left.created_at)
                        .then_with(|| right.id.cmp(&left.id))
                });
                reports.truncate(limit);
                Ok(reports)
            }
            RepositoryBackend::Postgres(pool) => {
                let rows = sqlx::query(&format!(
                    "{OPERATOR_REPORT_SELECT}
                     WHERE reports.target_type = 0
                       AND ($1::smallint IS NULL OR reports.status = $1)
                     ORDER BY reports.created_at DESC, reports.id DESC
                     LIMIT $2"
                ))
                .bind(status.map(OperatorReportStatus::database_value))
                .bind(i64::try_from(limit).map_err(|_| {
                    RepositoryError::InvalidData("operator report limit is invalid")
                })?)
                .fetch_all(pool)
                .await?;
                rows.iter().map(operator_report_from_row).collect()
            }
        }
    }

    pub async fn operator_report(
        &self,
        report_id: ReportId,
    ) -> Result<OperatorReport, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let store = store.read().await;
                let report = store
                    .reports
                    .iter()
                    .find(|report| report.receipt.id == report_id)
                    .ok_or(RepositoryError::NotFound("report"))?;
                memory_operator_report(&store, report)
            }
            RepositoryBackend::Postgres(pool) => {
                let row = sqlx::query(&format!(
                    "{OPERATOR_REPORT_SELECT}
                     WHERE reports.id = $1 AND reports.target_type = 0"
                ))
                .bind(db_id(report_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("report"))?;
                operator_report_from_row(&row)
            }
        }
    }

    pub async fn resolve_operator_report(
        &self,
        report_id: ReportId,
        status: OperatorReportStatus,
        operator: &str,
        note: Option<String>,
    ) -> Result<OperatorReport, RepositoryError> {
        if status == OperatorReportStatus::Open {
            return Err(RepositoryError::BadRequest(
                "a report can only be actioned or dismissed",
            ));
        }
        let operator = operator.trim();
        if operator.is_empty() || operator.len() > 100 {
            return Err(RepositoryError::BadRequest("the operator label is invalid"));
        }
        let note = note
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if note.as_ref().is_some_and(|value| value.len() > 1_000) {
            return Err(RepositoryError::BadRequest(
                "the report resolution note is too long",
            ));
        }
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let report_index = store
                    .reports
                    .iter()
                    .position(|report| report.receipt.id == report_id)
                    .ok_or(RepositoryError::NotFound("report"))?;
                if store.reports[report_index].receipt.status != OperatorReportStatus::Open.as_str()
                {
                    return Err(RepositoryError::Conflict);
                }
                let report = &mut store.reports[report_index];
                report.receipt.status = status.as_str().to_owned();
                report.handled_by_operator = Some(operator.to_owned());
                report.handled_at = Some(Utc::now());
                report.resolution_note = note;
                let report = report.clone();
                memory_operator_report(&store, &report)
            }
            RepositoryBackend::Postgres(pool) => {
                let updated = sqlx::query(
                    "UPDATE reports
                        SET status = $1,
                            handled_by_operator = $2,
                            handled_at = now(),
                            resolution_note = $3
                      WHERE id = $4 AND target_type = 0 AND status = 0",
                )
                .bind(status.database_value())
                .bind(operator)
                .bind(note)
                .bind(db_id(report_id.raw())?)
                .execute(pool)
                .await?;
                if updated.rows_affected() == 0 {
                    let exists: bool =
                        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM reports WHERE id = $1)")
                            .bind(db_id(report_id.raw())?)
                            .fetch_one(pool)
                            .await?;
                    return Err(if exists {
                        RepositoryError::Conflict
                    } else {
                        RepositoryError::NotFound("report")
                    });
                }
                let row = sqlx::query(&format!(
                    "{OPERATOR_REPORT_SELECT}
                     WHERE reports.id = $1 AND reports.target_type = 0"
                ))
                .bind(db_id(report_id.raw())?)
                .fetch_optional(pool)
                .await?
                .ok_or(RepositoryError::NotFound("report"))?;
                operator_report_from_row(&row)
            }
        }
    }

    pub async fn apply_automod_match(
        &self,
        guild_id: GuildId,
        member_id: UserId,
        matched: &AutomodMatch,
    ) -> Result<AutomodEnforcement, RepositoryError> {
        let now = Utc::now();
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let guild = store
                    .guilds
                    .get(&guild_id)
                    .ok_or(RepositoryError::NotFound("server"))?;
                if !store.users.contains_key(&member_id) {
                    return Err(RepositoryError::NotFound("user"));
                }
                let applied_action = if guild.owner_id == member_id
                    && matches!(
                        matched.action,
                        AutomodAction::Timeout | AutomodAction::Kick | AutomodAction::Ban
                    ) {
                    AutomodAction::Block
                } else {
                    matched.action
                };
                let mut removed_from_guild = false;
                match applied_action {
                    AutomodAction::Flag | AutomodAction::Block => {}
                    AutomodAction::Timeout => {
                        if store.memberships.contains(&(guild_id, member_id)) {
                            let seconds = matched.duration_seconds.ok_or_else(|| {
                                RepositoryError::Validation(
                                    "automod timeout duration is missing".into(),
                                )
                            })?;
                            store.timeouts.insert(
                                (guild_id, member_id),
                                now + chrono::TimeDelta::seconds(i64::from(seconds)),
                            );
                        }
                    }
                    AutomodAction::Kick => {
                        removed_from_guild = store.memberships.contains(&(guild_id, member_id));
                        remove_memory_membership(&mut store, guild_id, member_id);
                    }
                    AutomodAction::Ban => {
                        let seconds = matched.duration_seconds.ok_or_else(|| {
                            RepositoryError::Validation("automod ban duration is missing".into())
                        })?;
                        let expires_at = Some(now + chrono::TimeDelta::seconds(i64::from(seconds)));
                        store.bans.insert(
                            (guild_id, member_id),
                            MemoryBan {
                                actor_id: None,
                                reason: Some(matched.explanation.clone()),
                                expires_at,
                                created_at: now,
                            },
                        );
                        removed_from_guild = store.memberships.contains(&(guild_id, member_id));
                        remove_memory_membership(&mut store, guild_id, member_id);
                    }
                }
                push_memory_audit_entry(
                    &mut store,
                    guild_id,
                    None,
                    Some(member_id.raw()),
                    automod_audit_action(applied_action),
                    serde_json::json!({
                        "ruleId": matched.rule_id,
                        "ruleName": matched.rule_name,
                        "requestedAction": matched.action,
                        "appliedAction": applied_action,
                        "durationSeconds": matched.duration_seconds
                    }),
                    Some(matched.explanation.clone()),
                );
                Ok(AutomodEnforcement {
                    applied_action,
                    removed_from_guild,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let owner_id: i64 = sqlx::query_scalar(
                    "SELECT owner_id FROM guilds
                     WHERE id = $1 AND deleted_at IS NULL
                     FOR UPDATE",
                )
                .bind(db_id(guild_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("server"))?;
                let applied_action = if user_id_from_db(owner_id)? == member_id
                    && matches!(
                        matched.action,
                        AutomodAction::Timeout | AutomodAction::Kick | AutomodAction::Ban
                    ) {
                    AutomodAction::Block
                } else {
                    matched.action
                };
                let mut removed_from_guild = false;
                match applied_action {
                    AutomodAction::Flag | AutomodAction::Block => {}
                    AutomodAction::Timeout => {
                        let seconds = matched.duration_seconds.ok_or_else(|| {
                            RepositoryError::Validation(
                                "automod timeout duration is missing".into(),
                            )
                        })?;
                        sqlx::query(
                            "UPDATE guild_members
                             SET timeout_until = $1
                             WHERE guild_id = $2 AND user_id = $3",
                        )
                        .bind(now + chrono::TimeDelta::seconds(i64::from(seconds)))
                        .bind(db_id(guild_id.raw())?)
                        .bind(db_id(member_id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                    }
                    AutomodAction::Kick => {
                        let removed = sqlx::query(
                            "DELETE FROM guild_members
                             WHERE guild_id = $1 AND user_id = $2",
                        )
                        .bind(db_id(guild_id.raw())?)
                        .bind(db_id(member_id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                        removed_from_guild = removed.rows_affected() == 1;
                    }
                    AutomodAction::Ban => {
                        let seconds = matched.duration_seconds.ok_or_else(|| {
                            RepositoryError::Validation("automod ban duration is missing".into())
                        })?;
                        let expires_at = now + chrono::TimeDelta::seconds(i64::from(seconds));
                        sqlx::query(
                            "INSERT INTO bans
                               (guild_id, user_id, actor_id, reason, expires_at, created_at)
                             VALUES ($1, $2, NULL, $3, $4, $5)
                             ON CONFLICT (guild_id, user_id) DO UPDATE SET
                               actor_id = NULL,
                               reason = EXCLUDED.reason,
                               expires_at = EXCLUDED.expires_at,
                               created_at = EXCLUDED.created_at",
                        )
                        .bind(db_id(guild_id.raw())?)
                        .bind(db_id(member_id.raw())?)
                        .bind(&matched.explanation)
                        .bind(expires_at)
                        .bind(now)
                        .execute(&mut *transaction)
                        .await?;
                        let removed = sqlx::query(
                            "DELETE FROM guild_members
                             WHERE guild_id = $1 AND user_id = $2",
                        )
                        .bind(db_id(guild_id.raw())?)
                        .bind(db_id(member_id.raw())?)
                        .execute(&mut *transaction)
                        .await?;
                        removed_from_guild = removed.rows_affected() == 1;
                    }
                }
                if removed_from_guild {
                    sqlx::query(
                        "UPDATE guilds
                         SET member_count = GREATEST(member_count - 1, 0)
                         WHERE id = $1",
                    )
                    .bind(db_id(guild_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                }
                insert_system_audit_entry(
                    &mut transaction,
                    guild_id,
                    member_id,
                    automod_audit_action(applied_action),
                    serde_json::json!({
                        "ruleId": matched.rule_id,
                        "ruleName": matched.rule_name,
                        "requestedAction": matched.action,
                        "appliedAction": applied_action,
                        "durationSeconds": matched.duration_seconds
                    }),
                    &matched.explanation,
                )
                .await?;
                transaction.commit().await?;
                Ok(AutomodEnforcement {
                    applied_action,
                    removed_from_guild,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_message(
        &self,
        author_id: UserId,
        channel_id: ChannelId,
        content: String,
        reply_to: Option<MessageId>,
        nonce: String,
        attachment_ids: &[AttachmentId],
        sequence: u32,
    ) -> Result<CreatedMessage, RepositoryError> {
        self.create_message_payload(
            author_id,
            channel_id,
            content,
            None,
            None,
            reply_to,
            nonce,
            attachment_ids,
            sequence,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_encrypted_message(
        &self,
        author_id: UserId,
        channel_id: ChannelId,
        encryption: NewMessageEncryption,
        franking_key: [u8; 32],
        reply_to: Option<MessageId>,
        nonce: String,
        attachment_ids: &[AttachmentId],
        sequence: u32,
    ) -> Result<CreatedMessage, RepositoryError> {
        self.create_message_payload(
            author_id,
            channel_id,
            String::new(),
            Some(encryption),
            Some(franking_key),
            reply_to,
            nonce,
            attachment_ids,
            sequence,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_message_payload(
        &self,
        author_id: UserId,
        channel_id: ChannelId,
        content: String,
        mut encryption: Option<NewMessageEncryption>,
        franking_key: Option<[u8; 32]>,
        reply_to: Option<MessageId>,
        nonce: String,
        attachment_ids: &[AttachmentId],
        sequence: u32,
    ) -> Result<CreatedMessage, RepositoryError> {
        let message_id = MessageId::new();
        let created_at = Utc::now();
        if let Some(encryption) = encryption.as_mut() {
            encryption.franking_tag = calculate_franking_tag(
                &franking_key.ok_or(RepositoryError::InvalidData(
                    "encrypted message is missing a franking key",
                ))?,
                channel_id,
                author_id,
                message_id,
                created_at,
                &nonce,
                &encryption.franking_commitment,
            );
        }
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let audience = memory_message_audience(&store, author_id, channel_id, true)?;
                if let Some(encryption) = &encryption {
                    let identity = store
                        .device_identities
                        .get(&encryption.sender_device_id)
                        .ok_or(RepositoryError::NotFound("device identity"))?;
                    if identity.user_id != author_id || identity.revoked_at.is_some() {
                        return Err(RepositoryError::Forbidden);
                    }
                }
                let nonce_key = (channel_id, author_id, nonce.clone());
                if let Some(existing) = store.message_nonces.get(&nonce_key) {
                    return Ok(CreatedMessage {
                        message: existing.clone(),
                        audience,
                        created: false,
                    });
                }
                if let Some(reply_to) = reply_to
                    && !store.messages.get(&channel_id).is_some_and(|messages| {
                        messages.iter().any(|message| message.id == reply_to)
                    })
                {
                    return Err(RepositoryError::NotFound("reply message"));
                }
                let mut attachments = Vec::with_capacity(attachment_ids.len());
                let mut unique_ids = HashSet::new();
                for attachment_id in attachment_ids {
                    if !unique_ids.insert(*attachment_id) {
                        return Err(RepositoryError::BadRequest(
                            "an attachment cannot be included twice",
                        ));
                    }
                    let record = store
                        .attachments
                        .get(attachment_id)
                        .ok_or(RepositoryError::NotFound("attachment"))?;
                    validate_attachment_for_message(record, author_id, channel_id)?;
                    attachments.push(record_to_message_attachment(record)?);
                }
                let message = Message {
                    id: message_id,
                    channel_id,
                    author_id,
                    reply_to,
                    content,
                    encryption: encryption
                        .as_ref()
                        .map(|encryption| message_encryption(encryption, &nonce)),
                    attachments,
                    reactions: Vec::new(),
                    sequence: u64::from(sequence),
                    created_at,
                    edited_at: None,
                };
                for attachment_id in attachment_ids {
                    if let Some(record) = store.attachments.get_mut(attachment_id) {
                        record.message_id = Some(message.id);
                    }
                }
                store
                    .messages
                    .entry(channel_id)
                    .or_default()
                    .push(message.clone());
                if let Some(channel) = store.direct_channels.get_mut(&channel_id) {
                    channel.last_message_id = Some(message.id);
                }
                store.message_nonces.insert(nonce_key, message.clone());
                Ok(CreatedMessage {
                    message,
                    audience,
                    created: true,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let audience = require_message_access(pool, author_id, channel_id, true).await?;
                let guild_id = match &audience {
                    MessageAudience::Guild(guild_id) => Some(*guild_id),
                    MessageAudience::Users(_) => None,
                };
                let mut transaction = pool.begin().await?;
                if let Some(encryption) = &encryption {
                    let valid_device: bool = sqlx::query_scalar(
                        "SELECT EXISTS(
                           SELECT 1 FROM device_identities
                           WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
                         )",
                    )
                    .bind(encryption.sender_device_id)
                    .bind(db_id(author_id.raw())?)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if !valid_device {
                        return Err(RepositoryError::Forbidden);
                    }
                }
                let reserved: Option<i64> = sqlx::query_scalar(
                    "INSERT INTO message_nonces
                       (channel_id, author_id, nonce, message_id)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (channel_id, author_id, nonce) DO NOTHING
                     RETURNING message_id",
                )
                .bind(db_id(channel_id.raw())?)
                .bind(db_id(author_id.raw())?)
                .bind(&nonce)
                .bind(db_id(message_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?;
                if reserved.is_none() {
                    let existing = sqlx::query(
                        "SELECT m.id, m.channel_id, m.author_id,
                                COALESCE(m.content, '') AS content, m.ciphertext,
                                m.frank_commit, m.frank_tag, m.sender_device_id, m.nonce,
                                m.attachments, m.reference_id, m.sequence,
                                snowflake_to_timestamp(m.id) AS created_at, m.edited_at
                         FROM message_nonces n
                         JOIN messages m
                           ON m.id = n.message_id AND m.channel_id = n.channel_id
                         WHERE n.channel_id = $1 AND n.author_id = $2 AND n.nonce = $3",
                    )
                    .bind(db_id(channel_id.raw())?)
                    .bind(db_id(author_id.raw())?)
                    .bind(&nonce)
                    .fetch_one(&mut *transaction)
                    .await?;
                    let existing = message_from_row(&existing)?;
                    transaction.commit().await?;
                    return Ok(CreatedMessage {
                        message: existing,
                        audience,
                        created: false,
                    });
                }
                if let Some(reply_to) = reply_to {
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS (
                           SELECT 1 FROM messages
                           WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL
                         )",
                    )
                    .bind(db_id(reply_to.raw())?)
                    .bind(db_id(channel_id.raw())?)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if !exists {
                        return Err(RepositoryError::NotFound("reply message"));
                    }
                }
                let mut attachments_by_id = HashMap::new();
                if !attachment_ids.is_empty() {
                    let attachment_db_ids = attachment_ids
                        .iter()
                        .map(|id| db_id(id.raw()))
                        .collect::<Result<Vec<_>, _>>()?;
                    let rows = sqlx::query(
                        "SELECT id, channel_id, owner_id, message_id, filename,
                                declared_content_type, verified_content_type, file_size,
                                claimed_sha256, verified_sha256, object_key, public_url,
                                width, height, animated, state, expires_at
                         FROM attachment_uploads
                         WHERE id = ANY($1)
                         FOR UPDATE",
                    )
                    .bind(&attachment_db_ids)
                    .fetch_all(&mut *transaction)
                    .await?;
                    for row in &rows {
                        let record = attachment_record_from_row(row)?;
                        attachments_by_id.insert(record.id, record);
                    }
                }
                let mut attachments = Vec::with_capacity(attachment_ids.len());
                let mut unique_ids = HashSet::new();
                for attachment_id in attachment_ids {
                    if !unique_ids.insert(*attachment_id) {
                        return Err(RepositoryError::BadRequest(
                            "an attachment cannot be included twice",
                        ));
                    }
                    let record = attachments_by_id
                        .get(attachment_id)
                        .ok_or(RepositoryError::NotFound("attachment"))?;
                    validate_attachment_for_message(record, author_id, channel_id)?;
                    attachments.push(record_to_message_attachment(record)?);
                }
                let message = Message {
                    id: message_id,
                    channel_id,
                    author_id,
                    reply_to,
                    content,
                    encryption: encryption
                        .as_ref()
                        .map(|encryption| message_encryption(encryption, &nonce)),
                    attachments,
                    reactions: Vec::new(),
                    sequence: u64::from(sequence),
                    created_at,
                    edited_at: None,
                };
                sqlx::query(
                    "INSERT INTO messages
                       (id, channel_id, guild_id, author_id, content, ciphertext,
                        nonce, sequence, attachments, frank_tag, frank_commit,
                        sender_device_id, reference_id, reference_channel_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                )
                .bind(db_id(message.id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .bind(guild_id.map(|guild_id| db_id(guild_id.raw())).transpose()?)
                .bind(db_id(author_id.raw())?)
                .bind(encryption.as_ref().map_or(Some(&message.content), |_| None))
                .bind(encryption.as_ref().map(|value| value.ciphertext.as_slice()))
                .bind(&nonce)
                .bind(i64::from(sequence))
                .bind(
                    serde_json::to_value(&message.attachments)
                        .map_err(|_| RepositoryError::InvalidData("attachment JSON is invalid"))?,
                )
                .bind(
                    encryption
                        .as_ref()
                        .map(|value| value.franking_tag.as_slice()),
                )
                .bind(
                    encryption
                        .as_ref()
                        .map(|value| value.franking_commitment.as_slice()),
                )
                .bind(encryption.as_ref().map(|value| value.sender_device_id))
                .bind(reply_to.map(|id| db_id(id.raw())).transpose()?)
                .bind(reply_to.map(|_| db_id(channel_id.raw())).transpose()?)
                .execute(&mut *transaction)
                .await?;
                if !attachment_ids.is_empty() {
                    let attachment_db_ids = attachment_ids
                        .iter()
                        .map(|id| db_id(id.raw()))
                        .collect::<Result<Vec<_>, _>>()?;
                    sqlx::query(
                        "UPDATE attachment_uploads
                         SET message_id = $1, expires_at = GREATEST(expires_at, now())
                         WHERE id = ANY($2)",
                    )
                    .bind(db_id(message.id.raw())?)
                    .bind(&attachment_db_ids)
                    .execute(&mut *transaction)
                    .await?;
                }
                sqlx::query("UPDATE channels SET last_message_id = $1 WHERE id = $2")
                    .bind(db_id(message.id.raw())?)
                    .bind(db_id(channel_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                Ok(CreatedMessage {
                    message,
                    audience,
                    created: true,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_message(
        &self,
        actor_id: UserId,
        channel_id: ChannelId,
        message_id: MessageId,
        content: String,
        mut encryption: Option<NewMessageEncryption>,
        franking_key: Option<[u8; 32]>,
        nonce: String,
    ) -> Result<UpdatedMessage, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let audience = memory_message_audience(&store, actor_id, channel_id, true)?;
                let existing = store
                    .messages
                    .get(&channel_id)
                    .and_then(|messages| messages.iter().find(|message| message.id == message_id))
                    .cloned()
                    .ok_or(RepositoryError::NotFound("message"))?;
                if existing.author_id != actor_id {
                    return Err(RepositoryError::Forbidden);
                }
                if existing.encryption.is_some() != encryption.is_some() {
                    return Err(RepositoryError::BadRequest(
                        "message encryption mode cannot be changed",
                    ));
                }
                if let Some(value) = encryption.as_mut() {
                    let identity = store
                        .device_identities
                        .get(&value.sender_device_id)
                        .ok_or(RepositoryError::NotFound("device identity"))?;
                    if identity.user_id != actor_id || identity.revoked_at.is_some() {
                        return Err(RepositoryError::Forbidden);
                    }
                    value.franking_tag = calculate_franking_tag(
                        &franking_key.ok_or(RepositoryError::InvalidData(
                            "encrypted message is missing a franking key",
                        ))?,
                        channel_id,
                        actor_id,
                        message_id,
                        existing.created_at,
                        &nonce,
                        &value.franking_commitment,
                    );
                }
                let mut message = existing;
                message.content = content;
                message.encryption = encryption
                    .as_ref()
                    .map(|value| message_encryption(value, &nonce));
                message.edited_at = Some(Utc::now());
                if let Some(messages) = store.messages.get_mut(&channel_id)
                    && let Some(candidate) = messages
                        .iter_mut()
                        .find(|candidate| candidate.id == message_id)
                {
                    *candidate = message.clone();
                }
                for candidate in store.message_nonces.values_mut() {
                    if candidate.id == message_id {
                        *candidate = message.clone();
                    }
                }
                hydrate_memory_reactions(&store, actor_id, std::slice::from_mut(&mut message));
                Ok(UpdatedMessage { message, audience })
            }
            RepositoryBackend::Postgres(pool) => {
                let audience = require_message_access(pool, actor_id, channel_id, true).await?;
                let mut transaction = pool.begin().await?;
                let row = sqlx::query(
                    "SELECT id, channel_id, author_id, COALESCE(content, '') AS content,
                            ciphertext, frank_commit, frank_tag, sender_device_id, nonce,
                            attachments, reference_id, sequence,
                            snowflake_to_timestamp(id) AS created_at, edited_at
                     FROM messages
                     WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL
                     FOR UPDATE",
                )
                .bind(db_id(message_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::NotFound("message"))?;
                let existing = message_from_row(&row)?;
                if existing.author_id != actor_id {
                    return Err(RepositoryError::Forbidden);
                }
                if existing.encryption.is_some() != encryption.is_some() {
                    return Err(RepositoryError::BadRequest(
                        "message encryption mode cannot be changed",
                    ));
                }
                if let Some(value) = encryption.as_mut() {
                    let valid_device: bool = sqlx::query_scalar(
                        "SELECT EXISTS(
                           SELECT 1 FROM device_identities
                           WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
                         )",
                    )
                    .bind(value.sender_device_id)
                    .bind(db_id(actor_id.raw())?)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if !valid_device {
                        return Err(RepositoryError::Forbidden);
                    }
                    value.franking_tag = calculate_franking_tag(
                        &franking_key.ok_or(RepositoryError::InvalidData(
                            "encrypted message is missing a franking key",
                        ))?,
                        channel_id,
                        actor_id,
                        message_id,
                        existing.created_at,
                        &nonce,
                        &value.franking_commitment,
                    );
                }
                let edited_at = Utc::now();
                sqlx::query(
                    "UPDATE messages
                     SET content = $1, ciphertext = $2, nonce = $3,
                         frank_tag = $4, frank_commit = $5,
                         sender_device_id = $6, edited_at = $7
                     WHERE id = $8 AND channel_id = $9 AND deleted_at IS NULL",
                )
                .bind(encryption.as_ref().map_or(Some(&content), |_| None))
                .bind(encryption.as_ref().map(|value| value.ciphertext.as_slice()))
                .bind(&nonce)
                .bind(
                    encryption
                        .as_ref()
                        .map(|value| value.franking_tag.as_slice()),
                )
                .bind(
                    encryption
                        .as_ref()
                        .map(|value| value.franking_commitment.as_slice()),
                )
                .bind(encryption.as_ref().map(|value| value.sender_device_id))
                .bind(edited_at)
                .bind(db_id(message_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                let mut message = existing;
                message.content = content;
                message.encryption = encryption
                    .as_ref()
                    .map(|value| message_encryption(value, &nonce));
                message.edited_at = Some(edited_at);
                hydrate_postgres_reactions(pool, actor_id, std::slice::from_mut(&mut message))
                    .await?;
                Ok(UpdatedMessage { message, audience })
            }
        }
    }

    pub async fn delete_message(
        &self,
        actor_id: UserId,
        channel_id: ChannelId,
        message_id: MessageId,
    ) -> Result<DeletedMessage, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let audience = memory_message_audience(&store, actor_id, channel_id, false)?;
                let message = store
                    .messages
                    .get(&channel_id)
                    .and_then(|messages| messages.iter().find(|message| message.id == message_id))
                    .cloned()
                    .ok_or(RepositoryError::NotFound("message"))?;
                let can_manage = store.channels.get(&channel_id).is_some_and(|channel| {
                    memory_channel_permissions(&store, actor_id, channel).is_ok_and(|permissions| {
                        permissions.contains(GuildPermissions::MANAGE_MESSAGES)
                    })
                });
                if message.author_id != actor_id && !can_manage {
                    return Err(RepositoryError::Forbidden);
                }
                if let Some(messages) = store.messages.get_mut(&channel_id) {
                    messages.retain(|message| message.id != message_id);
                }
                store
                    .reactions
                    .retain(|(candidate, _, _, _)| *candidate != message_id);
                store
                    .message_nonces
                    .retain(|_, message| message.id != message_id);
                let attachment_delete_at = Utc::now() + chrono::TimeDelta::days(7);
                for attachment in store
                    .attachments
                    .values_mut()
                    .filter(|attachment| attachment.message_id == Some(message_id))
                {
                    attachment.message_id = None;
                    attachment.expires_at = attachment_delete_at;
                }
                let last_message_id = store
                    .messages
                    .get(&channel_id)
                    .and_then(|messages| messages.iter().map(|message| message.id).max());
                if let Some(channel) = store.direct_channels.get_mut(&channel_id) {
                    channel.last_message_id = last_message_id;
                }
                Ok(DeletedMessage {
                    event: MessageDeleteEvent {
                        id: message_id,
                        channel_id,
                    },
                    audience,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let audience = require_message_access(pool, actor_id, channel_id, false).await?;
                let author_id: UserId = sqlx::query_scalar::<_, i64>(
                    "SELECT author_id FROM messages
                     WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL",
                )
                .bind(db_id(message_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .fetch_optional(pool)
                .await?
                .map(user_id_from_db)
                .transpose()?
                .ok_or(RepositoryError::NotFound("message"))?;
                let can_manage = match &audience {
                    MessageAudience::Guild(guild_id) => {
                        postgres_channel_permission_map(pool, actor_id, *guild_id, [channel_id])
                            .await?
                            .get(&channel_id)
                            .is_some_and(|permissions| {
                                permissions.contains(GuildPermissions::MANAGE_MESSAGES)
                            })
                    }
                    MessageAudience::Users(_) => false,
                };
                if author_id != actor_id && !can_manage {
                    return Err(RepositoryError::Forbidden);
                }
                let mut transaction = pool.begin().await?;
                let changed = sqlx::query(
                    "UPDATE messages SET deleted_at = now()
                     WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL",
                )
                .bind(db_id(message_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                if changed.rows_affected() != 1 {
                    return Err(RepositoryError::NotFound("message"));
                }
                sqlx::query("DELETE FROM reactions WHERE message_id = $1 AND channel_id = $2")
                    .bind(db_id(message_id.raw())?)
                    .bind(db_id(channel_id.raw())?)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(
                    "UPDATE attachment_uploads
                     SET message_id = NULL, expires_at = now() + interval '7 days'
                     WHERE message_id = $1 AND channel_id = $2",
                )
                .bind(db_id(message_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "UPDATE channels
                     SET last_message_id = (
                       SELECT MAX(id) FROM messages
                       WHERE channel_id = $1 AND deleted_at IS NULL
                     )
                     WHERE id = $1",
                )
                .bind(db_id(channel_id.raw())?)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                Ok(DeletedMessage {
                    event: MessageDeleteEvent {
                        id: message_id,
                        channel_id,
                    },
                    audience,
                })
            }
        }
    }

    pub async fn update_reaction(
        &self,
        actor_id: UserId,
        channel_id: ChannelId,
        message_id: MessageId,
        emoji: String,
        added: bool,
    ) -> Result<UpdatedReaction, RepositoryError> {
        match &self.0 {
            RepositoryBackend::Memory(store) => {
                let mut store = store.write().await;
                let audience = memory_message_audience(&store, actor_id, channel_id, added)?;
                if !store
                    .messages
                    .get(&channel_id)
                    .is_some_and(|messages| messages.iter().any(|message| message.id == message_id))
                {
                    return Err(RepositoryError::NotFound("message"));
                }
                if added
                    && let Some(channel) = store.channels.get(&channel_id)
                    && !memory_channel_permissions(&store, actor_id, channel)?
                        .contains(GuildPermissions::ADD_REACTIONS)
                {
                    return Err(RepositoryError::Forbidden);
                }
                let key = (message_id, channel_id, actor_id, emoji.clone());
                let changed = if added {
                    store.reactions.insert(key)
                } else {
                    store.reactions.remove(&key)
                };
                let count = store
                    .reactions
                    .iter()
                    .filter(
                        |(candidate_message, candidate_channel, _, candidate_emoji)| {
                            *candidate_message == message_id
                                && *candidate_channel == channel_id
                                && candidate_emoji == &emoji
                        },
                    )
                    .count();
                Ok(UpdatedReaction {
                    event: MessageReactionEvent {
                        message_id,
                        channel_id,
                        user_id: actor_id,
                        emoji,
                        count: u32::try_from(count).unwrap_or(u32::MAX),
                        added,
                    },
                    audience,
                    changed,
                })
            }
            RepositoryBackend::Postgres(pool) => {
                let audience = require_message_access(pool, actor_id, channel_id, added).await?;
                if added
                    && let MessageAudience::Guild(guild_id) = &audience
                    && !postgres_channel_permission_map(pool, actor_id, *guild_id, [channel_id])
                        .await?
                        .get(&channel_id)
                        .is_some_and(|permissions| {
                            permissions.contains(GuildPermissions::ADD_REACTIONS)
                        })
                {
                    return Err(RepositoryError::Forbidden);
                }
                let mut transaction = pool.begin().await?;
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (
                       SELECT 1 FROM messages
                       WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL
                     )",
                )
                .bind(db_id(message_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .fetch_one(&mut *transaction)
                .await?;
                if !exists {
                    return Err(RepositoryError::NotFound("message"));
                }
                let changed = if added {
                    sqlx::query(
                        "INSERT INTO reactions
                           (message_id, channel_id, user_id, emoji_name, emoji_key)
                         VALUES ($1, $2, $3, $4, $4)
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(db_id(message_id.raw())?)
                    .bind(db_id(channel_id.raw())?)
                    .bind(db_id(actor_id.raw())?)
                    .bind(&emoji)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
                        == 1
                } else {
                    sqlx::query(
                        "DELETE FROM reactions
                         WHERE message_id = $1 AND channel_id = $2
                           AND user_id = $3 AND emoji_key = $4",
                    )
                    .bind(db_id(message_id.raw())?)
                    .bind(db_id(channel_id.raw())?)
                    .bind(db_id(actor_id.raw())?)
                    .bind(&emoji)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
                        == 1
                };
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM reactions
                     WHERE message_id = $1 AND channel_id = $2 AND emoji_key = $3",
                )
                .bind(db_id(message_id.raw())?)
                .bind(db_id(channel_id.raw())?)
                .bind(&emoji)
                .fetch_one(&mut *transaction)
                .await?;
                transaction.commit().await?;
                Ok(UpdatedReaction {
                    event: MessageReactionEvent {
                        message_id,
                        channel_id,
                        user_id: actor_id,
                        emoji,
                        count: u32::try_from(count).map_err(|_| {
                            RepositoryError::InvalidData("reaction count is invalid")
                        })?,
                        added,
                    },
                    audience,
                    changed,
                })
            }
        }
    }

    #[cfg(test)]
    pub async fn first_text_channel(&self) -> Option<ChannelId> {
        match &self.0 {
            RepositoryBackend::Memory(store) => store
                .read()
                .await
                .channels
                .values()
                .find(|channel| channel.kind == ChannelKind::Text)
                .map(|channel| channel.id),
            RepositoryBackend::Postgres(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
struct ActorRoleContext {
    is_owner: bool,
    permissions: GuildPermissions,
    highest_position: i32,
}

#[derive(Clone, Copy)]
struct TargetMemberContext {
    owner_id: UserId,
    highest_position: i32,
}

struct PermissionInputs {
    guild_id: GuildId,
    owner_id: UserId,
    user_id: UserId,
    everyone_role_id: RoleId,
    everyone: GuildPermissions,
    roles: Vec<RoleGrant>,
    timed_out: bool,
}

impl PermissionInputs {
    fn resolve(&self, overrides: &[ChannelOverride]) -> GuildPermissions {
        PermissionResolver::resolve(&PermissionContext {
            guild_id: self.guild_id,
            guild_owner_id: self.owner_id,
            user_id: self.user_id,
            everyone_role_id: self.everyone_role_id,
            everyone: self.everyone,
            roles: &self.roles,
            overrides,
            timed_out: self.timed_out,
        })
    }

    fn highest_position(&self, store: &MemoryStore) -> i32 {
        self.roles
            .iter()
            .filter_map(|grant| store.roles.get(&grant.role_id))
            .map(|role| role.position)
            .max()
            .unwrap_or(0)
    }
}

fn memory_permission_inputs(
    store: &MemoryStore,
    user_id: UserId,
    guild_id: GuildId,
) -> Result<PermissionInputs, RepositoryError> {
    if store.deleted_guilds.contains(&guild_id) {
        return Err(RepositoryError::NotFound("server"));
    }
    let guild = store
        .guilds
        .get(&guild_id)
        .ok_or(RepositoryError::NotFound("server"))?;
    if !store.memberships.contains(&(guild_id, user_id)) {
        return Err(RepositoryError::NotFound("server"));
    }
    let everyone_role_id = RoleId::from_raw(guild_id.raw())
        .map_err(|_| RepositoryError::InvalidData("default role id is invalid"))?;
    let everyone = store
        .roles
        .get(&everyone_role_id)
        .map_or(GuildPermissions::empty(), |role| role.permissions);
    let roles = store
        .member_roles
        .iter()
        .filter_map(|(role_guild, member_id, role_id)| {
            (*role_guild == guild_id && *member_id == user_id)
                .then(|| store.roles.get(role_id))
                .flatten()
                .map(|role| RoleGrant {
                    role_id: role.id,
                    permissions: role.permissions,
                })
        })
        .collect();
    Ok(PermissionInputs {
        guild_id,
        owner_id: guild.owner_id,
        user_id,
        everyone_role_id,
        everyone,
        roles,
        timed_out: store
            .timeouts
            .get(&(guild_id, user_id))
            .is_some_and(|timeout| *timeout > Utc::now()),
    })
}

fn memory_channel_overrides(store: &MemoryStore, channel_id: ChannelId) -> Vec<ChannelOverride> {
    store
        .channel_overwrites
        .iter()
        .filter(|((candidate, _, _), _)| *candidate == channel_id)
        .filter_map(|(_, overwrite)| memory_channel_override(overwrite))
        .collect()
}

fn memory_channel_override(overwrite: &MemoryOverwrite) -> Option<ChannelOverride> {
    match overwrite.target_kind {
        OverwriteTargetKind::Role => Some(ChannelOverride {
            role_id: RoleId::from_raw(overwrite.target_id).ok(),
            user_id: None,
            allow: overwrite.allow,
            deny: overwrite.deny,
        }),
        OverwriteTargetKind::Member => Some(ChannelOverride {
            role_id: None,
            user_id: UserId::from_raw(overwrite.target_id).ok(),
            allow: overwrite.allow,
            deny: overwrite.deny,
        }),
    }
}

fn memory_channel_permissions(
    store: &MemoryStore,
    user_id: UserId,
    channel: &Channel,
) -> Result<GuildPermissions, RepositoryError> {
    let inputs = memory_permission_inputs(store, user_id, channel.guild_id)
        .map_err(hide_server_as_channel)?;
    Ok(inputs.resolve(&memory_channel_overrides(store, channel.id)))
}

fn memory_message_audience(
    store: &MemoryStore,
    user_id: UserId,
    channel_id: ChannelId,
    send: bool,
) -> Result<MessageAudience, RepositoryError> {
    if let Some(channel) = store.channels.get(&channel_id) {
        let permissions = memory_channel_permissions(store, user_id, channel)?;
        let required = if send {
            GuildPermissions::VIEW_CHANNEL | GuildPermissions::SEND_MESSAGES
        } else {
            GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY
        };
        if !permissions.contains(required) {
            return Err(RepositoryError::NotFound("channel"));
        }
        if channel.kind != ChannelKind::Text {
            return Err(RepositoryError::BadRequest(
                "messages require a text channel",
            ));
        }
        return Ok(MessageAudience::Guild(channel.guild_id));
    }
    let channel = store
        .direct_channels
        .get(&channel_id)
        .ok_or(RepositoryError::NotFound("channel"))?;
    if !channel.recipients.contains(&user_id) {
        return Err(RepositoryError::NotFound("channel"));
    }
    if send {
        let target_id = channel
            .recipients
            .iter()
            .copied()
            .find(|recipient| *recipient != user_id)
            .ok_or(RepositoryError::InvalidData(
                "direct channel has no other recipient",
            ))?;
        if !store
            .relationships
            .get(&(user_id, target_id))
            .is_some_and(|relationship| relationship.kind == RelationshipKind::Friend)
            || store
                .relationships
                .get(&(target_id, user_id))
                .is_some_and(|relationship| relationship.kind == RelationshipKind::Blocked)
        {
            return Err(RepositoryError::Forbidden);
        }
    }
    Ok(MessageAudience::Users(channel.recipients.to_vec()))
}

fn memory_mls_channel_users(
    store: &MemoryStore,
    user_id: UserId,
    channel_id: ChannelId,
) -> Result<Vec<UserId>, RepositoryError> {
    if let Some(channel) = store.channels.get(&channel_id) {
        if !channel.encrypted {
            return Err(RepositoryError::BadRequest(
                "MLS bootstrap requires an encrypted channel",
            ));
        }
        let (requester_required, recipient_required) = match channel.kind {
            ChannelKind::Text => (
                GuildPermissions::VIEW_CHANNEL
                    | GuildPermissions::READ_MESSAGE_HISTORY
                    | GuildPermissions::SEND_MESSAGES,
                GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY,
            ),
            ChannelKind::Voice => {
                let required = GuildPermissions::VIEW_CHANNEL | GuildPermissions::CONNECT;
                (required, required)
            }
        };
        if !memory_channel_permissions(store, user_id, channel)?.contains(requester_required) {
            return Err(RepositoryError::NotFound("channel"));
        }
        let mut users = store
            .memberships
            .iter()
            .filter_map(|(guild_id, member_id)| {
                (*guild_id == channel.guild_id
                    && memory_channel_permissions(store, *member_id, channel)
                        .is_ok_and(|permissions| permissions.contains(recipient_required)))
                .then_some(*member_id)
            })
            .collect::<Vec<_>>();
        users.sort_unstable();
        return Ok(users);
    }
    match memory_message_audience(store, user_id, channel_id, true)? {
        MessageAudience::Users(users) => Ok(users),
        MessageAudience::Guild(_) => Err(RepositoryError::InvalidData(
            "direct MLS channel resolved to a guild",
        )),
    }
}

async fn postgres_permission_inputs(
    pool: &PgPool,
    user_id: UserId,
    guild_id: GuildId,
) -> Result<PermissionInputs, RepositoryError> {
    let rows = sqlx::query(
        "SELECT g.owner_id, gm.timeout_until,
                everyone.permissions AS everyone_permissions,
                assigned.id AS assigned_role_id,
                assigned.permissions AS assigned_permissions
         FROM guilds g
         JOIN guild_members gm ON gm.guild_id = g.id AND gm.user_id = $2
         JOIN roles everyone ON everyone.guild_id = g.id AND everyone.id = g.id
         LEFT JOIN member_roles mr
           ON mr.guild_id = gm.guild_id AND mr.user_id = gm.user_id
         LEFT JOIN roles assigned ON assigned.id = mr.role_id
         WHERE g.id = $1 AND g.deleted_at IS NULL
         ORDER BY assigned.position, assigned.id",
    )
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(user_id.raw())?)
    .fetch_all(pool)
    .await?;
    let first = rows.first().ok_or(RepositoryError::NotFound("server"))?;
    let owner_id = user_id_from_db(first.try_get("owner_id")?)?;
    let everyone_role_id = RoleId::from_raw(guild_id.raw())
        .map_err(|_| RepositoryError::InvalidData("default role id is invalid"))?;
    let mut roles = Vec::new();
    for row in &rows {
        let Some(role_id) = row.try_get::<Option<i64>, _>("assigned_role_id")? else {
            continue;
        };
        let permissions = row
            .try_get::<Option<i64>, _>("assigned_permissions")?
            .ok_or(RepositoryError::InvalidData(
                "assigned role permissions are missing",
            ))?;
        roles.push(RoleGrant {
            role_id: role_id_from_db(role_id)?,
            permissions: permissions_from_db(permissions)?,
        });
    }
    let timeout_until: Option<chrono::DateTime<Utc>> = first.try_get("timeout_until")?;
    Ok(PermissionInputs {
        guild_id,
        owner_id,
        user_id,
        everyone_role_id,
        everyone: permissions_from_db(first.try_get("everyone_permissions")?)?,
        roles,
        timed_out: timeout_until.is_some_and(|timeout| timeout > Utc::now()),
    })
}

async fn postgres_channel_overrides(
    pool: &PgPool,
    guild_id: GuildId,
) -> Result<HashMap<ChannelId, Vec<ChannelOverride>>, RepositoryError> {
    let rows = sqlx::query(
        "SELECT o.channel_id, o.target_id, o.target_type, o.allow_bits, o.deny_bits
         FROM channel_overwrites o
         JOIN channels c ON c.id = o.channel_id
         WHERE c.guild_id = $1 AND c.deleted_at IS NULL",
    )
    .bind(db_id(guild_id.raw())?)
    .fetch_all(pool)
    .await?;
    let mut grouped = HashMap::<ChannelId, Vec<ChannelOverride>>::new();
    for row in rows {
        let channel_id = channel_id_from_db(row.try_get("channel_id")?)?;
        let target_id: i64 = row.try_get("target_id")?;
        let target_type: i16 = row.try_get("target_type")?;
        let allow = permissions_from_db(row.try_get("allow_bits")?)?;
        let deny = permissions_from_db(row.try_get("deny_bits")?)?;
        let overwrite = match target_type {
            0 => ChannelOverride {
                role_id: Some(role_id_from_db(target_id)?),
                user_id: None,
                allow,
                deny,
            },
            1 => ChannelOverride {
                role_id: None,
                user_id: Some(user_id_from_db(target_id)?),
                allow,
                deny,
            },
            _ => {
                return Err(RepositoryError::InvalidData(
                    "unknown overwrite target type",
                ));
            }
        };
        grouped.entry(channel_id).or_default().push(overwrite);
    }
    Ok(grouped)
}

async fn postgres_channel_permission_map(
    pool: &PgPool,
    user_id: UserId,
    guild_id: GuildId,
    channel_ids: impl IntoIterator<Item = ChannelId>,
) -> Result<HashMap<ChannelId, GuildPermissions>, RepositoryError> {
    let inputs = postgres_permission_inputs(pool, user_id, guild_id).await?;
    let overrides = postgres_channel_overrides(pool, guild_id).await?;
    Ok(channel_ids
        .into_iter()
        .map(|channel_id| {
            let rules = overrides.get(&channel_id).map_or(&[][..], Vec::as_slice);
            (channel_id, inputs.resolve(rules))
        })
        .collect())
}

fn hide_server_as_channel(error: RepositoryError) -> RepositoryError {
    match error {
        RepositoryError::NotFound(_) => RepositoryError::NotFound("channel"),
        other => other,
    }
}

fn memory_actor_context(
    store: &MemoryStore,
    user_id: UserId,
    guild_id: GuildId,
) -> Result<ActorRoleContext, RepositoryError> {
    let inputs = memory_permission_inputs(store, user_id, guild_id)?;
    if inputs.owner_id == user_id {
        return Ok(ActorRoleContext {
            is_owner: true,
            permissions: GuildPermissions::ALL,
            highest_position: i32::MAX,
        });
    }
    Ok(ActorRoleContext {
        is_owner: false,
        permissions: inputs.resolve(&[]),
        highest_position: inputs.highest_position(store),
    })
}

fn memory_highest_role_position(store: &MemoryStore, guild_id: GuildId, user_id: UserId) -> i32 {
    store
        .member_roles
        .iter()
        .filter_map(|(role_guild, member_id, role_id)| {
            (*role_guild == guild_id && *member_id == user_id)
                .then(|| store.roles.get(role_id).map(|role| role.position))
                .flatten()
        })
        .max()
        .unwrap_or(0)
}

fn memory_target_member_context(
    store: &MemoryStore,
    guild_id: GuildId,
    member_id: UserId,
) -> Result<Option<TargetMemberContext>, RepositoryError> {
    let guild = store
        .guilds
        .get(&guild_id)
        .ok_or(RepositoryError::NotFound("server"))?;
    Ok(store
        .memberships
        .contains(&(guild_id, member_id))
        .then(|| TargetMemberContext {
            owner_id: guild.owner_id,
            highest_position: memory_highest_role_position(store, guild_id, member_id),
        }))
}

fn remove_memory_membership(store: &mut MemoryStore, guild_id: GuildId, member_id: UserId) {
    store.memberships.remove(&(guild_id, member_id));
    store
        .member_roles
        .retain(|(candidate, user_id, _)| *candidate != guild_id || *user_id != member_id);
    store.timeouts.remove(&(guild_id, member_id));
    let guild_channels = store
        .channels
        .values()
        .filter(|channel| channel.guild_id == guild_id)
        .map(|channel| channel.id)
        .collect::<HashSet<_>>();
    store
        .channel_overwrites
        .retain(|(channel_id, target_kind, target_id), _| {
            !guild_channels.contains(channel_id)
                || *target_kind != OverwriteTargetKind::Member
                || *target_id != member_id.raw()
        });
}

async fn postgres_actor_context(
    pool: &PgPool,
    user_id: UserId,
    guild_id: GuildId,
) -> Result<ActorRoleContext, RepositoryError> {
    let row = sqlx::query(
        "SELECT g.owner_id, gm.timeout_until,
                everyone.permissions AS everyone_permissions,
                COALESCE(bit_or(assigned.permissions), 0)::bigint AS assigned_permissions,
                COALESCE(MAX(assigned.position), 0)::integer AS highest_position
         FROM guilds g
         JOIN guild_members gm ON gm.guild_id = g.id AND gm.user_id = $2
         JOIN roles everyone ON everyone.guild_id = g.id AND everyone.id = g.id
         LEFT JOIN member_roles mr
           ON mr.guild_id = gm.guild_id AND mr.user_id = gm.user_id
         LEFT JOIN roles assigned ON assigned.id = mr.role_id
         WHERE g.id = $1 AND g.deleted_at IS NULL
         GROUP BY g.owner_id, gm.timeout_until, everyone.permissions",
    )
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(user_id.raw())?)
    .fetch_optional(pool)
    .await?
    .ok_or(RepositoryError::NotFound("server"))?;
    actor_context_from_row(&row, user_id)
}

async fn postgres_actor_context_for_update(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    guild_id: GuildId,
) -> Result<ActorRoleContext, RepositoryError> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT g.id
         FROM guilds g
         JOIN guild_members gm ON gm.guild_id = g.id AND gm.user_id = $2
         WHERE g.id = $1 AND g.deleted_at IS NULL
         FOR UPDATE OF g",
    )
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(user_id.raw())?)
    .fetch_optional(&mut **transaction)
    .await?;
    if exists.is_none() {
        return Err(RepositoryError::NotFound("server"));
    }
    let row = sqlx::query(
        "SELECT g.owner_id, gm.timeout_until,
                everyone.permissions AS everyone_permissions,
                COALESCE(bit_or(assigned.permissions), 0)::bigint AS assigned_permissions,
                COALESCE(MAX(assigned.position), 0)::integer AS highest_position
         FROM guilds g
         JOIN guild_members gm ON gm.guild_id = g.id AND gm.user_id = $2
         JOIN roles everyone ON everyone.guild_id = g.id AND everyone.id = g.id
         LEFT JOIN member_roles mr
           ON mr.guild_id = gm.guild_id AND mr.user_id = gm.user_id
         LEFT JOIN roles assigned ON assigned.id = mr.role_id
         WHERE g.id = $1
         GROUP BY g.owner_id, gm.timeout_until, everyone.permissions",
    )
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(user_id.raw())?)
    .fetch_one(&mut **transaction)
    .await?;
    actor_context_from_row(&row, user_id)
}

fn actor_context_from_row(
    row: &PgRow,
    user_id: UserId,
) -> Result<ActorRoleContext, RepositoryError> {
    let owner_id = user_id_from_db(row.try_get("owner_id")?)?;
    if owner_id == user_id {
        return Ok(ActorRoleContext {
            is_owner: true,
            permissions: GuildPermissions::ALL,
            highest_position: i32::MAX,
        });
    }
    let everyone: i64 = row.try_get("everyone_permissions")?;
    let assigned: i64 = row.try_get("assigned_permissions")?;
    let mut permissions = permissions_from_db(everyone | assigned)?;
    if permissions.contains(GuildPermissions::ADMINISTRATOR) {
        permissions = GuildPermissions::ALL_GUILD;
    }
    let timeout_until: Option<chrono::DateTime<Utc>> = row.try_get("timeout_until")?;
    if timeout_until.is_some_and(|timeout| timeout > Utc::now()) {
        permissions &= GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY;
    }
    Ok(ActorRoleContext {
        is_owner: false,
        permissions,
        highest_position: row.try_get("highest_position")?,
    })
}

fn require_manageable_permissions(
    actor: ActorRoleContext,
    requested: GuildPermissions,
) -> Result<(), RepositoryError> {
    if actor.is_owner {
        return Ok(());
    }
    if !actor.permissions.contains(GuildPermissions::MANAGE_ROLES)
        || requested.bits() & !actor.permissions.bits() != 0
    {
        return Err(RepositoryError::Forbidden);
    }
    Ok(())
}

fn delegated_role_position(highest_position: i32) -> Result<i32, RepositoryError> {
    if highest_position <= 0 {
        return Err(RepositoryError::BadRequest(
            "no manageable role position is available",
        ));
    }
    Ok(highest_position
        .checked_sub(1)
        .ok_or(RepositoryError::InvalidData("role position overflow"))?
        .max(1))
}

fn require_manageable_role(actor: ActorRoleContext, role: &Role) -> Result<(), RepositoryError> {
    if role.managed {
        return Err(RepositoryError::BadRequest(
            "managed roles cannot be changed manually",
        ));
    }
    if actor.is_owner {
        return Ok(());
    }
    if !actor.permissions.contains(GuildPermissions::MANAGE_ROLES)
        || role.position >= actor.highest_position
    {
        return Err(RepositoryError::Forbidden);
    }
    Ok(())
}

fn require_moderation_permission(
    actor: ActorRoleContext,
    permission: GuildPermissions,
) -> Result<(), RepositoryError> {
    if !actor.permissions.contains(permission) {
        return Err(RepositoryError::Forbidden);
    }
    Ok(())
}

fn require_automod_manager(actor: ActorRoleContext) -> Result<(), RepositoryError> {
    if !actor.permissions.contains(GuildPermissions::MANAGE_GUILD) {
        return Err(RepositoryError::Forbidden);
    }
    Ok(())
}

fn require_audit_viewer(actor: ActorRoleContext) -> Result<(), RepositoryError> {
    if !actor.permissions.contains(GuildPermissions::VIEW_AUDIT_LOG) {
        return Err(RepositoryError::Forbidden);
    }
    Ok(())
}

fn require_moderatable_target(
    actor: ActorRoleContext,
    actor_id: UserId,
    member_id: UserId,
    target: TargetMemberContext,
) -> Result<(), RepositoryError> {
    if member_id == actor_id
        || member_id == target.owner_id
        || (!actor.is_owner && target.highest_position >= actor.highest_position)
    {
        return Err(RepositoryError::Forbidden);
    }
    Ok(())
}

async fn postgres_target_member_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    guild_id: GuildId,
    member_id: UserId,
) -> Result<Option<TargetMemberContext>, RepositoryError> {
    let member = sqlx::query_scalar::<_, i64>(
        "SELECT user_id FROM guild_members
         WHERE guild_id = $1 AND user_id = $2
         FOR UPDATE",
    )
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(member_id.raw())?)
    .fetch_optional(&mut **transaction)
    .await?;
    if member.is_none() {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT g.owner_id,
                COALESCE(MAX(r.position), 0)::integer AS highest_position
         FROM guilds g
         LEFT JOIN member_roles mr
           ON mr.guild_id = g.id AND mr.user_id = $2
         LEFT JOIN roles r ON r.id = mr.role_id
         WHERE g.id = $1 AND g.deleted_at IS NULL
         GROUP BY g.owner_id",
    )
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(member_id.raw())?)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(RepositoryError::NotFound("server"))?;
    Ok(Some(TargetMemberContext {
        owner_id: user_id_from_db(row.try_get("owner_id")?)?,
        highest_position: row.try_get("highest_position")?,
    }))
}

fn require_channel_manager(actor: ActorRoleContext) -> Result<(), RepositoryError> {
    if !actor
        .permissions
        .contains(GuildPermissions::MANAGE_CHANNELS)
    {
        return Err(RepositoryError::Forbidden);
    }
    Ok(())
}

fn require_overwrite_grant(
    actor: ActorRoleContext,
    allow: GuildPermissions,
) -> Result<(), RepositoryError> {
    if !actor.is_owner && allow.bits() & !actor.permissions.bits() != 0 {
        return Err(RepositoryError::Forbidden);
    }
    Ok(())
}

fn validate_memory_overwrite_target(
    store: &MemoryStore,
    guild_id: GuildId,
    target_kind: OverwriteTargetKind,
    target_id: u64,
) -> Result<(), RepositoryError> {
    let valid = match target_kind {
        OverwriteTargetKind::Role => RoleId::from_raw(target_id)
            .ok()
            .and_then(|role_id| store.roles.get(&role_id))
            .is_some_and(|role| role.guild_id == guild_id),
        OverwriteTargetKind::Member => UserId::from_raw(target_id)
            .ok()
            .is_some_and(|user_id| store.memberships.contains(&(guild_id, user_id))),
    };
    if !valid {
        return Err(RepositoryError::NotFound(match target_kind {
            OverwriteTargetKind::Role => "role",
            OverwriteTargetKind::Member => "member",
        }));
    }
    Ok(())
}

async fn validate_postgres_overwrite_target(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    guild_id: GuildId,
    target_kind: OverwriteTargetKind,
    target_id: u64,
) -> Result<(), RepositoryError> {
    let valid: bool = match target_kind {
        OverwriteTargetKind::Role => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                   SELECT 1 FROM roles WHERE id = $1 AND guild_id = $2
                 )",
            )
            .bind(db_id(target_id)?)
            .bind(db_id(guild_id.raw())?)
            .fetch_one(&mut **transaction)
            .await?
        }
        OverwriteTargetKind::Member => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                   SELECT 1 FROM guild_members WHERE guild_id = $1 AND user_id = $2
                 )",
            )
            .bind(db_id(guild_id.raw())?)
            .bind(db_id(target_id)?)
            .fetch_one(&mut **transaction)
            .await?
        }
    };
    if !valid {
        return Err(RepositoryError::NotFound(match target_kind {
            OverwriteTargetKind::Role => "role",
            OverwriteTargetKind::Member => "member",
        }));
    }
    Ok(())
}

async fn postgres_channel_guild(
    pool: &PgPool,
    channel_id: ChannelId,
) -> Result<GuildId, RepositoryError> {
    let guild_id: i64 = sqlx::query_scalar(
        "SELECT c.guild_id
         FROM channels c
         JOIN guilds g ON g.id = c.guild_id
         WHERE c.id = $1 AND c.deleted_at IS NULL AND g.deleted_at IS NULL",
    )
    .bind(db_id(channel_id.raw())?)
    .fetch_optional(pool)
    .await?
    .ok_or(RepositoryError::NotFound("channel"))?;
    guild_id_from_db(guild_id)
}

async fn postgres_guilds(pool: &PgPool, user_id: UserId) -> Result<Vec<Guild>, RepositoryError> {
    let rows = sqlx::query(
        "SELECT g.id, g.owner_id, g.name, g.accent, g.created_at
         FROM guilds g
         JOIN guild_members gm ON gm.guild_id = g.id
         WHERE gm.user_id = $1 AND g.deleted_at IS NULL
         ORDER BY g.created_at, g.id",
    )
    .bind(db_id(user_id.raw())?)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(guild_from_row)
        .collect::<Result<Vec<_>, _>>()
}

async fn insert_channel(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    channel: &Channel,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO channels
           (id, guild_id, type, name, position, e2ee, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(db_id(channel.id.raw())?)
    .bind(db_id(channel.guild_id.raw())?)
    .bind(channel_kind_to_db(channel.kind))
    .bind(&channel.name)
    .bind(channel.position)
    .bind(channel.encrypted)
    .bind(channel.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_audit_entry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    guild_id: GuildId,
    actor_id: UserId,
    target_id: u64,
    action_type: i16,
    changes: serde_json::Value,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO audit_log
           (id, guild_id, actor_id, target_id, action_type, changes)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)",
    )
    .bind(db_id(AuditLogId::new().raw())?)
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(actor_id.raw())?)
    .bind(db_id(target_id)?)
    .bind(action_type)
    .bind(changes.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_system_audit_entry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    guild_id: GuildId,
    target_id: UserId,
    action_type: i16,
    changes: serde_json::Value,
    reason: &str,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO audit_log
           (id, guild_id, actor_id, target_id, action_type, changes, reason)
         VALUES ($1, $2, NULL, $3, $4, $5::jsonb, $6)",
    )
    .bind(db_id(AuditLogId::new().raw())?)
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(target_id.raw())?)
    .bind(action_type)
    .bind(changes.to_string())
    .bind(reason)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_moderation_audit_entry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    guild_id: GuildId,
    actor_id: UserId,
    target_id: UserId,
    action_type: i16,
    changes: serde_json::Value,
    reason: Option<&str>,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO audit_log
           (id, guild_id, actor_id, target_id, action_type, changes, reason)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)",
    )
    .bind(db_id(AuditLogId::new().raw())?)
    .bind(db_id(guild_id.raw())?)
    .bind(db_id(actor_id.raw())?)
    .bind(db_id(target_id.raw())?)
    .bind(action_type)
    .bind(changes.to_string())
    .bind(reason)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_memory_audit_entry(
    store: &mut MemoryStore,
    guild_id: GuildId,
    actor_id: Option<UserId>,
    target_id: Option<u64>,
    action_type: i16,
    changes: serde_json::Value,
    reason: Option<String>,
) {
    store.audit_entries.push(AuditLogEntry {
        id: AuditLogId::new(),
        guild_id,
        actor_id,
        target_id: target_id.map(|value| value.to_string()),
        action_type,
        changes,
        reason,
        mfa_verified: false,
        created_at: Utc::now(),
    });
}

async fn require_message_access(
    pool: &PgPool,
    user_id: UserId,
    channel_id: ChannelId,
    send: bool,
) -> Result<MessageAudience, RepositoryError> {
    let channel_row = sqlx::query(
        "SELECT guild_id, type
         FROM channels
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(db_id(channel_id.raw())?)
    .fetch_optional(pool)
    .await?
    .ok_or(RepositoryError::NotFound("channel"))?;
    let channel_type: i16 = channel_row.try_get("type")?;
    let guild_id: Option<i64> = channel_row.try_get("guild_id")?;
    if guild_id.is_none() && channel_type == 1 {
        let rows = sqlx::query(
            "SELECT user_id
             FROM channel_recipients
             WHERE channel_id = $1
             ORDER BY user_id",
        )
        .bind(db_id(channel_id.raw())?)
        .fetch_all(pool)
        .await?;
        let recipients = rows
            .iter()
            .map(|row| user_id_from_db(row.try_get("user_id")?))
            .collect::<Result<Vec<_>, _>>()?;
        if !recipients.contains(&user_id) || recipients.len() != 2 {
            return Err(RepositoryError::NotFound("channel"));
        }
        if send {
            let target_id = recipients
                .iter()
                .copied()
                .find(|recipient| *recipient != user_id)
                .ok_or(RepositoryError::InvalidData(
                    "direct channel has no other recipient",
                ))?;
            let allowed: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                   SELECT 1 FROM user_relationships mine
                   JOIN user_relationships theirs
                     ON theirs.user_id = mine.target_id
                    AND theirs.target_id = mine.user_id
                   WHERE mine.user_id = $1
                     AND mine.target_id = $2
                     AND mine.state = 2
                     AND theirs.state = 2
                 )",
            )
            .bind(db_id(user_id.raw())?)
            .bind(db_id(target_id.raw())?)
            .fetch_one(pool)
            .await?;
            if !allowed {
                return Err(RepositoryError::Forbidden);
            }
        }
        return Ok(MessageAudience::Users(recipients));
    }
    let guild_id = guild_id
        .map(guild_id_from_db)
        .transpose()?
        .ok_or(RepositoryError::NotFound("channel"))?;
    let required = if send {
        GuildPermissions::VIEW_CHANNEL | GuildPermissions::SEND_MESSAGES
    } else {
        GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY
    };
    let permissions =
        postgres_channel_permission_map(pool, user_id, guild_id, [channel_id]).await?;
    if !permissions
        .get(&channel_id)
        .is_some_and(|permissions| permissions.contains(required))
    {
        return Err(RepositoryError::NotFound("channel"));
    }
    if channel_type != channel_kind_to_db(ChannelKind::Text) {
        return Err(RepositoryError::BadRequest(
            "messages require a text channel",
        ));
    }
    Ok(MessageAudience::Guild(guild_id))
}

async fn postgres_mls_channel_users(
    pool: &PgPool,
    user_id: UserId,
    channel_id: ChannelId,
) -> Result<Vec<UserId>, RepositoryError> {
    let row = sqlx::query(
        "SELECT guild_id, type, e2ee
         FROM channels
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(db_id(channel_id.raw())?)
    .fetch_optional(pool)
    .await?
    .ok_or(RepositoryError::NotFound("channel"))?;
    let channel_type: i16 = row.try_get("type")?;
    let guild_id: Option<i64> = row.try_get("guild_id")?;
    if guild_id.is_none() && channel_type == 1 {
        return match require_message_access(pool, user_id, channel_id, true).await? {
            MessageAudience::Users(users) => Ok(users),
            MessageAudience::Guild(_) => Err(RepositoryError::InvalidData(
                "direct MLS channel resolved to a guild",
            )),
        };
    }
    if !row.try_get::<bool, _>("e2ee")? {
        return Err(RepositoryError::BadRequest(
            "MLS bootstrap requires an encrypted channel",
        ));
    }
    let guild_id = guild_id
        .map(guild_id_from_db)
        .transpose()?
        .ok_or(RepositoryError::NotFound("channel"))?;
    let kind = channel_kind_from_db(channel_type)?;
    let (requester_required, recipient_required) = match kind {
        ChannelKind::Text => (
            GuildPermissions::VIEW_CHANNEL
                | GuildPermissions::READ_MESSAGE_HISTORY
                | GuildPermissions::SEND_MESSAGES,
            GuildPermissions::VIEW_CHANNEL | GuildPermissions::READ_MESSAGE_HISTORY,
        ),
        ChannelKind::Voice => {
            let required = GuildPermissions::VIEW_CHANNEL | GuildPermissions::CONNECT;
            (required, required)
        }
    };
    let requester = postgres_channel_permission_map(pool, user_id, guild_id, [channel_id]).await?;
    if !requester
        .get(&channel_id)
        .is_some_and(|permissions| permissions.contains(requester_required))
    {
        return Err(RepositoryError::NotFound("channel"));
    }
    let rows =
        sqlx::query("SELECT user_id FROM guild_members WHERE guild_id = $1 ORDER BY user_id")
            .bind(db_id(guild_id.raw())?)
            .fetch_all(pool)
            .await?;
    let mut users = Vec::with_capacity(rows.len());
    for row in rows {
        let member = user_id_from_db(row.try_get("user_id")?)?;
        let permissions =
            postgres_channel_permission_map(pool, member, guild_id, [channel_id]).await?;
        if permissions
            .get(&channel_id)
            .is_some_and(|permissions| permissions.contains(recipient_required))
        {
            users.push(member);
        }
    }
    Ok(users)
}

fn default_channels(guild_id: GuildId) -> Vec<Channel> {
    vec![
        Channel {
            id: ChannelId::new(),
            guild_id,
            name: "general".into(),
            kind: ChannelKind::Text,
            position: 0,
            encrypted: false,
            created_at: Utc::now(),
        },
        Channel {
            id: ChannelId::new(),
            guild_id,
            name: "Lounge".into(),
            kind: ChannelKind::Voice,
            position: 1,
            encrypted: true,
            created_at: Utc::now(),
        },
    ]
}

fn invite_is_available(invite: &MemoryInvite) -> bool {
    invite
        .expires_at
        .is_none_or(|expires_at| expires_at > Utc::now())
        && invite.max_uses.is_none_or(|maximum| invite.uses < maximum)
}

fn apply_memory_window(messages: &mut Vec<Message>, window: MessageWindow) {
    messages.sort_by_key(|message| std::cmp::Reverse(message.id.raw()));
    if let Some(before) = window.before {
        messages.retain(|message| message.id.raw() < before);
    } else if let Some(after) = window.after {
        messages.retain(|message| message.id.raw() > after);
        messages.reverse();
    } else if let Some(around) = window.around {
        let half = window.limit / 2;
        let pivot = messages
            .iter()
            .position(|message| message.id.raw() <= around)
            .unwrap_or(messages.len());
        let start = pivot.saturating_sub(half);
        let end = (start + window.limit).min(messages.len());
        *messages = messages[start..end].to_vec();
    }
    messages.truncate(window.limit);
}

fn hydrate_memory_reactions(store: &MemoryStore, user_id: UserId, messages: &mut [Message]) {
    for message in messages {
        let mut grouped = HashMap::<String, (u32, bool)>::new();
        for (message_id, channel_id, reactor_id, emoji) in &store.reactions {
            if *message_id != message.id || *channel_id != message.channel_id {
                continue;
            }
            let entry = grouped.entry(emoji.clone()).or_default();
            entry.0 = entry.0.saturating_add(1);
            entry.1 |= *reactor_id == user_id;
        }
        message.reactions = grouped
            .into_iter()
            .map(|(emoji, (count, me))| MessageReaction { emoji, count, me })
            .collect();
        message
            .reactions
            .sort_by(|left, right| left.emoji.cmp(&right.emoji));
    }
}

async fn hydrate_postgres_reactions(
    pool: &PgPool,
    user_id: UserId,
    messages: &mut [Message],
) -> Result<(), RepositoryError> {
    if messages.is_empty() {
        return Ok(());
    }
    let message_ids = messages
        .iter()
        .map(|message| db_id(message.id.raw()))
        .collect::<Result<Vec<_>, _>>()?;
    let rows = sqlx::query(
        "SELECT message_id, channel_id, emoji_key,
                COUNT(*)::bigint AS reaction_count,
                BOOL_OR(user_id = $2) AS reacted_by_me
         FROM reactions
         WHERE message_id = ANY($1)
         GROUP BY message_id, channel_id, emoji_key
         ORDER BY message_id, emoji_key",
    )
    .bind(&message_ids)
    .bind(db_id(user_id.raw())?)
    .fetch_all(pool)
    .await?;
    let mut grouped = HashMap::<(MessageId, ChannelId), Vec<MessageReaction>>::new();
    for row in rows {
        let count: i64 = row.try_get("reaction_count")?;
        grouped
            .entry((
                message_id_from_db(row.try_get("message_id")?)?,
                channel_id_from_db(row.try_get("channel_id")?)?,
            ))
            .or_default()
            .push(MessageReaction {
                emoji: row.try_get("emoji_key")?,
                count: u32::try_from(count)
                    .map_err(|_| RepositoryError::InvalidData("reaction count is invalid"))?,
                me: row.try_get("reacted_by_me")?,
            });
    }
    for message in messages {
        message.reactions = grouped
            .remove(&(message.id, message.channel_id))
            .unwrap_or_default();
    }
    Ok(())
}

fn user_from_row(row: &PgRow) -> Result<User, RepositoryError> {
    let id = user_id_from_db(row.try_get("id")?)?;
    let avatar_hash = row.try_get::<Option<String>, _>("avatar_hash")?;
    let handle: String = row.try_get("username")?;
    Ok(User {
        id,
        handle: handle.clone(),
        display_name: row
            .try_get::<Option<String>, _>("display_name")?
            .unwrap_or(handle),
        avatar_url: avatar_hash.map(|hash| format!("/v1/users/{id}/avatar/{hash}")),
        created_at: row.try_get("created_at")?,
    })
}

fn device_identity_from_row(row: &PgRow) -> Result<DeviceIdentityRecord, RepositoryError> {
    Ok(DeviceIdentityRecord {
        device_id: row.try_get("device_id")?,
        user_id: user_id_from_db(row.try_get("user_id")?)?,
        signature_key: fixed_32(
            row.try_get("signature_key")?,
            "device identity signature key",
        )?,
        name: row.try_get("name")?,
        created_at: row.try_get("created_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

fn mls_key_package_from_row(row: &PgRow) -> Result<MlsKeyPackageRecord, RepositoryError> {
    let id = u64::try_from(row.try_get::<i64, _>("id")?)
        .map_err(|_| RepositoryError::InvalidData("MLS KeyPackage id is negative"))?;
    let cipher_suite = u16::try_from(row.try_get::<i16, _>("cipher_suite")?)
        .map_err(|_| RepositoryError::InvalidData("MLS cipher suite is negative"))?;
    Ok(MlsKeyPackageRecord {
        id,
        user_id: user_id_from_db(row.try_get("user_id")?)?,
        device_id: row.try_get("device_id")?,
        reference: fixed_32(row.try_get("key_package_ref")?, "MLS KeyPackage reference")?,
        key_package: row.try_get("key_package")?,
        cipher_suite,
        expires_at: row.try_get("expires_at")?,
        consumed_at: row.try_get("consumed_at")?,
        claimed_by_device: row.try_get("claimed_by_device")?,
        claimed_for_channel: row
            .try_get::<Option<i64>, _>("claimed_for_channel")?
            .map(channel_id_from_db)
            .transpose()?,
    })
}

fn mls_delivery_from_row(row: &PgRow) -> Result<MlsDeliveryRecord, RepositoryError> {
    let kind = match row.try_get::<i16, _>("kind")? {
        0 => MlsDeliveryRecordKind::Welcome,
        1 => MlsDeliveryRecordKind::Commit,
        2 => MlsDeliveryRecordKind::Proposal,
        _ => return Err(RepositoryError::InvalidData("unknown MLS delivery kind")),
    };
    Ok(MlsDeliveryRecord {
        channel_id: channel_id_from_db(row.try_get("channel_id")?)?,
        group_id: row.try_get("group_id")?,
        epoch: u64::try_from(row.try_get::<i64, _>("epoch")?)
            .map_err(|_| RepositoryError::InvalidData("MLS epoch is negative"))?,
        sequence: u64::try_from(row.try_get::<i64, _>("seq")?)
            .map_err(|_| RepositoryError::InvalidData("MLS sequence is negative"))?,
        kind,
        sender_device_id: row.try_get("sender_device")?,
        target_device_id: row.try_get("target_device")?,
        payload: row.try_get("payload")?,
        created_at: row.try_get("created_at")?,
        consumed_at: row.try_get("consumed_at")?,
    })
}

const fn mls_delivery_kind_to_db(kind: MlsDeliveryRecordKind) -> i16 {
    match kind {
        MlsDeliveryRecordKind::Welcome => 0,
        MlsDeliveryRecordKind::Commit => 1,
        MlsDeliveryRecordKind::Proposal => 2,
    }
}

fn fixed_32(value: Vec<u8>, label: &'static str) -> Result<[u8; 32], RepositoryError> {
    value
        .try_into()
        .map_err(|_| RepositoryError::InvalidData(label))
}

fn validate_welcome_set(
    claimed: &HashMap<[u8; 32], Uuid>,
    welcomes: &[MlsWelcomeRecord],
) -> Result<(), RepositoryError> {
    if claimed.len() != welcomes.len() {
        return Err(RepositoryError::Validation(
            "the MLS Welcome set must exactly match the claimed KeyPackages".into(),
        ));
    }
    if claimed.is_empty() {
        return Ok(());
    }
    let mut unique = HashSet::with_capacity(welcomes.len());
    for welcome in welcomes {
        if !unique.insert(welcome.key_package_reference)
            || claimed.get(&welcome.key_package_reference) != Some(&welcome.device_id)
        {
            return Err(RepositoryError::Validation(
                "an MLS Welcome does not match its claimed device KeyPackage".into(),
            ));
        }
    }
    Ok(())
}

fn guild_from_row(row: &PgRow) -> Result<Guild, RepositoryError> {
    let accent: i32 = row.try_get("accent")?;
    Ok(Guild {
        id: guild_id_from_db(row.try_get("id")?)?,
        owner_id: user_id_from_db(row.try_get("owner_id")?)?,
        name: row.try_get("name")?,
        accent: u32::try_from(accent)
            .map_err(|_| RepositoryError::InvalidData("server accent is negative"))?,
        created_at: row.try_get("created_at")?,
    })
}

fn channel_from_row(row: &PgRow) -> Result<Channel, RepositoryError> {
    Ok(Channel {
        id: channel_id_from_db(row.try_get("id")?)?,
        guild_id: guild_id_from_db(row.try_get("guild_id")?)?,
        name: row
            .try_get::<Option<String>, _>("name")?
            .unwrap_or_default(),
        kind: channel_kind_from_db(row.try_get("type")?)?,
        position: row.try_get("position")?,
        encrypted: row.try_get("e2ee")?,
        created_at: row.try_get("created_at")?,
    })
}

fn role_from_row(row: &PgRow) -> Result<Role, RepositoryError> {
    let color: i32 = row.try_get("color")?;
    Ok(Role {
        id: role_id_from_db(row.try_get("id")?)?,
        guild_id: guild_id_from_db(row.try_get("guild_id")?)?,
        name: row.try_get("name")?,
        color: u32::try_from(color)
            .map_err(|_| RepositoryError::InvalidData("role color is negative"))?,
        position: row.try_get("position")?,
        permissions: permissions_from_db(row.try_get("permissions")?)?,
        managed: row.try_get("managed")?,
    })
}

fn automod_rule_from_row(row: &PgRow) -> Result<AutomodRule, RepositoryError> {
    let duration_seconds = row
        .try_get::<Option<i32>, _>("duration_seconds")?
        .map(u32::try_from)
        .transpose()
        .map_err(|_| RepositoryError::InvalidData("automod duration is negative"))?;
    Ok(AutomodRule {
        id: automod_rule_id_from_db(row.try_get("id")?)?,
        guild_id: guild_id_from_db(row.try_get("guild_id")?)?,
        name: row.try_get("name")?,
        enabled: row.try_get("enabled")?,
        trigger: serde_json::from_value::<AutomodTrigger>(row.try_get("trigger")?)
            .map_err(|_| RepositoryError::InvalidData("automod trigger is invalid"))?,
        action: automod_action_from_db(row.try_get("action")?)?,
        duration_seconds,
        explanation: row.try_get("explanation")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn audit_log_entry_from_row(row: &PgRow) -> Result<AuditLogEntry, RepositoryError> {
    let target_id = row
        .try_get::<Option<i64>, _>("target_id")?
        .map(u64::try_from)
        .transpose()
        .map_err(|_| RepositoryError::InvalidData("audit target id is negative"))?
        .map(|value| value.to_string());
    Ok(AuditLogEntry {
        id: audit_log_id_from_db(row.try_get("id")?)?,
        guild_id: guild_id_from_db(row.try_get("guild_id")?)?,
        actor_id: row
            .try_get::<Option<i64>, _>("actor_id")?
            .map(user_id_from_db)
            .transpose()?,
        target_id,
        action_type: row.try_get("action_type")?,
        changes: row.try_get("changes")?,
        reason: row.try_get("reason")?,
        mfa_verified: row.try_get("mfa_verified")?,
        created_at: row.try_get("created_at")?,
    })
}

fn channel_overwrite_from_row(row: &PgRow) -> Result<ChannelPermissionOverwrite, RepositoryError> {
    let target_kind = match row.try_get::<i16, _>("target_type")? {
        0 => OverwriteTargetKind::Role,
        1 => OverwriteTargetKind::Member,
        _ => {
            return Err(RepositoryError::InvalidData(
                "unknown overwrite target type",
            ));
        }
    };
    let target_id = u64::try_from(row.try_get::<i64, _>("target_id")?)
        .map_err(|_| RepositoryError::InvalidData("overwrite target id is negative"))?;
    Ok(ChannelPermissionOverwrite {
        channel_id: channel_id_from_db(row.try_get("channel_id")?)?,
        target_kind,
        target_id: target_id.to_string(),
        allow: permissions_from_db(row.try_get("allow_bits")?)?,
        deny: permissions_from_db(row.try_get("deny_bits")?)?,
    })
}

fn message_from_row(row: &PgRow) -> Result<Message, RepositoryError> {
    let sequence: i64 = row.try_get("sequence")?;
    let attachments: serde_json::Value = row.try_get("attachments")?;
    let ciphertext: Option<Vec<u8>> = row.try_get("ciphertext")?;
    let encryption = ciphertext
        .map(|ciphertext| -> Result<MessageEncryption, RepositoryError> {
            let commitment = fixed_32(
                row.try_get::<Vec<u8>, _>("frank_commit")?,
                "message-franking commitment",
            )?;
            let tag = fixed_32(
                row.try_get::<Vec<u8>, _>("frank_tag")?,
                "message-franking tag",
            )?;
            Ok(MessageEncryption {
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
                franking_commitment: URL_SAFE_NO_PAD.encode(commitment),
                franking_tag: URL_SAFE_NO_PAD.encode(tag),
                context_nonce: row.try_get("nonce")?,
                sender_device_id: row.try_get("sender_device_id")?,
            })
        })
        .transpose()?;
    Ok(Message {
        id: message_id_from_db(row.try_get("id")?)?,
        channel_id: channel_id_from_db(row.try_get("channel_id")?)?,
        author_id: user_id_from_db(row.try_get("author_id")?)?,
        reply_to: row
            .try_get::<Option<i64>, _>("reference_id")?
            .map(message_id_from_db)
            .transpose()?,
        content: row.try_get("content")?,
        encryption,
        attachments: serde_json::from_value(attachments)
            .map_err(|_| RepositoryError::InvalidData("message attachments are invalid"))?,
        reactions: Vec::new(),
        sequence: u64::try_from(sequence)
            .map_err(|_| RepositoryError::InvalidData("message sequence is negative"))?,
        created_at: row.try_get("created_at")?,
        edited_at: row.try_get("edited_at")?,
    })
}

fn message_encryption(value: &NewMessageEncryption, nonce: &str) -> MessageEncryption {
    MessageEncryption {
        ciphertext: URL_SAFE_NO_PAD.encode(&value.ciphertext),
        franking_commitment: URL_SAFE_NO_PAD.encode(value.franking_commitment),
        franking_tag: URL_SAFE_NO_PAD.encode(value.franking_tag),
        context_nonce: nonce.to_owned(),
        sender_device_id: value.sender_device_id,
    }
}

#[allow(
    clippy::cast_sign_loss,
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts the fixed-size franking key by definition"
)]
fn calculate_franking_tag(
    key: &[u8; 32],
    channel_id: ChannelId,
    author_id: UserId,
    message_id: MessageId,
    created_at: DateTime<Utc>,
    nonce: &str,
    commitment: &[u8; 32],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts a 32-byte franking key");
    mac.update(b"exocord-message-franking-tag-v1");
    mac.update(&channel_id.raw().to_be_bytes());
    mac.update(&author_id.raw().to_be_bytes());
    mac.update(&message_id.raw().to_be_bytes());
    mac.update(&created_at.timestamp_millis().to_be_bytes());
    mac.update(&(nonce.len() as u64).to_be_bytes());
    mac.update(nonce.as_bytes());
    mac.update(commitment);
    mac.finalize().into_bytes().into()
}

pub(crate) fn verify_message_franking_tag(
    key: &[u8; 32],
    message: &Message,
    submitted_tag: &[u8; 32],
) -> Result<bool, RepositoryError> {
    let encryption = message
        .encryption
        .as_ref()
        .ok_or(RepositoryError::BadRequest(
            "plaintext messages do not have franking evidence",
        ))?;
    let commitment: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&encryption.franking_commitment)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RepositoryError::InvalidData(
            "stored franking commitment is invalid",
        ))?;
    let stored_tag: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&encryption.franking_tag)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RepositoryError::InvalidData(
            "stored message-franking tag is invalid",
        ))?;
    let expected = calculate_franking_tag(
        key,
        message.channel_id,
        message.author_id,
        message.id,
        message.created_at,
        &encryption.context_nonce,
        &commitment,
    );
    Ok(bool::from(expected.ct_eq(&stored_tag)) && bool::from(stored_tag.ct_eq(submitted_tag)))
}

const OPERATOR_REPORT_SELECT: &str = "
    SELECT reports.id AS report_id,
           reports.status AS report_status,
           reports.category AS report_category,
           reports.detail AS report_detail,
           reports.created_at AS report_created_at,
           reports.handled_at AS report_handled_at,
           reports.handled_by_operator,
           reports.resolution_note,
           reports.guild_id AS report_guild_id,
           reports.target_id AS report_message_id,
           reports.evidence_payload,
           reports.frank_tag AS report_frank_tag,
           messages.channel_id AS report_channel_id,
           messages.author_id AS report_author_id,
           COALESCE(messages.content, '') AS report_message_content,
           (messages.ciphertext IS NOT NULL) AS report_message_encrypted,
           guilds.name AS report_guild_name,
           reporter.id AS reporter_id,
           reporter.username AS reporter_username,
           reporter.display_name AS reporter_display_name,
           author.id AS author_id,
           author.username AS author_username,
           author.display_name AS author_display_name
      FROM reports
      JOIN messages
        ON messages.id = reports.target_id
      JOIN users AS reporter
        ON reporter.id = reports.reporter_id
      JOIN users AS author
        ON author.id = messages.author_id
 LEFT JOIN guilds
        ON guilds.id = reports.guild_id";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyReportEvidence {
    content: String,
    #[serde(default)]
    attachment_sha256: Vec<String>,
}

fn decode_report_evidence(
    payload: Option<&[u8]>,
    fallback_content: &str,
    encrypted: bool,
) -> Result<ReportEvidence, RepositoryError> {
    if let Some(payload) = payload {
        if let Ok(evidence) = serde_json::from_slice::<ReportEvidence>(payload)
            && evidence.verified
            && evidence.encrypted == encrypted
        {
            return Ok(evidence);
        }
        if let Ok(legacy) = serde_json::from_slice::<LegacyReportEvidence>(payload) {
            return Ok(ReportEvidence {
                content: legacy.content,
                encrypted,
                verified: true,
                attachments: Vec::new(),
                attachment_sha256: legacy
                    .attachment_sha256
                    .into_iter()
                    .map(|hash| hash.to_ascii_lowercase())
                    .collect(),
            });
        }
        return Err(RepositoryError::InvalidData(
            "stored report evidence is invalid",
        ));
    }
    if encrypted {
        return Err(RepositoryError::InvalidData(
            "encrypted report evidence is missing",
        ));
    }
    Ok(ReportEvidence {
        content: fallback_content.to_owned(),
        encrypted,
        verified: true,
        attachments: Vec::new(),
        attachment_sha256: Vec::new(),
    })
}

fn memory_report_identity(user: &User) -> OperatorReportIdentity {
    OperatorReportIdentity {
        id: user.id,
        handle: user.handle.clone(),
        display_name: user.display_name.clone(),
    }
}

fn memory_operator_report(
    store: &MemoryStore,
    report: &ReportRecord,
) -> Result<OperatorReport, RepositoryError> {
    let reporter = store
        .users
        .get(&report.reporter_id)
        .ok_or(RepositoryError::InvalidData("reporter is missing"))?;
    let author = store
        .users
        .get(&report.author_id)
        .ok_or(RepositoryError::InvalidData("reported author is missing"))?;
    let message = store
        .messages
        .get(&report.channel_id)
        .and_then(|messages| {
            messages
                .iter()
                .find(|message| message.id == report.message_id)
        })
        .ok_or(RepositoryError::InvalidData("reported message is missing"))?;
    let encrypted = message.encryption.is_some();
    Ok(OperatorReport {
        id: report.receipt.id,
        status: report.receipt.status.clone(),
        category: report.category,
        detail: report.detail.clone(),
        created_at: report.receipt.created_at,
        handled_at: report.handled_at,
        handled_by_operator: report.handled_by_operator.clone(),
        resolution_note: report.resolution_note.clone(),
        guild_id: report.guild_id,
        guild_name: report
            .guild_id
            .and_then(|guild_id| store.guilds.get(&guild_id))
            .map(|guild| guild.name.clone()),
        channel_id: Some(report.channel_id),
        message_id: report.message_id,
        reporter: memory_report_identity(reporter),
        author: memory_report_identity(author),
        evidence: decode_report_evidence(
            Some(&report.evidence_payload),
            &message.content,
            encrypted,
        )?,
        franking_tag: report.frank_tag.map(hex::encode),
    })
}

fn operator_report_status_from_db(value: i16) -> Result<&'static str, RepositoryError> {
    match value {
        0 => Ok(OperatorReportStatus::Open.as_str()),
        1 => Ok(OperatorReportStatus::Actioned.as_str()),
        2 => Ok(OperatorReportStatus::Dismissed.as_str()),
        _ => Err(RepositoryError::InvalidData("report status is invalid")),
    }
}

fn operator_report_from_row(row: &PgRow) -> Result<OperatorReport, RepositoryError> {
    let encrypted: bool = row.try_get("report_message_encrypted")?;
    let payload: Option<Vec<u8>> = row.try_get("evidence_payload")?;
    let content: String = row.try_get("report_message_content")?;
    let report_id = report_id_from_db(row.try_get("report_id")?)?;
    let guild_id = row
        .try_get::<Option<i64>, _>("report_guild_id")?
        .map(guild_id_from_db)
        .transpose()?;
    let tag = row
        .try_get::<Option<Vec<u8>>, _>("report_frank_tag")?
        .map(|value| fixed_32(value, "report franking tag").map(hex::encode))
        .transpose()?;
    Ok(OperatorReport {
        id: report_id,
        status: operator_report_status_from_db(row.try_get("report_status")?)?.to_owned(),
        category: report_category_from_db(row.try_get("report_category")?)?,
        detail: row.try_get("report_detail")?,
        created_at: row.try_get("report_created_at")?,
        handled_at: row.try_get("report_handled_at")?,
        handled_by_operator: row.try_get("handled_by_operator")?,
        resolution_note: row.try_get("resolution_note")?,
        guild_id,
        guild_name: row.try_get("report_guild_name")?,
        channel_id: Some(channel_id_from_db(row.try_get("report_channel_id")?)?),
        message_id: message_id_from_db(row.try_get("report_message_id")?)?,
        reporter: OperatorReportIdentity {
            id: user_id_from_db(row.try_get("reporter_id")?)?,
            handle: row.try_get("reporter_username")?,
            display_name: row
                .try_get::<Option<String>, _>("reporter_display_name")?
                .unwrap_or_else(|| "Member".to_owned()),
        },
        author: OperatorReportIdentity {
            id: user_id_from_db(row.try_get("author_id")?)?,
            handle: row.try_get("author_username")?,
            display_name: row
                .try_get::<Option<String>, _>("author_display_name")?
                .unwrap_or_else(|| "Member".to_owned()),
        },
        evidence: decode_report_evidence(payload.as_deref(), &content, encrypted)?,
        franking_tag: tag,
    })
}

const fn report_category_to_db(category: ReportCategory) -> i16 {
    match category {
        ReportCategory::Spam => 0,
        ReportCategory::Harassment => 1,
        ReportCategory::ThreatsViolence => 2,
        ReportCategory::SexualContentInvolvingMinors => 3,
        ReportCategory::SelfHarm => 4,
        ReportCategory::IllegalContent => 5,
        ReportCategory::Impersonation => 6,
        ReportCategory::Other => 7,
    }
}

fn report_category_from_db(value: i16) -> Result<ReportCategory, RepositoryError> {
    match value {
        0 => Ok(ReportCategory::Spam),
        1 => Ok(ReportCategory::Harassment),
        2 => Ok(ReportCategory::ThreatsViolence),
        3 => Ok(ReportCategory::SexualContentInvolvingMinors),
        4 => Ok(ReportCategory::SelfHarm),
        5 => Ok(ReportCategory::IllegalContent),
        6 => Ok(ReportCategory::Impersonation),
        7 => Ok(ReportCategory::Other),
        _ => Err(RepositoryError::InvalidData(
            "report category is outside the permanent allocation",
        )),
    }
}

fn export_report_from_row(row: &PgRow) -> Result<ExportReport, RepositoryError> {
    let status = match row.try_get::<i16, _>("status")? {
        0 => "open",
        1 => "actioned",
        2 => "dismissed",
        _ => "unknown",
    };
    let id = u64::try_from(row.try_get::<i64, _>("id")?)
        .map_err(|_| RepositoryError::InvalidData("report id is negative"))?;
    Ok(ExportReport {
        id: ReportId::from_raw(id)
            .map_err(|_| RepositoryError::InvalidData("report id is invalid"))?,
        message_id: message_id_from_db(row.try_get("target_id")?)?,
        category: report_category_from_db(row.try_get("category")?)?,
        detail: row.try_get("detail")?,
        status: status.to_owned(),
        created_at: row.try_get("created_at")?,
    })
}

fn relationship_from_row(row: &PgRow) -> Result<Relationship, RepositoryError> {
    let kind = match row.try_get::<i16, _>("state")? {
        0 => RelationshipKind::Incoming,
        1 => RelationshipKind::Outgoing,
        2 => RelationshipKind::Friend,
        3 => RelationshipKind::Blocked,
        _ => {
            return Err(RepositoryError::InvalidData("unknown relationship state"));
        }
    };
    Ok(Relationship {
        user: user_from_row(row)?,
        kind,
        since: row.try_get("relationship_since")?,
    })
}

fn sort_relationships(relationships: &mut [Relationship]) {
    relationships.sort_by(|left, right| {
        relationship_order(left.kind)
            .cmp(&relationship_order(right.kind))
            .then_with(|| {
                left.user
                    .handle
                    .to_lowercase()
                    .cmp(&right.user.handle.to_lowercase())
            })
            .then_with(|| left.user.id.cmp(&right.user.id))
    });
}

const fn relationship_order(kind: RelationshipKind) -> u8 {
    match kind {
        RelationshipKind::Incoming => 0,
        RelationshipKind::Friend => 1,
        RelationshipKind::Outgoing => 2,
        RelationshipKind::Blocked => 3,
    }
}

fn ordered_user_pair(left: UserId, right: UserId) -> (UserId, UserId) {
    if left < right {
        (left, right)
    } else {
        (right, left)
    }
}

async fn lock_user_pair(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    left: UserId,
    right: UserId,
) -> Result<(), RepositoryError> {
    let (low, high) = ordered_user_pair(left, right);
    let key = format!("relationship:{}:{}", low.raw(), high.raw());
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 813))")
        .bind(key)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn relationship_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: UserId,
    target_id: UserId,
) -> Result<Option<i16>, RepositoryError> {
    sqlx::query_scalar(
        "SELECT state FROM user_relationships
         WHERE user_id = $1 AND target_id = $2",
    )
    .bind(db_id(user_id.raw())?)
    .bind(db_id(target_id.raw())?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn postgres_user(pool: &PgPool, user_id: UserId) -> Result<User, RepositoryError> {
    let row = sqlx::query(
        "SELECT id, username, display_name, avatar_hash, created_at
         FROM users WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(db_id(user_id.raw())?)
    .fetch_optional(pool)
    .await?
    .ok_or(RepositoryError::NotFound("user"))?;
    user_from_row(&row)
}

fn memory_direct_channel(
    store: &MemoryStore,
    channel: &MemoryDirectChannel,
) -> Result<DirectChannel, RepositoryError> {
    let recipients = channel
        .recipients
        .iter()
        .map(|user_id| {
            store
                .users
                .get(user_id)
                .cloned()
                .ok_or(RepositoryError::InvalidData(
                    "direct channel recipient is missing",
                ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DirectChannel {
        id: channel.id,
        recipients,
        last_message_id: channel.last_message_id,
        encrypted: channel.encrypted,
        created_at: channel.created_at,
    })
}

fn sort_direct_channels(channels: &mut [DirectChannel]) {
    channels.sort_by_key(|channel| {
        (
            std::cmp::Reverse(channel.last_message_id.map(MessageId::raw)),
            std::cmp::Reverse(channel.created_at),
            channel.id,
        )
    });
}

async fn postgres_direct_channels(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Vec<DirectChannel>, RepositoryError> {
    let channel_rows = sqlx::query(
        "SELECT c.id, c.last_message_id, c.e2ee, c.created_at
         FROM channel_recipients mine
         JOIN channels c ON c.id = mine.channel_id
         WHERE mine.user_id = $1
           AND c.guild_id IS NULL
           AND c.type = 1
           AND c.deleted_at IS NULL
         ORDER BY c.last_message_id DESC NULLS LAST, c.created_at DESC, c.id",
    )
    .bind(db_id(user_id.raw())?)
    .fetch_all(pool)
    .await?;
    if channel_rows.is_empty() {
        return Ok(Vec::new());
    }
    let channel_ids = channel_rows
        .iter()
        .map(|row| row.try_get::<i64, _>("id"))
        .collect::<Result<Vec<_>, _>>()?;
    let recipient_rows = sqlx::query(
        "SELECT cr.channel_id, u.id, u.username, u.display_name, u.avatar_hash, u.created_at
         FROM channel_recipients cr
         JOIN users u ON u.id = cr.user_id
         WHERE cr.channel_id = ANY($1)
         ORDER BY cr.channel_id, u.id",
    )
    .bind(&channel_ids)
    .fetch_all(pool)
    .await?;
    let mut recipients = HashMap::<ChannelId, Vec<User>>::new();
    for row in &recipient_rows {
        recipients
            .entry(channel_id_from_db(row.try_get("channel_id")?)?)
            .or_default()
            .push(user_from_row(row)?);
    }
    let mut channels = Vec::with_capacity(channel_rows.len());
    for row in &channel_rows {
        let id = channel_id_from_db(row.try_get("id")?)?;
        let channel_recipients = recipients.remove(&id).ok_or(RepositoryError::InvalidData(
            "direct channel has no recipients",
        ))?;
        let last_message_id = row
            .try_get::<Option<i64>, _>("last_message_id")?
            .map(message_id_from_db)
            .transpose()?;
        channels.push(DirectChannel {
            id,
            recipients: channel_recipients,
            last_message_id,
            encrypted: row.try_get("e2ee")?,
            created_at: row.try_get("created_at")?,
        });
    }
    Ok(channels)
}

async fn postgres_direct_channel(
    pool: &PgPool,
    user_id: UserId,
    channel_id: ChannelId,
) -> Result<DirectChannel, RepositoryError> {
    postgres_direct_channels(pool, user_id)
        .await?
        .into_iter()
        .find(|channel| channel.id == channel_id)
        .ok_or(RepositoryError::NotFound("direct channel"))
}

fn read_state_from_row(row: &PgRow) -> Result<ReadState, RepositoryError> {
    let mention_count: i32 = row.try_get("mention_count")?;
    Ok(ReadState {
        channel_id: channel_id_from_db(row.try_get("channel_id")?)?,
        last_message_id: row
            .try_get::<Option<i64>, _>("last_message_id")?
            .map(message_id_from_db)
            .transpose()?,
        mention_count: u32::try_from(mention_count)
            .map_err(|_| RepositoryError::InvalidData("mention count is negative"))?,
    })
}

async fn postgres_read_states(
    pool: &PgPool,
    user_id: UserId,
    visible_channels: &HashSet<ChannelId>,
) -> Result<Vec<ReadState>, RepositoryError> {
    if visible_channels.is_empty() {
        return Ok(Vec::new());
    }
    let channel_ids = visible_channels
        .iter()
        .map(|channel_id| db_id(channel_id.raw()))
        .collect::<Result<Vec<_>, _>>()?;
    let rows = sqlx::query(
        "SELECT channel_id, NULLIF(last_message_id, 0) AS last_message_id, mention_count
         FROM read_state
         WHERE user_id = $1 AND channel_id = ANY($2)
         ORDER BY channel_id",
    )
    .bind(db_id(user_id.raw())?)
    .bind(&channel_ids)
    .fetch_all(pool)
    .await?;
    rows.iter().map(read_state_from_row).collect()
}

async fn lock_attachment_object(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    object_key: &str,
) -> Result<(), RepositoryError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7618))")
        .bind(object_key)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn attachment_record_from_row(row: &PgRow) -> Result<AttachmentRecord, RepositoryError> {
    let claimed_sha256 = fixed_hash(row.try_get("claimed_sha256")?)?;
    let verified_sha256 = row
        .try_get::<Option<Vec<u8>>, _>("verified_sha256")?
        .map(fixed_hash)
        .transpose()?;
    let file_size = u64::try_from(row.try_get::<i64, _>("file_size")?)
        .map_err(|_| RepositoryError::InvalidData("attachment size is negative"))?;
    let width = row
        .try_get::<Option<i32>, _>("width")?
        .map(u32::try_from)
        .transpose()
        .map_err(|_| RepositoryError::InvalidData("attachment width is negative"))?;
    let height = row
        .try_get::<Option<i32>, _>("height")?
        .map(u32::try_from)
        .transpose()
        .map_err(|_| RepositoryError::InvalidData("attachment height is negative"))?;
    Ok(AttachmentRecord {
        id: attachment_id_from_db(row.try_get("id")?)?,
        channel_id: channel_id_from_db(row.try_get("channel_id")?)?,
        owner_id: user_id_from_db(row.try_get("owner_id")?)?,
        message_id: row
            .try_get::<Option<i64>, _>("message_id")?
            .map(message_id_from_db)
            .transpose()?,
        filename: row.try_get("filename")?,
        declared_content_type: row.try_get("declared_content_type")?,
        verified_content_type: row.try_get("verified_content_type")?,
        file_size,
        claimed_sha256,
        verified_sha256,
        object_key: row.try_get("object_key")?,
        public_url: row.try_get("public_url")?,
        width,
        height,
        animated: row.try_get("animated")?,
        ready: row.try_get::<i16, _>("state")? == 1,
        expires_at: row.try_get("expires_at")?,
    })
}

fn export_attachment(record: &AttachmentRecord) -> ExportAttachment {
    ExportAttachment {
        id: record.id,
        channel_id: record.channel_id,
        message_id: record.message_id,
        filename: record.filename.clone(),
        declared_content_type: record.declared_content_type.clone(),
        verified_content_type: record.verified_content_type.clone(),
        file_size: record.file_size,
        claimed_sha256: hex::encode(record.claimed_sha256),
        verified_sha256: record.verified_sha256.map(hex::encode),
        public_url: record.public_url.clone(),
        ready: record.ready,
        expires_at: record.expires_at,
    }
}

fn export_device(identity: &DeviceIdentityRecord) -> ExportDevice {
    ExportDevice {
        device_id: identity.device_id,
        signature_key: URL_SAFE_NO_PAD.encode(identity.signature_key),
        name: identity.name.clone(),
        created_at: identity.created_at,
        revoked_at: identity.revoked_at,
    }
}

fn validate_attachment_completion(
    record: &AttachmentRecord,
    owner_id: UserId,
    verified: &VerifiedAttachment,
) -> Result<(), RepositoryError> {
    if record.owner_id != owner_id {
        return Err(RepositoryError::NotFound("attachment"));
    }
    if record.message_id.is_some() {
        return Err(RepositoryError::BadRequest(
            "the attachment is already attached to a message",
        ));
    }
    if record.expires_at <= Utc::now() {
        return Err(RepositoryError::BadRequest("the attachment upload expired"));
    }
    if verified.size != record.file_size
        || verified.sha256 != record.claimed_sha256
        || record
            .verified_sha256
            .is_some_and(|hash| hash != verified.sha256)
    {
        return Err(RepositoryError::BadRequest(
            "the uploaded object does not match its reservation",
        ));
    }
    Ok(())
}

fn validate_attachment_for_message(
    record: &AttachmentRecord,
    owner_id: UserId,
    channel_id: ChannelId,
) -> Result<(), RepositoryError> {
    if record.owner_id != owner_id
        || record.channel_id != channel_id
        || !record.ready
        || record.message_id.is_some()
    {
        return Err(RepositoryError::NotFound("attachment"));
    }
    if record.expires_at <= Utc::now() {
        return Err(RepositoryError::BadRequest("the attachment upload expired"));
    }
    Ok(())
}

fn record_to_message_attachment(
    record: &AttachmentRecord,
) -> Result<MessageAttachment, RepositoryError> {
    Ok(MessageAttachment {
        id: record.id,
        filename: record.filename.clone(),
        content_type: record
            .verified_content_type
            .clone()
            .ok_or(RepositoryError::InvalidData("attachment is not validated"))?,
        size: record.file_size,
        url: record.public_url.clone(),
        width: record.width,
        height: record.height,
        animated: record.animated,
        encryption: None,
    })
}

fn fixed_hash(value: Vec<u8>) -> Result<[u8; 32], RepositoryError> {
    value
        .try_into()
        .map_err(|_| RepositoryError::InvalidData("attachment hash must contain 32 bytes"))
}

fn search_terms(query: &str) -> Vec<String> {
    query
        .split_whitespace()
        .map(str::to_lowercase)
        .filter(|term| !term.is_empty())
        .collect()
}

fn sort_exclusions(exclusions: &mut [SearchExcludedChannel]) {
    exclusions.sort_by_key(|exclusion| exclusion.id);
}

const fn channel_kind_to_db(kind: ChannelKind) -> i16 {
    match kind {
        ChannelKind::Text => 0,
        ChannelKind::Voice => 2,
    }
}

const fn overwrite_target_kind_to_db(kind: OverwriteTargetKind) -> i16 {
    match kind {
        OverwriteTargetKind::Role => 0,
        OverwriteTargetKind::Member => 1,
    }
}

const fn automod_action_to_db(action: AutomodAction) -> i16 {
    match action {
        AutomodAction::Flag => 0,
        AutomodAction::Block => 1,
        AutomodAction::Timeout => 2,
        AutomodAction::Kick => 3,
        AutomodAction::Ban => 4,
    }
}

fn automod_action_from_db(value: i16) -> Result<AutomodAction, RepositoryError> {
    match value {
        0 => Ok(AutomodAction::Flag),
        1 => Ok(AutomodAction::Block),
        2 => Ok(AutomodAction::Timeout),
        3 => Ok(AutomodAction::Kick),
        4 => Ok(AutomodAction::Ban),
        _ => Err(RepositoryError::InvalidData("unknown automod action")),
    }
}

const fn automod_audit_action(action: AutomodAction) -> i16 {
    match action {
        AutomodAction::Flag => 60,
        AutomodAction::Block => 61,
        AutomodAction::Timeout => 62,
        AutomodAction::Kick => 63,
        AutomodAction::Ban => 64,
    }
}

fn apply_automod_update(
    mut rule: AutomodRule,
    input: UpdateAutomodRule,
) -> Result<AutomodRule, RepositoryError> {
    if let Some(name) = input.name {
        rule.name = name.trim().to_owned();
    }
    if let Some(enabled) = input.enabled {
        rule.enabled = enabled;
    }
    if let Some(trigger) = input.trigger {
        rule.trigger = trigger;
    }
    if let Some(action) = input.action {
        rule.action = action;
    }
    if let Some(duration_seconds) = input.duration_seconds {
        rule.duration_seconds = duration_seconds;
    }
    if let Some(explanation) = input.explanation {
        rule.explanation = explanation.trim().to_owned();
    }
    rule.updated_at = Utc::now();
    validate_rule(&rule).map_err(|error| RepositoryError::Validation(error.to_string()))?;
    Ok(rule)
}

fn channel_kind_from_db(value: i16) -> Result<ChannelKind, RepositoryError> {
    match value {
        0 => Ok(ChannelKind::Text),
        2 => Ok(ChannelKind::Voice),
        _ => Err(RepositoryError::InvalidData("unknown channel type")),
    }
}

fn permission_bits(value: GuildPermissions) -> Result<i64, RepositoryError> {
    i64::try_from(value.bits())
        .map_err(|_| RepositoryError::InvalidData("permission bits exceed the database range"))
}

fn permissions_from_db(value: i64) -> Result<GuildPermissions, RepositoryError> {
    let bits = u64::try_from(value)
        .map_err(|_| RepositoryError::InvalidData("permission bits are negative"))?;
    GuildPermissions::from_bits(bits).ok_or(RepositoryError::InvalidData(
        "permission bits are unallocated",
    ))
}

fn db_id(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value)
        .map_err(|_| RepositoryError::InvalidData("entity id exceeds the database range"))
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

fn normalized_handle(value: &str) -> String {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches(['.', '_', '-']);
    let normalized = truncate_chars(normalized, 32);
    if normalized.is_empty() {
        "member".to_owned()
    } else {
        normalized
    }
}

fn user_id_from_db(value: i64) -> Result<UserId, RepositoryError> {
    UserId::from_raw(
        u64::try_from(value).map_err(|_| RepositoryError::InvalidData("user id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("user id is invalid"))
}

fn report_id_from_db(value: i64) -> Result<ReportId, RepositoryError> {
    ReportId::from_raw(
        u64::try_from(value).map_err(|_| RepositoryError::InvalidData("report id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("report id is invalid"))
}

fn audit_log_id_from_db(value: i64) -> Result<AuditLogId, RepositoryError> {
    AuditLogId::from_raw(
        u64::try_from(value)
            .map_err(|_| RepositoryError::InvalidData("audit log id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("audit log id is invalid"))
}

fn automod_rule_id_from_db(value: i64) -> Result<AutomodRuleId, RepositoryError> {
    AutomodRuleId::from_raw(
        u64::try_from(value)
            .map_err(|_| RepositoryError::InvalidData("automod rule id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("automod rule id is invalid"))
}

fn guild_id_from_db(value: i64) -> Result<GuildId, RepositoryError> {
    GuildId::from_raw(
        u64::try_from(value).map_err(|_| RepositoryError::InvalidData("server id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("server id is invalid"))
}

fn role_id_from_db(value: i64) -> Result<RoleId, RepositoryError> {
    RoleId::from_raw(
        u64::try_from(value).map_err(|_| RepositoryError::InvalidData("role id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("role id is invalid"))
}

fn channel_id_from_db(value: i64) -> Result<ChannelId, RepositoryError> {
    ChannelId::from_raw(
        u64::try_from(value).map_err(|_| RepositoryError::InvalidData("channel id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("channel id is invalid"))
}

fn message_id_from_db(value: i64) -> Result<MessageId, RepositoryError> {
    MessageId::from_raw(
        u64::try_from(value).map_err(|_| RepositoryError::InvalidData("message id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("message id is invalid"))
}

fn attachment_id_from_db(value: i64) -> Result<AttachmentId, RepositoryError> {
    AttachmentId::from_raw(
        u64::try_from(value)
            .map_err(|_| RepositoryError::InvalidData("attachment id is negative"))?,
    )
    .map_err(|_| RepositoryError::InvalidData("attachment id is invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::AttachmentService;

    #[tokio::test]
    async fn existing_mls_group_is_preserved_for_online_device_admission() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let friend = UserId::new();
        repository
            .ensure_user(
                User {
                    id: friend,
                    handle: "mls-admission-friend".into(),
                    display_name: "MLS admission friend".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        repository
            .request_relationship(owner, "mls-admission-friend")
            .await
            .unwrap();
        repository
            .update_relationship(friend, owner, RelationshipAction::Accept)
            .await
            .unwrap();
        let direct = repository.open_direct_channel(owner, friend).await.unwrap();

        let owner_device = Uuid::now_v7();
        let friend_device = Uuid::now_v7();
        repository
            .register_device_identity(owner, owner_device, [1; 32], Some("owner".into()))
            .await
            .unwrap();
        repository
            .register_device_identity(friend, friend_device, [2; 32], Some("friend".into()))
            .await
            .unwrap();
        let friend_reference = [3; 32];
        repository
            .publish_mls_key_packages(
                friend,
                friend_device,
                vec![(friend_reference, vec![4; 128], 1)],
            )
            .await
            .unwrap();
        repository
            .claim_mls_key_packages(owner, owner_device, direct.id)
            .await
            .unwrap();
        repository
            .bootstrap_mls_group(
                owner,
                owner_device,
                direct.id,
                vec![5; 32],
                1,
                vec![6; 128],
                vec![MlsWelcomeRecord {
                    device_id: friend_device,
                    key_package_reference: friend_reference,
                    payload: vec![7; 128],
                }],
            )
            .await
            .unwrap();
        let friend_welcome = repository.mls_inbox(friend, friend_device).await.unwrap()[0].clone();
        repository
            .acknowledge_mls_delivery(
                friend,
                friend_device,
                &friend_welcome.group_id,
                friend_welcome.epoch,
                friend_welcome.sequence,
            )
            .await
            .unwrap();

        let second_owner_device = Uuid::now_v7();
        let second_reference = [8; 32];
        repository
            .register_device_identity(
                owner,
                second_owner_device,
                [9; 32],
                Some("owner second device".into()),
            )
            .await
            .unwrap();
        repository
            .publish_mls_key_packages(
                owner,
                second_owner_device,
                vec![(second_reference, vec![10; 128], 1)],
            )
            .await
            .unwrap();

        assert!(matches!(
            repository
                .claim_mls_key_packages(owner, second_owner_device, direct.id)
                .await,
            Err(RepositoryError::Conflict)
        ));
        assert_eq!(
            repository
                .pending_mls_removals(owner, owner_device)
                .await
                .unwrap(),
            vec![(direct.id, Vec::new())]
        );

        let claimed = repository
            .claim_mls_key_packages(owner, owner_device, direct.id)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].device_id, second_owner_device);
        repository
            .update_mls_group(
                owner,
                owner_device,
                direct.id,
                vec![5; 32],
                2,
                vec![11; 128],
                vec![MlsWelcomeRecord {
                    device_id: second_owner_device,
                    key_package_reference: second_reference,
                    payload: vec![12; 128],
                }],
                Vec::new(),
            )
            .await
            .unwrap();
        assert!(
            repository
                .pending_mls_removals(owner, owner_device)
                .await
                .unwrap()
                .is_empty()
        );
        let friend_commit = repository.mls_inbox(friend, friend_device).await.unwrap();
        assert_eq!(friend_commit.len(), 1);
        assert_eq!(friend_commit[0].kind, MlsDeliveryRecordKind::Commit);
    }

    #[tokio::test]
    async fn profile_updates_keep_unique_handles_and_version_avatar_urls() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let peer = UserId::new();
        repository
            .ensure_user(
                User {
                    id: peer,
                    handle: "profile-peer".into(),
                    display_name: "Profile Peer".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let avatar = UserAvatarRecord {
            content_type: "image/png".into(),
            content: vec![1, 2, 3, 4],
            content_sha256: "a".repeat(64),
            width: 64,
            height: 64,
        };
        let updated = repository
            .update_profile(
                owner,
                "erix-alpha",
                "Erix Alpha",
                UserAvatarUpdate::Set(avatar.clone()),
            )
            .await
            .unwrap();
        assert_eq!(updated.handle, "erix-alpha");
        assert_eq!(updated.display_name, "Erix Alpha");
        let expected_avatar_url = format!("/v1/users/{owner}/avatar/{}", "a".repeat(64));
        assert_eq!(
            updated.avatar_url.as_deref(),
            Some(expected_avatar_url.as_str())
        );
        assert_eq!(
            repository
                .user_avatar(owner, &avatar.content_sha256)
                .await
                .unwrap()
                .content,
            avatar.content
        );
        assert!(matches!(
            repository
                .update_profile(peer, "ERIX-ALPHA", "Collision", UserAvatarUpdate::Keep)
                .await,
            Err(RepositoryError::Conflict)
        ));
        let without_avatar = repository
            .update_profile(owner, "erix-alpha", "Erix Alpha", UserAvatarUpdate::Remove)
            .await
            .unwrap();
        assert!(without_avatar.avatar_url.is_none());
        assert!(matches!(
            repository.user_avatar(owner, &avatar.content_sha256).await,
            Err(RepositoryError::NotFound("avatar"))
        ));
    }

    #[tokio::test]
    async fn account_export_is_complete_and_anonymization_preserves_shared_history() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let peer = UserId::new();
        repository
            .ensure_user(
                User {
                    id: peer,
                    handle: "privacy-peer".into(),
                    display_name: "Privacy Peer".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        repository
            .request_relationship(owner, "privacy-peer")
            .await
            .unwrap();
        let device_id = Uuid::new_v4();
        repository
            .register_device_identity(owner, device_id, [7; 32], Some("Personal laptop".into()))
            .await
            .unwrap();

        let before = repository.account_data_export(owner).await.unwrap();
        assert_eq!(before.profile.handle, "erix");
        assert_eq!(before.guilds.len(), 1);
        assert_eq!(before.relationships.len(), 1);
        assert_eq!(before.messages.len(), 2);
        assert_eq!(before.devices.len(), 1);

        repository.anonymize_user(owner, Utc::now()).await.unwrap();

        let after = repository.account_data_export(owner).await.unwrap();
        assert!(after.profile.handle.starts_with("deleted-"));
        assert!(after.profile.display_name.starts_with("Deleted User #"));
        assert!(
            after.guilds.is_empty(),
            "a sole-member server must retire with its deleted owner"
        );
        assert_eq!(
            after.messages.len(),
            2,
            "shared conversation history must not disappear"
        );
        assert!(after.relationships.is_empty());
        assert_eq!(after.devices.len(), 1);
        assert_eq!(after.devices[0].device_id, device_id);
        assert!(after.devices[0].name.is_none());
        assert!(after.devices[0].revoked_at.is_some());
        assert!(
            repository
                .list_relationships(peer)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn ownership_transfer_resolves_account_deletion_and_server_delete_is_final() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        repository
            .ensure_user(
                User {
                    id: member,
                    handle: "next-owner".into(),
                    display_name: "Next Owner".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![41_u8; 32];
        repository
            .create_invite(
                owner,
                guild.id,
                "ownership-transfer-test".into(),
                &invite_hash,
                Some(1),
                None,
            )
            .await
            .unwrap();
        repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();

        let blockers = repository
            .prepare_account_deletion(owner, Utc::now())
            .await
            .unwrap();
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].guild.id, guild.id);
        assert_eq!(blockers[0].member_count, 2);

        let transferred = repository
            .transfer_guild_ownership(owner, guild.id, member)
            .await
            .unwrap();
        assert_eq!(transferred.owner_id, member);
        assert!(repository.owned_guilds(owner).await.unwrap().is_empty());
        assert_eq!(
            repository.owned_guilds(member).await.unwrap()[0].member_count,
            2
        );
        assert!(
            repository
                .prepare_account_deletion(owner, Utc::now())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            repository
                .delete_guild(member, guild.id, "wrong name", Utc::now())
                .await,
            Err(RepositoryError::Validation(_))
        ));

        let deleted = repository
            .delete_guild(member, guild.id, &guild.name, Utc::now())
            .await
            .unwrap();
        assert_eq!(deleted.member_ids.len(), 2);
        assert_eq!(deleted.voice_channel_ids.len(), 1);
        assert!(repository.list_guilds(owner).await.unwrap().is_empty());
        assert!(repository.list_guilds(member).await.unwrap().is_empty());
        assert!(matches!(
            repository.list_channels(member, guild.id).await,
            Err(RepositoryError::NotFound("server"))
        ));
    }

    #[tokio::test]
    async fn sole_owner_deletion_freezes_invites_and_cancel_restores_server_use() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        assert!(
            repository
                .prepare_account_deletion(owner, Utc::now())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            repository
                .create_invite(
                    owner,
                    guild.id,
                    "blocked-during-grace".into(),
                    &[42_u8; 32],
                    Some(1),
                    None,
                )
                .await,
            Err(RepositoryError::Conflict)
        ));
        repository
            .cancel_account_deletion_preparation(owner)
            .await
            .unwrap();
        repository
            .create_invite(
                owner,
                guild.id,
                "available-after-cancel".into(),
                &[43_u8; 32],
                Some(1),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn memory_repository_never_leaks_servers_to_non_members() {
        let repository = Repository::seeded();
        let outsider = UserId::new();
        repository
            .ensure_user(
                User {
                    id: outsider,
                    handle: "outsider".into(),
                    display_name: "Outsider".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        assert!(repository.list_guilds(outsider).await.unwrap().is_empty());
        let guild = repository
            .list_guilds(UserId::from_raw(1).unwrap())
            .await
            .unwrap()
            .remove(0);
        assert!(matches!(
            repository.list_channels(outsider, guild.id).await,
            Err(RepositoryError::NotFound("server"))
        ));
    }

    #[tokio::test]
    async fn create_guild_atomically_adds_owner_and_default_channels() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let created = repository
            .create_guild(owner, "New Home".into(), 0x123456)
            .await
            .unwrap();
        assert_eq!(created.channels.len(), 2);
        assert_eq!(
            repository
                .list_channels(owner, created.guild.id)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn attachment_cleanup_preserves_deduplicated_live_objects() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let channel = repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let service = AttachmentService::local(
            temporary.path().to_path_buf(),
            "http://127.0.0.1:4100".into(),
            [3; 32],
            [7; 32],
        )
        .unwrap();
        let hash = [11; 32];
        let now = Utc::now();
        let expired_id = AttachmentId::new();
        let live_id = AttachmentId::new();
        let prepared = service
            .prepare_upload(
                expired_id,
                owner,
                channel.id,
                &hash,
                "image/png",
                now - chrono::Duration::minutes(1),
            )
            .unwrap();
        for (id, expires_at) in [
            (expired_id, now - chrono::Duration::minutes(1)),
            (live_id, now + chrono::Duration::minutes(15)),
        ] {
            repository
                .reserve_attachment(NewAttachment {
                    id,
                    channel_id: channel.id,
                    owner_id: owner,
                    filename: "same.png".into(),
                    declared_content_type: "image/png".into(),
                    file_size: 8,
                    claimed_sha256: hash,
                    object_key: prepared.object_key.clone(),
                    public_url: prepared.public_url.clone(),
                    expires_at,
                })
                .await
                .unwrap();
        }
        let object_path = temporary.path().join(&prepared.object_key);
        std::fs::create_dir_all(object_path.parent().unwrap()).unwrap();
        std::fs::write(&object_path, b"occupied").unwrap();

        let first = repository
            .cleanup_expired_attachments(&service, now, 100)
            .await
            .unwrap();
        assert_eq!(first.reservations, 1);
        assert_eq!(first.objects, 0);
        assert!(object_path.exists());
        assert!(matches!(
            repository.attachment_record(expired_id).await,
            Err(RepositoryError::NotFound("attachment"))
        ));
        repository.attachment_record(live_id).await.unwrap();

        let second = repository
            .cleanup_expired_attachments(&service, now + chrono::Duration::minutes(16), 100)
            .await
            .unwrap();
        assert_eq!(
            second,
            AttachmentCleanup {
                reservations: 1,
                objects: 1
            }
        );
        assert!(!object_path.exists());
    }

    #[tokio::test]
    async fn deleting_a_message_schedules_its_attachments_for_grace_period_cleanup() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let channel = repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let attachment_id = AttachmentId::new();
        let hash = [29; 32];
        let reserved_at = Utc::now();
        repository
            .reserve_attachment(NewAttachment {
                id: attachment_id,
                channel_id: channel.id,
                owner_id: owner,
                filename: "delete-me.png".into(),
                declared_content_type: "image/png".into(),
                file_size: 8,
                claimed_sha256: hash,
                object_key: "objects/delete/message-attachment".into(),
                public_url: "https://cdn.example.test/delete-me.png".into(),
                expires_at: reserved_at + chrono::TimeDelta::minutes(15),
            })
            .await
            .unwrap();
        repository
            .complete_attachment(
                owner,
                attachment_id,
                &VerifiedAttachment {
                    content_type: "image/png".into(),
                    size: 8,
                    sha256: hash,
                    width: Some(1),
                    height: Some(1),
                    animated: false,
                },
            )
            .await
            .unwrap();
        let created = repository
            .create_message(
                owner,
                channel.id,
                "message with attachment".into(),
                None,
                "delete-attachment-message".into(),
                &[attachment_id],
                1,
            )
            .await
            .unwrap();

        repository
            .delete_message(owner, channel.id, created.message.id)
            .await
            .unwrap();
        let detached = repository.attachment_record(attachment_id).await.unwrap();
        assert_eq!(detached.message_id, None);
        assert!(
            detached.expires_at >= reserved_at + chrono::TimeDelta::days(6),
            "the attachment should remain recoverable during the seven-day grace period"
        );
    }

    #[tokio::test]
    async fn invite_acceptance_is_scoped_idempotent_and_adds_visible_profiles() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let outsider = UserId::new();
        repository
            .ensure_user(
                User {
                    id: outsider,
                    handle: "new-member".into(),
                    display_name: "New Member".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let hash = vec![7_u8; 32];
        repository
            .create_invite(
                owner,
                guild.id,
                "test-invite-code-1234".into(),
                &hash,
                Some(1),
                Some(Utc::now() + chrono::Duration::hours(1)),
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .preview_invite("test-invite-code-1234".into(), &hash)
                .await
                .unwrap()
                .member_count,
            1
        );
        repository.accept_invite(outsider, &hash).await.unwrap();
        repository.accept_invite(outsider, &hash).await.unwrap();
        let preview = repository
            .preview_invite("test-invite-code-1234".into(), &hash)
            .await;
        assert!(matches!(preview, Err(RepositoryError::InviteUnavailable)));
        let snapshot = repository.snapshot(outsider, 2).await.unwrap();
        assert!(snapshot.users.iter().any(|user| user.id == owner));
        assert!(snapshot.users.iter().any(|user| user.id == outsider));
        assert_eq!(
            repository
                .list_members(owner, guild.id, 100)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn assigned_roles_authorize_actions_without_allowing_escalation() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        repository
            .ensure_user(
                User {
                    id: member,
                    handle: "builder".into(),
                    display_name: "Builder".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![8_u8; 32];
        repository
            .create_invite(
                owner,
                guild.id,
                "role-test-invite-1234".into(),
                &invite_hash,
                Some(2),
                Some(Utc::now() + chrono::Duration::hours(1)),
            )
            .await
            .unwrap();
        repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();

        let delegated = repository
            .create_role(
                owner,
                guild.id,
                "Community builder".into(),
                0x69_D7_BD,
                GuildPermissions::CREATE_INVITE
                    | GuildPermissions::MANAGE_CHANNELS
                    | GuildPermissions::MANAGE_ROLES,
            )
            .await
            .unwrap();
        assert_eq!(delegated.position, 1);
        repository
            .set_member_role(owner, guild.id, member, delegated.id, true)
            .await
            .unwrap();

        let channel = repository
            .create_channel(
                member,
                guild.id,
                "delegated".into(),
                ChannelKind::Text,
                false,
            )
            .await
            .unwrap();
        assert_eq!(channel.name, "delegated");
        repository
            .create_invite(
                member,
                guild.id,
                "delegated-invite-1234".into(),
                &[9_u8; 32],
                Some(1),
                Some(Utc::now() + chrono::Duration::hours(1)),
            )
            .await
            .unwrap();

        let delegated_child = repository
            .create_role(
                member,
                guild.id,
                "Community helper".into(),
                0,
                GuildPermissions::CREATE_INVITE,
            )
            .await
            .unwrap();
        assert_eq!(delegated_child.position, 1);
        let roles = repository.list_roles(member, guild.id).await.unwrap();
        assert_eq!(
            roles.iter().map(|role| role.position).collect::<Vec<_>>(),
            vec![2, 1, 0]
        );
        assert_eq!(
            roles
                .iter()
                .find(|role| role.id == delegated.id)
                .map(|role| role.position),
            Some(2)
        );

        assert!(matches!(
            repository
                .create_role(
                    member,
                    guild.id,
                    "Escalation".into(),
                    0,
                    GuildPermissions::ADMINISTRATOR,
                )
                .await,
            Err(RepositoryError::Forbidden)
        ));
        let members = repository
            .list_members(member, guild.id, 100)
            .await
            .unwrap();
        assert!(
            members
                .iter()
                .find(|candidate| candidate.user.id == member)
                .is_some_and(|candidate| candidate.roles.contains(&delegated.id))
        );
    }

    #[tokio::test]
    async fn channel_overwrites_control_visibility_history_and_sends() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        repository
            .ensure_user(
                User {
                    id: member,
                    handle: "private-reader".into(),
                    display_name: "Private Reader".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![10_u8; 32];
        repository
            .create_invite(
                owner,
                guild.id,
                "overwrite-test-invite".into(),
                &invite_hash,
                Some(4),
                None,
            )
            .await
            .unwrap();
        repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();
        let general = repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();

        repository
            .set_channel_overwrite(
                owner,
                general.id,
                OverwriteTargetKind::Role,
                guild.id.raw(),
                GuildPermissions::empty(),
                GuildPermissions::VIEW_CHANNEL,
            )
            .await
            .unwrap();
        assert!(
            repository
                .list_channels(member, guild.id)
                .await
                .unwrap()
                .iter()
                .all(|channel| channel.id != general.id)
        );
        assert!(matches!(
            repository
                .create_message(
                    member,
                    general.id,
                    "secret".into(),
                    None,
                    "hidden".into(),
                    &[],
                    1,
                )
                .await,
            Err(RepositoryError::NotFound("channel"))
        ));

        repository
            .set_channel_overwrite(
                owner,
                general.id,
                OverwriteTargetKind::Member,
                member.raw(),
                GuildPermissions::VIEW_CHANNEL
                    | GuildPermissions::READ_MESSAGE_HISTORY
                    | GuildPermissions::SEND_MESSAGES,
                GuildPermissions::empty(),
            )
            .await
            .unwrap();
        assert!(
            repository
                .list_channels(member, guild.id)
                .await
                .unwrap()
                .iter()
                .any(|channel| channel.id == general.id)
        );
        repository
            .create_message(
                member,
                general.id,
                "hello".into(),
                None,
                "visible".into(),
                &[],
                2,
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .list_channel_overwrites(owner, general.id)
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            repository.list_channel_overwrites(member, general.id).await,
            Err(RepositoryError::Forbidden)
        ));
        repository
            .delete_channel_overwrite(owner, general.id, OverwriteTargetKind::Member, member.raw())
            .await
            .unwrap();
        assert!(matches!(
            repository
                .list_messages(
                    member,
                    general.id,
                    MessageWindow {
                        limit: 50,
                        ..Default::default()
                    }
                )
                .await,
            Err(RepositoryError::NotFound("channel"))
        ));
    }

    #[tokio::test]
    async fn voice_access_uses_channel_permissions_and_timeout_state() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        repository
            .ensure_user(
                User {
                    id: member,
                    handle: "voice-member".into(),
                    display_name: "Voice Member".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![12_u8; 32];
        repository
            .create_invite(
                owner,
                guild.id,
                "voice-access-invite".into(),
                &invite_hash,
                Some(2),
                None,
            )
            .await
            .unwrap();
        repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();
        let channels = repository.list_channels(owner, guild.id).await.unwrap();
        let voice = channels
            .iter()
            .find(|channel| channel.kind == ChannelKind::Voice)
            .unwrap();
        let text = channels
            .iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();

        let access = repository.voice_access(member, voice.id).await.unwrap();
        assert!(access.permissions.contains(GuildPermissions::CONNECT));
        assert!(access.permissions.contains(GuildPermissions::SPEAK));
        assert!(!access.permissions.contains(GuildPermissions::STREAM));
        assert!(matches!(
            repository.voice_access(member, text.id).await,
            Err(RepositoryError::BadRequest(
                "voice grants require a voice channel"
            ))
        ));

        repository
            .set_channel_overwrite(
                owner,
                voice.id,
                OverwriteTargetKind::Member,
                member.raw(),
                GuildPermissions::empty(),
                GuildPermissions::SPEAK | GuildPermissions::USE_VAD,
            )
            .await
            .unwrap();
        let receive_only = repository.voice_access(member, voice.id).await.unwrap();
        assert!(receive_only.permissions.contains(GuildPermissions::CONNECT));
        assert!(!receive_only.permissions.contains(GuildPermissions::SPEAK));

        repository
            .set_channel_overwrite(
                owner,
                voice.id,
                OverwriteTargetKind::Member,
                member.raw(),
                GuildPermissions::empty(),
                GuildPermissions::CONNECT | GuildPermissions::SPEAK | GuildPermissions::USE_VAD,
            )
            .await
            .unwrap();
        assert!(matches!(
            repository.voice_access(member, voice.id).await,
            Err(RepositoryError::NotFound("channel"))
        ));

        repository
            .delete_channel_overwrite(owner, voice.id, OverwriteTargetKind::Member, member.raw())
            .await
            .unwrap();
        repository
            .timeout_member(
                owner,
                guild.id,
                member,
                Some(Utc::now() + chrono::Duration::minutes(5)),
                Some("voice isolation test".into()),
            )
            .await
            .unwrap();
        assert!(matches!(
            repository.voice_access(member, voice.id).await,
            Err(RepositoryError::NotFound("channel"))
        ));
    }

    #[tokio::test]
    async fn direct_voice_requires_the_exact_active_friendship() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let friend = UserId::new();
        let outsider = UserId::new();
        for (id, handle) in [(friend, "dm-voice-friend"), (outsider, "dm-voice-outsider")] {
            repository
                .ensure_user(
                    User {
                        id,
                        handle: handle.into(),
                        display_name: handle.into(),
                        avatar_url: None,
                        created_at: Utc::now(),
                    },
                    None,
                )
                .await
                .unwrap();
        }
        repository
            .request_relationship(owner, "dm-voice-friend")
            .await
            .unwrap();
        repository
            .update_relationship(friend, owner, RelationshipAction::Accept)
            .await
            .unwrap();
        let direct = repository.open_direct_channel(owner, friend).await.unwrap();

        for user_id in [owner, friend] {
            let access = repository.voice_access(user_id, direct.id).await.unwrap();
            assert_eq!(access.channel_id, direct.id);
            assert_eq!(access.guild_id, None);
            assert!(access.permissions.contains(GuildPermissions::CONNECT));
            assert!(access.permissions.contains(GuildPermissions::SPEAK));
            assert!(access.permissions.contains(GuildPermissions::STREAM));
        }
        assert!(matches!(
            repository.voice_access(outsider, direct.id).await,
            Err(RepositoryError::NotFound("channel"))
        ));

        repository.delete_relationship(owner, friend).await.unwrap();
        assert!(matches!(
            repository.voice_access(owner, direct.id).await,
            Err(RepositoryError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn moderation_enforces_timeouts_hierarchy_bans_and_reentry() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let moderator = UserId::new();
        let member = UserId::new();
        for (id, handle) in [(moderator, "moderator"), (member, "member")] {
            repository
                .ensure_user(
                    User {
                        id,
                        handle: handle.into(),
                        display_name: handle.into(),
                        avatar_url: None,
                        created_at: Utc::now(),
                    },
                    None,
                )
                .await
                .unwrap();
        }
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![11_u8; 32];
        repository
            .create_invite(
                owner,
                guild.id,
                "moderation-test-invite".into(),
                &invite_hash,
                Some(20),
                None,
            )
            .await
            .unwrap();
        repository
            .accept_invite(moderator, &invite_hash)
            .await
            .unwrap();
        repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();
        let moderator_role = repository
            .create_role(
                owner,
                guild.id,
                "Moderator".into(),
                0,
                GuildPermissions::MODERATE_MEMBERS
                    | GuildPermissions::KICK_MEMBERS
                    | GuildPermissions::BAN_MEMBERS,
            )
            .await
            .unwrap();
        let protected_role = repository
            .create_role(
                owner,
                guild.id,
                "Protected".into(),
                0,
                GuildPermissions::empty(),
            )
            .await
            .unwrap();
        repository
            .set_member_role(owner, guild.id, moderator, moderator_role.id, true)
            .await
            .unwrap();
        repository
            .set_member_role(owner, guild.id, member, protected_role.id, true)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .timeout_member(
                    moderator,
                    guild.id,
                    member,
                    Some(Utc::now() + chrono::Duration::hours(1)),
                    None,
                )
                .await,
            Err(RepositoryError::Forbidden)
        ));

        repository
            .timeout_member(
                owner,
                guild.id,
                member,
                Some(Utc::now() + chrono::Duration::hours(1)),
                Some("cool down".into()),
            )
            .await
            .unwrap();
        let text_channel = repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        assert!(matches!(
            repository
                .create_message(
                    member,
                    text_channel.id,
                    "blocked".into(),
                    None,
                    "timeout".into(),
                    &[],
                    3
                )
                .await,
            Err(RepositoryError::NotFound("channel"))
        ));
        assert!(
            repository
                .list_members(owner, guild.id, 100)
                .await
                .unwrap()
                .into_iter()
                .find(|candidate| candidate.user.id == member)
                .and_then(|candidate| candidate.timeout_until)
                .is_some()
        );
        repository
            .timeout_member(owner, guild.id, member, None, None)
            .await
            .unwrap();
        repository
            .create_message(
                member,
                text_channel.id,
                "restored".into(),
                None,
                "restored".into(),
                &[],
                4,
            )
            .await
            .unwrap();

        repository
            .ban_member(owner, guild.id, member, Some("test ban".into()), None)
            .await
            .unwrap();
        assert!(matches!(
            repository.accept_invite(member, &invite_hash).await,
            Err(RepositoryError::Forbidden)
        ));
        let bans = repository.list_bans(owner, guild.id).await.unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].user.id, member);
        repository
            .unban_member(owner, guild.id, member, None)
            .await
            .unwrap();
        repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();
        repository
            .kick_member(owner, guild.id, member, Some("test kick".into()))
            .await
            .unwrap();
        assert!(!repository.is_guild_member(member, guild.id).await.unwrap());
    }

    #[tokio::test]
    async fn automod_rules_enforce_actions_and_write_auditable_records() {
        let repository = Repository::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        repository
            .ensure_user(
                User {
                    id: member,
                    handle: "automod-target".into(),
                    display_name: "Automod Target".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![29_u8; 32];
        repository
            .create_invite(
                owner,
                guild.id,
                "automod-test-invite".into(),
                &invite_hash,
                Some(2),
                None,
            )
            .await
            .unwrap();
        repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();

        let rule = repository
            .create_automod_rule(
                owner,
                guild.id,
                CreateAutomodRule {
                    name: "Block leaked secrets".into(),
                    enabled: true,
                    trigger: AutomodTrigger::Keyword {
                        terms: vec!["private-key".into()],
                    },
                    action: AutomodAction::Timeout,
                    duration_seconds: Some(600),
                    explanation: "Secrets cannot be posted here.".into(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            repository.list_automod_rules(member, guild.id).await,
            Err(RepositoryError::Forbidden)
        ));
        let active = repository.active_automod_rules(guild.id).await.unwrap();
        let engine = exo_safety::AutomodEngine::compile(&active).unwrap();
        let matched = engine
            .evaluate(&exo_safety::AutomodContext {
                guild_id: guild.id,
                author_id: member,
                content: "do not paste PRIVATE-KEY material",
                account_created_at: Utc::now() - chrono::Duration::days(30),
                now: Utc::now(),
            })
            .unwrap();
        let enforcement = repository
            .apply_automod_match(guild.id, member, &matched)
            .await
            .unwrap();
        assert_eq!(enforcement.applied_action, AutomodAction::Timeout);
        assert!(!enforcement.removed_from_guild);
        assert!(
            repository
                .list_members(owner, guild.id, 100)
                .await
                .unwrap()
                .into_iter()
                .find(|candidate| candidate.user.id == member)
                .and_then(|candidate| candidate.timeout_until)
                .is_some()
        );
        let audit = repository
            .list_audit_log(owner, guild.id, None, 100)
            .await
            .unwrap();
        assert!(audit.iter().any(|entry| entry.action_type == 50));
        assert!(audit.iter().any(|entry| {
            entry.action_type == 62
                && entry.reason.as_deref() == Some("Secrets cannot be posted here.")
        }));
        repository
            .delete_automod_rule(owner, guild.id, rule.id)
            .await
            .unwrap();
        assert!(
            repository
                .active_automod_rules(guild.id)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
