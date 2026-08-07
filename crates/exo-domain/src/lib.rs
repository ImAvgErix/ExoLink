mod permissions;

use std::{collections::BTreeMap, str::FromStr, sync::OnceLock};

use chrono::{DateTime, Utc};
use exo_id::{Snowflake, SnowflakeError, SnowflakeGenerator};
pub use permissions::{
    ChannelOverride, GuildPermissions, PermissionContext, PermissionResolver, RoleGrant,
};
use serde::{Deserialize, Serialize};

#[allow(
    clippy::expect_used,
    reason = "entity constructors are infallible by API contract; emitting a duplicate or malformed fallback ID would be less safe than stopping"
)]
fn next_id() -> Snowflake {
    static GENERATOR: OnceLock<SnowflakeGenerator> = OnceLock::new();
    GENERATOR
        .get_or_init(SnowflakeGenerator::default)
        .generate()
        .expect("the system clock must support Exocord snowflake generation")
}

macro_rules! entity_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Snowflake);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(next_id())
            }

            pub fn from_raw(value: u64) -> Result<Self, SnowflakeError> {
                Snowflake::from_raw(value).map(Self)
            }

            #[must_use]
            pub const fn raw(self) -> u64 {
                self.0.raw()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = SnowflakeError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                value.parse().map(Self)
            }
        }
    };
}

entity_id!(UserId);
entity_id!(GuildId);
entity_id!(RoleId);
entity_id!(ChannelId);
entity_id!(MessageId);
entity_id!(AttachmentId);
entity_id!(AuditLogId);
entity_id!(AutomodRuleId);
entity_id!(ReportId);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct User {
    pub id: UserId,
    pub handle: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    Incoming,
    Outgoing,
    Friend,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Relationship {
    pub user: User,
    pub kind: RelationshipKind,
    pub since: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectChannel {
    pub id: ChannelId,
    pub recipients: Vec<User>,
    pub last_message_id: Option<MessageId>,
    pub encrypted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadState {
    pub channel_id: ChannelId,
    pub last_message_id: Option<MessageId>,
    pub mention_count: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    Online,
    Offline,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPresence {
    pub user_id: UserId,
    pub status: PresenceStatus,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingEvent {
    pub channel_id: ChannelId,
    pub user_id: UserId,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AutomodTrigger {
    Keyword { terms: Vec<String> },
    Regex { patterns: Vec<String> },
    InviteLink,
    MassMention { limit: u16 },
    RepeatedContent { threshold: u8, window_seconds: u16 },
    NewAccountLink { max_account_age_days: u16 },
    Zalgo { combining_mark_limit: u16 },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomodAction {
    Flag,
    Block,
    Timeout,
    Kick,
    Ban,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomodRule {
    pub id: AutomodRuleId,
    pub guild_id: GuildId,
    pub name: String,
    pub enabled: bool,
    pub trigger: AutomodTrigger,
    pub action: AutomodAction,
    pub duration_seconds: Option<u32>,
    pub explanation: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAutomodRule {
    pub name: String,
    pub enabled: bool,
    pub trigger: AutomodTrigger,
    pub action: AutomodAction,
    pub duration_seconds: Option<u32>,
    pub explanation: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAutomodRule {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub trigger: Option<AutomodTrigger>,
    pub action: Option<AutomodAction>,
    pub duration_seconds: Option<Option<u32>>,
    pub explanation: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogEntry {
    pub id: AuditLogId,
    pub guild_id: GuildId,
    pub actor_id: Option<UserId>,
    /// Targets may be users, roles, channels, rules, or other future entities.
    /// A decimal string keeps the snowflake exact in JavaScript clients.
    pub target_id: Option<String>,
    pub action_type: i16,
    pub changes: serde_json::Value,
    pub reason: Option<String>,
    pub mfa_verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Guild {
    pub id: GuildId,
    pub owner_id: UserId,
    pub name: String,
    pub accent: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub id: RoleId,
    pub guild_id: GuildId,
    pub name: String,
    pub color: u32,
    pub position: i32,
    #[serde(with = "permission_bits_string")]
    pub permissions: GuildPermissions,
    pub managed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Text,
    Voice,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Channel {
    pub id: ChannelId,
    pub guild_id: GuildId,
    pub name: String,
    pub kind: ChannelKind,
    pub position: i32,
    pub encrypted: bool,
    pub created_at: DateTime<Utc>,
}

/// A short-lived, permission-scoped credential for joining one media room.
///
/// The LiveKit API secret never crosses this boundary. Clients must discard the
/// token after connecting and request a new grant for a later join.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceJoinGrant {
    pub channel_id: ChannelId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<GuildId>,
    pub room_name: String,
    pub server_url: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub participant_id: UserId,
    pub participant_name: String,
    pub can_speak: bool,
    pub can_stream: bool,
    pub transport_encrypted: bool,
    pub end_to_end_encrypted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message {
    pub id: MessageId,
    pub channel_id: ChannelId,
    pub author_id: UserId,
    /// Optional message in this channel that this message replies to. The
    /// server deliberately stores only the identifier so an encrypted reply
    /// preview remains client-owned plaintext.
    #[serde(default)]
    pub reply_to: Option<MessageId>,
    /// Server-readable plaintext. This is empty and omitted on the wire for an
    /// end-to-end encrypted message.
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub encryption: Option<MessageEncryption>,
    #[serde(default)]
    pub attachments: Vec<MessageAttachment>,
    #[serde(default)]
    pub reactions: Vec<MessageReaction>,
    pub sequence: u64,
    pub created_at: DateTime<Utc>,
    pub edited_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageReaction {
    pub emoji: String,
    pub count: u32,
    #[serde(default)]
    pub me: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDeleteEvent {
    pub id: MessageId,
    pub channel_id: ChannelId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageReactionEvent {
    pub message_id: MessageId,
    pub channel_id: ChannelId,
    pub user_id: UserId,
    pub emoji: String,
    pub count: u32,
    pub added: bool,
}

/// Opaque application ciphertext plus the server-authenticated message-franking
/// values required for end-to-end decryption and abuse reports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageEncryption {
    pub ciphertext: String,
    pub franking_commitment: String,
    pub franking_tag: String,
    pub context_nonce: String,
    pub sender_device_id: uuid::Uuid,
}

/// A random account history key wrapped client-side with a password-derived
/// key. The server stores these bytes but cannot unwrap them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedAccountKey {
    pub version: u8,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// One account-private copy of decrypted encrypted-message presentation data.
/// `nonce` and `ciphertext` are opaque to the server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateHistoryArchive {
    pub message_id: MessageId,
    pub channel_id: ChannelId,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentEncryption {
    pub algorithm: String,
    /// Unpadded base64url encoded 256-bit content-encryption key.
    pub key: String,
    /// Unpadded base64url encoded 96-bit AES-GCM nonce.
    pub nonce: String,
    /// Lowercase hexadecimal SHA-256 of the original file.
    pub plaintext_sha256: String,
    /// Lowercase hexadecimal SHA-256 of the encrypted upload.
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageAttachment {
    pub id: AttachmentId,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub url: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub animated: bool,
    /// Present only in an MLS-decrypted client view. The server never receives
    /// or persists these key bytes as attachment metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<AttachmentEncryption>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveAttachment {
    pub filename: String,
    pub file_size: u64,
    pub content_type: String,
    /// Lowercase hexadecimal SHA-256 calculated before an upload is requested.
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveAttachments {
    pub files: Vec<ReserveAttachment>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUpload {
    pub id: AttachmentId,
    pub upload_url: String,
    #[serde(default)]
    pub upload_headers: BTreeMap<String, String>,
    pub expires_at: DateTime<Utc>,
    pub max_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReservedAttachments {
    pub attachments: Vec<AttachmentUpload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub message: Message,
    pub channel_name: String,
    pub score: f64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchExclusionReason {
    E2ee,
    NoPermission,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchExcludedChannel {
    pub id: ChannelId,
    pub name: String,
    pub reason: SearchExclusionReason,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSearchResult {
    pub total: u64,
    pub hits: Vec<SearchHit>,
    pub excluded_channels: Vec<SearchExcludedChannel>,
}

/// A bounded REST bootstrap used to hydrate a client's durable local cache.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SyncSnapshot {
    pub current_user: User,
    #[serde(default)]
    pub users: Vec<User>,
    pub guilds: Vec<Guild>,
    #[serde(default)]
    pub guild_access: Vec<GuildAccess>,
    #[serde(default)]
    pub guild_members: Vec<GuildMemberReference>,
    pub channels: Vec<Channel>,
    #[serde(default)]
    pub direct_channels: Vec<DirectChannel>,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
    #[serde(default)]
    pub read_states: Vec<ReadState>,
    #[serde(default)]
    pub presences: Vec<UserPresence>,
    pub messages: Vec<Message>,
    pub last_sequence: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuildAccess {
    pub guild_id: GuildId,
    #[serde(with = "permission_bits_string")]
    pub permissions: GuildPermissions,
}

/// A privacy-filtered server membership edge used by clients to build the
/// member/presence roster. The referenced user is included in `SyncSnapshot::users`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuildMemberReference {
    pub guild_id: GuildId,
    pub user_id: UserId,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvite {
    pub expires_in_seconds: Option<u32>,
    pub max_uses: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuildInvite {
    pub code: String,
    pub guild_id: GuildId,
    pub creator_id: UserId,
    pub uses: u32,
    pub max_uses: Option<u32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePreview {
    pub code: String,
    pub guild: Guild,
    pub member_count: u32,
    pub uses: u32,
    pub max_uses: Option<u32>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuildMember {
    pub user: User,
    pub joined_at: DateTime<Utc>,
    #[serde(default)]
    pub roles: Vec<RoleId>,
    #[serde(default)]
    pub timeout_until: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateGuild {
    pub name: String,
    pub accent: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRole {
    pub name: String,
    pub color: Option<u32>,
    pub permissions: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRole {
    pub name: Option<String>,
    pub color: Option<u32>,
    pub permissions: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverwriteTargetKind {
    Role,
    Member,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelPermissionOverwrite {
    pub channel_id: ChannelId,
    pub target_kind: OverwriteTargetKind,
    pub target_id: String,
    #[serde(with = "permission_bits_string")]
    pub allow: GuildPermissions,
    #[serde(with = "permission_bits_string")]
    pub deny: GuildPermissions,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateChannelOverwrite {
    pub allow: String,
    pub deny: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateChannel {
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModerateMember {
    pub timeout_seconds: Option<u32>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BanMember {
    pub reason: Option<String>,
    pub duration_seconds: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuildBan {
    pub user: User,
    pub actor_id: Option<UserId>,
    pub reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateChannel {
    pub name: String,
    pub kind: ChannelKind,
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateMessage {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub encryption: Option<CreateMessageEncryption>,
    #[serde(default)]
    pub reply_to: Option<MessageId>,
    pub nonce: String,
    #[serde(default)]
    pub allowed_mentions: AllowedMentions,
    #[serde(default)]
    pub attachments: Vec<AttachmentId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessageEncryption {
    /// Unpadded base64url encoded TLS-serialized MLS application message.
    pub ciphertext: String,
    /// Unpadded base64url encoded 32-byte message-franking commitment.
    pub franking_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateMessage {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub encryption: Option<CreateMessageEncryption>,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MessageReactionInput {
    pub emoji: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportCategory {
    Spam,
    Harassment,
    ThreatsViolence,
    SexualContentInvolvingMinors,
    SelfHarm,
    IllegalContent,
    Impersonation,
    Other,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageFrankingEvidence {
    pub content: String,
    pub attachment_sha256: Vec<String>,
    /// Unpadded base64url encoded 32-byte franking opening.
    pub franking_key: String,
    /// Unpadded base64url encoded server tag returned with the message.
    pub franking_tag: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessageReport {
    pub message_id: MessageId,
    pub category: ReportCategory,
    pub detail: Option<String>,
    pub franking: Option<MessageFrankingEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportReceipt {
    pub id: ReportId,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIdentity {
    pub device_id: uuid::Uuid,
    pub user_id: UserId,
    /// Unpadded base64url encoded Ed25519 verification key.
    pub signature_key: String,
    pub fingerprint: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceIdentity {
    /// Unpadded base64url encoded 32-byte Ed25519 verification key.
    pub signature_key: String,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MlsKeyPackage {
    pub id: u64,
    pub user_id: UserId,
    pub device_id: uuid::Uuid,
    /// Unpadded base64url encoded RFC 9420 KeyPackage reference.
    pub reference: String,
    /// Unpadded base64url encoded TLS-serialized RFC 9420 KeyPackage.
    pub key_package: String,
    pub cipher_suite: u16,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishMlsKeyPackage {
    pub reference: String,
    pub key_package: String,
    pub cipher_suite: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishMlsKeyPackages {
    pub packages: Vec<PublishMlsKeyPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MlsWelcomeDelivery {
    pub channel_id: ChannelId,
    pub group_id: String,
    pub epoch: u64,
    pub sequence: u64,
    pub kind: MlsDeliveryKind,
    pub sender_device_id: uuid::Uuid,
    pub payload: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsDeliveryKind {
    Welcome,
    Commit,
    Proposal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MlsWelcomeUpload {
    pub device_id: uuid::Uuid,
    pub key_package_reference: String,
    pub payload: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapMlsGroup {
    pub group_id: String,
    pub epoch: u64,
    pub commit: String,
    pub welcomes: Vec<MlsWelcomeUpload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMlsGroup {
    pub group_id: String,
    pub epoch: u64,
    pub commit: String,
    #[serde(default)]
    pub welcomes: Vec<MlsWelcomeUpload>,
    #[serde(default)]
    pub removed_device_ids: Vec<uuid::Uuid>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MlsMembershipHint {
    pub channel_id: ChannelId,
    #[serde(default)]
    pub revoked_device_ids: Vec<uuid::Uuid>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AllowedMentions {
    #[serde(default)]
    pub parse: Vec<MentionKind>,
    #[serde(default)]
    pub users: Vec<UserId>,
    #[serde(default)]
    pub roles: Vec<RoleId>,
    #[serde(default)]
    pub replied_user: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MentionKind {
    Users,
    Roles,
    Everyone,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("{field} must contain between {min} and {max} characters")]
    Length {
        field: &'static str,
        min: usize,
        max: usize,
    },
    #[error("message content may not be blank")]
    BlankMessage,
    #[error("a message may contain at most {max} attachments")]
    TooManyAttachments { max: usize },
}

pub fn validate_guild_name(name: &str) -> Result<String, ValidationError> {
    validate_name("server name", name, 2, 64)
}

pub fn validate_channel_name(name: &str) -> Result<String, ValidationError> {
    let normalized = name.trim().to_lowercase().replace(' ', "-");
    validate_name("channel name", &normalized, 1, 64)
}

pub fn validate_role_name(name: &str) -> Result<String, ValidationError> {
    validate_name("role name", name, 1, 100)
}

pub fn validate_message(content: &str) -> Result<String, ValidationError> {
    validate_message_with_attachments(content, 0)
}

pub fn validate_message_with_attachments(
    content: &str,
    attachment_count: usize,
) -> Result<String, ValidationError> {
    const MAX_ATTACHMENTS: usize = 10;
    if attachment_count > MAX_ATTACHMENTS {
        return Err(ValidationError::TooManyAttachments {
            max: MAX_ATTACHMENTS,
        });
    }
    let content = content.trim();
    if content.is_empty() && attachment_count == 0 {
        return Err(ValidationError::BlankMessage);
    }
    if content.chars().count() > 4_000 {
        return Err(ValidationError::Length {
            field: "message",
            min: 1,
            max: 4_000,
        });
    }
    Ok(content.to_owned())
}

fn validate_name(
    field: &'static str,
    value: &str,
    min: usize,
    max: usize,
) -> Result<String, ValidationError> {
    let value = value.trim();
    let length = value.chars().count();
    if !(min..=max).contains(&length) {
        return Err(ValidationError::Length { field, min, max });
    }
    Ok(value.to_owned())
}

mod permission_bits_string {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use crate::GuildPermissions;

    pub fn serialize<S>(value: &GuildPermissions, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.bits().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<GuildPermissions, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bits = value
            .parse::<u64>()
            .map_err(|_| D::Error::custom("permission bits must be a decimal string"))?;
        GuildPermissions::from_bits(bits)
            .ok_or_else(|| D::Error::custom("permission bits contain unallocated values"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_names_are_normalized() {
        assert_eq!(
            validate_channel_name("  Build Room  ").unwrap(),
            "build-room"
        );
    }

    #[test]
    fn blank_messages_are_rejected() {
        assert!(matches!(
            validate_message("   "),
            Err(ValidationError::BlankMessage)
        ));
    }

    #[test]
    fn attachments_allow_an_empty_message_body_but_stay_bounded() {
        assert_eq!(validate_message_with_attachments(" ", 1).unwrap(), "");
        assert!(matches!(
            validate_message_with_attachments("", 11),
            Err(ValidationError::TooManyAttachments { max: 10 })
        ));
    }

    #[test]
    fn role_permissions_are_string_safe_on_json_boundaries() {
        let guild_id = GuildId::new();
        let role = Role {
            id: RoleId::new(),
            guild_id,
            name: "Moderator".into(),
            color: 0x69_D7_BD,
            position: 1,
            permissions: GuildPermissions::MANAGE_ROLES | GuildPermissions::ENABLE_E2EE,
            managed: false,
        };
        let json = serde_json::to_value(&role).unwrap();
        assert_eq!(
            json["permissions"].as_str().unwrap(),
            role.permissions.bits().to_string()
        );
        let round_trip: Role = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip.permissions, role.permissions);
    }
}
