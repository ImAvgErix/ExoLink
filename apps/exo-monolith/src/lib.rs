use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{
        ConnectInfo, DefaultBodyLimit, Path, Query, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE},
    },
    response::{Html, IntoResponse, Response},
    routing::get,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration as ChronoDuration, Utc};
use exo_crypto::verify_franking_opening;
use exo_discord::{DiscordIntegrationMode, capabilities as discord_capabilities};
use exo_domain::{
    AttachmentId, AttachmentUpload, AuditLogEntry, AuditLogId, AutomodAction, AutomodRule,
    AutomodRuleId, BanMember, BootstrapMlsGroup, Channel, ChannelId, ChannelPermissionOverwrite,
    CreateAutomodRule, CreateChannel, CreateGuild, CreateInvite, CreateMessage,
    CreateMessageReport, CreateRole, DeviceIdentity, DirectChannel, Guild, GuildBan, GuildId,
    GuildInvite, GuildMember, GuildPermissions, InvitePreview, Message, MessageId,
    MessageReactionInput, MessageSearchResult, MlsDeliveryKind, MlsKeyPackage, MlsMembershipHint,
    MlsWelcomeDelivery, ModerateMember, OverwriteTargetKind, PresenceStatus, PrivateHistoryArchive,
    PublishMlsKeyPackages, ReadState, RegisterDeviceIdentity, Relationship, ReportId,
    ReportReceipt, ReserveAttachments, ReservedAttachments, Role, RoleId, SyncSnapshot,
    TypingEvent, UpdateAutomodRule, UpdateChannel, UpdateChannelOverwrite, UpdateMessage,
    UpdateMlsGroup, UpdateRole, User, UserId, UserPresence, ValidationError, VoiceJoinGrant,
    WrappedAccountKey, validate_channel_name, validate_guild_name,
    validate_message_with_attachments, validate_role_name,
};
use exo_protocol::{EventType, ReadyPayload, RoutingMetadata, encode_frame, encode_routed_frame};
use exo_safety::{
    AutomodContext, AutomodEngine, GcraLimiter, ProofOfWorkError, ProofOfWorkManager,
    ProofOfWorkSolution, RateLimit, RateLimitDecision,
};
use futures_util::StreamExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use livekit_api::services::room::{RemoveParticipantOptions, RoomClient};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::broadcast;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use unicode_properties::emoji::UnicodeEmoji;
use unicode_segmentation::UnicodeSegmentation;
use uuid::Uuid;

pub mod apple;
pub mod auth;
pub mod media;
pub mod repository;

use apple::AppleClient;
use auth::{
    AccountDeletion, AccountEnforcementOverview, AccountSuspension, AppleFlowPoll, AppleLinkPoll,
    AuthDataExport, AuthError, AuthService, AuthUser, EmailDelivery, Principal, RecoveryKeyVault,
    RecoveryPreparation, SessionBundle,
};
use media::{AttachmentService, MAX_ATTACHMENT_BYTES, MediaError};
use repository::{
    DeviceIdentityRecord, MessageAudience, MessageWindow, MlsDeliveryRecord, MlsDeliveryRecordKind,
    MlsKeyPackageRecord, MlsWelcomeRecord, NewAttachment, NewMessageEncryption, OperatorReport,
    OperatorReportStatus, OwnedGuildRecord, RelationshipAction, ReportEvidence,
    ReportEvidenceAttachment, Repository, RepositoryDataExport, RepositoryError, UserAvatarRecord,
    UserAvatarUpdate, VerifiedAttachment, VoiceAccess, verify_message_franking_tag,
};

type TypingLeases = Arc<tokio::sync::Mutex<HashMap<(UserId, ChannelId), chrono::DateTime<Utc>>>>;
const PRIVACY_POLICY_TEMPLATE: &str = include_str!("../policies/privacy.html");
const TERMS_POLICY_TEMPLATE: &str = include_str!("../policies/terms.html");

#[derive(Clone)]
pub struct AppState {
    repository: Repository,
    next_sequence: Arc<AtomicU32>,
    events: broadcast::Sender<PublishedEvent>,
    auth: AuthService,
    allow_development_auth: bool,
    voice: Option<VoiceConfig>,
    attachments: AttachmentService,
    presence_connections: Arc<tokio::sync::Mutex<HashMap<UserId, u32>>>,
    revoked_gateway_devices: Arc<tokio::sync::RwLock<HashSet<Uuid>>>,
    typing_leases: TypingLeases,
    automod_engines: Arc<tokio::sync::RwLock<HashMap<GuildId, Arc<AutomodEngine>>>>,
    proof_of_work: ProofOfWorkManager,
    rate_limiter: GcraLimiter,
    trust_proxy_headers: bool,
    franking_key: [u8; 32],
    operator: OperatorInfo,
    operator_token_hash: Option<[u8; 32]>,
    suspended_gateway_users: Arc<tokio::sync::RwLock<HashSet<UserId>>>,
    registration_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
struct PublishedEvent {
    frame: Vec<u8>,
    guild_id: Option<GuildId>,
    channel_id: Option<ChannelId>,
    recipients: Option<Arc<HashSet<UserId>>>,
}

#[derive(Clone)]
pub struct VoiceConfig {
    server_url: String,
    api_key: String,
    api_secret: String,
    token_ttl_seconds: i64,
    room_client: Arc<RoomClient>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorInfo {
    pub name: String,
    pub privacy_url: Option<String>,
    pub terms_url: Option<String>,
    pub support_email: Option<String>,
    pub abuse_email: Option<String>,
}

impl OperatorInfo {
    #[must_use]
    pub fn development() -> Self {
        Self {
            name: "Local Exocord development".to_owned(),
            privacy_url: None,
            terms_url: None,
            support_email: None,
            abuse_email: None,
        }
    }
}

impl VoiceConfig {
    /// Creates a media configuration without exposing the signing secret to
    /// clients. Plain WebSocket signaling is accepted only on loopback.
    pub fn new(
        server_url: impl Into<String>,
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let server_url = server_url.into();
        let parsed = url::Url::parse(&server_url).map_err(|_| "LiveKit URL is invalid")?;
        if !matches!(parsed.scheme(), "ws" | "wss") {
            return Err("LiveKit URL must use ws or wss");
        }
        let loopback = parsed.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host == "127.0.0.1"
                || host == "::1"
                || host == "[::1]"
        });
        if parsed.scheme() == "ws" && !loopback {
            return Err("plain LiveKit WebSockets are limited to loopback development");
        }
        let api_key = api_key.into();
        let api_secret = api_secret.into();
        if api_key.trim().is_empty() || api_secret.trim().is_empty() {
            return Err("LiveKit API key and secret cannot be empty");
        }
        let mut control_url = parsed;
        control_url
            .set_scheme(if control_url.scheme() == "wss" {
                "https"
            } else {
                "http"
            })
            .map_err(|()| "LiveKit control URL could not be derived")?;
        let room_client = RoomClient::with_api_key(
            control_url.as_str().trim_end_matches('/'),
            &api_key,
            &api_secret,
        )
        .with_request_timeout(std::time::Duration::from_secs(2));
        Ok(Self {
            server_url,
            api_key,
            api_secret,
            token_ttl_seconds: 60,
            room_client: Arc::new(room_client),
        })
    }

    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "the fixed loopback URL and development credentials are compile-time invariants"
    )]
    pub fn development() -> Self {
        Self::new("ws://127.0.0.1:7880", "devkey", "secret")
            .expect("the loopback development media configuration is valid")
    }

    fn room_name(guild_id: GuildId, channel_id: ChannelId) -> String {
        format!("exo-{guild_id}-voice-{channel_id}")
    }

    fn direct_room_name(channel_id: ChannelId) -> String {
        format!("exo-dm-{channel_id}")
    }

    async fn remove_participant(&self, guild_id: GuildId, channel_id: ChannelId, user_id: UserId) {
        let room = Self::room_name(guild_id, channel_id);
        for attempt in 1..=3 {
            match self
                .room_client
                .remove_participant_with_options(
                    &room,
                    &user_id.to_string(),
                    RemoveParticipantOptions {
                        revoke_token_ts: Utc::now().timestamp_millis(),
                    },
                )
                .await
            {
                Ok(()) => return,
                Err(error) if attempt < 3 => {
                    tracing::debug!(
                        %error,
                        %room,
                        %user_id,
                        attempt,
                        "voice participant revocation will be retried"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        %room,
                        %user_id,
                        "voice participant could not be revoked after retries"
                    );
                }
            }
        }
    }

    async fn reset_room(&self, guild_id: GuildId, channel_id: ChannelId) {
        let room = Self::room_name(guild_id, channel_id);
        for attempt in 1..=3 {
            match self.room_client.delete_room(&room).await {
                Ok(()) => return,
                Err(error) if attempt < 3 => {
                    tracing::debug!(
                        %error,
                        %room,
                        attempt,
                        "voice room reset will be retried"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
                }
                Err(error) => {
                    tracing::debug!(
                        %error,
                        %room,
                        "voice room was not active or could not be reset after retries"
                    );
                }
            }
        }
    }
}

impl AppState {
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "seeded state is only a development/test constructor and cannot recover from an unavailable in-memory database"
    )]
    pub fn seeded() -> Self {
        let auth = AuthService::in_memory(EmailDelivery::DevelopmentConsole, None)
            .expect("the in-memory auth database initializes");
        Self::seeded_with_auth(auth, true)
    }

    #[must_use]
    pub fn seeded_with_auth(auth: AuthService, allow_development_auth: bool) -> Self {
        Self::with_repository(auth, allow_development_auth, Repository::seeded(), 3)
    }

    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "development/test state must fail closed if secure randomness is unavailable"
    )]
    pub fn with_repository(
        auth: AuthService,
        allow_development_auth: bool,
        repository: Repository,
        next_sequence: u32,
    ) -> Self {
        let (events, _) = broadcast::channel(256);
        let mut franking_key = [0_u8; 32];
        getrandom::fill(&mut franking_key)
            .expect("secure randomness is required for development message franking");
        Self {
            repository,
            next_sequence: Arc::new(AtomicU32::new(next_sequence)),
            events,
            auth,
            allow_development_auth,
            voice: Some(VoiceConfig::development()),
            attachments: AttachmentService::disabled([0; 32]),
            presence_connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            revoked_gateway_devices: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
            typing_leases: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            automod_engines: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            proof_of_work: ProofOfWorkManager::new(if allow_development_auth { 8 } else { 18 }, 24),
            rate_limiter: GcraLimiter::default(),
            trust_proxy_headers: false,
            franking_key,
            operator: OperatorInfo::development(),
            operator_token_hash: None,
            suspended_gateway_users: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
            registration_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    #[must_use]
    pub fn with_voice_config(mut self, voice: Option<VoiceConfig>) -> Self {
        self.voice = voice;
        self
    }

    #[must_use]
    pub fn with_attachment_service(mut self, attachments: AttachmentService) -> Self {
        self.attachments = attachments;
        self
    }

    #[must_use]
    pub fn with_trusted_proxy_headers(mut self, enabled: bool) -> Self {
        self.trust_proxy_headers = enabled;
        self
    }

    #[must_use]
    pub fn with_franking_key(mut self, key: [u8; 32]) -> Self {
        self.franking_key = key;
        self
    }

    #[must_use]
    pub fn with_operator_info(mut self, operator: OperatorInfo) -> Self {
        self.operator = operator;
        self
    }

    #[must_use]
    pub fn with_operator_token(mut self, token: &str) -> Self {
        self.operator_token_hash = Some(Sha256::digest(token.as_bytes()).into());
        self
    }

    #[must_use]
    pub fn repository_handle(&self) -> Repository {
        self.repository.clone()
    }

    pub async fn finalize_due_account_deletions(
        &self,
        now: chrono::DateTime<Utc>,
        limit: usize,
    ) -> Result<usize, String> {
        let users = self
            .auth
            .due_account_deletions(now, limit)
            .map_err(|error| error.to_string())?;
        let mut finalized = 0;
        for user_id in users {
            if !self
                .auth
                .begin_account_anonymization(user_id, now)
                .map_err(|error| error.to_string())?
            {
                continue;
            }
            self.repository
                .anonymize_user(user_id, now)
                .await
                .map_err(|error| error.to_string())?;
            if self
                .auth
                .finalize_account_deletion(user_id, now)
                .map_err(|error| error.to_string())?
            {
                finalized += 1;
            }
        }
        Ok(finalized)
    }
}

pub fn build_router(state: AppState) -> Router {
    build_router_with_allowed_origins(state, None)
}

pub fn build_router_with_allowed_origins(
    state: AppState,
    allowed_origins: Option<Vec<HeaderValue>>,
) -> Router {
    let middleware_state = state.clone();
    let cors = allowed_origins.map_or_else(CorsLayer::permissive, |origins| {
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(Any)
            .allow_headers(Any)
    });
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/privacy", get(privacy_policy))
        .route("/terms", get(terms_policy))
        .route("/v1/meta/capabilities", get(platform_capabilities))
        .route("/v1/meta/operator", get(operator_info))
        .route("/v1/operator/reports", get(list_operator_reports))
        .route(
            "/v1/operator/reports/{report_id}",
            axum::routing::put(resolve_operator_report),
        )
        .route(
            "/v1/operator/users/{user_id}/suspension",
            get(operator_account_enforcement)
                .put(suspend_operator_account)
                .delete(reinstate_operator_account),
        )
        .route("/v1/auth/providers", get(auth_providers))
        .route("/v1/auth/challenge", get(auth_challenge))
        .route(
            "/v1/auth/password/register",
            axum::routing::post(register_password),
        )
        .route(
            "/v1/auth/password/login",
            axum::routing::post(login_password),
        )
        .route(
            "/v1/users/@me/password",
            axum::routing::put(change_password),
        )
        .route(
            "/v1/auth/password/recover/prepare",
            axum::routing::post(prepare_password_recovery),
        )
        .route(
            "/v1/auth/password/recover",
            axum::routing::post(recover_password),
        )
        .route(
            "/v1/users/@me/password/recovery-codes",
            axum::routing::post(regenerate_recovery_codes),
        )
        .route(
            "/v1/auth/email/request",
            axum::routing::post(request_email_code),
        )
        .route(
            "/v1/auth/email/verify",
            axum::routing::post(verify_email_code),
        )
        .route("/v1/auth/refresh", axum::routing::post(refresh_session))
        .route("/v1/auth/logout", axum::routing::post(logout))
        .route("/v1/auth/me", get(current_auth_user))
        .route(
            "/v1/users/@me/key-vault",
            get(account_key_vault).put(set_account_key_vault),
        )
        .route(
            "/v1/users/@me/recovery-key-vaults",
            axum::routing::put(set_recovery_key_vaults),
        )
        .route("/v1/users/@me/private-history", get(private_history))
        .route(
            "/v1/users/@me/private-history/{message_id}",
            axum::routing::put(put_private_history),
        )
        .route("/v1/users/@me/data-export", get(export_account_data))
        .route(
            "/v1/users/@me",
            get(current_profile)
                .patch(update_profile)
                .delete(schedule_account_deletion),
        )
        .route("/v1/users/{user_id}/avatar/{hash}", get(user_avatar))
        .route(
            "/v1/users/@me/deletion",
            get(account_deletion_status).delete(cancel_account_deletion),
        )
        .route(
            "/v1/auth/apple/start",
            axum::routing::post(start_apple_login),
        )
        .route(
            "/v1/auth/apple/callback",
            axum::routing::post(apple_callback),
        )
        .route("/v1/auth/apple/status", get(apple_login_status))
        .route("/v1/users/@me/auth-methods", get(account_auth_methods))
        .route(
            "/v1/users/@me/apple/start",
            axum::routing::post(start_apple_link),
        )
        .route("/v1/users/@me/apple/status", get(apple_link_status))
        .route("/v1/users/@me/apple", axum::routing::delete(unlink_apple))
        .route(
            "/v1/users/@me/relationships",
            get(list_relationships).post(request_relationship),
        )
        .route(
            "/v1/users/@me/relationships/{target_id}",
            axum::routing::put(update_relationship).delete(delete_relationship),
        )
        .route(
            "/v1/users/@me/channels",
            get(list_direct_channels).post(open_direct_channel),
        )
        .route(
            "/v1/users/@me/devices/{device_id}",
            axum::routing::put(register_device_identity).delete(revoke_device_identity),
        )
        .route(
            "/v1/users/@me/devices/{device_id}/key-packages",
            axum::routing::post(publish_mls_key_packages),
        )
        .route(
            "/v1/users/@me/devices/{device_id}/mls/inbox",
            get(mls_inbox),
        )
        .route(
            "/v1/users/@me/devices/{device_id}/mls/maintenance",
            get(pending_mls_maintenance),
        )
        .route(
            "/v1/users/@me/devices/{device_id}/mls/inbox/ack",
            axum::routing::post(acknowledge_mls_delivery),
        )
        .route("/v1/users/{user_id}/devices", get(list_device_identities))
        .route("/v1/gateway", get(gateway_discovery))
        .route("/v1/sync", get(sync_snapshot))
        .route("/gateway", get(gateway))
        .route("/v1/guilds", get(list_guilds).post(create_guild))
        .route("/v1/guilds/{guild_id}", axum::routing::delete(delete_guild))
        .route(
            "/v1/guilds/{guild_id}/owner",
            axum::routing::put(transfer_guild_ownership),
        )
        .route(
            "/v1/guilds/{guild_id}/channels",
            get(list_channels).post(create_channel),
        )
        .route(
            "/v1/guilds/{guild_id}/messages/search",
            get(search_messages),
        )
        .route(
            "/v1/guilds/{guild_id}/invites",
            axum::routing::post(create_invite),
        )
        .route("/v1/guilds/{guild_id}/members", get(list_members))
        .route(
            "/v1/guilds/{guild_id}/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/v1/guilds/{guild_id}/automod/rules",
            get(list_automod_rules).post(create_automod_rule),
        )
        .route(
            "/v1/guilds/{guild_id}/automod/rules/{rule_id}",
            axum::routing::patch(update_automod_rule).delete(delete_automod_rule),
        )
        .route("/v1/guilds/{guild_id}/audit-log", get(list_audit_log))
        .route(
            "/v1/guilds/{guild_id}/roles/{role_id}",
            axum::routing::patch(update_role).delete(delete_role),
        )
        .route(
            "/v1/guilds/{guild_id}/members/{member_id}/roles/{role_id}",
            axum::routing::put(assign_member_role).delete(remove_member_role),
        )
        .route(
            "/v1/guilds/{guild_id}/members/{member_id}",
            axum::routing::patch(timeout_member).delete(kick_member),
        )
        .route("/v1/guilds/{guild_id}/bans", get(list_bans))
        .route(
            "/v1/guilds/{guild_id}/bans/{member_id}",
            axum::routing::put(ban_member).delete(unban_member),
        )
        .route(
            "/v1/invites/{code}",
            get(preview_invite).post(accept_invite),
        )
        .route(
            "/v1/channels/{channel_id}",
            axum::routing::patch(update_channel).delete(delete_channel),
        )
        .route(
            "/v1/channels/{channel_id}/overwrites",
            get(list_channel_overwrites),
        )
        .route(
            "/v1/channels/{channel_id}/overwrites/{target_kind}/{target_id}",
            axum::routing::put(set_channel_overwrite).delete(delete_channel_overwrite),
        )
        .route(
            "/v1/channels/{channel_id}/messages",
            get(list_messages).post(create_message),
        )
        .route(
            "/v1/channels/{channel_id}/messages/{message_id}",
            axum::routing::patch(update_message).delete(delete_message),
        )
        .route(
            "/v1/channels/{channel_id}/messages/{message_id}/reactions",
            axum::routing::put(add_reaction).delete(remove_reaction),
        )
        .route(
            "/v1/channels/{channel_id}/mls/key-packages/claim",
            axum::routing::post(claim_mls_key_packages),
        )
        .route(
            "/v1/channels/{channel_id}/mls/bootstrap",
            axum::routing::post(bootstrap_mls_group),
        )
        .route(
            "/v1/channels/{channel_id}/mls/members",
            axum::routing::post(update_mls_group),
        )
        .route(
            "/v1/channels/{channel_id}/read-state",
            axum::routing::put(acknowledge_read_state),
        )
        .route(
            "/v1/channels/{channel_id}/typing",
            axum::routing::post(start_typing),
        )
        .route(
            "/v1/channels/{channel_id}/attachments",
            axum::routing::post(reserve_attachments),
        )
        .route(
            "/v1/attachments/{attachment_id}/content",
            get(serve_attachment)
                .put(upload_attachment)
                .layer(DefaultBodyLimit::max(MAX_ATTACHMENT_BYTES as usize + 1)),
        )
        .route(
            "/v1/attachments/{attachment_id}/complete",
            axum::routing::post(complete_attachment),
        )
        .route(
            "/v1/channels/{channel_id}/voice-token",
            axum::routing::post(create_voice_token),
        )
        .route("/v1/reports", axum::routing::post(create_report))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(request_id))
        .layer(axum::middleware::from_fn_with_state(
            middleware_state,
            global_rate_limit,
        ))
        .layer(cors)
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn ready(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    state.repository.ready().await?;
    Ok(Json(serde_json::json!({
        "ready": true,
        "storage": state.repository.storage_name(),
        "auth": "password_sessions",
        "attachments": state.attachments.storage_name()
    })))
}

async fn auth_providers(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "password": true,
        "email": !matches!(&state.auth.delivery, EmailDelivery::Disabled),
        "apple": state.auth.apple.is_some(),
        "developmentCodePreview": state.allow_development_auth,
        "proofOfWork": true
    }))
}

async fn auth_challenge(
    State(state): State<AppState>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> ApiResult<Json<exo_safety::ProofOfWorkChallenge>> {
    let peer = peer.map(|axum::Extension(ConnectInfo(address))| address);
    let client_key = client_key(&state, &headers, peer);
    enforce_rate_limit(
        &state,
        format!("auth-challenge:{client_key}"),
        RateLimit::new(20, std::time::Duration::from_secs(60)),
        "c8b9384e",
        "shared",
    )?;
    state
        .proof_of_work
        .issue(client_key)
        .map(Json)
        .map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordAuthRequest {
    email: String,
    username: Option<String>,
    password: String,
    device_id: String,
    client_name: Option<String>,
    proof_of_work: Option<ProofOfWorkSolution>,
    account_id: Option<String>,
    wrapped_key: Option<WrappedAccountKey>,
    #[serde(default)]
    recovery_vaults: Vec<RecoveryKeyVaultRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
    wrapped_key: Option<WrappedAccountKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoverPasswordRequest {
    email: String,
    recovery_code: String,
    new_password: String,
    device_id: String,
    client_name: Option<String>,
    proof_of_work: Option<ProofOfWorkSolution>,
    account_id: Option<String>,
    wrapped_key: Option<WrappedAccountKey>,
    #[serde(default)]
    recovery_vaults: Vec<RecoveryKeyVaultRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparePasswordRecoveryRequest {
    email: String,
    recovery_code: String,
    proof_of_work: Option<ProofOfWorkSolution>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparePasswordRecoveryResponse {
    account_id: String,
    recovery_wrapped_key: Option<WrappedAccountKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmPasswordRequest {
    current_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetAccountKeyVaultRequest {
    current_password: String,
    wrapped_key: WrappedAccountKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetRecoveryKeyVaultsRequest {
    current_password: String,
    entries: Vec<RecoveryKeyVaultRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryKeyVaultRequest {
    recovery_code: String,
    wrapped_key: WrappedAccountKey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountKeyVaultResponse {
    wrapped_key: Option<WrappedAccountKey>,
    recovery_ready: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCodesResponse {
    recovery_codes: Vec<String>,
}

async fn register_password(
    State(state): State<AppState>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<PasswordAuthRequest>,
) -> ApiResult<Json<SessionBundle>> {
    let peer = peer.map(|axum::Extension(ConnectInfo(address))| address);
    let client_key = client_key(&state, &headers, peer);
    enforce_rate_limit(
        &state,
        format!("auth-register-ip:{client_key}"),
        RateLimit::new(5, std::time::Duration::from_secs(60 * 60)),
        "d53fc649",
        "shared",
    )?;
    let email_key = hex::encode(Sha256::digest(input.email.trim().to_ascii_lowercase()));
    enforce_rate_limit(
        &state,
        format!("auth-register-account:{email_key}"),
        RateLimit::new(3, std::time::Duration::from_secs(24 * 60 * 60)),
        "95a52fe5",
        "user",
    )?;
    verify_signup_proof(&state, &headers, peer, input.proof_of_work.as_ref())?;
    let username = input
        .username
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("choose a username to create an account"))?
        .trim()
        .to_ascii_lowercase();
    if username.len() < 3
        || username.len() > 32
        || !username
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        || !username
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(ApiError::bad_request(
            "username must be 3–32 letters, numbers, underscores, or hyphens and start with a letter or number",
        ));
    }
    let _registration_guard = state.registration_lock.lock().await;
    let registration_account_id = input
        .account_id
        .as_deref()
        .map(|value| {
            value
                .parse::<UserId>()
                .map_err(|_| ApiError::bad_request("account id is invalid"))
        })
        .transpose()?;
    if !state
        .repository
        .username_available(&username, registration_account_id)
        .await?
    {
        return Err(ApiError::conflict("that username is already taken"));
    }

    let auth = state.auth.clone();
    let registration_username = username.clone();
    let client_name = input
        .client_name
        .unwrap_or_else(|| "Exocord Desktop".to_owned());
    let session =
        tokio::task::spawn_blocking(move || match (input.account_id, input.wrapped_key) {
            (Some(account_id), Some(wrapped_key)) => {
                let account_id = account_id
                    .parse::<UserId>()
                    .map_err(|_| AuthError::InvalidRecoveryMaterial)?;
                let recovery_vaults = input
                    .recovery_vaults
                    .into_iter()
                    .map(|entry| RecoveryKeyVault {
                        recovery_code: entry.recovery_code,
                        wrapped_key: entry.wrapped_key,
                    })
                    .collect::<Vec<_>>();
                auth.register_password_provisioned_named(
                    &input.email,
                    Some(&registration_username),
                    &input.password,
                    &input.device_id,
                    &client_name,
                    account_id,
                    &wrapped_key,
                    &recovery_vaults,
                )
            }
            (None, None) if input.recovery_vaults.is_empty() => auth.register_password_named(
                &input.email,
                Some(&registration_username),
                &input.password,
                &input.device_id,
                &client_name,
            ),
            _ => Err(AuthError::InvalidRecoveryMaterial),
        })
        .await
        .map_err(|_| {
            ApiError::service_unavailable("password registration is temporarily unavailable")
        })??;
    ensure_authenticated_user(&state, &session.user).await?;
    Ok(Json(session))
}

async fn login_password(
    State(state): State<AppState>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<PasswordAuthRequest>,
) -> ApiResult<Json<SessionBundle>> {
    let peer = peer.map(|axum::Extension(ConnectInfo(address))| address);
    let client_key = client_key(&state, &headers, peer);
    enforce_rate_limit(
        &state,
        format!("auth-password-login-ip:{client_key}"),
        RateLimit::new(20, std::time::Duration::from_secs(15 * 60)),
        "1696ddfb",
        "shared",
    )?;
    let email_key = hex::encode(Sha256::digest(input.email.trim().to_ascii_lowercase()));
    enforce_rate_limit(
        &state,
        format!("auth-password-login-account:{email_key}"),
        RateLimit::new(10, std::time::Duration::from_secs(60 * 60)),
        "f3ceff87",
        "user",
    )?;
    verify_signup_proof(&state, &headers, peer, input.proof_of_work.as_ref())?;

    let auth = state.auth.clone();
    let client_name = input
        .client_name
        .unwrap_or_else(|| "Exocord Desktop".to_owned());
    let session = tokio::task::spawn_blocking(move || {
        auth.login_password(
            &input.email,
            &input.password,
            &input.device_id,
            &client_name,
        )
    })
    .await
    .map_err(|_| ApiError::service_unavailable("password sign-in is temporarily unavailable"))??;
    ensure_authenticated_user(&state, &session.user).await?;
    Ok(Json(session))
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    enforce_rate_limit(
        &state,
        format!("auth-password-change:{}", principal.user_id),
        RateLimit::new(5, std::time::Duration::from_secs(60 * 60)),
        "fa064c34",
        "user",
    )?;
    let auth = state.auth.clone();
    tokio::task::spawn_blocking(move || {
        auth.change_password(
            &principal,
            &input.current_password,
            &input.new_password,
            input.wrapped_key.as_ref(),
        )
    })
    .await
    .map_err(|_| ApiError::service_unavailable("password change is temporarily unavailable"))??;
    Ok(StatusCode::NO_CONTENT)
}

async fn recover_password(
    State(state): State<AppState>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<RecoverPasswordRequest>,
) -> ApiResult<Json<SessionBundle>> {
    let peer = peer.map(|axum::Extension(ConnectInfo(address))| address);
    let client_key = client_key(&state, &headers, peer);
    enforce_rate_limit(
        &state,
        format!("auth-password-recover-ip:{client_key}"),
        RateLimit::new(5, std::time::Duration::from_secs(60 * 60)),
        "469a7886",
        "shared",
    )?;
    let email_key = hex::encode(Sha256::digest(input.email.trim().to_ascii_lowercase()));
    enforce_rate_limit(
        &state,
        format!("auth-password-recover-account:{email_key}"),
        RateLimit::new(5, std::time::Duration::from_secs(24 * 60 * 60)),
        "3f5222ad",
        "user",
    )?;
    verify_signup_proof(&state, &headers, peer, input.proof_of_work.as_ref())?;

    let auth = state.auth.clone();
    let client_name = input
        .client_name
        .unwrap_or_else(|| "Exocord Desktop · Recovery".to_owned());
    let session = tokio::task::spawn_blocking(move || {
        match (input.account_id, input.wrapped_key) {
            (Some(account_id), Some(wrapped_key)) => {
                let account_id = account_id
                    .parse::<UserId>()
                    .map_err(|_| AuthError::InvalidRecoveryMaterial)?;
                let recovery_vaults = input
                    .recovery_vaults
                    .into_iter()
                    .map(|entry| RecoveryKeyVault {
                        recovery_code: entry.recovery_code,
                        wrapped_key: entry.wrapped_key,
                    })
                    .collect::<Vec<_>>();
                auth.recover_password_provisioned(
                    &input.email,
                    &input.recovery_code,
                    &input.new_password,
                    &input.device_id,
                    &client_name,
                    account_id,
                    &wrapped_key,
                    &recovery_vaults,
                )
            }
            (None, None) if input.recovery_vaults.is_empty() => auth.recover_password(
                &input.email,
                &input.recovery_code,
                &input.new_password,
                &input.device_id,
                &client_name,
            ),
            _ => Err(AuthError::InvalidRecoveryMaterial),
        }
    })
    .await
    .map_err(|_| ApiError::service_unavailable("password recovery is temporarily unavailable"))??;
    ensure_authenticated_user_after_provisioning(&state, &session.user).await;
    Ok(Json(session))
}

async fn prepare_password_recovery(
    State(state): State<AppState>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<PreparePasswordRecoveryRequest>,
) -> ApiResult<Json<PreparePasswordRecoveryResponse>> {
    let peer = peer.map(|axum::Extension(ConnectInfo(address))| address);
    let client_key = client_key(&state, &headers, peer);
    enforce_rate_limit(
        &state,
        format!("auth-password-recover-prepare-ip:{client_key}"),
        RateLimit::new(8, std::time::Duration::from_secs(60 * 60)),
        "d934bc72",
        "shared",
    )?;
    verify_signup_proof(&state, &headers, peer, input.proof_of_work.as_ref())?;
    let RecoveryPreparation {
        user_id,
        wrapped_key,
    } = state
        .auth
        .prepare_password_recovery(&input.email, &input.recovery_code)?;
    Ok(Json(PreparePasswordRecoveryResponse {
        account_id: user_id.to_string(),
        recovery_wrapped_key: wrapped_key,
    }))
}

async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ConfirmPasswordRequest>,
) -> ApiResult<Json<RecoveryCodesResponse>> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    enforce_rate_limit(
        &state,
        format!("auth-recovery-codes:{}", principal.user_id),
        RateLimit::new(3, std::time::Duration::from_secs(24 * 60 * 60)),
        "50fb1d72",
        "user",
    )?;
    let auth = state.auth.clone();
    let recovery_codes = tokio::task::spawn_blocking(move || {
        auth.regenerate_recovery_codes(&principal, &input.current_password)
    })
    .await
    .map_err(|_| {
        ApiError::service_unavailable("recovery-code replacement is temporarily unavailable")
    })??;
    Ok(Json(RecoveryCodesResponse { recovery_codes }))
}

async fn account_key_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AccountKeyVaultResponse>> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    state
        .auth
        .account_key_vault(&principal)
        .and_then(|wrapped_key| {
            state
                .auth
                .recovery_key_vaults_ready(&principal)
                .map(|recovery_ready| {
                    Json(AccountKeyVaultResponse {
                        wrapped_key,
                        recovery_ready,
                    })
                })
        })
        .map_err(Into::into)
}

async fn set_account_key_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SetAccountKeyVaultRequest>,
) -> ApiResult<StatusCode> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    enforce_rate_limit(
        &state,
        format!("account-key-vault:{}", principal.user_id),
        RateLimit::new(10, std::time::Duration::from_secs(60 * 60)),
        "cc1ec95d",
        "user",
    )?;
    state
        .auth
        .set_account_key_vault(&principal, &input.current_password, &input.wrapped_key)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_recovery_key_vaults(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SetRecoveryKeyVaultsRequest>,
) -> ApiResult<StatusCode> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    enforce_rate_limit(
        &state,
        format!("recovery-key-vaults:{}", principal.user_id),
        RateLimit::new(10, std::time::Duration::from_secs(60 * 60)),
        "f7e93fd2",
        "user",
    )?;
    let entries = input
        .entries
        .into_iter()
        .map(|entry| RecoveryKeyVault {
            recovery_code: entry.recovery_code,
            wrapped_key: entry.wrapped_key,
        })
        .collect::<Vec<_>>();
    state
        .auth
        .set_recovery_key_vaults(&principal, &input.current_password, &entries)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn private_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PrivateHistoryQuery>,
) -> ApiResult<Json<Vec<PrivateHistoryArchive>>> {
    let user_id = authenticated_user(&state, &headers)?;
    let before = query
        .before
        .map(|value| {
            MessageId::from_raw(parse_raw_id(&value, "private history cursor")?)
                .map_err(|_| ApiError::bad_request("invalid private history cursor"))
        })
        .transpose()?;
    state
        .repository
        .private_history(user_id, before, query.limit.unwrap_or(1_000))
        .await
        .map(Json)
        .map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrivateHistoryQuery {
    before: Option<String>,
    limit: Option<usize>,
}

async fn put_private_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(message_id): Path<String>,
    Json(archive): Json<PrivateHistoryArchive>,
) -> ApiResult<StatusCode> {
    let user_id = authenticated_user(&state, &headers)?;
    let routed_message_id = MessageId::from_raw(parse_raw_id(&message_id, "message")?)
        .map_err(|_| ApiError::bad_request("invalid message id"))?;
    if archive.message_id != routed_message_id {
        return Err(ApiError::bad_request(
            "private history message id does not match the route",
        ));
    }
    enforce_rate_limit(
        &state,
        format!("private-history:{user_id}"),
        RateLimit::new(120, std::time::Duration::from_secs(60)),
        "df708c33",
        "user",
    )?;
    state
        .repository
        .put_private_history(user_id, archive)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestEmailCode {
    email: String,
    proof_of_work: Option<ProofOfWorkSolution>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailCodeResponse {
    challenge_id: String,
    expires_in_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    development_code: Option<String>,
}

async fn request_email_code(
    State(state): State<AppState>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<RequestEmailCode>,
) -> ApiResult<Json<EmailCodeResponse>> {
    if matches!(&state.auth.delivery, EmailDelivery::Disabled) {
        return Err(ApiError::service_unavailable(
            "email-code sign-in is not configured",
        ));
    }
    let peer = peer.map(|axum::Extension(ConnectInfo(address))| address);
    let client_key = client_key(&state, &headers, peer);
    enforce_rate_limit(
        &state,
        format!("auth-login-ip:{client_key}"),
        RateLimit::new(5, std::time::Duration::from_secs(15 * 60)),
        "70f8f601",
        "shared",
    )?;
    let email_key = hex::encode(Sha256::digest(input.email.trim().to_ascii_lowercase()));
    enforce_rate_limit(
        &state,
        format!("auth-login-account:{email_key}"),
        RateLimit::new(10, std::time::Duration::from_secs(60 * 60)),
        "087c1529",
        "user",
    )?;
    verify_signup_proof(&state, &headers, peer, input.proof_of_work.as_ref())?;
    let challenge = state.auth.request_email_code(&input.email)?;
    match &state.auth.delivery {
        EmailDelivery::Disabled => {
            return Err(ApiError::service_unavailable(
                "email-code sign-in is not configured",
            ));
        }
        EmailDelivery::DevelopmentConsole => {
            tracing::info!(
                email = %challenge.email,
                code = %challenge.code,
                "development email sign-in code"
            );
        }
        EmailDelivery::Resend { api_key, from } => {
            let client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(3))
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|_| ApiError::service_unavailable("sign-in email is unavailable"))?;
            let response = client
                .post("https://api.resend.com/emails")
                .bearer_auth(api_key)
                .header("Idempotency-Key", &challenge.id)
                .json(&serde_json::json!({
                    "from": from,
                    "to": [challenge.email],
                    "subject": "Your Exocord sign-in code",
                    "text": format!(
                        "Your Exocord sign-in code is {}. It expires in 10 minutes.",
                        challenge.code
                    )
                }))
                .send()
                .await;
            let response = match response {
                Ok(response) => response,
                Err(_) => {
                    state.auth.cancel_email_challenge(&challenge.id)?;
                    return Err(ApiError::service_unavailable(
                        "sign-in email could not be sent",
                    ));
                }
            };
            if !response.status().is_success() {
                state.auth.cancel_email_challenge(&challenge.id)?;
                return Err(ApiError::service_unavailable(
                    "sign-in email provider rejected the request",
                ));
            }
        }
    }
    Ok(Json(EmailCodeResponse {
        challenge_id: challenge.id,
        expires_in_seconds: 600,
        development_code: state.allow_development_auth.then_some(challenge.code),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyEmailCode {
    challenge_id: String,
    code: String,
    device_id: String,
    client_name: Option<String>,
}

async fn verify_email_code(
    State(state): State<AppState>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<VerifyEmailCode>,
) -> ApiResult<Json<SessionBundle>> {
    let peer = peer.map(|axum::Extension(ConnectInfo(address))| address);
    enforce_rate_limit(
        &state,
        format!(
            "auth-verify:{}:{}",
            client_key(&state, &headers, peer),
            input.challenge_id
        ),
        RateLimit::new(5, std::time::Duration::from_secs(15 * 60)),
        "f392b81d",
        "shared",
    )?;
    let session = state.auth.verify_email_code(
        &input.challenge_id,
        &input.code,
        &input.device_id,
        input.client_name.as_deref().unwrap_or("Exocord"),
    )?;
    ensure_authenticated_user(&state, &session.user).await?;
    Ok(Json(session))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshSession {
    refresh_token: String,
}

async fn refresh_session(
    State(state): State<AppState>,
    Json(input): Json<RefreshSession>,
) -> ApiResult<Json<SessionBundle>> {
    state
        .auth
        .refresh(&input.refresh_token)
        .map(Json)
        .map_err(Into::into)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let principal = authenticated_principal(&state, &headers)?;
    state.auth.logout(&principal)?;
    match state.repository.list_guilds(principal.user_id).await {
        Ok(guilds) => {
            for guild in guilds {
                revoke_member_voice(&state, guild.id, principal.user_id);
            }
        }
        Err(error) => {
            tracing::warn!(
                %error,
                user_id = %principal.user_id,
                "logged-out voice sessions could not be enumerated for eviction"
            );
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn current_auth_user(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AuthUser>> {
    let principal = authenticated_principal(&state, &headers)?;
    state
        .auth
        .user(principal.user_id)
        .map(Json)
        .map_err(Into::into)
}

async fn current_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<User>> {
    let user_id = authenticated_user(&state, &headers)?;
    state
        .repository
        .snapshot(user_id, 0)
        .await
        .map(|snapshot| Json(snapshot.current_user))
        .map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProfileInput {
    handle: String,
    display_name: String,
    avatar_content_type: Option<String>,
    avatar_base64: Option<String>,
    #[serde(default)]
    remove_avatar: bool,
}

async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateProfileInput>,
) -> ApiResult<Json<User>> {
    let user_id = authenticated_user(&state, &headers)?;
    let handle = input.handle.trim().to_ascii_lowercase();
    if handle.len() < 3
        || handle.len() > 32
        || !handle
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        || !handle
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
    {
        return Err(ApiError::bad_request(
            "handle must be 3–32 letters, numbers, underscores, or hyphens and start with a letter or number",
        ));
    }
    let current_handle = state
        .repository
        .snapshot(user_id, 0)
        .await?
        .current_user
        .handle;
    if !handle.eq_ignore_ascii_case(&current_handle) {
        return Err(ApiError::conflict(
            "usernames are permanent; change your display name instead",
        ));
    }
    let display_name = input.display_name.trim();
    let display_characters = display_name.graphemes(true).count();
    if !(1..=32).contains(&display_characters) {
        return Err(ApiError::bad_request(
            "display name must contain between 1 and 32 characters",
        ));
    }
    if input.remove_avatar && input.avatar_base64.is_some() {
        return Err(ApiError::bad_request(
            "an avatar cannot be uploaded and removed in the same request",
        ));
    }
    let avatar = if input.remove_avatar {
        UserAvatarUpdate::Remove
    } else if let Some(encoded) = input.avatar_base64 {
        let bytes = STANDARD
            .decode(encoded.trim())
            .map_err(|_| ApiError::bad_request("avatar data is not valid base64"))?;
        if bytes.is_empty() || bytes.len() > 512 * 1024 {
            return Err(ApiError::bad_request(
                "avatar must be between 1 byte and 512 KiB",
            ));
        }
        let detected = infer::get(&bytes)
            .map(|kind| kind.mime_type())
            .ok_or_else(|| ApiError::bad_request("avatar image type could not be verified"))?;
        let content_type = input
            .avatar_content_type
            .as_deref()
            .unwrap_or(detected)
            .trim()
            .to_ascii_lowercase();
        if !matches!(detected, "image/png" | "image/jpeg" | "image/webp")
            || detected != content_type
        {
            return Err(ApiError::bad_request(
                "avatar must be a verified PNG, JPEG, or WebP image",
            ));
        }
        let dimensions = imagesize::blob_size(&bytes)
            .map_err(|_| ApiError::bad_request("avatar dimensions could not be verified"))?;
        if !(32..=1024).contains(&dimensions.width) || !(32..=1024).contains(&dimensions.height) {
            return Err(ApiError::bad_request(
                "avatar dimensions must be between 32 and 1024 pixels",
            ));
        }
        UserAvatarUpdate::Set(UserAvatarRecord {
            content_type,
            content_sha256: hex::encode(Sha256::digest(&bytes)),
            content: bytes,
            width: u32::try_from(dimensions.width)
                .map_err(|_| ApiError::bad_request("avatar width is invalid"))?,
            height: u32::try_from(dimensions.height)
                .map_err(|_| ApiError::bad_request("avatar height is invalid"))?,
        })
    } else {
        UserAvatarUpdate::Keep
    };
    let user = state
        .repository
        .update_profile(user_id, &handle, display_name, avatar)
        .await
        .map_err(|error| match error {
            RepositoryError::Conflict => ApiError::conflict("that handle is already taken"),
            other => other.into(),
        })?;
    if let Err(error) = state.auth.update_display_name(user_id, display_name) {
        if !state.allow_development_auth {
            return Err(error.into());
        }
        tracing::debug!(
            %error,
            %user_id,
            "development profile has no separate authentication record"
        );
    }
    match state.repository.presence_audience(user_id).await {
        Ok(recipients) => publish_user_event(&state, EventType::UserUpdate, &recipients, &user),
        Err(error) => tracing::warn!(
            %error,
            %user_id,
            "profile update could not publish a gateway user update"
        ),
    }
    Ok(Json(user))
}

async fn user_avatar(
    State(state): State<AppState>,
    Path((user_id, hash)): Path<(UserId, String)>,
) -> ApiResult<(HeaderMap, Bytes)> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::not_found("avatar"));
    }
    let avatar = state.repository.user_avatar(user_id, &hash).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&avatar.content_type)
            .map_err(|_| ApiError::internal("stored avatar type is invalid"))?,
    );
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok((headers, Bytes::from(avatar.content)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountDataExport {
    format: u8,
    generated_at: String,
    authentication: AuthDataExport,
    account: RepositoryDataExport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountDeletionStatus {
    deletion: Option<AccountDeletion>,
    owned_servers: Vec<OwnedServerStatus>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnedServerStatus {
    id: String,
    name: String,
    member_count: u32,
}

impl From<OwnedGuildRecord> for OwnedServerStatus {
    fn from(record: OwnedGuildRecord) -> Self {
        Self {
            id: record.guild.id.to_string(),
            name: record.guild.name,
            member_count: record.member_count,
        }
    }
}

async fn export_account_data(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<(HeaderMap, Json<AccountDataExport>)> {
    let principal = authenticated_principal(&state, &headers)?;
    enforce_rate_limit(
        &state,
        format!("account-export:{}", principal.user_id),
        RateLimit::new(2, std::time::Duration::from_secs(60 * 60)),
        "4ef65aed",
        "user",
    )?;
    let generated_at = Utc::now();
    let authentication = state.auth.data_export(principal.user_id)?;
    let account = state
        .repository
        .account_data_export(principal.user_id)
        .await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response_headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"exocord-data-export-{}.json\"",
            generated_at.format("%Y-%m-%d")
        ))
        .map_err(|_| ApiError::internal("data export filename is invalid"))?,
    );
    Ok((
        response_headers,
        Json(AccountDataExport {
            format: 1,
            generated_at: generated_at.to_rfc3339(),
            authentication,
            account,
        }),
    ))
}

async fn account_deletion_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AccountDeletionStatus>> {
    let principal = authenticated_principal(&state, &headers)?;
    let owned_servers = state
        .repository
        .owned_guilds(principal.user_id)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(Json(AccountDeletionStatus {
        deletion: state.auth.account_deletion(principal.user_id)?,
        owned_servers,
    }))
}

async fn schedule_account_deletion(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AccountDeletionStatus>> {
    let principal = authenticated_principal(&state, &headers)?;
    enforce_rate_limit(
        &state,
        format!("account-delete:{}", principal.user_id),
        RateLimit::new(2, std::time::Duration::from_secs(24 * 60 * 60)),
        "fb6974bd",
        "user",
    )?;
    let now = Utc::now();
    let ownership_blockers = state
        .repository
        .prepare_account_deletion(principal.user_id, now)
        .await?;
    if !ownership_blockers.is_empty() {
        let names = ownership_blockers
            .iter()
            .map(|record| record.guild.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ApiError::conflict(format!(
            "transfer ownership or delete these servers before deleting your account: {names}"
        )));
    }
    let devices = state
        .repository
        .list_device_identities(principal.user_id, principal.user_id)
        .await?;
    let guilds = state.repository.list_guilds(principal.user_id).await?;
    let deletion = match state.auth.schedule_account_deletion(&principal, now) {
        Ok(deletion) => deletion,
        Err(error) => {
            if let Err(cleanup_error) = state
                .repository
                .cancel_account_deletion_preparation(principal.user_id)
                .await
            {
                tracing::error!(
                    %cleanup_error,
                    user_id = %principal.user_id,
                    "failed to roll back server deletion preparation"
                );
            }
            return Err(error.into());
        }
    };
    {
        let mut revoked = state.revoked_gateway_devices.write().await;
        revoked.extend(devices.into_iter().map(|device| device.device_id));
    }
    for guild in guilds {
        revoke_member_voice(&state, guild.id, principal.user_id);
    }
    Ok(Json(AccountDeletionStatus {
        deletion: Some(deletion),
        owned_servers: Vec::new(),
    }))
}

async fn cancel_account_deletion(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let principal = authenticated_principal(&state, &headers)?;
    state.auth.cancel_account_deletion(&principal)?;
    state
        .repository
        .cancel_account_deletion_preparation(principal.user_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartAppleLogin {
    device_id: String,
    proof_of_work: Option<ProofOfWorkSolution>,
}

async fn start_apple_login(
    State(state): State<AppState>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(input): Json<StartAppleLogin>,
) -> ApiResult<Json<serde_json::Value>> {
    let peer = peer.map(|axum::Extension(ConnectInfo(address))| address);
    let client_key = client_key(&state, &headers, peer);
    enforce_rate_limit(
        &state,
        format!("auth-login-ip:{client_key}"),
        RateLimit::new(5, std::time::Duration::from_secs(15 * 60)),
        "70f8f601",
        "shared",
    )?;
    verify_signup_proof(&state, &headers, peer, input.proof_of_work.as_ref())?;
    let config = state
        .auth
        .apple
        .as_ref()
        .ok_or_else(|| ApiError::service_unavailable("Sign in with Apple is not configured"))?;
    let (flow_state, nonce) = state.auth.begin_apple_flow(&input.device_id)?;
    apple_authorization_response(config, flow_state, nonce)
}

fn apple_authorization_response(
    config: &crate::apple::AppleConfig,
    flow_state: String,
    nonce: String,
) -> ApiResult<Json<serde_json::Value>> {
    let mut url = url::Url::parse(&config.authorize_url)
        .map_err(|_| ApiError::service_unavailable("Apple authorization is unavailable"))?;
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "name email")
        .append_pair("response_mode", "form_post")
        .append_pair("state", &flow_state)
        .append_pair("nonce", &nonce);
    Ok(Json(serde_json::json!({
        "authorizationUrl": url.as_str(),
        "state": flow_state,
        "expiresInSeconds": 600
    })))
}

async fn account_auth_methods(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<auth::AccountAuthMethods>> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    state
        .auth
        .account_auth_methods(&principal)
        .map(Json)
        .map_err(Into::into)
}

async fn start_apple_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ConfirmPasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    enforce_rate_limit(
        &state,
        format!("auth-apple-link:{}", principal.user_id),
        RateLimit::new(5, std::time::Duration::from_secs(15 * 60)),
        "fa638c90",
        "user",
    )?;
    let config = state
        .auth
        .apple
        .clone()
        .ok_or_else(|| ApiError::service_unavailable("Sign in with Apple is not configured"))?;
    let auth = state.auth.clone();
    let (flow_state, nonce) = tokio::task::spawn_blocking(move || {
        auth.begin_apple_link(&principal, &input.current_password)
    })
    .await
    .map_err(|_| ApiError::service_unavailable("Apple linking is temporarily unavailable"))??;
    apple_authorization_response(&config, flow_state, nonce)
}

async fn apple_link_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AppleStatusQuery>,
) -> ApiResult<Response> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    match state.auth.poll_apple_link(&principal, &query.state)? {
        AppleLinkPoll::Pending => Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "pending" })),
        )
            .into_response()),
        AppleLinkPoll::Complete => Ok(Json(serde_json::json!({
            "status": "complete"
        }))
        .into_response()),
        AppleLinkPoll::Failed(message) => Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": 40_002,
                "message": message
            })),
        )
            .into_response()),
    }
}

async fn unlink_apple(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ConfirmPasswordRequest>,
) -> ApiResult<StatusCode> {
    let principal = authenticated_principal(&state, &headers)?;
    require_active_account(&state, principal.user_id)?;
    enforce_rate_limit(
        &state,
        format!("auth-apple-unlink:{}", principal.user_id),
        RateLimit::new(5, std::time::Duration::from_secs(60 * 60)),
        "6bd5a923",
        "user",
    )?;
    let auth = state.auth.clone();
    tokio::task::spawn_blocking(move || auth.unlink_apple(&principal, &input.current_password))
        .await
        .map_err(|_| {
            ApiError::service_unavailable("Apple unlinking is temporarily unavailable")
        })??;
    Ok(StatusCode::NO_CONTENT)
}

fn verify_signup_proof(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    solution: Option<&ProofOfWorkSolution>,
) -> ApiResult<()> {
    let Some(solution) = solution else {
        if state.allow_development_auth {
            return Ok(());
        }
        return Err(ApiError::proof_required());
    };
    state
        .proof_of_work
        .verify(&client_key(state, headers, peer), solution)
        .map_err(Into::into)
}

fn client_key(state: &AppState, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if state.trust_proxy_headers {
        // The edge proxy overwrites this dedicated header. Never trust
        // client-controlled forwarding headers such as CF-Connecting-IP or
        // X-Forwarded-For here.
        if let Some(ip) = header_ip(headers, "x-exocord-proxy-client-ip") {
            return ip.to_string();
        }
    }
    if let Some(address) = peer {
        return address.ip().to_string();
    }
    if state.allow_development_auth
        && let Some(ip) = header_ip(headers, "x-exocord-client-ip")
    {
        return ip.to_string();
    }
    "unavailable".into()
}

fn header_ip(headers: &HeaderMap, name: &'static str) -> Option<IpAddr> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
}

#[derive(Deserialize)]
struct AppleCallback {
    code: Option<String>,
    state: String,
    user: Option<String>,
    error: Option<String>,
}

async fn apple_callback(
    State(state): State<AppState>,
    Form(input): Form<AppleCallback>,
) -> Html<String> {
    let linking = state
        .auth
        .apple_flow(&input.state)
        .is_ok_and(|flow| flow.linking);
    let result = async {
        if input.error.is_some() {
            state
                .auth
                .fail_apple_flow(&input.state, "Apple sign-in was cancelled")?;
            return Ok::<bool, AuthError>(false);
        }
        let flow = state.auth.apple_flow(&input.state)?;
        let config = state.auth.apple.clone().ok_or(AuthError::AppleFailure)?;
        let code = input.code.as_deref().ok_or(AuthError::AppleFailure)?;
        let identity = AppleClient::new(config)
            .map_err(|_| AuthError::AppleFailure)?
            .exchange_code(code, &flow.nonce)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "Sign in with Apple verification failed");
                AuthError::AppleFailure
            })?;
        let display_name = input.user.as_deref().and_then(apple_display_name);
        state.auth.complete_apple_flow(
            &input.state,
            &identity.subject,
            &identity.email,
            display_name.as_deref(),
            &identity.refresh_token,
        )?;
        Ok(true)
    }
    .await;
    let success = result.as_ref().copied().unwrap_or(false);
    if let Err(error) = result {
        tracing::warn!(%error, "Apple callback could not complete");
        if let Err(flow_error) = state
            .auth
            .fail_apple_flow(&input.state, "Apple sign-in could not be completed")
        {
            tracing::warn!(%flow_error, "Apple callback failure state could not be recorded");
        }
    }
    Html(apple_callback_page(success, linking))
}

#[derive(Deserialize)]
struct AppleStatusQuery {
    state: String,
}

async fn apple_login_status(
    State(state): State<AppState>,
    Query(query): Query<AppleStatusQuery>,
) -> ApiResult<Response> {
    match state.auth.poll_apple_flow(&query.state)? {
        AppleFlowPoll::Pending => Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "pending" })),
        )
            .into_response()),
        AppleFlowPoll::Complete(session) => {
            ensure_authenticated_user(&state, &session.user).await?;
            Ok(Json(*session).into_response())
        }
        AppleFlowPoll::Failed(message) => Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": 40_002,
                "message": message
            })),
        )
            .into_response()),
    }
}

fn apple_display_name(user: &str) -> Option<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AppleUser {
        name: Option<AppleName>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AppleName {
        first_name: Option<String>,
        last_name: Option<String>,
    }
    let user = serde_json::from_str::<AppleUser>(user).ok()?;
    let name = user.name?;
    let value = [name.first_name, name.last_name]
        .into_iter()
        .flatten()
        .map(|part| part.trim().to_owned())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!value.is_empty()).then_some(value)
}

fn apple_callback_page(success: bool, linking: bool) -> String {
    let (title, body, accent) = if success && linking {
        (
            "Apple is connected",
            "Return to Exocord. This tab can close safely.",
            "#70dcb7",
        )
    } else if success {
        (
            "You’re signed in",
            "Return to Exocord. This tab can close safely.",
            "#69d7bd",
        )
    } else {
        (
            "Sign-in didn’t finish",
            "Return to Exocord and try again.",
            "#ff8e8e",
        )
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width\"><title>{title} · Exocord</title><style>\
         html{{color-scheme:dark}}body{{margin:0;min-height:100vh;display:grid;place-items:center;\
         background:#090a0d;color:#f4f4f6;font:15px system-ui}}main{{width:min(420px,calc(100% - \
         48px));padding:36px;border:1px solid #262830;border-radius:22px;background:#14151a;\
         box-shadow:0 30px 100px #0008}}b{{color:{accent};letter-spacing:.18em;font-size:10px}}\
         h1{{font-size:32px;letter-spacing:-.04em;margin:12px 0}}p{{color:#989da7;line-height:1.6}}\
         button{{margin-top:12px;padding:11px 16px;border:0;border-radius:10px;background:#8b7cff;\
         color:white;font-weight:650}}</style></head><body><main><b>EXOCORD</b><h1>{title}</h1>\
         <p>{body}</p><button onclick=\"window.close()\">Close this tab</button></main></body></html>"
    )
}

async fn ensure_authenticated_user(state: &AppState, user: &AuthUser) -> ApiResult<()> {
    let user_id = user
        .id
        .parse::<UserId>()
        .map_err(|_| ApiError::internal("authenticated user id is invalid"))?;
    let handle = state
        .auth
        .username(user_id)?
        .unwrap_or_else(|| user.email.split('@').next().unwrap_or("member").to_owned());
    state
        .repository
        .ensure_user(
            User {
                id: user_id,
                handle,
                display_name: user.display_name.clone(),
                avatar_url: None,
                created_at: Utc::now(),
            },
            Some(&user.email),
        )
        .await?;
    Ok(())
}

async fn ensure_authenticated_user_after_provisioning(state: &AppState, user: &AuthUser) {
    if let Err(error) = ensure_authenticated_user(state, user).await {
        tracing::warn!(
            ?error,
            user_id = %user.id,
            "account authentication completed before its profile record; scheduling repair"
        );
        let state = state.clone();
        let user = user.clone();
        tokio::spawn(async move {
            for attempt in 1..=30 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                match ensure_authenticated_user(&state, &user).await {
                    Ok(()) => {
                        tracing::info!(
                            user_id = %user.id,
                            attempt,
                            "repaired authenticated account profile"
                        );
                        return;
                    }
                    Err(error) if attempt == 30 => {
                        tracing::error!(
                            ?error,
                            user_id = %user.id,
                            "authenticated account profile repair was exhausted"
                        );
                    }
                    Err(_) => {}
                }
            }
        });
    }
}

async fn platform_capabilities(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "discord": discord_capabilities(DiscordIntegrationMode::StandardOauth),
        "native_voice": if state.voice.is_some() {
            "livekit_sframe_mls_exporter"
        } else {
            "not_configured"
        },
        "attachments": if state.attachments.available() {
            format!("{}_plus_client_aes_256_gcm", state.attachments.storage_name())
        } else {
            "not_configured".to_owned()
        },
        "conversation_actions": "replies_edits_deletes_unicode_reactions",
        "message_search": "plaintext_server_plus_encrypted_device",
        "relationships": "native_exact_handle",
        "direct_messages": "native_one_to_one_mls_e2ee",
        "presence": "gateway_scoped",
        "typing": "ephemeral_gateway",
        "read_state": "durable_per_channel",
        "automod": "durable_compiled_rules",
        "audit_log": "permission_scoped",
        "reports": "verified_message_franking_opening",
        "rate_limits": "gcra_scoped",
        "signup_proof_of_work": "adaptive_sha256",
        "password_storage": "argon2id_19mib_t2_p1_unique_salt",
        "e2ee": "openmls_suite_1_native_devices",
        "device_revocation": "session_cutoff_plus_durable_mls_remove",
        "account_data": "direct_json_export_plus_30_day_anonymization_with_ownership_gate",
        "server_ownership": "atomic_transfer_plus_policy_retained_retirement"
    }))
}

async fn operator_info(State(state): State<AppState>) -> Json<OperatorInfo> {
    Json(state.operator)
}

async fn privacy_policy(State(state): State<AppState>) -> Response {
    policy_response(PRIVACY_POLICY_TEMPLATE, &state.operator)
}

async fn terms_policy(State(state): State<AppState>) -> Response {
    policy_response(TERMS_POLICY_TEMPLATE, &state.operator)
}

fn policy_response(template: &str, operator: &OperatorInfo) -> Response {
    let support = operator
        .support_email
        .as_deref()
        .unwrap_or("not-configured@example.invalid");
    let abuse = operator
        .abuse_email
        .as_deref()
        .unwrap_or("not-configured@example.invalid");
    let body = template
        .replace("{{OPERATOR_NAME}}", &escape_html(&operator.name))
        .replace("{{SUPPORT_EMAIL}}", &escape_html(support))
        .replace("{{ABUSE_EMAIL}}", &escape_html(abuse));
    (
        [
            ("cache-control", "public, max-age=300"),
            (
                "content-security-policy",
                "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; \
                 form-action 'none'; frame-ancestors 'none'",
            ),
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
        ],
        Html(body),
    )
        .into_response()
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

async fn gateway_discovery() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "url": "/gateway",
        "shards": 1,
        "session_start_limit": {
            "total": 1_000,
            "remaining": 1_000,
            "reset_after_ms": 0
        }
    }))
}

async fn sync_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SyncSnapshot>> {
    let user_id = authenticated_user(&state, &headers)?;
    let last_sequence = state
        .next_sequence
        .load(Ordering::Relaxed)
        .saturating_sub(1);
    let mut snapshot = state
        .repository
        .snapshot(user_id, last_sequence)
        .await
        .map_err(ApiError::from)?;
    snapshot.presences = online_presences(&state, &snapshot).await;
    Ok(Json(snapshot))
}

#[derive(Deserialize)]
struct FriendRequestInput {
    handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelationshipActionInput {
    Accept,
    Block,
}

#[derive(Deserialize)]
struct UpdateRelationshipInput {
    action: RelationshipActionInput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RelationshipChanged {
    user_id: UserId,
}

async fn list_relationships(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Relationship>>> {
    state
        .repository
        .list_relationships(authenticated_user(&state, &headers)?)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn request_relationship(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<FriendRequestInput>,
) -> ApiResult<(StatusCode, Json<Relationship>)> {
    let user_id = authenticated_user(&state, &headers)?;
    let handle = input.handle.trim();
    if handle.is_empty() || handle.chars().count() > 64 {
        return Err(ApiError::bad_request(
            "friend handle must contain between 1 and 64 characters",
        ));
    }
    let relationship = state
        .repository
        .request_relationship(user_id, handle)
        .await?;
    let target_id = relationship.user.id;
    publish_user_event(
        &state,
        EventType::RelationshipUpdate,
        &[user_id, target_id],
        &RelationshipChanged { user_id },
    );
    Ok((StatusCode::CREATED, Json(relationship)))
}

async fn update_relationship(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(target_id): Path<String>,
    Json(input): Json<UpdateRelationshipInput>,
) -> ApiResult<Json<Relationship>> {
    let user_id = authenticated_user(&state, &headers)?;
    let target_id = parse_user_id(&target_id)?;
    let action = match input.action {
        RelationshipActionInput::Accept => RelationshipAction::Accept,
        RelationshipActionInput::Block => RelationshipAction::Block,
    };
    let relationship = state
        .repository
        .update_relationship(user_id, target_id, action)
        .await?;
    publish_user_event(
        &state,
        EventType::RelationshipUpdate,
        &[user_id, target_id],
        &RelationshipChanged { user_id },
    );
    Ok(Json(relationship))
}

async fn delete_relationship(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(target_id): Path<String>,
) -> ApiResult<StatusCode> {
    let user_id = authenticated_user(&state, &headers)?;
    let target_id = parse_user_id(&target_id)?;
    state
        .repository
        .delete_relationship(user_id, target_id)
        .await?;
    publish_user_event(
        &state,
        EventType::RelationshipUpdate,
        &[user_id, target_id],
        &RelationshipChanged { user_id },
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenDirectChannelInput {
    recipient_id: UserId,
}

async fn list_direct_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<DirectChannel>>> {
    state
        .repository
        .list_direct_channels(authenticated_user(&state, &headers)?)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn open_direct_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OpenDirectChannelInput>,
) -> ApiResult<(StatusCode, Json<DirectChannel>)> {
    let user_id = authenticated_user(&state, &headers)?;
    let channel = state
        .repository
        .open_direct_channel(user_id, input.recipient_id)
        .await?;
    let recipients = channel
        .recipients
        .iter()
        .map(|recipient| recipient.id)
        .collect::<Vec<_>>();
    publish_user_event(
        &state,
        EventType::DirectChannelCreate,
        &recipients,
        &channel,
    );
    Ok((StatusCode::CREATED, Json(channel)))
}

async fn register_device_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(input): Json<RegisterDeviceIdentity>,
) -> ApiResult<Json<DeviceIdentity>> {
    let device_id = parse_device_id(&device_id)?;
    let principal = authenticated_device_principal(&state, &headers)?;
    if principal.device_id != device_id {
        return Err(ApiError::forbidden_message(
            "a session may register only its own device identity",
        ));
    }
    let signature_key = decode_base64url(&input.signature_key, "device signature key", 32)?
        .try_into()
        .map_err(|_| ApiError::bad_request("device signature key must contain exactly 32 bytes"))?;
    let name = input
        .name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    if name.as_ref().is_some_and(|name| name.chars().count() > 64) {
        return Err(ApiError::bad_request(
            "device name may contain at most 64 characters",
        ));
    }
    let identity = state
        .repository
        .register_device_identity(principal.user_id, device_id, signature_key, name)
        .await?;
    Ok(Json(device_identity_response(identity)))
}

async fn list_device_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResult<Json<Vec<DeviceIdentity>>> {
    let requester_id = authenticated_user(&state, &headers)?;
    let user_id = parse_user_id(&user_id)?;
    state
        .repository
        .list_device_identities(requester_id, user_id)
        .await
        .map(|identities| {
            Json(
                identities
                    .into_iter()
                    .map(device_identity_response)
                    .collect(),
            )
        })
        .map_err(Into::into)
}

async fn revoke_device_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> ApiResult<StatusCode> {
    let device_id = parse_device_id(&device_id)?;
    let principal = authenticated_device_principal(&state, &headers)?;
    if principal.device_id == device_id {
        return Err(ApiError::bad_request(
            "sign out this device instead; another active device must revoke it",
        ));
    }
    let channels = state
        .repository
        .revoke_device_identity(principal.user_id, device_id)
        .await?;
    if principal.session_id != "development" {
        state
            .auth
            .revoke_device_sessions(principal.user_id, device_id)?;
    }
    state
        .revoked_gateway_devices
        .write()
        .await
        .insert(device_id);
    if let Ok(guilds) = state.repository.list_guilds(principal.user_id).await {
        for guild in guilds {
            revoke_member_voice(&state, guild.id, principal.user_id);
        }
    }

    for channel_id in channels {
        let audience = state
            .repository
            .mls_channel_audience(principal.user_id, channel_id)
            .await?;
        let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
        let hint = MlsMembershipHint {
            channel_id,
            revoked_device_ids: vec![device_id],
        };
        match audience {
            MessageAudience::Users(recipients) => publish_user_routed_event(
                &state,
                EventType::MlsKeyPackageConsumed,
                sequence,
                channel_id,
                &recipients,
                &hint,
            ),
            MessageAudience::Guild(guild_id) => publish_routed_event(
                &state,
                EventType::MlsKeyPackageConsumed,
                sequence,
                RoutingMetadata {
                    guild_id: guild_id.raw(),
                    channel_id: channel_id.raw(),
                },
                &hint,
            ),
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn publish_mls_key_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(input): Json<PublishMlsKeyPackages>,
) -> ApiResult<(StatusCode, Json<Vec<MlsKeyPackage>>)> {
    let device_id = parse_device_id(&device_id)?;
    let principal = authenticated_device_principal(&state, &headers)?;
    if principal.device_id != device_id {
        return Err(ApiError::forbidden_message(
            "a session may publish keys only for its own device",
        ));
    }
    if input.packages.is_empty() || input.packages.len() > 100 {
        return Err(ApiError::bad_request(
            "publish between 1 and 100 MLS KeyPackages at a time",
        ));
    }
    let mut unique = HashSet::with_capacity(input.packages.len());
    let packages = input
        .packages
        .into_iter()
        .map(|package| {
            if package.cipher_suite != 1 {
                return Err(ApiError::bad_request(
                    "only MLS cipher suite 1 is supported",
                ));
            }
            let reference: [u8; 32] =
                decode_base64url(&package.reference, "MLS KeyPackage reference", 32)?
                    .try_into()
                    .map_err(|_| {
                        ApiError::bad_request(
                            "MLS KeyPackage reference must contain exactly 32 bytes",
                        )
                    })?;
            if !unique.insert(reference) {
                return Err(ApiError::bad_request(
                    "an MLS KeyPackage reference may appear only once",
                ));
            }
            let key_package = decode_base64url(&package.key_package, "MLS KeyPackage", 65_535)?;
            if key_package.len() < 64 {
                return Err(ApiError::bad_request("MLS KeyPackage is too short"));
            }
            Ok((reference, key_package, package.cipher_suite))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let published = state
        .repository
        .publish_mls_key_packages(principal.user_id, device_id, packages)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            published
                .into_iter()
                .map(mls_key_package_response)
                .collect(),
        ),
    ))
}

async fn claim_mls_key_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> ApiResult<Json<Vec<MlsKeyPackage>>> {
    let principal = authenticated_device_principal(&state, &headers)?;
    let channel_id = parse_channel_id(&channel_id)?;
    let audience = state
        .repository
        .mls_channel_audience(principal.user_id, channel_id)
        .await?;
    let packages = match state
        .repository
        .claim_mls_key_packages(principal.user_id, principal.device_id, channel_id)
        .await
    {
        Ok(packages) => packages,
        Err(RepositoryError::Conflict) => {
            let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
            let hint = MlsMembershipHint {
                channel_id,
                revoked_device_ids: Vec::new(),
            };
            match audience {
                MessageAudience::Users(recipients) => publish_user_routed_event(
                    &state,
                    EventType::MlsKeyPackageConsumed,
                    sequence,
                    channel_id,
                    &recipients,
                    &hint,
                ),
                MessageAudience::Guild(guild_id) => publish_routed_event(
                    &state,
                    EventType::MlsKeyPackageConsumed,
                    sequence,
                    RoutingMetadata {
                        guild_id: guild_id.raw(),
                        channel_id: channel_id.raw(),
                    },
                    &hint,
                ),
            }
            return Err(RepositoryError::Conflict.into());
        }
        Err(error) => return Err(error.into()),
    };
    Ok(Json(
        packages.into_iter().map(mls_key_package_response).collect(),
    ))
}

async fn bootstrap_mls_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Json(input): Json<BootstrapMlsGroup>,
) -> ApiResult<StatusCode> {
    let principal = authenticated_device_principal(&state, &headers)?;
    let channel_id = parse_channel_id(&channel_id)?;
    if input.epoch != 1 {
        return Err(ApiError::bad_request(
            "an initial MLS group must start at epoch 1",
        ));
    }
    let group_id = decode_base64url(&input.group_id, "MLS group id", 255)?;
    if group_id.len() < 16 {
        return Err(ApiError::bad_request("MLS group id is too short"));
    }
    let commit = decode_base64url(&input.commit, "MLS commit", 1_048_576)?;
    if commit.is_empty() {
        return Err(ApiError::bad_request("MLS commit is empty"));
    }
    let audience = state
        .repository
        .mls_channel_audience(principal.user_id, channel_id)
        .await?;
    if input.welcomes.len() > 100
        || (input.welcomes.is_empty() && matches!(&audience, MessageAudience::Users(_)))
    {
        return Err(ApiError::bad_request(
            "MLS bootstrap has an invalid Welcome set",
        ));
    }
    let welcomes = input
        .welcomes
        .into_iter()
        .map(|welcome| {
            Ok(MlsWelcomeRecord {
                device_id: welcome.device_id,
                key_package_reference: decode_base64url(
                    &welcome.key_package_reference,
                    "MLS KeyPackage reference",
                    32,
                )?
                .try_into()
                .map_err(|_| {
                    ApiError::bad_request("MLS KeyPackage reference must contain exactly 32 bytes")
                })?,
                payload: decode_base64url(&welcome.payload, "MLS Welcome", 1_048_576)?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let deliveries = state
        .repository
        .bootstrap_mls_group(
            principal.user_id,
            principal.device_id,
            channel_id,
            group_id,
            input.epoch,
            commit,
            welcomes,
        )
        .await?;
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    match audience {
        MessageAudience::Users(recipients) => {
            for delivery in deliveries
                .iter()
                .filter(|delivery| delivery.kind == MlsDeliveryRecordKind::Welcome)
            {
                publish_user_routed_event(
                    &state,
                    EventType::MlsWelcome,
                    sequence,
                    channel_id,
                    &recipients,
                    &mls_delivery_response(delivery.clone()),
                );
            }
            publish_user_routed_event(
                &state,
                EventType::E2eeChannelEnabled,
                sequence,
                channel_id,
                &recipients,
                &serde_json::json!({ "channelId": channel_id }),
            );
        }
        MessageAudience::Guild(guild_id) => publish_routed_event(
            &state,
            EventType::E2eeChannelEnabled,
            sequence,
            RoutingMetadata {
                guild_id: guild_id.raw(),
                channel_id: channel_id.raw(),
            },
            &serde_json::json!({ "channelId": channel_id }),
        ),
    }
    Ok(StatusCode::CREATED)
}

async fn update_mls_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Json(input): Json<UpdateMlsGroup>,
) -> ApiResult<StatusCode> {
    let principal = authenticated_device_principal(&state, &headers)?;
    let channel_id = parse_channel_id(&channel_id)?;
    if input.epoch < 2 {
        return Err(ApiError::bad_request(
            "an MLS membership update must advance beyond epoch 1",
        ));
    }
    if (input.welcomes.is_empty() && input.removed_device_ids.is_empty())
        || input.welcomes.len() > 100
        || input.removed_device_ids.len() > 100
    {
        return Err(ApiError::bad_request(
            "an MLS membership update must add or remove between 1 and 100 devices",
        ));
    }
    let removed_device_ids = input
        .removed_device_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    if removed_device_ids.len() != input.removed_device_ids.len()
        || removed_device_ids.contains(&principal.device_id)
    {
        return Err(ApiError::bad_request(
            "MLS removal device ids must be distinct and cannot include the sender",
        ));
    }
    let group_id = decode_base64url(&input.group_id, "MLS group id", 255)?;
    if group_id.len() < 16 {
        return Err(ApiError::bad_request("MLS group id is too short"));
    }
    let commit = decode_base64url(&input.commit, "MLS commit", 1_048_576)?;
    if commit.is_empty() {
        return Err(ApiError::bad_request("MLS commit is empty"));
    }
    let welcomes = input
        .welcomes
        .into_iter()
        .map(|welcome| {
            Ok(MlsWelcomeRecord {
                device_id: welcome.device_id,
                key_package_reference: decode_base64url(
                    &welcome.key_package_reference,
                    "MLS KeyPackage reference",
                    32,
                )?
                .try_into()
                .map_err(|_| {
                    ApiError::bad_request("MLS KeyPackage reference must contain exactly 32 bytes")
                })?,
                payload: decode_base64url(&welcome.payload, "MLS Welcome", 1_048_576)?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let audience = state
        .repository
        .mls_channel_audience(principal.user_id, channel_id)
        .await?;
    let deliveries = state
        .repository
        .update_mls_group(
            principal.user_id,
            principal.device_id,
            channel_id,
            group_id,
            input.epoch,
            commit,
            welcomes,
            input.removed_device_ids,
        )
        .await?;
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    let hint = MlsMembershipHint {
        channel_id,
        revoked_device_ids: Vec::new(),
    };
    let event_type = if deliveries
        .iter()
        .any(|delivery| delivery.kind == MlsDeliveryRecordKind::Commit)
    {
        EventType::MlsCommit
    } else {
        EventType::MlsWelcome
    };
    match audience {
        MessageAudience::Users(recipients) => {
            publish_user_routed_event(&state, event_type, sequence, channel_id, &recipients, &hint)
        }
        MessageAudience::Guild(guild_id) => publish_routed_event(
            &state,
            event_type,
            sequence,
            RoutingMetadata {
                guild_id: guild_id.raw(),
                channel_id: channel_id.raw(),
            },
            &hint,
        ),
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn mls_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> ApiResult<Json<Vec<MlsWelcomeDelivery>>> {
    let device_id = parse_device_id(&device_id)?;
    let principal = authenticated_device_principal(&state, &headers)?;
    if principal.device_id != device_id {
        return Err(ApiError::forbidden_message(
            "a session may read only its own MLS inbox",
        ));
    }
    state
        .repository
        .mls_inbox(principal.user_id, device_id)
        .await
        .map(|deliveries| Json(deliveries.into_iter().map(mls_delivery_response).collect()))
        .map_err(Into::into)
}

async fn pending_mls_maintenance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> ApiResult<Json<Vec<MlsMembershipHint>>> {
    let device_id = parse_device_id(&device_id)?;
    let principal = authenticated_device_principal(&state, &headers)?;
    if principal.device_id != device_id {
        return Err(ApiError::forbidden_message(
            "a session may request maintenance only for its own device",
        ));
    }
    state
        .repository
        .pending_mls_removals(principal.user_id, device_id)
        .await
        .map(|pending| {
            Json(
                pending
                    .into_iter()
                    .map(|(channel_id, revoked_device_ids)| MlsMembershipHint {
                        channel_id,
                        revoked_device_ids,
                    })
                    .collect(),
            )
        })
        .map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcknowledgeMlsDelivery {
    group_id: String,
    epoch: u64,
    sequence: u64,
}

async fn acknowledge_mls_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(input): Json<AcknowledgeMlsDelivery>,
) -> ApiResult<StatusCode> {
    let device_id = parse_device_id(&device_id)?;
    let principal = authenticated_device_principal(&state, &headers)?;
    if principal.device_id != device_id {
        return Err(ApiError::forbidden_message(
            "a session may acknowledge only its own MLS inbox",
        ));
    }
    let group_id = decode_base64url(&input.group_id, "MLS group id", 255)?;
    state
        .repository
        .acknowledge_mls_delivery(
            principal.user_id,
            device_id,
            &group_id,
            input.epoch,
            input.sequence,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadStateInput {
    last_message_id: MessageId,
}

async fn acknowledge_read_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Json(input): Json<ReadStateInput>,
) -> ApiResult<Json<ReadState>> {
    let user_id = authenticated_user(&state, &headers)?;
    let read_state = state
        .repository
        .acknowledge_read_state(
            user_id,
            parse_channel_id(&channel_id)?,
            input.last_message_id,
        )
        .await?;
    publish_user_event(&state, EventType::ReadStateUpdate, &[user_id], &read_state);
    Ok(Json(read_state))
}

async fn start_typing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> ApiResult<StatusCode> {
    let user_id = authenticated_user(&state, &headers)?;
    let channel_id = parse_channel_id(&channel_id)?;
    enforce_rate_limit(
        &state,
        format!("typing:{user_id}:{channel_id}"),
        RateLimit::new(1, std::time::Duration::from_secs(8)),
        "924ff9b0",
        "user",
    )?;
    let audience = state
        .repository
        .channel_event_audience(user_id, channel_id, true)
        .await?;
    let now = Utc::now();
    {
        let mut leases = state.typing_leases.lock().await;
        leases.retain(|_, last| *last > now - ChronoDuration::minutes(1));
        if leases
            .get(&(user_id, channel_id))
            .is_some_and(|last| *last > now - ChronoDuration::seconds(3))
        {
            return Ok(StatusCode::NO_CONTENT);
        }
        leases.insert((user_id, channel_id), now);
    }
    let event = TypingEvent {
        channel_id,
        user_id,
        expires_at: now + ChronoDuration::seconds(8),
    };
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    match audience {
        MessageAudience::Guild(guild_id) => publish_routed_event(
            &state,
            EventType::TypingStart,
            sequence,
            RoutingMetadata {
                guild_id: guild_id.raw(),
                channel_id: channel_id.raw(),
            },
            &event,
        ),
        MessageAudience::Users(recipients) => publish_user_routed_event(
            &state,
            EventType::TypingStart,
            sequence,
            channel_id,
            &recipients,
            &event,
        ),
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn online_presences(state: &AppState, snapshot: &SyncSnapshot) -> Vec<UserPresence> {
    let connections = state.presence_connections.lock().await;
    snapshot
        .users
        .iter()
        .map(|user| user.id)
        .chain(std::iter::once(snapshot.current_user.id))
        .filter(|user_id| connections.get(user_id).copied().unwrap_or_default() > 0)
        .map(|user_id| UserPresence {
            user_id,
            status: PresenceStatus::Online,
            updated_at: Utc::now(),
        })
        .collect()
}

async fn global_rate_limit(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !request.uri().path().starts_with("/v1/") {
        return next.run(request).await;
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| *address);
    let identity = authenticated_user(&state, request.headers()).map_or_else(
        |_| format!("ip:{}", client_key(&state, request.headers(), peer)),
        |user_id| format!("user:{user_id}"),
    );
    let metadata = rate_metadata(
        &state,
        &format!("global:{identity}"),
        RateLimit::new(50, std::time::Duration::from_secs(1)),
        "0f5fd74c",
        "user",
        true,
    );
    if !metadata.decision.allowed {
        return ApiError::rate_limited(metadata).into_response();
    }
    let mut response = next.run(request).await;
    apply_rate_limit_headers(response.headers_mut(), &metadata);
    response
}

fn enforce_rate_limit(
    state: &AppState,
    key: String,
    policy: RateLimit,
    bucket: &'static str,
    scope: &'static str,
) -> ApiResult<()> {
    let metadata = rate_metadata(state, &key, policy, bucket, scope, false);
    if metadata.decision.allowed {
        Ok(())
    } else {
        Err(ApiError::rate_limited(metadata))
    }
}

fn rate_metadata(
    state: &AppState,
    key: &str,
    policy: RateLimit,
    bucket: &'static str,
    scope: &'static str,
    global: bool,
) -> RateMetadata {
    RateMetadata {
        decision: state.rate_limiter.check(key, policy),
        bucket,
        scope,
        global,
    }
}

fn apply_rate_limit_headers(headers: &mut HeaderMap, metadata: &RateMetadata) {
    let decision = metadata.decision;
    let reset_at =
        Utc::now().timestamp_millis() as f64 / 1_000.0 + decision.reset_after.as_secs_f64();
    insert_rate_header(headers, "x-ratelimit-limit", decision.limit.to_string());
    insert_rate_header(
        headers,
        "x-ratelimit-remaining",
        decision.remaining.to_string(),
    );
    insert_rate_header(headers, "x-ratelimit-reset", format!("{reset_at:.3}"));
    insert_rate_header(
        headers,
        "x-ratelimit-reset-after",
        format!("{:.3}", decision.reset_after.as_secs_f64()),
    );
    insert_rate_header(headers, "x-ratelimit-bucket", metadata.bucket);
    insert_rate_header(headers, "x-ratelimit-scope", metadata.scope);
    if !decision.allowed {
        insert_rate_header(
            headers,
            "retry-after",
            format!("{:.3}", decision.retry_after.as_secs_f64()),
        );
    }
}

fn insert_rate_header(headers: &mut HeaderMap, name: &'static str, value: impl AsRef<str>) {
    if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
        headers.insert(axum::http::HeaderName::from_static(name), value);
    }
}

async fn request_id(mut request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    request.extensions_mut().insert(request_id.clone());
    let mut response = next.run(request).await;
    if let Ok(request_id) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", request_id);
    }
    response
}

async fn list_guilds(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Guild>>> {
    let user_id = authenticated_user(&state, &headers)?;
    state
        .repository
        .list_guilds(user_id)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn create_guild(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateGuild>,
) -> ApiResult<(StatusCode, Json<Guild>)> {
    let owner_id = authenticated_user(&state, &headers)?;
    enforce_rate_limit(
        &state,
        format!("guild-create:{owner_id}"),
        RateLimit::new(10, std::time::Duration::from_secs(24 * 60 * 60)),
        "314a33c6",
        "user",
    )?;
    let name = validate_guild_name(&input.name)?;
    let accent = input.accent.unwrap_or(0x8B7CFF);
    if accent > 0xFF_FFFF {
        return Err(ApiError::bad_request(
            "server accent must be a 24-bit RGB color",
        ));
    }
    let created = state
        .repository
        .create_guild(owner_id, name, accent)
        .await?;
    publish_event(
        &state,
        EventType::GuildCreate,
        Some(created.guild.id),
        &created.guild,
    );
    for channel in &created.channels {
        publish_event(
            &state,
            EventType::ChannelCreate,
            Some(channel.guild_id),
            channel,
        );
    }
    Ok((StatusCode::CREATED, Json(created.guild)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferGuildOwnership {
    owner_id: String,
}

async fn transfer_guild_ownership(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(input): Json<TransferGuildOwnership>,
) -> ApiResult<Json<Guild>> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = guild_id
        .parse::<GuildId>()
        .map_err(|_| ApiError::bad_request("invalid server id"))?;
    let new_owner_id = parse_user_id(&input.owner_id)?;
    enforce_rate_limit(
        &state,
        format!("guild-owner-transfer:{actor_id}"),
        RateLimit::new(5, std::time::Duration::from_secs(24 * 60 * 60)),
        "d37c9571",
        "user",
    )?;
    let guild = state
        .repository
        .transfer_guild_ownership(actor_id, guild_id, new_owner_id)
        .await?;
    publish_event(&state, EventType::GuildUpdate, Some(guild.id), &guild);
    Ok(Json(guild))
}

#[derive(Deserialize)]
struct DeleteGuild {
    confirmation: String,
}

async fn delete_guild(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(input): Json<DeleteGuild>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = guild_id
        .parse::<GuildId>()
        .map_err(|_| ApiError::bad_request("invalid server id"))?;
    enforce_rate_limit(
        &state,
        format!("guild-delete:{actor_id}"),
        RateLimit::new(5, std::time::Duration::from_secs(24 * 60 * 60)),
        "01db2b37",
        "user",
    )?;
    let deleted = state
        .repository
        .delete_guild(actor_id, guild_id, &input.confirmation, Utc::now())
        .await?;
    reset_known_voice_rooms(&state, guild_id, deleted.voice_channel_ids);
    publish_user_event(
        &state,
        EventType::GuildDelete,
        &deleted.member_ids,
        &deleted.guild,
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn create_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(input): Json<CreateInvite>,
) -> ApiResult<(StatusCode, Json<GuildInvite>)> {
    let creator_id = authenticated_user(&state, &headers)?;
    let guild_id = guild_id
        .parse::<GuildId>()
        .map_err(|_| ApiError::bad_request("invalid server id"))?;
    enforce_rate_limit(
        &state,
        format!("invite-create:{creator_id}"),
        RateLimit::new(10, std::time::Duration::from_secs(10 * 60)),
        "029bc273",
        "user",
    )?;
    let max_uses = input.max_uses.unwrap_or(50);
    if !(1..=1_000).contains(&max_uses) {
        return Err(ApiError::bad_request(
            "invite max uses must be between 1 and 1000",
        ));
    }
    let expires_in_seconds = input.expires_in_seconds.unwrap_or(86_400);
    if !(300..=604_800).contains(&expires_in_seconds) {
        return Err(ApiError::bad_request(
            "invite lifetime must be between 5 minutes and 7 days",
        ));
    }
    let expires_at = Utc::now()
        .checked_add_signed(ChronoDuration::seconds(i64::from(expires_in_seconds)))
        .ok_or_else(|| ApiError::internal("invite expiry could not be calculated"))?;

    for _ in 0..3 {
        let code = new_invite_code()?;
        let code_hash = invite_code_hash(&code);
        match state
            .repository
            .create_invite(
                creator_id,
                guild_id,
                code,
                &code_hash,
                Some(max_uses),
                Some(expires_at),
            )
            .await
        {
            Ok(invite) => return Ok((StatusCode::CREATED, Json(invite))),
            Err(RepositoryError::Conflict) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::service_unavailable(
        "an invite code could not be allocated",
    ))
}

async fn preview_invite(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> ApiResult<Json<InvitePreview>> {
    let code = validate_invite_code(&code)?;
    let code_hash = invite_code_hash(&code);
    state
        .repository
        .preview_invite(code, &code_hash)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn accept_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> ApiResult<Json<Guild>> {
    let user_id = authenticated_user(&state, &headers)?;
    let code = validate_invite_code(&code)?;
    let guild = state
        .repository
        .accept_invite(user_id, &invite_code_hash(&code))
        .await?;
    publish_event(&state, EventType::GuildCreate, Some(guild.id), &guild);
    Ok(Json(guild))
}

#[derive(Deserialize)]
struct MemberQuery {
    limit: Option<usize>,
}

async fn list_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Query(query): Query<MemberQuery>,
) -> ApiResult<Json<Vec<GuildMember>>> {
    let user_id = authenticated_user(&state, &headers)?;
    let guild_id = guild_id
        .parse::<GuildId>()
        .map_err(|_| ApiError::bad_request("invalid server id"))?;
    let limit = query.limit.unwrap_or(100);
    if !(1..=1_000).contains(&limit) {
        return Err(ApiError::bad_request(
            "member limit must be between 1 and 1000",
        ));
    }
    state
        .repository
        .list_members(user_id, guild_id, limit)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn list_automod_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
) -> ApiResult<Json<Vec<AutomodRule>>> {
    state
        .repository
        .list_automod_rules(
            authenticated_user(&state, &headers)?,
            parse_guild_id(&guild_id)?,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn create_automod_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(input): Json<CreateAutomodRule>,
) -> ApiResult<(StatusCode, Json<AutomodRule>)> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    let rule = state
        .repository
        .create_automod_rule(actor_id, guild_id, input)
        .await?;
    invalidate_automod_engine(&state, guild_id).await;
    Ok((StatusCode::CREATED, Json(rule)))
}

async fn update_automod_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, rule_id)): Path<(String, String)>,
    Json(input): Json<UpdateAutomodRule>,
) -> ApiResult<Json<AutomodRule>> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    let rule_id = parse_automod_rule_id(&rule_id)?;
    let rule = state
        .repository
        .update_automod_rule(actor_id, guild_id, rule_id, input)
        .await?;
    invalidate_automod_engine(&state, guild_id).await;
    Ok(Json(rule))
}

async fn delete_automod_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, rule_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    state
        .repository
        .delete_automod_rule(actor_id, guild_id, parse_automod_rule_id(&rule_id)?)
        .await?;
    invalidate_automod_engine(&state, guild_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditLogQuery {
    before: Option<String>,
    limit: Option<usize>,
}

async fn list_audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Query(query): Query<AuditLogQuery>,
) -> ApiResult<Json<Vec<AuditLogEntry>>> {
    let before = query
        .before
        .as_deref()
        .map(str::parse::<AuditLogId>)
        .transpose()
        .map_err(|_| ApiError::bad_request("invalid audit log cursor"))?;
    state
        .repository
        .list_audit_log(
            authenticated_user(&state, &headers)?,
            parse_guild_id(&guild_id)?,
            before,
            query.limit.unwrap_or(50),
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn list_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
) -> ApiResult<Json<Vec<Role>>> {
    let user_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    state
        .repository
        .list_roles(user_id, guild_id)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(input): Json<CreateRole>,
) -> ApiResult<(StatusCode, Json<Role>)> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    enforce_role_rate_limit(&state, actor_id, guild_id)?;
    let name = validate_role_name(&input.name)?;
    let color = validate_role_color(input.color.unwrap_or(0))?;
    let permissions = parse_permission_bits(&input.permissions)?;
    let role = state
        .repository
        .create_role(actor_id, guild_id, name, color, permissions)
        .await?;
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok((StatusCode::CREATED, Json(role)))
}

async fn update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(input): Json<UpdateRole>,
) -> ApiResult<Json<Role>> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    enforce_role_rate_limit(&state, actor_id, guild_id)?;
    let role_id = parse_role_id(&role_id)?;
    let current = state
        .repository
        .list_roles(actor_id, guild_id)
        .await?
        .into_iter()
        .find(|role| role.id == role_id)
        .ok_or_else(|| ApiError::not_found("role"))?;
    let name = input
        .name
        .as_deref()
        .map(validate_role_name)
        .transpose()?
        .unwrap_or(current.name);
    let color = validate_role_color(input.color.unwrap_or(current.color))?;
    let permissions = input
        .permissions
        .as_deref()
        .map(parse_permission_bits)
        .transpose()?
        .unwrap_or(current.permissions);
    let role = state
        .repository
        .update_role(actor_id, guild_id, role_id, name, color, permissions)
        .await?;
    reset_guild_voice(&state, guild_id);
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok(Json(role))
}

async fn delete_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    enforce_role_rate_limit(&state, actor_id, guild_id)?;
    state
        .repository
        .delete_role(actor_id, guild_id, parse_role_id(&role_id)?)
        .await?;
    reset_guild_voice(&state, guild_id);
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn assign_member_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, member_id, role_id)): Path<(String, String, String)>,
) -> ApiResult<StatusCode> {
    set_member_role(&state, &headers, &guild_id, &member_id, &role_id, true).await
}

async fn remove_member_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, member_id, role_id)): Path<(String, String, String)>,
) -> ApiResult<StatusCode> {
    set_member_role(&state, &headers, &guild_id, &member_id, &role_id, false).await
}

async fn set_member_role(
    state: &AppState,
    headers: &HeaderMap,
    guild_id: &str,
    member_id: &str,
    role_id: &str,
    assigned: bool,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(state, headers)?;
    let guild_id = parse_guild_id(guild_id)?;
    let member_id = member_id
        .parse::<UserId>()
        .map_err(|_| ApiError::bad_request("invalid member id"))?;
    state
        .repository
        .set_member_role(
            actor_id,
            guild_id,
            member_id,
            parse_role_id(role_id)?,
            assigned,
        )
        .await?;
    revoke_member_voice(state, guild_id, member_id);
    publish_guild_refresh(state, actor_id, guild_id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn timeout_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, member_id)): Path<(String, String)>,
    Json(input): Json<ModerateMember>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    let member_id = parse_user_id(&member_id)?;
    let reason = validate_moderation_reason(input.reason)?;
    let timeout_until = match input.timeout_seconds {
        None | Some(0) => None,
        Some(seconds) if seconds <= 28 * 24 * 60 * 60 => {
            Some(Utc::now() + ChronoDuration::seconds(i64::from(seconds)))
        }
        Some(_) => {
            return Err(ApiError::bad_request(
                "timeouts cannot be longer than 28 days",
            ));
        }
    };
    state
        .repository
        .timeout_member(actor_id, guild_id, member_id, timeout_until, reason)
        .await?;
    if timeout_until.is_some() {
        revoke_member_voice(&state, guild_id, member_id);
    }
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn kick_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, member_id)): Path<(String, String)>,
    input: Option<Json<ModerateMember>>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    let member_id = parse_user_id(&member_id)?;
    state
        .repository
        .kick_member(
            actor_id,
            guild_id,
            member_id,
            validate_moderation_reason(input.and_then(|Json(value)| value.reason))?,
        )
        .await?;
    revoke_member_voice(&state, guild_id, member_id);
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_bans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
) -> ApiResult<Json<Vec<GuildBan>>> {
    state
        .repository
        .list_bans(
            authenticated_user(&state, &headers)?,
            parse_guild_id(&guild_id)?,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn ban_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, member_id)): Path<(String, String)>,
    Json(input): Json<BanMember>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    let member_id = parse_user_id(&member_id)?;
    let expires_at = match input.duration_seconds {
        None => None,
        Some(seconds) if (60..=365 * 24 * 60 * 60).contains(&seconds) => {
            Some(Utc::now() + ChronoDuration::seconds(i64::from(seconds)))
        }
        Some(_) => {
            return Err(ApiError::bad_request(
                "temporary bans must last between 1 minute and 365 days",
            ));
        }
    };
    state
        .repository
        .ban_member(
            actor_id,
            guild_id,
            member_id,
            validate_moderation_reason(input.reason)?,
            expires_at,
        )
        .await?;
    revoke_member_voice(&state, guild_id, member_id);
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn unban_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((guild_id, member_id)): Path<(String, String)>,
    input: Option<Json<ModerateMember>>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    state
        .repository
        .unban_member(
            actor_id,
            guild_id,
            parse_user_id(&member_id)?,
            validate_moderation_reason(input.and_then(|Json(value)| value.reason))?,
        )
        .await?;
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn publish_guild_refresh(state: &AppState, actor_id: UserId, guild_id: GuildId) {
    match state.repository.list_guilds(actor_id).await {
        Ok(guilds) => {
            if let Some(guild) = guilds.into_iter().find(|guild| guild.id == guild_id) {
                publish_event(state, EventType::GuildUpdate, Some(guild_id), &guild);
            }
        }
        Err(error) => {
            tracing::warn!(%error, %guild_id, "server refresh event could not be published");
        }
    }
}

fn revoke_member_voice(state: &AppState, guild_id: GuildId, user_id: UserId) {
    let Some(voice) = state.voice.clone() else {
        return;
    };
    let repository = state.repository.clone();
    tokio::spawn(async move {
        let mut channels = None;
        for attempt in 1..=3 {
            match repository.voice_channel_ids(guild_id).await {
                Ok(found) => {
                    channels = Some(found);
                    break;
                }
                Err(error) if attempt < 3 => {
                    tracing::warn!(
                        %error,
                        %guild_id,
                        %user_id,
                        attempt,
                        "voice revocation channel lookup will be retried"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        %guild_id,
                        %user_id,
                        "voice revocation channel lookup was exhausted"
                    );
                }
            }
        }
        let Some(channels) = channels else {
            return;
        };
        futures_util::future::join_all(
            channels
                .into_iter()
                .map(|channel_id| voice.remove_participant(guild_id, channel_id, user_id)),
        )
        .await;
    });
}

fn reset_guild_voice(state: &AppState, guild_id: GuildId) {
    let Some(voice) = state.voice.clone() else {
        return;
    };
    let repository = state.repository.clone();
    tokio::spawn(async move {
        let mut channels = None;
        for attempt in 1..=3 {
            match repository.voice_channel_ids(guild_id).await {
                Ok(found) => {
                    channels = Some(found);
                    break;
                }
                Err(error) if attempt < 3 => {
                    tracing::warn!(
                        %error,
                        %guild_id,
                        attempt,
                        "server voice reset channel lookup will be retried"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        %guild_id,
                        "server voice reset channel lookup was exhausted"
                    );
                }
            }
        }
        let Some(channels) = channels else {
            return;
        };
        futures_util::future::join_all(
            channels
                .into_iter()
                .map(|channel_id| voice.reset_room(guild_id, channel_id)),
        )
        .await;
    });
}

fn reset_known_voice_rooms(state: &AppState, guild_id: GuildId, channel_ids: Vec<ChannelId>) {
    let Some(voice) = state.voice.clone() else {
        return;
    };
    tokio::spawn(async move {
        futures_util::future::join_all(
            channel_ids
                .into_iter()
                .map(|channel_id| voice.reset_room(guild_id, channel_id)),
        )
        .await;
    });
}

fn reset_voice_room(state: &AppState, guild_id: GuildId, channel_id: ChannelId) {
    let Some(voice) = state.voice.clone() else {
        return;
    };
    tokio::spawn(async move {
        voice.reset_room(guild_id, channel_id).await;
    });
}

fn revoke_channel_voice_member(
    state: &AppState,
    guild_id: GuildId,
    channel_id: ChannelId,
    user_id: UserId,
) {
    let Some(voice) = state.voice.clone() else {
        return;
    };
    tokio::spawn(async move {
        voice
            .remove_participant(guild_id, channel_id, user_id)
            .await;
    });
}

fn parse_guild_id(value: &str) -> ApiResult<GuildId> {
    value
        .parse()
        .map_err(|_| ApiError::bad_request("invalid server id"))
}

fn parse_role_id(value: &str) -> ApiResult<RoleId> {
    value
        .parse()
        .map_err(|_| ApiError::bad_request("invalid role id"))
}

fn parse_automod_rule_id(value: &str) -> ApiResult<AutomodRuleId> {
    value
        .parse()
        .map_err(|_| ApiError::bad_request("invalid automod rule id"))
}

fn parse_user_id(value: &str) -> ApiResult<UserId> {
    value
        .parse()
        .map_err(|_| ApiError::bad_request("invalid user id"))
}

fn parse_device_id(value: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| ApiError::bad_request("invalid device id"))
}

fn decode_base64url(value: &str, label: &str, maximum: usize) -> ApiResult<Vec<u8>> {
    if value.is_empty() || value.contains('=') {
        return Err(ApiError::bad_request(format!(
            "{label} must be unpadded base64url"
        )));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request(format!("{label} is not valid base64url")))?;
    if decoded.len() > maximum || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ApiError::bad_request(format!(
            "{label} is not canonical or exceeds {maximum} bytes"
        )));
    }
    Ok(decoded)
}

fn device_identity_response(identity: DeviceIdentityRecord) -> DeviceIdentity {
    let mut digest = Sha256::new();
    digest.update(b"exocord-device-fingerprint-v1");
    digest.update(identity.user_id.raw().to_be_bytes());
    digest.update(identity.device_id.as_bytes());
    digest.update(identity.signature_key);
    let fingerprint = digest
        .finalize()
        .chunks(3)
        .map(hex::encode_upper)
        .collect::<Vec<_>>()
        .join(" ");
    DeviceIdentity {
        device_id: identity.device_id,
        user_id: identity.user_id,
        signature_key: URL_SAFE_NO_PAD.encode(identity.signature_key),
        fingerprint,
        name: identity.name,
        created_at: identity.created_at,
        revoked_at: identity.revoked_at,
    }
}

fn mls_key_package_response(package: MlsKeyPackageRecord) -> MlsKeyPackage {
    MlsKeyPackage {
        id: package.id,
        user_id: package.user_id,
        device_id: package.device_id,
        reference: URL_SAFE_NO_PAD.encode(package.reference),
        key_package: URL_SAFE_NO_PAD.encode(package.key_package),
        cipher_suite: package.cipher_suite,
        expires_at: package.expires_at,
    }
}

fn mls_delivery_response(delivery: MlsDeliveryRecord) -> MlsWelcomeDelivery {
    MlsWelcomeDelivery {
        channel_id: delivery.channel_id,
        group_id: URL_SAFE_NO_PAD.encode(delivery.group_id),
        epoch: delivery.epoch,
        sequence: delivery.sequence,
        kind: match delivery.kind {
            MlsDeliveryRecordKind::Welcome => MlsDeliveryKind::Welcome,
            MlsDeliveryRecordKind::Commit => MlsDeliveryKind::Commit,
            MlsDeliveryRecordKind::Proposal => MlsDeliveryKind::Proposal,
        },
        sender_device_id: delivery.sender_device_id,
        payload: URL_SAFE_NO_PAD.encode(delivery.payload),
        created_at: delivery.created_at,
    }
}

fn validate_moderation_reason(reason: Option<String>) -> ApiResult<Option<String>> {
    reason
        .map(|reason| {
            let reason = reason.trim();
            if reason.chars().count() > 512 {
                return Err(ApiError::bad_request(
                    "moderation reasons cannot exceed 512 characters",
                ));
            }
            Ok((!reason.is_empty()).then(|| reason.to_owned()))
        })
        .transpose()
        .map(Option::flatten)
}

fn validate_role_color(value: u32) -> ApiResult<u32> {
    if value > 0xFF_FFFF {
        return Err(ApiError::bad_request(
            "role color must be a 24-bit RGB color",
        ));
    }
    Ok(value)
}

fn enforce_role_rate_limit(state: &AppState, actor_id: UserId, guild_id: GuildId) -> ApiResult<()> {
    enforce_rate_limit(
        state,
        format!("role:{actor_id}:{guild_id}"),
        RateLimit::new(10, std::time::Duration::from_secs(10)),
        "3497c8a2",
        "user",
    )
}

fn parse_permission_bits(value: &str) -> ApiResult<GuildPermissions> {
    let bits = value
        .parse::<u64>()
        .map_err(|_| ApiError::bad_request("permissions must be a decimal string"))?;
    GuildPermissions::from_bits(bits)
        .ok_or_else(|| ApiError::bad_request("permissions contain unallocated bits"))
}

fn new_invite_code() -> ApiResult<String> {
    let mut value = [0_u8; 16];
    getrandom::fill(&mut value)
        .map_err(|_| ApiError::service_unavailable("secure randomness is unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}

fn validate_invite_code(value: &str) -> ApiResult<String> {
    let value = value.trim();
    if !(16..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::not_found("invite"));
    }
    Ok(value.to_owned())
}

fn invite_code_hash(code: &str) -> Vec<u8> {
    Sha256::digest(code.as_bytes()).to_vec()
}

async fn list_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
) -> ApiResult<Json<Vec<Channel>>> {
    let user_id = authenticated_user(&state, &headers)?;
    let guild_id = guild_id
        .parse::<GuildId>()
        .map_err(|_| ApiError::bad_request("invalid server id"))?;
    state
        .repository
        .list_channels(user_id, guild_id)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn create_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(input): Json<CreateChannel>,
) -> ApiResult<(StatusCode, Json<Channel>)> {
    let user_id = authenticated_user(&state, &headers)?;
    let guild_id = guild_id
        .parse::<GuildId>()
        .map_err(|_| ApiError::bad_request("invalid server id"))?;
    enforce_rate_limit(
        &state,
        format!("channel-create:{user_id}:{guild_id}"),
        RateLimit::new(5, std::time::Duration::from_secs(10)),
        "e941db42",
        "user",
    )?;
    let name = validate_channel_name(&input.name)?;
    let channel = state
        .repository
        .create_channel(user_id, guild_id, name, input.kind, input.encrypted)
        .await?;
    publish_event(
        &state,
        EventType::ChannelCreate,
        Some(channel.guild_id),
        &channel,
    );
    Ok((StatusCode::CREATED, Json(channel)))
}

async fn update_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Json(input): Json<UpdateChannel>,
) -> ApiResult<Json<Channel>> {
    let actor_id = authenticated_user(&state, &headers)?;
    let channel_id = parse_channel_id(&channel_id)?;
    let requested_name = input
        .name
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("a channel name is required"))?;
    let name = validate_channel_name(requested_name)?;
    let channel = state
        .repository
        .update_channel(actor_id, channel_id, name)
        .await?;
    publish_event(
        &state,
        EventType::ChannelUpdate,
        Some(channel.guild_id),
        &channel,
    );
    Ok(Json(channel))
}

async fn delete_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let channel = state
        .repository
        .delete_channel(actor_id, parse_channel_id(&channel_id)?)
        .await?;
    if channel.kind == exo_domain::ChannelKind::Voice {
        reset_voice_room(&state, channel.guild_id, channel.id);
    }
    publish_event(
        &state,
        EventType::ChannelDelete,
        Some(channel.guild_id),
        &channel,
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_channel_overwrites(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> ApiResult<Json<Vec<ChannelPermissionOverwrite>>> {
    state
        .repository
        .list_channel_overwrites(
            authenticated_user(&state, &headers)?,
            parse_channel_id(&channel_id)?,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn set_channel_overwrite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((channel_id, target_kind, target_id)): Path<(String, String, String)>,
    Json(input): Json<UpdateChannelOverwrite>,
) -> ApiResult<Json<ChannelPermissionOverwrite>> {
    let actor_id = authenticated_user(&state, &headers)?;
    let channel_id = parse_channel_id(&channel_id)?;
    let guild_id = state.repository.channel_guild_id(channel_id).await?;
    let target_kind = parse_overwrite_target_kind(&target_kind)?;
    let target_id = parse_raw_id(&target_id, "overwrite target")?;
    let overwrite = state
        .repository
        .set_channel_overwrite(
            actor_id,
            channel_id,
            target_kind,
            target_id,
            parse_permission_bits(&input.allow)?,
            parse_permission_bits(&input.deny)?,
        )
        .await?;
    match target_kind {
        OverwriteTargetKind::Member => {
            let user_id = UserId::from_raw(target_id)
                .map_err(|_| ApiError::bad_request("invalid overwrite target id"))?;
            revoke_channel_voice_member(&state, guild_id, channel_id, user_id);
        }
        OverwriteTargetKind::Role => reset_voice_room(&state, guild_id, channel_id),
    }
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok(Json(overwrite))
}

async fn delete_channel_overwrite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((channel_id, target_kind, target_id)): Path<(String, String, String)>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let channel_id = parse_channel_id(&channel_id)?;
    let guild_id = state.repository.channel_guild_id(channel_id).await?;
    let target_kind = parse_overwrite_target_kind(&target_kind)?;
    let target_id = parse_raw_id(&target_id, "overwrite target")?;
    state
        .repository
        .delete_channel_overwrite(actor_id, channel_id, target_kind, target_id)
        .await?;
    match target_kind {
        OverwriteTargetKind::Member => {
            let user_id = UserId::from_raw(target_id)
                .map_err(|_| ApiError::bad_request("invalid overwrite target id"))?;
            revoke_channel_voice_member(&state, guild_id, channel_id, user_id);
        }
        OverwriteTargetKind::Role => reset_voice_room(&state, guild_id, channel_id),
    }
    publish_guild_refresh(&state, actor_id, guild_id).await;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_channel_id(value: &str) -> ApiResult<ChannelId> {
    value
        .parse()
        .map_err(|_| ApiError::bad_request("invalid channel id"))
}

fn parse_overwrite_target_kind(value: &str) -> ApiResult<OverwriteTargetKind> {
    match value {
        "role" => Ok(OverwriteTargetKind::Role),
        "member" => Ok(OverwriteTargetKind::Member),
        _ => Err(ApiError::bad_request(
            "overwrite target kind must be role or member",
        )),
    }
}

fn parse_raw_id(value: &str, label: &'static str) -> ApiResult<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| ApiError::bad_request(format!("invalid {label} id")))
}

async fn list_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> ApiResult<Json<Vec<Message>>> {
    let user_id = authenticated_user(&state, &headers)?;
    let channel_id = channel_id
        .parse::<ChannelId>()
        .map_err(|_| ApiError::bad_request("invalid channel id"))?;
    let cursors = [
        query.before.is_some(),
        query.after.is_some(),
        query.around.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if cursors > 1 {
        return Err(ApiError::bad_request(
            "before, after, and around are mutually exclusive",
        ));
    }
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad_request("limit must be between 1 and 100"));
    }
    let window = MessageWindow {
        before: parse_cursor(query.before.as_deref())?,
        after: parse_cursor(query.after.as_deref())?,
        around: parse_cursor(query.around.as_deref())?,
        limit,
    };
    state
        .repository
        .list_messages(user_id, channel_id, window)
        .await
        .map(Json)
        .map_err(Into::into)
}

#[derive(Debug, Default, Deserialize)]
struct MessageQuery {
    before: Option<String>,
    after: Option<String>,
    around: Option<String>,
    limit: Option<usize>,
}

fn parse_cursor(value: Option<&str>) -> ApiResult<Option<u64>> {
    value
        .map(|value| {
            value
                .parse::<MessageId>()
                .map(MessageId::raw)
                .map_err(|_| ApiError::bad_request("invalid message cursor"))
        })
        .transpose()
}

#[derive(Debug, Deserialize)]
struct SearchMessagesQuery {
    q: String,
    limit: Option<usize>,
}

async fn search_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Query(query): Query<SearchMessagesQuery>,
) -> ApiResult<Json<MessageSearchResult>> {
    let user_id = authenticated_user(&state, &headers)?;
    let guild_id = parse_guild_id(&guild_id)?;
    let limit = query_limit(query.limit)?;
    let query = query.q.trim();
    if query.is_empty() || query.chars().count() > 256 {
        return Err(ApiError::bad_request(
            "search query must contain between 1 and 256 characters",
        ));
    }
    state
        .repository
        .search_messages(user_id, guild_id, query, limit)
        .await
        .map(Json)
        .map_err(Into::into)
}

fn query_limit(limit: Option<usize>) -> ApiResult<usize> {
    let limit = limit.unwrap_or(25);
    if !(1..=50).contains(&limit) {
        return Err(ApiError::bad_request(
            "search limit must be between 1 and 50",
        ));
    }
    Ok(limit)
}

async fn reserve_attachments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Json(input): Json<ReserveAttachments>,
) -> ApiResult<(HeaderMap, Json<ReservedAttachments>)> {
    let owner_id = authenticated_user(&state, &headers)?;
    let channel_id = parse_channel_id(&channel_id)?;
    enforce_rate_limit(
        &state,
        format!("attachment:{owner_id}"),
        RateLimit::new(20, std::time::Duration::from_secs(60)),
        "0c7df1a9",
        "user",
    )?;
    if input.files.is_empty() || input.files.len() > media::MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(ApiError::bad_request(
            "an upload request must contain between 1 and 10 files",
        ));
    }
    let expires_at = Utc::now() + ChronoDuration::minutes(15);
    let mut uploads = Vec::with_capacity(input.files.len());
    for file in input.files {
        let filename = validate_attachment_filename(&file.filename)?;
        if file.file_size == 0 || file.file_size > MAX_ATTACHMENT_BYTES {
            return Err(ApiError::bad_request(
                "attachment size must be between 1 byte and 25 MiB",
            ));
        }
        let content_type = normalize_declared_content_type(&file.content_type)?;
        let claimed_sha256 = parse_attachment_hash(&file.sha256)?;
        let id = AttachmentId::new();
        let prepared = state.attachments.prepare_upload(
            id,
            owner_id,
            channel_id,
            &claimed_sha256,
            &content_type,
            expires_at,
        )?;
        state
            .repository
            .reserve_attachment(NewAttachment {
                id,
                channel_id,
                owner_id,
                filename,
                declared_content_type: content_type,
                file_size: file.file_size,
                claimed_sha256,
                object_key: prepared.object_key,
                public_url: prepared.public_url,
                expires_at,
            })
            .await?;
        uploads.push(AttachmentUpload {
            id,
            upload_url: prepared.upload_url,
            upload_headers: prepared.upload_headers,
            expires_at,
            max_bytes: MAX_ATTACHMENT_BYTES,
        });
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    Ok((
        response_headers,
        Json(ReservedAttachments {
            attachments: uploads,
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct AttachmentCapability {
    token: String,
}

async fn upload_attachment(
    State(state): State<AppState>,
    Path(attachment_id): Path<String>,
    Query(capability): Query<AttachmentCapability>,
    body: Bytes,
) -> ApiResult<(HeaderMap, StatusCode)> {
    let attachment_id = parse_attachment_id(&attachment_id)?;
    let record = state.repository.attachment_record(attachment_id).await?;
    state
        .attachments
        .verify_upload_capability(&record, &capability.token)?;
    state
        .attachments
        .store_local_upload(&record, body.to_vec())
        .await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    Ok((response_headers, StatusCode::NO_CONTENT))
}

async fn complete_attachment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(attachment_id): Path<String>,
) -> ApiResult<(HeaderMap, Json<exo_domain::MessageAttachment>)> {
    let owner_id = authenticated_user(&state, &headers)?;
    let attachment_id = parse_attachment_id(&attachment_id)?;
    let record = state.repository.attachment_record(attachment_id).await?;
    if record.owner_id != owner_id {
        return Err(ApiError::not_found("attachment"));
    }
    let inspected = state.attachments.inspect_reserved_object(&record).await?;
    let attachment = state
        .repository
        .complete_attachment(
            owner_id,
            attachment_id,
            &VerifiedAttachment {
                content_type: inspected.verified_content_type,
                size: inspected.size,
                sha256: inspected.sha256,
                width: inspected.width,
                height: inspected.height,
                animated: inspected.animated,
            },
        )
        .await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    Ok((response_headers, Json(attachment)))
}

async fn serve_attachment(
    State(state): State<AppState>,
    Path(attachment_id): Path<String>,
    Query(capability): Query<AttachmentCapability>,
) -> ApiResult<Response> {
    let attachment_id = parse_attachment_id(&attachment_id)?;
    let record = state.repository.attachment_record(attachment_id).await?;
    if !record.ready {
        return Err(ApiError::not_found("attachment"));
    }
    state
        .attachments
        .verify_read_capability(&record, &capability.token)?;
    let bytes = state.attachments.read_local_object(&record).await?;
    let content_type = record
        .verified_content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    let disposition = if content_type.starts_with("image/")
        || content_type.starts_with("video/")
        || content_type.starts_with("audio/")
    {
        "inline"
    } else {
        "attachment"
    };
    let safe_filename = record.filename.replace(['"', '\r', '\n'], "_");
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .map_err(|_| ApiError::internal("stored attachment type is invalid"))?,
    );
    response_headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("{disposition}; filename=\"{safe_filename}\""))
            .map_err(|_| ApiError::internal("stored attachment filename is invalid"))?,
    );
    response_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response_headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok((response_headers, bytes).into_response())
}

fn parse_attachment_id(value: &str) -> ApiResult<AttachmentId> {
    value
        .parse()
        .map_err(|_| ApiError::bad_request("invalid attachment id"))
}

fn validate_attachment_filename(value: &str) -> ApiResult<String> {
    let leaf = value.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    let cleaned = leaf
        .chars()
        .filter(|character| !character.is_control())
        .take(255)
        .collect::<String>();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return Err(ApiError::bad_request("attachment filename is invalid"));
    }
    Ok(cleaned)
}

fn normalize_declared_content_type(value: &str) -> ApiResult<String> {
    let content_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let content_type = if content_type.is_empty() {
        "application/octet-stream".to_owned()
    } else {
        content_type
    };
    if content_type.len() > 127
        || !content_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'+' | b'.'))
    {
        return Err(ApiError::bad_request("attachment content type is invalid"));
    }
    Ok(content_type)
}

fn parse_attachment_hash(value: &str) -> ApiResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(ApiError::bad_request(
            "attachment SHA-256 must contain 64 hexadecimal characters",
        ));
    }
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::bad_request("attachment SHA-256 is invalid"))
}

async fn enforce_message_automod(
    state: &AppState,
    guild_id: Option<GuildId>,
    author_id: UserId,
    account_created_at: chrono::DateTime<Utc>,
    content: &str,
) -> ApiResult<()> {
    let Some(guild_id) = guild_id else {
        return Ok(());
    };
    let engine = automod_engine(state, guild_id).await?;
    let Some(matched) = engine.evaluate(&AutomodContext {
        guild_id,
        author_id,
        content,
        account_created_at,
        now: Utc::now(),
    }) else {
        return Ok(());
    };
    let enforcement = state
        .repository
        .apply_automod_match(guild_id, author_id, &matched)
        .await?;
    if enforcement.removed_from_guild {
        revoke_member_voice(state, guild_id, author_id);
        publish_user_event(
            state,
            EventType::GuildDelete,
            &[author_id],
            &serde_json::json!({
                "guildId": guild_id,
                "reason": matched.explanation
            }),
        );
    } else if enforcement.applied_action == AutomodAction::Timeout {
        revoke_member_voice(state, guild_id, author_id);
    }
    if enforcement.applied_action != AutomodAction::Flag {
        return Err(ApiError::moderated(matched.explanation));
    }
    Ok(())
}

async fn create_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Json(input): Json<CreateMessage>,
) -> ApiResult<(StatusCode, Json<Message>)> {
    let author_id = authenticated_user(&state, &headers)?;
    let nonce = input.nonce.trim();
    if nonce.is_empty() || nonce.len() > 64 {
        return Err(ApiError::bad_request("nonce must contain 1–64 bytes"));
    }
    let channel_id = channel_id
        .parse::<ChannelId>()
        .map_err(|_| ApiError::bad_request("invalid channel id"))?;
    enforce_rate_limit(
        &state,
        format!("message:{author_id}:{channel_id}"),
        RateLimit::new(5, std::time::Duration::from_secs(5)),
        "4a0fb76d",
        "user",
    )?;
    let safety_context = state
        .repository
        .message_safety_context(author_id, channel_id, nonce)
        .await?;
    if let Some(existing) = safety_context.existing_message {
        return Ok((StatusCode::OK, Json(existing)));
    }
    let (content, encryption) = if safety_context.encrypted {
        if !safety_context.mls_ready {
            return Err(ApiError::conflict(
                "this encrypted channel is waiting for MLS device setup",
            ));
        }
        if !input.content.trim().is_empty() {
            return Err(ApiError::bad_request(
                "encrypted messages cannot include server-readable content",
            ));
        }
        if input.attachments.len() > media::MAX_ATTACHMENTS_PER_MESSAGE {
            return Err(ApiError::bad_request(
                "a message cannot contain more than 10 attachments",
            ));
        }
        let input_encryption = input.encryption.as_ref().ok_or_else(|| {
            ApiError::bad_request("this channel requires an end-to-end encrypted message")
        })?;
        let principal = authenticated_device_principal(&state, &headers)?;
        if principal.user_id != author_id {
            return Err(ApiError::unauthorized("the device session is invalid"));
        }
        let ciphertext =
            decode_base64url(&input_encryption.ciphertext, "MLS ciphertext", 1_048_576)?;
        if ciphertext.len() < 64 {
            return Err(ApiError::bad_request("MLS ciphertext is too short"));
        }
        let commitment: [u8; 32] = decode_base64url(
            &input_encryption.franking_commitment,
            "message-franking commitment",
            32,
        )?
        .try_into()
        .map_err(|_| {
            ApiError::bad_request("message-franking commitment must contain exactly 32 bytes")
        })?;
        (
            String::new(),
            Some(NewMessageEncryption {
                ciphertext,
                franking_commitment: commitment,
                franking_tag: [0_u8; 32],
                sender_device_id: principal.device_id,
            }),
        )
    } else {
        if input.encryption.is_some() {
            return Err(ApiError::bad_request(
                "plaintext channels do not accept MLS ciphertext",
            ));
        }
        (
            validate_message_with_attachments(&input.content, input.attachments.len())?,
            None,
        )
    };
    if encryption.is_none() {
        enforce_message_automod(
            &state,
            safety_context.guild_id,
            author_id,
            safety_context.account_created_at,
            &content,
        )
        .await?;
    }
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    let created = if let Some(encryption) = encryption {
        state
            .repository
            .create_encrypted_message(
                author_id,
                channel_id,
                encryption,
                state.franking_key,
                input.reply_to,
                nonce.to_owned(),
                &input.attachments,
                sequence,
            )
            .await?
    } else {
        state
            .repository
            .create_message(
                author_id,
                channel_id,
                content,
                input.reply_to,
                nonce.to_owned(),
                &input.attachments,
                sequence,
            )
            .await?
    };
    if created.created {
        match &created.audience {
            MessageAudience::Guild(guild_id) => publish_routed_event(
                &state,
                EventType::MessageCreate,
                sequence,
                RoutingMetadata {
                    guild_id: guild_id.raw(),
                    channel_id: channel_id.raw(),
                },
                &created.message,
            ),
            MessageAudience::Users(recipients) => publish_user_routed_event(
                &state,
                EventType::MessageCreate,
                sequence,
                channel_id,
                recipients,
                &created.message,
            ),
        }
    }
    let status = if created.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(created.message)))
}

async fn update_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((channel_id, message_id)): Path<(String, String)>,
    Json(input): Json<UpdateMessage>,
) -> ApiResult<Json<Message>> {
    let author_id = authenticated_user(&state, &headers)?;
    let channel_id = channel_id
        .parse::<ChannelId>()
        .map_err(|_| ApiError::bad_request("invalid channel id"))?;
    let message_id = message_id
        .parse::<MessageId>()
        .map_err(|_| ApiError::bad_request("invalid message id"))?;
    let nonce = input.nonce.trim();
    if nonce.is_empty() || nonce.len() > 64 {
        return Err(ApiError::bad_request("nonce must contain 1–64 bytes"));
    }
    enforce_rate_limit(
        &state,
        format!("message-edit:{author_id}:{channel_id}"),
        RateLimit::new(5, std::time::Duration::from_secs(5)),
        "769b86c1",
        "user",
    )?;
    let safety_context = state
        .repository
        .message_safety_context(author_id, channel_id, nonce)
        .await?;
    let (content, encryption) = if safety_context.encrypted {
        if !safety_context.mls_ready {
            return Err(ApiError::conflict(
                "this encrypted channel is waiting for MLS device setup",
            ));
        }
        if !input.content.trim().is_empty() {
            return Err(ApiError::bad_request(
                "encrypted messages cannot include server-readable content",
            ));
        }
        let input_encryption = input.encryption.as_ref().ok_or_else(|| {
            ApiError::bad_request("this channel requires an end-to-end encrypted message")
        })?;
        let principal = authenticated_device_principal(&state, &headers)?;
        if principal.user_id != author_id {
            return Err(ApiError::unauthorized("the device session is invalid"));
        }
        let ciphertext =
            decode_base64url(&input_encryption.ciphertext, "MLS ciphertext", 1_048_576)?;
        if ciphertext.len() < 64 {
            return Err(ApiError::bad_request("MLS ciphertext is too short"));
        }
        let commitment: [u8; 32] = decode_base64url(
            &input_encryption.franking_commitment,
            "message-franking commitment",
            32,
        )?
        .try_into()
        .map_err(|_| {
            ApiError::bad_request("message-franking commitment must contain exactly 32 bytes")
        })?;
        (
            String::new(),
            Some(NewMessageEncryption {
                ciphertext,
                franking_commitment: commitment,
                franking_tag: [0_u8; 32],
                sender_device_id: principal.device_id,
            }),
        )
    } else {
        if input.encryption.is_some() {
            return Err(ApiError::bad_request(
                "plaintext channels do not accept MLS ciphertext",
            ));
        }
        (validate_message_with_attachments(&input.content, 0)?, None)
    };
    if encryption.is_none() {
        enforce_message_automod(
            &state,
            safety_context.guild_id,
            author_id,
            safety_context.account_created_at,
            &content,
        )
        .await?;
    }
    let updated = state
        .repository
        .update_message(
            author_id,
            channel_id,
            message_id,
            content,
            encryption,
            safety_context.encrypted.then_some(state.franking_key),
            nonce.to_owned(),
        )
        .await?;
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    match &updated.audience {
        MessageAudience::Guild(guild_id) => publish_routed_event(
            &state,
            EventType::MessageUpdate,
            sequence,
            RoutingMetadata {
                guild_id: guild_id.raw(),
                channel_id: channel_id.raw(),
            },
            &updated.message,
        ),
        MessageAudience::Users(recipients) => publish_user_routed_event(
            &state,
            EventType::MessageUpdate,
            sequence,
            channel_id,
            recipients,
            &updated.message,
        ),
    }
    Ok(Json(updated.message))
}

async fn delete_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((channel_id, message_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let actor_id = authenticated_user(&state, &headers)?;
    let channel_id = channel_id
        .parse::<ChannelId>()
        .map_err(|_| ApiError::bad_request("invalid channel id"))?;
    let message_id = message_id
        .parse::<MessageId>()
        .map_err(|_| ApiError::bad_request("invalid message id"))?;
    enforce_rate_limit(
        &state,
        format!("message-delete:{actor_id}:{channel_id}"),
        RateLimit::new(5, std::time::Duration::from_secs(5)),
        "c4ce0351",
        "user",
    )?;
    let deleted = state
        .repository
        .delete_message(actor_id, channel_id, message_id)
        .await?;
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    match &deleted.audience {
        MessageAudience::Guild(guild_id) => publish_routed_event(
            &state,
            EventType::MessageDelete,
            sequence,
            RoutingMetadata {
                guild_id: guild_id.raw(),
                channel_id: channel_id.raw(),
            },
            &deleted.event,
        ),
        MessageAudience::Users(recipients) => publish_user_routed_event(
            &state,
            EventType::MessageDelete,
            sequence,
            channel_id,
            recipients,
            &deleted.event,
        ),
    }
    Ok(StatusCode::NO_CONTENT)
}

fn validate_reaction_emoji(value: &str) -> ApiResult<String> {
    let emoji = value.trim();
    if emoji.is_empty()
        || emoji.len() > 64
        || emoji.chars().count() > 16
        || UnicodeSegmentation::graphemes(emoji, true).count() != 1
        || emoji.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == '\u{feff}'
        })
        || emoji.is_ascii()
        || !emoji.chars().any(UnicodeEmoji::is_emoji_char)
        || emoji.chars().any(|character| {
            !character.is_emoji_char_or_emoji_component()
                && !matches!(character, '\u{200d}' | '\u{fe0e}' | '\u{fe0f}')
        })
    {
        return Err(ApiError::bad_request(
            "reaction must be one Unicode emoji sequence",
        ));
    }
    Ok(emoji.to_owned())
}

async fn add_reaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((channel_id, message_id)): Path<(String, String)>,
    Json(input): Json<MessageReactionInput>,
) -> ApiResult<Json<exo_domain::MessageReactionEvent>> {
    update_reaction(state, headers, channel_id, message_id, input, true).await
}

async fn remove_reaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((channel_id, message_id)): Path<(String, String)>,
    Json(input): Json<MessageReactionInput>,
) -> ApiResult<Json<exo_domain::MessageReactionEvent>> {
    update_reaction(state, headers, channel_id, message_id, input, false).await
}

async fn update_reaction(
    state: AppState,
    headers: HeaderMap,
    channel_id: String,
    message_id: String,
    input: MessageReactionInput,
    added: bool,
) -> ApiResult<Json<exo_domain::MessageReactionEvent>> {
    let actor_id = authenticated_user(&state, &headers)?;
    let channel_id = channel_id
        .parse::<ChannelId>()
        .map_err(|_| ApiError::bad_request("invalid channel id"))?;
    let message_id = message_id
        .parse::<MessageId>()
        .map_err(|_| ApiError::bad_request("invalid message id"))?;
    let emoji = validate_reaction_emoji(&input.emoji)?;
    enforce_rate_limit(
        &state,
        format!("reaction:{actor_id}:{channel_id}"),
        RateLimit::new(10, std::time::Duration::from_secs(5)),
        "a3aa1bd8",
        "user",
    )?;
    let updated = state
        .repository
        .update_reaction(actor_id, channel_id, message_id, emoji, added)
        .await?;
    if updated.changed {
        let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
        let event_type = if added {
            EventType::ReactionAdd
        } else {
            EventType::ReactionRemove
        };
        match &updated.audience {
            MessageAudience::Guild(guild_id) => publish_routed_event(
                &state,
                event_type,
                sequence,
                RoutingMetadata {
                    guild_id: guild_id.raw(),
                    channel_id: channel_id.raw(),
                },
                &updated.event,
            ),
            MessageAudience::Users(recipients) => publish_user_routed_event(
                &state,
                event_type,
                sequence,
                channel_id,
                recipients,
                &updated.event,
            ),
        }
    }
    Ok(Json(updated.event))
}

async fn create_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateMessageReport>,
) -> ApiResult<(StatusCode, Json<ReportReceipt>)> {
    let CreateMessageReport {
        message_id,
        category,
        detail,
        franking,
    } = input;
    let reporter_id = authenticated_user(&state, &headers)?;
    enforce_rate_limit(
        &state,
        format!("report:{reporter_id}"),
        RateLimit::new(5, std::time::Duration::from_secs(60)),
        "32a986bb",
        "user",
    )?;
    let detail = detail
        .map(|detail| detail.trim().to_owned())
        .filter(|detail| !detail.is_empty());
    if detail.as_ref().is_some_and(|detail| detail.len() > 2_000) {
        return Err(ApiError::bad_request(
            "report detail cannot exceed 2,000 bytes",
        ));
    }
    let message = state
        .repository
        .reportable_message(reporter_id, message_id)
        .await?;
    let (content, attachment_hashes, frank_tag) = if let Some(encryption) = &message.encryption {
        let evidence = franking.ok_or_else(|| {
            ApiError::bad_request("encrypted message reports require franking evidence")
        })?;
        if evidence.content.len() > 4_000 || evidence.attachment_sha256.len() > 10 {
            return Err(ApiError::bad_request(
                "message-franking evidence exceeds the message limits",
            ));
        }
        let attachment_hashes = evidence
            .attachment_sha256
            .iter()
            .map(|hash| {
                hex::decode(hash)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| ApiError::bad_request("attachment report hash is invalid"))
            })
            .collect::<ApiResult<Vec<[u8; 32]>>>()?;
        if attachment_hashes.len() != message.attachments.len() {
            return Err(ApiError::bad_request(
                "attachment report hashes do not match the reported message",
            ));
        }
        let franking_key: [u8; 32] =
            decode_base64url(&evidence.franking_key, "message-franking opening", 32)?
                .try_into()
                .map_err(|_| {
                    ApiError::bad_request("message-franking opening must contain exactly 32 bytes")
                })?;
        let submitted_tag: [u8; 32] =
            decode_base64url(&evidence.franking_tag, "message-franking tag", 32)?
                .try_into()
                .map_err(|_| {
                    ApiError::bad_request("message-franking tag must contain exactly 32 bytes")
                })?;
        let commitment: [u8; 32] = decode_base64url(
            &encryption.franking_commitment,
            "stored message-franking commitment",
            32,
        )?
        .try_into()
        .map_err(|_| ApiError::service_unavailable("stored franking evidence is invalid"))?;
        let opening_valid = verify_franking_opening(
            &evidence.content,
            &attachment_hashes,
            &franking_key,
            &commitment,
        )
        .map_err(|_| ApiError::bad_request("message-franking evidence is invalid"))?;
        let tag_valid = verify_message_franking_tag(&state.franking_key, &message, &submitted_tag)?;
        if !opening_valid || !tag_valid {
            return Err(ApiError::bad_request(
                "message-franking evidence could not be verified",
            ));
        }
        (
            evidence.content,
            evidence
                .attachment_sha256
                .into_iter()
                .map(|hash| hash.to_ascii_lowercase())
                .collect(),
            Some(submitted_tag),
        )
    } else {
        if franking.is_some() {
            return Err(ApiError::bad_request(
                "plaintext message reports do not accept franking evidence",
            ));
        }
        (message.content.clone(), Vec::new(), None)
    };
    let evidence = ReportEvidence {
        content,
        encrypted: message.encryption.is_some(),
        verified: true,
        attachments: message
            .attachments
            .iter()
            .enumerate()
            .map(|(index, attachment)| ReportEvidenceAttachment {
                id: attachment.id,
                filename: attachment.filename.clone(),
                content_type: attachment.content_type.clone(),
                size: attachment.size,
                sha256: attachment_hashes.get(index).cloned(),
            })
            .collect(),
        attachment_sha256: attachment_hashes,
    };
    let evidence_payload = serde_json::to_vec(&evidence)
        .map_err(|_| ApiError::bad_request("report evidence is invalid"))?;
    let guild_id = match state.repository.channel_guild_id(message.channel_id).await {
        Ok(guild_id) => Some(guild_id),
        Err(RepositoryError::NotFound(_)) => None,
        Err(error) => return Err(error.into()),
    };
    let receipt = state
        .repository
        .create_message_report(
            reporter_id,
            message.id,
            message.channel_id,
            message.author_id,
            guild_id,
            category,
            detail,
            evidence_payload,
            frank_tag,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(receipt)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperatorReportsQuery {
    status: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveOperatorReport {
    status: String,
    note: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountEnforcementRequest {
    reason: String,
    report_id: Option<ReportId>,
}

async fn list_operator_reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OperatorReportsQuery>,
) -> ApiResult<(HeaderMap, Json<Vec<OperatorReport>>)> {
    require_operator(&state, &headers)?;
    enforce_rate_limit(
        &state,
        "operator:reports:list".to_owned(),
        RateLimit::new(60, std::time::Duration::from_secs(60)),
        "68006bee",
        "operator",
    )?;
    let status = match query.status.as_deref().unwrap_or("open") {
        "open" => Some(OperatorReportStatus::Open),
        "actioned" => Some(OperatorReportStatus::Actioned),
        "dismissed" => Some(OperatorReportStatus::Dismissed),
        "all" => None,
        _ => {
            return Err(ApiError::bad_request(
                "status must be open, actioned, dismissed, or all",
            ));
        }
    };
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad_request(
            "operator report limit must be between 1 and 100",
        ));
    }
    let reports = state.repository.operator_reports(status, limit).await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    Ok((response_headers, Json(reports)))
}

async fn resolve_operator_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(report_id): Path<ReportId>,
    Json(input): Json<ResolveOperatorReport>,
) -> ApiResult<(HeaderMap, Json<OperatorReport>)> {
    require_operator(&state, &headers)?;
    enforce_rate_limit(
        &state,
        "operator:reports:resolve".to_owned(),
        RateLimit::new(30, std::time::Duration::from_secs(60)),
        "367046ea",
        "operator",
    )?;
    let status = match input.status.as_str() {
        "actioned" => OperatorReportStatus::Actioned,
        "dismissed" => OperatorReportStatus::Dismissed,
        _ => {
            return Err(ApiError::bad_request(
                "report status must be actioned or dismissed",
            ));
        }
    };
    let operator_name = state.operator.name.clone();
    let report = state
        .repository
        .resolve_operator_report(report_id, status, &operator_name, input.note)
        .await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    Ok((response_headers, Json(report)))
}

async fn operator_account_enforcement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<UserId>,
) -> ApiResult<(HeaderMap, Json<AccountEnforcementOverview>)> {
    require_operator(&state, &headers)?;
    enforce_rate_limit(
        &state,
        format!("operator:account-status:{user_id}"),
        RateLimit::new(60, std::time::Duration::from_secs(60)),
        "6ac563a1",
        "operator",
    )?;
    let overview = state.auth.account_enforcement(user_id, 50)?;
    Ok((operator_no_store_headers(), Json(overview)))
}

async fn suspend_operator_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<UserId>,
    Json(input): Json<AccountEnforcementRequest>,
) -> ApiResult<(HeaderMap, Json<AccountSuspension>)> {
    require_operator(&state, &headers)?;
    enforce_rate_limit(
        &state,
        format!("operator:account-suspend:{user_id}"),
        RateLimit::new(10, std::time::Duration::from_secs(60)),
        "b72b0056",
        "operator",
    )?;
    validate_enforcement_report_target(&state, input.report_id, user_id).await?;
    let operator_name = state.operator.name.clone();
    let report_id = input.report_id.map(|id| id.to_string());
    let suspension =
        state
            .auth
            .suspend_account(user_id, &operator_name, &input.reason, report_id.as_deref())?;
    state.suspended_gateway_users.write().await.insert(user_id);
    if let Ok(guilds) = state.repository.list_guilds(user_id).await {
        for guild in guilds {
            revoke_member_voice(&state, guild.id, user_id);
        }
    }
    publish_user_event(
        &state,
        EventType::SessionReplaced,
        &[user_id],
        &serde_json::json!({ "reason": "account_suspended" }),
    );
    Ok((operator_no_store_headers(), Json(suspension)))
}

async fn reinstate_operator_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<UserId>,
    Json(input): Json<AccountEnforcementRequest>,
) -> ApiResult<(HeaderMap, Json<AccountSuspension>)> {
    require_operator(&state, &headers)?;
    enforce_rate_limit(
        &state,
        format!("operator:account-reinstate:{user_id}"),
        RateLimit::new(10, std::time::Duration::from_secs(60)),
        "2cb45dc6",
        "operator",
    )?;
    validate_enforcement_report_target(&state, input.report_id, user_id).await?;
    let operator_name = state.operator.name.clone();
    let report_id = input.report_id.map(|id| id.to_string());
    let suspension = state.auth.reinstate_account(
        user_id,
        &operator_name,
        &input.reason,
        report_id.as_deref(),
    )?;
    state.suspended_gateway_users.write().await.remove(&user_id);
    Ok((operator_no_store_headers(), Json(suspension)))
}

async fn validate_enforcement_report_target(
    state: &AppState,
    report_id: Option<ReportId>,
    user_id: UserId,
) -> ApiResult<()> {
    if let Some(report_id) = report_id {
        let report = state.repository.operator_report(report_id).await?;
        if report.author.id != user_id {
            return Err(ApiError::bad_request(
                "the report does not identify this account as the reported author",
            ));
        }
    }
    Ok(())
}

fn operator_no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    headers
}

async fn automod_engine(state: &AppState, guild_id: GuildId) -> ApiResult<Arc<AutomodEngine>> {
    if let Some(engine) = state.automod_engines.read().await.get(&guild_id).cloned() {
        return Ok(engine);
    }
    let rules = state.repository.active_automod_rules(guild_id).await?;
    let engine = Arc::new(AutomodEngine::compile(&rules).map_err(|error| {
        tracing::error!(%error, %guild_id, "stored automod rules could not be compiled");
        ApiError::service_unavailable("server safety rules are temporarily unavailable")
    })?);
    let mut engines = state.automod_engines.write().await;
    Ok(engines.entry(guild_id).or_insert(engine).clone())
}

async fn invalidate_automod_engine(state: &AppState, guild_id: GuildId) {
    state.automod_engines.write().await.remove(&guild_id);
}

#[derive(Serialize)]
struct LiveKitTokenClaims {
    iss: String,
    sub: String,
    name: String,
    nbf: i64,
    exp: i64,
    jti: String,
    video: LiveKitVideoGrant,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LiveKitVideoGrant {
    room_join: bool,
    room: String,
    can_publish: bool,
    can_subscribe: bool,
    can_publish_data: bool,
    can_publish_sources: Vec<&'static str>,
    can_update_own_metadata: bool,
}

async fn create_voice_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> ApiResult<(HeaderMap, Json<VoiceJoinGrant>)> {
    let user_id = authenticated_user(&state, &headers)?;
    let channel_id = channel_id
        .parse::<ChannelId>()
        .map_err(|_| ApiError::bad_request("invalid channel id"))?;
    let config = state
        .voice
        .as_ref()
        .ok_or_else(|| ApiError::service_unavailable("voice service is not configured"))?;
    let access = state.repository.voice_access(user_id, channel_id).await?;
    let grant = issue_voice_grant(config, access)?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, private"),
    );
    Ok((response_headers, Json(grant)))
}

fn issue_voice_grant(config: &VoiceConfig, access: VoiceAccess) -> ApiResult<VoiceJoinGrant> {
    let issued_at = Utc::now();
    let expires_at = issued_at + ChronoDuration::seconds(config.token_ttl_seconds);
    let can_speak = access
        .permissions
        .contains(GuildPermissions::SPEAK | GuildPermissions::USE_VAD);
    let can_stream = access.permissions.contains(GuildPermissions::STREAM);
    let mut sources = Vec::with_capacity(3);
    if can_speak {
        sources.push("microphone");
    }
    if can_stream {
        sources.extend(["screen_share", "screen_share_audio"]);
    }
    let room_name = access.guild_id.map_or_else(
        || VoiceConfig::direct_room_name(access.channel_id),
        |guild_id| VoiceConfig::room_name(guild_id, access.channel_id),
    );
    let claims = LiveKitTokenClaims {
        iss: config.api_key.clone(),
        sub: access.user.id.to_string(),
        name: access.user.display_name.clone(),
        nbf: issued_at.timestamp().saturating_sub(5),
        exp: expires_at.timestamp(),
        jti: Uuid::now_v7().to_string(),
        video: LiveKitVideoGrant {
            room_join: true,
            room: room_name.clone(),
            can_publish: can_speak || can_stream,
            can_subscribe: true,
            can_publish_data: false,
            can_publish_sources: sources,
            can_update_own_metadata: false,
        },
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.api_secret.as_bytes()),
    )
    .map_err(|error| {
        tracing::error!(%error, "LiveKit grant signing failed");
        ApiError::service_unavailable("voice credential could not be issued")
    })?;
    Ok(VoiceJoinGrant {
        channel_id: access.channel_id,
        guild_id: access.guild_id,
        room_name,
        server_url: config.server_url.clone(),
        token,
        expires_at,
        participant_id: access.user.id,
        participant_name: access.user.display_name,
        can_speak,
        can_stream,
        transport_encrypted: true,
        end_to_end_encrypted: false,
    })
}

async fn gateway(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let principal = match authenticated_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(_) if state.allow_development_auth => {
            let Some(user_id) = headers
                .get("x-exocord-user-id")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<UserId>().ok())
            else {
                return ApiError::unauthorized("a valid session is required").into_response();
            };
            Principal {
                user_id,
                session_id: "development".into(),
                device_id: Uuid::nil(),
            }
        }
        Err(error) => return error.into_response(),
    };
    if principal.session_id != "development"
        && let Err(error) = require_active_account(&state, principal.user_id)
    {
        return error.into_response();
    }
    let user_id = principal.user_id;
    let session_principal = (principal.session_id != "development").then_some(principal);
    ws.max_message_size(64 * 1024)
        .on_upgrade(move |socket| gateway_session(socket, state, user_id, session_principal))
}

async fn gateway_session(
    mut socket: WebSocket,
    state: AppState,
    user_id: UserId,
    session_principal: Option<Principal>,
) {
    let mut events = state.events.subscribe();
    let became_online = {
        let mut connections = state.presence_connections.lock().await;
        let count = connections.entry(user_id).or_default();
        *count = count.saturating_add(1);
        *count == 1
    };
    if became_online {
        publish_presence(&state, user_id, PresenceStatus::Online).await;
    }
    let mut visible_guilds = match state.repository.list_guilds(user_id).await {
        Ok(guilds) => guilds
            .into_iter()
            .map(|guild| guild.id)
            .collect::<HashSet<_>>(),
        Err(error) => {
            tracing::warn!(
                %error,
                %user_id,
                "gateway initialization stopped because server visibility could not be loaded"
            );
            release_presence(&state, user_id).await;
            return;
        }
    };
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    let ready = ReadyPayload {
        session_id: Uuid::now_v7().to_string(),
        heartbeat_interval_ms: 30_000,
        resume_gateway_url: "/gateway".into(),
    };
    if let Ok(frame) = encode_frame(EventType::Ready, sequence, &ready)
        && socket.send(WsMessage::Binary(frame.into())).await.is_err()
    {
        release_presence(&state, user_id).await;
        return;
    }

    loop {
        tokio::select! {
            incoming = socket.next() => {
                match incoming {
                    Some(Ok(WsMessage::Ping(bytes))) => {
                        if socket.send(WsMessage::Pong(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            outbound = events.recv() => {
                match outbound {
                    Ok(event) => {
                        if let Some(principal) = &session_principal
                            && (state
                                .revoked_gateway_devices
                                .read()
                                .await
                                .contains(&principal.device_id)
                                || state
                                    .suspended_gateway_users
                                    .read()
                                    .await
                                    .contains(&user_id))
                        {
                            break;
                        }
                        if event
                            .recipients
                            .as_ref()
                            .is_some_and(|recipients| !recipients.contains(&user_id))
                        {
                            continue;
                        }
                        if let Some(guild_id) = event.guild_id {
                            match state.repository.is_guild_member(user_id, guild_id).await {
                                Ok(true) => {
                                    visible_guilds.insert(guild_id);
                                }
                                Ok(false) | Err(_) => {
                                    visible_guilds.remove(&guild_id);
                                    continue;
                                }
                            }
                        }
                        if let Some(channel_id) = event.channel_id
                            && state
                                .repository
                                .channel_event_audience(user_id, channel_id, false)
                                .await
                                .is_err()
                        {
                            continue;
                        }
                        if socket.send(WsMessage::Binary(event.frame.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    release_presence(&state, user_id).await;
}

async fn release_presence(state: &AppState, user_id: UserId) {
    let became_offline = {
        let mut connections = state.presence_connections.lock().await;
        let Some(count) = connections.get_mut(&user_id) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            connections.remove(&user_id);
            true
        } else {
            false
        }
    };
    if became_offline {
        publish_presence(state, user_id, PresenceStatus::Offline).await;
    }
}

async fn publish_presence(state: &AppState, user_id: UserId, status: PresenceStatus) {
    if let Ok(mut recipients) = state.repository.presence_audience(user_id).await {
        recipients.retain(|recipient| *recipient != user_id);
        publish_user_event(
            state,
            EventType::PresenceUpdate,
            &recipients,
            &UserPresence {
                user_id,
                status,
                updated_at: Utc::now(),
            },
        );
    }
}

fn publish_event<T: Serialize>(
    state: &AppState,
    event_type: EventType,
    guild_id: Option<GuildId>,
    payload: &T,
) {
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    if let Ok(frame) = encode_frame(event_type, sequence, payload) {
        let _ = state.events.send(PublishedEvent {
            frame,
            guild_id,
            channel_id: None,
            recipients: None,
        });
    }
}

fn publish_routed_event<T: Serialize>(
    state: &AppState,
    event_type: EventType,
    sequence: u32,
    routing: RoutingMetadata,
    payload: &T,
) {
    if let Ok(frame) = encode_routed_frame(event_type, sequence, routing, payload) {
        let guild_id = GuildId::from_raw(routing.guild_id).ok();
        let _ = state.events.send(PublishedEvent {
            frame,
            guild_id,
            channel_id: ChannelId::from_raw(routing.channel_id).ok(),
            recipients: None,
        });
    }
}

fn publish_user_routed_event<T: Serialize>(
    state: &AppState,
    event_type: EventType,
    sequence: u32,
    channel_id: ChannelId,
    recipients: &[UserId],
    payload: &T,
) {
    let routing = RoutingMetadata {
        guild_id: 0,
        channel_id: channel_id.raw(),
    };
    if let Ok(frame) = encode_routed_frame(event_type, sequence, routing, payload) {
        let _ = state.events.send(PublishedEvent {
            frame,
            guild_id: None,
            channel_id: Some(channel_id),
            recipients: Some(Arc::new(recipients.iter().copied().collect())),
        });
    }
}

fn publish_user_event<T: Serialize>(
    state: &AppState,
    event_type: EventType,
    recipients: &[UserId],
    payload: &T,
) {
    let sequence = state.next_sequence.fetch_add(1, Ordering::Relaxed);
    if let Ok(frame) = encode_frame(event_type, sequence, payload) {
        let _ = state.events.send(PublishedEvent {
            frame,
            guild_id: None,
            channel_id: None,
            recipients: Some(Arc::new(recipients.iter().copied().collect())),
        });
    }
}

fn authenticated_principal(state: &AppState, headers: &HeaderMap) -> ApiResult<Principal> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("a bearer session is required"))?;
    state.auth.authenticate(token).map_err(Into::into)
}

fn authenticated_device_principal(state: &AppState, headers: &HeaderMap) -> ApiResult<Principal> {
    if let Ok(principal) = authenticated_principal(state, headers) {
        require_active_account(state, principal.user_id)?;
        return Ok(principal);
    }
    if state.allow_development_auth {
        let user_id = headers
            .get("x-exocord-user-id")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::unauthorized("a valid session is required"))?
            .parse::<UserId>()
            .map_err(|_| ApiError::unauthorized("invalid development user"))?;
        let device_id = headers
            .get("x-exocord-device-id")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                ApiError::unauthorized("a device-bound session or development device is required")
            })
            .and_then(|value| {
                Uuid::parse_str(value)
                    .map_err(|_| ApiError::unauthorized("invalid development device"))
            })?;
        return Ok(Principal {
            user_id,
            session_id: "development".into(),
            device_id,
        });
    }
    Err(ApiError::unauthorized(
        "a valid device-bound session is required",
    ))
}

fn authenticated_user(state: &AppState, headers: &HeaderMap) -> ApiResult<UserId> {
    if let Ok(principal) = authenticated_principal(state, headers) {
        require_active_account(state, principal.user_id)?;
        return Ok(principal.user_id);
    }
    if state.allow_development_auth {
        return headers
            .get("x-exocord-user-id")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::unauthorized("a valid session is required"))?
            .parse::<UserId>()
            .map_err(|_| ApiError::unauthorized("invalid development user"));
    }
    Err(ApiError::unauthorized("a valid session is required"))
}

fn require_operator(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let supplied = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let valid = supplied
        .zip(state.operator_token_hash.as_ref())
        .is_some_and(|(token, expected)| {
            let supplied_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            bool::from(supplied_hash.ct_eq(expected))
        });
    if valid {
        Ok(())
    } else {
        Err(ApiError::unauthorized("operator credentials are required"))
    }
}

fn require_active_account(state: &AppState, user_id: UserId) -> ApiResult<()> {
    if state.auth.account_deletion(user_id)?.is_some() {
        return Err(ApiError::forbidden_message(
            "account deletion is pending; cancel it before using Exocord",
        ));
    }
    Ok(())
}

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: u32,
    message: String,
    rate_limit: Option<RateMetadata>,
}

#[derive(Clone, Debug)]
struct RateMetadata {
    decision: RateLimitDecision,
    bucket: &'static str,
    scope: &'static str,
    global: bool,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: 50_035,
            message: message.into(),
            rate_limit: None,
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: 40_001,
            message: message.into(),
            rate_limit: None,
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: 50_013,
            message: "you do not have permission to perform this action".into(),
            rate_limit: None,
        }
    }

    fn forbidden_message(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: 50_013,
            message: message.into(),
            rate_limit: None,
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: 40_009,
            message: message.into(),
            rate_limit: None,
        }
    }

    fn moderated(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: 20_001,
            message: message.into(),
            rate_limit: None,
        }
    }

    fn proof_required() -> Self {
        Self {
            status: StatusCode::PRECONDITION_REQUIRED,
            code: 40_028,
            message: "a fresh proof-of-work challenge is required".into(),
            rate_limit: None,
        }
    }

    fn not_found(resource: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: 10_003,
            message: format!("{resource} was not found"),
            rate_limit: None,
        }
    }

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: 50_300,
            message: message.into(),
            rate_limit: None,
        }
    }

    fn insufficient_storage(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INSUFFICIENT_STORAGE,
            code: 50_700,
            message: message.into(),
            rate_limit: None,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: 50_000,
            message: message.into(),
            rate_limit: None,
        }
    }

    fn rate_limited(metadata: RateMetadata) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: 20_028,
            message: "you are being rate limited".into(),
            rate_limit: Some(metadata),
        }
    }
}

impl From<ValidationError> for ApiError {
    fn from(error: ValidationError) -> Self {
        Self::bad_request(error.to_string())
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::InvalidEmail
            | AuthError::InvalidUsername
            | AuthError::WeakPassword
            | AuthError::InvalidCurrentPassword
            | AuthError::PasswordUnchanged
            | AuthError::InvalidRecoveryCode
            | AuthError::InvalidRecoveryMaterial
            | AuthError::RecoveryKeyUnavailable
            | AuthError::InvalidCode
            | AuthError::InvalidEnforcement
            | AuthError::InvalidDevice => Self::bad_request(error.to_string()),
            AuthError::InvalidCredentials | AuthError::InvalidSession | AuthError::RefreshReuse => {
                Self::unauthorized(error.to_string())
            }
            AuthError::AccountExists | AuthError::UsernameExists => {
                Self::conflict(error.to_string())
            }
            AuthError::DeviceRevoked | AuthError::AccountSuspended => {
                Self::forbidden_message(error.to_string())
            }
            AuthError::InvalidAppleFlow
            | AuthError::AppleNotLinked
            | AuthError::DeletionUnavailable => Self::bad_request(error.to_string()),
            AuthError::AppleLinkRequired
            | AuthError::AppleAlreadyLinked
            | AuthError::AppleUnlinkUnsafe
            | AuthError::AccountEnforcementConflict => Self::conflict(error.to_string()),
            AuthError::AccountUnavailable => Self::not_found("account"),
            AuthError::AppleFailure
            | AuthError::Encryption
            | AuthError::Randomness
            | AuthError::Storage => Self::service_unavailable(error.to_string()),
        }
    }
}

impl From<ProofOfWorkError> for ApiError {
    fn from(error: ProofOfWorkError) -> Self {
        match error {
            ProofOfWorkError::InvalidChallenge | ProofOfWorkError::InvalidSolution => {
                Self::bad_request(error.to_string())
            }
            ProofOfWorkError::Randomness | ProofOfWorkError::Exhausted => {
                Self::service_unavailable(error.to_string())
            }
        }
    }
}

impl From<RepositoryError> for ApiError {
    fn from(error: RepositoryError) -> Self {
        match error {
            RepositoryError::NotFound(resource) => Self::not_found(resource),
            RepositoryError::Forbidden => Self::forbidden(),
            RepositoryError::BadRequest(message) => Self::bad_request(message),
            RepositoryError::Validation(message) => Self::bad_request(message),
            RepositoryError::InviteUnavailable => Self::not_found("invite"),
            RepositoryError::Conflict => Self::conflict("the requested state already exists"),
            RepositoryError::InvalidData(message) => Self::internal(message),
            RepositoryError::Migration(_)
            | RepositoryError::Database(_)
            | RepositoryError::AttachmentStorage(_) => {
                tracing::error!(%error, "repository operation failed");
                Self::service_unavailable("server storage is temporarily unavailable")
            }
        }
    }
}

impl From<MediaError> for ApiError {
    fn from(error: MediaError) -> Self {
        match error {
            MediaError::Disabled => {
                Self::service_unavailable("attachment storage is not configured")
            }
            MediaError::InvalidCapability | MediaError::MissingObject => {
                Self::not_found("attachment")
            }
            MediaError::SizeMismatch
            | MediaError::HashMismatch
            | MediaError::TypeMismatch
            | MediaError::UnsupportedType
            | MediaError::UnsafeImage => Self::bad_request(error.to_string()),
            MediaError::Capacity => Self::insufficient_storage(error.to_string()),
            MediaError::Storage(_) => {
                tracing::error!(%error, "attachment storage operation failed");
                Self::service_unavailable("attachment storage is temporarily unavailable")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            code: u32,
            message: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            retry_after: Option<f64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            global: Option<bool>,
        }
        let retry_after = self
            .rate_limit
            .as_ref()
            .map(|metadata| metadata.decision.retry_after.as_secs_f64());
        let global = self.rate_limit.as_ref().map(|metadata| metadata.global);
        let mut response = (
            self.status,
            Json(Body {
                code: self.code,
                message: self.message,
                retry_after,
                global,
            }),
        )
            .into_response();
        if let Some(metadata) = &self.rate_limit {
            apply_rate_limit_headers(response.headers_mut(), metadata);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, Bytes, to_bytes},
        http::{HeaderMap, Request, Uri},
        response::IntoResponse,
    };
    use exo_client::{ApiClient, GatewayEvent, LocalStore, MessageState};
    use exo_crypto::{MessageContext as CryptoMessageContext, MlsClient, PublishedKeyPackage};
    use exo_domain::{
        ChannelKind, CreateMessageReport, MessageFrankingEvidence, ReportCategory,
        SearchExclusionReason,
    };
    use tower::ServiceExt;

    use super::*;

    async fn capture_livekit_request(
        axum::extract::State(sender): axum::extract::State<
            tokio::sync::mpsc::Sender<(Uri, HeaderMap, Bytes)>,
        >,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        let _ = sender.send((uri, headers, body)).await;
        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/protobuf")],
            Vec::<u8>::new(),
        )
    }

    fn bytes_contain(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    #[test]
    fn trusted_proxy_mode_ignores_client_spoofable_forwarding_headers() {
        let state = AppState::seeded().with_trusted_proxy_headers(true);
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.10".parse().unwrap());
        headers.insert("x-forwarded-for", "203.0.113.11".parse().unwrap());
        headers.insert("x-exocord-proxy-client-ip", "198.51.100.7".parse().unwrap());
        let peer = Some("10.0.0.2:4100".parse().unwrap());

        assert_eq!(client_key(&state, &headers, peer), "198.51.100.7");
        headers.remove("x-exocord-proxy-client-ip");
        assert_eq!(client_key(&state, &headers, peer), "10.0.0.2");
    }

    async fn development_email_login(
        app: &Router,
        email: &str,
        device_id: &str,
    ) -> serde_json::Value {
        let challenge = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/email/request")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "email": email }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge: serde_json::Value =
            serde_json::from_slice(&to_bytes(challenge.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        let verified = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/email/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "challengeId": challenge["challengeId"],
                            "code": challenge["developmentCode"],
                            "deviceId": device_id,
                            "clientName": "Account privacy test"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verified.status(), StatusCode::OK);
        serde_json::from_slice(&to_bytes(verified.into_body(), 32 * 1024).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn health_endpoint_is_available() {
        let response = build_router(AppState::seeded())
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap().as_ref(),
            b"ok"
        );
    }

    #[tokio::test]
    async fn password_registration_and_login_issue_real_sessions() {
        let app = build_router(AppState::seeded());
        let device_id = "018f04b2-3c71-7f42-b12d-6f090d44be11";
        let registration_body = serde_json::json!({
            "email": "alpha-password@example.com",
            "username": "alpha-password",
            "password": "correct horse battery staple",
            "deviceId": device_id,
            "clientName": "Exocord password API test"
        })
        .to_string();
        let registered = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/register")
                    .header("content-type", "application/json")
                    .body(Body::from(registration_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registered.status(), StatusCode::OK);
        let registered: serde_json::Value =
            serde_json::from_slice(&to_bytes(registered.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(registered["user"]["email"], "alpha-password@example.com");
        assert!(
            registered["accessToken"]
                .as_str()
                .is_some_and(|token| token.starts_with("exo_at_"))
        );

        let duplicate = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/register")
                    .header("content-type", "application/json")
                    .body(Body::from(registration_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);

        let login_body = |email: &str, password: &str| {
            serde_json::json!({
                "email": email,
                "password": password,
                "deviceId": device_id,
                "clientName": "Exocord password API test"
            })
            .to_string()
        };
        let wrong = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/login")
                    .header("content-type", "application/json")
                    .body(Body::from(login_body(
                        "alpha-password@example.com",
                        "wrong password",
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let wrong: serde_json::Value =
            serde_json::from_slice(&to_bytes(wrong.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(wrong["message"], "the email or password is incorrect");

        let signed_in = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/login")
                    .header("content-type", "application/json")
                    .body(Body::from(login_body(
                        "alpha-password@example.com",
                        "correct horse battery staple",
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(signed_in.status(), StatusCode::OK);
        let signed_in: serde_json::Value =
            serde_json::from_slice(&to_bytes(signed_in.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        let access_token = signed_in["accessToken"].as_str().unwrap();
        let changed = app
            .clone()
            .oneshot(
                Request::put("/v1/users/@me/password")
                    .header("authorization", format!("Bearer {access_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "currentPassword": "correct horse battery staple",
                            "newPassword": "a new correct horse password"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(changed.status(), StatusCode::NO_CONTENT);

        let old_password = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/login")
                    .header("content-type", "application/json")
                    .body(Body::from(login_body(
                        "alpha-password@example.com",
                        "correct horse battery staple",
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_password.status(), StatusCode::UNAUTHORIZED);

        let new_password = app
            .oneshot(
                Request::post("/v1/auth/password/login")
                    .header("content-type", "application/json")
                    .body(Body::from(login_body(
                        "alpha-password@example.com",
                        "a new correct horse password",
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(new_password.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn operator_suspension_cuts_off_sessions_and_can_be_reinstated() {
        const OPERATOR_TOKEN: &str = "exo_op_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let app = build_router(AppState::seeded().with_operator_token(OPERATOR_TOKEN));
        let device_id = "018f04b2-3c71-7f42-b12d-6f090d44be21";
        let registered = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "suspended-api@example.com",
                            "username": "suspended-api",
                            "password": "correct horse battery staple",
                            "deviceId": device_id,
                            "clientName": "Account enforcement API test"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registered.status(), StatusCode::OK);
        let registered: serde_json::Value =
            serde_json::from_slice(&to_bytes(registered.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        let user_id = registered["user"]["id"].as_str().unwrap();
        let old_access = registered["accessToken"].as_str().unwrap();
        let suspension_uri = format!("/v1/operator/users/{user_id}/suspension");

        let regular_user_denied = app
            .clone()
            .oneshot(
                Request::get(&suspension_uri)
                    .header("authorization", format!("Bearer {old_access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(regular_user_denied.status(), StatusCode::UNAUTHORIZED);

        let suspended = app
            .clone()
            .oneshot(
                Request::put(&suspension_uri)
                    .header("authorization", format!("Bearer {OPERATOR_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "reason": "Credible severe-abuse report."
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(suspended.status(), StatusCode::OK);
        assert_eq!(
            suspended.headers().get(CACHE_CONTROL).unwrap(),
            "no-store, private"
        );
        let suspended: serde_json::Value =
            serde_json::from_slice(&to_bytes(suspended.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(suspended["suspended"], true);
        assert_eq!(suspended["reason"], "Credible severe-abuse report.");

        let old_session = app
            .clone()
            .oneshot(
                Request::get("/v1/auth/me")
                    .header("authorization", format!("Bearer {old_access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_session.status(), StatusCode::UNAUTHORIZED);

        let login = |password: &str| {
            Request::post("/v1/auth/password/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": "suspended-api@example.com",
                        "password": password,
                        "deviceId": device_id,
                        "clientName": "Account enforcement API test"
                    })
                    .to_string(),
                ))
                .unwrap()
        };
        let blocked_login = app
            .clone()
            .oneshot(login("correct horse battery staple"))
            .await
            .unwrap();
        assert_eq!(blocked_login.status(), StatusCode::FORBIDDEN);

        let overview = app
            .clone()
            .oneshot(
                Request::get(&suspension_uri)
                    .header("authorization", format!("Bearer {OPERATOR_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(overview.status(), StatusCode::OK);
        let overview: serde_json::Value =
            serde_json::from_slice(&to_bytes(overview.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(overview["suspension"]["suspended"], true);
        assert_eq!(overview["events"].as_array().unwrap().len(), 1);
        assert_eq!(overview["events"][0]["action"], "suspended");

        let reinstated = app
            .clone()
            .oneshot(
                Request::delete(&suspension_uri)
                    .header("authorization", format!("Bearer {OPERATOR_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "reason": "Appeal accepted after review."
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reinstated.status(), StatusCode::OK);
        let reinstated: serde_json::Value =
            serde_json::from_slice(&to_bytes(reinstated.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(reinstated["suspended"], false);

        let fresh_login = app
            .oneshot(login("correct horse battery staple"))
            .await
            .unwrap();
        assert_eq!(fresh_login.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn recovery_code_rotates_credentials_and_old_sessions() {
        let app = build_router(AppState::seeded());
        let registered = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "recovery-api@example.com",
                            "username": "recovery-api",
                            "password": "first recovery API password",
                            "deviceId": "018f04b2-3c71-7f42-b12d-6f090d44be11",
                            "clientName": "Recovery API test"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registered.status(), StatusCode::OK);
        let registered: serde_json::Value =
            serde_json::from_slice(&to_bytes(registered.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        let old_access = registered["accessToken"].as_str().unwrap();
        let recovery_code = registered["recoveryCodes"][0].as_str().unwrap();
        assert_eq!(registered["recoveryCodes"].as_array().unwrap().len(), 8);

        let recovered = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/recover")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "recovery-api@example.com",
                            "recoveryCode": recovery_code,
                            "newPassword": "second recovery API password",
                            "deviceId": "018f04b2-3c71-7f42-b12d-6f090d44be12",
                            "clientName": "Recovery API test"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
        let recovered: serde_json::Value =
            serde_json::from_slice(&to_bytes(recovered.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(recovered["recoveryCodes"].as_array().unwrap().len(), 8);
        assert_ne!(recovered["recoveryCodes"][0], recovery_code);

        let old_session = app
            .clone()
            .oneshot(
                Request::get("/v1/auth/me")
                    .header("authorization", format!("Bearer {old_access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_session.status(), StatusCode::UNAUTHORIZED);

        let reused = app
            .oneshot(
                Request::post("/v1/auth/password/recover")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "recovery-api@example.com",
                            "recoveryCode": recovery_code,
                            "newPassword": "third recovery API password",
                            "deviceId": "018f04b2-3c71-7f42-b12d-6f090d44be13",
                            "clientName": "Recovery API test"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reused.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn operator_identity_is_public_before_login() {
        let state = AppState::seeded().with_operator_info(OperatorInfo {
            name: "Exocord Test Alpha".to_owned(),
            privacy_url: Some("https://alpha.example.test/privacy".to_owned()),
            terms_url: None,
            support_email: Some("help@alpha.example.test".to_owned()),
            abuse_email: Some("abuse@alpha.example.test".to_owned()),
        });
        let response = build_router(state)
            .oneshot(
                Request::get("/v1/meta/operator")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["name"], "Exocord Test Alpha");
        assert_eq!(body["privacyUrl"], "https://alpha.example.test/privacy");
        assert_eq!(body["abuseEmail"], "abuse@alpha.example.test");
    }

    #[tokio::test]
    async fn policy_pages_are_self_contained_hardened_and_escape_operator_data() {
        let state = AppState::seeded().with_operator_info(OperatorInfo {
            name: "Alpha <script>alert(1)</script>".to_owned(),
            privacy_url: Some("https://alpha.example.test/privacy".to_owned()),
            terms_url: Some("https://alpha.example.test/terms".to_owned()),
            support_email: Some("help@alpha.example.test".to_owned()),
            abuse_email: Some("abuse@alpha.example.test".to_owned()),
        });
        for (path, marker) in [
            ("/privacy", "data-exocord-policy=\"privacy-v2\""),
            ("/terms", "data-exocord-policy=\"terms-v2\""),
        ] {
            let response = build_router(state.clone())
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["content-type"],
                "text/html; charset=utf-8"
            );
            assert!(
                response.headers()["content-security-policy"]
                    .to_str()
                    .unwrap()
                    .contains("default-src 'none'")
            );
            let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.contains(marker));
            assert!(body.contains("Alpha &lt;script&gt;alert(1)&lt;/script&gt;"));
            assert!(!body.contains("<script>alert(1)</script>"));
            assert!(!body.contains("<script"));
        }
    }

    #[tokio::test]
    async fn production_cors_allows_only_the_configured_desktop_origin() {
        let app = build_router_with_allowed_origins(
            AppState::seeded(),
            Some(vec![HeaderValue::from_static("http://tauri.localhost")]),
        );
        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/auth/providers")
                    .header("origin", "http://tauri.localhost")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            allowed
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "http://tauri.localhost"
        );

        let rejected = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/auth/providers")
                    .header("origin", "https://malicious.example.test")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            rejected
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
    }

    #[tokio::test]
    async fn account_export_and_deletion_grace_are_enforced_over_http() {
        let auth = AuthService::in_memory(EmailDelivery::DevelopmentConsole, None).unwrap();
        let app = build_router(AppState::seeded_with_auth(auth, true));
        let email = "privacy-export@example.test";
        let device_id = "018f04b2-3c71-7f42-b12d-6f090d44be20";
        let first_session = development_email_login(&app, email, device_id).await;
        let first_token = first_session["accessToken"].as_str().unwrap();

        let export = app
            .clone()
            .oneshot(
                Request::get("/v1/users/@me/data-export")
                    .header("authorization", format!("Bearer {first_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(export.status(), StatusCode::OK);
        assert_eq!(
            export.headers().get(CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        assert!(
            export
                .headers()
                .get(CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("attachment; filename=\"exocord-data-export-")
        );
        let export_bytes = to_bytes(export.into_body(), 512 * 1024).await.unwrap();
        let exported: serde_json::Value = serde_json::from_slice(&export_bytes).unwrap();
        assert_eq!(exported["format"], 1);
        assert_eq!(exported["authentication"]["profile"]["email"], email);
        assert_eq!(
            exported["account"]["profile"]["id"],
            first_session["user"]["id"]
        );
        assert!(!bytes_contain(&export_bytes, "accessToken"));
        assert!(!bytes_contain(&export_bytes, "refreshToken"));
        assert!(!bytes_contain(&export_bytes, "tokenHash"));

        let scheduled = app
            .clone()
            .oneshot(
                Request::delete("/v1/users/@me")
                    .header("authorization", format!("Bearer {first_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scheduled.status(), StatusCode::OK);
        let scheduled: serde_json::Value =
            serde_json::from_slice(&to_bytes(scheduled.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert!(scheduled["deletion"]["requestedAt"].is_string());
        assert!(scheduled["deletion"]["scheduledFor"].is_string());

        let old_session = app
            .clone()
            .oneshot(
                Request::get("/v1/auth/me")
                    .header("authorization", format!("Bearer {first_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_session.status(), StatusCode::UNAUTHORIZED);

        let second_session = development_email_login(&app, email, device_id).await;
        assert!(second_session["user"]["deletionScheduledFor"].is_string());
        let second_token = second_session["accessToken"].as_str().unwrap();
        let restricted = app
            .clone()
            .oneshot(
                Request::post("/v1/guilds")
                    .header("authorization", format!("Bearer {second_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"Must not be created"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(restricted.status(), StatusCode::FORBIDDEN);
        let cancelled = app
            .clone()
            .oneshot(
                Request::delete("/v1/users/@me/deletion")
                    .header("authorization", format!("Bearer {second_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cancelled.status(), StatusCode::NO_CONTENT);

        let status = app
            .oneshot(
                Request::get("/v1/users/@me/deletion")
                    .header("authorization", format!("Bearer {second_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&to_bytes(status.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert!(status["deletion"].is_null());
    }

    #[tokio::test]
    async fn account_deletion_requires_server_ownership_resolution_over_http() {
        let auth = AuthService::in_memory(EmailDelivery::DevelopmentConsole, None).unwrap();
        let app = build_router(AppState::seeded_with_auth(auth, true));
        let owner = development_email_login(
            &app,
            "server-owner@example.test",
            "018f04b2-3c71-7f42-b12d-6f090d44be31",
        )
        .await;
        let member = development_email_login(
            &app,
            "next-owner@example.test",
            "018f04b2-3c71-7f42-b12d-6f090d44be32",
        )
        .await;
        let owner_token = owner["accessToken"].as_str().unwrap();
        let member_token = member["accessToken"].as_str().unwrap();
        let member_id = member["user"]["id"].as_str().unwrap();

        let created = app
            .clone()
            .oneshot(
                Request::post("/v1/guilds")
                    .header("authorization", format!("Bearer {owner_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"Ownership Test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let guild: serde_json::Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        let guild_id = guild["id"].as_str().unwrap();
        let invite = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/guilds/{guild_id}/invites"))
                    .header("authorization", format!("Bearer {owner_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"maxUses":1,"expiresInSeconds":3600}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invite.status(), StatusCode::CREATED);
        let invite: serde_json::Value =
            serde_json::from_slice(&to_bytes(invite.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        let code = invite["code"].as_str().unwrap();
        let accepted = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/invites/{code}"))
                    .header("authorization", format!("Bearer {member_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);

        let status = app
            .clone()
            .oneshot(
                Request::get("/v1/users/@me/deletion")
                    .header("authorization", format!("Bearer {owner_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&to_bytes(status.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(status["ownedServers"][0]["memberCount"], 2);

        let blocked = app
            .clone()
            .oneshot(
                Request::delete("/v1/users/@me")
                    .header("authorization", format!("Bearer {owner_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::CONFLICT);

        let transferred = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/guilds/{guild_id}/owner"))
                    .header("authorization", format!("Bearer {owner_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "ownerId": member_id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(transferred.status(), StatusCode::OK);
        let transferred: serde_json::Value =
            serde_json::from_slice(&to_bytes(transferred.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(transferred["owner_id"], member_id);

        let scheduled = app
            .clone()
            .oneshot(
                Request::delete("/v1/users/@me")
                    .header("authorization", format!("Bearer {owner_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scheduled.status(), StatusCode::OK);

        let wrong_confirmation = app
            .clone()
            .oneshot(
                Request::delete(format!("/v1/guilds/{guild_id}"))
                    .header("authorization", format!("Bearer {member_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"confirmation":"Ownership test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_confirmation.status(), StatusCode::BAD_REQUEST);
        let deleted = app
            .oneshot(
                Request::delete(format!("/v1/guilds/{guild_id}"))
                    .header("authorization", format!("Bearer {member_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"confirmation":"Ownership Test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn due_account_cleanup_is_idempotent_and_keeps_anonymized_messages() {
        let auth = AuthService::in_memory(EmailDelivery::DevelopmentConsole, None).unwrap();
        let state = AppState::seeded_with_auth(auth, true);
        let app = build_router(state.clone());
        let session = development_email_login(
            &app,
            "due-account@example.test",
            "018f04b2-3c71-7f42-b12d-6f090d44be21",
        )
        .await;
        let token = session["accessToken"].as_str().unwrap();
        let principal = state.auth.authenticate(token).unwrap();
        let guild = state
            .repository
            .create_guild(principal.user_id, "Privacy Archive".into(), 0x8B7CFF)
            .await
            .unwrap();
        let text_channel = guild
            .channels
            .iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let message = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{}/messages", text_channel.id))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"content":"Keep this shared context.","nonce":"privacy-cleanup"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(message.status(), StatusCode::CREATED);
        let exported_before = state
            .repository
            .account_data_export(principal.user_id)
            .await
            .unwrap();
        assert_eq!(exported_before.messages.len(), 1);
        state
            .auth
            .schedule_account_deletion(&principal, Utc::now() - ChronoDuration::days(31))
            .unwrap();

        assert_eq!(
            state
                .finalize_due_account_deletions(Utc::now(), 100)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            state
                .finalize_due_account_deletions(Utc::now(), 100)
                .await
                .unwrap(),
            0
        );
        assert!(state.auth.user(principal.user_id).is_err());
        let exported_after = state
            .repository
            .account_data_export(principal.user_id)
            .await
            .unwrap();
        assert!(exported_after.profile.handle.starts_with("deleted-"));
        assert_eq!(
            exported_after.messages.len(),
            exported_before.messages.len(),
            "the cleanup worker must preserve shared message content"
        );
    }

    #[tokio::test]
    async fn apple_http_flow_is_pending_then_consumes_cancellation() {
        let auth = AuthService::in_memory(
            EmailDelivery::DevelopmentConsole,
            Some(crate::apple::AppleConfig {
                client_id: "com.exocord.test".into(),
                team_id: "TESTTEAM01".into(),
                key_id: "TESTKEY001".into(),
                private_key_pem: String::new(),
                redirect_uri: "https://example.com/v1/auth/apple/callback".into(),
                provider_token_key: [4; 32],
                authorize_url: "https://appleid.apple.com/auth/authorize".into(),
                token_url: "https://appleid.apple.com/auth/token".into(),
                jwks_url: "https://appleid.apple.com/auth/keys".into(),
            }),
        )
        .unwrap();
        let app = build_router(AppState::seeded_with_auth(auth, false));
        let challenge = app
            .clone()
            .oneshot(
                Request::get("/v1/auth/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge: exo_safety::ProofOfWorkChallenge =
            serde_json::from_slice(&to_bytes(challenge.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        let proof = exo_safety::solve_proof_of_work(&challenge).unwrap();
        let start = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/apple/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "deviceId": "018f04b2-3c71-7f42-b12d-6f090d44be12",
                            "proofOfWork": proof
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::OK);
        let start_body = to_bytes(start.into_body(), 16 * 1024).await.unwrap();
        let start_json: serde_json::Value = serde_json::from_slice(&start_body).unwrap();
        let flow_state = start_json["state"].as_str().unwrap();
        let pending = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/auth/apple/status?state={flow_state}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pending.status(), StatusCode::ACCEPTED);

        let cancellation = format!("error=user_cancelled_authorize&state={flow_state}");
        let callback = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/apple/callback")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(cancellation))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::OK);
        let failed = app
            .oneshot(
                Request::get(format!("/v1/auth/apple/status?state={flow_state}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn authenticated_apple_link_routes_require_password_and_update_methods() {
        let auth = AuthService::in_memory(
            EmailDelivery::DevelopmentConsole,
            Some(crate::apple::AppleConfig {
                client_id: "com.exocord.test".into(),
                team_id: "TESTTEAM01".into(),
                key_id: "TESTKEY001".into(),
                private_key_pem: String::new(),
                redirect_uri: "https://example.com/v1/auth/apple/callback".into(),
                provider_token_key: [7; 32],
                authorize_url: "https://appleid.apple.com/auth/authorize".into(),
                token_url: "https://appleid.apple.com/auth/token".into(),
                jwks_url: "https://appleid.apple.com/auth/keys".into(),
            }),
        )
        .unwrap();
        let state = AppState::seeded_with_auth(auth, true);
        let app = build_router(state.clone());
        let registration = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/password/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "link-routes@example.test",
                            "username": "link-routes",
                            "password": "route linking private password",
                            "deviceId": "018f04b2-3c71-7f42-b12d-6f090d44be31",
                            "clientName": "link route test"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registration.status(), StatusCode::OK);
        let registration: serde_json::Value =
            serde_json::from_slice(&to_bytes(registration.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        let token = registration["accessToken"].as_str().unwrap();

        let wrong_password = app
            .clone()
            .oneshot(
                Request::post("/v1/users/@me/apple/start")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"currentPassword":"wrong password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_password.status(), StatusCode::BAD_REQUEST);

        let started = app
            .clone()
            .oneshot(
                Request::post("/v1/users/@me/apple/start")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"currentPassword":"route linking private password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let started: serde_json::Value =
            serde_json::from_slice(&to_bytes(started.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        let flow_state = started["state"].as_str().unwrap();
        state
            .auth
            .complete_apple_flow(
                flow_state,
                "link-route-subject",
                "link-route@privaterelay.appleid.com",
                None,
                "link-route-refresh",
            )
            .unwrap();

        let completed = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/users/@me/apple/status?state={flow_state}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(completed.status(), StatusCode::OK);
        let methods = app
            .clone()
            .oneshot(
                Request::get("/v1/users/@me/auth-methods")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let methods: serde_json::Value =
            serde_json::from_slice(&to_bytes(methods.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(methods["passwordSet"], true);
        assert_eq!(methods["appleLinked"], true);
        assert_eq!(methods["appleEmail"], "link-route@privaterelay.appleid.com");

        let unlinked = app
            .clone()
            .oneshot(
                Request::delete("/v1/users/@me/apple")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"currentPassword":"route linking private password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unlinked.status(), StatusCode::NO_CONTENT);
        let methods = app
            .oneshot(
                Request::get("/v1/users/@me/auth-methods")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let methods: serde_json::Value =
            serde_json::from_slice(&to_bytes(methods.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(methods["appleLinked"], false);
        assert!(methods["appleEmail"].is_null());
    }

    #[tokio::test]
    async fn seeded_server_has_text_and_voice_channels() {
        let app = build_router(AppState::seeded());
        let guild_response = app
            .clone()
            .oneshot(
                Request::get("/v1/guilds")
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(guild_response.into_body(), 32_768).await.unwrap();
        let guilds: Vec<Guild> = serde_json::from_slice(&body).unwrap();

        let response = app
            .oneshot(
                Request::get(format!("/v1/guilds/{}/channels", guilds[0].id))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 32_768).await.unwrap();
        let channels: Vec<Channel> = serde_json::from_slice(&body).unwrap();
        assert!(
            channels
                .iter()
                .any(|channel| channel.kind == ChannelKind::Text)
        );
        assert!(
            channels
                .iter()
                .any(|channel| channel.kind == ChannelKind::Voice)
        );
    }

    #[tokio::test]
    async fn voice_tokens_are_short_lived_room_scoped_and_never_cacheable() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        let channels = state
            .repository
            .list_channels(owner, guild.id)
            .await
            .unwrap();
        let voice = channels
            .iter()
            .find(|channel| channel.kind == ChannelKind::Voice)
            .unwrap();
        let text = channels
            .iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let app = build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{}/voice-token", voice.id))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "no-store, private"
        );
        let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("\"secret\""));
        let grant: VoiceJoinGrant = serde_json::from_slice(&body).unwrap();
        assert_eq!(grant.channel_id, voice.id);
        assert_eq!(grant.guild_id, Some(guild.id));
        assert!(grant.can_speak);
        assert!(grant.can_stream);
        assert!(grant.transport_encrypted);
        assert!(!grant.end_to_end_encrypted);
        let remaining = grant.expires_at - Utc::now();
        assert!(remaining > ChronoDuration::seconds(45));
        assert!(remaining <= ChronoDuration::seconds(60));

        let token = jsonwebtoken::decode::<serde_json::Value>(
            &grant.token,
            &jsonwebtoken::DecodingKey::from_secret(b"secret"),
            &jsonwebtoken::Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token.claims["iss"], "devkey");
        assert_eq!(token.claims["sub"], "1");
        assert_eq!(token.claims["video"]["roomJoin"], true);
        assert_eq!(token.claims["video"]["room"], grant.room_name);
        assert_eq!(token.claims["video"]["canPublishData"], false);
        assert_eq!(
            token.claims["video"]["canPublishSources"],
            serde_json::json!(["microphone", "screen_share", "screen_share_audio"])
        );

        let wrong_kind = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{}/voice-token", text.id))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_kind.status(), StatusCode::BAD_REQUEST);
        let unauthenticated = app
            .oneshot(
                Request::post(format!("/v1/channels/{}/voice-token", voice.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_revokes_the_session_and_evicts_voice_from_every_server() {
        let (sender, mut requests) = tokio::sync::mpsc::channel(4);
        let livekit_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let livekit_address = livekit_listener.local_addr().unwrap();
        let livekit_server = tokio::spawn(
            axum::serve(
                livekit_listener,
                Router::new()
                    .fallback(axum::routing::post(capture_livekit_request))
                    .with_state(sender),
            )
            .into_future(),
        );
        let auth = AuthService::in_memory(EmailDelivery::DevelopmentConsole, None).unwrap();
        let voice = VoiceConfig::new(
            format!("ws://{livekit_address}"),
            "logout-test-key",
            "logout-test-secret",
        )
        .unwrap();
        let app =
            build_router(AppState::seeded_with_auth(auth, true).with_voice_config(Some(voice)));

        let challenge = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/email/request")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"voice-logout@example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(challenge.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        let verify_body = serde_json::json!({
            "challengeId": challenge_json["challengeId"],
            "code": challenge_json["developmentCode"],
            "deviceId": "018f04b2-3c71-7f42-b12d-6f090d44be13",
            "clientName": "Voice logout test"
        });
        let verified = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/email/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(verify_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let session: serde_json::Value =
            serde_json::from_slice(&to_bytes(verified.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        let access_token = session["accessToken"].as_str().unwrap();
        let user_id = session["user"]["id"].as_str().unwrap();

        let created = app
            .clone()
            .oneshot(
                Request::post("/v1/guilds")
                    .header("authorization", format!("Bearer {access_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"Voice logout server"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let guild: serde_json::Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        let guild_id = guild["id"].as_str().unwrap();
        let sync = app
            .clone()
            .oneshot(
                Request::get("/v1/sync")
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let snapshot: serde_json::Value =
            serde_json::from_slice(&to_bytes(sync.into_body(), 64 * 1024).await.unwrap()).unwrap();
        let voice_channel_id = snapshot["channels"]
            .as_array()
            .unwrap()
            .iter()
            .find(|channel| {
                channel["guild_id"].as_str() == Some(guild_id) && channel["kind"] == "voice"
            })
            .and_then(|channel| channel["id"].as_str())
            .unwrap();
        let expected_room = format!("exo-{guild_id}-voice-{voice_channel_id}");

        let logout = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/logout")
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
        let rejected = app
            .oneshot(
                Request::get("/v1/auth/me")
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

        let (uri, headers, body) =
            tokio::time::timeout(std::time::Duration::from_secs(3), requests.recv())
                .await
                .expect("voice eviction should reach the LiveKit control plane")
                .expect("the LiveKit capture channel should remain open");
        assert_eq!(uri.path(), "/twirp/livekit.RoomService/RemoveParticipant");
        assert!(
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Bearer "))
        );
        assert!(bytes_contain(&body, &expected_room));
        assert!(bytes_contain(&body, user_id));
        assert!(!bytes_contain(&body, "logout-test-secret"));

        livekit_server.abort();
    }

    #[tokio::test]
    async fn invite_http_flow_previews_publicly_and_joins_an_authenticated_member() {
        let state = AppState::seeded();
        let outsider = UserId::new();
        state
            .repository
            .ensure_user(
                User {
                    id: outsider,
                    handle: "joiner".into(),
                    display_name: "Joiner".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = state
            .repository
            .list_guilds(UserId::from_raw(1).unwrap())
            .await
            .unwrap()
            .remove(0);
        let app = build_router(state);
        let create = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/guilds/{}/invites", guild.id))
                    .header("x-exocord-user-id", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"expiresInSeconds":3600,"maxUses":5}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::CREATED);
        let invite: GuildInvite =
            serde_json::from_slice(&to_bytes(create.into_body(), 16 * 1024).await.unwrap())
                .unwrap();

        let preview = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/invites/{}", invite.code))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preview.status(), StatusCode::OK);
        let preview: InvitePreview =
            serde_json::from_slice(&to_bytes(preview.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(preview.guild.id, guild.id);

        let accepted = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/invites/{}", invite.code))
                    .header("x-exocord-user-id", outsider.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let channels = app
            .oneshot(
                Request::get(format!("/v1/guilds/{}/channels", guild.id))
                    .header("x-exocord-user-id", outsider.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(channels.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn role_http_flow_uses_string_safe_permissions_and_enforces_assignments() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        state
            .repository
            .ensure_user(
                User {
                    id: member,
                    handle: "role-member".into(),
                    display_name: "Role Member".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![11_u8; 32];
        state
            .repository
            .create_invite(
                owner,
                guild.id,
                "role-http-invite-1234".into(),
                &invite_hash,
                Some(1),
                Some(Utc::now() + ChronoDuration::hours(1)),
            )
            .await
            .unwrap();
        state
            .repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();
        let app = build_router(state);
        let permissions =
            (GuildPermissions::MANAGE_CHANNELS | GuildPermissions::VIEW_MEMBER_LIST).bits();
        let created = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/guilds/{}/roles", guild.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "name": "Channel steward",
                            "color": 6_938_557,
                            "permissions": permissions.to_string()
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body = to_bytes(created.into_body(), 16 * 1024).await.unwrap();
        let created_json: serde_json::Value = serde_json::from_slice(&created_body).unwrap();
        assert_eq!(
            created_json["permissions"].as_str().unwrap(),
            permissions.to_string()
        );
        let role: Role = serde_json::from_slice(&created_body).unwrap();

        let assigned = app
            .clone()
            .oneshot(
                Request::put(format!(
                    "/v1/guilds/{}/members/{member}/roles/{}",
                    guild.id, role.id
                ))
                .header("x-exocord-user-id", owner.to_string())
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(assigned.status(), StatusCode::NO_CONTENT);

        let channel = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/guilds/{}/channels", guild.id))
                    .header("x-exocord-user-id", member.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"role-created","kind":"text","encrypted":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(channel.status(), StatusCode::CREATED);

        let forbidden = app
            .oneshot(
                Request::patch(format!("/v1/guilds/{}/roles/{}", guild.id, role.id))
                    .header("x-exocord-user-id", member.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"Escalated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn channel_access_and_moderation_http_flow_is_enforced_end_to_end() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        state
            .repository
            .ensure_user(
                User {
                    id: member,
                    handle: "channel-member".into(),
                    display_name: "Channel Member".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![13_u8; 32];
        state
            .repository
            .create_invite(
                owner,
                guild.id,
                "channel-http-invite".into(),
                &invite_hash,
                Some(10),
                None,
            )
            .await
            .unwrap();
        state
            .repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();
        let general = state
            .repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let app = build_router(state);

        let created = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/guilds/{}/channels", guild.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"ops","kind":"text","encrypted":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let created: Channel =
            serde_json::from_slice(&to_bytes(created.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        let renamed = app
            .clone()
            .oneshot(
                Request::patch(format!("/v1/channels/{}", created.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"operations"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(renamed.status(), StatusCode::OK);

        let overwritten = app
            .clone()
            .oneshot(
                Request::put(format!(
                    "/v1/channels/{}/overwrites/role/{}",
                    general.id, guild.id
                ))
                .header("x-exocord-user-id", owner.to_string())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "allow": "0",
                        "deny": GuildPermissions::VIEW_CHANNEL.bits().to_string()
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(overwritten.status(), StatusCode::OK);
        let overwrite: ChannelPermissionOverwrite =
            serde_json::from_slice(&to_bytes(overwritten.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(overwrite.target_id, guild.id.to_string());
        let member_channels = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/guilds/{}/channels", guild.id))
                    .header("x-exocord-user-id", member.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let member_channels: Vec<Channel> = serde_json::from_slice(
            &to_bytes(member_channels.into_body(), 32 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            member_channels
                .iter()
                .all(|channel| channel.id != general.id)
        );

        let timeout = app
            .clone()
            .oneshot(
                Request::patch(format!("/v1/guilds/{}/members/{member}", guild.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"timeoutSeconds":3600,"reason":"cool down"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(timeout.status(), StatusCode::NO_CONTENT);
        let members = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/guilds/{}/members", guild.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let members: Vec<GuildMember> =
            serde_json::from_slice(&to_bytes(members.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        assert!(
            members
                .iter()
                .find(|candidate| candidate.user.id == member)
                .and_then(|candidate| candidate.timeout_until)
                .is_some()
        );

        let banned = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/guilds/{}/bans/{member}", guild.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"reason":"spam"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(banned.status(), StatusCode::NO_CONTENT);
        let bans = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/guilds/{}/bans", guild.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bans: Vec<GuildBan> =
            serde_json::from_slice(&to_bytes(bans.into_body(), 32 * 1024).await.unwrap()).unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].user.id, member);
        let unbanned = app
            .clone()
            .oneshot(
                Request::delete(format!("/v1/guilds/{}/bans/{member}", guild.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unbanned.status(), StatusCode::NO_CONTENT);
        let deleted = app
            .oneshot(
                Request::delete(format!("/v1/channels/{}", created.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn message_nonce_makes_retries_idempotent() {
        let state = AppState::seeded();
        let channel_id = state.repository.first_text_channel().await.unwrap();
        let app = build_router(state);
        let body = serde_json::json!({
            "content": "one logical message",
            "nonce": "retry-safe-nonce"
        })
        .to_string();
        let request = || {
            Request::post(format!("/v1/channels/{channel_id}/messages"))
                .header("content-type", "application/json")
                .header("x-exocord-user-id", "1")
                .body(Body::from(body.clone()))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body = to_bytes(first.into_body(), 32_768).await.unwrap();
        let first_message: Message = serde_json::from_slice(&first_body).unwrap();

        let retry = app.oneshot(request()).await.unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        let retry_body = to_bytes(retry.into_body(), 32_768).await.unwrap();
        let retry_message: Message = serde_json::from_slice(&retry_body).unwrap();
        assert_eq!(first_message.id, retry_message.id);
    }

    #[tokio::test]
    async fn replies_edits_deletes_and_reactions_are_durable_api_actions() {
        let state = AppState::seeded();
        let channel_id = state.repository.first_text_channel().await.unwrap();
        let app = build_router(state);
        let create = |content: &str, nonce: &str, reply_to: Option<MessageId>| {
            let mut body = serde_json::json!({
                "content": content,
                "nonce": nonce
            });
            if let Some(reply_to) = reply_to {
                body["reply_to"] = serde_json::json!(reply_to);
            }
            Request::post(format!("/v1/channels/{channel_id}/messages"))
                .header("content-type", "application/json")
                .header("x-exocord-user-id", "1")
                .body(Body::from(body.to_string()))
                .unwrap()
        };

        let root = app
            .clone()
            .oneshot(create("original", "conversation-root", None))
            .await
            .unwrap();
        assert_eq!(root.status(), StatusCode::CREATED);
        let root: Message =
            serde_json::from_slice(&to_bytes(root.into_body(), 32_768).await.unwrap()).unwrap();

        let reply = app
            .clone()
            .oneshot(create("reply", "conversation-reply", Some(root.id)))
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::CREATED);
        let reply: Message =
            serde_json::from_slice(&to_bytes(reply.into_body(), 32_768).await.unwrap()).unwrap();
        assert_eq!(reply.reply_to, Some(root.id));

        let edited = app
            .clone()
            .oneshot(
                Request::patch(format!("/v1/channels/{channel_id}/messages/{}", reply.id))
                    .header("content-type", "application/json")
                    .header("x-exocord-user-id", "1")
                    .body(Body::from(
                        serde_json::json!({
                            "content": "edited reply",
                            "nonce": "conversation-edit"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(edited.status(), StatusCode::OK);
        let edited: Message =
            serde_json::from_slice(&to_bytes(edited.into_body(), 32_768).await.unwrap()).unwrap();
        assert_eq!(edited.content, "edited reply");
        assert!(edited.edited_at.is_some());

        for _ in 0..2 {
            let reaction = app
                .clone()
                .oneshot(
                    Request::put(format!(
                        "/v1/channels/{channel_id}/messages/{}/reactions",
                        reply.id
                    ))
                    .header("content-type", "application/json")
                    .header("x-exocord-user-id", "1")
                    .body(Body::from(serde_json::json!({ "emoji": "👍" }).to_string()))
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reaction.status(), StatusCode::OK);
        }
        for invalid in ["é", "👍❤️"] {
            let reaction = app
                .clone()
                .oneshot(
                    Request::put(format!(
                        "/v1/channels/{channel_id}/messages/{}/reactions",
                        reply.id
                    ))
                    .header("content-type", "application/json")
                    .header("x-exocord-user-id", "1")
                    .body(Body::from(
                        serde_json::json!({ "emoji": invalid }).to_string(),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reaction.status(), StatusCode::BAD_REQUEST);
        }

        let listed = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/channels/{channel_id}/messages?limit=100"))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let listed: Vec<Message> =
            serde_json::from_slice(&to_bytes(listed.into_body(), 65_536).await.unwrap()).unwrap();
        let listed_reply = listed
            .iter()
            .find(|message| message.id == reply.id)
            .unwrap();
        assert_eq!(listed_reply.reply_to, Some(root.id));
        assert_eq!(listed_reply.content, "edited reply");
        assert_eq!(
            listed_reply.reactions,
            vec![exo_domain::MessageReaction {
                emoji: "👍".into(),
                count: 1,
                me: true,
            }]
        );

        let deleted = app
            .clone()
            .oneshot(
                Request::delete(format!("/v1/channels/{channel_id}/messages/{}", reply.id))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let listed = app
            .oneshot(
                Request::get(format!("/v1/channels/{channel_id}/messages?limit=100"))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let listed: Vec<Message> =
            serde_json::from_slice(&to_bytes(listed.into_body(), 65_536).await.unwrap()).unwrap();
        assert!(!listed.iter().any(|message| message.id == reply.id));
    }

    #[tokio::test]
    async fn conversation_actions_reach_authorized_gateway_clients() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        state
            .repository
            .ensure_user(
                User {
                    id: member,
                    handle: "conversation-observer".into(),
                    display_name: "Conversation Observer".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        let channel = state
            .repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let invite_hash = vec![89_u8; 32];
        state
            .repository
            .create_invite(
                owner,
                guild.id,
                "conversation-events-invite".into(),
                &invite_hash,
                Some(1),
                None,
            )
            .await
            .unwrap();
        state
            .repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_router(server_state))
                .await
                .unwrap();
        });
        let owner_client = ApiClient::new(&format!("http://{address}"), owner.to_string()).unwrap();
        let member_client =
            ApiClient::new(&format!("http://{address}"), member.to_string()).unwrap();
        let mut gateway = member_client.connect_gateway().await.unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::Ready(_))
        ));

        let root = owner_client
            .send_message(
                channel.id.raw(),
                "conversation root",
                None,
                "gateway-conversation-root",
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::MessageCreate(message)) if message.id == root.id
        ));
        assert!(
            member_client
                .update_message(
                    channel.id.raw(),
                    root.id.raw(),
                    "unauthorized edit",
                    "gateway-unauthorized-edit",
                )
                .await
                .is_err()
        );
        assert!(
            member_client
                .delete_message(channel.id.raw(), root.id.raw())
                .await
                .is_err()
        );

        let reply = owner_client
            .send_message(
                channel.id.raw(),
                "conversation reply",
                Some(root.id),
                "gateway-conversation-reply",
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::MessageCreate(message))
                if message.id == reply.id && message.reply_to == Some(root.id)
        ));

        owner_client
            .update_message(
                channel.id.raw(),
                reply.id.raw(),
                "edited conversation reply",
                "gateway-conversation-edit",
            )
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::MessageUpdate(message))
                if message.id == reply.id
                    && message.content == "edited conversation reply"
                    && message.edited_at.is_some()
        ));

        owner_client
            .update_reaction(channel.id.raw(), reply.id.raw(), "👍", true)
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::ReactionUpdate(event))
                if event.message_id == reply.id
                    && event.user_id == owner
                    && event.emoji == "👍"
                    && event.count == 1
                    && event.added
        ));

        owner_client
            .update_reaction(channel.id.raw(), reply.id.raw(), "👍", false)
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::ReactionUpdate(event))
                if event.message_id == reply.id
                    && event.emoji == "👍"
                    && event.count == 0
                    && !event.added
        ));

        owner_client
            .delete_message(channel.id.raw(), reply.id.raw())
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::MessageDelete(event))
                if event.id == reply.id && event.channel_id == channel.id
        ));
        server.abort();
    }

    #[tokio::test]
    async fn attachment_upload_is_hash_verified_render_safe_and_message_bound() {
        let state = AppState::seeded();
        let channel_id = state.repository.first_text_channel().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let state = state.with_attachment_service(
            AttachmentService::local(
                directory.path().to_owned(),
                "http://127.0.0.1:4100".into(),
                [17; 32],
                [23; 32],
            )
            .unwrap(),
        );
        let app = build_router(state);
        let png = base64::engine::general_purpose::STANDARD
            .decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
            )
            .unwrap();
        let hash = hex::encode(Sha256::digest(&png));
        let reserve_body = serde_json::json!({
            "files": [{
                "filename": "../pixel.png",
                "fileSize": png.len(),
                "contentType": "image/png",
                "sha256": hash
            }]
        });
        let reserved = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{channel_id}/attachments"))
                    .header("x-exocord-user-id", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(reserve_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reserved.status(), StatusCode::OK);
        assert_eq!(reserved.headers()[CACHE_CONTROL], "no-store, private");
        let reserved: ReservedAttachments =
            serde_json::from_slice(&to_bytes(reserved.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        let upload = reserved.attachments.first().unwrap();
        let upload_url = url::Url::parse(&upload.upload_url).unwrap();
        let upload_path = match upload_url.query() {
            Some(query) => format!("{}?{query}", upload_url.path()),
            None => upload_url.path().to_owned(),
        };
        let uploaded = app
            .clone()
            .oneshot(
                Request::put(upload_path)
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(png.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(uploaded.status(), StatusCode::NO_CONTENT);

        let completed = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/attachments/{}/complete", upload.id))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(completed.status(), StatusCode::OK);
        let attachment: exo_domain::MessageAttachment =
            serde_json::from_slice(&to_bytes(completed.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(attachment.filename, "pixel.png");
        assert_eq!(attachment.content_type, "image/png");
        assert_eq!((attachment.width, attachment.height), (Some(1), Some(1)));

        let message_body = serde_json::json!({
            "content": "",
            "nonce": "attachment-message",
            "attachments": [attachment.id]
        });
        let created = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{channel_id}/messages"))
                    .header("x-exocord-user-id", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(message_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let message: Message =
            serde_json::from_slice(&to_bytes(created.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert!(message.content.is_empty());
        assert_eq!(message.attachments, vec![attachment.clone()]);

        let content_url = url::Url::parse(&attachment.url).unwrap();
        let content_path = format!(
            "{}?{}",
            content_url.path(),
            content_url.query().unwrap_or_default()
        );
        let content = app
            .oneshot(Request::get(content_path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(content.status(), StatusCode::OK);
        assert_eq!(content.headers()["x-content-type-options"], "nosniff");
        assert_eq!(content.headers()[CONTENT_TYPE], "image/png");
        assert_eq!(
            to_bytes(content.into_body(), MAX_ATTACHMENT_BYTES as usize)
                .await
                .unwrap()
                .as_ref(),
            png.as_slice()
        );
    }

    #[tokio::test]
    async fn search_returns_plaintext_hits_and_discloses_encrypted_exclusions() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        state
            .repository
            .create_channel(
                owner,
                guild.id,
                "sealed-search".into(),
                ChannelKind::Text,
                true,
            )
            .await
            .unwrap();
        let response = build_router(state)
            .oneshot(
                Request::get(format!(
                    "/v1/guilds/{}/messages/search?q=dependable&limit=25",
                    guild.id
                ))
                .header("x-exocord-user-id", "1")
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let result: MessageSearchResult =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.hits.len(), 1);
        assert!(result.hits[0].message.content.contains("dependable"));
        assert!(result.excluded_channels.iter().any(|channel| {
            channel.name == "sealed-search" && channel.reason == SearchExclusionReason::E2ee
        }));
    }

    #[tokio::test]
    async fn friendships_direct_messages_blocks_and_read_state_are_private() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let friend = UserId::new();
        let outsider = UserId::new();
        for (id, handle) in [(friend, "alice"), (outsider, "mallory")] {
            state
                .repository
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
        let app = build_router(state.clone());

        let request = app
            .clone()
            .oneshot(
                Request::post("/v1/users/@me/relationships")
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"handle":"alice"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(request.status(), StatusCode::CREATED);
        let outgoing: Relationship =
            serde_json::from_slice(&to_bytes(request.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(outgoing.kind, exo_domain::RelationshipKind::Outgoing);

        let incoming = app
            .clone()
            .oneshot(
                Request::get("/v1/users/@me/relationships")
                    .header("x-exocord-user-id", friend.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let incoming: Vec<Relationship> =
            serde_json::from_slice(&to_bytes(incoming.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].kind, exo_domain::RelationshipKind::Incoming);

        let accepted = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/users/@me/relationships/{owner}"))
                    .header("x-exocord-user-id", friend.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"accept"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);

        let opened = app
            .clone()
            .oneshot(
                Request::post("/v1/users/@me/channels")
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"recipientId":"{friend}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(opened.status(), StatusCode::CREATED);
        let direct: DirectChannel =
            serde_json::from_slice(&to_bytes(opened.into_body(), 32 * 1024).await.unwrap())
                .unwrap();
        assert!(direct.encrypted);
        assert_eq!(direct.recipients.len(), 2);
        let owner_device = Uuid::now_v7();
        let friend_device = Uuid::now_v7();
        state
            .repository
            .register_device_identity(owner, owner_device, [1_u8; 32], Some("Owner".into()))
            .await
            .unwrap();
        state
            .repository
            .register_device_identity(friend, friend_device, [2_u8; 32], Some("Friend".into()))
            .await
            .unwrap();
        let package_reference = [3_u8; 32];
        state
            .repository
            .publish_mls_key_packages(
                friend,
                friend_device,
                vec![(package_reference, vec![4_u8; 128], 1)],
            )
            .await
            .unwrap();
        state
            .repository
            .claim_mls_key_packages(owner, owner_device, direct.id)
            .await
            .unwrap();
        state
            .repository
            .bootstrap_mls_group(
                owner,
                owner_device,
                direct.id,
                vec![5_u8; 32],
                1,
                vec![6_u8; 128],
                vec![MlsWelcomeRecord {
                    device_id: friend_device,
                    key_package_reference: package_reference,
                    payload: vec![7_u8; 128],
                }],
            )
            .await
            .unwrap();

        let sent = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{}/messages", direct.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .header("x-exocord-device-id", owner_device.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "content": "",
                            "encryption": {
                                "ciphertext": URL_SAFE_NO_PAD.encode([8_u8; 128]),
                                "frankingCommitment": URL_SAFE_NO_PAD.encode([9_u8; 32])
                            },
                            "nonce": "dm-one",
                            "attachments": []
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sent.status(), StatusCode::CREATED);
        let message: Message =
            serde_json::from_slice(&to_bytes(sent.into_body(), 32 * 1024).await.unwrap()).unwrap();
        assert!(message.content.is_empty());
        assert!(message.encryption.is_some());

        let owner_archive = PrivateHistoryArchive {
            message_id: message.id,
            channel_id: direct.id,
            nonce: URL_SAFE_NO_PAD.encode([10_u8; 24]),
            ciphertext: URL_SAFE_NO_PAD.encode([11_u8; 48]),
        };
        let archived = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/users/@me/private-history/{}", message.id))
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&owner_archive).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(archived.status(), StatusCode::NO_CONTENT);
        let owner_history = app
            .clone()
            .oneshot(
                Request::get("/v1/users/@me/private-history")
                    .header("x-exocord-user-id", owner.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let owner_history: Vec<PrivateHistoryArchive> = serde_json::from_slice(
            &to_bytes(owner_history.into_body(), 32 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(owner_history, vec![owner_archive.clone()]);
        let friend_history = app
            .clone()
            .oneshot(
                Request::get("/v1/users/@me/private-history")
                    .header("x-exocord-user-id", friend.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let friend_history: Vec<PrivateHistoryArchive> = serde_json::from_slice(
            &to_bytes(friend_history.into_body(), 32 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(friend_history.is_empty());
        let friend_archive = PrivateHistoryArchive {
            ciphertext: URL_SAFE_NO_PAD.encode([12_u8; 48]),
            ..owner_archive.clone()
        };
        let archived = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/users/@me/private-history/{}", message.id))
                    .header("x-exocord-user-id", friend.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&friend_archive).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(archived.status(), StatusCode::NO_CONTENT);
        let friend_history = app
            .clone()
            .oneshot(
                Request::get("/v1/users/@me/private-history")
                    .header("x-exocord-user-id", friend.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let friend_history: Vec<PrivateHistoryArchive> = serde_json::from_slice(
            &to_bytes(friend_history.into_body(), 32 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(friend_history, vec![friend_archive]);
        let outsider_archive = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/users/@me/private-history/{}", message.id))
                    .header("x-exocord-user-id", outsider.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&owner_archive).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outsider_archive.status(), StatusCode::FORBIDDEN);

        let outsider_history = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/channels/{}/messages", direct.id))
                    .header("x-exocord-user-id", outsider.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outsider_history.status(), StatusCode::NOT_FOUND);

        let acknowledged = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/channels/{}/read-state", direct.id))
                    .header("x-exocord-user-id", friend.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"lastMessageId":"{}"}}"#,
                        message.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let acknowledged: ReadState =
            serde_json::from_slice(&to_bytes(acknowledged.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(acknowledged.last_message_id, Some(message.id));

        let snapshot = app
            .clone()
            .oneshot(
                Request::get("/v1/sync")
                    .header("x-exocord-user-id", friend.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let snapshot: SyncSnapshot =
            serde_json::from_slice(&to_bytes(snapshot.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(snapshot.direct_channels.len(), 1);
        assert!(snapshot.messages.iter().any(|value| value.id == message.id));
        assert_eq!(snapshot.read_states, vec![acknowledged]);

        let blocked = app
            .clone()
            .oneshot(
                Request::put(format!("/v1/users/@me/relationships/{friend}"))
                    .header("x-exocord-user-id", owner.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action":"block"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::OK);
        let blocked_send = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{}/messages", direct.id))
                    .header("x-exocord-user-id", friend.to_string())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"content":"must fail","nonce":"dm-two","attachments":[]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked_send.status(), StatusCode::FORBIDDEN);
        let retained_history = app
            .oneshot(
                Request::get(format!("/v1/channels/{}/messages", direct.id))
                    .header("x-exocord-user-id", friend.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retained_history.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn real_openmls_direct_message_is_opaque_to_server_and_readable_by_recipient() {
        const OPERATOR_TOKEN: &str = "exo_op_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = AppState::seeded().with_operator_token(OPERATOR_TOKEN);
        let owner = UserId::from_raw(1).unwrap();
        let friend = UserId::new();
        state
            .repository
            .ensure_user(
                User {
                    id: friend,
                    handle: "mls-friend".into(),
                    display_name: "MLS Friend".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_router(state)).await.unwrap();
        });
        let endpoint = format!("http://{address}");
        let owner_device = Uuid::now_v7();
        let friend_device = Uuid::now_v7();
        let owner_client = ApiClient::new(&endpoint, owner.to_string()).unwrap();
        let friend_client = ApiClient::new(&endpoint, friend.to_string()).unwrap();
        owner_client.set_device_id(owner_device.to_string());
        friend_client.set_device_id(friend_device.to_string());
        let mut owner_mls = MlsClient::create(owner.raw(), owner_device).unwrap();
        let mut friend_mls = MlsClient::create(friend.raw(), friend_device).unwrap();
        for (remote, mls) in [(&owner_client, &owner_mls), (&friend_client, &friend_mls)] {
            let identity = mls.public_identity();
            remote
                .register_device_identity(
                    &identity.device_id.to_string(),
                    &RegisterDeviceIdentity {
                        signature_key: URL_SAFE_NO_PAD.encode(identity.signature_key),
                        name: Some("OpenMLS test device".into()),
                    },
                )
                .await
                .unwrap();
        }
        let friend_package = friend_mls.generate_key_package().unwrap();
        friend_client
            .publish_mls_key_packages(
                &friend_device.to_string(),
                &PublishMlsKeyPackages {
                    packages: vec![exo_domain::PublishMlsKeyPackage {
                        reference: URL_SAFE_NO_PAD.encode(&friend_package.reference),
                        key_package: URL_SAFE_NO_PAD.encode(&friend_package.key_package),
                        cipher_suite: friend_package.cipher_suite,
                    }],
                },
            )
            .await
            .unwrap();
        owner_client.request_friend("mls-friend").await.unwrap();
        friend_client.accept_friend(owner).await.unwrap();
        let direct = owner_client.open_direct_channel(friend).await.unwrap();
        assert!(direct.encrypted);

        let claimed = owner_client
            .claim_mls_key_packages(direct.id.raw())
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let friend_identity = owner_client
            .list_device_identities(friend)
            .await
            .unwrap()
            .into_iter()
            .find(|identity| identity.device_id == friend_device)
            .unwrap();
        let package = PublishedKeyPackage {
            user_id: friend.raw(),
            device_id: friend_device,
            signature_key: URL_SAFE_NO_PAD
                .decode(friend_identity.signature_key)
                .unwrap(),
            reference: URL_SAFE_NO_PAD.decode(&claimed[0].reference).unwrap(),
            key_package: URL_SAFE_NO_PAD.decode(&claimed[0].key_package).unwrap(),
            cipher_suite: claimed[0].cipher_suite,
        };
        let bootstrap = owner_mls.create_group(direct.id.raw(), &[package]).unwrap();
        owner_client
            .bootstrap_mls_group(
                direct.id.raw(),
                &BootstrapMlsGroup {
                    group_id: URL_SAFE_NO_PAD.encode(&bootstrap.group_id),
                    epoch: bootstrap.epoch,
                    commit: URL_SAFE_NO_PAD.encode(&bootstrap.commit),
                    welcomes: vec![exo_domain::MlsWelcomeUpload {
                        device_id: friend_device,
                        key_package_reference: claimed[0].reference.clone(),
                        payload: URL_SAFE_NO_PAD.encode(&bootstrap.welcome),
                    }],
                },
            )
            .await
            .unwrap();
        let inbox = friend_client
            .mls_inbox(&friend_device.to_string())
            .await
            .unwrap();
        assert_eq!(inbox.len(), 1);
        friend_mls
            .join_group(
                direct.id.raw(),
                &URL_SAFE_NO_PAD.decode(&inbox[0].payload).unwrap(),
            )
            .unwrap();
        friend_client
            .acknowledge_mls_delivery(&friend_device.to_string(), &inbox[0])
            .await
            .unwrap();

        let context = CryptoMessageContext {
            channel_id: direct.id.raw(),
            author_id: owner.raw(),
            nonce: "real-mls-message".into(),
        };
        let encrypted = owner_mls
            .encrypt_message(&context, "only devices can read this", &[])
            .unwrap();
        assert!(
            !encrypted
                .ciphertext
                .windows("only devices".len())
                .any(|window| window == b"only devices")
        );
        let stored = owner_client
            .send_encrypted_message(
                direct.id.raw(),
                URL_SAFE_NO_PAD.encode(&encrypted.ciphertext),
                URL_SAFE_NO_PAD.encode(encrypted.commitment),
                None,
                &context.nonce,
                &[],
            )
            .await
            .unwrap();
        assert!(stored.content.is_empty());
        let transport = stored.encryption.as_ref().unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&transport.franking_tag)
                .unwrap()
                .len(),
            32
        );
        let decrypted = friend_mls
            .decrypt_message(
                &context,
                &URL_SAFE_NO_PAD.decode(&transport.ciphertext).unwrap(),
                &URL_SAFE_NO_PAD
                    .decode(&transport.franking_commitment)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(decrypted.content, "only devices can read this");

        let report_evidence = MessageFrankingEvidence {
            content: decrypted.content,
            attachment_sha256: decrypted
                .attachment_sha256
                .iter()
                .map(hex::encode)
                .collect(),
            franking_key: URL_SAFE_NO_PAD.encode(decrypted.franking_key),
            franking_tag: transport.franking_tag.clone(),
        };
        let report_opening_secret = report_evidence.franking_key.clone();
        let mut tampered = report_evidence.clone();
        tampered.content = "altered after decryption".into();
        assert!(
            friend_client
                .create_report(&CreateMessageReport {
                    message_id: stored.id,
                    category: ReportCategory::Harassment,
                    detail: None,
                    franking: Some(tampered),
                })
                .await
                .is_err(),
            "altered message-franking evidence must be rejected"
        );
        let receipt = friend_client
            .create_report(&CreateMessageReport {
                message_id: stored.id,
                category: ReportCategory::Harassment,
                detail: Some("This is a verified test report.".into()),
                franking: Some(report_evidence),
            })
            .await
            .unwrap();
        assert_eq!(receipt.status, "open");

        let operator_http = reqwest::Client::new();
        let unauthorized = operator_http
            .get(format!("{endpoint}/v1/operator/reports"))
            .bearer_auth("exo_at_a-regular-user-session-is-not-an-operator-token")
            .send()
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

        let listed = operator_http
            .get(format!(
                "{endpoint}/v1/operator/reports?status=open&limit=10"
            ))
            .bearer_auth(OPERATOR_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status(), reqwest::StatusCode::OK);
        assert_eq!(
            listed
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .unwrap(),
            "no-store, private"
        );
        let listed_bytes = listed.bytes().await.unwrap();
        assert!(
            !bytes_contain(&listed_bytes, &report_opening_secret),
            "the franking opening must never be returned or retained as operator evidence"
        );
        assert!(
            !bytes_contain(&listed_bytes, "frankingKey"),
            "the operator contract must not contain a franking-key field"
        );
        let reports: serde_json::Value = serde_json::from_slice(&listed_bytes).unwrap();
        assert_eq!(reports.as_array().unwrap().len(), 1);
        assert_eq!(reports[0]["id"], receipt.id.to_string());
        assert_eq!(reports[0]["status"], "open");
        assert_eq!(
            reports[0]["evidence"]["content"],
            "only devices can read this"
        );
        assert_eq!(reports[0]["evidence"]["encrypted"], true);
        assert_eq!(reports[0]["evidence"]["verified"], true);

        let resolved = operator_http
            .put(format!("{endpoint}/v1/operator/reports/{}", receipt.id))
            .bearer_auth(OPERATOR_TOKEN)
            .json(&serde_json::json!({
                "status": "actioned",
                "note": "Verified in the encrypted-message integration test."
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resolved.status(), reqwest::StatusCode::OK);
        assert_eq!(
            resolved
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .unwrap(),
            "no-store, private"
        );
        let resolved: serde_json::Value = resolved.json().await.unwrap();
        assert_eq!(resolved["status"], "actioned");
        assert_eq!(resolved["handledByOperator"], "Local Exocord development");

        let duplicate_resolution = operator_http
            .put(format!("{endpoint}/v1/operator/reports/{}", receipt.id))
            .bearer_auth(OPERATOR_TOKEN)
            .json(&serde_json::json!({ "status": "dismissed" }))
            .send()
            .await
            .unwrap();
        assert_eq!(duplicate_resolution.status(), reqwest::StatusCode::CONFLICT);
        assert!(
            friend_client
                .mls_inbox(&friend_device.to_string())
                .await
                .unwrap()
                .is_empty()
        );

        let second_owner_device = Uuid::now_v7();
        let second_owner_client = ApiClient::new(&endpoint, owner.to_string()).unwrap();
        second_owner_client.set_device_id(second_owner_device.to_string());
        let mut second_owner_mls = MlsClient::create(owner.raw(), second_owner_device).unwrap();
        let second_identity = second_owner_mls.public_identity();
        second_owner_client
            .register_device_identity(
                &second_owner_device.to_string(),
                &RegisterDeviceIdentity {
                    signature_key: URL_SAFE_NO_PAD.encode(second_identity.signature_key),
                    name: Some("Second owner device".into()),
                },
            )
            .await
            .unwrap();
        let second_package = second_owner_mls.generate_key_package().unwrap();
        second_owner_client
            .publish_mls_key_packages(
                &second_owner_device.to_string(),
                &PublishMlsKeyPackages {
                    packages: vec![exo_domain::PublishMlsKeyPackage {
                        reference: URL_SAFE_NO_PAD.encode(&second_package.reference),
                        key_package: URL_SAFE_NO_PAD.encode(&second_package.key_package),
                        cipher_suite: second_package.cipher_suite,
                    }],
                },
            )
            .await
            .unwrap();

        let claimed = owner_client
            .claim_mls_key_packages(direct.id.raw())
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].device_id, second_owner_device);
        let second_identity = owner_client
            .list_device_identities(owner)
            .await
            .unwrap()
            .into_iter()
            .find(|identity| identity.device_id == second_owner_device)
            .unwrap();
        let update = owner_mls
            .add_members(
                direct.id.raw(),
                &[PublishedKeyPackage {
                    user_id: owner.raw(),
                    device_id: second_owner_device,
                    signature_key: URL_SAFE_NO_PAD
                        .decode(second_identity.signature_key)
                        .unwrap(),
                    reference: URL_SAFE_NO_PAD.decode(&claimed[0].reference).unwrap(),
                    key_package: URL_SAFE_NO_PAD.decode(&claimed[0].key_package).unwrap(),
                    cipher_suite: claimed[0].cipher_suite,
                }],
            )
            .unwrap();
        owner_client
            .update_mls_group(
                direct.id.raw(),
                &UpdateMlsGroup {
                    group_id: URL_SAFE_NO_PAD.encode(&update.group_id),
                    epoch: update.epoch,
                    commit: URL_SAFE_NO_PAD.encode(&update.commit),
                    welcomes: vec![exo_domain::MlsWelcomeUpload {
                        device_id: second_owner_device,
                        key_package_reference: claimed[0].reference.clone(),
                        payload: URL_SAFE_NO_PAD.encode(&update.welcome),
                    }],
                    removed_device_ids: Vec::new(),
                },
            )
            .await
            .unwrap();
        let friend_update = friend_client
            .mls_inbox(&friend_device.to_string())
            .await
            .unwrap();
        assert_eq!(friend_update.len(), 1);
        assert_eq!(friend_update[0].kind, MlsDeliveryKind::Commit);
        assert_eq!(
            friend_mls
                .process_commit(
                    direct.id.raw(),
                    &URL_SAFE_NO_PAD.decode(&friend_update[0].payload).unwrap(),
                )
                .unwrap(),
            2
        );
        friend_client
            .acknowledge_mls_delivery(&friend_device.to_string(), &friend_update[0])
            .await
            .unwrap();
        let second_inbox = second_owner_client
            .mls_inbox(&second_owner_device.to_string())
            .await
            .unwrap();
        assert_eq!(second_inbox.len(), 1);
        assert_eq!(second_inbox[0].kind, MlsDeliveryKind::Welcome);
        assert_eq!(
            second_owner_mls
                .join_group(
                    direct.id.raw(),
                    &URL_SAFE_NO_PAD.decode(&second_inbox[0].payload).unwrap(),
                )
                .unwrap(),
            2
        );
        second_owner_client
            .acknowledge_mls_delivery(&second_owner_device.to_string(), &second_inbox[0])
            .await
            .unwrap();
        let second_context = CryptoMessageContext {
            channel_id: direct.id.raw(),
            author_id: owner.raw(),
            nonce: "second-device-message".into(),
        };
        let second_encrypted = second_owner_mls
            .encrypt_message(&second_context, "future history on a new device", &[])
            .unwrap();
        let second_stored = second_owner_client
            .send_encrypted_message(
                direct.id.raw(),
                URL_SAFE_NO_PAD.encode(&second_encrypted.ciphertext),
                URL_SAFE_NO_PAD.encode(second_encrypted.commitment),
                None,
                &second_context.nonce,
                &[],
            )
            .await
            .unwrap();
        let second_transport = second_stored.encryption.unwrap();
        assert_eq!(
            friend_mls
                .decrypt_message(
                    &second_context,
                    &URL_SAFE_NO_PAD.decode(second_transport.ciphertext).unwrap(),
                    &URL_SAFE_NO_PAD
                        .decode(second_transport.franking_commitment)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
                .unwrap()
                .content,
            "future history on a new device"
        );

        owner_client
            .revoke_device_identity(&second_owner_device.to_string())
            .await
            .unwrap();
        let pending = owner_client
            .pending_mls_maintenance(&owner_device.to_string())
            .await
            .unwrap();
        assert_eq!(
            pending,
            vec![MlsMembershipHint {
                channel_id: direct.id,
                revoked_device_ids: vec![second_owner_device],
            }]
        );
        assert!(
            second_owner_client
                .mls_inbox(&second_owner_device.to_string())
                .await
                .is_err(),
            "a revoked device must lose MLS inbox access immediately"
        );
        let removal = owner_mls
            .remove_devices(direct.id.raw(), &[second_owner_device])
            .unwrap();
        owner_client
            .update_mls_group(
                direct.id.raw(),
                &UpdateMlsGroup {
                    group_id: URL_SAFE_NO_PAD.encode(&removal.group_id),
                    epoch: removal.epoch,
                    commit: URL_SAFE_NO_PAD.encode(&removal.commit),
                    welcomes: Vec::new(),
                    removed_device_ids: vec![second_owner_device],
                },
            )
            .await
            .unwrap();
        assert!(
            owner_client
                .pending_mls_maintenance(&owner_device.to_string())
                .await
                .unwrap()
                .is_empty()
        );
        let removal_inbox = friend_client
            .mls_inbox(&friend_device.to_string())
            .await
            .unwrap();
        assert_eq!(removal_inbox.len(), 1);
        assert_eq!(removal_inbox[0].kind, MlsDeliveryKind::Commit);
        assert_eq!(
            friend_mls
                .process_commit(
                    direct.id.raw(),
                    &URL_SAFE_NO_PAD.decode(&removal_inbox[0].payload).unwrap(),
                )
                .unwrap(),
            3
        );
        let post_revoke_context = CryptoMessageContext {
            channel_id: direct.id.raw(),
            author_id: owner.raw(),
            nonce: "post-revoke-message".into(),
        };
        let post_revoke = owner_mls
            .encrypt_message(&post_revoke_context, "rotated future secret", &[])
            .unwrap();
        assert!(
            second_owner_mls
                .decrypt_message(
                    &post_revoke_context,
                    &post_revoke.ciphertext,
                    &post_revoke.commitment,
                )
                .is_err(),
            "the removed device must not derive the next epoch"
        );
        assert_eq!(
            friend_mls
                .decrypt_message(
                    &post_revoke_context,
                    &post_revoke.ciphertext,
                    &post_revoke.commitment,
                )
                .unwrap()
                .content,
            "rotated future secret"
        );
        server.abort();
    }

    #[tokio::test]
    async fn message_history_enforces_window_limit() {
        let state = AppState::seeded();
        let channel_id = state.repository.first_text_channel().await.unwrap();
        let response = build_router(state)
            .oneshot(
                Request::get(format!("/v1/channels/{channel_id}/messages?limit=101"))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sync_snapshot_is_bounded_and_requires_development_identity() {
        let app = build_router(AppState::seeded());
        let unauthorized = app
            .clone()
            .oneshot(Request::get("/v1/sync").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::get("/v1/sync")
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let snapshot: SyncSnapshot = serde_json::from_slice(&body).unwrap();
        assert_eq!(snapshot.current_user.id.raw(), 1);
        assert!(!snapshot.guilds.is_empty());
        assert!(snapshot.messages.len() <= snapshot.channels.len() * 100);
    }

    #[tokio::test]
    async fn native_client_sync_send_and_gateway_delivery_form_one_data_path() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_router(AppState::seeded()))
                .await
                .unwrap();
        });
        let client = ApiClient::new(&format!("http://{address}"), "1").unwrap();
        let snapshot = client.fetch_sync().await.unwrap();
        let cache = LocalStore::open_in_memory().unwrap();
        cache.apply_remote_snapshot(&snapshot).unwrap();
        let cached = cache.snapshot().unwrap();
        let guild = snapshot.guilds.first().unwrap();
        let access = snapshot
            .guild_access
            .iter()
            .find(|access| access.guild_id == guild.id)
            .unwrap();
        assert_eq!(
            cached
                .guilds
                .iter()
                .find(|cached_guild| cached_guild.id == guild.id.raw())
                .unwrap()
                .current_permissions,
            access.permissions.bits()
        );
        let channel = snapshot
            .channels
            .iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let pending = cache
            .enqueue_message(
                42,
                "integration-nonce",
                channel.id.raw(),
                snapshot.current_user.id.raw(),
                None,
                "one real path",
                &[],
                Utc::now(),
            )
            .unwrap();
        assert_eq!(pending.state, MessageState::Pending);
        let mut gateway = client.connect_gateway().await.unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::Ready(_))
        ));

        let managed_channel = client
            .create_channel(
                guild.id.raw(),
                &CreateChannel {
                    name: "gateway-lifecycle".into(),
                    kind: ChannelKind::Voice,
                    encrypted: true,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::ChannelCreate(channel)) if channel.id == managed_channel.id
        ));
        let voice_grant = client
            .create_voice_grant(managed_channel.id.raw())
            .await
            .unwrap();
        assert_eq!(voice_grant.channel_id, managed_channel.id);
        assert!(voice_grant.can_speak);
        assert!(voice_grant.can_stream);
        let managed_channel = client
            .update_channel(
                managed_channel.id.raw(),
                &UpdateChannel {
                    name: Some("gateway-renamed".into()),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::ChannelUpdate(channel))
                if channel.id == managed_channel.id && channel.name == "gateway-renamed"
        ));
        client
            .delete_channel(managed_channel.id.raw())
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::ChannelDelete(channel)) if channel.id == managed_channel.id
        ));

        let sent = client
            .send_message(
                channel.id.raw(),
                "one real path",
                None,
                "integration-nonce",
                &[],
            )
            .await
            .unwrap();
        let event = gateway.next_event().await.unwrap();
        assert!(matches!(
            event,
            Some(GatewayEvent::MessageCreate(message)) if message.id == sent.id
        ));
        let acknowledged = cache
            .acknowledge_message("integration-nonce", &sent)
            .unwrap();
        assert_eq!(acknowledged.state, MessageState::Sent);
        assert_eq!(acknowledged.client_key, "integration-nonce");
        assert_eq!(cache.snapshot().unwrap().pending_outbox, 0);
        server.abort();
    }

    #[tokio::test]
    async fn direct_message_gateway_events_never_reach_an_outsider() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let friend = UserId::new();
        let outsider = UserId::new();
        for (id, handle) in [(friend, "gateway-friend"), (outsider, "gateway-outsider")] {
            state
                .repository
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_router(server_state))
                .await
                .unwrap();
        });
        let endpoint = format!("http://{address}");
        let owner_client = ApiClient::new(&endpoint, owner.to_string()).unwrap();
        let friend_client = ApiClient::new(&endpoint, friend.to_string()).unwrap();
        let outsider_client = ApiClient::new(&endpoint, outsider.to_string()).unwrap();
        let owner_device = Uuid::now_v7();
        let friend_device = Uuid::now_v7();
        owner_client.set_device_id(owner_device.to_string());
        friend_client.set_device_id(friend_device.to_string());
        owner_client
            .register_device_identity(
                &owner_device.to_string(),
                &RegisterDeviceIdentity {
                    signature_key: URL_SAFE_NO_PAD.encode([10_u8; 32]),
                    name: Some("Gateway owner".into()),
                },
            )
            .await
            .unwrap();
        friend_client
            .register_device_identity(
                &friend_device.to_string(),
                &RegisterDeviceIdentity {
                    signature_key: URL_SAFE_NO_PAD.encode([11_u8; 32]),
                    name: Some("Gateway friend".into()),
                },
            )
            .await
            .unwrap();
        friend_client
            .publish_mls_key_packages(
                &friend_device.to_string(),
                &PublishMlsKeyPackages {
                    packages: vec![exo_domain::PublishMlsKeyPackage {
                        reference: URL_SAFE_NO_PAD.encode([12_u8; 32]),
                        key_package: URL_SAFE_NO_PAD.encode([13_u8; 128]),
                        cipher_suite: 1,
                    }],
                },
            )
            .await
            .unwrap();

        owner_client.request_friend("gateway-friend").await.unwrap();
        friend_client.accept_friend(owner).await.unwrap();
        let direct = owner_client.open_direct_channel(friend).await.unwrap();
        let claimed = owner_client
            .claim_mls_key_packages(direct.id.raw())
            .await
            .unwrap();
        owner_client
            .bootstrap_mls_group(
                direct.id.raw(),
                &BootstrapMlsGroup {
                    group_id: URL_SAFE_NO_PAD.encode([14_u8; 32]),
                    epoch: 1,
                    commit: URL_SAFE_NO_PAD.encode([15_u8; 128]),
                    welcomes: claimed
                        .iter()
                        .map(|package| exo_domain::MlsWelcomeUpload {
                            device_id: package.device_id,
                            key_package_reference: package.reference.clone(),
                            payload: URL_SAFE_NO_PAD.encode([16_u8; 128]),
                        })
                        .collect(),
                },
            )
            .await
            .unwrap();

        let mut owner_gateway = owner_client.connect_gateway().await.unwrap();
        assert!(matches!(
            owner_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::Ready(_))
        ));
        let mut outsider_gateway = outsider_client.connect_gateway().await.unwrap();
        assert!(matches!(
            outsider_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::Ready(_))
        ));
        let mut friend_gateway = friend_client.connect_gateway().await.unwrap();
        assert!(matches!(
            friend_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::Ready(_))
        ));
        assert!(matches!(
            owner_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::PresenceUpdate(UserPresence {
                user_id,
                status: PresenceStatus::Online,
                ..
            })) if user_id == friend
        ));
        assert!(
            owner_client
                .fetch_sync()
                .await
                .unwrap()
                .presences
                .iter()
                .any(|presence| presence.user_id == friend
                    && presence.status == PresenceStatus::Online)
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                outsider_gateway.next_event(),
            )
            .await
            .is_err()
        );

        let avatar_one = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAKUlEQVR42u3OIQEAAAACIP+f1hkWWEB6FgEBAQEBAQEBAQEBAQEBgXdgl/rw4tnPBf0AAAAASUVORK5CYII=";
        let avatar_two = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAKklEQVR42u3OIQEAAAACIP+f1hkWAp0k7ZeAgICAgICAgICAgICAgMA5MFuV+GpwBUhIAAAAAElFTkSuQmCC";
        let first_profile = friend_client
            .update_profile(&exo_client::UpdateProfile {
                handle: "gateway-friend".into(),
                display_name: "Gateway Friend One".into(),
                avatar_content_type: Some("image/png".into()),
                avatar_base64: Some(avatar_one.into()),
                remove_avatar: false,
            })
            .await
            .unwrap();
        let first_avatar_url = first_profile.avatar_url.clone().unwrap();
        assert!(first_avatar_url.contains("/v1/users/") && first_avatar_url.len() > 64);
        assert!(matches!(
            owner_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::UserUpdate(user))
                if user.id == friend && user.display_name == "Gateway Friend One"
                    && user.avatar_url.as_deref() == Some(first_avatar_url.as_str())
        ));
        assert!(matches!(
            friend_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::UserUpdate(user))
                if user.id == friend && user.avatar_url.as_deref() == Some(first_avatar_url.as_str())
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                outsider_gateway.next_event(),
            )
            .await
            .is_err()
        );

        let second_profile = friend_client
            .update_profile(&exo_client::UpdateProfile {
                handle: "gateway-friend".into(),
                display_name: "Gateway Friend Two".into(),
                avatar_content_type: Some("image/png".into()),
                avatar_base64: Some(avatar_two.into()),
                remove_avatar: false,
            })
            .await
            .unwrap();
        let second_avatar_url = second_profile.avatar_url.clone().unwrap();
        assert_ne!(first_avatar_url, second_avatar_url);
        assert!(matches!(
            owner_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::UserUpdate(user))
                if user.id == friend && user.display_name == "Gateway Friend Two"
                    && user.avatar_url.as_deref() == Some(second_avatar_url.as_str())
        ));
        assert!(matches!(
            friend_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::UserUpdate(user))
                if user.id == friend && user.avatar_url.as_deref() == Some(second_avatar_url.as_str())
        ));

        friend_client
            .update_profile(&exo_client::UpdateProfile {
                handle: "gateway-friend".into(),
                display_name: "Gateway Friend Three".into(),
                avatar_content_type: None,
                avatar_base64: None,
                remove_avatar: true,
            })
            .await
            .unwrap();
        assert!(matches!(
            owner_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::UserUpdate(user))
                if user.id == friend && user.display_name == "Gateway Friend Three"
                    && user.avatar_url.is_none()
        ));
        assert!(matches!(
            friend_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::UserUpdate(user))
                if user.id == friend && user.avatar_url.is_none()
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                outsider_gateway.next_event(),
            )
            .await
            .is_err()
        );

        let sent = owner_client
            .send_encrypted_message(
                direct.id.raw(),
                URL_SAFE_NO_PAD.encode([17_u8; 128]),
                URL_SAFE_NO_PAD.encode([18_u8; 32]),
                None,
                "private-gateway",
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            owner_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::MessageCreate(message)) if message.id == sent.id
        ));
        assert!(matches!(
            friend_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::MessageCreate(message)) if message.id == sent.id
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                outsider_gateway.next_event(),
            )
            .await
            .is_err()
        );

        owner_client.start_typing(direct.id.raw()).await.unwrap();
        assert!(matches!(
            owner_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::TypingStart(event))
                if event.channel_id == direct.id && event.user_id == owner
        ));
        assert!(matches!(
            friend_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::TypingStart(event))
                if event.channel_id == direct.id && event.user_id == owner
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                outsider_gateway.next_event(),
            )
            .await
            .is_err()
        );

        friend_client
            .acknowledge_read_state(direct.id.raw(), sent.id)
            .await
            .unwrap();
        assert!(matches!(
            friend_gateway.next_event().await.unwrap(),
            Some(GatewayEvent::ReadStateUpdate(_))
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                owner_gateway.next_event(),
            )
            .await
            .is_err()
        );
        drop(friend_gateway);
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                owner_gateway.next_event(),
            )
            .await
            .unwrap()
            .unwrap(),
            Some(GatewayEvent::PresenceUpdate(UserPresence {
                user_id,
                status: PresenceStatus::Offline,
                ..
            })) if user_id == friend
        ));
        server.abort();
    }

    #[tokio::test]
    async fn gateway_rechecks_hidden_channel_access_before_each_event() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        state
            .repository
            .ensure_user(
                User {
                    id: member,
                    handle: "hidden-channel-member".into(),
                    display_name: "Hidden Channel Member".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        let channel = state
            .repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let invite_hash = vec![71_u8; 32];
        state
            .repository
            .create_invite(
                owner,
                guild.id,
                "hidden-channel-invite".into(),
                &invite_hash,
                Some(1),
                None,
            )
            .await
            .unwrap();
        state
            .repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();
        state
            .repository
            .set_channel_overwrite(
                owner,
                channel.id,
                OverwriteTargetKind::Role,
                guild.id.raw(),
                GuildPermissions::empty(),
                GuildPermissions::VIEW_CHANNEL,
            )
            .await
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_router(server_state))
                .await
                .unwrap();
        });
        let endpoint = format!("http://{address}");
        let owner_client = ApiClient::new(&endpoint, owner.to_string()).unwrap();
        let member_client = ApiClient::new(&endpoint, member.to_string()).unwrap();
        let mut gateway = member_client.connect_gateway().await.unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::Ready(_))
        ));

        owner_client
            .send_message(
                channel.id.raw(),
                "must stay hidden",
                None,
                "hidden-event",
                &[],
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), gateway.next_event(),)
                .await
                .is_err()
        );

        state
            .repository
            .set_channel_overwrite(
                owner,
                channel.id,
                OverwriteTargetKind::Member,
                member.raw(),
                GuildPermissions::VIEW_CHANNEL
                    | GuildPermissions::READ_MESSAGE_HISTORY
                    | GuildPermissions::SEND_MESSAGES,
                GuildPermissions::empty(),
            )
            .await
            .unwrap();
        let visible = owner_client
            .send_message(channel.id.raw(), "now visible", None, "visible-event", &[])
            .await
            .unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::MessageCreate(message)) if message.id == visible.id
        ));
        server.abort();
    }

    #[tokio::test]
    async fn gateway_stops_server_events_after_membership_revocation() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let member = UserId::new();
        state
            .repository
            .ensure_user(
                User {
                    id: member,
                    handle: "gateway-revoked".into(),
                    display_name: "Gateway Revoked".into(),
                    avatar_url: None,
                    created_at: Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        let invite_hash = vec![14_u8; 32];
        state
            .repository
            .create_invite(
                owner,
                guild.id,
                "gateway-revocation-invite".into(),
                &invite_hash,
                Some(2),
                None,
            )
            .await
            .unwrap();
        state
            .repository
            .accept_invite(member, &invite_hash)
            .await
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_router(server_state))
                .await
                .unwrap();
        });
        let client = ApiClient::new(&format!("http://{address}"), member.to_string()).unwrap();
        let mut gateway = client.connect_gateway().await.unwrap();
        assert!(matches!(
            gateway.next_event().await.unwrap(),
            Some(GatewayEvent::Ready(_))
        ));

        state
            .repository
            .ban_member(owner, guild.id, member, Some("revoked".into()), None)
            .await
            .unwrap();
        publish_event(&state, EventType::GuildUpdate, Some(guild.id), &guild);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), gateway.next_event(),)
                .await
                .is_err(),
            "a revoked member must not receive later server events"
        );
        server.abort();
    }

    #[tokio::test]
    async fn production_auth_requires_ip_bound_single_use_proof_of_work() {
        let auth = AuthService::in_memory(EmailDelivery::DevelopmentConsole, None).unwrap();
        let app = build_router(AppState::seeded_with_auth(auth, false));
        let first_ip: SocketAddr = "198.51.100.8:43100".parse().unwrap();
        let second_ip: SocketAddr = "203.0.113.4:43100".parse().unwrap();

        let missing = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/email/request")
                    .extension(ConnectInfo(first_ip))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"secure@example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);
        assert!(missing.headers().contains_key("x-ratelimit-limit"));

        let challenge_response = app
            .clone()
            .oneshot(
                Request::get("/v1/auth/challenge")
                    .extension(ConnectInfo(first_ip))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge: exo_safety::ProofOfWorkChallenge = serde_json::from_slice(
            &to_bytes(challenge_response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let proof = exo_safety::solve_proof_of_work(&challenge).unwrap();
        let wrong_ip = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/email/request")
                    .extension(ConnectInfo(second_ip))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "email": "secure@example.test",
                            "proofOfWork": proof
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_ip.status(), StatusCode::BAD_REQUEST);

        let challenge_response = app
            .clone()
            .oneshot(
                Request::get("/v1/auth/challenge")
                    .extension(ConnectInfo(first_ip))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge: exo_safety::ProofOfWorkChallenge = serde_json::from_slice(
            &to_bytes(challenge_response.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let proof = exo_safety::solve_proof_of_work(&challenge).unwrap();
        let request_body = serde_json::json!({
            "email": "secure@example.test",
            "proofOfWork": proof
        })
        .to_string();
        let accepted = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/email/request")
                    .extension(ConnectInfo(first_ip))
                    .header("content-type", "application/json")
                    .body(Body::from(request_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let replay = app
            .oneshot(
                Request::post("/v1/auth/email/request")
                    .extension(ConnectInfo(first_ip))
                    .header("content-type", "application/json")
                    .body(Body::from(request_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn message_rate_limit_returns_retry_contract_after_exact_burst() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        let channel = state
            .repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let app = build_router(state);
        for index in 0..5 {
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("/v1/channels/{}/messages", channel.id))
                        .header("x-exocord-user-id", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "content": format!("burst {index}"),
                                "nonce": format!("burst-{index}")
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }
        let limited = app
            .oneshot(
                Request::post(format!("/v1/channels/{}/messages", channel.id))
                    .header("x-exocord-user-id", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"content":"six","nonce":"burst-6"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key("retry-after"));
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(limited.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body["global"], false);
        assert!(body["retryAfter"].as_f64().is_some_and(|value| value > 0.0));
    }

    #[tokio::test]
    async fn automod_http_blocks_before_storage_and_exposes_audit_history() {
        let state = AppState::seeded();
        let owner = UserId::from_raw(1).unwrap();
        let guild = state.repository.list_guilds(owner).await.unwrap().remove(0);
        let channel = state
            .repository
            .list_channels(owner, guild.id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.kind == ChannelKind::Text)
            .unwrap();
        let rule = state
            .repository
            .create_automod_rule(
                owner,
                guild.id,
                CreateAutomodRule {
                    name: "No credential leaks".into(),
                    enabled: true,
                    trigger: exo_domain::AutomodTrigger::Keyword {
                        terms: vec!["secret-token".into()],
                    },
                    action: AutomodAction::Block,
                    duration_seconds: None,
                    explanation: "Credentials must stay private.".into(),
                },
            )
            .await
            .unwrap();
        let app = build_router(state);
        let blocked = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{}/messages", channel.id))
                    .header("x-exocord-user-id", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"content":"SECRET-TOKEN is here","nonce":"blocked-automod"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let blocked_body = to_bytes(blocked.into_body(), 16 * 1024).await.unwrap();
        assert!(bytes_contain(
            &blocked_body,
            "Credentials must stay private."
        ));

        let disabled = app
            .clone()
            .oneshot(
                Request::patch(format!("/v1/guilds/{}/automod/rules/{}", guild.id, rule.id))
                    .header("x-exocord-user-id", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::OK);
        let accepted = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/channels/{}/messages", channel.id))
                    .header("x-exocord-user-id", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"content":"SECRET-TOKEN is here","nonce":"allowed-automod"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::CREATED);

        let audit = app
            .oneshot(
                Request::get(format!("/v1/guilds/{}/audit-log", guild.id))
                    .header("x-exocord-user-id", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(audit.status(), StatusCode::OK);
        let entries: Vec<AuditLogEntry> =
            serde_json::from_slice(&to_bytes(audit.into_body(), 64 * 1024).await.unwrap()).unwrap();
        assert!(entries.iter().any(|entry| entry.action_type == 61));
        assert!(entries.iter().any(|entry| entry.action_type == 51));
    }
}
