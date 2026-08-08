use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use exo_client::{
    AccountAuthMethods, AccountDeletion, ApiClient, AuthProviders, CacheSnapshot, CachedChannel,
    CachedGuild, CachedMessage, CachedUser, EmailCodeChallenge, GatewayEvent, LocalStore,
    MessageState, OperatorInfo, OwnedServerStatus, RecoveryKeyVaultEntry, RemoteError, ServerProbe,
    UpdateProfile,
};
use exo_crypto::{
    EncryptedAttachment, FrankingOpening, MessageContext, MlsClient, PublishedKeyPackage,
    WrappedAccountKeyMaterial, open_account_history_key,
    open_account_history_key_with_recovery_code, open_franking_opening, open_private_history,
    seal_franking_opening, seal_private_history, wrap_account_history_key,
    wrap_account_history_key_with_recovery_code,
};
use exo_domain::{
    AttachmentEncryption, AttachmentId, AttachmentUpload, AuditLogEntry, AutomodAction,
    AutomodRule, AutomodTrigger, BanMember, BootstrapMlsGroup, Channel as DomainChannel,
    ChannelKind, ChannelPermissionOverwrite, CreateAutomodRule, CreateChannel, CreateGuild,
    CreateInvite, CreateRole, GuildBan, GuildInvite, GuildMember, GuildPermissions, InvitePreview,
    Message as DomainMessage, MessageAttachment, MessageFrankingEvidence, MessageId,
    MessageReaction, MlsDeliveryKind, MlsKeyPackage, MlsMembershipHint, MlsWelcomeUpload,
    ModerateMember, OverwriteTargetKind, PresenceStatus, PrivateHistoryArchive,
    PublishMlsKeyPackage, PublishMlsKeyPackages, RegisterDeviceIdentity, RelationshipKind,
    ReportCategory, ReportReceipt, ReserveAttachment, Role, SearchExclusionReason, SyncSnapshot,
    TypingEvent, UpdateAutomodRule, UpdateChannel, UpdateChannelOverwrite, UpdateMlsGroup,
    UpdateRole, User, UserId, UserPresence, WrappedAccountKey, validate_message_with_attachments,
};
use exo_id::SnowflakeGenerator;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{
    AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder, WindowEvent,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use uuid::Uuid;
use zeroize::Zeroizing;

mod credentials;

use credentials::CredentialVault;

const CORE_SNAPSHOT_EVENT: &str = "core://snapshot";
const CORE_DELTA_EVENT: &str = "core://delta";
const CORE_AUTHORIZATION_EVENT: &str = "core://authorization-changed";
const CORE_DELTA_VERSION: u8 = 1;
const DEFAULT_API_URL: &str = "http://127.0.0.1:4100";
const ALPHA_CONVERSATION_CAPABILITY: &str = "replies_edits_deletes_unicode_reactions";
const CACHE_RESET_CONFIRMATION: &str = "RESET LOCAL CACHE";
const ACCOUNT_DELETE_CONFIRMATION: &str = "DELETE MY ACCOUNT";
const ACTIVE_ACCOUNT_FILENAME: &str = "active-account";
const MAX_OUTBOX_ATTEMPTS: u32 = 8;
const UPDATE_INSTALLER_ARGUMENTS: [&str; 3] = ["/S", "/NS", "/R"];
const MAIN_WINDOW_LABEL: &str = "main";

const fn default_minimize_to_tray() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone)]
struct NetworkConfiguration {
    api_url: String,
    source: &'static str,
    secure: bool,
    settings_path: PathBuf,
    warning: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkConfigurationView {
    api_url: String,
    source: &'static str,
    secure: bool,
    managed: bool,
    warning: Option<String>,
}

impl NetworkConfiguration {
    fn view(&self) -> NetworkConfigurationView {
        NetworkConfigurationView {
            api_url: self.api_url.clone(),
            source: self.source,
            secure: self.secure,
            managed: self.source == "environment",
            warning: self.warning.clone(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopSettings {
    api_url: Option<String>,
    #[serde(default)]
    notification_mode: NotificationMode,
    #[serde(default = "default_minimize_to_tray")]
    minimize_to_tray: bool,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            api_url: None,
            notification_mode: NotificationMode::default(),
            minimize_to_tray: default_minimize_to_tray(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NotificationMode {
    Off,
    #[default]
    Private,
    Names,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct NotificationSettingsView {
    mode: NotificationMode,
}

#[derive(Deserialize)]
struct NotificationSettingsInput {
    mode: NotificationMode,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct WindowSettingsView {
    minimize_to_tray: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WindowSettingsInput {
    minimize_to_tray: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkConfigurationInput {
    api_url: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateManifest {
    version: String,
    filename: String,
    sha256: String,
    #[serde(default)]
    notes: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateStatusView {
    current_version: String,
    update: Option<UpdateManifest>,
}

fn version_parts(value: &str) -> Option<Vec<u64>> {
    let value = value.trim().trim_start_matches('v');
    let core = value.split(['-', '+']).next()?;
    let parts = core
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!parts.is_empty()).then_some(parts)
}

fn version_is_newer(candidate: &str, current: &str) -> bool {
    let Some(mut candidate) = version_parts(candidate) else {
        return false;
    };
    let Some(mut current) = version_parts(current) else {
        return false;
    };
    let width = candidate.len().max(current.len());
    candidate.resize(width, 0);
    current.resize(width, 0);
    candidate > current
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn validate_update_manifest(manifest: &UpdateManifest) -> Result<(), String> {
    if !version_is_newer(&manifest.version, env!("CARGO_PKG_VERSION")) {
        return Ok(());
    }
    if manifest.filename.is_empty()
        || manifest.filename.len() > 120
        || !manifest.filename.ends_with(".exe")
        || !manifest
            .filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("the update manifest contains an invalid filename".to_owned());
    }
    if manifest.sha256.len() != 64 || !manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("the update manifest contains an invalid checksum".to_owned());
    }
    Ok(())
}

async fn fetch_update_manifest(network: &NetworkConfiguration) -> Result<UpdateManifest, String> {
    let url = format!("{}/downloads/latest.json", network.api_url);
    let response = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(8))
        .send()
        .await
        .map_err(|_| "the update server could not be reached".to_owned())?;
    if !response.status().is_success() {
        return Err("no published update is available".to_owned());
    }
    let manifest = response
        .json::<UpdateManifest>()
        .await
        .map_err(|_| "the update manifest is invalid".to_owned())?;
    validate_update_manifest(&manifest)?;
    Ok(manifest)
}

#[derive(Deserialize)]
struct OperatorResourceInput {
    resource: String,
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn normalize_api_url(value: &str) -> Result<(String, bool), String> {
    let mut url = url::Url::parse(value.trim())
        .map_err(|_| "Enter a complete server URL such as https://alpha.example.com.".to_owned())?;
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err("The server URL must include a network host.".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Credentials are not allowed inside the server URL.".to_owned());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("The server URL cannot include a query or fragment.".to_owned());
    }
    let secure = match url.scheme() {
        "https" => true,
        "http" if url.host_str().is_some_and(is_loopback_host) => false,
        "http" => return Err("Remote alpha servers must use HTTPS.".to_owned()),
        _ => return Err("The server URL must use HTTPS.".to_owned()),
    };
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok((url.as_str().trim_end_matches('/').to_owned(), secure))
}

fn resolve_network_configuration(data_directory: &Path) -> NetworkConfiguration {
    let environment_url = std::env::var("EXOCORD_API_URL").ok();
    resolve_network_configuration_from(
        data_directory,
        environment_url.as_deref(),
        option_env!("EXOCORD_DEFAULT_API_URL"),
    )
}

fn resolve_network_configuration_from(
    data_directory: &Path,
    environment_url: Option<&str>,
    build_url: Option<&str>,
) -> NetworkConfiguration {
    let settings_path = data_directory.join("settings.json");
    let mut warning = None;
    if let Some(value) = environment_url {
        match normalize_api_url(value) {
            Ok((api_url, secure)) => {
                return NetworkConfiguration {
                    api_url,
                    source: "environment",
                    secure,
                    settings_path,
                    warning: None,
                };
            }
            Err(error) => {
                warning = Some(format!("EXOCORD_API_URL was ignored: {error}"));
            }
        }
    }
    if let Some(value) = build_url {
        match normalize_api_url(value) {
            Ok((api_url, secure)) => {
                return NetworkConfiguration {
                    api_url,
                    source: "build",
                    secure,
                    settings_path,
                    warning,
                };
            }
            Err(error) => {
                warning = Some(format!("The build server URL was ignored: {error}"));
            }
        }
    }
    match std::fs::read_to_string(&settings_path) {
        Ok(value) => match serde_json::from_str::<DesktopSettings>(&value) {
            Ok(settings) => {
                if let Some(value) = settings.api_url {
                    match normalize_api_url(&value) {
                        Ok((api_url, secure)) => {
                            return NetworkConfiguration {
                                api_url,
                                source: "saved",
                                secure,
                                settings_path,
                                warning,
                            };
                        }
                        Err(error) => {
                            warning = Some(format!("The saved server URL was ignored: {error}"));
                        }
                    }
                }
            }
            Err(error) => {
                warning = Some(format!(
                    "The saved network settings could not be read: {error}"
                ));
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            warning = Some(format!(
                "The network settings file could not be read: {error}"
            ));
        }
    }
    NetworkConfiguration {
        api_url: DEFAULT_API_URL.to_owned(),
        source: "local_default",
        secure: false,
        settings_path,
        warning,
    }
}

fn read_desktop_settings(path: &Path) -> Result<DesktopSettings, String> {
    match std::fs::read(path) {
        Ok(contents) => serde_json::from_slice(&contents)
            .map_err(|error| format!("The desktop settings could not be decoded: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DesktopSettings::default())
        }
        Err(error) => Err(format!("The desktop settings could not be read: {error}")),
    }
}

fn save_desktop_settings(path: &Path, settings: &DesktopSettings) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "The desktop settings location is invalid.".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("The desktop settings folder could not be created: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    let backup = path.with_extension("json.bak");
    let contents = serde_json::to_vec_pretty(settings)
        .map_err(|error| format!("The desktop settings could not be encoded: {error}"))?;
    std::fs::write(&temporary, contents)
        .map_err(|error| format!("The desktop settings could not be written: {error}"))?;

    if path.exists() {
        if backup.exists() {
            std::fs::remove_file(&backup).map_err(|error| {
                format!("The stale settings backup could not be removed: {error}")
            })?;
        }
        std::fs::rename(path, &backup).map_err(|error| {
            format!("The current network settings could not be backed up: {error}")
        })?;
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        if backup.exists() {
            if let Err(rollback_error) = std::fs::rename(&backup, path) {
                return Err(format!(
                    "The new network settings could not be activated: {error}. The previous settings also could not be restored: {rollback_error}. The backup remains at {}.",
                    backup.display()
                ));
            }
        }
        return Err(format!(
            "The new network settings could not be activated: {error}"
        ));
    }
    if backup.exists() {
        std::fs::remove_file(&backup)
            .map_err(|error| format!("The stale settings backup could not be removed: {error}"))?;
    }
    Ok(())
}

fn save_network_settings(path: &Path, api_url: &str) -> Result<(), String> {
    let mut settings = read_desktop_settings(path)?;
    settings.api_url = Some(api_url.to_owned());
    save_desktop_settings(path, &settings)
}

fn active_account_path(data_directory: &Path) -> PathBuf {
    data_directory.join(ACTIVE_ACCOUNT_FILENAME)
}

fn read_active_account(data_directory: &Path) -> Result<Option<u64>, String> {
    let path = active_account_path(data_directory);
    match std::fs::read_to_string(&path) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .map(Some)
            .ok_or_else(|| "the active account marker is invalid".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "the active account marker could not be read: {error}"
        )),
    }
}

fn write_active_account(data_directory: &Path, account_id: u64) -> Result<(), String> {
    if account_id == 0 {
        return Err("the account id is invalid".to_owned());
    }
    std::fs::create_dir_all(data_directory)
        .map_err(|error| format!("the account directory could not be created: {error}"))?;
    let path = active_account_path(data_directory);
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, format!("{account_id}\n"))
        .map_err(|error| format!("the active account marker could not be written: {error}"))?;
    std::fs::rename(&temporary, &path)
        .map_err(|error| format!("the active account marker could not be activated: {error}"))
}

fn clear_active_account(data_directory: &Path) -> Result<(), String> {
    match std::fs::remove_file(active_account_path(data_directory)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "the active account marker could not be removed: {error}"
        )),
    }
}

fn account_cache_path(data_directory: &Path, account_id: u64) -> PathBuf {
    data_directory
        .join("accounts")
        .join(account_id.to_string())
        .join("client.sqlite3")
}

fn account_device_path(data_directory: &Path, account_id: u64) -> PathBuf {
    data_directory
        .join("accounts")
        .join(account_id.to_string())
        .join("device-id")
}

fn persist_device_id(path: &Path, device_id: &str) -> std::io::Result<()> {
    let canonical = Uuid::parse_str(device_id)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?
        .to_string();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, canonical)
}

fn existing_device_id(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|stored| Uuid::parse_str(stored.trim()).ok())
        .map(|device_id| device_id.to_string())
}

fn startup_device_id(
    data_directory: &Path,
    active_account_id: Option<u64>,
) -> std::io::Result<String> {
    let Some(account_id) = active_account_id else {
        return Ok(Uuid::now_v7().to_string());
    };
    let scoped_path = account_device_path(data_directory, account_id);
    if let Some(device_id) = existing_device_id(&scoped_path) {
        return Ok(device_id);
    }
    let legacy_path = data_directory.join("device-id");
    if let Some(device_id) = existing_device_id(&legacy_path) {
        return Ok(device_id);
    }
    load_or_create_device_id(&scoped_path)
}

fn ensure_alpha_server_compatible(probe: &ServerProbe, secure: bool) -> Result<(), String> {
    if !probe.ready {
        return Err("The server reports that it is not ready.".to_owned());
    }
    if !probe.password {
        return Err("This server does not support Exo Link password sign-in.".to_owned());
    }
    if probe.conversation_actions != ALPHA_CONVERSATION_CAPABILITY {
        return Err("This server is not compatible with this Exo Link alpha build.".to_owned());
    }
    if secure && probe.storage != "postgres" {
        return Err("A remote alpha server must use durable PostgreSQL storage.".to_owned());
    }
    if secure && matches!(probe.attachments.as_str(), "disabled" | "not_configured") {
        return Err("A remote alpha server must configure attachment storage.".to_owned());
    }
    if secure && probe.native_voice == "not_configured" {
        return Err("A remote alpha server must configure native voice.".to_owned());
    }
    if secure && probe.operator.name.trim().is_empty() {
        return Err("A remote alpha server must identify its operator.".to_owned());
    }
    if secure {
        validate_operator_https_url(probe.operator.privacy_url.as_deref())?;
        validate_operator_email(probe.operator.support_email.as_deref())?;
        validate_operator_email(probe.operator.abuse_email.as_deref())?;
        if probe.operator.terms_url.is_some() {
            validate_operator_https_url(probe.operator.terms_url.as_deref())?;
        }
    }
    Ok(())
}

fn validate_operator_https_url(value: Option<&str>) -> Result<String, String> {
    let value =
        value.ok_or_else(|| "The alpha operator did not publish a privacy URL.".to_owned())?;
    let parsed =
        url::Url::parse(value).map_err(|_| "The alpha operator URL is invalid.".to_owned())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "Alpha operator links must be credential-free HTTPS URLs without query data."
                .to_owned(),
        );
    }
    Ok(parsed.into())
}

fn validate_operator_email(value: Option<&str>) -> Result<String, String> {
    let value =
        value.ok_or_else(|| "The alpha operator did not publish a contact email.".to_owned())?;
    if value.len() > 254
        || value.matches('@').count() != 1
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("The alpha operator contact email is invalid.".to_owned());
    }
    let Some((local, domain)) = value.split_once('@') else {
        return Err("The alpha operator contact email is invalid.".to_owned());
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err("The alpha operator contact email is invalid.".to_owned());
    }
    Ok(value.to_owned())
}

fn cache_reset_confirmed(value: &str) -> bool {
    value.trim() == CACHE_RESET_CONFIRMATION
}

fn account_delete_confirmed(value: &str) -> bool {
    value.trim() == ACCOUNT_DELETE_CONFIRMATION
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConnectionState {
    Offline,
    Connecting,
    Connected,
    CatchingUp,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Channel {
    id: String,
    name: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    unread: Option<bool>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Member {
    id: String,
    name: String,
    handle: String,
    initials: String,
    color: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_url: Option<String>,
    presence: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct VoiceParticipant {
    member_id: String,
    state: &'static str,
    note: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct VoiceRoom {
    id: String,
    name: String,
    latency_ms: u32,
    encrypted: bool,
    participants: Vec<VoiceParticipant>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Workspace {
    id: String,
    owner_id: String,
    name: String,
    initials: String,
    accent: String,
    permission_keys: Vec<String>,
    member_ids: Vec<String>,
    channels: Vec<Channel>,
    voice_rooms: Vec<VoiceRoom>,
    direct_messages: bool,
    local_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unread_count: Option<u32>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatMessage {
    id: String,
    client_key: String,
    channel_id: String,
    author_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to_id: Option<String>,
    content: String,
    attachments: Vec<MessageAttachment>,
    reactions: Vec<MessageReaction>,
    sent_at: String,
    edited: bool,
    delivery_state: MessageState,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivered: Option<bool>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapViewModel {
    revision: u64,
    current_user_id: String,
    active_workspace_id: String,
    active_channel_id: String,
    active_voice_room_id: Option<String>,
    connection_state: ConnectionState,
    pending_outbox: u32,
    workspaces: Vec<Workspace>,
    members: Vec<Member>,
    relationships: Vec<RelationshipView>,
    typing: Vec<TypingView>,
    messages: Vec<ChatMessage>,
    cache_protection: CacheProtectionView,
    cache_recovery: Option<CacheRecoveryView>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CacheProtectionView {
    encrypted: bool,
    cipher: String,
    key_storage: &'static str,
}

#[derive(Clone, Copy)]
enum CacheRecoveryKind {
    VaultUnavailable,
    CacheKeyUnavailable,
    EncryptionUnavailable,
    CacheLocked,
    CacheCorrupt,
    MigrationFailed,
    StorageFailed,
}

impl CacheRecoveryKind {
    const fn code(self) -> &'static str {
        match self {
            Self::VaultUnavailable => "vault_unavailable",
            Self::CacheKeyUnavailable => "cache_key_unavailable",
            Self::EncryptionUnavailable => "encryption_unavailable",
            Self::CacheLocked => "cache_locked",
            Self::CacheCorrupt => "cache_corrupt",
            Self::MigrationFailed => "migration_failed",
            Self::StorageFailed => "storage_failed",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::VaultUnavailable => "The secure key vault is unavailable",
            Self::CacheKeyUnavailable => "The local cache key cannot be read",
            Self::EncryptionUnavailable => "This build cannot open encrypted caches",
            Self::CacheLocked => "The local cache is locked",
            Self::CacheCorrupt => "The local cache did not pass verification",
            Self::MigrationFailed => "The local cache upgrade was interrupted",
            Self::StorageFailed => "The local cache cannot be opened safely",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::VaultUnavailable => {
                "Exo Link cannot reach the operating-system credential vault. Your cache has not been changed."
            }
            Self::CacheKeyUnavailable => {
                "The saved cache key is missing, malformed, or temporarily unreadable. Exo Link will not guess or fall back to plaintext."
            }
            Self::EncryptionUnavailable => {
                "SQLCipher is unavailable in this desktop build. Reinstall a verified Exo Link build before touching the cache."
            }
            Self::CacheLocked => {
                "The vault key does not unlock this database, or an authenticated page is damaged. The original files remain in place."
            }
            Self::CacheCorrupt => {
                "SQLCipher opened the database, but its integrity check failed. The original files remain in place."
            }
            Self::MigrationFailed => {
                "Exo Link could not prove that the legacy-to-encrypted migration completed safely, so it stopped without replacing the cache."
            }
            Self::StorageFailed => {
                "A filesystem or database error prevented a safe open. Exo Link stopped before starting synchronization."
            }
        }
    }
}

#[derive(Clone)]
struct CacheRecoveryState {
    kind: CacheRecoveryKind,
    detail: String,
    cache_path: std::path::PathBuf,
    can_reset: bool,
}

impl CacheRecoveryState {
    fn from_store_error(cache_path: std::path::PathBuf, error: &exo_client::StoreError) -> Self {
        let kind = match error {
            exo_client::StoreError::EncryptionUnavailable => {
                CacheRecoveryKind::EncryptionUnavailable
            }
            exo_client::StoreError::CacheUnlockFailed => CacheRecoveryKind::CacheLocked,
            exo_client::StoreError::CacheIntegrityFailed => CacheRecoveryKind::CacheCorrupt,
            exo_client::StoreError::CacheMigrationFailed => CacheRecoveryKind::MigrationFailed,
            _ => CacheRecoveryKind::StorageFailed,
        };
        Self {
            kind,
            detail: error.to_string(),
            cache_path,
            can_reset: !matches!(kind, CacheRecoveryKind::EncryptionUnavailable),
        }
    }

    fn view(&self) -> CacheRecoveryView {
        CacheRecoveryView {
            reason: self.kind.code(),
            title: self.kind.title(),
            message: self.kind.message(),
            detail: self.detail.clone(),
            cache_path: self.cache_path.to_string_lossy().into_owned(),
            can_reset: self.can_reset,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CacheRecoveryView {
    reason: &'static str,
    title: &'static str,
    message: &'static str,
    detail: String,
    cache_path: String,
    can_reset: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelationshipView {
    user_id: String,
    name: String,
    handle: String,
    initials: String,
    color: String,
    kind: &'static str,
    since: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TypingView {
    channel_id: String,
    user_id: String,
    expires_at: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectUnreadDelta {
    channel_id: String,
    unread: bool,
    unread_count: u32,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CoreDeltaChange {
    MessageUpsert {
        message: ChatMessage,
        #[serde(skip_serializing_if = "Option::is_none")]
        direct_unread: Option<DirectUnreadDelta>,
        #[serde(skip_serializing_if = "is_false")]
        notify: bool,
    },
    MessageDelete {
        message_id: String,
        channel_id: String,
    },
    Presence {
        user_id: String,
        presence: &'static str,
    },
    TypingUpsert {
        typing: TypingView,
    },
    TypingRemove {
        channel_id: String,
        user_id: String,
    },
    ReadState {
        direct_unread: DirectUnreadDelta,
    },
    Connection {
        connection_state: ConnectionState,
    },
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreDelta {
    version: u8,
    revision: u64,
    #[serde(flatten)]
    change: CoreDeltaChange,
}

#[derive(Deserialize)]
struct CreateWorkspaceInput {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceInviteInput {
    workspace_id: String,
}

#[derive(Deserialize)]
struct InviteCodeInput {
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteView {
    code: String,
    max_uses: Option<u32>,
    expires_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitePreviewView {
    code: String,
    workspace_id: String,
    name: String,
    accent: String,
    member_count: u32,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceRolesInput {
    workspace_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleMutationInput {
    workspace_id: String,
    #[serde(default)]
    role_id: Option<String>,
    name: String,
    color: String,
    permission_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleTargetInput {
    workspace_id: String,
    role_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberRoleInput {
    workspace_id: String,
    member_id: String,
    role_id: String,
    assigned: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoleView {
    id: String,
    name: String,
    color: String,
    position: i32,
    permission_keys: Vec<String>,
    everyone: bool,
    managed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoleMemberView {
    id: String,
    name: String,
    handle: String,
    initials: String,
    color: String,
    role_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoleManagerView {
    roles: Vec<RoleView>,
    members: Vec<RoleMemberView>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceChannelsInput {
    workspace_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelMutationInput {
    workspace_id: String,
    #[serde(default)]
    channel_id: Option<String>,
    name: String,
    kind: String,
    #[serde(default)]
    encrypted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelTargetInput {
    channel_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VoiceGrantInput {
    channel_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelOverwriteInput {
    channel_id: String,
    target_kind: String,
    target_id: String,
    allow_keys: Vec<String>,
    deny_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelOverwriteTargetInput {
    channel_id: String,
    target_kind: String,
    target_id: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedChannelView {
    id: String,
    name: String,
    kind: &'static str,
    encrypted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelManagerView {
    channels: Vec<ManagedChannelView>,
    roles: Vec<RoleView>,
    members: Vec<RoleMemberView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelOverwriteView {
    channel_id: String,
    target_kind: &'static str,
    target_id: String,
    allow_keys: Vec<String>,
    deny_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberModerationInput {
    workspace_id: String,
    member_id: String,
    #[serde(default)]
    duration_seconds: Option<u32>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModerationMemberView {
    id: String,
    name: String,
    handle: String,
    initials: String,
    color: String,
    role_ids: Vec<String>,
    timeout_until: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BanView {
    id: String,
    name: String,
    handle: String,
    initials: String,
    color: String,
    reason: Option<String>,
    expires_at: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModerationManagerView {
    members: Vec<ModerationMemberView>,
    bans: Vec<BanView>,
    rules: Vec<AutomodRuleView>,
    audit: Vec<AuditLogView>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutomodRuleMutationInput {
    workspace_id: String,
    #[serde(default)]
    rule_id: Option<String>,
    name: String,
    enabled: bool,
    trigger_type: String,
    #[serde(default)]
    terms: Vec<String>,
    #[serde(default)]
    mention_limit: Option<u16>,
    #[serde(default)]
    repeat_threshold: Option<u8>,
    #[serde(default)]
    window_seconds: Option<u16>,
    #[serde(default)]
    max_account_age_days: Option<u16>,
    #[serde(default)]
    combining_mark_limit: Option<u16>,
    action: String,
    #[serde(default)]
    duration_seconds: Option<u32>,
    explanation: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutomodRuleTargetInput {
    workspace_id: String,
    rule_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AutomodRuleView {
    id: String,
    name: String,
    enabled: bool,
    trigger_type: &'static str,
    terms: Vec<String>,
    mention_limit: Option<u16>,
    repeat_threshold: Option<u8>,
    window_seconds: Option<u16>,
    max_account_age_days: Option<u16>,
    combining_mark_limit: Option<u16>,
    action: &'static str,
    duration_seconds: Option<u32>,
    explanation: String,
    updated_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditLogView {
    id: String,
    actor_id: Option<String>,
    target_id: Option<String>,
    action_type: i16,
    action_label: &'static str,
    detail: Option<String>,
    reason: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendMessageInput {
    channel_id: String,
    content: String,
    #[serde(default)]
    reply_to_id: Option<String>,
    #[serde(default)]
    attachments: Vec<MessageAttachment>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditMessageInput {
    channel_id: String,
    message_id: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageTargetInput {
    channel_id: String,
    message_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageReactionInput {
    channel_id: String,
    message_id: String,
    emoji: String,
    added: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrepareAttachmentInput {
    channel_id: String,
    filename: String,
    content_type: String,
    file_size: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentTargetInput {
    attachment_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchInput {
    workspace_id: String,
    query: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReportMessageInput {
    message_id: String,
    category: String,
    detail: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenSearchHitInput {
    workspace_id: String,
    channel_id: String,
    message_id: String,
    local_only: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchHitView {
    message: ChatMessage,
    workspace_id: String,
    workspace_name: String,
    channel_id: String,
    channel_name: String,
    local_only: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchView {
    total: u64,
    hits: Vec<SearchHitView>,
    encrypted_channel_count: u32,
    permission_excluded_count: u32,
}

#[derive(Deserialize)]
struct ActiveContextInput {
    #[serde(rename = "workspaceId")]
    workspace: String,
    #[serde(rename = "channelId")]
    channel: String,
    #[serde(rename = "voiceRoomId")]
    voice_room: Option<String>,
}

#[derive(Deserialize)]
struct FriendHandleInput {
    handle: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelationshipTargetInput {
    user_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadStateCommandInput {
    channel_id: String,
    message_id: String,
}

#[derive(Clone)]
struct DesktopCore {
    store: Arc<LocalStore>,
    remote: ApiClient,
    network: NetworkConfiguration,
    settings: Arc<Mutex<DesktopSettings>>,
    ids: Arc<SnowflakeGenerator>,
    connection: Arc<Mutex<ConnectionState>>,
    revision: Arc<AtomicU64>,
    device_id: String,
    data_directory: PathBuf,
    active_account_id: Option<u64>,
    vault: Option<CredentialVault>,
    mls: Arc<Mutex<Option<MlsClient>>>,
    mls_device_key: Option<[u8; 32]>,
    mls_setup: Arc<tokio::sync::Mutex<()>>,
    mls_published: Arc<AtomicBool>,
    private_history_retry: Arc<AtomicBool>,
    update_installing: Arc<AtomicBool>,
    auth_restore: Arc<tokio::sync::Mutex<()>>,
    presences: Arc<Mutex<HashMap<u64, UserPresence>>>,
    typing: Arc<Mutex<HashMap<(u64, u64), TypingEvent>>>,
    cache_recovery: Option<CacheRecoveryState>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
// These are independent server/session capabilities exposed to the renderer.
#[allow(clippy::struct_excessive_bools)]
struct AuthView {
    signed_in: bool,
    email: Option<String>,
    deletion_scheduled_for: Option<String>,
    password_available: bool,
    apple_available: bool,
    development_code_preview: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasswordAuthenticationView {
    auth: AuthView,
    recovery_codes: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountDeletionView {
    requested_at: String,
    scheduled_for: String,
}

impl From<AccountDeletion> for AccountDeletionView {
    fn from(value: AccountDeletion) -> Self {
        Self {
            requested_at: value.requested_at,
            scheduled_for: value.scheduled_for,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnedServerStatusView {
    id: String,
    name: String,
    member_count: u32,
}

impl From<OwnedServerStatus> for OwnedServerStatusView {
    fn from(value: OwnedServerStatus) -> Self {
        Self {
            id: value.id,
            name: value.name,
            member_count: value.member_count,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountDeletionStatusView {
    deletion: Option<AccountDeletionView>,
    owned_servers: Vec<OwnedServerStatusView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerOwnershipMemberView {
    id: String,
    name: String,
    handle: String,
    initials: String,
    color: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerOwnershipView {
    workspace_id: String,
    owner_id: String,
    name: String,
    members: Vec<ServerOwnershipMemberView>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferServerOwnershipInput {
    workspace_id: String,
    member_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteServerInput {
    workspace_id: String,
    confirmation: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceSecurityDevice {
    device_id: String,
    name: String,
    fingerprint: String,
    current: bool,
    revoked: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceSecurityView {
    ready: bool,
    device_id: String,
    fingerprint: Option<String>,
    cipher_suite: &'static str,
    no_key_backup: bool,
    history_notice: &'static str,
    devices: Vec<DeviceSecurityDevice>,
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceTargetInput {
    device_id: String,
}

#[derive(Deserialize)]
struct EmailInput {
    email: String,
}

#[derive(Deserialize)]
struct PasswordAuthInput {
    email: String,
    username: Option<String>,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordInput {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoverPasswordInput {
    email: String,
    recovery_code: String,
    new_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmPasswordInput {
    current_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyCodeInput {
    challenge_id: String,
    code: String,
}

#[derive(Deserialize)]
struct ResetLocalCacheInput {
    confirmation: String,
}

#[derive(Deserialize)]
struct DeleteAccountInput {
    confirmation: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProfileInput {
    handle: String,
    display_name: String,
    avatar_content_type: Option<String>,
    avatar_base64: Option<String>,
    remove_avatar: bool,
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn network_configuration(state: State<'_, DesktopCore>) -> NetworkConfigurationView {
    state.network.view()
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn notification_settings(
    state: State<'_, DesktopCore>,
) -> Result<NotificationSettingsView, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "The desktop settings lock is unavailable.".to_owned())?;
    Ok(NotificationSettingsView {
        mode: settings.notification_mode,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn save_notification_settings(
    input: NotificationSettingsInput,
    state: State<'_, DesktopCore>,
) -> Result<NotificationSettingsView, String> {
    let mut settings = state
        .settings
        .lock()
        .map_err(|_| "The desktop settings lock is unavailable.".to_owned())?;
    let mut updated = settings.clone();
    updated.notification_mode = input.mode;
    save_desktop_settings(&state.network.settings_path, &updated)?;
    *settings = updated;
    Ok(NotificationSettingsView { mode: input.mode })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn window_settings(state: State<'_, DesktopCore>) -> Result<WindowSettingsView, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "The desktop settings lock is unavailable.".to_owned())?;
    Ok(WindowSettingsView {
        minimize_to_tray: settings.minimize_to_tray,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn save_window_settings(
    input: WindowSettingsInput,
    state: State<'_, DesktopCore>,
) -> Result<WindowSettingsView, String> {
    let mut settings = state
        .settings
        .lock()
        .map_err(|_| "The desktop settings lock is unavailable.".to_owned())?;
    let mut updated = settings.clone();
    updated.minimize_to_tray = input.minimize_to_tray;
    save_desktop_settings(&state.network.settings_path, &updated)?;
    *settings = updated;
    Ok(WindowSettingsView {
        minimize_to_tray: input.minimize_to_tray,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn probe_network_configuration(
    input: NetworkConfigurationInput,
) -> Result<ServerProbe, String> {
    let (api_url, _) = normalize_api_url(&input.api_url)?;
    ApiClient::new(&api_url, "network-probe")
        .map_err(|error| error.to_string())?
        .probe_server()
        .await
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn operator_info(state: State<'_, DesktopCore>) -> Result<OperatorInfo, String> {
    state
        .remote
        .operator_info()
        .await
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn open_operator_resource(
    input: OperatorResourceInput,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    let operator = state
        .remote
        .operator_info()
        .await
        .map_err(|error| error.to_string())?;
    let resource = match input.resource.as_str() {
        "privacy" => validate_operator_https_url(operator.privacy_url.as_deref()).ok(),
        "terms" => validate_operator_https_url(operator.terms_url.as_deref()).ok(),
        "support" => validate_operator_email(operator.support_email.as_deref())
            .ok()
            .map(|email| format!("mailto:{email}")),
        "abuse" => validate_operator_email(operator.abuse_email.as_deref())
            .ok()
            .map(|email| format!("mailto:{email}")),
        _ => return Err("unknown operator resource".to_owned()),
    }
    .ok_or_else(|| "the alpha operator did not publish that resource".to_owned())?;
    tauri_plugin_opener::open_url(&resource, None::<&str>)
        .map_err(|error| format!("the operator resource could not be opened: {error}"))
}

#[tauri::command]
async fn check_for_update(state: State<'_, DesktopCore>) -> Result<UpdateStatusView, String> {
    let current_version = env!("CARGO_PKG_VERSION").to_owned();
    let manifest = fetch_update_manifest(&state.network).await?;
    let update = version_is_newer(&manifest.version, &current_version).then_some(manifest);
    Ok(UpdateStatusView {
        current_version,
        update,
    })
}

#[tauri::command]
async fn install_available_update(
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    let manifest = fetch_update_manifest(&state.network).await?;
    if !version_is_newer(&manifest.version, env!("CARGO_PKG_VERSION")) {
        return Err("Exo Link is already up to date".to_owned());
    }
    let url = format!("{}/downloads/{}", state.network.api_url, manifest.filename);
    let response = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        .map_err(|_| "the update download could not start".to_owned())?;
    if !response.status().is_success() {
        return Err("the update download failed".to_owned());
    }
    if response
        .content_length()
        .is_some_and(|length| length > 200 * 1024 * 1024)
    {
        return Err("the update is unexpectedly large".to_owned());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "the update download was interrupted".to_owned())?;
    if bytes.len() > 200 * 1024 * 1024 {
        return Err("the update is unexpectedly large".to_owned());
    }
    let checksum = hex::encode(Sha256::digest(&bytes));
    if !checksum.eq_ignore_ascii_case(&manifest.sha256) {
        return Err("the update checksum did not match; nothing was installed".to_owned());
    }
    let path = std::env::temp_dir().join(&manifest.filename);
    std::fs::write(&path, &bytes)
        .map_err(|_| "the verified update could not be staged".to_owned())?;

    if state
        .update_installing
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .is_err()
    {
        return Err("an Exo Link update is already being installed".to_owned());
    }

    // Remove tray/window resources before handing control to NSIS. `/R` asks
    // the signed installer to relaunch the freshly installed app exactly once
    // after it has finished replacing the executable.
    app.cleanup_before_exit();
    if let Err(error) = std::process::Command::new(&path)
        .args(UPDATE_INSTALLER_ARGUMENTS)
        .spawn()
        .map_err(|_| "the verified update installer could not start".to_owned())
    {
        state
            .update_installing
            .store(false, AtomicOrdering::Release);
        return Err(error);
    }
    app.exit(0);
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn save_network_configuration(
    input: NetworkConfigurationInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    if state.network.source == "environment" || state.network.source == "build" {
        return Err(
            if state.network.source == "environment" {
                "This installation is managed by EXOCORD_API_URL. Remove that override to change networks."
            } else {
                "This alpha is pinned to its hosted server. Install a generic build to change networks."
            }
            .to_owned(),
        );
    }
    let (api_url, secure) = normalize_api_url(&input.api_url)?;
    let probe = ApiClient::new(&api_url, "network-probe")
        .map_err(|error| error.to_string())?
        .probe_server()
        .await
        .map_err(|error| error.to_string())?;
    ensure_alpha_server_compatible(&probe, secure)?;
    save_network_settings(&state.network.settings_path, &api_url)?;
    app.restart();
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn auth_status(state: State<'_, DesktopCore>) -> Result<AuthView, String> {
    if state.cache_recovery.is_some() {
        return Ok(AuthView {
            signed_in: false,
            email: None,
            deletion_scheduled_for: None,
            password_available: false,
            apple_available: false,
            development_code_preview: false,
        });
    }
    restore_session(&state).await?;
    let providers = state
        .remote
        .auth_providers()
        .await
        .unwrap_or(AuthProviders {
            password: true,
            email: true,
            apple: false,
            development_code_preview: false,
        });
    let session = state.remote.session();
    Ok(AuthView {
        signed_in: session.is_some(),
        email: session.as_ref().map(|session| session.user.email.clone()),
        deletion_scheduled_for: session.and_then(|session| session.user.deletion_scheduled_for),
        password_available: providers.password,
        apple_available: providers.apple,
        development_code_preview: providers.development_code_preview,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn update_profile(
    input: UpdateProfileInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<BootstrapViewModel, String> {
    let updated = state
        .remote
        .update_profile(&UpdateProfile {
            handle: input.handle,
            display_name: input.display_name,
            avatar_content_type: input.avatar_content_type,
            avatar_base64: input.avatar_base64,
            remove_avatar: input.remove_avatar,
        })
        .await
        .map_err(|error| error.to_string())?;
    state
        .store
        .put_user(&CachedUser {
            id: updated.id.raw(),
            handle: updated.handle,
            display_name: updated.display_name,
            avatar_url: updated.avatar_url,
            origin_remote: true,
        })
        .map_err(|error| error.to_string())?;
    synchronize_once(&state)
        .await
        .map_err(|error| error.to_string())?;
    emit_snapshot(&app, &state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn device_security_status(
    state: State<'_, DesktopCore>,
) -> Result<DeviceSecurityView, String> {
    let user_id = state
        .store
        .snapshot()
        .map_err(|error| error.to_string())?
        .current_user_id
        .ok_or_else(|| "the local profile is unavailable".to_owned())?;
    let setup_error = ensure_e2ee_identity(&state, user_id)
        .await
        .err()
        .map(|error| error.to_string());
    let local_identity = state
        .mls
        .lock()
        .map_err(|_| "the local MLS state lock is unavailable".to_owned())?
        .as_ref()
        .map(MlsClient::public_identity);
    let mut devices = state
        .remote
        .list_device_identities(UserId::from_raw(user_id).map_err(|error| error.to_string())?)
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|device| DeviceSecurityDevice {
            device_id: device.device_id.to_string(),
            name: device.name.unwrap_or_else(|| "Exo Link device".to_owned()),
            fingerprint: device.fingerprint,
            current: device.device_id.to_string() == state.device_id,
            revoked: device.revoked_at.is_some(),
        })
        .collect::<Vec<_>>();
    if devices.is_empty()
        && let Some(identity) = &local_identity
    {
        devices.push(DeviceSecurityDevice {
            device_id: identity.device_id.to_string(),
            name: "Exo Link Desktop".to_owned(),
            fingerprint: identity.fingerprint.clone(),
            current: true,
            revoked: false,
        });
    }
    devices.sort_by_key(|device| (!device.current, device.revoked, device.name.clone()));

    Ok(DeviceSecurityView {
        ready: local_identity.is_some() && setup_error.is_none(),
        device_id: state.device_id.clone(),
        fingerprint: local_identity.map(|identity| identity.fingerprint),
        cipher_suite: "MLS 1.0 · X25519 · AES-128-GCM · Ed25519",
        no_key_backup: false,
        history_notice: "Sign in after reinstalling to restore account data and client-encrypted direct-message history. Exo Link never receives the recovery key or archived plaintext.",
        devices,
        error: setup_error,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn revoke_device(
    input: DeviceTargetInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    if input.device_id == state.device_id {
        return Err("Sign out this device instead of revoking it.".to_owned());
    }
    Uuid::parse_str(&input.device_id)
        .map_err(|_| "the selected device id is invalid".to_owned())?;
    state
        .remote
        .revoke_device_identity(&input.device_id)
        .await
        .map_err(|error| error.to_string())?;
    if let Ok(hints) = state.remote.pending_mls_maintenance(&state.device_id).await {
        for hint in hints {
            if let Err(error) = maintain_channel_mls(&state, &hint).await {
                tracing::warn!(
                    %error,
                    channel_id = %hint.channel_id,
                    "revoked device is queued for MLS removal"
                );
            } else {
                app.emit(CORE_AUTHORIZATION_EVENT, ())
                    .map_err(|error| error.to_string())?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn request_login_code(
    input: EmailInput,
    state: State<'_, DesktopCore>,
) -> Result<EmailCodeChallenge, String> {
    state
        .remote
        .request_email_code(&input.email)
        .await
        .map_err(|error| error.to_string())
}

async fn finish_authentication(
    app: &AppHandle,
    state: &DesktopCore,
    session: exo_client::SessionBundle,
    activate_immediately: bool,
) -> Result<AuthView, String> {
    let account_id = session_account_id(&session)?;
    let device_id = state
        .remote
        .device_id()
        .ok_or_else(|| "the authenticated device id is unavailable".to_owned())?;
    persist_device_id(
        &account_device_path(&state.data_directory, account_id),
        &device_id,
    )
    .map_err(|error| format!("the account device id could not be saved: {error}"))?;
    let switched_account = state.active_account_id != Some(account_id);
    let switched_device = state.device_id != device_id;
    if activate_immediately {
        persist_session_bundle(state, &session)?;
        write_active_account(&state.data_directory, account_id)?;
        if switched_account || switched_device {
            app.restart();
        }
    }
    if activate_immediately
        && !switched_account
        && !switched_device
        && session.user.deletion_scheduled_for.is_none()
        && synchronize_once(state).await.is_ok()
    {
        emit_snapshot_or_warn(app, state, "authentication");
    }
    let providers = state
        .remote
        .auth_providers()
        .await
        .unwrap_or(AuthProviders {
            password: true,
            email: true,
            apple: false,
            development_code_preview: false,
        });
    Ok(AuthView {
        signed_in: true,
        email: Some(session.user.email),
        deletion_scheduled_for: session.user.deletion_scheduled_for,
        password_available: providers.password,
        apple_available: providers.apple,
        development_code_preview: false,
    })
}

async fn bind_password_session_to_account_device(
    state: &DesktopCore,
    email: &str,
    password: &str,
    session: exo_client::SessionBundle,
) -> Result<exo_client::SessionBundle, String> {
    let account_id = session_account_id(&session)?;
    let account_device =
        existing_device_id(&account_device_path(&state.data_directory, account_id))
            .unwrap_or_else(|| Uuid::now_v7().to_string());
    let current_device = state
        .remote
        .device_id()
        .ok_or_else(|| "the authenticated device id is unavailable".to_owned())?;
    if account_device == current_device {
        return Ok(session);
    }

    if let Err(error) = state.remote.logout().await {
        tracing::debug!(
            %error,
            "the temporary password session could not be revoked before device rebinding"
        );
    }
    state.remote.clear_session();
    state.remote.set_device_id(account_device.clone());
    let rebound = state
        .remote
        .login_password(email, password, &account_device)
        .await
        .map_err(|error| error.to_string())?;
    if session_account_id(&rebound)? != account_id {
        state.remote.clear_session();
        return Err("the rebound session belongs to another account".to_owned());
    }
    Ok(rebound)
}

fn select_account_device(state: &DesktopCore, account_id: u64) -> Result<String, String> {
    let device_id = existing_device_id(&account_device_path(&state.data_directory, account_id))
        .or_else(|| state.remote.device_id())
        .ok_or_else(|| "the authenticated device id is unavailable".to_owned())?;
    state.remote.set_device_id(device_id.clone());
    Ok(device_id)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn register_with_password(
    input: PasswordAuthInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<PasswordAuthenticationView, String> {
    let username = input
        .username
        .as_deref()
        .ok_or_else(|| "choose a username to create an account".to_owned())?;
    let account_id = UserId::new().raw();
    let mut history_key = [0_u8; 32];
    getrandom::fill(&mut history_key).map_err(|_| "secure randomness is unavailable".to_owned())?;
    let recovery_codes = generate_recovery_codes()?;
    let password_wrapped = wrap_account_history_key(&history_key, &input.password, account_id)
        .map_err(|error| error.to_string())?;
    let recovery_vaults = recovery_key_vault_entries(account_id, &history_key, &recovery_codes)?;
    CredentialVault::open(account_id)?.save_history_key(&history_key)?;
    let account_device = select_account_device(&state, account_id)?;
    let session = state
        .remote
        .register_password_provisioned(
            &input.email,
            username,
            &input.password,
            &account_device,
            account_id,
            &wrapped_account_key_view(&password_wrapped),
            &recovery_vaults,
        )
        .await
        .map_err(|error| error.to_string())?;
    if session_account_id(&session)? != account_id {
        state.remote.clear_session();
        return Err("the server created an account with an unexpected identity".to_owned());
    }
    let auth = finish_authentication(&app, &state, session, false).await?;
    Ok(PasswordAuthenticationView {
        auth,
        recovery_codes,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn login_with_password(
    input: PasswordAuthInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<PasswordAuthenticationView, String> {
    let initial_session = state
        .remote
        .login_password(&input.email, &input.password, &state.device_id)
        .await
        .map_err(|error| error.to_string())?;
    let session = bind_password_session_to_account_device(
        &state,
        &input.email,
        &input.password,
        initial_session,
    )
    .await?;
    let history_key = establish_account_history_key(&state, &session, &input.password).await?;
    let recovery_codes = if state
        .remote
        .recovery_key_vaults_ready()
        .await
        .map_err(|error| error.to_string())?
    {
        Vec::new()
    } else {
        let codes = state
            .remote
            .regenerate_recovery_codes(&input.password)
            .await
            .map_err(|error| error.to_string())?;
        upload_recovery_key_vaults(
            &state,
            session_account_id(&session)?,
            &history_key,
            &input.password,
            &codes,
        )
        .await?;
        codes
    };
    let activate_immediately = recovery_codes.is_empty();
    let auth = finish_authentication(&app, &state, session, activate_immediately).await?;
    Ok(PasswordAuthenticationView {
        auth,
        recovery_codes,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn change_password(
    input: ChangePasswordInput,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    let account_id = state
        .active_account_id
        .ok_or_else(|| "there is no active account".to_owned())?;
    let vault = state
        .vault
        .as_ref()
        .ok_or_else(|| "the account credential vault is unavailable".to_owned())?;
    let key = vault.load_history_key()?.ok_or_else(|| {
        "private-history recovery must be restored before changing the password".to_owned()
    })?;
    let wrapped = wrap_account_history_key(&key, &input.new_password, account_id)
        .map_err(|error| error.to_string())?;
    state
        .remote
        .change_password(
            &input.current_password,
            &input.new_password,
            &wrapped_account_key_view(&wrapped),
        )
        .await
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn recover_password(
    input: RecoverPasswordInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<PasswordAuthenticationView, String> {
    let preparation = state
        .remote
        .prepare_password_recovery(&input.email, &input.recovery_code)
        .await
        .map_err(|error| error.to_string())?;
    let account_id = preparation
        .account_id
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "the recovery account id is invalid".to_owned())?;
    let vault = CredentialVault::open(account_id)?;
    let history_key = if let Some(wrapped) = preparation.recovery_wrapped_key.as_ref() {
        open_account_history_key_with_recovery_code(
            &wrapped_account_key_material(wrapped)?,
            &input.recovery_code,
            account_id,
        )
        .map_err(|_| "the private-history key could not be unlocked by this recovery code")?
    } else if let Some(key) = vault.load_history_key()? {
        key
    } else {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| "secure randomness is unavailable".to_owned())?;
        key
    };
    vault.save_history_key(&history_key)?;
    let recovery_codes = generate_recovery_codes()?;
    let password_wrapped = wrap_account_history_key(&history_key, &input.new_password, account_id)
        .map_err(|error| error.to_string())?;
    let recovery_vaults = recovery_key_vault_entries(account_id, &history_key, &recovery_codes)?;
    let account_device = select_account_device(&state, account_id)?;
    let session = state
        .remote
        .recover_password_provisioned(
            &input.email,
            &input.recovery_code,
            &input.new_password,
            &account_device,
            account_id,
            &wrapped_account_key_view(&password_wrapped),
            &recovery_vaults,
        )
        .await
        .map_err(|error| error.to_string())?;
    if session_account_id(&session)? != account_id {
        state.remote.clear_session();
        return Err("the recovered account identity did not match the prepared account".to_owned());
    }
    let auth = finish_authentication(&app, &state, session, false).await?;
    Ok(PasswordAuthenticationView {
        auth,
        recovery_codes,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn regenerate_recovery_codes(
    input: ConfirmPasswordInput,
    state: State<'_, DesktopCore>,
) -> Result<Vec<String>, String> {
    let recovery_codes = state
        .remote
        .regenerate_recovery_codes(&input.current_password)
        .await
        .map_err(|error| error.to_string())?;
    let account_id = state
        .active_account_id
        .ok_or_else(|| "sign in before replacing recovery codes".to_owned())?;
    let key = state
        .vault
        .as_ref()
        .ok_or_else(|| "the account credential vault is unavailable".to_owned())?
        .load_history_key()?
        .ok_or_else(|| "the private-history recovery key is unavailable".to_owned())?;
    upload_recovery_key_vaults(
        &state,
        account_id,
        &key,
        &input.current_password,
        &recovery_codes,
    )
    .await?;
    Ok(recovery_codes)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn account_auth_methods(state: State<'_, DesktopCore>) -> Result<AccountAuthMethods, String> {
    state
        .remote
        .account_auth_methods()
        .await
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn link_apple(
    input: ConfirmPasswordInput,
    state: State<'_, DesktopCore>,
) -> Result<AccountAuthMethods, String> {
    let login = state
        .remote
        .start_apple_link(&input.current_password)
        .await
        .map_err(|error| error.to_string())?;
    tauri_plugin_opener::open_url(&login.authorization_url, None::<&str>)
        .map_err(|error| format!("the Apple connection page could not be opened: {error}"))?;
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(u64::from(login.expires_in_seconds));
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("Connecting Apple timed out. Please try again.".to_owned());
        }
        match state.remote.poll_apple_link(&login.state).await {
            Ok(true) => return account_auth_methods(state).await,
            Ok(false) => tokio::time::sleep(Duration::from_millis(900)).await,
            Err(error) => return Err(error.to_string()),
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn unlink_apple(
    input: ConfirmPasswordInput,
    state: State<'_, DesktopCore>,
) -> Result<AccountAuthMethods, String> {
    state
        .remote
        .unlink_apple(&input.current_password)
        .await
        .map_err(|error| error.to_string())?;
    account_auth_methods(state).await
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn verify_login_code(
    input: VerifyCodeInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<AuthView, String> {
    let session = state
        .remote
        .verify_email_code(&input.challenge_id, &input.code, &state.device_id)
        .await
        .map_err(|error| error.to_string())?;
    finish_authentication(&app, &state, session, true).await
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn activate_authenticated_account(
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    let session = state
        .remote
        .session()
        .ok_or_else(|| "there is no authenticated account to activate".to_owned())?;
    let account_id = session_account_id(&session)?;
    write_active_account(&state.data_directory, account_id)?;
    persist_session_bundle(&state, &session)?;
    app.restart();
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn logout_session(app: AppHandle, state: State<'_, DesktopCore>) -> Result<AuthView, String> {
    let logout_result = state.remote.logout().await;
    state.remote.clear_session();
    clear_persisted_session(&state)?;
    set_connection_state(&app, &state, ConnectionState::Offline);
    if let Err(error) = logout_result {
        tracing::debug!(%error, "server logout could not be confirmed; local credentials were removed");
    }
    clear_active_account(&state.data_directory)?;
    app.restart()
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn account_deletion_status(
    state: State<'_, DesktopCore>,
) -> Result<AccountDeletionStatusView, String> {
    state
        .remote
        .account_deletion_status()
        .await
        .map(|status| AccountDeletionStatusView {
            deletion: status.deletion.map(Into::into),
            owned_servers: status.owned_servers.into_iter().map(Into::into).collect(),
        })
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn export_account_data(
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<String, String> {
    let export = state
        .remote
        .export_account_data()
        .await
        .map_err(|error| error.to_string())?;
    let directory = app
        .path()
        .download_dir()
        .map_err(|error| format!("the Downloads folder is unavailable: {error}"))?;
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("the Downloads folder could not be created: {error}"))?;
    let filename = format!(
        "ExoLink-data-export-{}-{}.json",
        Utc::now().format("%Y-%m-%d-%H%M%S"),
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let path = directory.join(filename);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("the export file could not be created: {error}"))?;
    serde_json::to_writer_pretty(&mut file, &export)
        .map_err(|error| format!("the account export could not be encoded: {error}"))?;
    std::io::Write::write_all(&mut file, b"\n")
        .map_err(|error| format!("the account export could not be completed: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("the account export could not be saved safely: {error}"))?;
    Ok(path.to_string_lossy().into_owned())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn schedule_account_deletion(
    input: DeleteAccountInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<AccountDeletionView, String> {
    if !account_delete_confirmed(&input.confirmation) {
        return Err(format!(
            "Type {ACCOUNT_DELETE_CONFIRMATION} exactly to schedule deletion."
        ));
    }
    let status = state
        .remote
        .schedule_account_deletion()
        .await
        .map_err(|error| error.to_string())?;
    let _deletion = status
        .deletion
        .map(AccountDeletionView::from)
        .ok_or_else(|| "the server did not return the deletion schedule".to_owned())?;
    state.remote.clear_session();
    if let Err(error) = clear_persisted_session(&state) {
        tracing::warn!(
            %error,
            "account deletion is scheduled but the already-revoked local credential could not be removed"
        );
    }
    set_connection_state(&app, &state, ConnectionState::Offline);
    clear_active_account(&state.data_directory)?;
    app.restart()
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn cancel_account_deletion(
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .cancel_account_deletion()
        .await
        .map_err(|error| error.to_string())?;
    state.remote.refresh_session().await.map_err(|error| {
        format!("deletion was cancelled, but the session could not refresh: {error}")
    })?;
    persist_session(&state)?;
    if synchronize_once(&state).await.is_ok() {
        emit_snapshot_or_warn(&app, &state, "account deletion cancellation");
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn login_with_apple(
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<AuthView, String> {
    let login = state
        .remote
        .start_apple_login(&state.device_id)
        .await
        .map_err(|error| error.to_string())?;
    tauri_plugin_opener::open_url(&login.authorization_url, None::<&str>)
        .map_err(|error| format!("the Apple sign-in page could not be opened: {error}"))?;
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(u64::from(login.expires_in_seconds));
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("Apple sign-in timed out. Please try again.".to_owned());
        }
        match state.remote.poll_apple_login(&login.state).await {
            Ok(Some(session)) => {
                return finish_authentication(&app, &state, session, true).await;
            }
            Ok(None) => tokio::time::sleep(Duration::from_millis(900)).await,
            Err(error) => return Err(error.to_string()),
        }
    }
}

async fn restore_session(core: &DesktopCore) -> Result<(), String> {
    let _guard = core.auth_restore.lock().await;
    if core.remote.session().is_some() {
        return Ok(());
    }
    let Some(vault) = &core.vault else {
        return Ok(());
    };
    let Some(refresh_token) = vault.load()? else {
        return Ok(());
    };
    match core.remote.refresh_with_token(&refresh_token).await {
        Ok(session) => {
            let account_id = session_account_id(&session)?;
            if core.active_account_id != Some(account_id) {
                core.remote.clear_session();
                // Do not erase a token written by another process while this
                // stale process was refreshing the previous account.
                vault.clear_if_matches(&refresh_token)?;
                return Err("the saved session belongs to another account".to_owned());
            }
            vault.save(&session.refresh_token)
        }
        Err(error) if error.is_permanent() => {
            // Refresh tokens rotate on every successful request. A duplicate
            // or stale process may receive RefreshReuse after the live process
            // has already saved the replacement token; compare before clearing
            // so that response cannot log the user out.
            vault.clear_if_matches(&refresh_token)?;
            core.remote.clear_session();
            Ok(())
        }
        Err(error) => {
            tracing::debug!(%error, "saved session could not be refreshed while offline");
            Ok(())
        }
    }
}

fn session_account_id(session: &exo_client::SessionBundle) -> Result<u64, String> {
    session
        .user
        .id
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "the authenticated account id is invalid".to_owned())
}

fn wrapped_account_key_view(material: &WrappedAccountKeyMaterial) -> WrappedAccountKey {
    WrappedAccountKey {
        version: 1,
        salt: URL_SAFE_NO_PAD.encode(material.salt),
        nonce: URL_SAFE_NO_PAD.encode(material.nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(&material.ciphertext),
    }
}

fn wrapped_account_key_material(
    wrapped: &WrappedAccountKey,
) -> Result<WrappedAccountKeyMaterial, String> {
    if wrapped.version != 1 {
        return Err("the account history key uses an unsupported version".to_owned());
    }
    Ok(WrappedAccountKeyMaterial {
        salt: URL_SAFE_NO_PAD
            .decode(&wrapped.salt)
            .map_err(|_| "the account history key salt is invalid".to_owned())?
            .try_into()
            .map_err(|_| "the account history key salt has the wrong size".to_owned())?,
        nonce: URL_SAFE_NO_PAD
            .decode(&wrapped.nonce)
            .map_err(|_| "the account history key nonce is invalid".to_owned())?
            .try_into()
            .map_err(|_| "the account history key nonce has the wrong size".to_owned())?,
        ciphertext: URL_SAFE_NO_PAD
            .decode(&wrapped.ciphertext)
            .map_err(|_| "the account history key ciphertext is invalid".to_owned())?,
    })
}

async fn establish_account_history_key(
    core: &DesktopCore,
    session: &exo_client::SessionBundle,
    password: &str,
) -> Result<[u8; 32], String> {
    let account_id = session_account_id(session)?;
    let vault = CredentialVault::open(account_id)?;
    let local_key = vault.load_history_key()?;
    let remote_key = core
        .remote
        .account_key_vault()
        .await
        .map_err(|error| error.to_string())?;
    let key = match (local_key, remote_key) {
        (Some(local), Some(wrapped)) => {
            match open_account_history_key(
                &wrapped_account_key_material(&wrapped)?,
                password,
                account_id,
            ) {
                Ok(remote) if remote == local => local,
                Ok(_) => {
                    return Err(
                        "the server and this device disagree about the private-history key"
                            .to_owned(),
                    );
                }
                Err(_) => {
                    let rewrapped = wrap_account_history_key(&local, password, account_id)
                        .map_err(|error| error.to_string())?;
                    core.remote
                        .set_account_key_vault(password, &wrapped_account_key_view(&rewrapped))
                        .await
                        .map_err(|error| error.to_string())?;
                    local
                }
            }
        }
        (Some(local), None) => {
            let wrapped = wrap_account_history_key(&local, password, account_id)
                .map_err(|error| error.to_string())?;
            core.remote
                .set_account_key_vault(password, &wrapped_account_key_view(&wrapped))
                .await
                .map_err(|error| error.to_string())?;
            local
        }
        (None, Some(wrapped)) => open_account_history_key(
            &wrapped_account_key_material(&wrapped)?,
            password,
            account_id,
        )
        .map_err(|_| {
            "the private-history key could not be unlocked with this password".to_owned()
        })?,
        (None, None) => {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key).map_err(|_| "secure randomness is unavailable".to_owned())?;
            let wrapped = wrap_account_history_key(&key, password, account_id)
                .map_err(|error| error.to_string())?;
            core.remote
                .set_account_key_vault(password, &wrapped_account_key_view(&wrapped))
                .await
                .map_err(|error| error.to_string())?;
            key
        }
    };
    vault.save_history_key(&key)?;
    Ok(key)
}

async fn upload_recovery_key_vaults(
    core: &DesktopCore,
    account_id: u64,
    history_key: &[u8; 32],
    current_password: &str,
    recovery_codes: &[String],
) -> Result<(), String> {
    let entries = recovery_key_vault_entries(account_id, history_key, recovery_codes)?;
    core.remote
        .set_recovery_key_vaults(current_password, &entries)
        .await
        .map_err(|error| error.to_string())
}

fn recovery_key_vault_entries(
    account_id: u64,
    history_key: &[u8; 32],
    recovery_codes: &[String],
) -> Result<Vec<RecoveryKeyVaultEntry>, String> {
    if recovery_codes.len() != 8 {
        return Err("the server returned an incomplete recovery-code set".to_owned());
    }
    recovery_codes
        .iter()
        .map(|recovery_code| {
            let wrapped =
                wrap_account_history_key_with_recovery_code(history_key, recovery_code, account_id)
                    .map_err(|error| error.to_string())?;
            Ok(RecoveryKeyVaultEntry {
                recovery_code: recovery_code.clone(),
                wrapped_key: wrapped_account_key_view(&wrapped),
            })
        })
        .collect()
}

fn generate_recovery_codes() -> Result<Vec<String>, String> {
    (0..8)
        .map(|_| {
            let mut bytes = [0_u8; 16];
            getrandom::fill(&mut bytes)
                .map_err(|_| "secure randomness is unavailable".to_owned())?;
            Ok(format!("exo_rc_{}", URL_SAFE_NO_PAD.encode(bytes)))
        })
        .collect()
}

fn persist_session_bundle(
    core: &DesktopCore,
    session: &exo_client::SessionBundle,
) -> Result<(), String> {
    let account_id = session_account_id(session)?;
    if let (Some(active_id), Some(vault)) = (core.active_account_id, &core.vault)
        && active_id == account_id
    {
        return vault.save(&session.refresh_token);
    }
    CredentialVault::open(account_id)?.save(&session.refresh_token)
}

fn persist_session(core: &DesktopCore) -> Result<(), String> {
    if let Some(session) = core.remote.session() {
        persist_session_bundle(core, &session)?;
    }
    Ok(())
}

fn clear_persisted_session(core: &DesktopCore) -> Result<(), String> {
    if let Some(vault) = &core.vault {
        vault.clear()?;
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn bootstrap_view_model(state: State<'_, DesktopCore>) -> Result<BootstrapViewModel, String> {
    build_view_model(&state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn retry_local_cache(app: AppHandle, state: State<'_, DesktopCore>) -> Result<(), String> {
    state
        .cache_recovery
        .as_ref()
        .ok_or_else(|| "the local cache does not require recovery".to_owned())?;
    app.restart()
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn open_local_cache_folder(state: State<'_, DesktopCore>) -> Result<(), String> {
    let recovery = state
        .cache_recovery
        .as_ref()
        .ok_or_else(|| "the local cache does not require recovery".to_owned())?;
    let parent = recovery
        .cache_path
        .parent()
        .ok_or_else(|| "the local cache folder is unavailable".to_owned())?;
    tauri_plugin_opener::open_path(parent, None::<&str>)
        .map_err(|error| format!("the local cache folder could not be opened: {error}"))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn reset_local_cache(
    input: ResetLocalCacheInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    if !cache_reset_confirmed(&input.confirmation) {
        return Err(format!(
            "type {CACHE_RESET_CONFIRMATION} exactly before resetting the local cache"
        ));
    }
    let recovery = state
        .cache_recovery
        .as_ref()
        .ok_or_else(|| "the local cache does not require recovery".to_owned())?;
    if !recovery.can_reset {
        return Err(
            "starting fresh cannot fix this failure; reinstall or restore the secure key vault"
                .to_owned(),
        );
    }
    let vault = state
        .vault
        .as_ref()
        .ok_or_else(|| "the operating-system credential vault is unavailable".to_owned())?;
    let parent = recovery
        .cache_path
        .parent()
        .ok_or_else(|| "the local cache folder is unavailable".to_owned())?;
    let preserved = preserve_cache_artifacts(
        &recovery.cache_path,
        &parent.join("cache-recovery"),
        recovery.kind.code(),
        &recovery.detail,
    )?;
    if let Err(error) = vault.clear_cache_key() {
        let rollback = restore_cache_artifacts(&recovery.cache_path, &preserved);
        return Err(match rollback {
            Ok(()) => error,
            Err(rollback_error) => format!(
                "{error}; the cache files are preserved at {} because rollback also failed: {rollback_error}",
                preserved.display()
            ),
        });
    }
    app.restart()
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn request_friend(
    input: FriendHandleInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<BootstrapViewModel, String> {
    state
        .remote
        .request_friend(input.handle.trim())
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await?;
    build_view_model(&state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn accept_friend(
    input: RelationshipTargetInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<BootstrapViewModel, String> {
    state
        .remote
        .accept_friend(parse_user_id(&input.user_id)?)
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await?;
    build_view_model(&state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn remove_relationship(
    input: RelationshipTargetInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<BootstrapViewModel, String> {
    state
        .remote
        .delete_relationship(parse_user_id(&input.user_id)?)
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await?;
    build_view_model(&state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn block_user(
    input: RelationshipTargetInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<BootstrapViewModel, String> {
    state
        .remote
        .block_user(parse_user_id(&input.user_id)?)
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await?;
    build_view_model(&state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn open_direct_message(
    input: RelationshipTargetInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<BootstrapViewModel, String> {
    let channel = state
        .remote
        .open_direct_channel(parse_user_id(&input.user_id)?)
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)?;
    synchronize_once(&state)
        .await
        .map_err(|error| error.to_string())?;
    state
        .store
        .set_active_context(0, channel.id.raw(), None)
        .map_err(|error| error.to_string())?;
    emit_snapshot(&app, &state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn acknowledge_read_state(
    input: ReadStateCommandInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    let channel_id = parse_id(&input.channel_id, "channel")?;
    let message_id = MessageId::from_raw(parse_id(&input.message_id, "message")?)
        .map_err(|_| "message id is invalid".to_owned())?;
    let read_state = state
        .remote
        .acknowledge_read_state(channel_id, message_id)
        .await
        .map_err(|error| error.to_string())?;
    state
        .store
        .put_read_state(&read_state)
        .map_err(|error| error.to_string())?;
    if let Some(direct_unread) =
        direct_unread_delta(&state, channel_id).map_err(|error| error.to_string())?
    {
        emit_delta(&app, &state, CoreDeltaChange::ReadState { direct_unread });
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn start_typing(
    input: ChannelTargetInput,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .start_typing(parse_id(&input.channel_id, "channel")?)
        .await
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn create_workspace(
    input: CreateWorkspaceInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<Workspace, String> {
    let guild = state
        .remote
        .create_guild(&CreateGuild {
            name: input.name,
            accent: Some(0x008B_7CFF),
        })
        .await
        .map_err(|error| error.to_string())?;
    synchronize_once(&state)
        .await
        .map_err(|error| error.to_string())?;
    let model = emit_snapshot(&app, &state).map_err(|error| error.to_string())?;
    model
        .workspaces
        .into_iter()
        .find(|workspace| workspace.id == guild.id.to_string())
        .ok_or_else(|| "created server was not present after synchronization".to_owned())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn create_workspace_invite(
    input: WorkspaceInviteInput,
    state: State<'_, DesktopCore>,
) -> Result<InviteView, String> {
    let invite = state
        .remote
        .create_invite(
            parse_id(&input.workspace_id, "server")?,
            &CreateInvite {
                expires_in_seconds: Some(86_400),
                max_uses: Some(50),
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)?;
    Ok(invite_view(&invite))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn preview_server_invite(
    input: InviteCodeInput,
    state: State<'_, DesktopCore>,
) -> Result<InvitePreviewView, String> {
    state
        .remote
        .preview_invite(input.code.trim())
        .await
        .map(|preview| invite_preview_view(&preview))
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn accept_server_invite(
    input: InviteCodeInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<Workspace, String> {
    let guild = state
        .remote
        .accept_invite(input.code.trim())
        .await
        .map_err(|error| error.to_string())?;
    synchronize_once(&state)
        .await
        .map_err(|error| error.to_string())?;
    let model = emit_snapshot(&app, &state).map_err(|error| error.to_string())?;
    model
        .workspaces
        .into_iter()
        .find(|workspace| workspace.id == guild.id.to_string())
        .ok_or_else(|| "joined server was not present after synchronization".to_owned())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn load_server_ownership(
    input: WorkspaceRolesInput,
    state: State<'_, DesktopCore>,
) -> Result<ServerOwnershipView, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let snapshot = state.store.snapshot().map_err(|error| error.to_string())?;
    let guild = snapshot
        .guilds
        .iter()
        .find(|guild| guild.id == guild_id && guild.origin_remote)
        .ok_or_else(|| "server was not found in the synchronized cache".to_owned())?;
    let members = state
        .remote
        .list_members(guild_id)
        .await
        .map_err(|error| error.to_string())?;
    Ok(ServerOwnershipView {
        workspace_id: guild.id.to_string(),
        owner_id: guild.owner_id.to_string(),
        name: guild.name.clone(),
        members: members
            .iter()
            .filter(|member| member.user.id.raw() != guild.owner_id)
            .map(server_ownership_member_view)
            .collect(),
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn transfer_server_ownership(
    input: TransferServerOwnershipInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<BootstrapViewModel, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let member_id = parse_id(&input.member_id, "member")?;
    state
        .remote
        .transfer_guild_ownership(guild_id, member_id)
        .await
        .map_err(|error| error.to_string())?;
    synchronize_once(&state)
        .await
        .map_err(|error| error.to_string())?;
    emit_snapshot(&app, &state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn delete_server(
    input: DeleteServerInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<BootstrapViewModel, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    state
        .remote
        .delete_guild(guild_id, &input.confirmation)
        .await
        .map_err(|error| error.to_string())?;
    synchronize_once(&state)
        .await
        .map_err(|error| error.to_string())?;
    emit_snapshot(&app, &state).map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn load_server_roles(
    input: WorkspaceRolesInput,
    state: State<'_, DesktopCore>,
) -> Result<RoleManagerView, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let (roles, members) = tokio::try_join!(
        state.remote.list_roles(guild_id),
        state.remote.list_members(guild_id)
    )
    .map_err(|error| error.to_string())?;
    persist_session(&state)?;
    Ok(role_manager_view(guild_id, &roles, &members))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn create_server_role(
    input: RoleMutationInput,
    state: State<'_, DesktopCore>,
) -> Result<RoleView, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let role = state
        .remote
        .create_role(
            guild_id,
            &CreateRole {
                name: input.name,
                color: Some(parse_color(&input.color)?),
                permissions: permissions_from_keys(&input.permission_keys)?
                    .bits()
                    .to_string(),
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)?;
    Ok(role_view(guild_id, &role))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn update_server_role(
    input: RoleMutationInput,
    state: State<'_, DesktopCore>,
) -> Result<RoleView, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let role_id = parse_id(
        input
            .role_id
            .as_deref()
            .ok_or_else(|| "role id is required".to_owned())?,
        "role",
    )?;
    let role = state
        .remote
        .update_role(
            guild_id,
            role_id,
            &UpdateRole {
                name: Some(input.name),
                color: Some(parse_color(&input.color)?),
                permissions: Some(
                    permissions_from_keys(&input.permission_keys)?
                        .bits()
                        .to_string(),
                ),
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)?;
    Ok(role_view(guild_id, &role))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn delete_server_role(
    input: RoleTargetInput,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .delete_role(
            parse_id(&input.workspace_id, "server")?,
            parse_id(&input.role_id, "role")?,
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn set_server_member_role(
    input: MemberRoleInput,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .set_member_role(
            parse_id(&input.workspace_id, "server")?,
            parse_id(&input.member_id, "member")?,
            parse_id(&input.role_id, "role")?,
            input.assigned,
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn load_server_channels(
    input: WorkspaceChannelsInput,
    state: State<'_, DesktopCore>,
) -> Result<ChannelManagerView, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let (channels, roles) = tokio::try_join!(
        state.remote.list_channels(guild_id),
        state.remote.list_roles(guild_id)
    )
    .map_err(|error| error.to_string())?;
    let members = match state.remote.list_members(guild_id).await {
        Ok(members) => members,
        Err(RemoteError::Status { status: 403, .. }) => Vec::new(),
        Err(error) => return Err(error.to_string()),
    };
    persist_session(&state)?;
    Ok(ChannelManagerView {
        channels: channels.iter().map(managed_channel_view).collect(),
        roles: roles.iter().map(|role| role_view(guild_id, role)).collect(),
        members: members.iter().map(role_member_view).collect(),
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn create_server_channel(
    input: ChannelMutationInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<ManagedChannelView, String> {
    let channel = state
        .remote
        .create_channel(
            parse_id(&input.workspace_id, "server")?,
            &CreateChannel {
                name: input.name,
                kind: parse_channel_kind(&input.kind)?,
                encrypted: input.encrypted,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await?;
    Ok(managed_channel_view(&channel))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn create_voice_grant(
    input: VoiceGrantInput,
    state: State<'_, DesktopCore>,
) -> Result<serde_json::Value, String> {
    let channel_id = parse_id(&input.channel_id, "voice channel")?;
    let grant = state
        .remote
        .create_voice_grant(channel_id)
        .await
        .map_err(|error| error.to_string())?;
    let user_id = state
        .store
        .snapshot()
        .map_err(|error| error.to_string())?
        .current_user_id
        .ok_or_else(|| "the local profile is unavailable".to_owned())?;
    ensure_e2ee_identity(&state, user_id)
        .await
        .map_err(|error| error.to_string())?;
    bootstrap_channel_mls(&state, channel_id)
        .await
        .map_err(|error| error.to_string())?;
    let key = state
        .mls
        .lock()
        .map_err(|_| "the local MLS state lock is unavailable".to_owned())?
        .as_ref()
        .ok_or_else(|| "the local MLS identity is unavailable".to_owned())?
        .export_secret(
            channel_id,
            "EXOCORD_SFRAME_V1",
            &channel_id.to_be_bytes(),
            32,
        )
        .map_err(|error| error.to_string())?;
    let mut value = serde_json::to_value(grant).map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "the voice grant is invalid".to_owned())?;
    object.insert("endToEndEncrypted".into(), serde_json::Value::Bool(true));
    object.insert(
        "e2eeKey".into(),
        serde_json::Value::String(URL_SAFE_NO_PAD.encode(key)),
    );
    Ok(value)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn update_server_channel(
    input: ChannelMutationInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<ManagedChannelView, String> {
    let channel = state
        .remote
        .update_channel(
            parse_id(
                input
                    .channel_id
                    .as_deref()
                    .ok_or_else(|| "channel id is required".to_owned())?,
                "channel",
            )?,
            &UpdateChannel {
                name: Some(input.name),
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await?;
    Ok(managed_channel_view(&channel))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn delete_server_channel(
    input: ChannelTargetInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .delete_channel(parse_id(&input.channel_id, "channel")?)
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn load_channel_overwrites(
    input: ChannelTargetInput,
    state: State<'_, DesktopCore>,
) -> Result<Vec<ChannelOverwriteView>, String> {
    let overwrites = state
        .remote
        .list_channel_overwrites(parse_id(&input.channel_id, "channel")?)
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)?;
    Ok(overwrites.iter().map(channel_overwrite_view).collect())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn set_server_channel_overwrite(
    input: ChannelOverwriteInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<ChannelOverwriteView, String> {
    let overwrite = state
        .remote
        .set_channel_overwrite(
            parse_id(&input.channel_id, "channel")?,
            parse_overwrite_kind(&input.target_kind)?,
            parse_id(&input.target_id, "overwrite target")?,
            &UpdateChannelOverwrite {
                allow: permissions_from_keys(&input.allow_keys)?.bits().to_string(),
                deny: permissions_from_keys(&input.deny_keys)?.bits().to_string(),
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await?;
    Ok(channel_overwrite_view(&overwrite))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn delete_server_channel_overwrite(
    input: ChannelOverwriteTargetInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .delete_channel_overwrite(
            parse_id(&input.channel_id, "channel")?,
            parse_overwrite_kind(&input.target_kind)?,
            parse_id(&input.target_id, "overwrite target")?,
        )
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn load_server_moderation(
    input: WorkspaceRolesInput,
    state: State<'_, DesktopCore>,
) -> Result<ModerationManagerView, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let members = match state.remote.list_members(guild_id).await {
        Ok(members) => members,
        Err(RemoteError::Status { status: 403, .. }) => Vec::new(),
        Err(error) => return Err(error.to_string()),
    };
    let bans = match state.remote.list_bans(guild_id).await {
        Ok(bans) => bans,
        Err(RemoteError::Status { status: 403, .. }) => Vec::new(),
        Err(error) => return Err(error.to_string()),
    };
    let rules = match state.remote.list_automod_rules(guild_id).await {
        Ok(rules) => rules,
        Err(RemoteError::Status { status: 403, .. }) => Vec::new(),
        Err(error) => return Err(error.to_string()),
    };
    let audit = match state.remote.list_audit_log(guild_id, None, 100).await {
        Ok(audit) => audit,
        Err(RemoteError::Status { status: 403, .. }) => Vec::new(),
        Err(error) => return Err(error.to_string()),
    };
    persist_session(&state)?;
    Ok(ModerationManagerView {
        members: members.iter().map(moderation_member_view).collect(),
        bans: bans.iter().map(ban_view).collect(),
        rules: rules.iter().map(automod_rule_view).collect(),
        audit: audit.iter().map(audit_log_view).collect(),
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn create_automod_rule(
    input: AutomodRuleMutationInput,
    state: State<'_, DesktopCore>,
) -> Result<AutomodRuleView, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let trigger = automod_trigger_from_input(&input)?;
    let action = parse_automod_action(&input.action)?;
    let rule = state
        .remote
        .create_automod_rule(
            guild_id,
            &CreateAutomodRule {
                name: input.name,
                enabled: input.enabled,
                trigger,
                action,
                duration_seconds: input.duration_seconds,
                explanation: input.explanation,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)?;
    Ok(automod_rule_view(&rule))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn update_automod_rule(
    input: AutomodRuleMutationInput,
    state: State<'_, DesktopCore>,
) -> Result<AutomodRuleView, String> {
    let guild_id = parse_id(&input.workspace_id, "server")?;
    let rule_id = parse_id(
        input
            .rule_id
            .as_deref()
            .ok_or_else(|| "automod rule id is required".to_owned())?,
        "automod rule",
    )?;
    let trigger = automod_trigger_from_input(&input)?;
    let action = parse_automod_action(&input.action)?;
    let rule = state
        .remote
        .update_automod_rule(
            guild_id,
            rule_id,
            &UpdateAutomodRule {
                name: Some(input.name),
                enabled: Some(input.enabled),
                trigger: Some(trigger),
                action: Some(action),
                duration_seconds: Some(input.duration_seconds),
                explanation: Some(input.explanation),
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)?;
    Ok(automod_rule_view(&rule))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn delete_automod_rule(
    input: AutomodRuleTargetInput,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .delete_automod_rule(
            parse_id(&input.workspace_id, "server")?,
            parse_id(&input.rule_id, "automod rule")?,
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_session(&state)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn timeout_server_member(
    input: MemberModerationInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .timeout_member(
            parse_id(&input.workspace_id, "server")?,
            parse_id(&input.member_id, "member")?,
            &ModerateMember {
                timeout_seconds: input.duration_seconds,
                reason: input.reason,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn kick_server_member(
    input: MemberModerationInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .kick_member(
            parse_id(&input.workspace_id, "server")?,
            parse_id(&input.member_id, "member")?,
            &ModerateMember {
                timeout_seconds: None,
                reason: input.reason,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn ban_server_member(
    input: MemberModerationInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .ban_member(
            parse_id(&input.workspace_id, "server")?,
            parse_id(&input.member_id, "member")?,
            &BanMember {
                reason: input.reason,
                duration_seconds: input.duration_seconds,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn unban_server_member(
    input: MemberModerationInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .remote
        .unban_member(
            parse_id(&input.workspace_id, "server")?,
            parse_id(&input.member_id, "member")?,
            &ModerateMember {
                timeout_seconds: None,
                reason: input.reason,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    refresh_desktop_snapshot(&app, &state).await
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn prepare_attachment(
    input: PrepareAttachmentInput,
    state: State<'_, DesktopCore>,
) -> Result<AttachmentUpload, String> {
    state
        .remote
        .reserve_attachment(
            parse_id(&input.channel_id, "channel")?,
            ReserveAttachment {
                filename: input.filename,
                file_size: input.file_size,
                content_type: input.content_type,
                sha256: input.sha256,
            },
        )
        .await
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn channel_is_end_to_end_encrypted(
    input: ChannelTargetInput,
    state: State<'_, DesktopCore>,
) -> Result<bool, String> {
    state
        .store
        .is_encrypted_channel(parse_id(&input.channel_id, "channel")?)
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn complete_attachment(
    input: AttachmentTargetInput,
    state: State<'_, DesktopCore>,
) -> Result<MessageAttachment, String> {
    let attachment_id = input
        .attachment_id
        .parse::<AttachmentId>()
        .map_err(|_| "attachment id is invalid".to_owned())?;
    state
        .remote
        .complete_attachment(attachment_id)
        .await
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn report_message(
    input: ReportMessageInput,
    state: State<'_, DesktopCore>,
) -> Result<ReportReceipt, String> {
    let message_id = input
        .message_id
        .parse::<MessageId>()
        .map_err(|_| "message id is invalid".to_owned())?;
    let cached = state
        .store
        .snapshot()
        .map_err(|error| error.to_string())?
        .messages
        .into_iter()
        .find(|message| message.id == message_id.raw())
        .ok_or_else(|| "that message is not available on this device".to_owned())?;
    let encrypted = state
        .store
        .is_encrypted_channel(cached.channel_id)
        .map_err(|error| error.to_string())?;
    let franking = if encrypted {
        let sealed = state
            .store
            .load_franking_opening(message_id.raw())
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                "This device does not hold the verified opening for that encrypted message."
                    .to_owned()
            })?;
        let key = state
            .mls_device_key
            .ok_or_else(|| "the operating-system MLS device key is unavailable".to_owned())?;
        let opening = open_franking_opening(&sealed, &key, message_id.raw())
            .map_err(|error| error.to_string())?;
        Some(MessageFrankingEvidence {
            content: opening.content,
            attachment_sha256: opening
                .attachment_sha256
                .into_iter()
                .map(hex::encode)
                .collect(),
            franking_key: URL_SAFE_NO_PAD.encode(opening.franking_key),
            franking_tag: URL_SAFE_NO_PAD.encode(opening.franking_tag),
        })
    } else {
        None
    };
    state
        .remote
        .create_report(&exo_domain::CreateMessageReport {
            message_id,
            category: parse_report_category(&input.category)?,
            detail: input.detail,
            franking,
        })
        .await
        .map_err(|error| error.to_string())
}

fn parse_report_category(value: &str) -> Result<ReportCategory, String> {
    match value {
        "spam" => Ok(ReportCategory::Spam),
        "harassment" => Ok(ReportCategory::Harassment),
        "threats_violence" => Ok(ReportCategory::ThreatsViolence),
        "sexual_content_involving_minors" => Ok(ReportCategory::SexualContentInvolvingMinors),
        "self_harm" => Ok(ReportCategory::SelfHarm),
        "illegal_content" => Ok(ReportCategory::IllegalContent),
        "impersonation" => Ok(ReportCategory::Impersonation),
        "other" => Ok(ReportCategory::Other),
        _ => Err("report category is invalid".to_owned()),
    }
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn search_messages(
    input: SearchInput,
    state: State<'_, DesktopCore>,
) -> Result<SearchView, String> {
    let workspace_id = parse_id(&input.workspace_id, "workspace")?;
    let query = input.query.trim();
    if query.is_empty() || query.chars().count() > 256 {
        return Err("search must contain between 1 and 256 characters".into());
    }
    if workspace_id == 0 {
        return search_direct_message_history(query, state.inner());
    }

    let snapshot = state.store.snapshot().map_err(|error| error.to_string())?;
    let current_user_id = snapshot
        .current_user_id
        .ok_or_else(|| "the local profile is unavailable".to_owned())?;
    let server = state
        .remote
        .search_messages(workspace_id, query, 40)
        .await
        .map_err(|error| error.to_string())?;
    let local = state
        .store
        .search_encrypted_messages(workspace_id, query, 40)
        .map_err(|error| error.to_string())?;
    let workspace_name = snapshot
        .guilds
        .iter()
        .find(|guild| guild.id == workspace_id)
        .map_or_else(|| "Server".to_owned(), |guild| guild.name.clone());
    let mut indexed_hits = Vec::new();
    for hit in server.hits {
        let channel_id = hit.message.channel_id.raw();
        indexed_hits.push((
            hit.message.id.raw(),
            SearchHitView {
                message: domain_chat_message(&hit.message, current_user_id),
                workspace_id: workspace_id.to_string(),
                workspace_name: workspace_name.clone(),
                channel_id: channel_id.to_string(),
                channel_name: hit.channel_name,
                local_only: false,
            },
        ));
    }
    for message in &local {
        let channel_name = snapshot
            .channels
            .iter()
            .find(|channel| channel.id == message.channel_id)
            .map_or_else(|| "encrypted".to_owned(), |channel| channel.name.clone());
        indexed_hits.push((
            message.id,
            SearchHitView {
                message: chat_message(message, current_user_id),
                workspace_id: workspace_id.to_string(),
                workspace_name: workspace_name.clone(),
                channel_id: message.channel_id.to_string(),
                channel_name,
                local_only: true,
            },
        ));
    }
    indexed_hits.sort_by_key(|(id, _)| std::cmp::Reverse(*id));
    indexed_hits.truncate(50);
    let encrypted_channel_count = u32::try_from(
        server
            .excluded_channels
            .iter()
            .filter(|channel| channel.reason == SearchExclusionReason::E2ee)
            .count(),
    )
    .unwrap_or(u32::MAX);
    let permission_excluded_count = u32::try_from(
        server
            .excluded_channels
            .iter()
            .filter(|channel| channel.reason == SearchExclusionReason::NoPermission)
            .count(),
    )
    .unwrap_or(u32::MAX);
    Ok(SearchView {
        total: server
            .total
            .saturating_add(u64::try_from(local.len()).unwrap_or(u64::MAX)),
        hits: indexed_hits.into_iter().map(|(_, hit)| hit).collect(),
        encrypted_channel_count,
        permission_excluded_count,
    })
}

fn search_direct_message_history(query: &str, state: &DesktopCore) -> Result<SearchView, String> {
    let snapshot = state.store.snapshot().map_err(|error| error.to_string())?;
    let current_user_id = snapshot
        .current_user_id
        .ok_or_else(|| "the local profile is unavailable".to_owned())?;
    let local = state
        .store
        .search_cached_messages(0, query, 50)
        .map_err(|error| error.to_string())?;
    let hits = local
        .iter()
        .map(|message| {
            let channel_name = snapshot
                .channels
                .iter()
                .find(|channel| channel.id == message.channel_id)
                .map_or_else(|| "conversation".to_owned(), |channel| channel.name.clone());
            SearchHitView {
                message: chat_message(message, current_user_id),
                workspace_id: "0".to_owned(),
                workspace_name: "Messages".to_owned(),
                channel_id: message.channel_id.to_string(),
                channel_name,
                local_only: true,
            }
        })
        .collect();
    Ok(SearchView {
        total: u64::try_from(local.len()).unwrap_or(u64::MAX),
        hits,
        encrypted_channel_count: 0,
        permission_excluded_count: 0,
    })
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn open_search_hit(
    input: OpenSearchHitInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    let workspace_id = parse_id(&input.workspace_id, "server")?;
    let channel_id = parse_id(&input.channel_id, "channel")?;
    let message_id = parse_id(&input.message_id, "message")?;
    if !input.local_only {
        let messages = state
            .remote
            .message_window(channel_id, message_id, 60)
            .await
            .map_err(|error| error.to_string())?;
        for message in &messages {
            state
                .store
                .upsert_remote_message(message)
                .map_err(|error| error.to_string())?;
        }
    }
    state
        .store
        .set_active_context(workspace_id, channel_id, None)
        .map_err(|error| error.to_string())?;
    emit_snapshot(&app, &state).map_err(|error| error.to_string())?;
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn send_message(
    input: SendMessageInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<ChatMessage, String> {
    let content = validate_message_with_attachments(&input.content, input.attachments.len())
        .map_err(|error| error.to_string())?;
    let channel_id = parse_id(&input.channel_id, "channel")?;
    let reply_to = input
        .reply_to_id
        .as_deref()
        .map(|value| parse_id(value, "reply message"))
        .transpose()?;
    if let Some(reply_to) = reply_to
        && state
            .store
            .message_by_id(reply_to)
            .map_err(|error| error.to_string())?
            .is_none_or(|message| message.channel_id != channel_id)
    {
        return Err("the replied-to message is not in this conversation".into());
    }
    let author_id = state
        .store
        .snapshot()
        .map_err(|error| error.to_string())?
        .current_user_id
        .ok_or_else(|| "the local profile is unavailable".to_owned())?;
    let temporary_id = state
        .ids
        .generate()
        .map_err(|error| error.to_string())?
        .raw();

    if !state
        .store
        .is_remote_channel(channel_id)
        .map_err(|error| error.to_string())?
    {
        if !input.attachments.is_empty() {
            return Err("attachments require a connected server channel".into());
        }
        let message = state
            .store
            .insert_local_message(
                temporary_id,
                channel_id,
                author_id,
                reply_to,
                &content,
                Utc::now(),
            )
            .map_err(|error| error.to_string())?;
        emit_snapshot(&app, &state).map_err(|error| error.to_string())?;
        return Ok(chat_message(&message, author_id));
    }

    let nonce = Uuid::now_v7().to_string();
    let pending = state
        .store
        .enqueue_message(
            temporary_id,
            &nonce,
            channel_id,
            author_id,
            reply_to,
            &content,
            &input.attachments,
            Utc::now(),
        )
        .map_err(|error| error.to_string())?;
    let core = state.inner().clone();
    tauri::async_runtime::spawn(async move {
        deliver_message(
            &app,
            &core,
            &nonce,
            0,
            channel_id,
            reply_to,
            &content,
            &input.attachments,
        )
        .await;
    });
    Ok(chat_message(&pending, author_id))
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
#[tauri::command]
async fn edit_message(
    input: EditMessageInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<ChatMessage, String> {
    let content =
        validate_message_with_attachments(&input.content, 0).map_err(|error| error.to_string())?;
    let channel_id = parse_id(&input.channel_id, "channel")?;
    let message_id = parse_id(&input.message_id, "message")?;
    let current_user_id = state
        .store
        .current_user_id()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the local profile is unavailable".to_owned())?;
    let cached = state
        .store
        .message_by_id(message_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "that message is no longer in the local conversation window".to_owned())?;
    if cached.channel_id != channel_id || cached.author_id != current_user_id {
        return Err("only the message author can edit it".into());
    }
    if cached.state != MessageState::Sent {
        return Err("wait for this message to finish sending before editing it".into());
    }
    if !state
        .store
        .is_remote_channel(channel_id)
        .map_err(|error| error.to_string())?
    {
        let edited = state
            .store
            .edit_local_message(message_id, current_user_id, &content)
            .map_err(|error| error.to_string())?;
        emit_delta(
            &app,
            &state,
            CoreDeltaChange::MessageUpsert {
                message: chat_message(&edited, current_user_id),
                direct_unread: None,
                notify: false,
            },
        );
        return Ok(chat_message(&edited, current_user_id));
    }

    let nonce = Uuid::now_v7().to_string();
    let encrypted = state
        .store
        .is_encrypted_channel(channel_id)
        .map_err(|error| error.to_string())?;
    let message = if encrypted {
        bootstrap_channel_mls(&state, channel_id)
            .await
            .map_err(|error| error.to_string())?;
        let encrypted_attachments = cached
            .attachments
            .iter()
            .map(encrypted_attachment)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        let encrypted_message = {
            let mut current = state
                .mls
                .lock()
                .map_err(|_| "the local MLS state lock is unavailable".to_owned())?;
            let client = current
                .as_mut()
                .ok_or_else(|| "the local MLS identity is unavailable".to_owned())?;
            let encrypted_message = client
                .encrypt_message_with_attachments(
                    &MessageContext {
                        channel_id,
                        author_id: current_user_id,
                        nonce: nonce.clone(),
                    },
                    &content,
                    &encrypted_attachments,
                )
                .map_err(|error| error.to_string())?;
            persist_mls_client(&state, client, 0).map_err(|error| error.to_string())?;
            encrypted_message
        };
        let mut opening = FrankingOpening {
            content: content.clone(),
            attachment_sha256: encrypted_message.attachment_sha256.clone(),
            franking_key: encrypted_message.franking_key,
            franking_tag: [0; 32],
        };
        let message = state
            .remote
            .update_encrypted_message(
                channel_id,
                message_id,
                URL_SAFE_NO_PAD.encode(encrypted_message.ciphertext),
                URL_SAFE_NO_PAD.encode(encrypted_message.commitment),
                &nonce,
            )
            .await
            .map_err(|error| error.to_string())?;
        let encryption = message
            .encryption
            .as_ref()
            .ok_or_else(|| "encrypted edit response omitted franking metadata".to_owned())?;
        opening.franking_tag = decode_e2ee_value(&encryption.franking_tag, "message-franking tag")
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "message-franking tag is not 32 bytes".to_owned())?;
        persist_franking_opening(&state, message_id, &opening)
            .map_err(|error| error.to_string())?;
        message
    } else {
        state
            .remote
            .update_message(channel_id, message_id, &content, &nonce)
            .await
            .map_err(|error| error.to_string())?
    };
    let edited = state
        .store
        .merge_remote_message_update(&message, encrypted.then_some(content.as_str()))
        .map_err(|error| error.to_string())?;
    emit_delta(
        &app,
        &state,
        CoreDeltaChange::MessageUpsert {
            message: chat_message(&edited, current_user_id),
            direct_unread: None,
            notify: false,
        },
    );
    Ok(chat_message(&edited, current_user_id))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn delete_message(
    input: MessageTargetInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    let channel_id = parse_id(&input.channel_id, "channel")?;
    let message_id = parse_id(&input.message_id, "message")?;
    let current_user_id = state
        .store
        .current_user_id()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the local profile is unavailable".to_owned())?;
    let message = state
        .store
        .message_by_id(message_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "that message is no longer in the local conversation window".to_owned())?;
    if message.channel_id != channel_id {
        return Err("that message is not in this conversation".into());
    }
    let remote = state
        .store
        .is_remote_channel(channel_id)
        .map_err(|error| error.to_string())?;
    if !remote && message.author_id != current_user_id {
        return Err("only the message author can delete a device-only message".into());
    }
    if remote {
        state
            .remote
            .delete_message(channel_id, message_id)
            .await
            .map_err(|error| error.to_string())?;
    }
    state
        .store
        .mark_message_deleted(message_id, channel_id)
        .map_err(|error| error.to_string())?;
    emit_delta(
        &app,
        &state,
        CoreDeltaChange::MessageDelete {
            message_id: message_id.to_string(),
            channel_id: channel_id.to_string(),
        },
    );
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn update_message_reaction(
    input: MessageReactionInput,
    app: AppHandle,
    state: State<'_, DesktopCore>,
) -> Result<ChatMessage, String> {
    let channel_id = parse_id(&input.channel_id, "channel")?;
    let message_id = parse_id(&input.message_id, "message")?;
    let current_user_id = state
        .store
        .current_user_id()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the local profile is unavailable".to_owned())?;
    let message = state
        .store
        .message_by_id(message_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "that message is no longer available".to_owned())?;
    if message.channel_id != channel_id {
        return Err("that message is not in this conversation".to_owned());
    }
    if message.state != MessageState::Sent {
        return Err("reactions are unavailable until the message is delivered".to_owned());
    }
    let emoji = input.emoji.trim().to_owned();
    if emoji.is_empty() {
        return Err("a reaction emoji is required".to_owned());
    }
    let event = if state
        .store
        .is_remote_channel(channel_id)
        .map_err(|error| error.to_string())?
    {
        state
            .remote
            .update_reaction(channel_id, message_id, &emoji, input.added)
            .await
            .map_err(|error| error.to_string())?
    } else {
        let message = state
            .store
            .message_by_id(message_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "that message is no longer available".to_owned())?;
        let current_count = message
            .reactions
            .iter()
            .find(|reaction| reaction.emoji == emoji)
            .map_or(0, |reaction| reaction.count);
        exo_domain::MessageReactionEvent {
            message_id: MessageId::from_raw(message_id)
                .map_err(|_| "the message id is invalid".to_owned())?,
            channel_id: exo_domain::ChannelId::from_raw(channel_id)
                .map_err(|_| "the channel id is invalid".to_owned())?,
            user_id: UserId::from_raw(current_user_id)
                .map_err(|_| "the user id is invalid".to_owned())?,
            emoji,
            count: if input.added {
                current_count.saturating_add(1)
            } else {
                current_count.saturating_sub(1)
            },
            added: input.added,
        }
    };
    let message = state
        .store
        .apply_reaction_event(&event, current_user_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "that message is no longer available".to_owned())?;
    emit_delta(
        &app,
        &state,
        CoreDeltaChange::MessageUpsert {
            message: chat_message(&message, current_user_id),
            direct_unread: None,
            notify: false,
        },
    );
    Ok(chat_message(&message, current_user_id))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn set_active_context(
    input: ActiveContextInput,
    state: State<'_, DesktopCore>,
) -> Result<(), String> {
    state
        .store
        .set_active_context(
            parse_id(&input.workspace, "server")?,
            if input.channel.is_empty() {
                0
            } else {
                parse_id(&input.channel, "channel")?
            },
            input
                .voice_room
                .as_deref()
                .map(|id| parse_id(id, "voice room"))
                .transpose()?,
        )
        .map_err(|error| error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
async fn retry_outbox(app: AppHandle, state: State<'_, DesktopCore>) -> Result<(), String> {
    let previous = state
        .connection
        .lock()
        .map_or(ConnectionState::Offline, |state| *state);
    set_connection_state(&app, &state, ConnectionState::CatchingUp);
    let result = async {
        state
            .store
            .requeue_failed_messages()
            .map_err(|error| error.to_string())?;
        flush_outbox(&app, &state).await;
        flush_private_history_outbox(&state).await;
        if state.private_history_retry.load(AtomicOrdering::Acquire) {
            retry_private_history_restore(&state).await;
        }
        emit_snapshot(&app, &state)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
    .await;
    set_connection_state(
        &app,
        &state,
        if matches!(
            previous,
            ConnectionState::Connected | ConnectionState::CatchingUp
        ) {
            ConnectionState::Connected
        } else {
            previous
        },
    );
    result
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn window_action(window: tauri::Window, action: &str) -> Result<(), String> {
    match action {
        "minimize" => window.minimize(),
        "toggle_maximize" => match window.is_maximized() {
            Ok(true) => window.unmaximize(),
            Ok(false) => window.maximize(),
            Err(error) => return Err(error.to_string()),
        },
        "close" => window.close(),
        _ => return Err("unknown window action".to_owned()),
    }
    .map_err(|error| error.to_string())
}

fn parse_id(value: &str, label: &str) -> Result<u64, String> {
    value.parse().map_err(|_| format!("{label} id is invalid"))
}

fn load_or_create_device_id(path: &std::path::Path) -> std::io::Result<String> {
    if let Ok(stored) = std::fs::read_to_string(path)
        && let Ok(device_id) = Uuid::parse_str(stored.trim())
    {
        let canonical = device_id.to_string();
        if stored != canonical {
            std::fs::write(path, &canonical)?;
        }
        return Ok(canonical);
    }
    let device_id = Uuid::now_v7().to_string();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &device_id)?;
    Ok(device_id)
}

fn parse_user_id(value: &str) -> Result<UserId, String> {
    UserId::from_raw(parse_id(value, "user")?).map_err(|_| "user id is invalid".to_owned())
}

fn parse_channel_kind(value: &str) -> Result<ChannelKind, String> {
    match value {
        "text" => Ok(ChannelKind::Text),
        "voice" => Ok(ChannelKind::Voice),
        _ => Err("channel kind must be text or voice".to_owned()),
    }
}

fn parse_overwrite_kind(value: &str) -> Result<OverwriteTargetKind, String> {
    match value {
        "role" => Ok(OverwriteTargetKind::Role),
        "member" => Ok(OverwriteTargetKind::Member),
        _ => Err("overwrite target kind must be role or member".to_owned()),
    }
}

fn parse_automod_action(value: &str) -> Result<AutomodAction, String> {
    match value {
        "flag" => Ok(AutomodAction::Flag),
        "block" => Ok(AutomodAction::Block),
        "timeout" => Ok(AutomodAction::Timeout),
        "kick" => Ok(AutomodAction::Kick),
        "ban" => Ok(AutomodAction::Ban),
        _ => Err("automod action is invalid".to_owned()),
    }
}

fn automod_trigger_from_input(input: &AutomodRuleMutationInput) -> Result<AutomodTrigger, String> {
    let terms = || {
        input
            .terms
            .iter()
            .map(|term| term.trim().to_owned())
            .filter(|term| !term.is_empty())
            .collect::<Vec<_>>()
    };
    match input.trigger_type.as_str() {
        "keyword" => Ok(AutomodTrigger::Keyword { terms: terms() }),
        "regex" => Ok(AutomodTrigger::Regex { patterns: terms() }),
        "invite_link" => Ok(AutomodTrigger::InviteLink),
        "mass_mention" => Ok(AutomodTrigger::MassMention {
            limit: input
                .mention_limit
                .ok_or_else(|| "mention limit is required".to_owned())?,
        }),
        "repeated_content" => Ok(AutomodTrigger::RepeatedContent {
            threshold: input
                .repeat_threshold
                .ok_or_else(|| "repeat threshold is required".to_owned())?,
            window_seconds: input
                .window_seconds
                .ok_or_else(|| "repeat window is required".to_owned())?,
        }),
        "new_account_link" => Ok(AutomodTrigger::NewAccountLink {
            max_account_age_days: input
                .max_account_age_days
                .ok_or_else(|| "account age is required".to_owned())?,
        }),
        "zalgo" => Ok(AutomodTrigger::Zalgo {
            combining_mark_limit: input
                .combining_mark_limit
                .ok_or_else(|| "combining mark limit is required".to_owned())?,
        }),
        _ => Err("automod trigger is invalid".to_owned()),
    }
}

async fn refresh_desktop_snapshot(app: &AppHandle, core: &DesktopCore) -> Result<(), String> {
    persist_session(core)?;
    synchronize_once(core)
        .await
        .map_err(|error| error.to_string())?;
    emit_snapshot(app, core)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn build_view_model(core: &DesktopCore) -> Result<BootstrapViewModel, exo_client::StoreError> {
    let snapshot = core.store.snapshot()?;
    let connection_state = core
        .connection
        .lock()
        .map_or(ConnectionState::Offline, |state| *state);
    let presences = core
        .presences
        .lock()
        .map_or_else(|_| HashMap::new(), |value| value.clone());
    let typing = core
        .typing
        .lock()
        .map_or_else(|_| HashMap::new(), |value| value.clone());
    Ok(view_model_from_snapshot(
        &snapshot,
        core.revision.load(AtomicOrdering::Acquire),
        connection_state,
        &presences,
        &typing,
        core.store.cipher_version(),
        core.cache_recovery.as_ref().map(CacheRecoveryState::view),
    ))
}

fn view_model_from_snapshot(
    snapshot: &CacheSnapshot,
    revision: u64,
    connection_state: ConnectionState,
    presences: &HashMap<u64, UserPresence>,
    typing: &HashMap<(u64, u64), TypingEvent>,
    cipher_version: Option<&str>,
    cache_recovery: Option<CacheRecoveryView>,
) -> BootstrapViewModel {
    let current_user_id = snapshot.current_user_id.unwrap_or_default();
    let members = snapshot
        .users
        .iter()
        .map(|user| member(user, current_user_id, connection_state, presences))
        .collect::<Vec<_>>();
    let channels_by_guild = snapshot.channels.iter().fold(
        HashMap::<u64, Vec<&CachedChannel>>::new(),
        |mut groups, channel| {
            groups.entry(channel.guild_id).or_default().push(channel);
            groups
        },
    );
    let mut workspaces = snapshot
        .guilds
        .iter()
        .map(|guild| {
            workspace(
                guild,
                channels_by_guild.get(&guild.id),
                snapshot
                    .guild_members
                    .iter()
                    .filter(|member| member.guild_id == guild.id)
                    .map(|member| member.user_id.to_string())
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    let direct_channels = channels_by_guild.get(&0).cloned().unwrap_or_default();
    workspaces.insert(
        0,
        direct_message_workspace(snapshot, current_user_id, &direct_channels),
    );
    let active_workspace_id = snapshot
        .active_guild_id
        .filter(|id| *id == 0 || snapshot.guilds.iter().any(|guild| guild.id == *id))
        .or_else(|| snapshot.guilds.first().map(|guild| guild.id))
        .unwrap_or(0);
    let active_channel_id = snapshot
        .active_channel_id
        .filter(|id| {
            snapshot
                .channels
                .iter()
                .any(|channel| channel.id == *id && channel.guild_id == active_workspace_id)
        })
        .or_else(|| {
            snapshot.channels.iter().find_map(|channel| {
                (channel.guild_id == active_workspace_id && channel.kind == ChannelKind::Text)
                    .then_some(channel.id)
            })
        })
        .unwrap_or_default();
    let active_voice_room_id = snapshot.active_voice_channel_id.filter(|id| {
        snapshot.channels.iter().any(|channel| {
            channel.id == *id
                && channel.guild_id == active_workspace_id
                && channel.kind == ChannelKind::Voice
        })
    });
    BootstrapViewModel {
        revision,
        current_user_id: current_user_id.to_string(),
        active_workspace_id: active_workspace_id.to_string(),
        active_channel_id: active_channel_id.to_string(),
        active_voice_room_id: active_voice_room_id.map(|id| id.to_string()),
        connection_state,
        pending_outbox: snapshot.pending_outbox,
        workspaces,
        members,
        relationships: relationship_views(snapshot),
        typing: typing
            .values()
            .filter(|event| event.expires_at > Utc::now())
            .map(|event| TypingView {
                channel_id: event.channel_id.to_string(),
                user_id: event.user_id.to_string(),
                expires_at: event.expires_at.to_rfc3339(),
            })
            .collect(),
        messages: snapshot
            .messages
            .iter()
            .map(|message| chat_message(message, current_user_id))
            .collect(),
        cache_protection: CacheProtectionView {
            encrypted: cipher_version.is_some(),
            cipher: cipher_version.map_or_else(
                || "Unavailable".to_owned(),
                |version| format!("SQLCipher {version} · AES-256"),
            ),
            key_storage: "Operating-system credential vault",
        },
        cache_recovery,
    }
}

fn direct_message_workspace(
    snapshot: &CacheSnapshot,
    current_user_id: u64,
    direct_channels: &[&CachedChannel],
) -> Workspace {
    let read_by_channel = snapshot
        .read_states
        .iter()
        .map(|state| {
            (
                state.channel_id.raw(),
                state.last_message_id.map(MessageId::raw),
            )
        })
        .collect::<HashMap<_, _>>();
    let direct_by_id = snapshot
        .direct_channels
        .iter()
        .map(|channel| (channel.id, channel))
        .collect::<HashMap<_, _>>();
    Workspace {
        id: "0".into(),
        owner_id: current_user_id.to_string(),
        name: "Messages".into(),
        initials: "DM".into(),
        accent: "#69d7bd".into(),
        permission_keys: Vec::new(),
        member_ids: snapshot
            .relationships
            .iter()
            .filter(|relationship| relationship.kind == RelationshipKind::Friend)
            .map(|relationship| relationship.user_id.to_string())
            .collect(),
        channels: direct_channels
            .iter()
            .map(|channel| {
                let last_message_id = direct_by_id
                    .get(&channel.id)
                    .and_then(|direct| direct.last_message_id);
                let last_read_id = read_by_channel.get(&channel.id).copied().flatten();
                Channel {
                    id: channel.id.to_string(),
                    name: channel.name.clone(),
                    kind: "text",
                    unread: Some(
                        last_message_id
                            .is_some_and(|last| last_read_id.is_none_or(|read| last > read)),
                    ),
                }
            })
            .collect(),
        voice_rooms: Vec::new(),
        direct_messages: true,
        local_only: false,
        unread_count: Some(
            direct_channels
                .iter()
                .filter(|channel| {
                    direct_by_id
                        .get(&channel.id)
                        .and_then(|direct| direct.last_message_id)
                        .is_some_and(|last| {
                            read_by_channel
                                .get(&channel.id)
                                .copied()
                                .flatten()
                                .is_none_or(|read| last > read)
                        })
                })
                .count()
                .try_into()
                .unwrap_or(u32::MAX),
        ),
    }
}

fn relationship_views(snapshot: &CacheSnapshot) -> Vec<RelationshipView> {
    snapshot
        .relationships
        .iter()
        .filter_map(|relationship| {
            snapshot
                .users
                .iter()
                .find(|user| user.id == relationship.user_id)
                .map(|user| {
                    let name = if user.display_name.is_empty() {
                        user.handle.clone()
                    } else {
                        user.display_name.clone()
                    };
                    RelationshipView {
                        user_id: user.id.to_string(),
                        name: name.clone(),
                        handle: user.handle.clone(),
                        initials: initials(&name),
                        color: color_for(user.id),
                        kind: relationship_kind_name(relationship.kind),
                        since: relationship.since.clone(),
                    }
                })
        })
        .collect()
}

fn member(
    user: &CachedUser,
    current_user_id: u64,
    connection_state: ConnectionState,
    presences: &HashMap<u64, UserPresence>,
) -> Member {
    let name = if user.display_name.is_empty() {
        user.handle.clone()
    } else {
        user.display_name.clone()
    };
    Member {
        id: user.id.to_string(),
        initials: initials(&name),
        name,
        handle: user.handle.clone(),
        color: color_for(user.id),
        avatar_url: user.avatar_url.clone(),
        presence: if user.id == current_user_id {
            if connection_state == ConnectionState::Connected {
                "online"
            } else {
                "offline"
            }
        } else if presences
            .get(&user.id)
            .is_some_and(|presence| presence.status == PresenceStatus::Online)
        {
            "online"
        } else {
            "offline"
        },
    }
}

const fn relationship_kind_name(kind: RelationshipKind) -> &'static str {
    match kind {
        RelationshipKind::Incoming => "incoming",
        RelationshipKind::Outgoing => "outgoing",
        RelationshipKind::Friend => "friend",
        RelationshipKind::Blocked => "blocked",
    }
}

fn workspace(
    guild: &CachedGuild,
    channels: Option<&Vec<&CachedChannel>>,
    member_ids: Vec<String>,
) -> Workspace {
    let empty = Vec::new();
    let channels = channels.unwrap_or(&empty);
    Workspace {
        id: guild.id.to_string(),
        owner_id: guild.owner_id.to_string(),
        name: guild.name.clone(),
        initials: initials(&guild.name),
        accent: format!("#{:06x}", guild.accent),
        permission_keys: permission_keys(GuildPermissions::from_bits_retain(
            guild.current_permissions,
        )),
        member_ids,
        channels: channels
            .iter()
            .filter(|channel| channel.kind == ChannelKind::Text)
            .map(|channel| Channel {
                id: channel.id.to_string(),
                name: channel.name.clone(),
                kind: "text",
                unread: None,
            })
            .collect(),
        voice_rooms: channels
            .iter()
            .filter(|channel| channel.kind == ChannelKind::Voice)
            .map(|channel| VoiceRoom {
                id: channel.id.to_string(),
                name: channel.name.clone(),
                latency_ms: 0,
                encrypted: channel.encrypted,
                participants: Vec::new(),
            })
            .collect(),
        direct_messages: false,
        local_only: !guild.origin_remote,
        unread_count: None,
    }
}

fn invite_view(invite: &GuildInvite) -> InviteView {
    InviteView {
        code: invite.code.clone(),
        max_uses: invite.max_uses,
        expires_at: invite.expires_at.map(|value| value.to_rfc3339()),
    }
}

fn invite_preview_view(preview: &InvitePreview) -> InvitePreviewView {
    InvitePreviewView {
        code: preview.code.clone(),
        workspace_id: preview.guild.id.to_string(),
        name: preview.guild.name.clone(),
        accent: format!("#{:06x}", preview.guild.accent),
        member_count: preview.member_count,
        expires_at: preview.expires_at.map(|value| value.to_rfc3339()),
    }
}

fn role_manager_view(guild_id: u64, roles: &[Role], members: &[GuildMember]) -> RoleManagerView {
    RoleManagerView {
        roles: roles.iter().map(|role| role_view(guild_id, role)).collect(),
        members: members.iter().map(role_member_view).collect(),
    }
}

fn role_view(guild_id: u64, role: &Role) -> RoleView {
    RoleView {
        id: role.id.to_string(),
        name: role.name.clone(),
        color: format!("#{:06x}", role.color),
        position: role.position,
        permission_keys: permission_keys(role.permissions),
        everyone: role.id.raw() == guild_id,
        managed: role.managed,
    }
}

fn role_member_view(member: &GuildMember) -> RoleMemberView {
    let name = if member.user.display_name.is_empty() {
        member.user.handle.clone()
    } else {
        member.user.display_name.clone()
    };
    RoleMemberView {
        id: member.user.id.to_string(),
        initials: initials(&name),
        name,
        handle: member.user.handle.clone(),
        color: color_for(member.user.id.raw()),
        role_ids: member.roles.iter().map(ToString::to_string).collect(),
    }
}

fn server_ownership_member_view(member: &GuildMember) -> ServerOwnershipMemberView {
    let name = if member.user.display_name.is_empty() {
        member.user.handle.clone()
    } else {
        member.user.display_name.clone()
    };
    ServerOwnershipMemberView {
        id: member.user.id.to_string(),
        initials: initials(&name),
        name,
        handle: member.user.handle.clone(),
        color: color_for(member.user.id.raw()),
    }
}

fn managed_channel_view(channel: &DomainChannel) -> ManagedChannelView {
    ManagedChannelView {
        id: channel.id.to_string(),
        name: channel.name.clone(),
        kind: match channel.kind {
            ChannelKind::Text => "text",
            ChannelKind::Voice => "voice",
        },
        encrypted: channel.encrypted,
    }
}

fn channel_overwrite_view(overwrite: &ChannelPermissionOverwrite) -> ChannelOverwriteView {
    ChannelOverwriteView {
        channel_id: overwrite.channel_id.to_string(),
        target_kind: match overwrite.target_kind {
            OverwriteTargetKind::Role => "role",
            OverwriteTargetKind::Member => "member",
        },
        target_id: overwrite.target_id.clone(),
        allow_keys: permission_keys(overwrite.allow),
        deny_keys: permission_keys(overwrite.deny),
    }
}

fn moderation_member_view(member: &GuildMember) -> ModerationMemberView {
    let role_member = role_member_view(member);
    ModerationMemberView {
        id: role_member.id,
        name: role_member.name,
        handle: role_member.handle,
        initials: role_member.initials,
        color: role_member.color,
        role_ids: role_member.role_ids,
        timeout_until: member.timeout_until.map(|value| value.to_rfc3339()),
    }
}

fn ban_view(ban: &GuildBan) -> BanView {
    let name = if ban.user.display_name.is_empty() {
        ban.user.handle.clone()
    } else {
        ban.user.display_name.clone()
    };
    BanView {
        id: ban.user.id.to_string(),
        initials: initials(&name),
        name,
        handle: ban.user.handle.clone(),
        color: color_for(ban.user.id.raw()),
        reason: ban.reason.clone(),
        expires_at: ban.expires_at.map(|value| value.to_rfc3339()),
        created_at: ban.created_at.to_rfc3339(),
    }
}

fn automod_rule_view(rule: &AutomodRule) -> AutomodRuleView {
    let mut view = AutomodRuleView {
        id: rule.id.to_string(),
        name: rule.name.clone(),
        enabled: rule.enabled,
        trigger_type: "invite_link",
        terms: Vec::new(),
        mention_limit: None,
        repeat_threshold: None,
        window_seconds: None,
        max_account_age_days: None,
        combining_mark_limit: None,
        action: match rule.action {
            AutomodAction::Flag => "flag",
            AutomodAction::Block => "block",
            AutomodAction::Timeout => "timeout",
            AutomodAction::Kick => "kick",
            AutomodAction::Ban => "ban",
        },
        duration_seconds: rule.duration_seconds,
        explanation: rule.explanation.clone(),
        updated_at: rule.updated_at.to_rfc3339(),
    };
    match &rule.trigger {
        AutomodTrigger::Keyword { terms } => {
            view.trigger_type = "keyword";
            view.terms.clone_from(terms);
        }
        AutomodTrigger::Regex { patterns } => {
            view.trigger_type = "regex";
            view.terms.clone_from(patterns);
        }
        AutomodTrigger::InviteLink => {}
        AutomodTrigger::MassMention { limit } => {
            view.trigger_type = "mass_mention";
            view.mention_limit = Some(*limit);
        }
        AutomodTrigger::RepeatedContent {
            threshold,
            window_seconds,
        } => {
            view.trigger_type = "repeated_content";
            view.repeat_threshold = Some(*threshold);
            view.window_seconds = Some(*window_seconds);
        }
        AutomodTrigger::NewAccountLink {
            max_account_age_days,
        } => {
            view.trigger_type = "new_account_link";
            view.max_account_age_days = Some(*max_account_age_days);
        }
        AutomodTrigger::Zalgo {
            combining_mark_limit,
        } => {
            view.trigger_type = "zalgo";
            view.combining_mark_limit = Some(*combining_mark_limit);
        }
    }
    view
}

fn audit_log_view(entry: &AuditLogEntry) -> AuditLogView {
    let detail = entry
        .changes
        .get("name")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            entry
                .changes
                .pointer("/after/name")
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| {
            entry
                .changes
                .get("ruleName")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_owned);
    AuditLogView {
        id: entry.id.to_string(),
        actor_id: entry.actor_id.map(|value| value.to_string()),
        target_id: entry.target_id.clone(),
        action_type: entry.action_type,
        action_label: match entry.action_type {
            10 => "Channel created",
            11 => "Channel updated",
            12 => "Channel deleted",
            20 => "Role created",
            21 => "Role updated",
            22 => "Role deleted",
            23 => "Role assigned",
            24 => "Role removed",
            30 => "Access rule updated",
            31 => "Access rule deleted",
            40 => "Member timed out",
            41 => "Member removed",
            42 => "Member banned",
            43 => "Member unbanned",
            50 => "Safety rule created",
            51 => "Safety rule updated",
            52 => "Safety rule deleted",
            60 => "Message flagged",
            61 => "Message blocked",
            62 => "Automod timeout",
            63 => "Automod removal",
            64 => "Automod ban",
            _ => "Server setting changed",
        },
        detail,
        reason: entry.reason.clone(),
        created_at: entry.created_at.to_rfc3339(),
    }
}

fn parse_color(value: &str) -> Result<u32, String> {
    let value = value.trim().trim_start_matches('#');
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("role color must be a six-digit hex color".to_owned());
    }
    u32::from_str_radix(value, 16).map_err(|_| "role color is invalid".to_owned())
}

fn permissions_from_keys(keys: &[String]) -> Result<GuildPermissions, String> {
    let mut permissions = GuildPermissions::empty();
    for key in keys {
        let permission = permission_catalog()
            .iter()
            .find_map(|(candidate, permission)| (*candidate == key).then_some(*permission))
            .ok_or_else(|| format!("unknown permission: {key}"))?;
        permissions.insert(permission);
    }
    Ok(permissions)
}

fn permission_keys(permissions: GuildPermissions) -> Vec<String> {
    permission_catalog()
        .iter()
        .filter(|(_, permission)| permissions.contains(*permission))
        .map(|(key, _)| (*key).to_owned())
        .collect()
}

fn permission_catalog() -> &'static [(&'static str, GuildPermissions)] {
    &[
        ("create_invite", GuildPermissions::CREATE_INVITE),
        ("kick_members", GuildPermissions::KICK_MEMBERS),
        ("ban_members", GuildPermissions::BAN_MEMBERS),
        ("administrator", GuildPermissions::ADMINISTRATOR),
        ("manage_channels", GuildPermissions::MANAGE_CHANNELS),
        ("manage_guild", GuildPermissions::MANAGE_GUILD),
        ("view_audit_log", GuildPermissions::VIEW_AUDIT_LOG),
        ("manage_roles", GuildPermissions::MANAGE_ROLES),
        ("manage_webhooks", GuildPermissions::MANAGE_WEBHOOKS),
        ("manage_emoji", GuildPermissions::MANAGE_EMOJI),
        ("change_nickname", GuildPermissions::CHANGE_NICKNAME),
        ("manage_nicknames", GuildPermissions::MANAGE_NICKNAMES),
        ("moderate_members", GuildPermissions::MODERATE_MEMBERS),
        ("view_member_list", GuildPermissions::VIEW_MEMBER_LIST),
        ("view_channel", GuildPermissions::VIEW_CHANNEL),
        ("send_messages", GuildPermissions::SEND_MESSAGES),
        ("send_messages_in_dm", GuildPermissions::SEND_MESSAGES_IN_DM),
        ("embed_links", GuildPermissions::EMBED_LINKS),
        ("attach_files", GuildPermissions::ATTACH_FILES),
        ("add_reactions", GuildPermissions::ADD_REACTIONS),
        ("use_external_emoji", GuildPermissions::USE_EXTERNAL_EMOJI),
        ("mention_everyone", GuildPermissions::MENTION_EVERYONE),
        ("manage_messages", GuildPermissions::MANAGE_MESSAGES),
        (
            "read_message_history",
            GuildPermissions::READ_MESSAGE_HISTORY,
        ),
        ("send_tts_messages", GuildPermissions::SEND_TTS_MESSAGES),
        ("manage_pins", GuildPermissions::MANAGE_PINS),
        ("bypass_slowmode", GuildPermissions::BYPASS_SLOWMODE),
        ("connect", GuildPermissions::CONNECT),
        ("speak", GuildPermissions::SPEAK),
        ("stream", GuildPermissions::STREAM),
        ("mute_members", GuildPermissions::MUTE_MEMBERS),
        ("deafen_members", GuildPermissions::DEAFEN_MEMBERS),
        ("move_members", GuildPermissions::MOVE_MEMBERS),
        ("use_vad", GuildPermissions::USE_VAD),
        ("priority_speaker", GuildPermissions::PRIORITY_SPEAKER),
        (
            "manage_voice_channel",
            GuildPermissions::MANAGE_VOICE_CHANNEL,
        ),
        ("manage_automod", GuildPermissions::MANAGE_AUTOMOD),
        ("view_automod_alerts", GuildPermissions::VIEW_AUTOMOD_ALERTS),
        ("manage_integrations", GuildPermissions::MANAGE_INTEGRATIONS),
        (
            "use_application_commands",
            GuildPermissions::USE_APPLICATION_COMMANDS,
        ),
        ("enable_e2ee", GuildPermissions::ENABLE_E2EE),
        ("manage_e2ee_members", GuildPermissions::MANAGE_E2EE_MEMBERS),
    ]
}

fn chat_message(message: &CachedMessage, current_user_id: u64) -> ChatMessage {
    ChatMessage {
        id: message.id.to_string(),
        client_key: message.client_key.clone(),
        channel_id: message.channel_id.to_string(),
        author_id: message.author_id.to_string(),
        reply_to_id: message.reply_to.map(|id| id.to_string()),
        content: message.content.clone(),
        attachments: message.attachments.clone(),
        reactions: message.reactions.clone(),
        sent_at: DateTime::parse_from_rfc3339(&message.created_at).map_or_else(
            |_| message.created_at.clone(),
            |timestamp| timestamp.to_rfc3339(),
        ),
        edited: message.edited_at.is_some(),
        delivery_state: message.state,
        delivered: (message.author_id == current_user_id && message.state == MessageState::Sent)
            .then_some(true),
    }
}

fn direct_unread_delta(
    core: &DesktopCore,
    channel_id: u64,
) -> Result<Option<DirectUnreadDelta>, RemoteError> {
    Ok(core
        .store
        .direct_unread_state(channel_id)
        .map_err(|error| e2ee_error(error.to_string()))?
        .map(|(unread, unread_count)| DirectUnreadDelta {
            channel_id: channel_id.to_string(),
            unread,
            unread_count,
        }))
}

fn domain_chat_message(message: &DomainMessage, current_user_id: u64) -> ChatMessage {
    ChatMessage {
        id: message.id.to_string(),
        client_key: message.id.to_string(),
        channel_id: message.channel_id.to_string(),
        author_id: message.author_id.to_string(),
        reply_to_id: message.reply_to.map(|id| id.to_string()),
        content: message.content.clone(),
        attachments: message.attachments.clone(),
        reactions: message.reactions.clone(),
        sent_at: message.created_at.to_rfc3339(),
        edited: message.edited_at.is_some(),
        delivery_state: MessageState::Sent,
        delivered: (message.author_id.raw() == current_user_id).then_some(true),
    }
}

fn initials(value: &str) -> String {
    value.chars().take(2).collect::<String>().to_uppercase()
}

fn color_for(id: u64) -> String {
    const COLORS: [&str; 6] = [
        "#7157ff", "#f05a38", "#13a895", "#ec1764", "#4a82f0", "#c8862c",
    ];
    let index = usize::try_from(id % COLORS.len() as u64).unwrap_or_default();
    COLORS[index].to_owned()
}

fn emit_snapshot(
    app: &AppHandle,
    core: &DesktopCore,
) -> Result<BootstrapViewModel, Box<dyn std::error::Error>> {
    core.revision.fetch_add(1, AtomicOrdering::AcqRel);
    let model = build_view_model(core)?;
    app.emit(CORE_SNAPSHOT_EVENT, &model)?;
    Ok(model)
}

fn emit_snapshot_or_warn(app: &AppHandle, core: &DesktopCore, context: &str) {
    if let Err(error) = emit_snapshot(app, core) {
        tracing::warn!(%error, %context, "desktop snapshot emission failed");
    }
}

fn emit_delta(app: &AppHandle, core: &DesktopCore, change: CoreDeltaChange) {
    let revision = core.revision.fetch_add(1, AtomicOrdering::AcqRel) + 1;
    if let Err(error) = app.emit(
        CORE_DELTA_EVENT,
        CoreDelta {
            version: CORE_DELTA_VERSION,
            revision,
            change,
        },
    ) {
        tracing::warn!(%error, "desktop delta emission failed");
    }
}

fn set_connection_state(app: &AppHandle, core: &DesktopCore, state: ConnectionState) {
    let mut current = core
        .connection
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *current == state {
        return;
    }
    *current = state;
    drop(current);
    emit_delta(
        app,
        core,
        CoreDeltaChange::Connection {
            connection_state: state,
        },
    );
}

fn e2ee_error(message: impl Into<String>) -> RemoteError {
    RemoteError::LocalStore(message.into())
}

fn current_user_id(core: &DesktopCore) -> Result<u64, RemoteError> {
    core.store
        .current_user_id()
        .map_err(|error| e2ee_error(error.to_string()))?
        .ok_or_else(|| e2ee_error("the local profile is unavailable"))
}

fn decode_e2ee_value(value: &str, label: &str) -> Result<Vec<u8>, RemoteError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| e2ee_error(format!("{label} is not valid base64url")))
}

fn persist_mls_client(
    core: &DesktopCore,
    client: &MlsClient,
    epoch: u64,
) -> Result<(), RemoteError> {
    let key = core
        .mls_device_key
        .ok_or_else(|| e2ee_error("the operating-system MLS device key is unavailable"))?;
    let device_id = Uuid::parse_str(&core.device_id)
        .map_err(|_| e2ee_error("the local device id is invalid"))?;
    let sealed = client
        .seal(&key)
        .map_err(|error| e2ee_error(error.to_string()))?;
    core.store
        .save_mls_state(device_id.as_bytes(), &sealed, epoch)
        .map_err(|error| e2ee_error(error.to_string()))
}

async fn ensure_e2ee_identity(core: &DesktopCore, user_id: u64) -> Result<(), RemoteError> {
    let _setup = core.mls_setup.lock().await;
    let device_id = Uuid::parse_str(&core.device_id)
        .map_err(|_| e2ee_error("the local device id is invalid"))?;
    let key = core
        .mls_device_key
        .ok_or_else(|| e2ee_error("end-to-end encryption requires the OS credential vault"))?;

    if !core.mls_published.load(AtomicOrdering::Acquire) {
        let (identity, packages) = {
            let mut current = core
                .mls
                .lock()
                .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?;
            if current.is_none() {
                let client = match core
                    .store
                    .load_mls_state(device_id.as_bytes())
                    .map_err(|error| e2ee_error(error.to_string()))?
                {
                    Some(sealed) => MlsClient::open(&sealed, &key)
                        .map_err(|error| e2ee_error(error.to_string()))?,
                    None => MlsClient::create(user_id, device_id)
                        .map_err(|error| e2ee_error(error.to_string()))?,
                };
                if client.user_id() != user_id || client.device_id() != device_id {
                    return Err(e2ee_error(
                        "the sealed MLS identity belongs to another account or device",
                    ));
                }
                *current = Some(client);
            }
            let client = current
                .as_ref()
                .ok_or_else(|| e2ee_error("the local MLS identity is unavailable"))?;
            let identity = client.public_identity();
            let packages = (0..20)
                .map(|_| client.generate_key_package())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| e2ee_error(error.to_string()))?;
            persist_mls_client(core, client, 0)?;
            (identity, packages)
        };
        core.remote
            .register_device_identity(
                &core.device_id,
                &RegisterDeviceIdentity {
                    signature_key: URL_SAFE_NO_PAD.encode(identity.signature_key),
                    name: Some("Exo Link Desktop".into()),
                },
            )
            .await?;
        core.remote
            .publish_mls_key_packages(
                &core.device_id,
                &PublishMlsKeyPackages {
                    packages: packages
                        .into_iter()
                        .map(|package| PublishMlsKeyPackage {
                            reference: URL_SAFE_NO_PAD.encode(package.reference),
                            key_package: URL_SAFE_NO_PAD.encode(package.key_package),
                            cipher_suite: package.cipher_suite,
                        })
                        .collect(),
                },
            )
            .await?;
        core.mls_published.store(true, AtomicOrdering::Release);
    }
    process_mls_inbox(core).await
}

async fn process_mls_inbox(core: &DesktopCore) -> Result<(), RemoteError> {
    let deliveries = core.remote.mls_inbox(&core.device_id).await?;
    for delivery in deliveries {
        let group_id = decode_e2ee_value(&delivery.group_id, "MLS group id")?;
        let payload = decode_e2ee_value(&delivery.payload, "MLS delivery")?;
        {
            let mut current = core
                .mls
                .lock()
                .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?;
            let client = current
                .as_mut()
                .ok_or_else(|| e2ee_error("the local MLS identity is unavailable"))?;
            match delivery.kind {
                MlsDeliveryKind::Welcome => {
                    if let Some(existing) = client.group_id(delivery.channel_id.raw()) {
                        if existing != group_id {
                            return Err(e2ee_error(
                                "the server attempted to fork an existing MLS channel group",
                            ));
                        }
                    } else {
                        client
                            .join_group(delivery.channel_id.raw(), &payload)
                            .map_err(|error| e2ee_error(error.to_string()))?;
                    }
                }
                MlsDeliveryKind::Commit => {
                    client
                        .process_commit(delivery.channel_id.raw(), &payload)
                        .map_err(|error| e2ee_error(error.to_string()))?;
                }
                MlsDeliveryKind::Proposal => {
                    return Err(e2ee_error(
                        "standalone MLS proposals are not accepted by this client",
                    ));
                }
            }
            persist_mls_client(core, client, delivery.epoch)?;
        }
        core.remote
            .acknowledge_mls_delivery(&core.device_id, &delivery)
            .await?;
    }
    Ok(())
}

async fn validate_claimed_mls_packages(
    core: &DesktopCore,
    claimed: &[MlsKeyPackage],
) -> Result<Vec<PublishedKeyPackage>, RemoteError> {
    let mut identities = HashMap::new();
    for user_id in claimed
        .iter()
        .map(|package| package.user_id)
        .collect::<std::collections::HashSet<_>>()
    {
        for identity in core.remote.list_device_identities(user_id).await? {
            identities.insert(identity.device_id, identity);
        }
    }
    claimed
        .iter()
        .map(|package| {
            let identity = identities.get(&package.device_id).ok_or_else(|| {
                e2ee_error("a claimed MLS KeyPackage has no registered device identity")
            })?;
            Ok(PublishedKeyPackage {
                user_id: package.user_id.raw(),
                device_id: package.device_id,
                signature_key: decode_e2ee_value(&identity.signature_key, "device signature key")?,
                reference: decode_e2ee_value(&package.reference, "MLS KeyPackage reference")?,
                key_package: decode_e2ee_value(&package.key_package, "MLS KeyPackage")?,
                cipher_suite: package.cipher_suite,
            })
        })
        .collect()
}

async fn wait_for_mls_membership(core: &DesktopCore, channel_id: u64) -> Result<bool, RemoteError> {
    for _ in 0..8 {
        process_mls_inbox(core).await?;
        if core
            .mls
            .lock()
            .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?
            .as_ref()
            .is_some_and(|client| client.has_group(channel_id))
        {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    Ok(false)
}

async fn bootstrap_channel_mls(core: &DesktopCore, channel_id: u64) -> Result<(), RemoteError> {
    let user_id = core
        .store
        .snapshot()
        .map_err(|error| e2ee_error(error.to_string()))?
        .current_user_id
        .ok_or_else(|| e2ee_error("the local profile is unavailable"))?;
    ensure_e2ee_identity(core, user_id).await?;
    let _setup = core.mls_setup.lock().await;
    if core
        .mls
        .lock()
        .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?
        .as_ref()
        .is_some_and(|client| client.has_group(channel_id))
    {
        return Ok(());
    }

    let claimed = match core.remote.claim_mls_key_packages(channel_id).await {
        Ok(claimed) => claimed,
        Err(error @ RemoteError::Status { status: 409, .. }) => {
            if wait_for_mls_membership(core, channel_id).await? {
                return Ok(());
            }
            return Err(e2ee_error(format!(
                "another verified device must approve this device for the encrypted channel ({error})"
            )));
        }
        Err(error) => return Err(error),
    };
    let packages = validate_claimed_mls_packages(core, &claimed).await?;

    let key = core
        .mls_device_key
        .ok_or_else(|| e2ee_error("the operating-system MLS device key is unavailable"))?;
    let (mut client, backup) = {
        let mut current = core
            .mls
            .lock()
            .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?;
        let client = current
            .take()
            .ok_or_else(|| e2ee_error("the local MLS identity is unavailable"))?;
        let backup = client
            .seal(&key)
            .map_err(|error| e2ee_error(error.to_string()))?;
        (client, backup)
    };
    let bootstrap = client
        .create_group(channel_id, &packages)
        .map_err(|error| e2ee_error(error.to_string()))?;
    let request = BootstrapMlsGroup {
        group_id: URL_SAFE_NO_PAD.encode(&bootstrap.group_id),
        epoch: bootstrap.epoch,
        commit: URL_SAFE_NO_PAD.encode(&bootstrap.commit),
        welcomes: claimed
            .iter()
            .map(|package| MlsWelcomeUpload {
                device_id: package.device_id,
                key_package_reference: package.reference.clone(),
                payload: URL_SAFE_NO_PAD.encode(&bootstrap.welcome),
            })
            .collect(),
    };
    if let Err(error) = core.remote.bootstrap_mls_group(channel_id, &request).await {
        let restored = MlsClient::open(&backup, &key)
            .map_err(|restore_error| e2ee_error(restore_error.to_string()))?;
        *core
            .mls
            .lock()
            .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))? = Some(restored);
        if matches!(&error, RemoteError::Status { status: 409, .. })
            && wait_for_mls_membership(core, channel_id).await?
        {
            return Ok(());
        }
        return Err(error);
    }
    persist_mls_client(core, &client, bootstrap.epoch)?;
    *core
        .mls
        .lock()
        .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))? = Some(client);
    Ok(())
}

fn unresolved_revoked_devices(
    core: &DesktopCore,
    channel_id: u64,
    requested: &[Uuid],
) -> Result<Vec<Uuid>, RemoteError> {
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    let current = core
        .mls
        .lock()
        .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?;
    let client = current
        .as_ref()
        .ok_or_else(|| e2ee_error("the local MLS identity is unavailable"))?;
    devices_still_in_group(client, channel_id, requested)
}

fn devices_still_in_group(
    client: &MlsClient,
    channel_id: u64,
    requested: &[Uuid],
) -> Result<Vec<Uuid>, RemoteError> {
    let mut unresolved = Vec::new();
    for device_id in requested {
        if client
            .group_contains_device(channel_id, *device_id)
            .map_err(|error| e2ee_error(error.to_string()))?
        {
            unresolved.push(*device_id);
        }
    }
    Ok(unresolved)
}

async fn maintain_channel_mls(
    core: &DesktopCore,
    hint: &MlsMembershipHint,
) -> Result<(), RemoteError> {
    let channel_id = hint.channel_id.raw();
    let user_id = core
        .store
        .snapshot()
        .map_err(|error| e2ee_error(error.to_string()))?
        .current_user_id
        .ok_or_else(|| e2ee_error("the local profile is unavailable"))?;
    ensure_e2ee_identity(core, user_id).await?;
    let _setup = core.mls_setup.lock().await;
    if !core
        .mls
        .lock()
        .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?
        .as_ref()
        .is_some_and(|client| client.has_group(channel_id))
    {
        return Ok(());
    }
    let revoked_device_ids =
        unresolved_revoked_devices(core, channel_id, &hint.revoked_device_ids)?;
    if !hint.revoked_device_ids.is_empty() && revoked_device_ids.is_empty() {
        return Ok(());
    }
    let claimed = if revoked_device_ids.is_empty() {
        core.remote.claim_mls_key_packages(channel_id).await?
    } else {
        Vec::new()
    };
    if claimed.is_empty() && revoked_device_ids.is_empty() {
        return Ok(());
    }
    let packages = validate_claimed_mls_packages(core, &claimed).await?;
    let key = core
        .mls_device_key
        .ok_or_else(|| e2ee_error("the operating-system MLS device key is unavailable"))?;
    let (client, backup) = {
        let mut current = core
            .mls
            .lock()
            .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?;
        let client = current
            .take()
            .ok_or_else(|| e2ee_error("the local MLS identity is unavailable"))?;
        let backup = client
            .seal(&key)
            .map_err(|error| e2ee_error(error.to_string()))?;
        (client, backup)
    };
    let update = if revoked_device_ids.is_empty() {
        client
            .add_members(channel_id, &packages)
            .map_err(|error| e2ee_error(error.to_string()))?
    } else {
        client
            .remove_devices(channel_id, &revoked_device_ids)
            .map_err(|error| e2ee_error(error.to_string()))?
    };
    let request = UpdateMlsGroup {
        group_id: URL_SAFE_NO_PAD.encode(&update.group_id),
        epoch: update.epoch,
        commit: URL_SAFE_NO_PAD.encode(&update.commit),
        welcomes: claimed
            .iter()
            .map(|package| MlsWelcomeUpload {
                device_id: package.device_id,
                key_package_reference: package.reference.clone(),
                payload: URL_SAFE_NO_PAD.encode(&update.welcome),
            })
            .collect(),
        removed_device_ids: revoked_device_ids,
    };
    if let Err(error) = core.remote.update_mls_group(channel_id, &request).await {
        let restored = MlsClient::open(&backup, &key)
            .map_err(|restore_error| e2ee_error(restore_error.to_string()))?;
        *core
            .mls
            .lock()
            .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))? = Some(restored);
        if matches!(&error, RemoteError::Status { status: 409, .. }) {
            process_mls_inbox(core).await?;
            return Ok(());
        }
        return Err(error);
    }
    persist_mls_client(core, &client, update.epoch)?;
    *core
        .mls
        .lock()
        .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))? = Some(client);
    Ok(())
}

fn decrypt_message(
    core: &DesktopCore,
    message: &DomainMessage,
) -> Result<(String, Vec<MessageAttachment>), RemoteError> {
    let encryption = message
        .encryption
        .as_ref()
        .ok_or_else(|| e2ee_error("message is not encrypted"))?;
    let ciphertext = decode_e2ee_value(&encryption.ciphertext, "MLS ciphertext")?;
    let commitment: [u8; 32] = decode_e2ee_value(
        &encryption.franking_commitment,
        "message-franking commitment",
    )?
    .try_into()
    .map_err(|_| e2ee_error("message-franking commitment is not 32 bytes"))?;
    let context = MessageContext {
        channel_id: message.channel_id.raw(),
        author_id: message.author_id.raw(),
        nonce: encryption.context_nonce.clone(),
    };
    let current = core
        .mls
        .lock()
        .map_err(|_| e2ee_error("the local MLS state lock is unavailable"))?;
    let client = current
        .as_ref()
        .ok_or_else(|| e2ee_error("the local MLS identity is unavailable"))?;
    let decrypted = client
        .decrypt_message(&context, &ciphertext, &commitment)
        .map_err(|error| e2ee_error(error.to_string()))?;
    persist_mls_client(core, client, 0)?;
    persist_franking_opening(
        core,
        message.id.raw(),
        &FrankingOpening {
            content: decrypted.content.clone(),
            attachment_sha256: decrypted.attachment_sha256.clone(),
            franking_key: decrypted.franking_key,
            franking_tag: decode_e2ee_value(&encryption.franking_tag, "message-franking tag")?
                .try_into()
                .map_err(|_| e2ee_error("message-franking tag is not 32 bytes"))?,
        },
    )?;
    let attachments = decrypted
        .attachments
        .iter()
        .map(|attachment| decrypted_attachment(message, attachment))
        .collect::<Result<Vec<_>, _>>()?;
    let descriptor_ids = attachments
        .iter()
        .map(|attachment| attachment.id)
        .collect::<std::collections::HashSet<_>>();
    let server_ids = message
        .attachments
        .iter()
        .map(|attachment| attachment.id)
        .collect::<std::collections::HashSet<_>>();
    if descriptor_ids.len() != attachments.len() || descriptor_ids != server_ids {
        return Err(e2ee_error(
            "encrypted attachment descriptors do not match the server attachment set",
        ));
    }
    Ok((decrypted.content, attachments))
}

fn persist_franking_opening(
    core: &DesktopCore,
    message_id: u64,
    opening: &FrankingOpening,
) -> Result<(), RemoteError> {
    let key = core
        .mls_device_key
        .ok_or_else(|| e2ee_error("the operating-system MLS device key is unavailable"))?;
    let sealed = seal_franking_opening(opening, &key, message_id)
        .map_err(|error| e2ee_error(error.to_string()))?;
    core.store
        .save_franking_opening(message_id, &sealed)
        .map_err(|error| e2ee_error(error.to_string()))
}

fn decrypted_attachment(
    message: &DomainMessage,
    attachment: &EncryptedAttachment,
) -> Result<MessageAttachment, RemoteError> {
    let id = attachment
        .id
        .parse::<AttachmentId>()
        .map_err(|_| e2ee_error("encrypted attachment id is invalid"))?;
    let remote = message
        .attachments
        .iter()
        .find(|candidate| candidate.id == id)
        .ok_or_else(|| e2ee_error("encrypted attachment is missing from the server message"))?;
    if attachment.algorithm != "AES-256-GCM" {
        return Err(e2ee_error("encrypted attachment algorithm is unsupported"));
    }
    if attachment.filename.is_empty()
        || attachment.filename.len() > 255
        || attachment.content_type.is_empty()
        || attachment.content_type.len() > 255
        || remote.size != attachment.size.saturating_add(16)
    {
        return Err(e2ee_error("encrypted attachment metadata is invalid"));
    }
    Ok(MessageAttachment {
        id,
        filename: attachment.filename.clone(),
        content_type: attachment.content_type.clone(),
        size: attachment.size,
        url: remote.url.clone(),
        width: attachment.width,
        height: attachment.height,
        animated: attachment.animated,
        encryption: Some(AttachmentEncryption {
            algorithm: attachment.algorithm.clone(),
            key: URL_SAFE_NO_PAD.encode(attachment.key),
            nonce: URL_SAFE_NO_PAD.encode(attachment.nonce),
            plaintext_sha256: hex::encode(attachment.plaintext_sha256),
            ciphertext_sha256: hex::encode(attachment.ciphertext_sha256),
        }),
    })
}

fn encrypted_attachment(
    attachment: &MessageAttachment,
) -> Result<EncryptedAttachment, RemoteError> {
    let encryption = attachment
        .encryption
        .as_ref()
        .ok_or_else(|| e2ee_error("attachment was not encrypted before upload"))?;
    if encryption.algorithm != "AES-256-GCM" {
        return Err(e2ee_error("encrypted attachment algorithm is unsupported"));
    }
    Ok(EncryptedAttachment {
        id: attachment.id.to_string(),
        filename: attachment.filename.clone(),
        content_type: attachment.content_type.clone(),
        size: attachment.size,
        width: attachment.width,
        height: attachment.height,
        animated: attachment.animated,
        algorithm: encryption.algorithm.clone(),
        key: decode_e2ee_value(&encryption.key, "attachment key")?
            .try_into()
            .map_err(|_| e2ee_error("attachment key must contain exactly 32 bytes"))?,
        nonce: decode_e2ee_value(&encryption.nonce, "attachment nonce")?
            .try_into()
            .map_err(|_| e2ee_error("attachment nonce must contain exactly 12 bytes"))?,
        plaintext_sha256: decode_hex_32(&encryption.plaintext_sha256, "attachment plaintext hash")?,
        ciphertext_sha256: decode_hex_32(
            &encryption.ciphertext_sha256,
            "attachment ciphertext hash",
        )?,
    })
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], RemoteError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| e2ee_error(format!("{label} must be 32-byte lowercase hexadecimal")))
}

fn decrypt_and_store_message(
    core: &DesktopCore,
    message: &DomainMessage,
) -> Result<Option<CachedMessage>, RemoteError> {
    if message.encryption.is_none()
        || core
            .store
            .has_decrypted_message(message.id.raw())
            .map_err(|error| e2ee_error(error.to_string()))?
    {
        return Ok(None);
    }
    let (plaintext, attachments) = decrypt_message(core, message)?;
    core.store
        .upsert_decrypted_remote_message(message, &plaintext, &attachments)
        .map(Some)
        .map_err(|error| e2ee_error(error.to_string()))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivateHistoryPayload {
    version: u8,
    content: String,
    attachments: Vec<MessageAttachment>,
    #[serde(default)]
    author_id: Option<u64>,
    #[serde(default)]
    reply_to: Option<u64>,
    #[serde(default)]
    reactions: Vec<MessageReaction>,
    #[serde(default)]
    sequence: Option<u64>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    edited_at: Option<String>,
}

async fn archive_private_message(
    core: &DesktopCore,
    message: &CachedMessage,
) -> Result<(), RemoteError> {
    core.store
        .queue_private_history_archive(message.id)
        .map_err(|error| e2ee_error(error.to_string()))?;
    let user_id = core
        .active_account_id
        .ok_or_else(|| e2ee_error("the active account is unavailable"))?;
    let key = core
        .vault
        .as_ref()
        .ok_or_else(|| e2ee_error("the account credential vault is unavailable"))?
        .load_history_key()
        .map_err(e2ee_error)?
        .ok_or_else(|| e2ee_error("the account history key is unavailable"))?;
    let plaintext = serde_json::to_vec(&PrivateHistoryPayload {
        version: 2,
        content: message.content.clone(),
        attachments: message.attachments.clone(),
        author_id: Some(message.author_id),
        reply_to: message.reply_to,
        reactions: message.reactions.clone(),
        sequence: Some(message.sequence),
        created_at: Some(message.created_at.clone()),
        edited_at: message.edited_at.clone(),
    })
    .map_err(|error| e2ee_error(error.to_string()))?;
    let (nonce, ciphertext) = seal_private_history(&key, user_id, message.id, &plaintext)
        .map_err(|error| e2ee_error(error.to_string()))?;
    let result = core
        .remote
        .put_private_history(&PrivateHistoryArchive {
            message_id: MessageId::from_raw(message.id)
                .map_err(|error| e2ee_error(error.to_string()))?,
            channel_id: exo_domain::ChannelId::from_raw(message.channel_id)
                .map_err(|error| e2ee_error(error.to_string()))?,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .await;
    match result {
        Ok(()) => core
            .store
            .complete_private_history_archive(message.id)
            .map_err(|error| e2ee_error(error.to_string())),
        Err(error) => {
            if let Err(store_error) = core.store.record_private_history_attempt(message.id) {
                tracing::warn!(
                    %store_error,
                    message_id = message.id,
                    "private-history retry state could not be updated"
                );
            }
            Err(error)
        }
    }
}

fn restore_private_message(
    core: &DesktopCore,
    message: Option<&DomainMessage>,
    archive: &PrivateHistoryArchive,
) -> Result<CachedMessage, RemoteError> {
    if message.is_some_and(|message| {
        archive.message_id != message.id || archive.channel_id != message.channel_id
    }) {
        return Err(e2ee_error(
            "private history metadata does not match the message",
        ));
    }
    let user_id = core
        .active_account_id
        .ok_or_else(|| e2ee_error("the active account is unavailable"))?;
    let key = core
        .vault
        .as_ref()
        .ok_or_else(|| e2ee_error("the account credential vault is unavailable"))?
        .load_history_key()
        .map_err(e2ee_error)?
        .ok_or_else(|| e2ee_error("the account history key is unavailable"))?;
    let nonce: [u8; 24] = URL_SAFE_NO_PAD
        .decode(&archive.nonce)
        .map_err(|_| e2ee_error("private history nonce is invalid"))?
        .try_into()
        .map_err(|_| e2ee_error("private history nonce has the wrong size"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&archive.ciphertext)
        .map_err(|_| e2ee_error("private history ciphertext is invalid"))?;
    let plaintext =
        open_private_history(&key, user_id, archive.message_id.raw(), &nonce, &ciphertext)
            .map_err(|error| e2ee_error(error.to_string()))?;
    let payload = decode_private_history_payload(&plaintext, message.is_some())?;
    if !matches!(payload.version, 0..=2) {
        return Err(e2ee_error("private history uses an unsupported version"));
    }
    let content = validate_message_with_attachments(&payload.content, payload.attachments.len())
        .map_err(|error| e2ee_error(error.to_string()))?;
    if let Some(message) = message {
        return core
            .store
            .upsert_decrypted_remote_message(message, &content, &payload.attachments)
            .map_err(|error| e2ee_error(error.to_string()));
    }
    if payload.version != 2 {
        return Err(e2ee_error(
            "legacy private history requires server message metadata",
        ));
    }
    let author_id = payload
        .author_id
        .filter(|value| UserId::from_raw(*value).is_ok())
        .ok_or_else(|| e2ee_error("private history author is invalid"))?;
    let reply_to = payload
        .reply_to
        .map(|value| {
            MessageId::from_raw(value)
                .map(MessageId::raw)
                .map_err(|error| e2ee_error(error.to_string()))
        })
        .transpose()?;
    let sequence = payload
        .sequence
        .ok_or_else(|| e2ee_error("private history sequence is missing"))?;
    let created_at = payload
        .created_at
        .filter(|value| DateTime::parse_from_rfc3339(value).is_ok())
        .ok_or_else(|| e2ee_error("private history timestamp is invalid"))?;
    let edited_at = payload
        .edited_at
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|_| value)
                .map_err(|_| e2ee_error("private history edit timestamp is invalid"))
        })
        .transpose()?;
    core.store
        .upsert_restored_private_message(&CachedMessage {
            id: archive.message_id.raw(),
            client_key: archive.message_id.to_string(),
            channel_id: archive.channel_id.raw(),
            author_id,
            reply_to,
            content,
            attachments: payload.attachments,
            reactions: payload.reactions,
            sequence,
            created_at,
            edited_at,
            state: MessageState::Sent,
            nonce: None,
            origin_remote: true,
        })
        .map_err(|error| e2ee_error(error.to_string()))
}

fn decode_private_history_payload(
    plaintext: &[u8],
    has_server_metadata: bool,
) -> Result<PrivateHistoryPayload, RemoteError> {
    match serde_json::from_slice(plaintext) {
        Ok(payload) => Ok(payload),
        Err(json_error) if has_server_metadata => {
            let content = std::str::from_utf8(plaintext)
                .map_err(|_| e2ee_error(format!("private history is invalid: {json_error}")))?;
            Ok(PrivateHistoryPayload {
                version: 0,
                content: content.to_owned(),
                attachments: Vec::new(),
                author_id: None,
                reply_to: None,
                reactions: Vec::new(),
                sequence: None,
                created_at: None,
                edited_at: None,
            })
        }
        Err(error) => Err(e2ee_error(error.to_string())),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn deliver_message(
    app: &AppHandle,
    core: &DesktopCore,
    nonce: &str,
    attempts: u32,
    channel_id: u64,
    reply_to: Option<u64>,
    content: &str,
    attachments: &[MessageAttachment],
) {
    let encrypted = match core.store.channel_encryption(channel_id) {
        Ok(Some(encrypted)) => encrypted,
        Ok(None) => {
            tracing::warn!(
                channel_id,
                "message delivery stopped because the channel is no longer in the encrypted cache"
            );
            if let Err(error) = core.store.record_attempt(nonce) {
                tracing::warn!(%error, %nonce, "missing-channel delivery attempt could not be recorded");
            }
            if let Err(error) = core.store.mark_failed(nonce) {
                tracing::warn!(%error, %nonce, "missing-channel message could not be marked failed");
            }
            emit_snapshot_or_warn(app, core, "missing channel delivery");
            return;
        }
        Err(error) => {
            tracing::warn!(
                %error,
                channel_id,
                "message delivery paused because channel encryption metadata is unavailable"
            );
            if let Err(store_error) = core.store.record_attempt(nonce) {
                tracing::warn!(
                    %store_error,
                    %nonce,
                    "paused delivery attempt could not be recorded"
                );
            }
            if attempts.saturating_add(1) >= MAX_OUTBOX_ATTEMPTS {
                if let Err(store_error) = core.store.mark_failed(nonce) {
                    tracing::warn!(%store_error, %nonce, "paused message could not be marked failed");
                }
            }
            emit_snapshot_or_warn(app, core, "paused channel delivery");
            return;
        }
    };
    let result = if encrypted {
        if let Err(error) = bootstrap_channel_mls(core, channel_id).await {
            Err(error)
        } else {
            let encrypted_attachments = attachments
                .iter()
                .map(encrypted_attachment)
                .collect::<Result<Vec<_>, _>>();
            let encrypted = {
                let current = core
                    .mls
                    .lock()
                    .map_err(|_| e2ee_error("the local MLS state lock is unavailable"));
                current.and_then(|current| {
                    let encrypted_attachments = encrypted_attachments?;
                    let client = current
                        .as_ref()
                        .ok_or_else(|| e2ee_error("the local MLS identity is unavailable"))?;
                    let message_context = MessageContext {
                        channel_id,
                        author_id: core
                            .store
                            .snapshot()
                            .map_err(|error| e2ee_error(error.to_string()))?
                            .current_user_id
                            .ok_or_else(|| e2ee_error("the local profile is unavailable"))?,
                        nonce: nonce.to_owned(),
                    };
                    let encrypted = client
                        .encrypt_message_with_attachments(
                            &message_context,
                            content,
                            &encrypted_attachments,
                        )
                        .map_err(|error| e2ee_error(error.to_string()))?;
                    persist_mls_client(core, client, 0)?;
                    Ok(encrypted)
                })
            };
            match encrypted {
                Ok(encrypted) => {
                    let opening = FrankingOpening {
                        content: content.to_owned(),
                        attachment_sha256: encrypted.attachment_sha256.clone(),
                        franking_key: encrypted.franking_key,
                        franking_tag: [0; 32],
                    };
                    core.remote
                        .send_encrypted_message(
                            channel_id,
                            URL_SAFE_NO_PAD.encode(encrypted.ciphertext),
                            URL_SAFE_NO_PAD.encode(encrypted.commitment),
                            reply_to.and_then(|id| MessageId::from_raw(id).ok()),
                            nonce,
                            attachments,
                        )
                        .await
                        .map(|message| (message, Some(opening)))
                }
                Err(error) => Err(error),
            }
        }
    } else {
        core.remote
            .send_message(
                channel_id,
                content,
                reply_to.and_then(|id| MessageId::from_raw(id).ok()),
                nonce,
                attachments,
            )
            .await
            .map(|message| (message, None))
    };
    let updated = match result {
        Ok((message, opening)) => {
            if encrypted {
                if let Some(mut opening) = opening {
                    let persisted = message
                        .encryption
                        .as_ref()
                        .ok_or_else(|| e2ee_error("encrypted response omitted franking metadata"))
                        .and_then(|encryption| {
                            opening.franking_tag = decode_e2ee_value(
                                &encryption.franking_tag,
                                "message-franking tag",
                            )?
                            .try_into()
                            .map_err(|_| e2ee_error("message-franking tag is not 32 bytes"))?;
                            persist_franking_opening(core, message.id.raw(), &opening)
                        });
                    if let Err(error) = persisted {
                        tracing::warn!(%error, "message-franking opening could not be persisted");
                    }
                }
                match core.store.acknowledge_encrypted_message(
                    nonce,
                    &message,
                    content,
                    attachments,
                ) {
                    Ok(message) => Some(message),
                    Err(error) => {
                        tracing::error!(
                            %error,
                            %nonce,
                            message_id = %message.id,
                            "server-accepted encrypted message could not be written to the local cache"
                        );
                        None
                    }
                }
            } else {
                match core.store.acknowledge_message(nonce, &message) {
                    Ok(message) => Some(message),
                    Err(error) => {
                        tracing::error!(
                            %error,
                            %nonce,
                            message_id = %message.id,
                            "server-accepted message could not be written to the local cache"
                        );
                        None
                    }
                }
            }
        }
        Err(error) => {
            if let Err(store_error) = core.store.record_attempt(nonce) {
                tracing::warn!(%store_error, %nonce, "message retry state could not be updated");
            }
            if error.is_terminal() || attempts.saturating_add(1) >= MAX_OUTBOX_ATTEMPTS {
                if let Err(store_error) = core.store.mark_failed(nonce) {
                    tracing::warn!(%store_error, %nonce, "message could not be marked failed");
                }
            }
            None
        }
    };
    if let Err(error) = persist_session(core) {
        tracing::warn!(%error, "rotated session could not be persisted");
    }
    if let Some(message) = updated {
        if encrypted && let Err(error) = archive_private_message(core, &message).await {
            tracing::warn!(%error, message_id = message.id, "private message recovery archive could not be updated");
        }
        let current_user_id = match current_user_id(core) {
            Ok(current_user_id) => current_user_id,
            Err(error) => {
                tracing::warn!(%error, "sent-message delta could not be constructed");
                emit_snapshot_or_warn(app, core, "message delivery failure");
                return;
            }
        };
        emit_delta(
            app,
            core,
            CoreDeltaChange::MessageUpsert {
                message: chat_message(&message, current_user_id),
                direct_unread: None,
                notify: false,
            },
        );
    } else {
        emit_snapshot_or_warn(app, core, "message delivery completion");
    }
}

async fn flush_outbox(app: &AppHandle, core: &DesktopCore) {
    let pending = match core.store.pending_messages() {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(%error, "message outbox could not be loaded");
            return;
        }
    };
    for message in pending {
        deliver_message(
            app,
            core,
            &message.nonce,
            message.attempts,
            message.channel_id,
            message.reply_to,
            &message.content,
            &message.attachments,
        )
        .await;
    }
}

async fn flush_private_history_outbox(core: &DesktopCore) {
    const BATCH_SIZE: usize = 100;
    const MAX_BATCHES: usize = 32;
    for _ in 0..MAX_BATCHES {
        let pending = match core.store.pending_private_history_archives(BATCH_SIZE) {
            Ok(pending) => pending,
            Err(error) => {
                tracing::warn!(%error, "private-history outbox could not be loaded");
                return;
            }
        };
        if pending.is_empty() {
            return;
        }
        let mut completed = 0_usize;
        for message_id in pending {
            match core.store.message_by_id(message_id) {
                Ok(Some(message)) => {
                    if let Err(error) = archive_private_message(core, &message).await {
                        tracing::debug!(
                            %error,
                            message_id,
                            "private-history archive remains queued"
                        );
                    } else {
                        completed += 1;
                    }
                }
                Ok(None) => {
                    if let Err(error) = core.store.complete_private_history_archive(message_id) {
                        tracing::warn!(
                            %error,
                            message_id,
                            "orphaned private-history outbox entry could not be removed"
                        );
                    } else {
                        completed += 1;
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, message_id, "queued private message could not be loaded");
                }
            }
        }
        if completed == 0 {
            return;
        }
    }
}

async fn retry_private_history_restore(core: &DesktopCore) {
    let archives = match core.remote.private_history().await {
        Ok(archives) => archives,
        Err(error) => {
            tracing::debug!(%error, "private-history restore retry is unavailable");
            return;
        }
    };
    let mut retry_needed = false;
    for archive in archives {
        match core.store.has_decrypted_message(archive.message_id.raw()) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                retry_needed = true;
                tracing::debug!(%error, message_id = %archive.message_id, "private-history restore lookup failed");
                continue;
            }
        }
        if let Err(error) = restore_private_message(core, None, &archive) {
            retry_needed = true;
            tracing::debug!(
                %error,
                message_id = %archive.message_id,
                "private-history restore retry remains deferred"
            );
        }
    }
    core.private_history_retry
        .store(retry_needed, AtomicOrdering::Release);
}

async fn perform_mls_maintenance(app: Option<&AppHandle>, core: &DesktopCore) {
    if let Err(error) = process_mls_inbox(core).await {
        tracing::debug!(%error, "scheduled MLS inbox processing failed");
    }
    match core.remote.pending_mls_maintenance(&core.device_id).await {
        Ok(hints) => {
            for hint in hints {
                if let Err(error) = maintain_channel_mls(core, &hint).await {
                    tracing::debug!(
                        %error,
                        channel_id = %hint.channel_id,
                        "scheduled MLS membership maintenance failed"
                    );
                } else if let Some(app) = app {
                    if let Err(error) = app.emit(CORE_AUTHORIZATION_EVENT, ()) {
                        tracing::debug!(%error, "scheduled MLS authorization refresh could not be emitted");
                    }
                }
            }
        }
        Err(error) => tracing::debug!(%error, "scheduled MLS maintenance lookup failed"),
    }
}

async fn synchronize_private_history(
    core: &DesktopCore,
    snapshot: &SyncSnapshot,
    history: &HashMap<u64, PrivateHistoryArchive>,
) -> Result<bool, RemoteError> {
    ensure_e2ee_identity(core, snapshot.current_user.id.raw()).await?;
    perform_mls_maintenance(None, core).await;
    let mut retry_needed = false;
    for message in &snapshot.messages {
        match decrypt_and_store_message(core, message) {
            Ok(Some(cached)) => {
                if !history.contains_key(&message.id.raw())
                    && let Err(error) = archive_private_message(core, &cached).await
                {
                    retry_needed = true;
                    tracing::warn!(
                        %error,
                        message_id = %message.id,
                        "private message recovery archive could not be updated"
                    );
                }
            }
            Ok(None) => {
                if message.encryption.is_some() && !history.contains_key(&message.id.raw()) {
                    let cached = core
                        .store
                        .message_by_id(message.id.raw())
                        .map_err(|error| e2ee_error(error.to_string()))?;
                    if let Some(cached) = cached
                        && let Err(error) = archive_private_message(core, &cached).await
                    {
                        retry_needed = true;
                        tracing::warn!(
                            %error,
                            message_id = %message.id,
                            "cached private message recovery archive remains queued"
                        );
                    }
                }
            }
            Err(error) => {
                if !history.contains_key(&message.id.raw()) {
                    retry_needed = true;
                    tracing::debug!(
                        %error,
                        message_id = %message.id,
                        "encrypted message has no private recovery archive"
                    );
                }
            }
        }
    }
    let snapshot_messages = snapshot
        .messages
        .iter()
        .map(|message| (message.id.raw(), message))
        .collect::<HashMap<_, _>>();
    for archive in history.values() {
        if core
            .store
            .has_decrypted_message(archive.message_id.raw())
            .map_err(|error| e2ee_error(error.to_string()))?
        {
            continue;
        }
        if let Err(error) = restore_private_message(
            core,
            snapshot_messages.get(&archive.message_id.raw()).copied(),
            archive,
        ) {
            retry_needed = true;
            tracing::debug!(
                %error,
                message_id = %archive.message_id,
                "private message history could not be restored"
            );
        }
    }
    Ok(retry_needed)
}

async fn synchronize_once(core: &DesktopCore) -> Result<(), RemoteError> {
    let snapshot = core.remote.fetch_sync().await?;
    if core.active_account_id != Some(snapshot.current_user.id.raw()) {
        return Err(RemoteError::LocalStore(
            "synchronization was refused because the server account does not match the active encrypted cache"
                .to_owned(),
        ));
    }
    {
        let mut presences = core
            .presences
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        presences.clear();
        presences.extend(
            snapshot
                .presences
                .iter()
                .cloned()
                .map(|presence| (presence.user_id.raw(), presence)),
        );
    }
    core.store
        .apply_remote_snapshot(&snapshot)
        .map_err(|error| RemoteError::LocalStore(error.to_string()))?;
    match core.remote.private_history().await {
        Ok(archives) => {
            let history = archives
                .into_iter()
                .map(|archive| (archive.message_id.raw(), archive))
                .collect::<HashMap<_, _>>();
            match synchronize_private_history(core, &snapshot, &history).await {
                Ok(retry_needed) => core
                    .private_history_retry
                    .store(retry_needed, AtomicOrdering::Release),
                Err(error) => {
                    core.private_history_retry
                        .store(true, AtomicOrdering::Release);
                    tracing::warn!(%error, "private-history synchronization deferred after server snapshot");
                }
            }
        }
        Err(error) => {
            core.private_history_retry
                .store(true, AtomicOrdering::Release);
            tracing::warn!(%error, "private-history fetch deferred after server snapshot");
        }
    }
    if let Err(error) = persist_session(core) {
        tracing::warn!(%error, "rotated session could not be persisted");
    }
    Ok(())
}

async fn apply_gateway_message(
    app: &AppHandle,
    core: &DesktopCore,
    message: &DomainMessage,
) -> Result<(), RemoteError> {
    let encrypted = message.encryption.is_some();
    let cached = if encrypted {
        match decrypt_and_store_message(core, message) {
            Ok(cached) => cached,
            Err(error) => {
                tracing::debug!(
                    %error,
                    message_id = %message.id,
                    "gateway ciphertext is not readable on this device"
                );
                None
            }
        }
    } else {
        Some(
            core.store
                .upsert_remote_message(message)
                .map_err(|error| e2ee_error(error.to_string()))?,
        )
    };
    let Some(cached) = cached else {
        return Ok(());
    };
    if encrypted && let Err(error) = archive_private_message(core, &cached).await {
        tracing::warn!(
            %error,
            message_id = %message.id,
            "gateway private-history archive could not be updated"
        );
    }
    let current_user_id = current_user_id(core)?;
    emit_delta(
        app,
        core,
        CoreDeltaChange::MessageUpsert {
            message: chat_message(&cached, current_user_id),
            direct_unread: if cached.author_id == current_user_id {
                None
            } else {
                direct_unread_delta(core, cached.channel_id)?
            },
            notify: cached.author_id != current_user_id,
        },
    );
    Ok(())
}

async fn apply_gateway_message_update(
    app: &AppHandle,
    core: &DesktopCore,
    message: &DomainMessage,
) -> Result<(), RemoteError> {
    let encrypted = message.encryption.is_some();
    let decrypted = if encrypted {
        match decrypt_message(core, message) {
            Ok((content, _)) => Some(content),
            Err(error) => {
                tracing::debug!(
                    %error,
                    message_id = %message.id,
                    "gateway message edit is not readable on this device"
                );
                return Ok(());
            }
        }
    } else {
        None
    };
    let cached = core
        .store
        .merge_remote_message_update(message, decrypted.as_deref())
        .map_err(|error| e2ee_error(error.to_string()))?;
    if encrypted && let Err(error) = archive_private_message(core, &cached).await {
        tracing::warn!(
            %error,
            message_id = %message.id,
            "edited private-history archive could not be updated"
        );
    }
    let current_user_id = current_user_id(core)?;
    emit_delta(
        app,
        core,
        CoreDeltaChange::MessageUpsert {
            message: chat_message(&cached, current_user_id),
            direct_unread: None,
            notify: false,
        },
    );
    Ok(())
}

fn apply_gateway_presence(app: &AppHandle, core: &DesktopCore, presence: UserPresence) {
    let user_id = presence.user_id;
    let online = presence.status == PresenceStatus::Online;
    let mut presences = core
        .presences
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if online {
        presences.insert(user_id.raw(), presence);
    } else {
        presences.remove(&user_id.raw());
    }
    drop(presences);
    emit_delta(
        app,
        core,
        CoreDeltaChange::Presence {
            user_id: user_id.to_string(),
            presence: if online { "online" } else { "offline" },
        },
    );
}

fn apply_gateway_user_update(
    app: &AppHandle,
    core: &DesktopCore,
    user: User,
) -> Result<(), RemoteError> {
    core.store
        .put_user(&CachedUser {
            id: user.id.raw(),
            handle: user.handle,
            display_name: user.display_name,
            avatar_url: user.avatar_url,
            origin_remote: true,
        })
        .map_err(|error| e2ee_error(error.to_string()))?;
    emit_snapshot(app, core).map_err(|error| e2ee_error(error.to_string()))?;
    Ok(())
}

async fn apply_gateway_event(
    app: &AppHandle,
    core: &DesktopCore,
    event: GatewayEvent,
) -> Result<(), RemoteError> {
    match event {
        GatewayEvent::Ready(_) => {}
        GatewayEvent::MessageCreate(message) => {
            apply_gateway_message(app, core, &message).await?;
        }
        GatewayEvent::MessageUpdate(message) => {
            apply_gateway_message_update(app, core, &message).await?;
        }
        GatewayEvent::MessageDelete(event) => {
            core.store
                .mark_message_deleted(event.id.raw(), event.channel_id.raw())
                .map_err(|error| e2ee_error(error.to_string()))?;
            emit_delta(
                app,
                core,
                CoreDeltaChange::MessageDelete {
                    message_id: event.id.to_string(),
                    channel_id: event.channel_id.to_string(),
                },
            );
        }
        GatewayEvent::ReactionUpdate(event) => {
            let current_user_id = current_user_id(core)?;
            if let Some(message) = core
                .store
                .apply_reaction_event(&event, current_user_id)
                .map_err(|error| e2ee_error(error.to_string()))?
            {
                emit_delta(
                    app,
                    core,
                    CoreDeltaChange::MessageUpsert {
                        message: chat_message(&message, current_user_id),
                        direct_unread: None,
                        notify: false,
                    },
                );
            }
        }
        GatewayEvent::PresenceUpdate(presence) => apply_gateway_presence(app, core, presence),
        GatewayEvent::UserUpdate(user) => apply_gateway_user_update(app, core, user)?,
        GatewayEvent::TypingStart(event) => remember_typing(app, core, &event),
        GatewayEvent::ReadStateUpdate(read_state) => {
            core.store
                .put_read_state(&read_state)
                .map_err(|error| e2ee_error(error.to_string()))?;
            if let Some(direct_unread) = direct_unread_delta(core, read_state.channel_id.raw())? {
                emit_delta(app, core, CoreDeltaChange::ReadState { direct_unread });
            }
        }
        GatewayEvent::MlsMembershipNeeded(hint) => {
            if let Err(error) = maintain_channel_mls(core, &hint).await {
                tracing::debug!(
                    %error,
                    channel_id = %hint.channel_id,
                    "MLS membership maintenance failed"
                );
            } else if let Err(error) = app.emit(CORE_AUTHORIZATION_EVENT, ()) {
                tracing::debug!(%error, "MLS authorization refresh could not be emitted");
            }
        }
        GatewayEvent::MlsDeliveryAvailable => {
            if let Err(error) = process_mls_inbox(core).await {
                tracing::debug!(%error, "MLS inbox processing failed");
            } else if let Err(error) = app.emit(CORE_AUTHORIZATION_EVENT, ()) {
                tracing::debug!(%error, "MLS authorization refresh could not be emitted");
            }
        }
        GatewayEvent::GuildCreate(_)
        | GatewayEvent::GuildUpdate(_)
        | GatewayEvent::GuildDelete(_)
        | GatewayEvent::ChannelCreate(_)
        | GatewayEvent::ChannelUpdate(_)
        | GatewayEvent::ChannelDelete(_)
        | GatewayEvent::RelationshipUpdate
        | GatewayEvent::DirectChannelCreate => {
            synchronize_once(core).await?;
            emit_snapshot(app, core).map_err(|error| e2ee_error(error.to_string()))?;
            app.emit(CORE_AUTHORIZATION_EVENT, ())
                .map_err(|error| e2ee_error(error.to_string()))?;
        }
    }
    Ok(())
}

async fn synchronization_loop(app: AppHandle, core: DesktopCore) {
    let mut retry_delay = 1_u64;
    loop {
        if let Err(error) = restore_session(&core).await {
            tracing::debug!(%error, "saved session restore failed");
        }
        set_connection_state(&app, &core, ConnectionState::Connecting);
        match synchronize_once(&core).await {
            Ok(()) => {
                retry_delay = 1;
                set_connection_state(&app, &core, ConnectionState::CatchingUp);
                flush_outbox(&app, &core).await;
                if let Ok(mut gateway) = core.remote.connect_gateway().await {
                    set_connection_state(&app, &core, ConnectionState::Connected);
                    emit_snapshot_or_warn(&app, &core, "initial synchronization");
                    let mut maintenance = tokio::time::interval(Duration::from_secs(15));
                    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    maintenance.tick().await;
                    loop {
                        tokio::select! {
                            event = gateway.next_event() => {
                                match event {
                                    Ok(Some(event)) => {
                                        if let Err(error) = apply_gateway_event(&app, &core, event).await {
                                            tracing::warn!(
                                                %error,
                                                "gateway update failed locally; reconnecting for a full synchronization"
                                            );
                                            break;
                                        }
                                    }
                                    Ok(None) | Err(_) => break,
                                }
                            }
                            _ = maintenance.tick() => {
                                flush_outbox(&app, &core).await;
                                flush_private_history_outbox(&core).await;
                                if core.private_history_retry.load(AtomicOrdering::Acquire) {
                                    retry_private_history_restore(&core).await;
                                }
                                perform_mls_maintenance(Some(&app), &core).await;
                                emit_snapshot_or_warn(&app, &core, "periodic maintenance");
                            }
                        }
                    }
                }
            }
            Err(error) => {
                tracing::debug!(%error, "remote synchronization unavailable");
            }
        }
        core.presences
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        core.typing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        set_connection_state(&app, &core, ConnectionState::Offline);
        emit_snapshot_or_warn(&app, &core, "connection loss");
        tokio::time::sleep(Duration::from_secs(retry_delay)).await;
        retry_delay = (retry_delay * 2).min(30);
    }
}

fn remember_typing(app: &AppHandle, core: &DesktopCore, event: &TypingEvent) {
    let key = (event.channel_id.raw(), event.user_id.raw());
    core.typing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, event.clone());
    emit_delta(
        app,
        core,
        CoreDeltaChange::TypingUpsert {
            typing: TypingView {
                channel_id: event.channel_id.to_string(),
                user_id: event.user_id.to_string(),
                expires_at: event.expires_at.to_rfc3339(),
            },
        },
    );
    let event = event.clone();
    let app = app.clone();
    let core = core.clone();
    tauri::async_runtime::spawn(async move {
        let delay = (event.expires_at - Utc::now()).to_std().unwrap_or_default();
        tokio::time::sleep(delay).await;
        let mut typing = core
            .typing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = typing
            .get(&key)
            .is_some_and(|current| current.expires_at <= Utc::now())
            && typing.remove(&key).is_some();
        drop(typing);
        if removed {
            emit_delta(
                &app,
                &core,
                CoreDeltaChange::TypingRemove {
                    channel_id: event.channel_id.to_string(),
                    user_id: event.user_id.to_string(),
                },
            );
        }
    });
}

fn seed_local_store(
    store: &LocalStore,
    ids: &SnowflakeGenerator,
) -> Result<(), Box<dyn std::error::Error>> {
    if !store.is_empty()? {
        return Ok(());
    }
    let user_id = 1;
    let guild_id = ids.generate()?.raw();
    let channel_id = ids.generate()?.raw();
    let message_id = ids.generate()?.raw();
    let now = Utc::now();
    store.put_user(&CachedUser {
        id: user_id,
        handle: "erix".into(),
        display_name: "Erix".into(),
        avatar_url: None,
        origin_remote: false,
    })?;
    store.put_guild(&CachedGuild {
        id: guild_id,
        owner_id: user_id,
        name: "On this device".into(),
        accent: 0x006E_7685,
        created_at: now.to_rfc3339(),
        current_permissions: GuildPermissions::ALL.bits(),
        origin_remote: false,
    })?;
    store.put_channel(&CachedChannel {
        id: channel_id,
        guild_id,
        name: "notes".into(),
        kind: ChannelKind::Text,
        position: 0,
        encrypted: false,
        created_at: now.to_rfc3339(),
        origin_remote: false,
    })?;
    store.put_message(&CachedMessage {
        id: message_id,
        client_key: message_id.to_string(),
        channel_id,
        author_id: user_id,
        reply_to: None,
        content: "This private channel stays on this device. Remote servers appear when the development backend is available.".into(),
        attachments: Vec::new(),
        reactions: Vec::new(),
        sequence: 0,
        created_at: now.to_rfc3339(),
        edited_at: None,
        state: MessageState::Sent,
        nonce: None,
        origin_remote: false,
    })?;
    store.set_current_user(user_id)?;
    store.set_active_context(guild_id, channel_id, None)?;
    Ok(())
}

fn cache_artifact_paths(cache_path: &std::path::Path) -> Result<Vec<std::path::PathBuf>, String> {
    let filename = cache_path
        .file_name()
        .ok_or_else(|| "the local cache filename is unavailable".to_owned())?;
    let mut paths = vec![cache_path.to_path_buf()];
    for suffix in [
        "-wal",
        "-shm",
        "-journal",
        ".encrypted-migrating",
        ".plaintext-backup",
    ] {
        let mut companion = std::ffi::OsString::from(filename);
        companion.push(suffix);
        paths.push(cache_path.with_file_name(companion));
    }
    Ok(paths)
}

fn preserve_cache_artifacts(
    cache_path: &std::path::Path,
    recovery_root: &std::path::Path,
    reason: &str,
    detail: &str,
) -> Result<std::path::PathBuf, String> {
    std::fs::create_dir_all(recovery_root)
        .map_err(|error| format!("the cache recovery folder could not be created: {error}"))?;
    let recovery_directory = recovery_root.join(format!(
        "cache-{}-{}",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        Uuid::now_v7()
    ));
    std::fs::create_dir(&recovery_directory)
        .map_err(|error| format!("the cache recovery set could not be created: {error}"))?;

    let mut moved = Vec::new();
    for source in cache_artifact_paths(cache_path)?
        .into_iter()
        .filter(|candidate| candidate.exists())
    {
        let filename = source
            .file_name()
            .ok_or_else(|| "a cache recovery filename is unavailable".to_owned())?;
        let destination = recovery_directory.join(filename);
        if let Err(error) = std::fs::rename(&source, &destination) {
            let rollback = rollback_cache_creation(&moved, &recovery_directory);
            return Err(format!(
                "the local cache could not be preserved before reset: {error}{rollback}"
            ));
        }
        moved.push((source, destination));
    }

    let manifest = serde_json::json!({
        "format": 1,
        "recordedAt": Utc::now().to_rfc3339(),
        "reason": reason,
        "detail": detail,
        "originalPath": cache_path.to_string_lossy(),
        "files": moved
            .iter()
            .filter_map(|(_, destination)| destination.file_name())
            .map(|filename| filename.to_string_lossy())
            .collect::<Vec<_>>(),
    });
    let manifest_path = recovery_directory.join("recovery.json");
    let encoded = match serde_json::to_vec_pretty(&manifest) {
        Ok(encoded) => encoded,
        Err(error) => {
            let rollback = rollback_cache_creation(&moved, &recovery_directory);
            return Err(format!(
                "the cache recovery record could not be encoded: {error}{rollback}"
            ));
        }
    };
    if let Err(error) = std::fs::write(&manifest_path, encoded) {
        let rollback = rollback_cache_creation(&moved, &recovery_directory);
        return Err(format!(
            "the cache recovery record could not be written: {error}{rollback}"
        ));
    }
    Ok(recovery_directory)
}

fn rollback_cache_moves(moved: &[(std::path::PathBuf, std::path::PathBuf)]) -> Result<(), String> {
    let mut failures = Vec::new();
    for (source, destination) in moved.iter().rev() {
        if let Err(error) = std::fs::rename(destination, source) {
            failures.push(format!(
                "{} -> {}: {error}",
                destination.display(),
                source.display()
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn rollback_cache_creation(
    moved: &[(std::path::PathBuf, std::path::PathBuf)],
    recovery_directory: &std::path::Path,
) -> String {
    if let Err(error) = rollback_cache_moves(moved) {
        return format!(
            ". Automatic rollback also failed ({error}); preserved files remain in {}",
            recovery_directory.display()
        );
    }
    match std::fs::remove_dir(recovery_directory) {
        Ok(()) => String::new(),
        Err(error) => format!(
            ". The cache was restored, but its empty recovery folder could not be removed: {error}"
        ),
    }
}

fn restore_cache_artifacts(
    cache_path: &std::path::Path,
    recovery_directory: &std::path::Path,
) -> Result<(), String> {
    let parent = cache_path
        .parent()
        .ok_or_else(|| "the local cache folder is unavailable".to_owned())?;
    let entries = std::fs::read_dir(recovery_directory)
        .map_err(|error| format!("the preserved cache set could not be read: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("a preserved cache artifact could not be read: {error}"))?;
    let mut moves = entries
        .into_iter()
        .filter(|entry| entry.file_name() != std::ffi::OsStr::new("recovery.json"))
        .map(|entry| {
            let destination = parent.join(entry.file_name());
            (entry.path(), destination)
        })
        .collect::<Vec<_>>();
    moves.sort_by(|left, right| left.0.cmp(&right.0));
    if moves.iter().any(|(_, destination)| destination.exists()) {
        return Err("a new cache artifact appeared before rollback".to_owned());
    }

    let mut restored = Vec::new();
    for (source, destination) in &moves {
        if let Err(error) = std::fs::rename(source, destination) {
            let rollback = rollback_cache_moves(&restored).map_or_else(
                |rollback_error| {
                    format!(
                        ". Automatic rollback also failed ({rollback_error}); preserved files remain in {}",
                        recovery_directory.display()
                    )
                },
                |()| String::new(),
            );
            return Err(format!(
                "the preserved cache could not be restored: {error}{rollback}"
            ));
        }
        restored.push((source.clone(), destination.clone()));
    }
    let manifest = recovery_directory.join("recovery.json");
    if manifest.exists() {
        std::fs::remove_file(&manifest)
            .map_err(|error| format!("the cache recovery record could not be removed: {error}"))?;
    }
    std::fs::remove_dir(recovery_directory)
        .map_err(|error| format!("the empty cache recovery folder could not be removed: {error}"))
}

fn show_main_window<R: tauri::Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
        // A hidden window can still be minimized. Restore it before showing so
        // tray activation always brings the main UI back to a usable state.
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn handle_single_instance<R: tauri::Runtime>(app: &AppHandle<R>, _args: Vec<String>, _cwd: String) {
    // The single-instance plugin invokes this in the already-running process;
    // the secondary process exits before its tray or credential/session setup.
    show_main_window(app);
}

fn should_minimize_to_tray(window_label: &str, minimize_to_tray: bool) -> bool {
    window_label == MAIN_WINDOW_LABEL && minimize_to_tray
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Starts the native Exo Link shell.
///
/// # Errors
///
/// Returns an error if Tauri cannot initialize or run the native application loop.
#[allow(clippy::too_many_lines)]
pub fn run() -> Result<(), tauri::Error> {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(handle_single_instance))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            bootstrap_view_model,
            retry_local_cache,
            open_local_cache_folder,
            reset_local_cache,
            network_configuration,
            notification_settings,
            save_notification_settings,
            window_settings,
            save_window_settings,
            probe_network_configuration,
            check_for_update,
            install_available_update,
            save_network_configuration,
            operator_info,
            open_operator_resource,
            auth_status,
            update_profile,
            device_security_status,
            revoke_device,
            register_with_password,
            login_with_password,
            activate_authenticated_account,
            change_password,
            recover_password,
            regenerate_recovery_codes,
            account_auth_methods,
            link_apple,
            unlink_apple,
            request_login_code,
            verify_login_code,
            login_with_apple,
            logout_session,
            account_deletion_status,
            export_account_data,
            schedule_account_deletion,
            cancel_account_deletion,
            request_friend,
            accept_friend,
            remove_relationship,
            block_user,
            open_direct_message,
            acknowledge_read_state,
            start_typing,
            create_workspace,
            create_workspace_invite,
            preview_server_invite,
            accept_server_invite,
            load_server_ownership,
            transfer_server_ownership,
            delete_server,
            load_server_roles,
            create_server_role,
            update_server_role,
            delete_server_role,
            set_server_member_role,
            load_server_channels,
            create_server_channel,
            create_voice_grant,
            update_server_channel,
            delete_server_channel,
            load_channel_overwrites,
            set_server_channel_overwrite,
            delete_server_channel_overwrite,
            load_server_moderation,
            create_automod_rule,
            update_automod_rule,
            delete_automod_rule,
            timeout_server_member,
            kick_server_member,
            ban_server_member,
            unban_server_member,
            prepare_attachment,
            complete_attachment,
            channel_is_end_to_end_encrypted,
            report_message,
            search_messages,
            open_search_hit,
            send_message,
            edit_message,
            delete_message,
            update_message_reaction,
            set_active_context,
            retry_outbox,
            window_action
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let minimize_to_tray =
                    window
                        .app_handle()
                        .try_state::<DesktopCore>()
                        .is_some_and(|state| {
                            state
                                .settings
                                .lock()
                                .map(|settings| {
                                    should_minimize_to_tray(
                                        window.label(),
                                        settings.minimize_to_tray,
                                    )
                                })
                                .unwrap_or(false)
                        });
                if minimize_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
            // Build the main window in code so Windows WebView2 can receive
            // optional CDP browser args (env WEBVIEW2_* is ignored when wry
            // supplies additionalBrowserArguments). Set EXOLINK_CDP=1 or a port.
            let mut main_window = WebviewWindowBuilder::new(
                app,
                MAIN_WINDOW_LABEL,
                WebviewUrl::App("index.html".into()),
            )
            .title("Exo Link")
            .inner_size(1400.0, 900.0)
            .min_inner_size(1100.0, 700.0)
            .center()
            .decorations(false)
            .resizable(true)
            .visible(true)
            .background_color(tauri::window::Color(0, 0, 0, 255));

            #[cfg(windows)]
            {
                // Keep wry defaults; append remote debugging only when requested.
                let mut browser_args = String::from(
                    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --autoplay-policy=no-user-gesture-required",
                );
                if let Ok(value) = std::env::var("EXOLINK_CDP") {
                    let port = if value == "1" || value.eq_ignore_ascii_case("true") {
                        "9223".to_owned()
                    } else if value.chars().all(|c| c.is_ascii_digit()) {
                        value
                    } else {
                        "9223".to_owned()
                    };
                    browser_args.push_str(&format!(
                        " --remote-debugging-port={port} --remote-allow-origins=*"
                    ));
                    tracing::info!(%port, "Exo Link CDP debugging enabled via EXOLINK_CDP");
                }
                main_window = main_window.additional_browser_args(&browser_args);
            }

            main_window.build()?;

            let show_item = MenuItem::with_id(app, "show", "Show Exo Link", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit Exo Link", true, None::<&str>)?;
            let tray_menu = Menu::with_items(app, &[&show_item, &quit_item])?;
            let tray_icon = app
                .default_window_icon()
                .cloned()
                .ok_or_else(|| std::io::Error::other("the Exo Link tray icon is unavailable"))?;
            TrayIconBuilder::with_id("main-tray")
                .icon(tray_icon)
                .tooltip("Exo Link")
                .menu(&tray_menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;
            let data_directory = app.path().app_data_dir()?;
            let active_account_id = read_active_account(&data_directory).unwrap_or_else(|error| {
                tracing::warn!(%error, "invalid active account marker was ignored");
                None
            });
            let cache_path = active_account_id.map_or_else(
                || {
                    data_directory
                        .join("accounts")
                        .join("signed-out")
                        .join("client.sqlite3")
                },
                |account_id| account_cache_path(&data_directory, account_id),
            );
            let ids = Arc::new(SnowflakeGenerator::new(31, 31)?);
            let (store, vault, cache_recovery, mls_device_key) =
                match std::fs::create_dir_all(&data_directory) {
                    Err(error) => (
                        Arc::new(LocalStore::open_in_memory()?),
                        None,
                        Some(CacheRecoveryState {
                            kind: CacheRecoveryKind::StorageFailed,
                            detail: format!(
                                "the local cache directory could not be created: {error}"
                            ),
                            cache_path: cache_path.clone(),
                            can_reset: false,
                        }),
                        None,
                    ),
                    Ok(()) => match active_account_id {
                        None => (Arc::new(LocalStore::open_in_memory()?), None, None, None),
                        Some(active_account_id) => match CredentialVault::open(active_account_id) {
                            Err(error) => (
                                Arc::new(LocalStore::open_in_memory()?),
                                None,
                                Some(CacheRecoveryState {
                                    kind: CacheRecoveryKind::VaultUnavailable,
                                    detail: error,
                                    cache_path: cache_path.clone(),
                                    can_reset: false,
                                }),
                                None,
                            ),
                            Ok(vault) => match vault.load_or_create_cache_key() {
                                Err(error) => (
                                    Arc::new(LocalStore::open_in_memory()?),
                                    Some(vault),
                                    Some(CacheRecoveryState {
                                        kind: CacheRecoveryKind::CacheKeyUnavailable,
                                        detail: error,
                                        cache_path: cache_path.clone(),
                                        can_reset: true,
                                    }),
                                    None,
                                ),
                                Ok(key) => {
                                    let key = Zeroizing::new(key);
                                    if let Some(parent) = cache_path.parent() {
                                        std::fs::create_dir_all(parent)?;
                                    }
                                    match LocalStore::open_encrypted(&cache_path, &key) {
                                        Err(error) => {
                                            let recovery = CacheRecoveryState::from_store_error(
                                                cache_path.clone(),
                                                &error,
                                            );
                                            (
                                                Arc::new(LocalStore::open_in_memory()?),
                                                Some(vault),
                                                Some(recovery),
                                                None,
                                            )
                                        }
                                        Ok(opened_store) => {
                                            let store = Arc::new(opened_store);
                                            seed_local_store(&store, &ids)?;
                                            let device_key = Some(
                                                vault
                                                    .load_or_create_device_key()
                                                    .map_err(std::io::Error::other)?,
                                            );
                                            (store, Some(vault), None, device_key)
                                        }
                                    }
                                }
                            },
                        },
                    },
                };
            let cache_ready = active_account_id.is_some() && cache_recovery.is_none();
            let device_id = startup_device_id(&data_directory, active_account_id)?;
            let network = resolve_network_configuration(&data_directory);
            let settings = read_desktop_settings(&network.settings_path).unwrap_or_else(|error| {
                tracing::warn!(%error, "desktop settings could not be loaded");
                DesktopSettings::default()
            });
            let remote = ApiClient::new(
                &network.api_url,
                std::env::var("EXOCORD_DEV_USER_ID").unwrap_or_else(|_| "1".to_owned()),
            )?;
            remote.set_device_id(device_id.clone());
            let core = DesktopCore {
                store,
                remote,
                network,
                settings: Arc::new(Mutex::new(settings)),
                ids,
                connection: Arc::new(Mutex::new(ConnectionState::Offline)),
                revision: Arc::new(AtomicU64::new(0)),
                device_id,
                data_directory,
                active_account_id,
                vault,
                mls: Arc::new(Mutex::new(None)),
                mls_device_key,
                mls_setup: Arc::new(tokio::sync::Mutex::new(())),
                mls_published: Arc::new(AtomicBool::new(false)),
                private_history_retry: Arc::new(AtomicBool::new(false)),
                update_installing: Arc::new(AtomicBool::new(false)),
                auth_restore: Arc::new(tokio::sync::Mutex::new(())),
                presences: Arc::new(Mutex::new(HashMap::new())),
                typing: Arc::new(Mutex::new(HashMap::new())),
                cache_recovery,
            };
            app.manage(core.clone());
            if cache_ready {
                tauri::async_runtime::spawn(synchronization_loop(app.handle().clone(), core));
            }
            #[cfg(debug_assertions)]
            app.get_webview_window("main")
                .ok_or("main window is unavailable")?
                .open_devtools();
            Ok(())
        })
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_compares_release_versions_without_lexical_errors() {
        assert!(version_is_newer("0.1.10", "0.1.9"));
        assert!(version_is_newer("v1.0.0-alpha", "0.99.99"));
        assert!(!version_is_newer("0.1.10", "0.1.10"));
        assert!(!version_is_newer("0.1.9", "0.1.10"));
        assert!(!version_is_newer("latest", "0.1.10"));
    }

    #[test]
    fn updater_rejects_unsafe_filenames_and_checksums() {
        let valid = UpdateManifest {
            version: "99.0.0".to_owned(),
            filename: "Exo Link-99.0.0-x64-setup.exe".to_owned(),
            sha256: "a".repeat(64),
            notes: "Test release".to_owned(),
        };
        assert!(validate_update_manifest(&valid).is_ok());

        let mut traversal = valid.clone();
        traversal.filename = "../Exo Link.exe".to_owned();
        assert!(validate_update_manifest(&traversal).is_err());

        let mut bad_checksum = valid;
        bad_checksum.sha256 = "not-a-sha256".to_owned();
        assert!(validate_update_manifest(&bad_checksum).is_err());
    }

    #[test]
    fn updater_uses_silent_install_without_desktop_shortcut_and_single_restart_arguments() {
        assert_eq!(UPDATE_INSTALLER_ARGUMENTS, ["/S", "/NS", "/R"]);
    }

    #[test]
    fn single_instance_callback_targets_the_existing_main_window() {
        // The callback receives the primary app handle from the plugin. Keep
        // its target explicit so a future refactor cannot accidentally create
        // a second tray/window instead of restoring the primary UI.
        assert_eq!(MAIN_WINDOW_LABEL, "main");
    }

    #[test]
    fn cache_reset_requires_the_exact_confirmation_phrase() {
        assert!(cache_reset_confirmed(CACHE_RESET_CONFIRMATION));
        assert!(cache_reset_confirmed(&format!(
            "  {CACHE_RESET_CONFIRMATION}\n"
        )));
        assert!(!cache_reset_confirmed("reset local cache"));
        assert!(!cache_reset_confirmed("RESET LOCAL"));
    }

    #[test]
    fn account_deletion_requires_the_exact_confirmation_phrase() {
        assert!(account_delete_confirmed(ACCOUNT_DELETE_CONFIRMATION));
        assert!(account_delete_confirmed(&format!(
            " {ACCOUNT_DELETE_CONFIRMATION}\n"
        )));
        assert!(!account_delete_confirmed("delete my account"));
        assert!(!account_delete_confirmed("DELETE ACCOUNT"));
    }

    #[test]
    fn current_member_presence_follows_connection_state() {
        let current = CachedUser {
            id: 7,
            handle: "current".into(),
            display_name: "Current".into(),
            avatar_url: None,
            origin_remote: true,
        };
        let mut presences = HashMap::new();
        presences.insert(
            current.id,
            UserPresence {
                user_id: UserId::from_raw(current.id).unwrap(),
                status: PresenceStatus::Online,
                updated_at: Utc::now(),
            },
        );
        assert_eq!(
            member(&current, current.id, ConnectionState::Offline, &presences).presence,
            "offline"
        );
        assert_eq!(
            member(
                &current,
                current.id,
                ConnectionState::Connecting,
                &presences
            )
            .presence,
            "offline"
        );
        assert_eq!(
            member(&current, current.id, ConnectionState::Connected, &presences).presence,
            "online"
        );

        let external = CachedUser {
            id: 8,
            handle: "external".into(),
            display_name: "External".into(),
            avatar_url: None,
            origin_remote: true,
        };
        presences.insert(
            external.id,
            UserPresence {
                user_id: UserId::from_raw(external.id).unwrap(),
                status: PresenceStatus::Online,
                updated_at: Utc::now(),
            },
        );
        assert_eq!(
            member(&external, current.id, ConnectionState::Offline, &presences).presence,
            "online"
        );
    }

    #[test]
    fn device_id_is_trimmed_validated_and_repaired_durably() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device-id");
        let expected = Uuid::now_v7();
        std::fs::write(&path, format!("  {expected}\n")).unwrap();
        assert_eq!(
            load_or_create_device_id(&path).unwrap(),
            expected.to_string()
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            expected.to_string()
        );

        std::fs::write(&path, "not-a-device-id").unwrap();
        let repaired = load_or_create_device_id(&path).unwrap();
        assert!(Uuid::parse_str(&repaired).is_ok());
        assert_ne!(repaired, "not-a-device-id");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), repaired);
    }

    #[test]
    fn device_ids_are_scoped_per_account_and_legacy_sessions_still_restore() {
        let directory = tempfile::tempdir().unwrap();
        let legacy = Uuid::now_v7().to_string();
        persist_device_id(&directory.path().join("device-id"), &legacy).unwrap();
        assert_eq!(
            startup_device_id(directory.path(), Some(11)).unwrap(),
            legacy
        );

        let account_a = Uuid::now_v7().to_string();
        let account_b = Uuid::now_v7().to_string();
        persist_device_id(&account_device_path(directory.path(), 11), &account_a).unwrap();
        persist_device_id(&account_device_path(directory.path(), 22), &account_b).unwrap();
        assert_eq!(
            startup_device_id(directory.path(), Some(11)).unwrap(),
            account_a
        );
        assert_eq!(
            startup_device_id(directory.path(), Some(22)).unwrap(),
            account_b
        );
        assert_ne!(
            account_device_path(directory.path(), 11),
            account_device_path(directory.path(), 22)
        );
    }

    #[test]
    fn signed_out_startup_uses_an_unpersisted_one_time_device() {
        let directory = tempfile::tempdir().unwrap();
        let first = startup_device_id(directory.path(), None).unwrap();
        let second = startup_device_id(directory.path(), None).unwrap();
        assert!(Uuid::parse_str(&first).is_ok());
        assert!(Uuid::parse_str(&second).is_ok());
        assert_ne!(first, second);
        assert!(!directory.path().join("device-id").exists());
    }

    #[test]
    fn core_delta_variant_fields_match_the_renderer_camel_case_contract() {
        let read_state = CoreDelta {
            version: 1,
            revision: 9,
            change: CoreDeltaChange::ReadState {
                direct_unread: DirectUnreadDelta {
                    channel_id: "71".to_owned(),
                    unread: false,
                    unread_count: 2,
                },
            },
        };
        let read_state = serde_json::to_value(read_state).unwrap();
        assert_eq!(read_state["type"], "read_state");
        assert_eq!(read_state["directUnread"]["channelId"], "71");
        assert_eq!(read_state["directUnread"]["unreadCount"], 2);
        assert!(read_state.get("direct_unread").is_none());

        let deletion = CoreDelta {
            version: 1,
            revision: 10,
            change: CoreDeltaChange::MessageDelete {
                message_id: "81".to_owned(),
                channel_id: "71".to_owned(),
            },
        };
        let deletion = serde_json::to_value(deletion).unwrap();
        assert_eq!(deletion["messageId"], "81");
        assert_eq!(deletion["channelId"], "71");
        assert!(deletion.get("message_id").is_none());
        assert!(deletion.get("channel_id").is_none());
    }

    #[test]
    fn revoked_device_checks_fail_closed_when_the_mls_group_is_unreadable() {
        let mut client = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let current_device = client.device_id();
        assert!(devices_still_in_group(&client, 71, &[current_device]).is_err());

        client.create_group(71, &[]).unwrap();
        assert_eq!(
            devices_still_in_group(&client, 71, &[current_device]).unwrap(),
            vec![current_device]
        );
        assert!(
            devices_still_in_group(&client, 71, &[Uuid::now_v7()])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn network_urls_require_https_except_for_loopback_development() {
        assert_eq!(
            normalize_api_url(" https://alpha.example.com/ ").unwrap(),
            ("https://alpha.example.com".to_owned(), true)
        );
        assert_eq!(
            normalize_api_url("http://127.0.0.1:4100").unwrap(),
            ("http://127.0.0.1:4100".to_owned(), false)
        );
        assert!(normalize_api_url("http://alpha.example.com").is_err());
        assert!(normalize_api_url("https://user:secret@alpha.example.com").is_err());
        assert!(normalize_api_url("https://alpha.example.com?token=secret").is_err());
    }

    #[test]
    fn network_settings_replace_cleanly_without_leaving_credentials_or_backups() {
        let directory = tempfile::tempdir().unwrap();
        let settings_path = directory.path().join("settings.json");
        save_network_settings(&settings_path, "https://one.example.com").unwrap();
        save_network_settings(&settings_path, "https://two.example.com").unwrap();
        let settings: DesktopSettings =
            serde_json::from_slice(&std::fs::read(&settings_path).unwrap()).unwrap();
        assert_eq!(settings.api_url.as_deref(), Some("https://two.example.com"));
        assert!(!settings_path.with_extension("json.tmp").exists());
        assert!(!settings_path.with_extension("json.bak").exists());
    }

    #[test]
    fn tray_minimize_defaults_on_and_survives_legacy_settings() {
        assert!(DesktopSettings::default().minimize_to_tray);
        let legacy: DesktopSettings = serde_json::from_str(
            r#"{"apiUrl":"https://alpha.example.com","notificationMode":"private"}"#,
        )
        .unwrap();
        assert!(legacy.minimize_to_tray);
    }

    #[test]
    fn tray_close_decision_only_hides_main_window_when_enabled() {
        assert!(should_minimize_to_tray("main", true));
        assert!(!should_minimize_to_tray("main", false));
        assert!(!should_minimize_to_tray("settings", true));
    }

    #[test]
    fn packaged_alpha_server_overrides_stale_saved_networks() {
        let directory = tempfile::tempdir().unwrap();
        save_network_settings(
            &directory.path().join("settings.json"),
            "http://127.0.0.1:4100",
        )
        .unwrap();

        let network = resolve_network_configuration_from(
            directory.path(),
            None,
            Some("https://api.alpha.example.com"),
        );

        assert_eq!(network.source, "build");
        assert_eq!(network.api_url, "https://api.alpha.example.com");
        assert!(network.secure);
    }

    #[test]
    fn explicit_environment_network_still_overrides_packaged_alpha() {
        let directory = tempfile::tempdir().unwrap();
        let network = resolve_network_configuration_from(
            directory.path(),
            Some("http://127.0.0.1:4100"),
            Some("https://api.alpha.example.com"),
        );

        assert_eq!(network.source, "environment");
        assert_eq!(network.api_url, "http://127.0.0.1:4100");
        assert!(!network.secure);
    }

    #[test]
    fn account_markers_and_cache_paths_are_strictly_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let account_a = 11_u64;
        let account_b = 22_u64;
        let cache_a = account_cache_path(directory.path(), account_a);
        let cache_b = account_cache_path(directory.path(), account_b);

        assert_ne!(cache_a, cache_b);
        assert_eq!(
            cache_a,
            directory
                .path()
                .join("accounts")
                .join(account_a.to_string())
                .join("client.sqlite3")
        );
        assert_eq!(
            cache_b,
            directory
                .path()
                .join("accounts")
                .join(account_b.to_string())
                .join("client.sqlite3")
        );

        assert_eq!(read_active_account(directory.path()).unwrap(), None);
        write_active_account(directory.path(), account_a).unwrap();
        assert_eq!(
            read_active_account(directory.path()).unwrap(),
            Some(account_a)
        );
        write_active_account(directory.path(), account_b).unwrap();
        assert_eq!(
            read_active_account(directory.path()).unwrap(),
            Some(account_b)
        );
        clear_active_account(directory.path()).unwrap();
        assert_eq!(read_active_account(directory.path()).unwrap(), None);
    }

    #[test]
    fn remote_alpha_networks_require_durable_media_and_voice_services() {
        let mut probe = ServerProbe {
            ready: true,
            storage: "memory".to_owned(),
            attachments: "disabled".to_owned(),
            password: true,
            email: true,
            apple: false,
            development_code_preview: true,
            conversation_actions: ALPHA_CONVERSATION_CAPABILITY.to_owned(),
            native_voice: "not_configured".to_owned(),
            operator: OperatorInfo {
                name: "Test alpha".to_owned(),
                privacy_url: Some("https://alpha.example.test/privacy".to_owned()),
                terms_url: None,
                support_email: Some("help@alpha.example.test".to_owned()),
                abuse_email: Some("abuse@alpha.example.test".to_owned()),
            },
        };
        assert!(ensure_alpha_server_compatible(&probe, false).is_ok());
        assert!(ensure_alpha_server_compatible(&probe, true).is_err());
        probe.storage = "postgres".to_owned();
        probe.attachments = "r2".to_owned();
        probe.native_voice = "livekit_sframe_mls_exporter".to_owned();
        assert!(ensure_alpha_server_compatible(&probe, true).is_ok());
        probe.operator.privacy_url = Some("javascript:alert(1)".to_owned());
        assert!(ensure_alpha_server_compatible(&probe, true).is_err());
    }

    #[test]
    fn private_history_accepts_raw_legacy_text_only_with_server_metadata() {
        let legacy =
            decode_private_history_payload(b"clean install keeps this exact private DM", true)
                .unwrap();
        assert_eq!(legacy.version, 0);
        assert_eq!(legacy.content, "clean install keeps this exact private DM");
        assert!(legacy.attachments.is_empty());
        assert!(
            decode_private_history_payload(b"clean install keeps this exact private DM", false)
                .is_err()
        );
    }

    #[test]
    fn private_history_rejects_invalid_binary_legacy_payloads() {
        assert!(decode_private_history_payload(&[0xff, 0xfe, 0xfd], true).is_err());
    }

    #[test]
    fn cache_recovery_preserves_every_candidate_and_can_roll_back() {
        let directory = tempfile::tempdir().unwrap();
        let application = directory.path().join("app");
        std::fs::create_dir(&application).unwrap();
        let cache_path = application.join("client.sqlite3");
        let candidates = cache_artifact_paths(&cache_path).unwrap();
        let expected = [
            (candidates[0].clone(), b"encrypted-main".as_slice()),
            (candidates[1].clone(), b"encrypted-wal".as_slice()),
            (candidates[4].clone(), b"migration-temp".as_slice()),
            (candidates[5].clone(), b"plaintext-backup".as_slice()),
        ];
        for (path, content) in &expected {
            std::fs::write(path, content).unwrap();
        }

        let recovery = preserve_cache_artifacts(
            &cache_path,
            &application.join("cache-recovery"),
            "cache_locked",
            "test-only recovery",
        )
        .unwrap();
        for (original, content) in &expected {
            assert!(!original.exists());
            assert_eq!(
                std::fs::read(recovery.join(original.file_name().unwrap())).unwrap(),
                *content
            );
        }
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(recovery.join("recovery.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["format"], 1);
        assert_eq!(manifest["reason"], "cache_locked");
        assert_eq!(manifest["files"].as_array().unwrap().len(), expected.len());

        restore_cache_artifacts(&cache_path, &recovery).unwrap();
        assert!(!recovery.exists());
        for (original, content) in &expected {
            assert_eq!(std::fs::read(original).unwrap(), *content);
        }
    }

    #[test]
    fn cache_recovery_distinguishes_reinstall_from_explicit_reset() {
        let path = std::path::PathBuf::from("client.sqlite3");
        let unavailable = CacheRecoveryState::from_store_error(
            path.clone(),
            &exo_client::StoreError::EncryptionUnavailable,
        );
        assert!(!unavailable.view().can_reset);
        assert_eq!(unavailable.view().reason, "encryption_unavailable");

        let locked =
            CacheRecoveryState::from_store_error(path, &exo_client::StoreError::CacheUnlockFailed);
        assert!(locked.view().can_reset);
        assert_eq!(locked.view().reason, "cache_locked");
    }
}
