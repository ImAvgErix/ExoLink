use std::{
    collections::HashSet,
    path::Path,
    sync::{Arc, Mutex},
};

use argon2::{
    Algorithm, Argon2, Params as Argon2Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Duration, Utc};
use exo_domain::{UserId, WrappedAccountKey};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::apple::AppleConfig;

const ACCESS_LIFETIME_MINUTES: i64 = 15;
const REFRESH_LIFETIME_DAYS: i64 = 30;
const EMAIL_CODE_LIFETIME_MINUTES: i64 = 10;
const MAX_CODE_ATTEMPTS: i64 = 5;
const ACCOUNT_DELETION_GRACE_DAYS: i64 = 30;
const MIN_PASSWORD_CHARACTERS: usize = 10;
const MAX_PASSWORD_CHARACTERS: usize = 128;
const MAX_PASSWORD_BYTES: usize = 512;
const RECOVERY_CODE_COUNT: usize = 8;

#[derive(Clone)]
pub struct AuthService {
    connection: Arc<Mutex<Connection>>,
    dummy_password_hash: Arc<str>,
    pub delivery: EmailDelivery,
    pub apple: Option<AppleConfig>,
}

#[derive(Clone)]
pub enum EmailDelivery {
    Disabled,
    DevelopmentConsole,
    Resend { api_key: String, from: String },
}

#[derive(Clone, Debug)]
pub struct EmailChallenge {
    pub id: String,
    pub email: String,
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionBundle {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: String,
    pub refresh_expires_at: String,
    pub user: AuthUser,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedAccountKey>,
}

#[derive(Clone, Debug)]
pub struct RecoveryKeyVault {
    pub recovery_code: String,
    pub wrapped_key: WrappedAccountKey,
}

#[derive(Clone, Debug)]
pub struct RecoveryPreparation {
    pub user_id: UserId,
    pub wrapped_key: Option<WrappedAccountKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub deletion_scheduled_for: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDeletion {
    pub requested_at: String,
    pub scheduled_for: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthDataExport {
    pub profile: AuthUser,
    pub created_at: String,
    pub external_identities: Vec<AuthExportIdentity>,
    pub sessions: Vec<AuthExportSession>,
    pub account_enforcement: Vec<AccountEnforcementEvent>,
    pub deletion: Option<AccountDeletion>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthExportIdentity {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthExportSession {
    pub id: String,
    pub device_id: String,
    pub client_name: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub user_id: UserId,
    pub session_id: String,
    pub device_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct AppleFlow {
    pub nonce: String,
    pub linking: bool,
}

#[derive(Clone, Debug)]
pub enum AppleFlowPoll {
    Pending,
    Complete(Box<SessionBundle>),
    Failed(String),
}

#[derive(Clone, Debug)]
pub enum AppleLinkPoll {
    Pending,
    Complete,
    Failed(String),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAuthMethods {
    pub password_set: bool,
    pub apple_linked: bool,
    pub apple_email: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSuspension {
    pub user_id: String,
    pub suspended: bool,
    pub suspended_at: Option<String>,
    pub suspended_by: Option<String>,
    pub reason: Option<String>,
    pub report_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountEnforcementEvent {
    pub id: String,
    pub action: String,
    pub operator: String,
    pub reason: String,
    pub report_id: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountEnforcementOverview {
    pub suspension: AccountSuspension,
    pub events: Vec<AccountEnforcementEvent>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("authentication storage is unavailable")]
    Storage,
    #[error("the email address is invalid")]
    InvalidEmail,
    #[error(
        "username must be 3–32 letters, numbers, underscores, or hyphens and start with a letter or number"
    )]
    InvalidUsername,
    #[error("the password must be between 10 and 128 characters")]
    WeakPassword,
    #[error("an account already exists for this email address")]
    AccountExists,
    #[error("that username is already taken")]
    UsernameExists,
    #[error("the email or password is incorrect")]
    InvalidCredentials,
    #[error("the current password is incorrect")]
    InvalidCurrentPassword,
    #[error("the new password must be different from the current password")]
    PasswordUnchanged,
    #[error("the recovery code is invalid or has already been used")]
    InvalidRecoveryCode,
    #[error("the sign-in code is invalid or expired")]
    InvalidCode,
    #[error("the session is invalid or expired")]
    InvalidSession,
    #[error("the device identifier is invalid")]
    InvalidDevice,
    #[error("this device installation has been revoked")]
    DeviceRevoked,
    #[error("this account is suspended")]
    AccountSuspended,
    #[error("the account is unavailable")]
    AccountUnavailable,
    #[error("the requested account enforcement state already exists")]
    AccountEnforcementConflict,
    #[error("the account enforcement request is invalid")]
    InvalidEnforcement,
    #[error("a reused refresh token revoked this session")]
    RefreshReuse,
    #[error("the Apple sign-in request is invalid or expired")]
    InvalidAppleFlow,
    #[error("Apple sign-in could not be completed")]
    AppleFailure,
    #[error("sign in with the existing password before linking Apple")]
    AppleLinkRequired,
    #[error("this Apple account is already linked to another Exocord account")]
    AppleAlreadyLinked,
    #[error("Apple is not linked to this account")]
    AppleNotLinked,
    #[error("set a password before disconnecting Apple")]
    AppleUnlinkUnsafe,
    #[error("the account deletion request is unavailable")]
    DeletionUnavailable,
    #[error("authentication encryption failed")]
    Encryption,
    #[error("secure randomness is temporarily unavailable")]
    Randomness,
    #[error("the encrypted account recovery material is invalid")]
    InvalidRecoveryMaterial,
    #[error(
        "this recovery code predates private-history recovery; sign in on an existing device and replace your recovery codes"
    )]
    RecoveryKeyUnavailable,
}

impl AuthService {
    pub fn open(
        path: impl AsRef<Path>,
        delivery: EmailDelivery,
        apple: Option<AppleConfig>,
    ) -> Result<Self, AuthError> {
        let connection = Connection::open(path).map_err(|_| AuthError::Storage)?;
        Self::from_connection(connection, delivery, apple)
    }

    pub fn in_memory(
        delivery: EmailDelivery,
        apple: Option<AppleConfig>,
    ) -> Result<Self, AuthError> {
        let connection = Connection::open_in_memory().map_err(|_| AuthError::Storage)?;
        Self::from_connection(connection, delivery, apple)
    }

    fn from_connection(
        connection: Connection,
        delivery: EmailDelivery,
        apple: Option<AppleConfig>,
    ) -> Result<Self, AuthError> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS auth_users (
                   id INTEGER PRIMARY KEY,
                   email TEXT NOT NULL UNIQUE,
                   display_name TEXT NOT NULL,
                   created_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS email_challenges (
                   id TEXT PRIMARY KEY,
                   email TEXT NOT NULL,
                   code_hash BLOB NOT NULL,
                   expires_at INTEGER NOT NULL,
                   attempts INTEGER NOT NULL DEFAULT 0,
                   consumed_at INTEGER
                 );
                 CREATE INDEX IF NOT EXISTS email_challenges_email
                   ON email_challenges(email, expires_at);
                 CREATE TABLE IF NOT EXISTS auth_sessions (
                   id TEXT PRIMARY KEY,
                   user_id INTEGER NOT NULL REFERENCES auth_users(id),
                   device_id TEXT NOT NULL,
                   client_name TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   last_seen_at INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL,
                   revoked_at INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS auth_tokens (
                   token_hash BLOB PRIMARY KEY,
                   session_id TEXT NOT NULL REFERENCES auth_sessions(id),
                   kind TEXT NOT NULL CHECK(kind IN ('access', 'refresh')),
                   expires_at INTEGER NOT NULL,
                   consumed_at INTEGER
                 );
                 CREATE INDEX IF NOT EXISTS auth_tokens_session
                   ON auth_tokens(session_id);
                 CREATE TABLE IF NOT EXISTS revoked_devices (
                   user_id INTEGER NOT NULL REFERENCES auth_users(id),
                   device_id TEXT NOT NULL,
                   revoked_at INTEGER NOT NULL,
                   PRIMARY KEY (user_id, device_id)
                 );
                 CREATE TABLE IF NOT EXISTS apple_flows (
                   state_hash BLOB PRIMARY KEY,
                   nonce TEXT NOT NULL,
                   device_id TEXT NOT NULL,
                   expires_at INTEGER NOT NULL,
                   consumed_at INTEGER,
                   completed_at INTEGER,
                   encrypted_result BLOB,
                   error TEXT
                 );
                 CREATE TABLE IF NOT EXISTS external_identities (
                   provider TEXT NOT NULL,
                   subject TEXT NOT NULL,
                   user_id INTEGER NOT NULL REFERENCES auth_users(id),
                   email TEXT,
                   refresh_token_enc BLOB,
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL,
                   PRIMARY KEY (provider, subject)
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS external_identities_provider_user
                   ON external_identities(provider, user_id);
                 CREATE TABLE IF NOT EXISTS password_recovery_codes (
                   user_id INTEGER NOT NULL REFERENCES auth_users(id),
                   code_hash BLOB NOT NULL,
                   batch_id TEXT NOT NULL,
                   created_at INTEGER NOT NULL,
                   PRIMARY KEY (user_id, code_hash)
                 );
                 CREATE TABLE IF NOT EXISTS account_key_vaults (
                   user_id INTEGER PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
                   version INTEGER NOT NULL,
                   salt TEXT NOT NULL,
                   nonce TEXT NOT NULL,
                   ciphertext TEXT NOT NULL,
                   updated_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS account_enforcement_events (
                   id TEXT PRIMARY KEY,
                   user_id INTEGER NOT NULL REFERENCES auth_users(id),
                   action TEXT NOT NULL CHECK(action IN ('suspended', 'reinstated')),
                   operator TEXT NOT NULL,
                   reason TEXT NOT NULL,
                   report_id TEXT,
                   created_at INTEGER NOT NULL
                 );",
            )
            .map_err(|_| AuthError::Storage)?;
        ensure_column(&connection, "apple_flows", "completed_at", "INTEGER")?;
        ensure_column(&connection, "apple_flows", "encrypted_result", "BLOB")?;
        ensure_column(&connection, "apple_flows", "error", "TEXT")?;
        ensure_column(
            &connection,
            "apple_flows",
            "flow_kind",
            "TEXT NOT NULL DEFAULT 'login'",
        )?;
        ensure_column(&connection, "apple_flows", "link_user_id", "INTEGER")?;
        ensure_column(&connection, "apple_flows", "link_session_id", "TEXT")?;
        ensure_column(
            &connection,
            "auth_users",
            "deletion_requested_at",
            "INTEGER",
        )?;
        ensure_column(&connection, "auth_users", "deletion_due_at", "INTEGER")?;
        ensure_column(
            &connection,
            "auth_users",
            "anonymization_started_at",
            "INTEGER",
        )?;
        ensure_column(&connection, "auth_users", "anonymized_at", "INTEGER")?;
        ensure_column(&connection, "auth_users", "password_hash", "TEXT")?;
        ensure_column(&connection, "auth_users", "username", "TEXT")?;
        ensure_column(&connection, "auth_users", "password_changed_at", "INTEGER")?;
        ensure_column(&connection, "auth_users", "email_verified_at", "INTEGER")?;
        ensure_column(&connection, "auth_users", "suspended_at", "INTEGER")?;
        ensure_column(&connection, "auth_users", "suspended_by", "TEXT")?;
        ensure_column(&connection, "auth_users", "suspension_reason", "TEXT")?;
        ensure_column(&connection, "auth_users", "suspension_report_id", "TEXT")?;
        ensure_column(
            &connection,
            "password_recovery_codes",
            "key_version",
            "INTEGER",
        )?;
        ensure_column(&connection, "password_recovery_codes", "key_salt", "TEXT")?;
        ensure_column(&connection, "password_recovery_codes", "key_nonce", "TEXT")?;
        ensure_column(
            &connection,
            "password_recovery_codes",
            "key_ciphertext",
            "TEXT",
        )?;
        connection
            .execute_batch(
                "CREATE UNIQUE INDEX IF NOT EXISTS auth_users_username_active
                   ON auth_users(lower(username))
                   WHERE username IS NOT NULL AND anonymized_at IS NULL;
                 CREATE INDEX IF NOT EXISTS account_enforcement_events_user
                   ON account_enforcement_events(user_id, created_at DESC, id DESC);",
            )
            .map_err(|_| AuthError::Storage)?;
        let dummy_password_hash = hash_password("Exocord timing equalization password")?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            dummy_password_hash: dummy_password_hash.into(),
            delivery,
            apple,
        })
    }

    pub fn register_password(
        &self,
        email: &str,
        password: &str,
        device_id: &str,
        client_name: &str,
    ) -> Result<SessionBundle, AuthError> {
        self.register_password_named(email, None, password, device_id, client_name)
    }

    pub fn register_password_named(
        &self,
        email: &str,
        username: Option<&str>,
        password: &str,
        device_id: &str,
        client_name: &str,
    ) -> Result<SessionBundle, AuthError> {
        let email = normalize_email(email)?;
        let username = username.map(normalize_username).transpose()?;
        validate_password(password)?;
        Uuid::parse_str(device_id).map_err(|_| AuthError::InvalidDevice)?;
        let password_hash = hash_password(password)?;
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let exists = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM auth_users
                    WHERE email = ?1 AND anonymized_at IS NULL
                 )",
                [&email],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if exists {
            return Err(AuthError::AccountExists);
        }
        if let Some(username) = username.as_deref() {
            let exists = transaction
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM auth_users
                        WHERE lower(username) = lower(?1) AND anonymized_at IS NULL
                     )",
                    [username],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| AuthError::Storage)?;
            if exists {
                return Err(AuthError::UsernameExists);
            }
        }
        let id = UserId::new().raw();
        let display_name = username.clone().unwrap_or_else(|| display_name_for(&email));
        let now = Utc::now().timestamp();
        transaction
            .execute(
                "INSERT INTO auth_users
                   (id, email, username, display_name, created_at, password_hash,
                    password_changed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5)",
                params![id, email, username, display_name, now, password_hash],
            )
            .map_err(|_| AuthError::Storage)?;
        let user = AuthUser {
            id: id.to_string(),
            email,
            display_name,
            deletion_scheduled_for: None,
        };
        let recovery_codes = replace_recovery_codes(&transaction, id)?;
        let mut bundle = issue_session(&transaction, &user, device_id, client_name)?;
        bundle.recovery_codes = recovery_codes;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(bundle)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_password_provisioned(
        &self,
        email: &str,
        password: &str,
        device_id: &str,
        client_name: &str,
        user_id: UserId,
        account_key: &WrappedAccountKey,
        recovery_vaults: &[RecoveryKeyVault],
    ) -> Result<SessionBundle, AuthError> {
        self.register_password_provisioned_named(
            email,
            None,
            password,
            device_id,
            client_name,
            user_id,
            account_key,
            recovery_vaults,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_password_provisioned_named(
        &self,
        email: &str,
        username: Option<&str>,
        password: &str,
        device_id: &str,
        client_name: &str,
        user_id: UserId,
        account_key: &WrappedAccountKey,
        recovery_vaults: &[RecoveryKeyVault],
    ) -> Result<SessionBundle, AuthError> {
        let email = normalize_email(email)?;
        let username = username.map(normalize_username).transpose()?;
        validate_password(password)?;
        Uuid::parse_str(device_id).map_err(|_| AuthError::InvalidDevice)?;
        validate_wrapped_account_key(account_key)?;
        let password_hash = hash_password(password)?;
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let existing = transaction
            .query_row(
                "SELECT id, password_hash
                   FROM auth_users
                  WHERE email = ?1 AND anonymized_at IS NULL",
                [&email],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?;
        if let Some((existing_id, password_hash)) = existing {
            if existing_id != user_id.raw() || !verify_password(password, &password_hash)? {
                return Err(AuthError::AccountExists);
            }
            if !provisioning_matches(&transaction, existing_id, account_key, recovery_vaults)? {
                return Err(AuthError::InvalidRecoveryMaterial);
            }
            let user = transaction
                .query_row(
                    "SELECT id, email, display_name, deletion_due_at
                       FROM auth_users WHERE id = ?1",
                    [existing_id],
                    auth_user_from_row,
                )
                .map_err(|_| AuthError::Storage)?;
            let mut bundle = issue_session(&transaction, &user, device_id, client_name)?;
            bundle.recovery_codes = recovery_vaults
                .iter()
                .map(|entry| entry.recovery_code.clone())
                .collect();
            transaction.commit().map_err(|_| AuthError::Storage)?;
            return Ok(bundle);
        }
        if let Some(username) = username.as_deref() {
            let exists = transaction
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM auth_users
                        WHERE lower(username) = lower(?1) AND anonymized_at IS NULL
                     )",
                    [username],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| AuthError::Storage)?;
            if exists {
                return Err(AuthError::UsernameExists);
            }
        }
        let id = user_id.raw();
        let display_name = username.clone().unwrap_or_else(|| display_name_for(&email));
        let now = Utc::now().timestamp();
        transaction
            .execute(
                "INSERT INTO auth_users
                   (id, email, username, display_name, created_at, password_hash,
                    password_changed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5)",
                params![id, email, username, display_name, now, password_hash],
            )
            .map_err(|_| AuthError::Storage)?;
        let recovery_codes = stage_provisioned_recovery_codes(&transaction, id, recovery_vaults)?;
        transaction
            .execute(
                "INSERT INTO account_key_vaults
                   (user_id, version, salt, nonce, ciphertext, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id,
                    account_key.version,
                    account_key.salt,
                    account_key.nonce,
                    account_key.ciphertext,
                    now
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        let user = AuthUser {
            id: id.to_string(),
            email,
            display_name,
            deletion_scheduled_for: None,
        };
        let mut bundle = issue_session(&transaction, &user, device_id, client_name)?;
        bundle.recovery_codes = recovery_codes;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(bundle)
    }

    pub fn login_password(
        &self,
        email: &str,
        password: &str,
        device_id: &str,
        client_name: &str,
    ) -> Result<SessionBundle, AuthError> {
        let email = normalize_email(email).map_err(|_| AuthError::InvalidCredentials)?;
        Uuid::parse_str(device_id).map_err(|_| AuthError::InvalidDevice)?;
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let row = transaction
            .query_row(
                "SELECT id, email, display_name, deletion_due_at, password_hash,
                        suspended_at
                   FROM auth_users
                  WHERE email = ?1 AND anonymized_at IS NULL",
                [&email],
                |row| {
                    Ok((
                        auth_user_from_row(row)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?;
        let candidate_hash = row
            .as_ref()
            .and_then(|(_, password_hash, _)| password_hash.as_deref())
            .unwrap_or(&self.dummy_password_hash);
        let password_valid = verify_password(password, candidate_hash)?;
        let Some((user, Some(_), suspended_at)) = row else {
            return Err(AuthError::InvalidCredentials);
        };
        if !password_valid {
            return Err(AuthError::InvalidCredentials);
        }
        if suspended_at.is_some() {
            return Err(AuthError::AccountSuspended);
        }
        let bundle = issue_session(&transaction, &user, device_id, client_name)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(bundle)
    }

    pub fn change_password(
        &self,
        principal: &Principal,
        current_password: &str,
        new_password: &str,
        wrapped_key: Option<&WrappedAccountKey>,
    ) -> Result<(), AuthError> {
        validate_password(new_password)?;
        if let Some(wrapped_key) = wrapped_key {
            validate_wrapped_account_key(wrapped_key)?;
        }
        let password_hash = {
            let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
            connection
                .query_row(
                    "SELECT password_hash
                       FROM auth_users
                      WHERE id = ?1 AND anonymized_at IS NULL",
                    [principal.user_id.raw()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|_| AuthError::Storage)?
                .flatten()
                .ok_or(AuthError::InvalidCurrentPassword)?
        };
        if !verify_password(current_password, &password_hash)? {
            return Err(AuthError::InvalidCurrentPassword);
        }
        if current_password == new_password {
            return Err(AuthError::PasswordUnchanged);
        }
        let new_password_hash = hash_password(new_password)?;
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let has_account_key = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM account_key_vaults WHERE user_id = ?1
                 )",
                [principal.user_id.raw()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if has_account_key && wrapped_key.is_none() {
            return Err(AuthError::RecoveryKeyUnavailable);
        }
        let updated = transaction
            .execute(
                "UPDATE auth_users
                    SET password_hash = ?1, password_changed_at = ?2
                  WHERE id = ?3
                    AND password_hash = ?4
                    AND anonymized_at IS NULL",
                params![
                    new_password_hash,
                    now,
                    principal.user_id.raw(),
                    password_hash
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        if updated != 1 {
            return Err(AuthError::InvalidCurrentPassword);
        }
        if let Some(wrapped_key) = wrapped_key {
            transaction
                .execute(
                    "INSERT INTO account_key_vaults
                       (user_id, version, salt, nonce, ciphertext, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(user_id) DO UPDATE SET
                       version = excluded.version,
                       salt = excluded.salt,
                       nonce = excluded.nonce,
                       ciphertext = excluded.ciphertext,
                       updated_at = excluded.updated_at",
                    params![
                        principal.user_id.raw(),
                        wrapped_key.version,
                        wrapped_key.salt,
                        wrapped_key.nonce,
                        wrapped_key.ciphertext,
                        now
                    ],
                )
                .map_err(|_| AuthError::Storage)?;
        }
        transaction
            .execute(
                "UPDATE auth_sessions
                    SET revoked_at = COALESCE(revoked_at, ?1)
                  WHERE user_id = ?2 AND id <> ?3",
                params![now, principal.user_id.raw(), principal.session_id],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)
    }

    pub fn recover_password(
        &self,
        email: &str,
        recovery_code: &str,
        new_password: &str,
        device_id: &str,
        client_name: &str,
    ) -> Result<SessionBundle, AuthError> {
        let email = normalize_email(email).map_err(|_| AuthError::InvalidRecoveryCode)?;
        validate_password(new_password)?;
        Uuid::parse_str(device_id).map_err(|_| AuthError::InvalidDevice)?;
        let recovery_code = recovery_code.trim();
        if !recovery_code.starts_with("exo_rc_") || recovery_code.len() != 29 {
            return Err(AuthError::InvalidRecoveryCode);
        }
        let new_password_hash = hash_password(new_password)?;
        let code_hash = hash_recovery_code(recovery_code);
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let (user, recovery_wrapped_key) = recovery_account(&transaction, &email, &code_hash)?;
        let user_id = user.id.parse::<u64>().map_err(|_| AuthError::Storage)?;
        let account_key_exists = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM account_key_vaults WHERE user_id = ?1
                 )",
                [user_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if account_key_exists && recovery_wrapped_key.is_none() {
            return Err(AuthError::RecoveryKeyUnavailable);
        }
        if let Some(wrapped) = recovery_wrapped_key.as_ref() {
            validate_wrapped_account_key(wrapped)?;
        }
        transaction
            .execute(
                "UPDATE auth_users
                    SET password_hash = ?1, password_changed_at = ?2
                  WHERE id = ?3 AND anonymized_at IS NULL",
                params![new_password_hash, now, user_id],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "UPDATE auth_sessions
                    SET revoked_at = COALESCE(revoked_at, ?1)
                  WHERE user_id = ?2",
                params![now, user_id],
            )
            .map_err(|_| AuthError::Storage)?;
        let recovery_codes = replace_recovery_codes(&transaction, user_id)?;
        let mut bundle = issue_session(&transaction, &user, device_id, client_name)?;
        bundle.recovery_codes = recovery_codes;
        bundle.recovery_wrapped_key = recovery_wrapped_key;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(bundle)
    }

    pub fn prepare_password_recovery(
        &self,
        email: &str,
        recovery_code: &str,
    ) -> Result<RecoveryPreparation, AuthError> {
        let email = normalize_email(email).map_err(|_| AuthError::InvalidRecoveryCode)?;
        let recovery_code = recovery_code.trim();
        if !recovery_code.starts_with("exo_rc_") || recovery_code.len() != 29 {
            return Err(AuthError::InvalidRecoveryCode);
        }
        let code_hash = hash_recovery_code(recovery_code);
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let (user, wrapped_key) = recovery_account(&connection, &email, &code_hash)?;
        let user_id = user.id.parse::<UserId>().map_err(|_| AuthError::Storage)?;
        let account_key_exists = connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM account_key_vaults WHERE user_id = ?1
                 )",
                [user_id.raw()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if account_key_exists && wrapped_key.is_none() {
            return Err(AuthError::RecoveryKeyUnavailable);
        }
        if let Some(wrapped) = wrapped_key.as_ref() {
            validate_wrapped_account_key(wrapped)?;
        }
        Ok(RecoveryPreparation {
            user_id,
            wrapped_key,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recover_password_provisioned(
        &self,
        email: &str,
        recovery_code: &str,
        new_password: &str,
        device_id: &str,
        client_name: &str,
        expected_user_id: UserId,
        account_key: &WrappedAccountKey,
        recovery_vaults: &[RecoveryKeyVault],
    ) -> Result<SessionBundle, AuthError> {
        let email = normalize_email(email).map_err(|_| AuthError::InvalidRecoveryCode)?;
        validate_password(new_password)?;
        Uuid::parse_str(device_id).map_err(|_| AuthError::InvalidDevice)?;
        validate_wrapped_account_key(account_key)?;
        let recovery_code = recovery_code.trim();
        if !recovery_code.starts_with("exo_rc_") || recovery_code.len() != 29 {
            return Err(AuthError::InvalidRecoveryCode);
        }
        let password_hash = hash_password(new_password)?;
        let code_hash = hash_recovery_code(recovery_code);
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let (user, old_recovery_key) = match recovery_account(&transaction, &email, &code_hash) {
            Ok(account) => account,
            Err(AuthError::InvalidRecoveryCode) => {
                let existing = transaction
                    .query_row(
                        "SELECT id, email, display_name, deletion_due_at, password_hash
                           FROM auth_users
                          WHERE email = ?1 AND anonymized_at IS NULL",
                        [&email],
                        |row| Ok((auth_user_from_row(row)?, row.get::<_, Option<String>>(4)?)),
                    )
                    .optional()
                    .map_err(|_| AuthError::Storage)?;
                let Some((user, Some(stored_password_hash))) = existing else {
                    return Err(AuthError::InvalidRecoveryCode);
                };
                let user_id = user.id.parse::<UserId>().map_err(|_| AuthError::Storage)?;
                if user_id != expected_user_id
                    || !verify_password(new_password, &stored_password_hash)?
                    || !provisioning_matches(
                        &transaction,
                        user_id.raw(),
                        account_key,
                        recovery_vaults,
                    )?
                {
                    return Err(AuthError::InvalidRecoveryCode);
                }
                let mut bundle = issue_session(&transaction, &user, device_id, client_name)?;
                bundle.recovery_codes = recovery_vaults
                    .iter()
                    .map(|entry| entry.recovery_code.clone())
                    .collect();
                transaction.commit().map_err(|_| AuthError::Storage)?;
                return Ok(bundle);
            }
            Err(error) => return Err(error),
        };
        let user_id = user.id.parse::<UserId>().map_err(|_| AuthError::Storage)?;
        if user_id != expected_user_id {
            return Err(AuthError::InvalidRecoveryCode);
        }
        if old_recovery_key.is_none()
            && transaction
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM account_key_vaults WHERE user_id = ?1
                     )",
                    [user_id.raw()],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| AuthError::Storage)?
        {
            return Err(AuthError::RecoveryKeyUnavailable);
        }
        transaction
            .execute(
                "UPDATE auth_users
                    SET password_hash = ?1, password_changed_at = ?2
                  WHERE id = ?3 AND anonymized_at IS NULL",
                params![password_hash, now, user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "UPDATE auth_sessions
                    SET revoked_at = COALESCE(revoked_at, ?1)
                  WHERE user_id = ?2",
                params![now, user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "DELETE FROM password_recovery_codes WHERE user_id = ?1",
                [user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        let recovery_codes =
            stage_provisioned_recovery_codes(&transaction, user_id.raw(), recovery_vaults)?;
        transaction
            .execute(
                "INSERT INTO account_key_vaults
                   (user_id, version, salt, nonce, ciphertext, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(user_id) DO UPDATE SET
                   version = excluded.version,
                   salt = excluded.salt,
                   nonce = excluded.nonce,
                   ciphertext = excluded.ciphertext,
                   updated_at = excluded.updated_at",
                params![
                    user_id.raw(),
                    account_key.version,
                    account_key.salt,
                    account_key.nonce,
                    account_key.ciphertext,
                    now
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        let mut bundle = issue_session(&transaction, &user, device_id, client_name)?;
        bundle.recovery_codes = recovery_codes;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(bundle)
    }

    pub fn regenerate_recovery_codes(
        &self,
        principal: &Principal,
        current_password: &str,
    ) -> Result<Vec<String>, AuthError> {
        let password_hash = {
            let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
            connection
                .query_row(
                    "SELECT password_hash
                       FROM auth_users
                      WHERE id = ?1 AND anonymized_at IS NULL",
                    [principal.user_id.raw()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|_| AuthError::Storage)?
                .flatten()
                .ok_or(AuthError::InvalidCurrentPassword)?
        };
        if !verify_password(current_password, &password_hash)? {
            return Err(AuthError::InvalidCurrentPassword);
        }
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let unchanged: bool = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM auth_users
                    WHERE id = ?1
                      AND password_hash = ?2
                      AND anonymized_at IS NULL
                 )",
                params![principal.user_id.raw(), password_hash],
                |row| row.get(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if !unchanged {
            return Err(AuthError::InvalidCurrentPassword);
        }
        let codes = stage_recovery_codes(&transaction, principal.user_id.raw())?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(codes)
    }

    pub fn set_recovery_key_vaults(
        &self,
        principal: &Principal,
        current_password: &str,
        entries: &[RecoveryKeyVault],
    ) -> Result<(), AuthError> {
        if entries.len() != RECOVERY_CODE_COUNT {
            return Err(AuthError::InvalidRecoveryMaterial);
        }
        let mut unique_hashes = HashSet::with_capacity(entries.len());
        let mut hashes = Vec::with_capacity(entries.len());
        for entry in entries {
            let code = entry.recovery_code.trim();
            if !code.starts_with("exo_rc_") || code.len() != 29 {
                return Err(AuthError::InvalidRecoveryMaterial);
            }
            validate_wrapped_account_key(&entry.wrapped_key)?;
            let hash = hash_recovery_code(code);
            if !unique_hashes.insert(hash) {
                return Err(AuthError::InvalidRecoveryMaterial);
            }
            hashes.push(hash);
        }

        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let password_hash = transaction
            .query_row(
                "SELECT password_hash
                   FROM auth_users
                  WHERE id = ?1 AND anonymized_at IS NULL",
                [principal.user_id.raw()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .flatten()
            .ok_or(AuthError::InvalidCurrentPassword)?;
        if !verify_password(current_password, &password_hash)? {
            return Err(AuthError::InvalidCurrentPassword);
        }

        let mut target_batch = None::<String>;
        for hash in &hashes {
            let batch = transaction
                .query_row(
                    "SELECT batch_id
                       FROM password_recovery_codes
                      WHERE user_id = ?1 AND code_hash = ?2",
                    params![principal.user_id.raw(), hash.as_slice()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| AuthError::Storage)?
                .ok_or(AuthError::InvalidRecoveryMaterial)?;
            if target_batch
                .as_ref()
                .is_some_and(|current| current != &batch)
            {
                return Err(AuthError::InvalidRecoveryMaterial);
            }
            target_batch = Some(batch);
        }
        let target_batch = target_batch.ok_or(AuthError::InvalidRecoveryMaterial)?;
        let batch_count = transaction
            .query_row(
                "SELECT COUNT(*)
                   FROM password_recovery_codes
                  WHERE user_id = ?1 AND batch_id = ?2",
                params![principal.user_id.raw(), &target_batch],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if batch_count != RECOVERY_CODE_COUNT as i64 {
            return Err(AuthError::InvalidRecoveryMaterial);
        }
        for (entry, code_hash) in entries.iter().zip(&hashes) {
            let updated = transaction
                .execute(
                    "UPDATE password_recovery_codes
                        SET key_version = ?1,
                            key_salt = ?2,
                            key_nonce = ?3,
                            key_ciphertext = ?4
                      WHERE user_id = ?5 AND code_hash = ?6",
                    params![
                        entry.wrapped_key.version,
                        entry.wrapped_key.salt,
                        entry.wrapped_key.nonce,
                        entry.wrapped_key.ciphertext,
                        principal.user_id.raw(),
                        code_hash.as_slice()
                    ],
                )
                .map_err(|_| AuthError::Storage)?;
            if updated != 1 {
                return Err(AuthError::InvalidRecoveryMaterial);
            }
        }
        transaction
            .execute(
                "DELETE FROM password_recovery_codes
                  WHERE user_id = ?1 AND batch_id <> ?2",
                params![principal.user_id.raw(), &target_batch],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)
    }

    pub fn account_key_vault(
        &self,
        principal: &Principal,
    ) -> Result<Option<WrappedAccountKey>, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        connection
            .query_row(
                "SELECT version, salt, nonce, ciphertext
                   FROM account_key_vaults
                  WHERE user_id = ?1",
                [principal.user_id.raw()],
                |row| {
                    Ok(WrappedAccountKey {
                        version: row.get::<_, u8>(0)?,
                        salt: row.get(1)?,
                        nonce: row.get(2)?,
                        ciphertext: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)
    }

    pub fn recovery_key_vaults_ready(&self, principal: &Principal) -> Result<bool, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let (total, ready) = connection
            .query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(
                          CASE WHEN key_version IS NOT NULL
                                  AND key_salt IS NOT NULL
                                  AND key_nonce IS NOT NULL
                                  AND key_ciphertext IS NOT NULL
                               THEN 1 ELSE 0 END
                        ), 0)
                   FROM password_recovery_codes
                  WHERE user_id = ?1",
                [principal.user_id.raw()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(|_| AuthError::Storage)?;
        Ok(total == RECOVERY_CODE_COUNT as i64 && ready == total)
    }

    pub fn set_account_key_vault(
        &self,
        principal: &Principal,
        current_password: &str,
        wrapped: &WrappedAccountKey,
    ) -> Result<(), AuthError> {
        validate_wrapped_account_key(wrapped)?;
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let password_hash = connection
            .query_row(
                "SELECT password_hash
                   FROM auth_users
                  WHERE id = ?1 AND anonymized_at IS NULL",
                [principal.user_id.raw()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .flatten()
            .ok_or(AuthError::InvalidCurrentPassword)?;
        if !verify_password(current_password, &password_hash)? {
            return Err(AuthError::InvalidCurrentPassword);
        }
        connection
            .execute(
                "INSERT INTO account_key_vaults
                   (user_id, version, salt, nonce, ciphertext, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(user_id) DO UPDATE SET
                   version = excluded.version,
                   salt = excluded.salt,
                   nonce = excluded.nonce,
                   ciphertext = excluded.ciphertext,
                   updated_at = excluded.updated_at",
                params![
                    principal.user_id.raw(),
                    wrapped.version,
                    wrapped.salt,
                    wrapped.nonce,
                    wrapped.ciphertext,
                    Utc::now().timestamp()
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        Ok(())
    }

    pub fn request_email_code(&self, email: &str) -> Result<EmailChallenge, AuthError> {
        let email = normalize_email(email)?;
        let id = Uuid::now_v7().to_string();
        let code = six_digit_code()?;
        let hash = hash_secret(&format!("{id}:{code}"));
        let now = Utc::now().timestamp();
        let expires_at = (Utc::now() + Duration::minutes(EMAIL_CODE_LIFETIME_MINUTES)).timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "UPDATE email_challenges
                    SET consumed_at = ?1
                  WHERE email = ?2 AND consumed_at IS NULL",
                params![now, email],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "INSERT INTO email_challenges
                   (id, email, code_hash, expires_at, attempts)
                 VALUES (?1, ?2, ?3, ?4, 0)",
                params![id, email, hash.as_slice(), expires_at],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(EmailChallenge { id, email, code })
    }

    pub fn cancel_email_challenge(&self, challenge_id: &str) -> Result<(), AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        connection
            .execute(
                "UPDATE email_challenges
                    SET consumed_at = COALESCE(consumed_at, ?1)
                  WHERE id = ?2",
                params![Utc::now().timestamp(), challenge_id],
            )
            .map_err(|_| AuthError::Storage)?;
        Ok(())
    }

    pub fn verify_email_code(
        &self,
        challenge_id: &str,
        code: &str,
        device_id: &str,
        client_name: &str,
    ) -> Result<SessionBundle, AuthError> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AuthError::InvalidCode);
        }
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let challenge = transaction
            .query_row(
                "SELECT email, code_hash, expires_at, attempts, consumed_at
                   FROM email_challenges WHERE id = ?1",
                [challenge_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidCode)?;
        let expected = hash_secret(&format!("{challenge_id}:{code}"));
        let valid_hash = challenge.1.as_slice().ct_eq(expected.as_slice()).into();
        let valid = valid_hash
            && challenge.2 >= Utc::now().timestamp()
            && challenge.3 < MAX_CODE_ATTEMPTS
            && challenge.4.is_none();
        if !valid {
            transaction
                .execute(
                    "UPDATE email_challenges SET attempts = attempts + 1 WHERE id = ?1",
                    [challenge_id],
                )
                .map_err(|_| AuthError::Storage)?;
            transaction.commit().map_err(|_| AuthError::Storage)?;
            return Err(AuthError::InvalidCode);
        }
        transaction
            .execute(
                "UPDATE email_challenges SET consumed_at = ?1 WHERE id = ?2",
                params![Utc::now().timestamp(), challenge_id],
            )
            .map_err(|_| AuthError::Storage)?;
        let user = find_or_create_user(&transaction, &challenge.0)?;
        transaction
            .execute(
                "UPDATE auth_users
                    SET email_verified_at = COALESCE(email_verified_at, ?1)
                  WHERE id = ?2",
                params![
                    Utc::now().timestamp(),
                    user.id.parse::<u64>().map_err(|_| AuthError::Storage)?
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        let bundle = issue_session(&transaction, &user, device_id, client_name)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(bundle)
    }

    pub fn authenticate(&self, token: &str) -> Result<Principal, AuthError> {
        if !token.starts_with("exo_at_") {
            return Err(AuthError::InvalidSession);
        }
        let hash = hash_secret(token);
        let now = Utc::now().timestamp();
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let principal = connection
            .query_row(
                "SELECT s.user_id, s.id, s.device_id
                   FROM auth_tokens t
                   JOIN auth_sessions s ON s.id = t.session_id
                   JOIN auth_users u ON u.id = s.user_id
                  WHERE t.token_hash = ?1
                    AND t.kind = 'access'
                    AND t.expires_at >= ?2
                    AND t.consumed_at IS NULL
                    AND s.expires_at >= ?2
                    AND s.revoked_at IS NULL
                    AND u.anonymized_at IS NULL
                    AND u.suspended_at IS NULL",
                params![hash.as_slice(), now],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidSession)?;
        Ok(Principal {
            user_id: UserId::from_raw(principal.0).map_err(|_| AuthError::InvalidSession)?,
            session_id: principal.1,
            device_id: Uuid::parse_str(&principal.2).map_err(|_| AuthError::InvalidSession)?,
        })
    }

    pub fn refresh(&self, refresh_token: &str) -> Result<SessionBundle, AuthError> {
        if !refresh_token.starts_with("exo_rt_") {
            return Err(AuthError::InvalidSession);
        }
        let hash = hash_secret(refresh_token);
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let token = transaction
            .query_row(
                "SELECT t.session_id, t.expires_at, t.consumed_at,
                        s.user_id, s.device_id, s.client_name, s.revoked_at
                   FROM auth_tokens t
                   JOIN auth_sessions s ON s.id = t.session_id
                  WHERE t.token_hash = ?1 AND t.kind = 'refresh'",
                [hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidSession)?;
        if token.2.is_some() {
            transaction
                .execute(
                    "UPDATE auth_sessions SET revoked_at = ?1 WHERE id = ?2",
                    params![now, token.0],
                )
                .map_err(|_| AuthError::Storage)?;
            transaction.commit().map_err(|_| AuthError::Storage)?;
            return Err(AuthError::RefreshReuse);
        }
        if token.1 < now || token.6.is_some() {
            return Err(AuthError::InvalidSession);
        }
        transaction
            .execute(
                "UPDATE auth_tokens SET consumed_at = ?1 WHERE token_hash = ?2",
                params![now, hash.as_slice()],
            )
            .map_err(|_| AuthError::Storage)?;
        let user = load_user(&transaction, token.3)?;
        let bundle = rotate_session(&transaction, &token.0, &user)?;
        transaction
            .execute(
                "UPDATE auth_sessions SET last_seen_at = ?1, expires_at = ?2 WHERE id = ?3",
                params![
                    now,
                    (Utc::now() + Duration::days(REFRESH_LIFETIME_DAYS)).timestamp(),
                    token.0
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(bundle)
    }

    pub fn logout(&self, principal: &Principal) -> Result<(), AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        connection
            .execute(
                "UPDATE auth_sessions SET revoked_at = ?1
                  WHERE id = ?2 AND user_id = ?3",
                params![
                    Utc::now().timestamp(),
                    principal.session_id,
                    principal.user_id.raw()
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        Ok(())
    }

    pub fn revoke_device_sessions(
        &self,
        user_id: UserId,
        device_id: Uuid,
    ) -> Result<usize, AuthError> {
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "INSERT INTO revoked_devices (user_id, device_id, revoked_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (user_id, device_id) DO NOTHING",
                params![user_id.raw(), device_id.to_string(), Utc::now().timestamp()],
            )
            .map_err(|_| AuthError::Storage)?;
        let revoked_sessions = transaction
            .execute(
                "UPDATE auth_sessions
                 SET revoked_at = COALESCE(revoked_at, ?1)
                 WHERE user_id = ?2 AND device_id = ?3",
                params![Utc::now().timestamp(), user_id.raw(), device_id.to_string()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(revoked_sessions)
    }

    pub fn account_enforcement(
        &self,
        user_id: UserId,
        limit: usize,
    ) -> Result<AccountEnforcementOverview, AuthError> {
        let limit = i64::try_from(limit.clamp(1, 100)).map_err(|_| AuthError::Storage)?;
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let suspension = load_account_suspension(&connection, user_id)?;
        let events = load_enforcement_events(&connection, user_id, limit)?;
        Ok(AccountEnforcementOverview { suspension, events })
    }

    pub fn suspend_account(
        &self,
        user_id: UserId,
        operator: &str,
        reason: &str,
        report_id: Option<&str>,
    ) -> Result<AccountSuspension, AuthError> {
        validate_enforcement(operator, reason, report_id)?;
        let operator = operator.trim();
        let reason = reason.trim();
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let current = transaction
            .query_row(
                "SELECT suspended_at
                   FROM auth_users
                  WHERE id = ?1 AND anonymized_at IS NULL",
                [user_id.raw()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::AccountUnavailable)?;
        if current.is_some() {
            return Err(AuthError::AccountEnforcementConflict);
        }
        let updated = transaction
            .execute(
                "UPDATE auth_users
                    SET suspended_at = ?1,
                        suspended_by = ?2,
                        suspension_reason = ?3,
                        suspension_report_id = ?4
                  WHERE id = ?5
                    AND anonymized_at IS NULL
                    AND suspended_at IS NULL",
                params![now, operator, reason, report_id, user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        if updated != 1 {
            return Err(AuthError::AccountEnforcementConflict);
        }
        transaction
            .execute(
                "UPDATE auth_sessions
                    SET revoked_at = COALESCE(revoked_at, ?1)
                  WHERE user_id = ?2",
                params![now, user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        insert_enforcement_event(
            &transaction,
            user_id,
            "suspended",
            operator,
            reason,
            report_id,
            now,
        )?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        drop(connection);
        self.account_enforcement(user_id, 1)
            .map(|overview| overview.suspension)
    }

    pub fn reinstate_account(
        &self,
        user_id: UserId,
        operator: &str,
        reason: &str,
        report_id: Option<&str>,
    ) -> Result<AccountSuspension, AuthError> {
        validate_enforcement(operator, reason, report_id)?;
        let operator = operator.trim();
        let reason = reason.trim();
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let current = transaction
            .query_row(
                "SELECT suspended_at
                   FROM auth_users
                  WHERE id = ?1 AND anonymized_at IS NULL",
                [user_id.raw()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::AccountUnavailable)?;
        if current.is_none() {
            return Err(AuthError::AccountEnforcementConflict);
        }
        let updated = transaction
            .execute(
                "UPDATE auth_users
                    SET suspended_at = NULL,
                        suspended_by = NULL,
                        suspension_reason = NULL,
                        suspension_report_id = NULL
                  WHERE id = ?1
                    AND anonymized_at IS NULL
                    AND suspended_at IS NOT NULL",
                [user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        if updated != 1 {
            return Err(AuthError::AccountEnforcementConflict);
        }
        insert_enforcement_event(
            &transaction,
            user_id,
            "reinstated",
            operator,
            reason,
            report_id,
            now,
        )?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        drop(connection);
        self.account_enforcement(user_id, 1)
            .map(|overview| overview.suspension)
    }

    pub fn user(&self, user_id: UserId) -> Result<AuthUser, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        load_user(&connection, user_id.raw())
    }

    pub fn username(&self, user_id: UserId) -> Result<Option<String>, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        connection
            .query_row(
                "SELECT username FROM auth_users
                  WHERE id = ?1 AND anonymized_at IS NULL",
                [user_id.raw()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidSession)
    }

    pub fn update_display_name(
        &self,
        user_id: UserId,
        display_name: &str,
    ) -> Result<AuthUser, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let updated = connection
            .execute(
                "UPDATE auth_users
                    SET display_name = ?1
                  WHERE id = ?2 AND anonymized_at IS NULL",
                params![display_name, user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        if updated != 1 {
            return Err(AuthError::InvalidSession);
        }
        load_user(&connection, user_id.raw())
    }

    pub fn account_deletion(&self, user_id: UserId) -> Result<Option<AccountDeletion>, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let timestamps = connection
            .query_row(
                "SELECT deletion_requested_at, deletion_due_at
                   FROM auth_users
                  WHERE id = ?1 AND anonymized_at IS NULL",
                [user_id.raw()],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidSession)?;
        deletion_from_timestamps(timestamps.0, timestamps.1)
    }

    pub fn schedule_account_deletion(
        &self,
        principal: &Principal,
        now: DateTime<Utc>,
    ) -> Result<AccountDeletion, AuthError> {
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let due_at = (now + Duration::days(ACCOUNT_DELETION_GRACE_DAYS)).timestamp();
        let updated = transaction
            .execute(
                "UPDATE auth_users
                    SET deletion_requested_at = COALESCE(deletion_requested_at, ?1),
                        deletion_due_at = COALESCE(deletion_due_at, ?2)
                  WHERE id = ?3 AND anonymized_at IS NULL",
                params![now.timestamp(), due_at, principal.user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        if updated == 0 {
            return Err(AuthError::DeletionUnavailable);
        }
        let timestamps = transaction
            .query_row(
                "SELECT deletion_requested_at, deletion_due_at
                   FROM auth_users WHERE id = ?1",
                [principal.user_id.raw()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "UPDATE auth_sessions
                    SET revoked_at = COALESCE(revoked_at, ?1)
                  WHERE user_id = ?2",
                params![now.timestamp(), principal.user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(AccountDeletion {
            requested_at: timestamp_rfc3339(timestamps.0)?,
            scheduled_for: timestamp_rfc3339(timestamps.1)?,
        })
    }

    pub fn cancel_account_deletion(&self, principal: &Principal) -> Result<(), AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let updated = connection
            .execute(
                "UPDATE auth_users
                    SET deletion_requested_at = NULL, deletion_due_at = NULL
                  WHERE id = ?1
                    AND anonymization_started_at IS NULL
                    AND anonymized_at IS NULL",
                [principal.user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        if updated == 0 {
            return Err(AuthError::DeletionUnavailable);
        }
        Ok(())
    }

    pub fn data_export(&self, user_id: UserId) -> Result<AuthDataExport, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let (profile, created_at, requested_at, due_at) = connection
            .query_row(
                "SELECT id, email, display_name, deletion_due_at, created_at,
                        deletion_requested_at
                   FROM auth_users
                  WHERE id = ?1 AND anonymized_at IS NULL",
                [user_id.raw()],
                |row| {
                    Ok((
                        auth_user_from_row(row)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidSession)?;
        let mut identity_statement = connection
            .prepare(
                "SELECT provider, subject, email, created_at, updated_at
                   FROM external_identities
                  WHERE user_id = ?1
                  ORDER BY provider, subject",
            )
            .map_err(|_| AuthError::Storage)?;
        let identity_rows = identity_statement
            .query_map([user_id.raw()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|_| AuthError::Storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuthError::Storage)?;
        let external_identities = identity_rows
            .into_iter()
            .map(|(provider, subject, email, created_at, updated_at)| {
                Ok(AuthExportIdentity {
                    provider,
                    subject,
                    email,
                    created_at: timestamp_rfc3339(created_at)?,
                    updated_at: timestamp_rfc3339(updated_at)?,
                })
            })
            .collect::<Result<Vec<_>, AuthError>>()?;
        let mut session_statement = connection
            .prepare(
                "SELECT id, device_id, client_name, created_at, last_seen_at,
                        expires_at, revoked_at
                   FROM auth_sessions
                  WHERE user_id = ?1
                  ORDER BY created_at, id",
            )
            .map_err(|_| AuthError::Storage)?;
        let session_rows = session_statement
            .query_map([user_id.raw()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })
            .map_err(|_| AuthError::Storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuthError::Storage)?;
        let sessions = session_rows
            .into_iter()
            .map(
                |(id, device_id, client_name, created_at, last_seen_at, expires_at, revoked_at)| {
                    Ok(AuthExportSession {
                        id,
                        device_id,
                        client_name,
                        created_at: timestamp_rfc3339(created_at)?,
                        last_seen_at: timestamp_rfc3339(last_seen_at)?,
                        expires_at: timestamp_rfc3339(expires_at)?,
                        revoked_at: revoked_at.map(timestamp_rfc3339).transpose()?,
                    })
                },
            )
            .collect::<Result<Vec<_>, AuthError>>()?;
        let account_enforcement = load_enforcement_events(&connection, user_id, 100)?;
        Ok(AuthDataExport {
            profile,
            created_at: timestamp_rfc3339(created_at)?,
            external_identities,
            sessions,
            account_enforcement,
            deletion: deletion_from_timestamps(requested_at, due_at)?,
        })
    }

    pub fn due_account_deletions(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<UserId>, AuthError> {
        let limit = i64::try_from(limit).map_err(|_| AuthError::Storage)?;
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let mut statement = connection
            .prepare(
                "SELECT id
                   FROM auth_users
                  WHERE deletion_due_at IS NOT NULL
                    AND deletion_due_at <= ?1
                    AND anonymized_at IS NULL
                  ORDER BY deletion_due_at, id
                  LIMIT ?2",
            )
            .map_err(|_| AuthError::Storage)?;
        statement
            .query_map(params![now.timestamp(), limit], |row| row.get::<_, u64>(0))
            .map_err(|_| AuthError::Storage)?
            .map(|row| {
                UserId::from_raw(row.map_err(|_| AuthError::Storage)?)
                    .map_err(|_| AuthError::Storage)
            })
            .collect()
    }

    pub fn begin_account_anonymization(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let updated = connection
            .execute(
                "UPDATE auth_users
                    SET anonymization_started_at =
                          COALESCE(anonymization_started_at, ?1)
                  WHERE id = ?2
                    AND deletion_due_at IS NOT NULL
                    AND deletion_due_at <= ?1
                    AND anonymized_at IS NULL",
                params![now.timestamp(), user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        Ok(updated > 0)
    }

    pub fn finalize_account_deletion(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let row = transaction
            .query_row(
                "SELECT email, deletion_due_at, anonymized_at
                   FROM auth_users WHERE id = ?1",
                [user_id.raw()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?;
        let Some((email, due_at, anonymized_at)) = row else {
            return Ok(false);
        };
        if anonymized_at.is_some() || due_at.is_none_or(|due_at| due_at > now.timestamp()) {
            return Ok(false);
        }
        transaction
            .execute("DELETE FROM email_challenges WHERE email = ?1", [&email])
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "DELETE FROM apple_flows
                  WHERE device_id IN (
                    SELECT device_id FROM auth_sessions WHERE user_id = ?1
                  )",
                [user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "DELETE FROM auth_tokens
                  WHERE session_id IN (
                    SELECT id FROM auth_sessions WHERE user_id = ?1
                  )",
                [user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "DELETE FROM auth_sessions WHERE user_id = ?1",
                [user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "DELETE FROM external_identities WHERE user_id = ?1",
                [user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "DELETE FROM revoked_devices WHERE user_id = ?1",
                [user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction
            .execute(
                "DELETE FROM password_recovery_codes WHERE user_id = ?1",
                [user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        let suffix = format!("{:016x}", user_id.raw());
        transaction
            .execute(
                "UPDATE auth_users
                    SET email = ?1,
                        display_name = ?2,
                        password_hash = NULL,
                        password_changed_at = NULL,
                        email_verified_at = NULL,
                        deletion_due_at = NULL,
                        anonymized_at = ?3
                  WHERE id = ?4",
                params![
                    format!("deleted-{suffix}@deleted.invalid"),
                    format!("Deleted User #{}", &suffix[suffix.len() - 6..]),
                    now.timestamp(),
                    user_id.raw()
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(true)
    }

    pub fn account_auth_methods(
        &self,
        principal: &Principal,
    ) -> Result<AccountAuthMethods, AuthError> {
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let password_set = connection
            .query_row(
                "SELECT password_hash IS NOT NULL
                   FROM auth_users
                  WHERE id = ?1 AND anonymized_at IS NULL",
                [principal.user_id.raw()],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidSession)?;
        let apple_identity = connection
            .query_row(
                "SELECT email FROM external_identities
                  WHERE provider = 'apple' AND user_id = ?1
                  ORDER BY updated_at DESC
                  LIMIT 1",
                [principal.user_id.raw()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?;
        Ok(AccountAuthMethods {
            password_set,
            apple_linked: apple_identity.is_some(),
            apple_email: apple_identity.flatten(),
        })
    }

    pub fn begin_apple_flow(&self, device_id: &str) -> Result<(String, String), AuthError> {
        Uuid::parse_str(device_id).map_err(|_| AuthError::InvalidDevice)?;
        let state = random_secret("exo_as_")?;
        let nonce = random_secret("exo_an_")?;
        let state_hash = hash_secret(&state);
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        connection
            .execute(
                "INSERT INTO apple_flows
                   (state_hash, nonce, device_id, expires_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    state_hash.as_slice(),
                    nonce,
                    device_id,
                    (Utc::now() + Duration::minutes(10)).timestamp()
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        Ok((state, nonce))
    }

    pub fn begin_apple_link(
        &self,
        principal: &Principal,
        current_password: &str,
    ) -> Result<(String, String), AuthError> {
        if self.apple.is_none() {
            return Err(AuthError::AppleFailure);
        }
        let password_hash = {
            let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
            connection
                .query_row(
                    "SELECT password_hash
                       FROM auth_users
                      WHERE id = ?1 AND anonymized_at IS NULL",
                    [principal.user_id.raw()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|_| AuthError::Storage)?
                .flatten()
                .ok_or(AuthError::AppleLinkRequired)?
        };
        if !verify_password(current_password, &password_hash)? {
            return Err(AuthError::InvalidCurrentPassword);
        }
        let state = random_secret("exo_as_")?;
        let nonce = random_secret("exo_an_")?;
        let state_hash = hash_secret(&state);
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let valid_session_and_password: bool = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1
                     FROM auth_users AS users
                     JOIN auth_sessions AS sessions ON sessions.user_id = users.id
                    WHERE users.id = ?1
                      AND users.password_hash = ?2
                      AND users.anonymized_at IS NULL
                      AND sessions.id = ?3
                      AND sessions.revoked_at IS NULL
                      AND sessions.expires_at >= ?4
                 )",
                params![
                    principal.user_id.raw(),
                    password_hash,
                    principal.session_id,
                    now
                ],
                |row| row.get(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if !valid_session_and_password {
            return Err(AuthError::InvalidCurrentPassword);
        }
        let already_linked: bool = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM external_identities
                    WHERE provider = 'apple' AND user_id = ?1
                 )",
                [principal.user_id.raw()],
                |row| row.get(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if already_linked {
            return Err(AuthError::AppleAlreadyLinked);
        }
        transaction
            .execute(
                "INSERT INTO apple_flows
                   (state_hash, nonce, device_id, expires_at, flow_kind,
                    link_user_id, link_session_id)
                 VALUES (?1, ?2, ?3, ?4, 'link', ?5, ?6)",
                params![
                    state_hash.as_slice(),
                    nonce,
                    principal.device_id.to_string(),
                    (Utc::now() + Duration::minutes(10)).timestamp(),
                    principal.user_id.raw(),
                    principal.session_id
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok((state, nonce))
    }

    pub fn unlink_apple(
        &self,
        principal: &Principal,
        current_password: &str,
    ) -> Result<(), AuthError> {
        let password_hash = {
            let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
            connection
                .query_row(
                    "SELECT password_hash
                       FROM auth_users
                      WHERE id = ?1 AND anonymized_at IS NULL",
                    [principal.user_id.raw()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|_| AuthError::Storage)?
                .flatten()
                .ok_or(AuthError::AppleUnlinkUnsafe)?
        };
        if !verify_password(current_password, &password_hash)? {
            return Err(AuthError::InvalidCurrentPassword);
        }
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let unchanged: bool = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM auth_users
                    WHERE id = ?1
                      AND password_hash = ?2
                      AND anonymized_at IS NULL
                 )",
                params![principal.user_id.raw(), password_hash],
                |row| row.get(0),
            )
            .map_err(|_| AuthError::Storage)?;
        if !unchanged {
            return Err(AuthError::InvalidCurrentPassword);
        }
        let removed = transaction
            .execute(
                "DELETE FROM external_identities
                  WHERE provider = 'apple' AND user_id = ?1",
                [principal.user_id.raw()],
            )
            .map_err(|_| AuthError::Storage)?;
        if removed == 0 {
            return Err(AuthError::AppleNotLinked);
        }
        transaction.commit().map_err(|_| AuthError::Storage)
    }

    pub fn apple_flow(&self, state: &str) -> Result<AppleFlow, AuthError> {
        let state_hash = hash_secret(state);
        let now = Utc::now().timestamp();
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        connection
            .query_row(
                "SELECT nonce, flow_kind FROM apple_flows
                  WHERE state_hash = ?1
                    AND expires_at >= ?2
                    AND consumed_at IS NULL
                    AND completed_at IS NULL
                    AND error IS NULL",
                params![state_hash.as_slice(), now],
                |row| {
                    Ok(AppleFlow {
                        nonce: row.get(0)?,
                        linking: row.get::<_, String>(1)? == "link",
                    })
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidAppleFlow)
    }

    pub fn complete_apple_flow(
        &self,
        state: &str,
        subject: &str,
        email: &str,
        display_name: Option<&str>,
        apple_refresh_token: &str,
    ) -> Result<(), AuthError> {
        let config = self.apple.as_ref().ok_or(AuthError::AppleFailure)?;
        let email = normalize_email(email)?;
        let state_hash = hash_secret(state);
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let flow = transaction
            .query_row(
                "SELECT device_id, flow_kind, link_user_id, link_session_id
                   FROM apple_flows
                  WHERE state_hash = ?1
                    AND expires_at >= ?2
                    AND consumed_at IS NULL
                    AND completed_at IS NULL
                    AND error IS NULL",
                params![state_hash.as_slice(), now],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<u64>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidAppleFlow)?;

        if flow.1 == "link" {
            let link_user_id = flow.2.ok_or(AuthError::InvalidAppleFlow)?;
            let link_session_id = flow.3.as_deref().ok_or(AuthError::InvalidAppleFlow)?;
            let target_is_active: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1
                         FROM auth_users AS users
                         JOIN auth_sessions AS sessions ON sessions.user_id = users.id
                        WHERE users.id = ?1
                          AND users.anonymized_at IS NULL
                          AND sessions.id = ?2
                          AND sessions.revoked_at IS NULL
                          AND sessions.expires_at >= ?3
                     )",
                    params![link_user_id, link_session_id, now],
                    |row| row.get(0),
                )
                .map_err(|_| AuthError::Storage)?;
            if !target_is_active {
                return Err(AuthError::InvalidAppleFlow);
            }
            let subject_owner = transaction
                .query_row(
                    "SELECT user_id FROM external_identities
                      WHERE provider = 'apple' AND subject = ?1",
                    [subject],
                    |row| row.get::<_, u64>(0),
                )
                .optional()
                .map_err(|_| AuthError::Storage)?;
            if subject_owner.is_some_and(|owner| owner != link_user_id) {
                return Err(AuthError::AppleAlreadyLinked);
            }
            let linked_subject = transaction
                .query_row(
                    "SELECT subject FROM external_identities
                      WHERE provider = 'apple' AND user_id = ?1
                      LIMIT 1",
                    [link_user_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| AuthError::Storage)?;
            if linked_subject
                .as_deref()
                .is_some_and(|linked| linked != subject)
            {
                return Err(AuthError::AppleAlreadyLinked);
            }
            if subject_owner.is_none() {
                transaction
                    .execute(
                        "INSERT INTO external_identities
                           (provider, subject, user_id, email, created_at, updated_at)
                         VALUES ('apple', ?1, ?2, ?3, ?4, ?4)",
                        params![subject, link_user_id, email, now],
                    )
                    .map_err(|_| AuthError::Storage)?;
            }
            let encrypted_refresh = seal(
                &config.provider_token_key,
                subject.as_bytes(),
                apple_refresh_token.as_bytes(),
            )?;
            transaction
                .execute(
                    "UPDATE external_identities
                        SET email = ?1, refresh_token_enc = ?2, updated_at = ?3
                      WHERE provider = 'apple' AND subject = ?4 AND user_id = ?5",
                    params![email, encrypted_refresh, now, subject, link_user_id],
                )
                .map_err(|_| AuthError::Storage)?;
            transaction
                .execute(
                    "UPDATE apple_flows SET completed_at = ?1
                      WHERE state_hash = ?2",
                    params![now, state_hash.as_slice()],
                )
                .map_err(|_| AuthError::Storage)?;
            transaction.commit().map_err(|_| AuthError::Storage)?;
            return Ok(());
        }
        if flow.1 != "login" || flow.2.is_some() || flow.3.is_some() {
            return Err(AuthError::InvalidAppleFlow);
        }
        let device_id = flow.0;
        let existing_user_id = transaction
            .query_row(
                "SELECT user_id FROM external_identities
                  WHERE provider = 'apple' AND subject = ?1",
                [subject],
                |row| row.get::<_, u64>(0),
            )
            .optional()
            .map_err(|_| AuthError::Storage)?;
        let user = if let Some(user_id) = existing_user_id {
            load_user(&transaction, user_id)?
        } else {
            let existing_email_user = transaction
                .query_row(
                    "SELECT id, email, display_name, deletion_due_at, email_verified_at
                       FROM auth_users
                      WHERE email = ?1 AND anonymized_at IS NULL",
                    [&email],
                    |row| Ok((auth_user_from_row(row)?, row.get::<_, Option<i64>>(4)?)),
                )
                .optional()
                .map_err(|_| AuthError::Storage)?;
            let mut user = match existing_email_user {
                Some((user, Some(_))) => user,
                Some((_, None)) => return Err(AuthError::AppleLinkRequired),
                None => {
                    let id = UserId::new().raw();
                    let display_name = display_name_for(&email);
                    transaction
                        .execute(
                            "INSERT INTO auth_users
                               (id, email, display_name, created_at, email_verified_at)
                             VALUES (?1, ?2, ?3, ?4, ?4)",
                            params![id, email, display_name, now],
                        )
                        .map_err(|_| AuthError::Storage)?;
                    AuthUser {
                        id: id.to_string(),
                        email: email.clone(),
                        display_name,
                        deletion_scheduled_for: None,
                    }
                }
            };
            if let Some(name) = display_name.map(str::trim).filter(|name| !name.is_empty()) {
                transaction
                    .execute(
                        "UPDATE auth_users SET display_name = ?1 WHERE id = ?2",
                        params![
                            name.chars().take(80).collect::<String>(),
                            user.id.parse::<u64>().map_err(|_| AuthError::Storage)?
                        ],
                    )
                    .map_err(|_| AuthError::Storage)?;
                user.display_name = name.chars().take(80).collect();
            }
            transaction
                .execute(
                    "INSERT INTO external_identities
                       (provider, subject, user_id, email, created_at, updated_at)
                     VALUES ('apple', ?1, ?2, ?3, ?4, ?4)",
                    params![
                        subject,
                        user.id.parse::<u64>().map_err(|_| AuthError::Storage)?,
                        email,
                        now
                    ],
                )
                .map_err(|_| AuthError::Storage)?;
            user
        };
        let encrypted_refresh = seal(
            &config.provider_token_key,
            subject.as_bytes(),
            apple_refresh_token.as_bytes(),
        )?;
        transaction
            .execute(
                "UPDATE external_identities
                    SET email = ?1, refresh_token_enc = ?2, updated_at = ?3
                  WHERE provider = 'apple' AND subject = ?4",
                params![email, encrypted_refresh, now, subject],
            )
            .map_err(|_| AuthError::Storage)?;
        let session = issue_session(&transaction, &user, &device_id, "Exocord Desktop · Apple")?;
        let session_json = serde_json::to_vec(&session).map_err(|_| AuthError::Encryption)?;
        let encrypted_result = seal(
            &config.provider_token_key,
            state_hash.as_slice(),
            &session_json,
        )?;
        transaction
            .execute(
                "UPDATE apple_flows
                    SET completed_at = ?1, encrypted_result = ?2
                  WHERE state_hash = ?3",
                params![now, encrypted_result, state_hash.as_slice()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)
    }

    pub fn fail_apple_flow(&self, state: &str, message: &str) -> Result<(), AuthError> {
        let state_hash = hash_secret(state);
        let connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let updated = connection
            .execute(
                "UPDATE apple_flows
                    SET error = ?1, completed_at = ?2
                  WHERE state_hash = ?3
                    AND expires_at >= ?2
                    AND consumed_at IS NULL
                    AND completed_at IS NULL",
                params![
                    message.chars().take(160).collect::<String>(),
                    Utc::now().timestamp(),
                    state_hash.as_slice()
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        if updated == 0 {
            return Err(AuthError::InvalidAppleFlow);
        }
        Ok(())
    }

    pub fn poll_apple_flow(&self, state: &str) -> Result<AppleFlowPoll, AuthError> {
        let config = self.apple.as_ref().ok_or(AuthError::AppleFailure)?;
        let state_hash = hash_secret(state);
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let row = transaction
            .query_row(
                "SELECT expires_at, consumed_at, completed_at, encrypted_result, error
                   FROM apple_flows
                  WHERE state_hash = ?1
                    AND flow_kind = 'login'
                    AND link_user_id IS NULL
                    AND link_session_id IS NULL",
                [state_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidAppleFlow)?;
        if row.0 < now || row.1.is_some() {
            return Err(AuthError::InvalidAppleFlow);
        }
        if row.2.is_none() {
            return Ok(AppleFlowPoll::Pending);
        }
        transaction
            .execute(
                "UPDATE apple_flows SET consumed_at = ?1 WHERE state_hash = ?2",
                params![now, state_hash.as_slice()],
            )
            .map_err(|_| AuthError::Storage)?;
        if let Some(error) = row.4 {
            transaction.commit().map_err(|_| AuthError::Storage)?;
            return Ok(AppleFlowPoll::Failed(error));
        }
        let encrypted = row.3.ok_or(AuthError::Encryption)?;
        let plaintext = open(
            &config.provider_token_key,
            state_hash.as_slice(),
            &encrypted,
        )?;
        let session = serde_json::from_slice::<SessionBundle>(&plaintext)
            .map_err(|_| AuthError::Encryption)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        Ok(AppleFlowPoll::Complete(Box::new(session)))
    }

    pub fn poll_apple_link(
        &self,
        principal: &Principal,
        state: &str,
    ) -> Result<AppleLinkPoll, AuthError> {
        let state_hash = hash_secret(state);
        let now = Utc::now().timestamp();
        let mut connection = self.connection.lock().map_err(|_| AuthError::Storage)?;
        let transaction = connection.transaction().map_err(|_| AuthError::Storage)?;
        let row = transaction
            .query_row(
                "SELECT expires_at, consumed_at, completed_at, error
                   FROM apple_flows
                  WHERE state_hash = ?1
                    AND flow_kind = 'link'
                    AND link_user_id = ?2
                    AND link_session_id = ?3",
                params![
                    state_hash.as_slice(),
                    principal.user_id.raw(),
                    principal.session_id
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthError::Storage)?
            .ok_or(AuthError::InvalidAppleFlow)?;
        if row.0 < now || row.1.is_some() {
            return Err(AuthError::InvalidAppleFlow);
        }
        if row.2.is_none() {
            return Ok(AppleLinkPoll::Pending);
        }
        transaction
            .execute(
                "UPDATE apple_flows SET consumed_at = ?1 WHERE state_hash = ?2",
                params![now, state_hash.as_slice()],
            )
            .map_err(|_| AuthError::Storage)?;
        transaction.commit().map_err(|_| AuthError::Storage)?;
        if let Some(error) = row.3 {
            return Ok(AppleLinkPoll::Failed(error));
        }
        Ok(AppleLinkPoll::Complete)
    }
}

fn ensure_column(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), AuthError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|_| AuthError::Storage)?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| AuthError::Storage)?;
    let mut present = false;
    for name in names {
        if name.map_err(|_| AuthError::Storage)? == column {
            present = true;
            break;
        }
    }
    if !present {
        connection
            .execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN {column} {definition};"
            ))
            .map_err(|_| AuthError::Storage)?;
    }
    Ok(())
}

fn find_or_create_user(transaction: &Transaction<'_>, email: &str) -> Result<AuthUser, AuthError> {
    if let Some(user) = transaction
        .query_row(
            "SELECT id, email, display_name, deletion_due_at
               FROM auth_users
              WHERE email = ?1 AND anonymized_at IS NULL",
            [email],
            auth_user_from_row,
        )
        .optional()
        .map_err(|_| AuthError::Storage)?
    {
        return Ok(user);
    }
    let id = UserId::new().raw();
    let display_name = display_name_for(email);
    transaction
        .execute(
            "INSERT INTO auth_users (id, email, display_name, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![id, email, display_name, Utc::now().timestamp()],
        )
        .map_err(|_| AuthError::Storage)?;
    Ok(AuthUser {
        id: id.to_string(),
        email: email.to_owned(),
        display_name,
        deletion_scheduled_for: None,
    })
}

fn load_user(connection: &Connection, user_id: u64) -> Result<AuthUser, AuthError> {
    connection
        .query_row(
            "SELECT id, email, display_name, deletion_due_at
               FROM auth_users
              WHERE id = ?1 AND anonymized_at IS NULL",
            [user_id],
            auth_user_from_row,
        )
        .optional()
        .map_err(|_| AuthError::Storage)?
        .ok_or(AuthError::InvalidSession)
}

fn load_account_suspension(
    connection: &Connection,
    user_id: UserId,
) -> Result<AccountSuspension, AuthError> {
    connection
        .query_row(
            "SELECT suspended_at, suspended_by, suspension_reason,
                    suspension_report_id
               FROM auth_users
              WHERE id = ?1 AND anonymized_at IS NULL",
            [user_id.raw()],
            |row| {
                let suspended_at = row.get::<_, Option<i64>>(0)?;
                Ok((
                    suspended_at,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| AuthError::Storage)?
        .ok_or(AuthError::AccountUnavailable)
        .and_then(|(suspended_at, suspended_by, reason, report_id)| {
            Ok(AccountSuspension {
                user_id: user_id.to_string(),
                suspended: suspended_at.is_some(),
                suspended_at: suspended_at.map(timestamp_rfc3339).transpose()?,
                suspended_by,
                reason,
                report_id,
            })
        })
}

fn load_enforcement_events(
    connection: &Connection,
    user_id: UserId,
    limit: i64,
) -> Result<Vec<AccountEnforcementEvent>, AuthError> {
    let mut statement = connection
        .prepare(
            "SELECT id, action, operator, reason, report_id, created_at
               FROM account_enforcement_events
              WHERE user_id = ?1
              ORDER BY created_at DESC, id DESC
              LIMIT ?2",
        )
        .map_err(|_| AuthError::Storage)?;
    statement
        .query_map(params![user_id.raw(), limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|_| AuthError::Storage)?
        .map(|row| {
            let (id, action, operator, reason, report_id, created_at) =
                row.map_err(|_| AuthError::Storage)?;
            Ok(AccountEnforcementEvent {
                id,
                action,
                operator,
                reason,
                report_id,
                created_at: timestamp_rfc3339(created_at)?,
            })
        })
        .collect()
}

fn validate_enforcement(
    operator: &str,
    reason: &str,
    report_id: Option<&str>,
) -> Result<(), AuthError> {
    let operator = operator.trim();
    let reason = reason.trim();
    if operator.is_empty()
        || operator.chars().count() > 100
        || operator.chars().any(char::is_control)
        || reason.is_empty()
        || reason.chars().count() > 1_000
        || reason
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        || report_id.is_some_and(|value| {
            value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(AuthError::InvalidEnforcement);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_enforcement_event(
    transaction: &Transaction<'_>,
    user_id: UserId,
    action: &str,
    operator: &str,
    reason: &str,
    report_id: Option<&str>,
    created_at: i64,
) -> Result<(), AuthError> {
    transaction
        .execute(
            "INSERT INTO account_enforcement_events
               (id, user_id, action, operator, reason, report_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                Uuid::now_v7().to_string(),
                user_id.raw(),
                action,
                operator.trim(),
                reason.trim(),
                report_id,
                created_at
            ],
        )
        .map_err(|_| AuthError::Storage)?;
    Ok(())
}

fn auth_user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthUser> {
    let deletion_due_at = row.get::<_, Option<i64>>(3)?;
    Ok(AuthUser {
        id: row.get::<_, u64>(0)?.to_string(),
        email: row.get(1)?,
        display_name: row.get(2)?,
        deletion_scheduled_for: deletion_due_at
            .and_then(|value| DateTime::<Utc>::from_timestamp(value, 0))
            .map(|value| value.to_rfc3339()),
    })
}

fn recovery_account(
    connection: &Connection,
    email: &str,
    code_hash: &[u8; 32],
) -> Result<(AuthUser, Option<WrappedAccountKey>), AuthError> {
    connection
        .query_row(
            "SELECT users.id, users.email, users.display_name, users.deletion_due_at,
                    codes.key_version, codes.key_salt, codes.key_nonce,
                    codes.key_ciphertext
               FROM auth_users AS users
               JOIN password_recovery_codes AS codes
                 ON codes.user_id = users.id
              WHERE users.email = ?1
                AND users.anonymized_at IS NULL
                AND codes.code_hash = ?2",
            params![email, code_hash.as_slice()],
            |row| {
                let user = auth_user_from_row(row)?;
                let version = row.get::<_, Option<u8>>(4)?;
                let salt = row.get::<_, Option<String>>(5)?;
                let nonce = row.get::<_, Option<String>>(6)?;
                let ciphertext = row.get::<_, Option<String>>(7)?;
                let wrapped = match (version, salt, nonce, ciphertext) {
                    (Some(version), Some(salt), Some(nonce), Some(ciphertext)) => {
                        Some(WrappedAccountKey {
                            version,
                            salt,
                            nonce,
                            ciphertext,
                        })
                    }
                    (None, None, None, None) => None,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok((user, wrapped))
            },
        )
        .optional()
        .map_err(|_| AuthError::Storage)?
        .ok_or(AuthError::InvalidRecoveryCode)
}

fn deletion_from_timestamps(
    requested_at: Option<i64>,
    due_at: Option<i64>,
) -> Result<Option<AccountDeletion>, AuthError> {
    match (requested_at, due_at) {
        (Some(requested_at), Some(due_at)) => Ok(Some(AccountDeletion {
            requested_at: timestamp_rfc3339(requested_at)?,
            scheduled_for: timestamp_rfc3339(due_at)?,
        })),
        (None, None) => Ok(None),
        _ => Err(AuthError::Storage),
    }
}

fn timestamp_rfc3339(timestamp: i64) -> Result<String, AuthError> {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|value| value.to_rfc3339())
        .ok_or(AuthError::Storage)
}

fn issue_session(
    transaction: &Transaction<'_>,
    user: &AuthUser,
    device_id: &str,
    client_name: &str,
) -> Result<SessionBundle, AuthError> {
    Uuid::parse_str(device_id).map_err(|_| AuthError::InvalidDevice)?;
    let user_id = user.id.parse::<u64>().map_err(|_| AuthError::Storage)?;
    let revoked: bool = transaction
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM revoked_devices
               WHERE user_id = ?1 AND device_id = ?2
             )",
            params![user_id, device_id],
            |row| row.get(0),
        )
        .map_err(|_| AuthError::Storage)?;
    if revoked {
        return Err(AuthError::DeviceRevoked);
    }
    let session_id = Uuid::now_v7().to_string();
    let now = Utc::now();
    let refresh_expires = now + Duration::days(REFRESH_LIFETIME_DAYS);
    transaction
        .execute(
            "INSERT INTO auth_sessions
               (id, user_id, device_id, client_name, created_at, last_seen_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            params![
                session_id,
                user_id,
                device_id,
                client_name,
                now.timestamp(),
                refresh_expires.timestamp()
            ],
        )
        .map_err(|_| AuthError::Storage)?;
    rotate_session(transaction, &session_id, user)
}

fn rotate_session(
    transaction: &Transaction<'_>,
    session_id: &str,
    user: &AuthUser,
) -> Result<SessionBundle, AuthError> {
    let user_id = user.id.parse::<u64>().map_err(|_| AuthError::Storage)?;
    let suspended: bool = transaction
        .query_row(
            "SELECT suspended_at IS NOT NULL
               FROM auth_users
              WHERE id = ?1 AND anonymized_at IS NULL",
            [user_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| AuthError::Storage)?
        .ok_or(AuthError::InvalidSession)?;
    if suspended {
        return Err(AuthError::AccountSuspended);
    }
    let now = Utc::now();
    let access_expires = now + Duration::minutes(ACCESS_LIFETIME_MINUTES);
    let refresh_expires = now + Duration::days(REFRESH_LIFETIME_DAYS);
    let access_token = random_secret("exo_at_")?;
    let refresh_token = random_secret("exo_rt_")?;
    for (token, kind, expires) in [
        (&access_token, "access", access_expires.timestamp()),
        (&refresh_token, "refresh", refresh_expires.timestamp()),
    ] {
        let hash = hash_secret(token);
        transaction
            .execute(
                "INSERT INTO auth_tokens (token_hash, session_id, kind, expires_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![hash.as_slice(), session_id, kind, expires],
            )
            .map_err(|_| AuthError::Storage)?;
    }
    Ok(SessionBundle {
        access_token,
        refresh_token,
        access_expires_at: access_expires.to_rfc3339(),
        refresh_expires_at: refresh_expires.to_rfc3339(),
        user: user.clone(),
        recovery_codes: Vec::new(),
        recovery_wrapped_key: None,
    })
}

fn normalize_email(value: &str) -> Result<String, AuthError> {
    let email = value.trim().to_lowercase();
    let (local, domain) = email.split_once('@').ok_or(AuthError::InvalidEmail)?;
    if local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || email.len() > 254
        || email.chars().any(char::is_whitespace)
    {
        return Err(AuthError::InvalidEmail);
    }
    Ok(email)
}

fn validate_password(value: &str) -> Result<(), AuthError> {
    let characters = value.chars().count();
    if !(MIN_PASSWORD_CHARACTERS..=MAX_PASSWORD_CHARACTERS).contains(&characters)
        || value.len() > MAX_PASSWORD_BYTES
        || value.chars().any(|character| character == '\0')
    {
        return Err(AuthError::WeakPassword);
    }
    Ok(())
}

fn password_hasher() -> Result<Argon2<'static>, AuthError> {
    let params = Argon2Params::new(19_456, 2, 1, Some(32)).map_err(|_| AuthError::Storage)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_password(value: &str) -> Result<String, AuthError> {
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).map_err(|_| AuthError::Storage)?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| AuthError::Storage)?;
    password_hasher()?
        .hash_password(value.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthError::Storage)
}

fn verify_password(value: &str, encoded: &str) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(encoded).map_err(|_| AuthError::Storage)?;
    Ok(password_hasher()?
        .verify_password(value.as_bytes(), &parsed)
        .is_ok())
}

fn display_name_for(email: &str) -> String {
    email
        .split('@')
        .next()
        .unwrap_or("Member")
        .split(['.', '_', '-'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_username(value: &str) -> Result<String, AuthError> {
    let username = value.trim().to_ascii_lowercase();
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
        return Err(AuthError::InvalidUsername);
    }
    Ok(username)
}

fn six_digit_code() -> Result<String, AuthError> {
    const CODE_SPACE: u32 = 1_000_000;
    const UNBIASED_UPPER_BOUND: u32 = u32::MAX - (u32::MAX % CODE_SPACE);
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| AuthError::Randomness)?;
        let value = u32::from_le_bytes(bytes);
        if value < UNBIASED_UPPER_BOUND {
            return Ok(format!("{:06}", value % CODE_SPACE));
        }
    }
}

fn random_secret(prefix: &str) -> Result<String, AuthError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Randomness)?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn hash_secret(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn hash_recovery_code(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"exocord-password-recovery-v1:");
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

fn validate_wrapped_account_key(value: &WrappedAccountKey) -> Result<(), AuthError> {
    let decoded_len = |encoded: &str| {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map(|bytes| bytes.len())
            .map_err(|_| AuthError::InvalidRecoveryMaterial)
    };
    if value.version != 1
        || decoded_len(&value.salt)? != 16
        || decoded_len(&value.nonce)? != 24
        || decoded_len(&value.ciphertext)? != 48
    {
        return Err(AuthError::InvalidRecoveryMaterial);
    }
    Ok(())
}

fn replace_recovery_codes(
    transaction: &Transaction<'_>,
    user_id: u64,
) -> Result<Vec<String>, AuthError> {
    transaction
        .execute(
            "DELETE FROM password_recovery_codes WHERE user_id = ?1",
            [user_id],
        )
        .map_err(|_| AuthError::Storage)?;
    stage_recovery_codes(transaction, user_id)
}

fn stage_recovery_codes(
    transaction: &Transaction<'_>,
    user_id: u64,
) -> Result<Vec<String>, AuthError> {
    let batch_id = Uuid::now_v7().to_string();
    let created_at = Utc::now().timestamp();
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| AuthError::Storage)?;
        let code = format!("exo_rc_{}", URL_SAFE_NO_PAD.encode(bytes));
        let hash = hash_recovery_code(&code);
        transaction
            .execute(
                "INSERT INTO password_recovery_codes
                   (user_id, code_hash, batch_id, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![user_id, hash.as_slice(), batch_id, created_at],
            )
            .map_err(|_| AuthError::Storage)?;
        codes.push(code);
    }
    Ok(codes)
}

fn stage_provisioned_recovery_codes(
    transaction: &Transaction<'_>,
    user_id: u64,
    recovery_vaults: &[RecoveryKeyVault],
) -> Result<Vec<String>, AuthError> {
    if recovery_vaults.len() != RECOVERY_CODE_COUNT {
        return Err(AuthError::InvalidRecoveryMaterial);
    }
    let batch_id = Uuid::now_v7().to_string();
    let created_at = Utc::now().timestamp();
    let mut unique_hashes = HashSet::with_capacity(recovery_vaults.len());
    let mut recovery_codes = Vec::with_capacity(recovery_vaults.len());
    for entry in recovery_vaults {
        let recovery_code = entry.recovery_code.trim();
        if !recovery_code.starts_with("exo_rc_") || recovery_code.len() != 29 {
            return Err(AuthError::InvalidRecoveryMaterial);
        }
        validate_wrapped_account_key(&entry.wrapped_key)?;
        let hash = hash_recovery_code(recovery_code);
        if !unique_hashes.insert(hash) {
            return Err(AuthError::InvalidRecoveryMaterial);
        }
        transaction
            .execute(
                "INSERT INTO password_recovery_codes
                   (user_id, code_hash, batch_id, created_at, key_version,
                    key_salt, key_nonce, key_ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    user_id,
                    hash.as_slice(),
                    batch_id,
                    created_at,
                    entry.wrapped_key.version,
                    entry.wrapped_key.salt,
                    entry.wrapped_key.nonce,
                    entry.wrapped_key.ciphertext
                ],
            )
            .map_err(|_| AuthError::Storage)?;
        recovery_codes.push(recovery_code.to_owned());
    }
    Ok(recovery_codes)
}

fn provisioning_matches(
    connection: &Connection,
    user_id: u64,
    account_key: &WrappedAccountKey,
    recovery_vaults: &[RecoveryKeyVault],
) -> Result<bool, AuthError> {
    if recovery_vaults.len() != RECOVERY_CODE_COUNT {
        return Ok(false);
    }
    let mut expected_hashes = HashSet::with_capacity(recovery_vaults.len());
    for entry in recovery_vaults {
        validate_wrapped_account_key(&entry.wrapped_key)?;
        let code = entry.recovery_code.trim();
        if !code.starts_with("exo_rc_")
            || code.len() != 29
            || !expected_hashes.insert(hash_recovery_code(code))
        {
            return Ok(false);
        }
    }
    let stored_key = connection
        .query_row(
            "SELECT version, salt, nonce, ciphertext
               FROM account_key_vaults
              WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok(WrappedAccountKey {
                    version: row.get(0)?,
                    salt: row.get(1)?,
                    nonce: row.get(2)?,
                    ciphertext: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|_| AuthError::Storage)?;
    if !stored_key.is_some_and(|stored| {
        stored.version == account_key.version
            && stored.salt == account_key.salt
            && stored.nonce == account_key.nonce
            && stored.ciphertext == account_key.ciphertext
    }) {
        return Ok(false);
    }
    let mut statement = connection
        .prepare("SELECT code_hash FROM password_recovery_codes WHERE user_id = ?1")
        .map_err(|_| AuthError::Storage)?;
    let stored_hashes = statement
        .query_map([user_id], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| AuthError::Storage)?
        .map(|row| {
            row.map_err(|_| AuthError::Storage)?
                .try_into()
                .map_err(|_| AuthError::Storage)
        })
        .collect::<Result<HashSet<[u8; 32]>, _>>()?;
    Ok(stored_hashes == expected_hashes)
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| AuthError::Encryption)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AuthError::Encryption)?;
    let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, AuthError> {
    if sealed.len() < 24 {
        return Err(AuthError::Encryption);
    }
    let (nonce, ciphertext) = sealed.split_at(24);
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AuthError::Encryption)
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    const TEST_DEVICE_ID: &str = "018f04b2-3c71-7f42-b12d-6f090d44be11";

    fn service() -> AuthService {
        let file = NamedTempFile::new().unwrap();
        AuthService::open(file.path(), EmailDelivery::DevelopmentConsole, None).unwrap()
    }

    fn wrapped_account_key(fill: u8) -> WrappedAccountKey {
        WrappedAccountKey {
            version: 1,
            salt: URL_SAFE_NO_PAD.encode([fill; 16]),
            nonce: URL_SAFE_NO_PAD.encode([fill.wrapping_add(1); 24]),
            ciphertext: URL_SAFE_NO_PAD.encode([fill.wrapping_add(2); 48]),
        }
    }

    fn recovery_key_vaults(codes: &[String], fill: u8) -> Vec<RecoveryKeyVault> {
        codes
            .iter()
            .map(|recovery_code| RecoveryKeyVault {
                recovery_code: recovery_code.clone(),
                wrapped_key: wrapped_account_key(fill),
            })
            .collect()
    }

    fn apple_service() -> AuthService {
        let file = NamedTempFile::new().unwrap();
        AuthService::open(
            file.path(),
            EmailDelivery::DevelopmentConsole,
            Some(AppleConfig {
                client_id: "com.exocord.test".into(),
                team_id: "TESTTEAM01".into(),
                key_id: "TESTKEY001".into(),
                private_key_pem: String::new(),
                redirect_uri: "https://example.com/callback".into(),
                provider_token_key: [9; 32],
                authorize_url: "https://appleid.apple.com/auth/authorize".into(),
                token_url: "https://appleid.apple.com/auth/token".into(),
                jwks_url: "https://appleid.apple.com/auth/keys".into(),
            }),
        )
        .unwrap()
    }

    #[test]
    fn email_code_creates_and_authenticates_a_session() {
        let service = service();
        let challenge = service.request_email_code(" Erix@Example.COM ").unwrap();
        let session = service
            .verify_email_code(&challenge.id, &challenge.code, TEST_DEVICE_ID, "test")
            .unwrap();
        let principal = service.authenticate(&session.access_token).unwrap();
        assert_eq!(principal.user_id.to_string(), session.user.id);
        assert_eq!(session.user.email, "erix@example.com");
    }

    #[test]
    fn password_registration_hashes_and_authenticates_credentials() {
        let service = service();
        let registered = service
            .register_password(
                " Erix@Example.COM ",
                "correct horse battery staple",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        assert_eq!(registered.user.email, "erix@example.com");
        assert!(service.authenticate(&registered.access_token).is_ok());

        let stored_hash = service
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT password_hash FROM auth_users WHERE email = ?1",
                ["erix@example.com"],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert!(stored_hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(!stored_hash.contains("correct horse battery staple"));

        let login = service
            .login_password(
                "erix@example.com",
                "correct horse battery staple",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        assert_eq!(login.user.id, registered.user.id);
        assert!(service.authenticate(&login.access_token).is_ok());
    }

    #[test]
    fn password_auth_rejects_weak_duplicate_and_invalid_credentials() {
        let service = service();
        assert!(matches!(
            service.register_password("alpha@example.com", "short", TEST_DEVICE_ID, "desktop"),
            Err(AuthError::WeakPassword)
        ));
        service
            .register_password(
                "alpha@example.com",
                "a long private password",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        assert!(matches!(
            service.register_password(
                "ALPHA@example.com",
                "another long private password",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::AccountExists)
        ));
        assert!(matches!(
            service.login_password(
                "alpha@example.com",
                "definitely the wrong password",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::InvalidCredentials)
        ));
        assert!(matches!(
            service.login_password(
                "missing@example.com",
                "definitely the wrong password",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn named_registration_enforces_case_insensitive_unique_usernames_and_emails() {
        let service = service();
        let first = service
            .register_password_named(
                "first@example.com",
                Some("Alpha_User"),
                "a long private password",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let first_id = first.user.id.parse::<UserId>().unwrap();
        assert_eq!(
            service.username(first_id).unwrap().as_deref(),
            Some("alpha_user")
        );
        assert_eq!(first.user.display_name, "alpha_user");
        assert!(matches!(
            service.register_password_named(
                "second@example.com",
                Some("ALPHA_USER"),
                "another long private password",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::UsernameExists)
        ));
        assert!(matches!(
            service.register_password_named(
                "FIRST@EXAMPLE.COM",
                Some("another_user"),
                "another long private password",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::AccountExists)
        ));
        assert!(matches!(
            service.register_password_named(
                "third@example.com",
                Some("no spaces"),
                "another long private password",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::InvalidUsername)
        ));
    }

    #[test]
    fn operator_suspension_revokes_sessions_and_reinstatement_keeps_an_audit_trail() {
        let service = service();
        let registered = service
            .register_password(
                "suspension@example.com",
                "correct horse battery staple",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let user_id = registered.user.id.parse::<UserId>().unwrap();
        let suspended = service
            .suspend_account(
                user_id,
                "Alpha safety operator",
                "Credible severe-abuse report.",
                Some("123"),
            )
            .unwrap();
        assert!(suspended.suspended);
        assert_eq!(suspended.report_id.as_deref(), Some("123"));
        assert!(matches!(
            service.authenticate(&registered.access_token),
            Err(AuthError::InvalidSession)
        ));
        assert!(matches!(
            service.login_password(
                "suspension@example.com",
                "correct horse battery staple",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::AccountSuspended)
        ));
        assert!(matches!(
            service.suspend_account(
                user_id,
                "Alpha safety operator",
                "Duplicate suspension.",
                Some("123")
            ),
            Err(AuthError::AccountEnforcementConflict)
        ));

        let overview = service.account_enforcement(user_id, 50).unwrap();
        assert!(overview.suspension.suspended);
        assert_eq!(overview.events.len(), 1);
        assert_eq!(overview.events[0].action, "suspended");

        let reinstated = service
            .reinstate_account(
                user_id,
                "Alpha safety operator",
                "Appeal accepted after review.",
                Some("123"),
            )
            .unwrap();
        assert!(!reinstated.suspended);
        assert!(matches!(
            service.reinstate_account(
                user_id,
                "Alpha safety operator",
                "Duplicate reinstatement.",
                None
            ),
            Err(AuthError::AccountEnforcementConflict)
        ));
        let fresh = service
            .login_password(
                "suspension@example.com",
                "correct horse battery staple",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        assert!(service.authenticate(&fresh.access_token).is_ok());
        let exported = service.data_export(user_id).unwrap();
        assert_eq!(exported.account_enforcement.len(), 2);
        assert_eq!(exported.account_enforcement[0].action, "reinstated");
        assert_eq!(exported.account_enforcement[1].action, "suspended");
    }

    #[test]
    fn account_key_vault_is_password_confirmed_and_account_scoped() {
        let service = service();
        let left = service
            .register_password(
                "vault-left@example.com",
                "left correct private password",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let right = service
            .register_password(
                "vault-right@example.com",
                "right correct private password",
                &Uuid::now_v7().to_string(),
                "desktop",
            )
            .unwrap();
        let left_principal = service.authenticate(&left.access_token).unwrap();
        let right_principal = service.authenticate(&right.access_token).unwrap();
        assert!(!service.recovery_key_vaults_ready(&left_principal).unwrap());
        let recovery_entries = left
            .recovery_codes
            .iter()
            .enumerate()
            .map(|(index, recovery_code)| RecoveryKeyVault {
                recovery_code: recovery_code.clone(),
                wrapped_key: wrapped_account_key(u8::try_from(index + 1).unwrap()),
            })
            .collect::<Vec<_>>();
        service
            .set_recovery_key_vaults(
                &left_principal,
                "left correct private password",
                &recovery_entries,
            )
            .unwrap();
        assert!(service.recovery_key_vaults_ready(&left_principal).unwrap());
        let wrapped = wrapped_account_key(1);
        assert!(matches!(
            service.set_account_key_vault(&left_principal, "wrong password", &wrapped),
            Err(AuthError::InvalidCurrentPassword)
        ));
        service
            .set_account_key_vault(&left_principal, "left correct private password", &wrapped)
            .unwrap();
        assert_eq!(
            service.account_key_vault(&left_principal).unwrap(),
            Some(wrapped)
        );
        assert_eq!(service.account_key_vault(&right_principal).unwrap(), None);
    }

    #[test]
    fn provisioned_registration_and_recovery_are_atomic_and_idempotent() {
        let service = service();
        let user_id = UserId::new();
        let recovery_codes = (1_u8..=8)
            .map(|fill| format!("exo_rc_{}", URL_SAFE_NO_PAD.encode([fill; 16])))
            .collect::<Vec<_>>();
        let recovery_vaults = recovery_key_vaults(&recovery_codes, 11);
        let account_key = wrapped_account_key(10);
        let registered = service
            .register_password_provisioned(
                "provisioned@example.com",
                "first provisioned password",
                TEST_DEVICE_ID,
                "desktop",
                user_id,
                &account_key,
                &recovery_vaults,
            )
            .unwrap();
        assert_eq!(registered.user.id, user_id.to_string());
        assert_eq!(registered.recovery_codes, recovery_codes);

        let retried = service
            .register_password_provisioned(
                "provisioned@example.com",
                "first provisioned password",
                TEST_DEVICE_ID,
                "desktop retry",
                user_id,
                &account_key,
                &recovery_vaults,
            )
            .unwrap();
        assert_eq!(retried.user.id, user_id.to_string());
        assert_eq!(retried.recovery_codes, recovery_codes);

        let prepared = service
            .prepare_password_recovery("provisioned@example.com", &recovery_codes[0])
            .unwrap();
        assert_eq!(prepared.user_id, user_id);
        assert_eq!(prepared.wrapped_key, Some(wrapped_account_key(11)));

        let invalid_recovery = vec![RecoveryKeyVault {
            recovery_code: format!("exo_rc_{}", URL_SAFE_NO_PAD.encode([99_u8; 16])),
            wrapped_key: wrapped_account_key(31),
        }];
        assert!(matches!(
            service.recover_password_provisioned(
                "provisioned@example.com",
                &recovery_codes[0],
                "second provisioned password",
                TEST_DEVICE_ID,
                "desktop recovery",
                user_id,
                &wrapped_account_key(30),
                &invalid_recovery,
            ),
            Err(AuthError::InvalidRecoveryMaterial)
        ));
        assert!(
            service
                .login_password(
                    "provisioned@example.com",
                    "first provisioned password",
                    TEST_DEVICE_ID,
                    "desktop",
                )
                .is_ok()
        );

        let next_codes = (21_u8..=28)
            .map(|fill| format!("exo_rc_{}", URL_SAFE_NO_PAD.encode([fill; 16])))
            .collect::<Vec<_>>();
        let next_vaults = recovery_key_vaults(&next_codes, 41);
        let next_key = wrapped_account_key(40);
        let recovered = service
            .recover_password_provisioned(
                "provisioned@example.com",
                &recovery_codes[0],
                "second provisioned password",
                TEST_DEVICE_ID,
                "desktop recovery",
                user_id,
                &next_key,
                &next_vaults,
            )
            .unwrap();
        assert_eq!(recovered.recovery_codes, next_codes);
        assert!(
            service
                .login_password(
                    "provisioned@example.com",
                    "first provisioned password",
                    TEST_DEVICE_ID,
                    "desktop",
                )
                .is_err()
        );

        let retry = service
            .recover_password_provisioned(
                "provisioned@example.com",
                &recovery_codes[0],
                "second provisioned password",
                TEST_DEVICE_ID,
                "desktop recovery retry",
                user_id,
                &next_key,
                &next_vaults,
            )
            .unwrap();
        assert_eq!(retry.recovery_codes, next_codes);
    }

    #[test]
    fn recovery_wrappers_are_account_scoped_and_preserve_private_history() {
        let service = service();
        let registered = service
            .register_password(
                "wrapped-recovery@example.com",
                "first wrapped recovery password",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let principal = service.authenticate(&registered.access_token).unwrap();
        let password_wrapped = wrapped_account_key(10);
        service
            .set_account_key_vault(
                &principal,
                "first wrapped recovery password",
                &password_wrapped,
            )
            .unwrap();
        assert!(matches!(
            service.recover_password(
                "wrapped-recovery@example.com",
                &registered.recovery_codes[0],
                "second wrapped recovery password",
                &Uuid::now_v7().to_string(),
                "recovery"
            ),
            Err(AuthError::RecoveryKeyUnavailable)
        ));

        let recovery_wrapped = wrapped_account_key(20);
        let entries = registered
            .recovery_codes
            .iter()
            .map(|recovery_code| RecoveryKeyVault {
                recovery_code: recovery_code.clone(),
                wrapped_key: recovery_wrapped.clone(),
            })
            .collect::<Vec<_>>();
        service
            .set_recovery_key_vaults(&principal, "first wrapped recovery password", &entries)
            .unwrap();

        let other = service
            .register_password(
                "other-wrapped-recovery@example.com",
                "other wrapped recovery password",
                &Uuid::now_v7().to_string(),
                "desktop",
            )
            .unwrap();
        let other_principal = service.authenticate(&other.access_token).unwrap();
        assert!(matches!(
            service.set_recovery_key_vaults(
                &other_principal,
                "other wrapped recovery password",
                &entries
            ),
            Err(AuthError::InvalidRecoveryMaterial)
        ));

        let recovered = service
            .recover_password(
                "wrapped-recovery@example.com",
                &registered.recovery_codes[0],
                "second wrapped recovery password",
                &Uuid::now_v7().to_string(),
                "recovery",
            )
            .unwrap();
        assert_eq!(recovered.recovery_wrapped_key, Some(recovery_wrapped));
    }

    #[test]
    fn password_change_rehashes_and_revokes_other_sessions() {
        let service = service();
        let current = service
            .register_password(
                "change@example.com",
                "first correct private password",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let other_device = Uuid::now_v7().to_string();
        let other = service
            .login_password(
                "change@example.com",
                "first correct private password",
                &other_device,
                "laptop",
            )
            .unwrap();
        let principal = service.authenticate(&current.access_token).unwrap();
        let old_wrapper = wrapped_account_key(10);
        let new_wrapper = wrapped_account_key(11);
        service
            .set_account_key_vault(&principal, "first correct private password", &old_wrapper)
            .unwrap();

        assert!(matches!(
            service.change_password(
                &principal,
                "not the current password",
                "second correct private password",
                None,
            ),
            Err(AuthError::InvalidCurrentPassword)
        ));
        assert!(matches!(
            service.change_password(
                &principal,
                "first correct private password",
                "first correct private password",
                None,
            ),
            Err(AuthError::PasswordUnchanged)
        ));
        assert!(matches!(
            service.change_password(
                &principal,
                "first correct private password",
                "second correct private password",
                None,
            ),
            Err(AuthError::RecoveryKeyUnavailable)
        ));
        assert_eq!(
            service.account_key_vault(&principal).unwrap(),
            Some(old_wrapper)
        );
        service
            .change_password(
                &principal,
                "first correct private password",
                "second correct private password",
                Some(&new_wrapper),
            )
            .unwrap();
        assert_eq!(
            service.account_key_vault(&principal).unwrap(),
            Some(new_wrapper)
        );

        assert!(service.authenticate(&current.access_token).is_ok());
        assert!(matches!(
            service.authenticate(&other.access_token),
            Err(AuthError::InvalidSession)
        ));
        assert!(matches!(
            service.login_password(
                "change@example.com",
                "first correct private password",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::InvalidCredentials)
        ));
        assert!(
            service
                .login_password(
                    "change@example.com",
                    "second correct private password",
                    TEST_DEVICE_ID,
                    "desktop"
                )
                .is_ok()
        );
    }

    #[test]
    fn recovery_code_resets_password_once_and_rotates_the_set() {
        let service = service();
        let registered = service
            .register_password(
                "recover@example.com",
                "first private recovery password",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        assert_eq!(registered.recovery_codes.len(), RECOVERY_CODE_COUNT);
        let original_code = registered.recovery_codes[0].clone();
        let recovery_device = Uuid::now_v7().to_string();

        assert!(matches!(
            service.recover_password(
                "recover@example.com",
                "exo_rc_AAAAAAAAAAAAAAAAAAAAAA",
                "second private recovery password",
                &recovery_device,
                "recovery"
            ),
            Err(AuthError::InvalidRecoveryCode)
        ));
        let recovered = service
            .recover_password(
                "recover@example.com",
                &original_code,
                "second private recovery password",
                &recovery_device,
                "recovery",
            )
            .unwrap();
        assert_eq!(recovered.recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert!(!recovered.recovery_codes.contains(&original_code));
        assert!(matches!(
            service.authenticate(&registered.access_token),
            Err(AuthError::InvalidSession)
        ));
        assert!(service.authenticate(&recovered.access_token).is_ok());
        assert!(matches!(
            service.recover_password(
                "recover@example.com",
                &original_code,
                "third private recovery password",
                &Uuid::now_v7().to_string(),
                "recovery"
            ),
            Err(AuthError::InvalidRecoveryCode)
        ));
        assert!(matches!(
            service.login_password(
                "recover@example.com",
                "first private recovery password",
                TEST_DEVICE_ID,
                "desktop"
            ),
            Err(AuthError::InvalidCredentials)
        ));
        assert!(
            service
                .login_password(
                    "recover@example.com",
                    "second private recovery password",
                    TEST_DEVICE_ID,
                    "desktop"
                )
                .is_ok()
        );
    }

    #[test]
    fn recovery_codes_can_be_replaced_only_with_the_current_password() {
        let service = service();
        let registered = service
            .register_password(
                "replace-codes@example.com",
                "current recovery code password",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let original_code = registered.recovery_codes[0].clone();
        let principal = service.authenticate(&registered.access_token).unwrap();

        assert!(matches!(
            service.regenerate_recovery_codes(&principal, "wrong recovery code password"),
            Err(AuthError::InvalidCurrentPassword)
        ));
        let replacement = service
            .regenerate_recovery_codes(&principal, "current recovery code password")
            .unwrap();
        assert_eq!(replacement.len(), RECOVERY_CODE_COUNT);
        assert!(!replacement.contains(&original_code));
        service
            .set_recovery_key_vaults(
                &principal,
                "current recovery code password",
                &recovery_key_vaults(&replacement, 30),
            )
            .unwrap();
        assert!(matches!(
            service.recover_password(
                "replace-codes@example.com",
                &original_code,
                "replacement recovery password",
                &Uuid::now_v7().to_string(),
                "recovery"
            ),
            Err(AuthError::InvalidRecoveryCode)
        ));
        assert!(
            service
                .recover_password(
                    "replace-codes@example.com",
                    &replacement[0],
                    "replacement recovery password",
                    &Uuid::now_v7().to_string(),
                    "recovery"
                )
                .is_ok()
        );
    }

    #[test]
    fn password_hash_is_never_in_the_account_export() {
        let service = service();
        let session = service
            .register_password(
                "export@example.com",
                "export secret only on server",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let principal = service.authenticate(&session.access_token).unwrap();
        let export =
            serde_json::to_string(&service.data_export(principal.user_id).unwrap()).unwrap();
        assert!(!export.contains("password"));
        assert!(!export.contains("export secret only on server"));
        assert!(!export.contains("$argon2"));
        assert!(
            session
                .recovery_codes
                .iter()
                .all(|code| !export.contains(code))
        );
    }

    #[test]
    fn refresh_tokens_rotate_and_reuse_revokes_the_family() {
        let service = service();
        let challenge = service.request_email_code("a@example.com").unwrap();
        let first = service
            .verify_email_code(&challenge.id, &challenge.code, TEST_DEVICE_ID, "test")
            .unwrap();
        let second = service.refresh(&first.refresh_token).unwrap();
        assert!(matches!(
            service.refresh(&first.refresh_token),
            Err(AuthError::RefreshReuse)
        ));
        assert!(matches!(
            service.authenticate(&second.access_token),
            Err(AuthError::InvalidSession)
        ));
    }

    #[test]
    fn revoking_a_device_evicts_all_its_sessions_only() {
        let service = service();
        let first_challenge = service.request_email_code("a@example.com").unwrap();
        let first = service
            .verify_email_code(
                &first_challenge.id,
                &first_challenge.code,
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let second_challenge = service.request_email_code("a@example.com").unwrap();
        let second = service
            .verify_email_code(
                &second_challenge.id,
                &second_challenge.code,
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let other_device = Uuid::now_v7();
        let other_challenge = service.request_email_code("a@example.com").unwrap();
        let other = service
            .verify_email_code(
                &other_challenge.id,
                &other_challenge.code,
                &other_device.to_string(),
                "laptop",
            )
            .unwrap();
        let user_id = service.authenticate(&first.access_token).unwrap().user_id;

        assert_eq!(
            service
                .revoke_device_sessions(user_id, Uuid::parse_str(TEST_DEVICE_ID).unwrap())
                .unwrap(),
            2
        );
        assert!(service.authenticate(&first.access_token).is_err());
        assert!(service.authenticate(&second.access_token).is_err());
        assert!(service.authenticate(&other.access_token).is_ok());
        let retry_challenge = service.request_email_code("a@example.com").unwrap();
        assert!(matches!(
            service.verify_email_code(
                &retry_challenge.id,
                &retry_challenge.code,
                TEST_DEVICE_ID,
                "desktop",
            ),
            Err(AuthError::DeviceRevoked)
        ));
    }

    #[test]
    fn codes_are_one_time_and_attempt_limited() {
        let service = service();
        let challenge = service.request_email_code("a@example.com").unwrap();
        assert!(
            service
                .verify_email_code(&challenge.id, "000000", TEST_DEVICE_ID, "test")
                .is_err()
        );
        service
            .verify_email_code(&challenge.id, &challenge.code, TEST_DEVICE_ID, "test")
            .unwrap();
        assert!(
            service
                .verify_email_code(&challenge.id, &challenge.code, TEST_DEVICE_ID, "test")
                .is_err()
        );
    }

    #[test]
    fn cancelled_email_delivery_cannot_leave_a_usable_code() {
        let service = service();
        let challenge = service.request_email_code("delivery@example.com").unwrap();
        service.cancel_email_challenge(&challenge.id).unwrap();
        assert!(matches!(
            service.verify_email_code(&challenge.id, &challenge.code, TEST_DEVICE_ID, "desktop",),
            Err(AuthError::InvalidCode)
        ));
    }

    #[test]
    fn apple_handoff_is_encrypted_bound_to_state_and_one_time() {
        let service = apple_service();
        let (state, nonce) = service.begin_apple_flow(TEST_DEVICE_ID).unwrap();
        assert_eq!(service.apple_flow(&state).unwrap().nonce, nonce);
        service
            .complete_apple_flow(
                &state,
                "apple-subject-1",
                "relay@privaterelay.appleid.com",
                Some("Private Member"),
                "apple-refresh-secret",
            )
            .unwrap();
        let AppleFlowPoll::Complete(session) = service.poll_apple_flow(&state).unwrap() else {
            panic!("completed Apple flow must return a session");
        };
        assert_eq!(session.user.display_name, "Private Member");
        assert!(service.authenticate(&session.access_token).is_ok());
        assert!(matches!(
            service.poll_apple_flow(&state),
            Err(AuthError::InvalidAppleFlow)
        ));
        assert!(matches!(
            service.poll_apple_flow("exo_as_wrong"),
            Err(AuthError::InvalidAppleFlow)
        ));
    }

    #[test]
    fn apple_never_auto_links_an_unverified_password_email() {
        let service = apple_service();
        service
            .register_password(
                "shared@example.com",
                "a private password account secret",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let (state, _) = service.begin_apple_flow(TEST_DEVICE_ID).unwrap();
        assert!(matches!(
            service.complete_apple_flow(
                &state,
                "apple-shared-subject",
                "shared@example.com",
                Some("Shared Member"),
                "apple-refresh-secret"
            ),
            Err(AuthError::AppleLinkRequired)
        ));
    }

    #[test]
    fn apple_can_link_after_the_email_address_is_verified() {
        let service = apple_service();
        let password_session = service
            .register_password(
                "verified@example.com",
                "a verified password account secret",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let verification = service.request_email_code("verified@example.com").unwrap();
        service
            .verify_email_code(
                &verification.id,
                &verification.code,
                TEST_DEVICE_ID,
                "email verification",
            )
            .unwrap();
        let (state, _) = service.begin_apple_flow(TEST_DEVICE_ID).unwrap();
        service
            .complete_apple_flow(
                &state,
                "apple-verified-subject",
                "verified@example.com",
                Some("Verified Member"),
                "apple-refresh-secret",
            )
            .unwrap();
        let AppleFlowPoll::Complete(apple_session) = service.poll_apple_flow(&state).unwrap()
        else {
            panic!("verified Apple linking must complete");
        };
        assert_eq!(apple_session.user.id, password_session.user.id);
    }

    #[test]
    fn explicit_apple_link_is_password_verified_session_bound_and_reversible() {
        let service = apple_service();
        let session = service
            .register_password(
                "owner@example.com",
                "owner account private password",
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        let principal = service.authenticate(&session.access_token).unwrap();
        let other = service
            .register_password(
                "other@example.com",
                "other account private password",
                &Uuid::now_v7().to_string(),
                "other desktop",
            )
            .unwrap();
        let other_principal = service.authenticate(&other.access_token).unwrap();

        let methods = service.account_auth_methods(&principal).unwrap();
        assert!(methods.password_set);
        assert!(!methods.apple_linked);
        assert!(matches!(
            service.begin_apple_link(&principal, "wrong owner password"),
            Err(AuthError::InvalidCurrentPassword)
        ));

        let (state, nonce) = service
            .begin_apple_link(&principal, "owner account private password")
            .unwrap();
        let flow = service.apple_flow(&state).unwrap();
        assert_eq!(flow.nonce, nonce);
        assert!(flow.linking);
        assert!(matches!(
            service.poll_apple_flow(&state),
            Err(AuthError::InvalidAppleFlow)
        ));
        assert!(matches!(
            service.poll_apple_link(&other_principal, &state),
            Err(AuthError::InvalidAppleFlow)
        ));

        service
            .complete_apple_flow(
                &state,
                "explicit-link-subject",
                "private-relay@privaterelay.appleid.com",
                Some("Apple Must Not Rename Me"),
                "explicit-link-refresh",
            )
            .unwrap();
        assert!(matches!(
            service.poll_apple_link(&principal, &state).unwrap(),
            AppleLinkPoll::Complete
        ));
        let methods = service.account_auth_methods(&principal).unwrap();
        assert!(methods.apple_linked);
        assert_eq!(
            methods.apple_email.as_deref(),
            Some("private-relay@privaterelay.appleid.com")
        );
        let user = service.user(principal.user_id).unwrap();
        assert_eq!(user.email, "owner@example.com");
        assert_eq!(user.display_name, "Owner");

        assert!(matches!(
            service.unlink_apple(&principal, "wrong owner password"),
            Err(AuthError::InvalidCurrentPassword)
        ));
        service
            .unlink_apple(&principal, "owner account private password")
            .unwrap();
        assert!(
            !service
                .account_auth_methods(&principal)
                .unwrap()
                .apple_linked
        );
        assert!(
            service
                .login_password(
                    "owner@example.com",
                    "owner account private password",
                    TEST_DEVICE_ID,
                    "desktop"
                )
                .is_ok()
        );
    }

    #[test]
    fn an_apple_identity_cannot_be_linked_to_two_accounts() {
        let service = apple_service();
        let (login_state, _) = service.begin_apple_flow(TEST_DEVICE_ID).unwrap();
        service
            .complete_apple_flow(
                &login_state,
                "exclusive-apple-subject",
                "apple-owner@privaterelay.appleid.com",
                None,
                "apple-owner-refresh",
            )
            .unwrap();
        assert!(matches!(
            service.poll_apple_flow(&login_state).unwrap(),
            AppleFlowPoll::Complete(_)
        ));

        let password_session = service
            .register_password(
                "password-owner@example.com",
                "password owner private secret",
                &Uuid::now_v7().to_string(),
                "desktop",
            )
            .unwrap();
        let principal = service
            .authenticate(&password_session.access_token)
            .unwrap();
        let (link_state, _) = service
            .begin_apple_link(&principal, "password owner private secret")
            .unwrap();
        assert!(matches!(
            service.complete_apple_flow(
                &link_state,
                "exclusive-apple-subject",
                "apple-owner@privaterelay.appleid.com",
                None,
                "replacement-refresh"
            ),
            Err(AuthError::AppleAlreadyLinked)
        ));
    }

    #[test]
    fn apple_only_accounts_cannot_disconnect_their_only_login() {
        let service = apple_service();
        let (state, _) = service.begin_apple_flow(TEST_DEVICE_ID).unwrap();
        service
            .complete_apple_flow(
                &state,
                "apple-only-subject",
                "apple-only@privaterelay.appleid.com",
                None,
                "apple-only-refresh",
            )
            .unwrap();
        let AppleFlowPoll::Complete(session) = service.poll_apple_flow(&state).unwrap() else {
            panic!("Apple login must complete");
        };
        let principal = service.authenticate(&session.access_token).unwrap();
        let methods = service.account_auth_methods(&principal).unwrap();
        assert!(!methods.password_set);
        assert!(methods.apple_linked);
        assert!(matches!(
            service.unlink_apple(&principal, "anything"),
            Err(AuthError::AppleUnlinkUnsafe)
        ));
    }

    #[test]
    fn cancelled_apple_flow_returns_one_failure_then_is_consumed() {
        let service = apple_service();
        let (state, _) = service.begin_apple_flow(TEST_DEVICE_ID).unwrap();
        service
            .fail_apple_flow(&state, "Apple sign-in was cancelled")
            .unwrap();
        assert!(matches!(
            service.poll_apple_flow(&state).unwrap(),
            AppleFlowPoll::Failed(_)
        ));
        assert!(service.poll_apple_flow(&state).is_err());
    }

    #[test]
    fn account_deletion_revokes_sessions_but_can_be_cancelled_during_grace() {
        let service = service();
        let challenge = service.request_email_code("privacy@example.com").unwrap();
        let session = service
            .verify_email_code(&challenge.id, &challenge.code, TEST_DEVICE_ID, "desktop")
            .unwrap();
        let principal = service.authenticate(&session.access_token).unwrap();
        let deletion = service
            .schedule_account_deletion(&principal, Utc::now())
            .unwrap();
        assert!(deletion.scheduled_for > deletion.requested_at);
        assert!(service.authenticate(&session.access_token).is_err());

        let login = service.request_email_code("privacy@example.com").unwrap();
        let recovery = service
            .verify_email_code(&login.id, &login.code, TEST_DEVICE_ID, "desktop")
            .unwrap();
        assert!(recovery.user.deletion_scheduled_for.is_some());
        let recovery_principal = service.authenticate(&recovery.access_token).unwrap();
        service
            .cancel_account_deletion(&recovery_principal)
            .unwrap();
        assert!(
            service
                .account_deletion(recovery_principal.user_id)
                .unwrap()
                .is_none()
        );
        assert!(
            service
                .due_account_deletions(Utc::now() + Duration::days(60), 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn due_deletion_anonymizes_secrets_and_releases_the_email() {
        let service = apple_service();
        let (state, _) = service.begin_apple_flow(TEST_DEVICE_ID).unwrap();
        service
            .complete_apple_flow(
                &state,
                "apple-private-subject",
                "erase@example.com",
                Some("Erase Me"),
                "provider-refresh-secret",
            )
            .unwrap();
        let AppleFlowPoll::Complete(session) = service.poll_apple_flow(&state).unwrap() else {
            panic!("completed Apple flow must return a session");
        };
        let principal = service.authenticate(&session.access_token).unwrap();
        let export =
            serde_json::to_string(&service.data_export(principal.user_id).unwrap()).unwrap();
        assert!(export.contains("apple-private-subject"));
        assert!(!export.contains("provider-refresh-secret"));

        let requested_at = Utc::now() - Duration::days(31);
        service
            .schedule_account_deletion(&principal, requested_at)
            .unwrap();
        assert_eq!(
            service.due_account_deletions(Utc::now(), 10).unwrap(),
            vec![principal.user_id]
        );
        assert!(
            service
                .begin_account_anonymization(principal.user_id, Utc::now())
                .unwrap()
        );
        assert!(
            service
                .finalize_account_deletion(principal.user_id, Utc::now())
                .unwrap()
        );
        assert!(service.authenticate(&session.access_token).is_err());
        assert!(service.data_export(principal.user_id).is_err());

        let replacement = service.request_email_code("erase@example.com").unwrap();
        let replacement = service
            .verify_email_code(
                &replacement.id,
                &replacement.code,
                TEST_DEVICE_ID,
                "desktop",
            )
            .unwrap();
        assert_ne!(replacement.user.id, principal.user_id.to_string());
    }
}
