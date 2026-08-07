use std::sync::{Arc, RwLock};

use exo_domain::{
    AttachmentId, AttachmentUpload, AuditLogEntry, AutomodRule, BanMember, BootstrapMlsGroup,
    Channel, ChannelPermissionOverwrite, CreateAutomodRule, CreateChannel, CreateGuild,
    CreateInvite, CreateMessage, CreateMessageEncryption, CreateRole, DeviceIdentity,
    DirectChannel, Guild, GuildBan, GuildInvite, GuildMember, InvitePreview, Message,
    MessageAttachment, MessageDeleteEvent, MessageId, MessageReactionEvent, MessageReactionInput,
    MessageSearchResult, MlsKeyPackage, MlsMembershipHint, MlsWelcomeDelivery, ModerateMember,
    OverwriteTargetKind, PrivateHistoryArchive, PublishMlsKeyPackages, ReadState,
    RegisterDeviceIdentity, Relationship, ReportReceipt, ReserveAttachment, ReserveAttachments,
    ReservedAttachments, Role, SyncSnapshot, TypingEvent, UpdateAutomodRule, UpdateChannel,
    UpdateChannelOverwrite, UpdateMessage, UpdateMlsGroup, UpdateRole, User, UserId, UserPresence,
    VoiceJoinGrant, WrappedAccountKey,
};
use exo_protocol::{EventType, FrameHeader, ProtocolError, ReadyPayload, decode_frame};
use exo_safety::{ProofOfWorkChallenge, ProofOfWorkSolution, solve_proof_of_work};
use futures_util::StreamExt;
use reqwest::{Client, Response};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        self, Message as WebSocketMessage,
        client::IntoClientRequest,
        http::{
            HeaderValue,
            header::{AUTHORIZATION, HeaderName},
        },
    },
};
use url::Url;

#[derive(Clone)]
pub struct ApiClient {
    http: Client,
    base_url: Url,
    development_user_id: String,
    device_id: Arc<RwLock<Option<String>>>,
    session: Arc<RwLock<Option<SessionBundle>>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

// Every operation surfaces the typed transport/status errors documented by
// `RemoteError`; repeating the same list on each narrow method adds no detail.
#[allow(clippy::missing_errors_doc)]
impl ApiClient {
    pub fn new(
        base_url: &str,
        development_user_id: impl Into<String>,
    ) -> Result<Self, RemoteError> {
        let mut base_url = Url::parse(base_url)?;
        if !base_url.path().ends_with('/') {
            base_url
                .path_segments_mut()
                .map_err(|()| RemoteError::InvalidBaseUrl)?
                .push("");
        }
        Ok(Self {
            http: Client::builder()
                .connect_timeout(std::time::Duration::from_secs(3))
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
            base_url,
            development_user_id: development_user_id.into(),
            device_id: Arc::new(RwLock::new(None)),
            session: Arc::new(RwLock::new(None)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    #[must_use]
    pub fn session(&self) -> Option<SessionBundle> {
        self.session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn set_session(&self, mut session: SessionBundle) {
        session.recovery_codes.clear();
        session.recovery_wrapped_key = None;
        *self
            .session
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(session);
    }

    pub fn clear_session(&self) {
        *self
            .session
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub fn set_device_id(&self, device_id: impl Into<String>) {
        *self
            .device_id
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(device_id.into());
    }

    #[must_use]
    pub fn device_id(&self) -> Option<String> {
        self.device_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub async fn auth_providers(&self) -> Result<AuthProviders, RemoteError> {
        parse_json(
            self.http
                .get(self.endpoint("v1/auth/providers")?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn operator_info(&self) -> Result<OperatorInfo, RemoteError> {
        parse_json(
            self.http
                .get(self.endpoint("v1/meta/operator")?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn probe_server(&self) -> Result<ServerProbe, RemoteError> {
        let health = self.http.get(self.endpoint("health")?).send().await?;
        if !health.status().is_success() {
            return Err(status_error(health).await);
        }
        if health.text().await?.trim() != "ok" {
            return Err(RemoteError::InvalidResponse(
                "health endpoint did not return `ok`".to_owned(),
            ));
        }

        let readiness: ReadinessResponse =
            parse_json(self.http.get(self.endpoint("ready")?).send().await?).await?;
        let providers = self.auth_providers().await?;
        let capabilities: PlatformCapabilities = parse_json(
            self.http
                .get(self.endpoint("v1/meta/capabilities")?)
                .send()
                .await?,
        )
        .await?;
        let operator = self.operator_info().await?;

        Ok(ServerProbe {
            ready: readiness.ready,
            storage: readiness.storage,
            attachments: readiness.attachments,
            password: providers.password,
            email: providers.email,
            apple: providers.apple,
            development_code_preview: providers.development_code_preview,
            conversation_actions: capabilities.conversation_actions,
            native_voice: capabilities.native_voice,
            operator,
        })
    }

    pub async fn request_email_code(&self, email: &str) -> Result<EmailCodeChallenge, RemoteError> {
        let proof = self.signup_proof().await?;
        parse_json(
            self.http
                .post(self.endpoint("v1/auth/email/request")?)
                .json(&serde_json::json!({
                    "email": email,
                    "proofOfWork": proof
                }))
                .send()
                .await?,
        )
        .await
    }

    pub async fn register_password(
        &self,
        email: &str,
        password: &str,
        device_id: &str,
    ) -> Result<SessionBundle, RemoteError> {
        self.password_auth("v1/auth/password/register", email, password, device_id)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_password_provisioned(
        &self,
        email: &str,
        username: &str,
        password: &str,
        device_id: &str,
        account_id: u64,
        wrapped_key: &WrappedAccountKey,
        recovery_vaults: &[RecoveryKeyVaultEntry],
    ) -> Result<SessionBundle, RemoteError> {
        let mut last_error = None;
        for attempt in 0..3 {
            let proof = self.signup_proof().await?;
            let result = async {
                parse_json::<SessionBundle>(
                    self.http
                        .post(self.endpoint("v1/auth/password/register")?)
                        .json(&serde_json::json!({
                            "email": email,
                            "username": username,
                            "password": password,
                            "deviceId": device_id,
                            "clientName": "Exocord Desktop",
                            "proofOfWork": proof,
                            "accountId": account_id.to_string(),
                            "wrappedKey": wrapped_key,
                            "recoveryVaults": recovery_vaults
                        }))
                        .send()
                        .await?,
                )
                .await
            }
            .await;
            match result {
                Ok(session) => {
                    self.set_session(session.clone());
                    return Ok(session);
                }
                Err(error) if error.is_permanent() => return Err(error),
                Err(error) => last_error = Some(error),
            }
            tokio::time::sleep(std::time::Duration::from_millis(150 * (attempt + 1))).await;
        }
        Err(last_error.unwrap_or_else(|| {
            RemoteError::InvalidResponse("provisioned registration did not run".to_owned())
        }))
    }

    pub async fn login_password(
        &self,
        email: &str,
        password: &str,
        device_id: &str,
    ) -> Result<SessionBundle, RemoteError> {
        self.password_auth("v1/auth/password/login", email, password, device_id)
            .await
    }

    pub async fn recover_password(
        &self,
        email: &str,
        recovery_code: &str,
        new_password: &str,
        device_id: &str,
    ) -> Result<SessionBundle, RemoteError> {
        let proof = self.signup_proof().await?;
        let session: SessionBundle = parse_json(
            self.http
                .post(self.endpoint("v1/auth/password/recover")?)
                .json(&serde_json::json!({
                    "email": email,
                    "recoveryCode": recovery_code,
                    "newPassword": new_password,
                    "deviceId": device_id,
                    "clientName": "Exocord Desktop · Recovery",
                    "proofOfWork": proof
                }))
                .send()
                .await?,
        )
        .await?;
        self.set_session(session.clone());
        Ok(session)
    }

    pub async fn prepare_password_recovery(
        &self,
        email: &str,
        recovery_code: &str,
    ) -> Result<PasswordRecoveryPreparation, RemoteError> {
        let proof = self.signup_proof().await?;
        parse_json(
            self.http
                .post(self.endpoint("v1/auth/password/recover/prepare")?)
                .json(&serde_json::json!({
                    "email": email,
                    "recoveryCode": recovery_code,
                    "proofOfWork": proof
                }))
                .send()
                .await?,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn recover_password_provisioned(
        &self,
        email: &str,
        recovery_code: &str,
        new_password: &str,
        device_id: &str,
        account_id: u64,
        wrapped_key: &WrappedAccountKey,
        recovery_vaults: &[RecoveryKeyVaultEntry],
    ) -> Result<SessionBundle, RemoteError> {
        let mut last_error = None;
        for attempt in 0..3 {
            let proof = self.signup_proof().await?;
            let result = async {
                parse_json::<SessionBundle>(
                    self.http
                        .post(self.endpoint("v1/auth/password/recover")?)
                        .json(&serde_json::json!({
                            "email": email,
                            "recoveryCode": recovery_code,
                            "newPassword": new_password,
                            "deviceId": device_id,
                            "clientName": "Exocord Desktop · Recovery",
                            "proofOfWork": proof,
                            "accountId": account_id.to_string(),
                            "wrappedKey": wrapped_key,
                            "recoveryVaults": recovery_vaults
                        }))
                        .send()
                        .await?,
                )
                .await
            }
            .await;
            match result {
                Ok(session) => {
                    self.set_session(session.clone());
                    return Ok(session);
                }
                Err(error) if error.is_permanent() => return Err(error),
                Err(error) => last_error = Some(error),
            }
            tokio::time::sleep(std::time::Duration::from_millis(150 * (attempt + 1))).await;
        }
        Err(last_error.unwrap_or_else(|| {
            RemoteError::InvalidResponse("provisioned recovery did not run".to_owned())
        }))
    }

    async fn password_auth(
        &self,
        endpoint: &str,
        email: &str,
        password: &str,
        device_id: &str,
    ) -> Result<SessionBundle, RemoteError> {
        let proof = self.signup_proof().await?;
        let session: SessionBundle = parse_json(
            self.http
                .post(self.endpoint(endpoint)?)
                .json(&serde_json::json!({
                    "email": email,
                    "password": password,
                    "deviceId": device_id,
                    "clientName": "Exocord Desktop",
                    "proofOfWork": proof
                }))
                .send()
                .await?,
        )
        .await?;
        self.set_session(session.clone());
        Ok(session)
    }

    pub async fn verify_email_code(
        &self,
        challenge_id: &str,
        code: &str,
        device_id: &str,
    ) -> Result<SessionBundle, RemoteError> {
        let session: SessionBundle = parse_json(
            self.http
                .post(self.endpoint("v1/auth/email/verify")?)
                .json(&serde_json::json!({
                    "challengeId": challenge_id,
                    "code": code,
                    "deviceId": device_id,
                    "clientName": "Exocord Desktop"
                }))
                .send()
                .await?,
        )
        .await?;
        self.set_session(session.clone());
        Ok(session)
    }

    pub async fn start_apple_login(&self, device_id: &str) -> Result<AppleLoginStart, RemoteError> {
        let proof = self.signup_proof().await?;
        parse_json(
            self.http
                .post(self.endpoint("v1/auth/apple/start")?)
                .json(&serde_json::json!({
                    "deviceId": device_id,
                    "proofOfWork": proof
                }))
                .send()
                .await?,
        )
        .await
    }

    pub async fn account_auth_methods(&self) -> Result<AccountAuthMethods, RemoteError> {
        let response = self
            .send_authenticated(self.http.get(self.endpoint("v1/users/@me/auth-methods")?))
            .await?;
        parse_json(response).await
    }

    pub async fn start_apple_link(
        &self,
        current_password: &str,
    ) -> Result<AppleLoginStart, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint("v1/users/@me/apple/start")?)
                    .json(&serde_json::json!({
                        "currentPassword": current_password
                    })),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn poll_apple_link(&self, state: &str) -> Result<bool, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint("v1/users/@me/apple/status")?)
                    .query(&[("state", state)]),
            )
            .await?;
        if response.status().as_u16() == 202 {
            return Ok(false);
        }
        let status: AppleLinkStatus = parse_json(response).await?;
        if status.status != "complete" {
            return Err(RemoteError::InvalidResponse(
                "Apple link status was not complete".to_owned(),
            ));
        }
        Ok(true)
    }

    pub async fn unlink_apple(&self, current_password: &str) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(self.http.delete(self.endpoint("v1/users/@me/apple")?).json(
                &serde_json::json!({
                    "currentPassword": current_password
                }),
            ))
            .await?;
        expect_success(response).await
    }

    async fn signup_proof(&self) -> Result<ProofOfWorkSolution, RemoteError> {
        let challenge: ProofOfWorkChallenge = parse_json(
            self.http
                .get(self.endpoint("v1/auth/challenge")?)
                .send()
                .await?,
        )
        .await?;
        tokio::task::spawn_blocking(move || solve_proof_of_work(&challenge))
            .await
            .map_err(|error| RemoteError::ProofOfWork(error.to_string()))?
            .map_err(|error| RemoteError::ProofOfWork(error.to_string()))
    }

    pub async fn poll_apple_login(
        &self,
        state: &str,
    ) -> Result<Option<SessionBundle>, RemoteError> {
        let response = self
            .http
            .get(self.endpoint("v1/auth/apple/status")?)
            .query(&[("state", state)])
            .send()
            .await?;
        if response.status().as_u16() == 202 {
            return Ok(None);
        }
        let session: SessionBundle = parse_json(response).await?;
        self.set_session(session.clone());
        Ok(Some(session))
    }

    pub async fn refresh_session(&self) -> Result<SessionBundle, RemoteError> {
        let refresh_token = self
            .session()
            .map(|session| session.refresh_token)
            .ok_or(RemoteError::NoSession)?;
        self.refresh_with_token(&refresh_token).await
    }

    pub async fn refresh_with_token(
        &self,
        refresh_token: &str,
    ) -> Result<SessionBundle, RemoteError> {
        let session: SessionBundle = parse_json(
            self.http
                .post(self.endpoint("v1/auth/refresh")?)
                .json(&serde_json::json!({ "refreshToken": refresh_token }))
                .send()
                .await?,
        )
        .await?;
        self.set_session(session.clone());
        Ok(session)
    }

    pub async fn logout(&self) -> Result<(), RemoteError> {
        let response = self
            .request(self.http.post(self.endpoint("v1/auth/logout")?))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(status_error(response).await);
        }
        self.clear_session();
        Ok(())
    }

    pub async fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
        wrapped_key: &WrappedAccountKey,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(self.http.put(self.endpoint("v1/users/@me/password")?).json(
                &serde_json::json!({
                    "currentPassword": current_password,
                    "newPassword": new_password,
                    "wrappedKey": wrapped_key
                }),
            ))
            .await?;
        if !response.status().is_success() {
            return Err(status_error(response).await);
        }
        Ok(())
    }

    pub async fn account_key_vault(&self) -> Result<Option<WrappedAccountKey>, RemoteError> {
        let response: AccountKeyVaultResponse = parse_json(
            self.send_authenticated(self.http.get(self.endpoint("v1/users/@me/key-vault")?))
                .await?,
        )
        .await?;
        Ok(response.wrapped_key)
    }

    pub async fn recovery_key_vaults_ready(&self) -> Result<bool, RemoteError> {
        let response: AccountKeyVaultResponse = parse_json(
            self.send_authenticated(self.http.get(self.endpoint("v1/users/@me/key-vault")?))
                .await?,
        )
        .await?;
        Ok(response.recovery_ready)
    }

    pub async fn set_account_key_vault(
        &self,
        current_password: &str,
        wrapped_key: &WrappedAccountKey,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint("v1/users/@me/key-vault")?)
                    .json(&serde_json::json!({
                        "currentPassword": current_password,
                        "wrappedKey": wrapped_key
                    })),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn set_recovery_key_vaults(
        &self,
        current_password: &str,
        entries: &[RecoveryKeyVaultEntry],
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint("v1/users/@me/recovery-key-vaults")?)
                    .json(&serde_json::json!({
                        "currentPassword": current_password,
                        "entries": entries
                    })),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn private_history(&self) -> Result<Vec<PrivateHistoryArchive>, RemoteError> {
        const PAGE_SIZE: usize = 1_000;
        let mut archives = Vec::new();
        let mut before = None::<u64>;
        loop {
            let mut request = self
                .http
                .get(self.endpoint("v1/users/@me/private-history")?)
                .query(&[("limit", PAGE_SIZE.to_string())]);
            if let Some(cursor) = before {
                request = request.query(&[("before", cursor.to_string())]);
            }
            let response = self.send_authenticated(request).await?;
            let page: Vec<PrivateHistoryArchive> = parse_json(response).await?;
            if page.is_empty() {
                break;
            }
            let next = page.last().map(|archive| archive.message_id.raw());
            let complete = page.len() < PAGE_SIZE;
            archives.extend(page);
            if complete || next == before {
                break;
            }
            before = next;
        }
        archives.sort_by_key(|archive| archive.message_id);
        Ok(archives)
    }

    pub async fn put_private_history(
        &self,
        archive: &PrivateHistoryArchive,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint(&format!(
                        "v1/users/@me/private-history/{}",
                        archive.message_id
                    ))?)
                    .json(archive),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn regenerate_recovery_codes(
        &self,
        current_password: &str,
    ) -> Result<Vec<String>, RemoteError> {
        let response: RecoveryCodesResponse = parse_json(
            self.send_authenticated(
                self.http
                    .post(self.endpoint("v1/users/@me/password/recovery-codes")?)
                    .json(&serde_json::json!({
                        "currentPassword": current_password
                    })),
            )
            .await?,
        )
        .await?;
        Ok(response.recovery_codes)
    }

    pub async fn account_deletion_status(&self) -> Result<AccountDeletionStatus, RemoteError> {
        let response = self
            .send_authenticated(self.http.get(self.endpoint("v1/users/@me/deletion")?))
            .await?;
        parse_json(response).await
    }

    pub async fn export_account_data(&self) -> Result<serde_json::Value, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint("v1/users/@me/data-export")?)
                    .timeout(std::time::Duration::from_secs(60)),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn schedule_account_deletion(&self) -> Result<AccountDeletionStatus, RemoteError> {
        let response = self
            .send_authenticated(self.http.delete(self.endpoint("v1/users/@me")?))
            .await?;
        let deletion = parse_json(response).await?;
        self.clear_session();
        Ok(deletion)
    }

    pub async fn cancel_account_deletion(&self) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(self.http.delete(self.endpoint("v1/users/@me/deletion")?))
            .await?;
        expect_success(response).await
    }

    pub async fn fetch_sync(&self) -> Result<SyncSnapshot, RemoteError> {
        let response = self
            .send_authenticated(self.http.get(self.endpoint("v1/sync")?))
            .await?;
        let mut snapshot: SyncSnapshot = parse_json(response).await?;
        self.normalize_user_avatar(&mut snapshot.current_user);
        for user in &mut snapshot.users {
            self.normalize_user_avatar(user);
        }
        for relationship in &mut snapshot.relationships {
            self.normalize_user_avatar(&mut relationship.user);
        }
        for channel in &mut snapshot.direct_channels {
            for user in &mut channel.recipients {
                self.normalize_user_avatar(user);
            }
        }
        Ok(snapshot)
    }

    pub async fn update_profile(&self, input: &UpdateProfile) -> Result<User, RemoteError> {
        let response = self
            .send_authenticated(self.http.patch(self.endpoint("v1/users/@me")?).json(input))
            .await?;
        let mut user: User = parse_json(response).await?;
        self.normalize_user_avatar(&mut user);
        Ok(user)
    }

    pub async fn register_device_identity(
        &self,
        device_id: &str,
        input: &RegisterDeviceIdentity,
    ) -> Result<DeviceIdentity, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint(&format!("v1/users/@me/devices/{device_id}"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    fn normalize_user_avatar(&self, user: &mut User) {
        normalize_user_avatar(&self.base_url, user);
    }

    pub async fn list_device_identities(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceIdentity>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/users/{user_id}/devices"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn revoke_device_identity(&self, device_id: &str) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .delete(self.endpoint(&format!("v1/users/@me/devices/{device_id}"))?),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn publish_mls_key_packages(
        &self,
        device_id: &str,
        input: &PublishMlsKeyPackages,
    ) -> Result<Vec<MlsKeyPackage>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/users/@me/devices/{device_id}/key-packages"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn claim_mls_key_packages(
        &self,
        channel_id: u64,
    ) -> Result<Vec<MlsKeyPackage>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http.post(
                    self.endpoint(&format!("v1/channels/{channel_id}/mls/key-packages/claim"))?,
                ),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn bootstrap_mls_group(
        &self,
        channel_id: u64,
        input: &BootstrapMlsGroup,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/channels/{channel_id}/mls/bootstrap"))?)
                    .json(input),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn update_mls_group(
        &self,
        channel_id: u64,
        input: &UpdateMlsGroup,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/channels/{channel_id}/mls/members"))?)
                    .json(input),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn mls_inbox(&self, device_id: &str) -> Result<Vec<MlsWelcomeDelivery>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/users/@me/devices/{device_id}/mls/inbox"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn pending_mls_maintenance(
        &self,
        device_id: &str,
    ) -> Result<Vec<MlsMembershipHint>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http.get(
                    self.endpoint(&format!("v1/users/@me/devices/{device_id}/mls/maintenance"))?,
                ),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn acknowledge_mls_delivery(
        &self,
        device_id: &str,
        delivery: &MlsWelcomeDelivery,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(
                        self.endpoint(&format!("v1/users/@me/devices/{device_id}/mls/inbox/ack"))?,
                    )
                    .json(&serde_json::json!({
                        "groupId": delivery.group_id,
                        "epoch": delivery.epoch,
                        "sequence": delivery.sequence
                    })),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn request_friend(&self, handle: &str) -> Result<Relationship, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint("v1/users/@me/relationships")?)
                    .json(&serde_json::json!({ "handle": handle })),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn accept_friend(&self, target_id: UserId) -> Result<Relationship, RemoteError> {
        self.update_relationship(target_id, "accept").await
    }

    pub async fn block_user(&self, target_id: UserId) -> Result<Relationship, RemoteError> {
        self.update_relationship(target_id, "block").await
    }

    async fn update_relationship(
        &self,
        target_id: UserId,
        action: &str,
    ) -> Result<Relationship, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint(&format!("v1/users/@me/relationships/{target_id}"))?)
                    .json(&serde_json::json!({ "action": action })),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn delete_relationship(&self, target_id: UserId) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .delete(self.endpoint(&format!("v1/users/@me/relationships/{target_id}"))?),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn open_direct_channel(
        &self,
        recipient_id: UserId,
    ) -> Result<DirectChannel, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint("v1/users/@me/channels")?)
                    .json(&serde_json::json!({ "recipientId": recipient_id })),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn acknowledge_read_state(
        &self,
        channel_id: u64,
        message_id: MessageId,
    ) -> Result<ReadState, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint(&format!("v1/channels/{channel_id}/read-state"))?)
                    .json(&serde_json::json!({ "lastMessageId": message_id })),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn start_typing(&self, channel_id: u64) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/channels/{channel_id}/typing"))?),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn create_guild(&self, input: &CreateGuild) -> Result<Guild, RemoteError> {
        let response = self
            .send_authenticated(self.http.post(self.endpoint("v1/guilds")?).json(input))
            .await?;
        parse_json(response).await
    }

    pub async fn list_channels(&self, guild_id: u64) -> Result<Vec<Channel>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/guilds/{guild_id}/channels"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn create_channel(
        &self,
        guild_id: u64,
        input: &CreateChannel,
    ) -> Result<Channel, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/guilds/{guild_id}/channels"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn update_channel(
        &self,
        channel_id: u64,
        input: &UpdateChannel,
    ) -> Result<Channel, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .patch(self.endpoint(&format!("v1/channels/{channel_id}"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn delete_channel(&self, channel_id: u64) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .delete(self.endpoint(&format!("v1/channels/{channel_id}"))?),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn list_channel_overwrites(
        &self,
        channel_id: u64,
    ) -> Result<Vec<ChannelPermissionOverwrite>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/channels/{channel_id}/overwrites"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn set_channel_overwrite(
        &self,
        channel_id: u64,
        target_kind: OverwriteTargetKind,
        target_id: u64,
        input: &UpdateChannelOverwrite,
    ) -> Result<ChannelPermissionOverwrite, RemoteError> {
        let kind = match target_kind {
            OverwriteTargetKind::Role => "role",
            OverwriteTargetKind::Member => "member",
        };
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint(&format!(
                        "v1/channels/{channel_id}/overwrites/{kind}/{target_id}"
                    ))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn delete_channel_overwrite(
        &self,
        channel_id: u64,
        target_kind: OverwriteTargetKind,
        target_id: u64,
    ) -> Result<(), RemoteError> {
        let kind = match target_kind {
            OverwriteTargetKind::Role => "role",
            OverwriteTargetKind::Member => "member",
        };
        let response = self
            .send_authenticated(self.http.delete(self.endpoint(&format!(
                "v1/channels/{channel_id}/overwrites/{kind}/{target_id}"
            ))?))
            .await?;
        expect_success(response).await
    }

    pub async fn create_invite(
        &self,
        guild_id: u64,
        input: &CreateInvite,
    ) -> Result<GuildInvite, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/guilds/{guild_id}/invites"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn transfer_guild_ownership(
        &self,
        guild_id: u64,
        new_owner_id: u64,
    ) -> Result<Guild, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint(&format!("v1/guilds/{guild_id}/owner"))?)
                    .json(&serde_json::json!({ "ownerId": new_owner_id.to_string() })),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn delete_guild(&self, guild_id: u64, confirmation: &str) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .delete(self.endpoint(&format!("v1/guilds/{guild_id}"))?)
                    .json(&serde_json::json!({ "confirmation": confirmation })),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn preview_invite(&self, code: &str) -> Result<InvitePreview, RemoteError> {
        parse_json(
            self.http
                .get(self.endpoint(&format!("v1/invites/{code}"))?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn accept_invite(&self, code: &str) -> Result<Guild, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/invites/{code}"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn list_members(&self, guild_id: u64) -> Result<Vec<GuildMember>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/guilds/{guild_id}/members"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn list_roles(&self, guild_id: u64) -> Result<Vec<Role>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/guilds/{guild_id}/roles"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn list_automod_rules(&self, guild_id: u64) -> Result<Vec<AutomodRule>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/guilds/{guild_id}/automod/rules"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn create_automod_rule(
        &self,
        guild_id: u64,
        input: &CreateAutomodRule,
    ) -> Result<AutomodRule, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/guilds/{guild_id}/automod/rules"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn update_automod_rule(
        &self,
        guild_id: u64,
        rule_id: u64,
        input: &UpdateAutomodRule,
    ) -> Result<AutomodRule, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .patch(self.endpoint(&format!("v1/guilds/{guild_id}/automod/rules/{rule_id}"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn delete_automod_rule(
        &self,
        guild_id: u64,
        rule_id: u64,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http.delete(
                    self.endpoint(&format!("v1/guilds/{guild_id}/automod/rules/{rule_id}"))?,
                ),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn list_audit_log(
        &self,
        guild_id: u64,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<AuditLogEntry>, RemoteError> {
        let mut request = self
            .http
            .get(self.endpoint(&format!("v1/guilds/{guild_id}/audit-log"))?)
            .query(&[("limit", limit.to_string())]);
        if let Some(before) = before {
            request = request.query(&[("before", before.to_string())]);
        }
        let response = self.send_authenticated(request).await?;
        parse_json(response).await
    }

    pub async fn create_role(
        &self,
        guild_id: u64,
        input: &CreateRole,
    ) -> Result<Role, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/guilds/{guild_id}/roles"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn update_role(
        &self,
        guild_id: u64,
        role_id: u64,
        input: &UpdateRole,
    ) -> Result<Role, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .patch(self.endpoint(&format!("v1/guilds/{guild_id}/roles/{role_id}"))?)
                    .json(input),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn delete_role(&self, guild_id: u64, role_id: u64) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .delete(self.endpoint(&format!("v1/guilds/{guild_id}/roles/{role_id}"))?),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn set_member_role(
        &self,
        guild_id: u64,
        member_id: u64,
        role_id: u64,
        assigned: bool,
    ) -> Result<(), RemoteError> {
        let endpoint = self.endpoint(&format!(
            "v1/guilds/{guild_id}/members/{member_id}/roles/{role_id}"
        ))?;
        let request = if assigned {
            self.http.put(endpoint)
        } else {
            self.http.delete(endpoint)
        };
        let response = self.send_authenticated(request).await?;
        expect_success(response).await
    }

    pub async fn timeout_member(
        &self,
        guild_id: u64,
        member_id: u64,
        input: &ModerateMember,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .patch(self.endpoint(&format!("v1/guilds/{guild_id}/members/{member_id}"))?)
                    .json(input),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn kick_member(
        &self,
        guild_id: u64,
        member_id: u64,
        input: &ModerateMember,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .delete(self.endpoint(&format!("v1/guilds/{guild_id}/members/{member_id}"))?)
                    .json(input),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn list_bans(&self, guild_id: u64) -> Result<Vec<GuildBan>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/guilds/{guild_id}/bans"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn ban_member(
        &self,
        guild_id: u64,
        member_id: u64,
        input: &BanMember,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .put(self.endpoint(&format!("v1/guilds/{guild_id}/bans/{member_id}"))?)
                    .json(input),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn unban_member(
        &self,
        guild_id: u64,
        member_id: u64,
        input: &ModerateMember,
    ) -> Result<(), RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .delete(self.endpoint(&format!("v1/guilds/{guild_id}/bans/{member_id}"))?)
                    .json(input),
            )
            .await?;
        expect_success(response).await
    }

    pub async fn send_message(
        &self,
        channel_id: u64,
        content: &str,
        reply_to: Option<MessageId>,
        nonce: &str,
        attachments: &[MessageAttachment],
    ) -> Result<Message, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/channels/{channel_id}/messages"))?)
                    .json(&CreateMessage {
                        content: content.to_owned(),
                        encryption: None,
                        reply_to,
                        nonce: nonce.to_owned(),
                        allowed_mentions: exo_domain::AllowedMentions::default(),
                        attachments: attachments.iter().map(|attachment| attachment.id).collect(),
                    }),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn send_encrypted_message(
        &self,
        channel_id: u64,
        ciphertext: String,
        franking_commitment: String,
        reply_to: Option<MessageId>,
        nonce: &str,
        attachments: &[MessageAttachment],
    ) -> Result<Message, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/channels/{channel_id}/messages"))?)
                    .json(&CreateMessage {
                        content: String::new(),
                        encryption: Some(CreateMessageEncryption {
                            ciphertext,
                            franking_commitment,
                        }),
                        reply_to,
                        nonce: nonce.to_owned(),
                        allowed_mentions: exo_domain::AllowedMentions::default(),
                        attachments: attachments.iter().map(|attachment| attachment.id).collect(),
                    }),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn update_message(
        &self,
        channel_id: u64,
        message_id: u64,
        content: &str,
        nonce: &str,
    ) -> Result<Message, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .patch(
                        self.endpoint(&format!("v1/channels/{channel_id}/messages/{message_id}"))?,
                    )
                    .json(&UpdateMessage {
                        content: content.to_owned(),
                        encryption: None,
                        nonce: nonce.to_owned(),
                    }),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn update_encrypted_message(
        &self,
        channel_id: u64,
        message_id: u64,
        ciphertext: String,
        franking_commitment: String,
        nonce: &str,
    ) -> Result<Message, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .patch(
                        self.endpoint(&format!("v1/channels/{channel_id}/messages/{message_id}"))?,
                    )
                    .json(&UpdateMessage {
                        content: String::new(),
                        encryption: Some(CreateMessageEncryption {
                            ciphertext,
                            franking_commitment,
                        }),
                        nonce: nonce.to_owned(),
                    }),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn delete_message(
        &self,
        channel_id: u64,
        message_id: u64,
    ) -> Result<(), RemoteError> {
        let response =
            self.send_authenticated(self.http.delete(
                self.endpoint(&format!("v1/channels/{channel_id}/messages/{message_id}"))?,
            ))
            .await?;
        expect_success(response).await
    }

    pub async fn update_reaction(
        &self,
        channel_id: u64,
        message_id: u64,
        emoji: &str,
        added: bool,
    ) -> Result<MessageReactionEvent, RemoteError> {
        let endpoint = self.endpoint(&format!(
            "v1/channels/{channel_id}/messages/{message_id}/reactions"
        ))?;
        let request = if added {
            self.http.put(endpoint)
        } else {
            self.http.delete(endpoint)
        };
        let response = self
            .send_authenticated(request.json(&MessageReactionInput {
                emoji: emoji.to_owned(),
            }))
            .await?;
        parse_json(response).await
    }

    pub async fn create_report(
        &self,
        input: &exo_domain::CreateMessageReport,
    ) -> Result<ReportReceipt, RemoteError> {
        let response = self
            .send_authenticated(self.http.post(self.endpoint("v1/reports")?).json(input))
            .await?;
        parse_json(response).await
    }

    pub async fn reserve_attachment(
        &self,
        channel_id: u64,
        input: ReserveAttachment,
    ) -> Result<AttachmentUpload, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/channels/{channel_id}/attachments"))?)
                    .json(&ReserveAttachments { files: vec![input] }),
            )
            .await?;
        let mut reserved: ReservedAttachments = parse_json(response).await?;
        reserved
            .attachments
            .pop()
            .ok_or_else(|| RemoteError::InvalidResponse("upload reservation was empty".into()))
    }

    pub async fn complete_attachment(
        &self,
        attachment_id: AttachmentId,
    ) -> Result<MessageAttachment, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/attachments/{attachment_id}/complete"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn search_messages(
        &self,
        guild_id: u64,
        query: &str,
        limit: usize,
    ) -> Result<MessageSearchResult, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/guilds/{guild_id}/messages/search"))?)
                    .query(&[("q", query.to_owned()), ("limit", limit.to_string())]),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn message_window(
        &self,
        channel_id: u64,
        around: u64,
        limit: usize,
    ) -> Result<Vec<Message>, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .get(self.endpoint(&format!("v1/channels/{channel_id}/messages"))?)
                    .query(&[("around", around.to_string()), ("limit", limit.to_string())]),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn create_voice_grant(&self, channel_id: u64) -> Result<VoiceJoinGrant, RemoteError> {
        let response = self
            .send_authenticated(
                self.http
                    .post(self.endpoint(&format!("v1/channels/{channel_id}/voice-token"))?),
            )
            .await?;
        parse_json(response).await
    }

    pub async fn connect_gateway(&self) -> Result<GatewayConnection, RemoteError> {
        let request = self.gateway_request()?;
        let (stream, _) = connect_async(request).await?;
        Ok(GatewayConnection {
            stream,
            base_url: self.base_url.clone(),
        })
    }

    fn gateway_request(&self) -> Result<tungstenite::http::Request<()>, RemoteError> {
        let mut url = self.base_url.clone();
        let scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => return Err(RemoteError::InvalidBaseUrl),
        };
        url.set_scheme(scheme)
            .map_err(|()| RemoteError::InvalidBaseUrl)?;
        url.set_path("/gateway");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("v", "1").append_pair("enc", "msgpack");
        }
        let mut request = url.as_str().into_client_request()?;
        if let Some(session) = self.session() {
            let value = HeaderValue::from_str(&format!("Bearer {}", session.access_token))
                .map_err(|error| {
                    RemoteError::InvalidResponse(format!(
                        "gateway authorization header is invalid: {error}"
                    ))
                })?;
            request.headers_mut().insert(AUTHORIZATION, value);
        } else {
            let value = HeaderValue::from_str(&self.development_user_id).map_err(|error| {
                RemoteError::InvalidResponse(format!(
                    "development gateway identity header is invalid: {error}"
                ))
            })?;
            request
                .headers_mut()
                .insert(HeaderName::from_static("x-exocord-user-id"), value);
        }
        Ok(request)
    }

    fn endpoint(&self, relative: &str) -> Result<Url, RemoteError> {
        self.base_url.join(relative).map_err(Into::into)
    }

    fn request(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let request = if let Some(session) = self.session() {
            request.bearer_auth(session.access_token)
        } else {
            request.header("x-exocord-user-id", &self.development_user_id)
        };
        let device_id = self
            .device_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(device_id) = device_id {
            request.header("x-exocord-device-id", device_id)
        } else {
            request
        }
    }

    async fn send_authenticated(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Response, RemoteError> {
        let retry = request.try_clone();
        let attempted_access = self.session().map(|session| session.access_token);
        let response = self.request(request).send().await?;
        if response.status().as_u16() != 401 || attempted_access.is_none() {
            return Ok(response);
        }
        let Some(retry) = retry else {
            return Ok(response);
        };
        let _guard = self.refresh_lock.lock().await;
        let current_access = self.session().map(|session| session.access_token);
        if current_access == attempted_access {
            self.refresh_session().await?;
        }
        self.request(retry).send().await.map_err(Into::into)
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
// These are independent server capabilities, not mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub struct AuthProviders {
    #[serde(default)]
    pub password: bool,
    pub email: bool,
    pub apple: bool,
    pub development_code_preview: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
// These flags mirror independent server health/auth facts over the wire; they
// are not one state machine and collapsing them would hide useful diagnostics.
#[allow(clippy::struct_excessive_bools)]
pub struct ServerProbe {
    pub ready: bool,
    pub storage: String,
    pub attachments: String,
    pub password: bool,
    pub email: bool,
    pub apple: bool,
    pub development_code_preview: bool,
    pub conversation_actions: String,
    pub native_voice: String,
    pub operator: OperatorInfo,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorInfo {
    pub name: String,
    pub privacy_url: Option<String>,
    pub terms_url: Option<String>,
    pub support_email: Option<String>,
    pub abuse_email: Option<String>,
}

#[derive(serde::Deserialize)]
struct ReadinessResponse {
    ready: bool,
    storage: String,
    attachments: String,
}

#[derive(serde::Deserialize)]
struct PlatformCapabilities {
    conversation_actions: String,
    native_voice: String,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfile {
    pub handle: String,
    pub display_name: String,
    pub avatar_content_type: Option<String>,
    pub avatar_base64: Option<String>,
    pub remove_avatar: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailCodeChallenge {
    pub challenge_id: String,
    pub expires_in_seconds: u32,
    pub development_code: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppleLoginStart {
    pub authorization_url: String,
    pub state: String,
    pub expires_in_seconds: u32,
}

fn normalize_user_avatar(base_url: &Url, user: &mut User) {
    let Some(value) = user.avatar_url.as_deref() else {
        return;
    };
    if Url::parse(value).is_ok() {
        return;
    }
    if let Ok(url) = base_url.join(value) {
        user.avatar_url = Some(url.to_string());
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAuthMethods {
    pub password_set: bool,
    pub apple_linked: bool,
    pub apple_email: Option<String>,
}

#[derive(serde::Deserialize)]
struct AppleLinkStatus {
    status: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub display_name: String,
    #[serde(default)]
    pub deletion_scheduled_for: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDeletion {
    pub requested_at: String,
    pub scheduled_for: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDeletionStatus {
    pub deletion: Option<AccountDeletion>,
    #[serde(default)]
    pub owned_servers: Vec<OwnedServerStatus>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedServerStatus {
    pub id: String,
    pub name: String,
    pub member_count: u32,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionBundle {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: String,
    pub refresh_expires_at: String,
    pub user: AuthUser,
    #[serde(default)]
    pub recovery_codes: Vec<String>,
    #[serde(default)]
    pub recovery_wrapped_key: Option<WrappedAccountKey>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKeyVaultEntry {
    pub recovery_code: String,
    pub wrapped_key: WrappedAccountKey,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordRecoveryPreparation {
    pub account_id: String,
    pub recovery_wrapped_key: Option<WrappedAccountKey>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCodesResponse {
    recovery_codes: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountKeyVaultResponse {
    wrapped_key: Option<WrappedAccountKey>,
    #[serde(default)]
    recovery_ready: bool,
}

pub struct GatewayConnection {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    base_url: Url,
}

#[allow(clippy::missing_errors_doc)]
impl GatewayConnection {
    pub async fn next_event(&mut self) -> Result<Option<GatewayEvent>, RemoteError> {
        while let Some(message) = self.stream.next().await {
            match message? {
                WebSocketMessage::Binary(bytes) => {
                    let header = FrameHeader::decode(&bytes)?;
                    let event = match header.event_type {
                        EventType::Ready => {
                            let (_, payload) = decode_frame::<ReadyPayload>(&bytes)?;
                            GatewayEvent::Ready(payload)
                        }
                        EventType::UserUpdate => {
                            let (_, mut payload) = decode_frame::<User>(&bytes)?;
                            normalize_user_avatar(&self.base_url, &mut payload);
                            GatewayEvent::UserUpdate(payload)
                        }
                        EventType::GuildCreate => {
                            let (_, payload) = decode_frame::<Guild>(&bytes)?;
                            GatewayEvent::GuildCreate(payload)
                        }
                        EventType::GuildUpdate => {
                            let (_, payload) = decode_frame::<Guild>(&bytes)?;
                            GatewayEvent::GuildUpdate(payload)
                        }
                        EventType::GuildDelete => {
                            let (_, payload) = decode_frame::<Guild>(&bytes)?;
                            GatewayEvent::GuildDelete(payload)
                        }
                        EventType::ChannelCreate => {
                            let (_, payload) = decode_frame::<Channel>(&bytes)?;
                            GatewayEvent::ChannelCreate(payload)
                        }
                        EventType::ChannelUpdate => {
                            let (_, payload) = decode_frame::<Channel>(&bytes)?;
                            GatewayEvent::ChannelUpdate(payload)
                        }
                        EventType::ChannelDelete => {
                            let (_, payload) = decode_frame::<Channel>(&bytes)?;
                            GatewayEvent::ChannelDelete(payload)
                        }
                        EventType::MessageCreate => {
                            let (_, payload) = decode_frame::<Message>(&bytes)?;
                            GatewayEvent::MessageCreate(payload)
                        }
                        EventType::MessageUpdate => {
                            let (_, payload) = decode_frame::<Message>(&bytes)?;
                            GatewayEvent::MessageUpdate(payload)
                        }
                        EventType::MessageDelete => {
                            let (_, payload) = decode_frame::<MessageDeleteEvent>(&bytes)?;
                            GatewayEvent::MessageDelete(payload)
                        }
                        EventType::ReactionAdd | EventType::ReactionRemove => {
                            let (_, payload) = decode_frame::<MessageReactionEvent>(&bytes)?;
                            GatewayEvent::ReactionUpdate(payload)
                        }
                        EventType::RelationshipUpdate => GatewayEvent::RelationshipUpdate,
                        EventType::DirectChannelCreate => GatewayEvent::DirectChannelCreate,
                        EventType::ReadStateUpdate => {
                            let (_, payload) = decode_frame::<ReadState>(&bytes)?;
                            GatewayEvent::ReadStateUpdate(payload)
                        }
                        EventType::PresenceUpdate => {
                            let (_, payload) = decode_frame::<UserPresence>(&bytes)?;
                            GatewayEvent::PresenceUpdate(payload)
                        }
                        EventType::TypingStart => {
                            let (_, payload) = decode_frame::<TypingEvent>(&bytes)?;
                            GatewayEvent::TypingStart(payload)
                        }
                        EventType::MlsKeyPackageConsumed => {
                            let (_, payload) = decode_frame::<MlsMembershipHint>(&bytes)?;
                            GatewayEvent::MlsMembershipNeeded(payload)
                        }
                        EventType::MlsWelcome | EventType::MlsCommit => {
                            GatewayEvent::MlsDeliveryAvailable
                        }
                        _ => continue,
                    };
                    return Ok(Some(event));
                }
                WebSocketMessage::Close(_) => return Ok(None),
                WebSocketMessage::Ping(_)
                | WebSocketMessage::Pong(_)
                | WebSocketMessage::Text(_)
                | WebSocketMessage::Frame(_) => {}
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Debug)]
pub enum GatewayEvent {
    Ready(ReadyPayload),
    UserUpdate(User),
    GuildCreate(Guild),
    GuildUpdate(Guild),
    GuildDelete(Guild),
    ChannelCreate(Channel),
    ChannelUpdate(Channel),
    ChannelDelete(Channel),
    MessageCreate(Message),
    MessageUpdate(Message),
    MessageDelete(MessageDeleteEvent),
    ReactionUpdate(MessageReactionEvent),
    RelationshipUpdate,
    DirectChannelCreate,
    ReadStateUpdate(ReadState),
    PresenceUpdate(UserPresence),
    TypingStart(TypingEvent),
    MlsMembershipNeeded(MlsMembershipHint),
    MlsDeliveryAvailable,
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("remote URL is invalid: {0}")]
    Url(#[from] url::ParseError),
    #[error("remote base URL cannot be used for HTTP/WebSocket requests")]
    InvalidBaseUrl,
    #[error("remote response is invalid: {0}")]
    InvalidResponse(String),
    #[error("HTTP transport failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("remote request failed with HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("gateway transport failed: {0}")]
    Gateway(#[source] Box<tungstenite::Error>),
    #[error("gateway protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("local synchronization store failed: {0}")]
    LocalStore(String),
    #[error("no authenticated session is available")]
    NoSession,
    #[error("proof-of-work failed: {0}")]
    ProofOfWork(String),
}

impl From<tungstenite::Error> for RemoteError {
    fn from(error: tungstenite::Error) -> Self {
        Self::Gateway(Box::new(error))
    }
}

impl RemoteError {
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::Status { status, .. }
                if (400..500).contains(status) && !matches!(status, 408 | 425 | 429)
        ) || matches!(self, Self::NoSession)
    }

    /// Returns whether retrying the operation without user action would keep
    /// the local outbox spinning forever. MLS admission and identity errors
    /// are intentionally terminal until the user repairs trust or signs in
    /// again; the explicit retry command can requeue them afterward.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        if self.is_permanent() {
            return true;
        }
        let Self::LocalStore(message) = self else {
            return false;
        };
        let message = message.to_ascii_lowercase();
        [
            "another verified device must approve",
            "requires the os credential vault",
            "operating-system mls device key",
            "local mls identity",
            "sealed mls identity belongs",
            "no registered device identity",
            "fork an existing mls",
            "standalone mls proposals",
        ]
        .iter()
        .any(|needle| message.contains(needle))
    }
}

async fn parse_json<T: serde::de::DeserializeOwned>(response: Response) -> Result<T, RemoteError> {
    let status = response.status();
    if !status.is_success() {
        return Err(RemoteError::Status {
            status: status.as_u16(),
            body: response
                .text()
                .await
                .unwrap_or_else(|_| "response body unavailable".into()),
        });
    }
    response.json().await.map_err(Into::into)
}

async fn expect_success(response: Response) -> Result<(), RemoteError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(status_error(response).await)
    }
}

async fn status_error(response: Response) -> RemoteError {
    RemoteError::Status {
        status: response.status().as_u16(),
        body: response
            .text()
            .await
            .unwrap_or_else(|_| "response body unavailable".into()),
    }
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, routing::get};
    use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

    use super::{ApiClient, AuthUser, RemoteError, SessionBundle, WrappedAccountKey};

    #[test]
    fn terminal_delivery_errors_identify_auth_and_mls_trust_failures() {
        assert!(RemoteError::NoSession.is_terminal());
        assert!(
            RemoteError::Status {
                status: 403,
                body: "forbidden".into()
            }
            .is_terminal()
        );
        assert!(
            RemoteError::LocalStore(
                "another verified device must approve this device for the encrypted channel".into()
            )
            .is_terminal()
        );
        assert!(
            !RemoteError::Status {
                status: 503,
                body: "temporary".into()
            }
            .is_terminal()
        );
    }

    #[test]
    fn gateway_credentials_use_headers_and_never_the_url() {
        let client = ApiClient::new("https://alpha.example.test", "development-user").unwrap();
        client.set_session(SessionBundle {
            access_token: "private-access-token".into(),
            refresh_token: "private-refresh-token".into(),
            access_expires_at: "2030-01-01T00:00:00Z".into(),
            refresh_expires_at: "2030-02-01T00:00:00Z".into(),
            recovery_codes: vec!["must-not-remain-in-memory".into()],
            recovery_wrapped_key: Some(WrappedAccountKey {
                version: 1,
                salt: "private-salt".into(),
                nonce: "private-nonce".into(),
                ciphertext: "private-wrapped-key".into(),
            }),
            user: AuthUser {
                id: "1".into(),
                email: "tester@example.test".into(),
                display_name: "Tester".into(),
                deletion_scheduled_for: None,
            },
        });

        let request = client.gateway_request().unwrap();
        assert_eq!(
            request.headers().get(AUTHORIZATION).unwrap(),
            "Bearer private-access-token"
        );
        assert_eq!(request.uri().query(), Some("v=1&enc=msgpack"));
        assert!(!request.uri().to_string().contains("private-access-token"));
        assert!(!request.uri().to_string().contains("private-refresh-token"));
        assert!(client.session().unwrap().recovery_codes.is_empty());
        assert!(client.session().unwrap().recovery_wrapped_key.is_none());
    }

    #[tokio::test]
    async fn server_probe_verifies_health_readiness_auth_and_protocol_capabilities() {
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .route(
                "/ready",
                get(|| async {
                    Json(serde_json::json!({
                        "ready": true,
                        "storage": "postgres",
                        "attachments": "r2"
                    }))
                }),
            )
            .route(
                "/v1/auth/providers",
                get(|| async {
                    Json(serde_json::json!({
                        "email": true,
                        "apple": false,
                        "developmentCodePreview": false
                    }))
                }),
            )
            .route(
                "/v1/meta/capabilities",
                get(|| async {
                    Json(serde_json::json!({
                        "conversation_actions": "replies_edits_deletes_unicode_reactions",
                        "native_voice": "livekit_sframe_mls_exporter"
                    }))
                }),
            )
            .route(
                "/v1/meta/operator",
                get(|| async {
                    Json(serde_json::json!({
                        "name": "Exocord Test Alpha",
                        "privacyUrl": "https://alpha.example.test/privacy",
                        "termsUrl": null,
                        "supportEmail": "help@alpha.example.test",
                        "abuseEmail": "abuse@alpha.example.test"
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let probe = ApiClient::new(&format!("http://{address}"), "probe")
            .unwrap()
            .probe_server()
            .await
            .unwrap();
        assert!(probe.ready);
        assert_eq!(probe.storage, "postgres");
        assert_eq!(probe.attachments, "r2");
        assert!(probe.email);
        assert_eq!(
            probe.conversation_actions,
            "replies_edits_deletes_unicode_reactions"
        );
        assert_eq!(probe.native_voice, "livekit_sframe_mls_exporter");
        assert_eq!(probe.operator.name, "Exocord Test Alpha");
        assert_eq!(
            probe.operator.privacy_url.as_deref(),
            Some("https://alpha.example.test/privacy")
        );
        server.abort();
    }
}
