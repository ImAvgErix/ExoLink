//! Native-only MLS and message-franking primitives.
//!
//! The server-facing values produced by this crate are opaque TLS-encoded MLS
//! objects, public identity keys, and commitments. Private identity and group
//! state can be sealed with a device key held by the operating-system vault.

use std::collections::HashMap;

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn,
    LeafNodeParameters, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn,
    MlsMessageIn, ProcessedMessageContent, ProtocolMessage, ProtocolVersion, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, types::SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as _};
use uuid::Uuid;

const STATE_MAGIC: &[u8; 8] = b"EXOMLS01";
const STATE_AAD: &[u8] = b"exocord/native-mls-state/v1";
const FRANKING_MAGIC: &[u8; 8] = b"EXOFRK01";
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const CIPHER_SUITE_ID: u16 = 1;
const ACCOUNT_KEY_AAD_PREFIX: &[u8] = b"exocord/account-history-key/v1";
const RECOVERY_CODE_KEY_AAD_PREFIX: &[u8] = b"exocord/recovery-code-history-key/v1";
const PRIVATE_HISTORY_AAD_PREFIX: &[u8] = b"exocord/private-history/v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedAccountKeyMaterial {
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Wraps a random account history key with a password-derived key.
///
/// # Errors
///
/// Returns an error if secure randomness or the password KDF is unavailable,
/// or if authenticated encryption fails.
pub fn wrap_account_history_key(
    account_key: &[u8; 32],
    password: &str,
    user_id: u64,
) -> Result<WrappedAccountKeyMaterial, CryptoError> {
    wrap_account_history_key_with_secret(account_key, password, user_id, ACCOUNT_KEY_AAD_PREFIX)
}

/// Wraps the account history key with one single-use account recovery code.
///
/// # Errors
///
/// Returns an error if secure randomness or the recovery-code KDF is
/// unavailable, or if authenticated encryption fails.
pub fn wrap_account_history_key_with_recovery_code(
    account_key: &[u8; 32],
    recovery_code: &str,
    user_id: u64,
) -> Result<WrappedAccountKeyMaterial, CryptoError> {
    wrap_account_history_key_with_secret(
        account_key,
        recovery_code,
        user_id,
        RECOVERY_CODE_KEY_AAD_PREFIX,
    )
}

fn wrap_account_history_key_with_secret(
    account_key: &[u8; 32],
    secret: &str,
    user_id: u64,
    aad_prefix: &[u8],
) -> Result<WrappedAccountKeyMaterial, CryptoError> {
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::Randomness)?;
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let wrapping_key = derive_account_wrapping_key(secret, &salt)?;
    let ciphertext = XChaCha20Poly1305::new((&wrapping_key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: account_key,
                aad: &account_key_aad(aad_prefix, user_id),
            },
        )
        .map_err(|_| CryptoError::AccountRecovery)?;
    Ok(WrappedAccountKeyMaterial {
        salt,
        nonce,
        ciphertext,
    })
}

/// Opens an account history key after a fresh installation.
///
/// # Errors
///
/// Returns an error when the password, account identifier, or wrapped
/// material is invalid, or when the KDF is unavailable.
pub fn open_account_history_key(
    wrapped: &WrappedAccountKeyMaterial,
    password: &str,
    user_id: u64,
) -> Result<[u8; 32], CryptoError> {
    open_account_history_key_with_secret(wrapped, password, user_id, ACCOUNT_KEY_AAD_PREFIX)
}

/// Opens an account history key on a fresh device with a recovery code.
///
/// # Errors
///
/// Returns an error when the recovery code, account identifier, or wrapped
/// material is invalid, or when the KDF is unavailable.
pub fn open_account_history_key_with_recovery_code(
    wrapped: &WrappedAccountKeyMaterial,
    recovery_code: &str,
    user_id: u64,
) -> Result<[u8; 32], CryptoError> {
    open_account_history_key_with_secret(
        wrapped,
        recovery_code,
        user_id,
        RECOVERY_CODE_KEY_AAD_PREFIX,
    )
}

fn open_account_history_key_with_secret(
    wrapped: &WrappedAccountKeyMaterial,
    secret: &str,
    user_id: u64,
    aad_prefix: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let wrapping_key = derive_account_wrapping_key(secret, &wrapped.salt)?;
    XChaCha20Poly1305::new((&wrapping_key).into())
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            Payload {
                msg: &wrapped.ciphertext,
                aad: &account_key_aad(aad_prefix, user_id),
            },
        )
        .map_err(|_| CryptoError::InvalidAccountRecovery)?
        .try_into()
        .map_err(|_| CryptoError::InvalidAccountRecovery)
}

/// Encrypts one account-private message presentation for server persistence.
///
/// # Errors
///
/// Returns an error if secure randomness is unavailable or authenticated
/// encryption fails.
pub fn seal_private_history(
    account_key: &[u8; 32],
    user_id: u64,
    message_id: u64,
    plaintext: &[u8],
) -> Result<([u8; 24], Vec<u8>), CryptoError> {
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let ciphertext = XChaCha20Poly1305::new(account_key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &private_history_aad(user_id, message_id),
            },
        )
        .map_err(|_| CryptoError::AccountRecovery)?;
    Ok((nonce, ciphertext))
}

/// Decrypts one account-private message presentation.
///
/// # Errors
///
/// Returns an error when the account, message, nonce, key, or ciphertext does
/// not match the archive.
pub fn open_private_history(
    account_key: &[u8; 32],
    user_id: u64,
    message_id: u64,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    XChaCha20Poly1305::new(account_key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &private_history_aad(user_id, message_id),
            },
        )
        .map_err(|_| CryptoError::InvalidAccountRecovery)
}

fn derive_account_wrapping_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
    let params =
        Argon2Params::new(19 * 1024, 2, 1, Some(32)).map_err(|_| CryptoError::AccountRecovery)?;
    let mut key = [0_u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::AccountRecovery)?;
    Ok(key)
}

fn account_key_aad(prefix: &[u8], user_id: u64) -> Vec<u8> {
    let mut aad = prefix.to_vec();
    aad.extend_from_slice(&user_id.to_be_bytes());
    aad
}

fn private_history_aad(user_id: u64, message_id: u64) -> Vec<u8> {
    let mut aad = PRIVATE_HISTORY_AAD_PREFIX.to_vec();
    aad.extend_from_slice(&user_id.to_be_bytes());
    aad.extend_from_slice(&message_id.to_be_bytes());
    aad
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicDeviceIdentity {
    pub device_id: Uuid,
    pub user_id: u64,
    pub signature_key: Vec<u8>,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedKeyPackage {
    pub user_id: u64,
    pub device_id: Uuid,
    pub signature_key: Vec<u8>,
    pub reference: Vec<u8>,
    pub key_package: Vec<u8>,
    pub cipher_suite: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupBootstrap {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageContext {
    pub channel_id: u64,
    pub author_id: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub commitment: [u8; 32],
    pub attachment_sha256: Vec<[u8; 32]>,
    pub franking_key: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedMessage {
    pub content: String,
    pub attachment_sha256: Vec<[u8; 32]>,
    pub attachments: Vec<EncryptedAttachment>,
    pub franking_key: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrankingOpening {
    pub content: String,
    pub attachment_sha256: Vec<[u8; 32]>,
    pub franking_key: [u8; 32],
    pub franking_tag: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedAttachment {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub animated: bool,
    pub algorithm: String,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub plaintext_sha256: [u8; 32],
    pub ciphertext_sha256: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct ApplicationEnvelope {
    version: u8,
    content: String,
    attachment_sha256: Vec<[u8; 32]>,
    #[serde(default)]
    attachments: Vec<EncryptedAttachment>,
    franking_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    version: u8,
    device_id: Uuid,
    user_id: u64,
    signer: SignatureKeyPair,
    provider_values: HashMap<Vec<u8>, Vec<u8>>,
    channel_groups: HashMap<u64, Vec<u8>>,
}

pub struct MlsClient {
    device_id: Uuid,
    user_id: u64,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    channel_groups: HashMap<u64, Vec<u8>>,
}

impl MlsClient {
    /// Creates a device identity and an empty `OpenMLS` state.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform cryptographic provider cannot generate
    /// an Ed25519 key pair.
    pub fn create(user_id: u64, device_id: Uuid) -> Result<Self, CryptoError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|error| CryptoError::OpenMls(error.to_string()))?;
        signer
            .store(provider.storage())
            .map_err(|error| CryptoError::OpenMls(error.to_string()))?;
        let credential = credential(user_id, device_id, &signer);
        Ok(Self {
            device_id,
            user_id,
            provider,
            signer,
            credential,
            channel_groups: HashMap::new(),
        })
    }

    #[must_use]
    pub fn public_identity(&self) -> PublicDeviceIdentity {
        let signature_key = self.signer.to_public_vec();
        PublicDeviceIdentity {
            device_id: self.device_id,
            user_id: self.user_id,
            fingerprint: fingerprint(self.device_id, self.user_id, &signature_key),
            signature_key,
        }
    }

    #[must_use]
    pub const fn user_id(&self) -> u64 {
        self.user_id
    }

    #[must_use]
    pub const fn device_id(&self) -> Uuid {
        self.device_id
    }

    #[must_use]
    pub fn has_group(&self, channel_id: u64) -> bool {
        self.channel_groups.contains_key(&channel_id)
    }

    #[must_use]
    pub fn group_id(&self, channel_id: u64) -> Option<&[u8]> {
        self.channel_groups.get(&channel_id).map(Vec::as_slice)
    }

    /// Reports whether a device credential is a current leaf in a local group.
    ///
    /// # Errors
    ///
    /// Returns an error when the channel group is unavailable or unreadable.
    pub fn group_contains_device(
        &self,
        channel_id: u64,
        device_id: Uuid,
    ) -> Result<bool, CryptoError> {
        Ok(self
            .load_group(channel_id)?
            .members()
            .any(|member| credential_device_id(&member.credential) == Some(device_id)))
    }

    /// Generates an RFC 9420 `KeyPackage` and retains its private init material.
    ///
    /// # Errors
    ///
    /// Returns an error if `OpenMLS` cannot generate or hash the package.
    pub fn generate_key_package(&self) -> Result<PublishedKeyPackage, CryptoError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(openmls_error)?;
        let package = bundle.key_package();
        let reference = package
            .hash_ref(self.provider.crypto())
            .map_err(openmls_error)?
            .as_slice()
            .to_vec();
        Ok(PublishedKeyPackage {
            user_id: self.user_id,
            device_id: self.device_id,
            signature_key: self.signer.to_public_vec(),
            reference,
            key_package: package
                .tls_serialize_detached()
                .map_err(|error| CryptoError::Codec(error.to_string()))?,
            cipher_suite: CIPHER_SUITE_ID,
        })
    }

    /// Creates a new channel group and adds all supplied device `KeyPackages`.
    ///
    /// The returned Commit and Welcome are delivery-service payloads. The
    /// Welcome is one opaque MLS object containing encrypted group secrets for
    /// all added devices.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid `KeyPackage`. An empty member list
    /// creates a singleton group for a private guild or voice channel.
    pub fn create_group(
        &mut self,
        channel_id: u64,
        packages: &[PublishedKeyPackage],
    ) -> Result<GroupBootstrap, CryptoError> {
        if self.channel_groups.contains_key(&channel_id) {
            return Err(CryptoError::GroupAlreadyExists);
        }
        let validated = packages
            .iter()
            .map(|package| validate_key_package(&self.provider, package))
            .collect::<Result<Vec<_>, _>>()?;
        let group_id = GroupId::random(self.provider.rand());
        let config = group_config();
        let mut group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            group_id,
            self.credential.clone(),
        )
        .map_err(openmls_error)?;
        let (commit, welcome) = if validated.is_empty() {
            let (commit, _, _) = group
                .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
                .map_err(openmls_error)?
                .into_contents();
            (commit, None)
        } else {
            let (commit, welcome, _) = group
                .add_members(&self.provider, &self.signer, &validated)
                .map_err(openmls_error)?;
            (commit, Some(welcome))
        };
        group
            .merge_pending_commit(&self.provider)
            .map_err(openmls_error)?;
        let group_id = group.group_id().to_vec();
        let epoch = group.epoch().as_u64();
        self.channel_groups.insert(channel_id, group_id.clone());
        Ok(GroupBootstrap {
            group_id,
            epoch,
            commit: commit.to_bytes().map_err(openmls_error)?,
            welcome: welcome
                .map(|welcome| welcome.to_bytes().map_err(openmls_error))
                .transpose()?
                .unwrap_or_default(),
        })
    }

    /// Adds newly trusted devices to an existing channel group.
    ///
    /// The caller must durably distribute the Commit to every pre-existing
    /// device and the Welcome to each device represented by `packages`.
    ///
    /// # Errors
    ///
    /// Returns an error if the group is missing or a `KeyPackage` is invalid.
    pub fn add_members(
        &self,
        channel_id: u64,
        packages: &[PublishedKeyPackage],
    ) -> Result<GroupBootstrap, CryptoError> {
        if packages.is_empty() {
            return Err(CryptoError::MissingKeyPackages);
        }
        let validated = packages
            .iter()
            .map(|package| validate_key_package(&self.provider, package))
            .collect::<Result<Vec<_>, _>>()?;
        let mut group = self.load_group(channel_id)?;
        let (commit, welcome, _) = group
            .add_members(&self.provider, &self.signer, &validated)
            .map_err(openmls_error)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(openmls_error)?;
        Ok(GroupBootstrap {
            group_id: group.group_id().to_vec(),
            epoch: group.epoch().as_u64(),
            commit: commit.to_bytes().map_err(openmls_error)?,
            welcome: welcome.to_bytes().map_err(openmls_error)?,
        })
    }

    /// Removes device leaves from an existing channel group and advances the
    /// epoch, preventing those devices from deriving future message keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the group is missing, a device is not a current
    /// member, the local device is targeted, or `OpenMLS` rejects the Commit.
    pub fn remove_devices(
        &self,
        channel_id: u64,
        device_ids: &[Uuid],
    ) -> Result<GroupBootstrap, CryptoError> {
        if device_ids.is_empty() {
            return Err(CryptoError::MissingRemovalTargets);
        }
        let targets = device_ids
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        if targets.len() != device_ids.len() || targets.contains(&self.device_id) {
            return Err(CryptoError::InvalidRemovalTargets);
        }
        let mut group = self.load_group(channel_id)?;
        let leaf_indices = group
            .members()
            .filter_map(|member| {
                credential_device_id(&member.credential)
                    .filter(|device_id| targets.contains(device_id))
                    .map(|_| member.index)
            })
            .collect::<Vec<_>>();
        if leaf_indices.len() != targets.len() {
            return Err(CryptoError::InvalidRemovalTargets);
        }
        let (commit, _, _) = group
            .remove_members(&self.provider, &self.signer, &leaf_indices)
            .map_err(openmls_error)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(openmls_error)?;
        Ok(GroupBootstrap {
            group_id: group.group_id().to_vec(),
            epoch: group.epoch().as_u64(),
            commit: commit.to_bytes().map_err(openmls_error)?,
            welcome: Vec::new(),
        })
    }

    /// Joins a channel from an opaque MLS Welcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the Welcome is malformed, does not contain a group
    /// secret for a retained `KeyPackage`, or maps to a conflicting channel.
    pub fn join_group(&mut self, channel_id: u64, welcome: &[u8]) -> Result<u64, CryptoError> {
        if self.channel_groups.contains_key(&channel_id) {
            return Err(CryptoError::GroupAlreadyExists);
        }
        let message = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|error| CryptoError::Codec(error.to_string()))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(CryptoError::UnexpectedMessage);
        };
        let group = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            None,
        )
        .map_err(openmls_error)?
        .into_group(&self.provider)
        .map_err(openmls_error)?;
        let epoch = group.epoch().as_u64();
        self.channel_groups
            .insert(channel_id, group.group_id().to_vec());
        Ok(epoch)
    }

    /// Applies a server-ordered MLS Commit to an existing channel group.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is malformed, belongs to another group
    /// or epoch, or is not a Commit.
    pub fn process_commit(&self, channel_id: u64, commit: &[u8]) -> Result<u64, CryptoError> {
        let mut group = self.load_group(channel_id)?;
        let message = protocol_message(commit)?;
        let processed = group
            .process_message(&self.provider, message)
            .map_err(openmls_error)?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(CryptoError::UnexpectedMessage);
        };
        let epoch = staged.epoch().as_u64();
        group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(openmls_error)?;
        Ok(epoch)
    }

    /// Encrypts a message as an MLS application message and layers a committing
    /// HMAC over its canonical plaintext plus attachment hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel has no local MLS group, random key
    /// generation fails, or `OpenMLS` cannot create the application message.
    pub fn encrypt_message(
        &self,
        context: &MessageContext,
        message_body: &str,
        attachment_sha256: &[[u8; 32]],
    ) -> Result<EncryptedMessage, CryptoError> {
        self.encrypt_message_payload(context, message_body, attachment_sha256, &[])
    }

    /// Encrypts a message and its client-only encrypted attachment descriptors.
    ///
    /// Attachment bytes are encrypted before upload. The server sees opaque
    /// blobs and attachment ids; names, media types, hashes, nonces, and keys
    /// are authenticated inside this MLS application message.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel has no local MLS group, random key
    /// generation fails, or `OpenMLS` cannot create the application message.
    pub fn encrypt_message_with_attachments(
        &self,
        context: &MessageContext,
        message_body: &str,
        attachments: &[EncryptedAttachment],
    ) -> Result<EncryptedMessage, CryptoError> {
        let hashes = attachments
            .iter()
            .map(|attachment| attachment.plaintext_sha256)
            .collect::<Vec<_>>();
        self.encrypt_message_payload(context, message_body, &hashes, attachments)
    }

    fn encrypt_message_payload(
        &self,
        context: &MessageContext,
        message_body: &str,
        attachment_sha256: &[[u8; 32]],
        attachments: &[EncryptedAttachment],
    ) -> Result<EncryptedMessage, CryptoError> {
        let mut group = self.load_group(context.channel_id)?;
        group.set_aad(canonical_context(context)?);
        let mut franking_key = [0_u8; 32];
        getrandom::fill(&mut franking_key).map_err(|_| CryptoError::Randomness)?;
        let canonical = canonical_plaintext(message_body, attachment_sha256)?;
        let commitment = hmac(&franking_key, &canonical)?;
        let envelope = ApplicationEnvelope {
            version: 1,
            content: message_body.to_owned(),
            attachment_sha256: attachment_sha256.to_vec(),
            attachments: attachments.to_vec(),
            franking_key,
        };
        let plaintext = rmp_serde::to_vec_named(&envelope)?;
        let message = group
            .create_message(&self.provider, &self.signer, &plaintext)
            .map_err(openmls_error)?;
        Ok(EncryptedMessage {
            ciphertext: message.to_bytes().map_err(openmls_error)?,
            commitment,
            attachment_sha256: attachment_sha256.to_vec(),
            franking_key,
        })
    }

    /// Decrypts an MLS application message and verifies the explicit franking
    /// commitment before exposing plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if MLS authentication/decryption fails, the payload is
    /// not an application message, or its commitment does not match.
    pub fn decrypt_message(
        &self,
        context: &MessageContext,
        ciphertext: &[u8],
        commitment: &[u8; 32],
    ) -> Result<DecryptedMessage, CryptoError> {
        let mut group = self.load_group(context.channel_id)?;
        let expected_aad = canonical_context(context)?;
        let protocol = protocol_message(ciphertext)?;
        let ProtocolMessage::PrivateMessage(private_message) = &protocol else {
            return Err(CryptoError::UnexpectedMessage);
        };
        if private_message.aad() != expected_aad {
            return Err(CryptoError::ContextMismatch);
        }
        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(openmls_error)?;
        if processed.aad() != expected_aad {
            return Err(CryptoError::ContextMismatch);
        }
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err(CryptoError::UnexpectedMessage);
        };
        let envelope: ApplicationEnvelope = rmp_serde::from_slice(&application.into_bytes())?;
        if envelope.version != 1 {
            return Err(CryptoError::UnsupportedVersion);
        }
        let canonical = canonical_plaintext(&envelope.content, &envelope.attachment_sha256)?;
        let expected = hmac(&envelope.franking_key, &canonical)?;
        if !bool::from(expected.ct_eq(commitment)) {
            return Err(CryptoError::CommitmentMismatch);
        }
        Ok(DecryptedMessage {
            content: envelope.content,
            attachment_sha256: envelope.attachment_sha256,
            attachments: envelope.attachments,
            franking_key: envelope.franking_key,
        })
    }

    /// Derives an epoch-bound exporter secret for `SFrame` or attachment key
    /// derivation. Callers must domain-separate labels and contexts.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel has no group or `OpenMLS` export fails.
    pub fn export_secret(
        &self,
        channel_id: u64,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let group = self.load_group(channel_id)?;
        group
            .export_secret(self.provider.crypto(), label, context, length)
            .map_err(openmls_error)
    }

    /// Encrypts all native MLS state for persistence.
    ///
    /// # Errors
    ///
    /// Returns an error if state serialization, random nonce generation, or
    /// authenticated encryption fails.
    pub fn seal(&self, device_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let provider_values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| CryptoError::StateLock)?
            .clone();
        let state = PersistedState {
            version: 1,
            device_id: self.device_id,
            user_id: self.user_id,
            signer: self.signer.clone(),
            provider_values,
            channel_groups: self.channel_groups.clone(),
        };
        let plaintext = rmp_serde::to_vec_named(&state)?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
        let ciphertext = XChaCha20Poly1305::new(device_key.into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: STATE_AAD,
                },
            )
            .map_err(|_| CryptoError::StateEncryption)?;
        let mut sealed = Vec::with_capacity(STATE_MAGIC.len() + nonce.len() + ciphertext.len());
        sealed.extend_from_slice(STATE_MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Restores native MLS state from an authenticated encrypted snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key, damaged snapshot, unsupported
    /// version, or inconsistent stored signing identity.
    pub fn open(sealed: &[u8], device_key: &[u8; 32]) -> Result<Self, CryptoError> {
        let header = STATE_MAGIC.len() + 24;
        if sealed.len() <= header || sealed.get(..STATE_MAGIC.len()) != Some(STATE_MAGIC) {
            return Err(CryptoError::InvalidState);
        }
        let nonce = XNonce::from_slice(&sealed[STATE_MAGIC.len()..header]);
        let plaintext = XChaCha20Poly1305::new(device_key.into())
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed[header..],
                    aad: STATE_AAD,
                },
            )
            .map_err(|_| CryptoError::InvalidState)?;
        let state: PersistedState = rmp_serde::from_slice(&plaintext)?;
        if state.version != 1 {
            return Err(CryptoError::UnsupportedVersion);
        }
        let provider = OpenMlsRustCrypto::default();
        *provider
            .storage()
            .values
            .write()
            .map_err(|_| CryptoError::StateLock)? = state.provider_values;
        let stored_signer = SignatureKeyPair::read(
            provider.storage(),
            state.signer.public(),
            SignatureScheme::ED25519,
        )
        .ok_or(CryptoError::InvalidState)?;
        if stored_signer.public() != state.signer.public() {
            return Err(CryptoError::InvalidState);
        }
        let credential = credential(state.user_id, state.device_id, &state.signer);
        Ok(Self {
            device_id: state.device_id,
            user_id: state.user_id,
            provider,
            signer: state.signer,
            credential,
            channel_groups: state.channel_groups,
        })
    }

    fn load_group(&self, channel_id: u64) -> Result<MlsGroup, CryptoError> {
        let group_id = self
            .channel_groups
            .get(&channel_id)
            .ok_or(CryptoError::GroupNotFound)?;
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(|error| CryptoError::OpenMls(error.to_string()))?
            .ok_or(CryptoError::GroupNotFound)
    }
}

/// Verifies report evidence against the commitment sent with a message.
///
/// # Errors
///
/// Returns an error when canonical encoding or HMAC evaluation fails.
pub fn verify_franking_opening(
    content: &str,
    attachment_sha256: &[[u8; 32]],
    franking_key: &[u8; 32],
    commitment: &[u8; 32],
) -> Result<bool, CryptoError> {
    let canonical = canonical_plaintext(content, attachment_sha256)?;
    Ok(bool::from(
        hmac(franking_key, &canonical)?.ct_eq(commitment),
    ))
}

/// Seals report-only franking material under the operating-system device key.
///
/// # Errors
///
/// Returns an error if serialization, secure randomness, or authenticated
/// encryption fails.
pub fn seal_franking_opening(
    opening: &FrankingOpening,
    device_key: &[u8; 32],
    message_id: u64,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = rmp_serde::to_vec_named(opening)?;
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let aad = franking_aad(message_id);
    let ciphertext = XChaCha20Poly1305::new(device_key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::OpeningEncryption)?;
    let mut sealed = Vec::with_capacity(FRANKING_MAGIC.len() + nonce.len() + ciphertext.len());
    sealed.extend_from_slice(FRANKING_MAGIC);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Opens report-only franking material for its exact message id.
///
/// # Errors
///
/// Returns an error if the blob is damaged, belongs to another message or
/// device key, or cannot be decoded.
pub fn open_franking_opening(
    sealed: &[u8],
    device_key: &[u8; 32],
    message_id: u64,
) -> Result<FrankingOpening, CryptoError> {
    let header = FRANKING_MAGIC.len() + 24;
    if sealed.len() <= header || sealed.get(..FRANKING_MAGIC.len()) != Some(FRANKING_MAGIC) {
        return Err(CryptoError::InvalidOpening);
    }
    let aad = franking_aad(message_id);
    let plaintext = XChaCha20Poly1305::new(device_key.into())
        .decrypt(
            XNonce::from_slice(&sealed[FRANKING_MAGIC.len()..header]),
            Payload {
                msg: &sealed[header..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::InvalidOpening)?;
    rmp_serde::from_slice(&plaintext).map_err(Into::into)
}

fn franking_aad(message_id: u64) -> Vec<u8> {
    let mut aad = b"exocord/franking-opening/v1".to_vec();
    aad.extend_from_slice(&message_id.to_be_bytes());
    aad
}

#[must_use]
pub fn encode_urlsafe(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn credential(user_id: u64, device_id: Uuid, signer: &SignatureKeyPair) -> CredentialWithKey {
    let mut identity = Vec::with_capacity(1 + 8 + 16);
    identity.push(1);
    identity.extend_from_slice(&user_id.to_be_bytes());
    identity.extend_from_slice(device_id.as_bytes());
    CredentialWithKey {
        credential: BasicCredential::new(identity).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

fn credential_device_id(credential: &openmls::prelude::Credential) -> Option<Uuid> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    let identity = basic.identity();
    if identity.len() != 25 || identity.first() != Some(&1) {
        return None;
    }
    Uuid::from_slice(&identity[9..]).ok()
}

fn group_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

fn validate_key_package(
    provider: &OpenMlsRustCrypto,
    package: &PublishedKeyPackage,
) -> Result<KeyPackage, CryptoError> {
    if package.cipher_suite != CIPHER_SUITE_ID {
        return Err(CryptoError::UnsupportedCipherSuite);
    }
    let key_package = KeyPackageIn::tls_deserialize_exact(&package.key_package)
        .map_err(|error| CryptoError::Codec(error.to_string()))?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(openmls_error)?;
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(CryptoError::UnsupportedCipherSuite);
    }
    let reference = key_package
        .hash_ref(provider.crypto())
        .map_err(openmls_error)?;
    if reference.as_slice() != package.reference {
        return Err(CryptoError::KeyPackageReferenceMismatch);
    }
    let credential = BasicCredential::try_from(key_package.leaf_node().credential().clone())
        .map_err(|_| CryptoError::KeyPackageIdentityMismatch)?;
    let mut expected_identity = Vec::with_capacity(1 + 8 + 16);
    expected_identity.push(1);
    expected_identity.extend_from_slice(&package.user_id.to_be_bytes());
    expected_identity.extend_from_slice(package.device_id.as_bytes());
    if credential.identity() != expected_identity
        || key_package.leaf_node().signature_key().as_slice() != package.signature_key
    {
        return Err(CryptoError::KeyPackageIdentityMismatch);
    }
    Ok(key_package)
}

fn protocol_message(bytes: &[u8]) -> Result<openmls::prelude::ProtocolMessage, CryptoError> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|error| CryptoError::Codec(error.to_string()))?
        .try_into_protocol_message()
        .map_err(openmls_error)
}

fn canonical_context(context: &MessageContext) -> Result<Vec<u8>, CryptoError> {
    if context.nonce.is_empty() || context.nonce.len() > 64 {
        return Err(CryptoError::InvalidContext);
    }
    rmp_serde::to_vec_named(context).map_err(Into::into)
}

fn canonical_plaintext(
    content: &str,
    attachment_sha256: &[[u8; 32]],
) -> Result<Vec<u8>, CryptoError> {
    #[derive(Serialize)]
    struct Committed<'a> {
        version: u8,
        content: &'a str,
        attachment_sha256: &'a [[u8; 32]],
    }
    rmp_serde::to_vec_named(&Committed {
        version: 1,
        content,
        attachment_sha256,
    })
    .map_err(Into::into)
}

fn hmac(key: &[u8; 32], message: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| CryptoError::InvalidHmacKey)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

fn fingerprint(device_id: Uuid, user_id: u64, signature_key: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"exocord-device-fingerprint-v1");
    digest.update(user_id.to_be_bytes());
    digest.update(device_id.as_bytes());
    digest.update(signature_key);
    let bytes = digest.finalize();
    bytes
        .chunks(3)
        .map(hex::encode_upper)
        .collect::<Vec<_>>()
        .join(" ")
}

fn openmls_error(error: impl std::fmt::Display) -> CryptoError {
    CryptoError::OpenMls(error.to_string())
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("OpenMLS rejected the operation: {0}")]
    OpenMls(String),
    #[error("MLS data could not be encoded or decoded: {0}")]
    Codec(String),
    #[error("MLS state could not be locked")]
    StateLock,
    #[error("MLS state could not be encrypted")]
    StateEncryption,
    #[error("the encrypted MLS state is invalid or uses the wrong device key")]
    InvalidState,
    #[error("message-franking report material could not be encrypted")]
    OpeningEncryption,
    #[error("message-franking report material is invalid or uses the wrong device key")]
    InvalidOpening,
    #[error("secure randomness is unavailable")]
    Randomness,
    #[error("the MLS group does not exist on this device")]
    GroupNotFound,
    #[error("an MLS group already exists for this channel")]
    GroupAlreadyExists,
    #[error("at least one device KeyPackage is required")]
    MissingKeyPackages,
    #[error("at least one device removal target is required")]
    MissingRemovalTargets,
    #[error("the MLS device removal targets are invalid")]
    InvalidRemovalTargets,
    #[error("the MLS message has an unexpected type")]
    UnexpectedMessage,
    #[error("the MLS cipher suite is not supported")]
    UnsupportedCipherSuite,
    #[error("the MLS KeyPackage reference does not match its payload")]
    KeyPackageReferenceMismatch,
    #[error("the MLS KeyPackage identity does not match the registered device")]
    KeyPackageIdentityMismatch,
    #[error("the MLS payload version is not supported")]
    UnsupportedVersion,
    #[error("the message context is invalid")]
    InvalidContext,
    #[error("the authenticated message context does not match")]
    ContextMismatch,
    #[error("the message franking commitment does not match")]
    CommitmentMismatch,
    #[error("the HMAC key is invalid")]
    InvalidHmacKey,
    #[error("account recovery material could not be encrypted")]
    AccountRecovery,
    #[error("account recovery material is invalid or uses the wrong password")]
    InvalidAccountRecovery,
    #[error(transparent)]
    MessagePackEncode(#[from] rmp_serde::encode::Error),
    #[error(transparent)]
    MessagePackDecode(#[from] rmp_serde::decode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(channel_id: u64, author_id: u64, nonce: &str) -> MessageContext {
        MessageContext {
            channel_id,
            author_id,
            nonce: nonce.into(),
        }
    }

    #[test]
    fn account_history_key_and_message_archive_survive_a_fresh_device() {
        let account_key = [91_u8; 32];
        let wrapped =
            wrap_account_history_key(&account_key, "correct horse battery staple", 42).unwrap();
        assert_eq!(
            open_account_history_key(&wrapped, "correct horse battery staple", 42).unwrap(),
            account_key
        );
        assert!(open_account_history_key(&wrapped, "wrong password", 42).is_err());
        assert!(open_account_history_key(&wrapped, "correct horse battery staple", 43).is_err());

        let recovery_wrapped =
            wrap_account_history_key_with_recovery_code(&account_key, "exo_rc_saved", 42).unwrap();
        assert_eq!(
            open_account_history_key_with_recovery_code(&recovery_wrapped, "exo_rc_saved", 42)
                .unwrap(),
            account_key
        );
        assert!(
            open_account_history_key_with_recovery_code(&recovery_wrapped, "exo_rc_wrong", 42)
                .is_err()
        );
        assert!(open_account_history_key(&recovery_wrapped, "exo_rc_saved", 42).is_err());

        let (nonce, ciphertext) =
            seal_private_history(&account_key, 42, 700, b"private archived message").unwrap();
        assert!(!ciphertext.windows(7).any(|value| value == b"private"));
        assert_eq!(
            open_private_history(&account_key, 42, 700, &nonce, &ciphertext).unwrap(),
            b"private archived message"
        );
        assert!(open_private_history(&account_key, 42, 701, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn two_devices_exchange_committed_mls_messages_across_restart() {
        let channel_id = 42;
        let mut alice = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let mut bob = MlsClient::create(2, Uuid::now_v7()).unwrap();
        let bob_package = bob.generate_key_package().unwrap();
        let bootstrap = alice.create_group(channel_id, &[bob_package]).unwrap();
        assert_eq!(bootstrap.epoch, 1);
        assert_eq!(bob.join_group(channel_id, &bootstrap.welcome).unwrap(), 1);

        let attachment_hash = [7_u8; 32];
        let message_context = context(channel_id, 1, "nonce-one");
        let encrypted = alice
            .encrypt_message(&message_context, "private hello", &[attachment_hash])
            .unwrap();
        assert!(
            !encrypted
                .ciphertext
                .windows(7)
                .any(|part| part == b"private")
        );
        let decrypted = bob
            .decrypt_message(
                &message_context,
                &encrypted.ciphertext,
                &encrypted.commitment,
            )
            .unwrap();
        assert_eq!(decrypted.content, "private hello");
        assert_eq!(decrypted.attachment_sha256, vec![attachment_hash]);
        assert!(decrypted.attachments.is_empty());
        assert!(
            verify_franking_opening(
                &decrypted.content,
                &decrypted.attachment_sha256,
                &decrypted.franking_key,
                &encrypted.commitment
            )
            .unwrap()
        );

        let key = [9_u8; 32];
        let sealed = bob.seal(&key).unwrap();
        assert!(!sealed.windows(7).any(|part| part == b"private"));
        let bob = MlsClient::open(&sealed, &key).unwrap();
        let next_context = context(channel_id, 1, "nonce-two");
        let next = alice
            .encrypt_message(&next_context, "after restart", &[])
            .unwrap();
        assert_eq!(
            bob.decrypt_message(&next_context, &next.ciphertext, &next.commitment)
                .unwrap()
                .content,
            "after restart"
        );
    }

    #[test]
    fn aad_commitment_and_state_key_tampering_fail_closed() {
        let channel_id = 7;
        let mut alice = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let mut bob = MlsClient::create(2, Uuid::now_v7()).unwrap();
        let bootstrap = alice
            .create_group(channel_id, &[bob.generate_key_package().unwrap()])
            .unwrap();
        bob.join_group(channel_id, &bootstrap.welcome).unwrap();
        let original = context(channel_id, 1, "bound");
        let encrypted = alice.encrypt_message(&original, "authentic", &[]).unwrap();

        let wrong_context = context(channel_id, 1, "changed");
        assert!(
            bob.decrypt_message(&wrong_context, &encrypted.ciphertext, &encrypted.commitment)
                .is_err()
        );

        let mut commitment = encrypted.commitment;
        commitment[0] ^= 1;
        assert!(matches!(
            bob.decrypt_message(&original, &encrypted.ciphertext, &commitment),
            Err(CryptoError::CommitmentMismatch)
        ));

        let sealed = bob.seal(&[1_u8; 32]).unwrap();
        assert!(matches!(
            MlsClient::open(&sealed, &[2_u8; 32]),
            Err(CryptoError::InvalidState)
        ));
    }

    #[test]
    fn device_fingerprint_is_stable_and_identity_bound() {
        let device = Uuid::now_v7();
        let client = MlsClient::create(5, device).unwrap();
        let first = client.public_identity();
        let second = client.public_identity();
        assert_eq!(first, second);
        assert_eq!(first.signature_key.len(), 32);
        assert!(first.fingerprint.contains(' '));
    }

    #[test]
    fn franking_openings_are_device_and_message_bound_at_rest() {
        let opening = FrankingOpening {
            content: "reportable".into(),
            attachment_sha256: vec![[8; 32]],
            franking_key: [9; 32],
            franking_tag: [10; 32],
        };
        let sealed = seal_franking_opening(&opening, &[7; 32], 41).unwrap();
        assert_eq!(
            open_franking_opening(&sealed, &[7; 32], 41).unwrap(),
            opening
        );
        assert!(matches!(
            open_franking_opening(&sealed, &[7; 32], 42),
            Err(CryptoError::InvalidOpening)
        ));
        assert!(matches!(
            open_franking_opening(&sealed, &[6; 32], 41),
            Err(CryptoError::InvalidOpening)
        ));
    }

    #[test]
    fn singleton_group_exports_voice_key_material_without_a_welcome() {
        let channel_id = 91;
        let mut owner = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let bootstrap = owner.create_group(channel_id, &[]).unwrap();
        assert_eq!(bootstrap.epoch, 1);
        assert!(bootstrap.welcome.is_empty());
        assert!(!bootstrap.commit.is_empty());
        assert_eq!(
            owner
                .export_secret(
                    channel_id,
                    "EXOCORD_SFRAME_V1",
                    &channel_id.to_be_bytes(),
                    32
                )
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn a_later_device_joins_at_the_next_epoch_and_can_exchange_messages() {
        let channel_id = 92;
        let mut alice = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let mut bob = MlsClient::create(2, Uuid::now_v7()).unwrap();
        let mut charlie = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let bootstrap = alice
            .create_group(channel_id, &[bob.generate_key_package().unwrap()])
            .unwrap();
        bob.join_group(channel_id, &bootstrap.welcome).unwrap();

        let update = alice
            .add_members(channel_id, &[charlie.generate_key_package().unwrap()])
            .unwrap();
        assert_eq!(update.epoch, 2);
        assert_eq!(bob.process_commit(channel_id, &update.commit).unwrap(), 2);
        assert_eq!(charlie.join_group(channel_id, &update.welcome).unwrap(), 2);

        let message_context = context(channel_id, 1, "new-device");
        let encrypted = charlie
            .encrypt_message(&message_context, "future history is readable", &[])
            .unwrap();
        let alice_voice_key = alice
            .export_secret(
                channel_id,
                "EXOCORD_SFRAME_V1",
                &channel_id.to_be_bytes(),
                32,
            )
            .unwrap();
        let bob_voice_key = bob
            .export_secret(
                channel_id,
                "EXOCORD_SFRAME_V1",
                &channel_id.to_be_bytes(),
                32,
            )
            .unwrap();
        let charlie_voice_key = charlie
            .export_secret(
                channel_id,
                "EXOCORD_SFRAME_V1",
                &channel_id.to_be_bytes(),
                32,
            )
            .unwrap();
        assert_eq!(alice_voice_key, bob_voice_key);
        assert_eq!(alice_voice_key, charlie_voice_key);
        assert_eq!(
            alice
                .decrypt_message(
                    &message_context,
                    &encrypted.ciphertext,
                    &encrypted.commitment
                )
                .unwrap()
                .content,
            "future history is readable"
        );
        assert_eq!(
            bob.decrypt_message(
                &message_context,
                &encrypted.ciphertext,
                &encrypted.commitment
            )
            .unwrap()
            .content,
            "future history is readable"
        );
    }

    #[test]
    fn a_removed_device_cannot_decrypt_the_next_epoch() {
        let channel_id = 93;
        let mut alice = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let mut bob = MlsClient::create(2, Uuid::now_v7()).unwrap();
        let mut charlie = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let charlie_device_id = charlie.device_id();
        let bootstrap = alice
            .create_group(
                channel_id,
                &[
                    bob.generate_key_package().unwrap(),
                    charlie.generate_key_package().unwrap(),
                ],
            )
            .unwrap();
        bob.join_group(channel_id, &bootstrap.welcome).unwrap();
        charlie.join_group(channel_id, &bootstrap.welcome).unwrap();

        let removal = alice
            .remove_devices(channel_id, &[charlie_device_id])
            .unwrap();
        assert_eq!(removal.epoch, 2);
        assert!(removal.welcome.is_empty());
        assert_eq!(bob.process_commit(channel_id, &removal.commit).unwrap(), 2);

        let message_context = context(channel_id, 1, "after-revocation");
        let encrypted = alice
            .encrypt_message(&message_context, "future secret", &[])
            .unwrap();
        assert_eq!(
            bob.decrypt_message(
                &message_context,
                &encrypted.ciphertext,
                &encrypted.commitment
            )
            .unwrap()
            .content,
            "future secret"
        );
        assert!(
            charlie
                .decrypt_message(
                    &message_context,
                    &encrypted.ciphertext,
                    &encrypted.commitment
                )
                .is_err()
        );
    }

    #[test]
    fn attachment_keys_and_metadata_are_authenticated_inside_mls() {
        let channel_id = 13;
        let mut alice = MlsClient::create(1, Uuid::now_v7()).unwrap();
        let mut bob = MlsClient::create(2, Uuid::now_v7()).unwrap();
        let bootstrap = alice
            .create_group(channel_id, &[bob.generate_key_package().unwrap()])
            .unwrap();
        bob.join_group(channel_id, &bootstrap.welcome).unwrap();
        let attachment = EncryptedAttachment {
            id: "01953d73-79b0-7e80-8a24-a50bbf31e4ad".into(),
            filename: "private.png".into(),
            content_type: "image/png".into(),
            size: 4096,
            width: Some(320),
            height: Some(200),
            animated: false,
            algorithm: "AES-256-GCM".into(),
            key: [3; 32],
            nonce: [4; 12],
            plaintext_sha256: [5; 32],
            ciphertext_sha256: [6; 32],
        };
        let context = context(channel_id, 1, "attachment");
        let encrypted = alice
            .encrypt_message_with_attachments(
                &context,
                "the server cannot read the attachment descriptor",
                std::slice::from_ref(&attachment),
            )
            .unwrap();
        assert!(
            !encrypted
                .ciphertext
                .windows(11)
                .any(|part| part == b"private.png")
        );
        let decrypted = bob
            .decrypt_message(&context, &encrypted.ciphertext, &encrypted.commitment)
            .unwrap();
        assert_eq!(decrypted.attachments, vec![attachment]);
        assert_eq!(decrypted.attachment_sha256, vec![[5; 32]]);
    }
}
