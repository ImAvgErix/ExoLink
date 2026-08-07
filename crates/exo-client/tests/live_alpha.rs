use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use exo_client::{ApiClient, GatewayEvent, RecoveryKeyVaultEntry, UpdateProfile};
use exo_crypto::{
    MessageContext, MlsClient, PublishedKeyPackage, WrappedAccountKeyMaterial,
    open_account_history_key, open_account_history_key_with_recovery_code, open_private_history,
    seal_private_history, wrap_account_history_key, wrap_account_history_key_with_recovery_code,
};
use exo_domain::{
    BootstrapMlsGroup, ChannelKind, CreateChannel, CreateGuild, CreateInvite, MessageId,
    MlsWelcomeUpload, PrivateHistoryArchive, PublishMlsKeyPackage, PublishMlsKeyPackages,
    RegisterDeviceIdentity, UserId, WrappedAccountKey,
};
use uuid::Uuid;

fn wrapped_view(material: &WrappedAccountKeyMaterial) -> WrappedAccountKey {
    WrappedAccountKey {
        version: 1,
        salt: URL_SAFE_NO_PAD.encode(material.salt),
        nonce: URL_SAFE_NO_PAD.encode(material.nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(&material.ciphertext),
    }
}

fn wrapped_material(value: &WrappedAccountKey) -> WrappedAccountKeyMaterial {
    WrappedAccountKeyMaterial {
        salt: URL_SAFE_NO_PAD
            .decode(&value.salt)
            .unwrap()
            .try_into()
            .unwrap(),
        nonce: URL_SAFE_NO_PAD
            .decode(&value.nonce)
            .unwrap()
            .try_into()
            .unwrap(),
        ciphertext: URL_SAFE_NO_PAD.decode(&value.ciphertext).unwrap(),
    }
}

fn recovery_entries(key: &[u8; 32], user_id: u64, codes: &[String]) -> Vec<RecoveryKeyVaultEntry> {
    codes
        .iter()
        .map(|code| RecoveryKeyVaultEntry {
            recovery_code: code.clone(),
            wrapped_key: wrapped_view(
                &wrap_account_history_key_with_recovery_code(key, code, user_id).unwrap(),
            ),
        })
        .collect()
}

#[tokio::test]
#[ignore = "runs only against an explicitly selected deployed alpha"]
async fn deployed_gateway_accepts_a_tls_password_session() {
    let endpoint =
        std::env::var("EXOCORD_ACCEPTANCE_API").expect("set EXOCORD_ACCEPTANCE_API explicitly");
    let email =
        std::env::var("EXOCORD_ACCEPTANCE_EMAIL").expect("set EXOCORD_ACCEPTANCE_EMAIL explicitly");
    let password = std::env::var("EXOCORD_ACCEPTANCE_PASSWORD")
        .expect("set EXOCORD_ACCEPTANCE_PASSWORD explicitly");
    let device_id = Uuid::now_v7().to_string();
    let client = ApiClient::new(&endpoint, "").unwrap();
    client.set_device_id(device_id.clone());
    client
        .login_password(&email, &password, &device_id)
        .await
        .unwrap();
    let mut gateway = client.connect_gateway().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(10), gateway.next_event())
            .await
            .unwrap()
            .unwrap(),
        Some(GatewayEvent::Ready { .. })
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(35), gateway.next_event())
            .await
            .is_err(),
        "the deployed gateway did not remain open while idle"
    );
}

async fn establish_recovery(
    client: &ApiClient,
    user_id: u64,
    password: &str,
    codes: &[String],
    key: &[u8; 32],
) {
    let password_wrapper = wrap_account_history_key(key, password, user_id).unwrap();
    client
        .set_account_key_vault(password, &wrapped_view(&password_wrapper))
        .await
        .unwrap();
    client
        .set_recovery_key_vaults(password, &recovery_entries(key, user_id, codes))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "runs only against an explicitly selected deployed alpha"]
#[allow(clippy::too_many_lines)]
async fn deployed_accounts_are_isolated_and_survive_a_clean_install() {
    let endpoint =
        std::env::var("EXOCORD_ACCEPTANCE_API").expect("set EXOCORD_ACCEPTANCE_API explicitly");
    assert!(
        endpoint.starts_with("https://"),
        "acceptance must use the public TLS endpoint"
    );
    let run = Uuid::now_v7().simple().to_string();
    let suffix = &run[..10];
    let a_email = format!("acceptance-a-{run}@example.test");
    let b_email = format!("acceptance-b-{run}@example.test");
    let a_handle = format!("alpha-a-{suffix}");
    let b_handle = format!("alpha-b-{suffix}");
    let a_password = "alpha acceptance first private password";
    let a_new_password = "alpha acceptance replacement private password";
    let b_password = "beta acceptance private password";
    let a_device = Uuid::now_v7();
    let b_device = Uuid::now_v7();

    let a = ApiClient::new(&endpoint, "").unwrap();
    a.set_device_id(a_device.to_string());
    let a_registered = a
        .register_password(&a_email, a_password, &a_device.to_string())
        .await
        .unwrap();
    let a_id = a_registered.user.id.parse::<u64>().unwrap();
    assert_eq!(a_registered.recovery_codes.len(), 8);
    a.update_profile(&UpdateProfile {
        handle: a_handle.clone(),
        display_name: "Alpha Recovery A".into(),
        avatar_content_type: None,
        avatar_base64: None,
        remove_avatar: false,
    })
    .await
    .unwrap();
    let a_history_key = [41_u8; 32];
    establish_recovery(
        &a,
        a_id,
        a_password,
        &a_registered.recovery_codes,
        &a_history_key,
    )
    .await;

    let b = ApiClient::new(&endpoint, "").unwrap();
    b.set_device_id(b_device.to_string());
    let b_registered = b
        .register_password(&b_email, b_password, &b_device.to_string())
        .await
        .unwrap();
    let b_id = b_registered.user.id.parse::<u64>().unwrap();
    assert_eq!(b_registered.recovery_codes.len(), 8);
    b.update_profile(&UpdateProfile {
        handle: b_handle.clone(),
        display_name: "Alpha Recovery B".into(),
        avatar_content_type: None,
        avatar_base64: None,
        remove_avatar: false,
    })
    .await
    .unwrap();
    assert!(b.account_key_vault().await.unwrap().is_none());
    assert!(b.private_history().await.unwrap().is_empty());
    let b_history_key = [82_u8; 32];
    establish_recovery(
        &b,
        b_id,
        b_password,
        &b_registered.recovery_codes,
        &b_history_key,
    )
    .await;
    assert!(
        b.set_recovery_key_vaults(
            b_password,
            &recovery_entries(&b_history_key, b_id, &a_registered.recovery_codes)
        )
        .await
        .is_err(),
        "account B must not update account A's recovery-code records"
    );

    let a_reinstalled = ApiClient::new(&endpoint, "").unwrap();
    let a_reinstall_device = Uuid::now_v7();
    a_reinstalled.set_device_id(a_reinstall_device.to_string());
    let reinstalled_session = a_reinstalled
        .login_password(&a_email, a_password, &a_reinstall_device.to_string())
        .await
        .unwrap();
    assert_eq!(reinstalled_session.user.id, a_id.to_string());
    let mut gateway = a_reinstalled.connect_gateway().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(10), gateway.next_event())
            .await
            .unwrap()
            .unwrap(),
        Some(GatewayEvent::Ready { .. })
    ));
    drop(gateway);
    let server_wrapper = a_reinstalled.account_key_vault().await.unwrap().unwrap();
    assert_eq!(
        open_account_history_key(&wrapped_material(&server_wrapper), a_password, a_id).unwrap(),
        a_history_key
    );

    let mut a_mls = MlsClient::create(a_id, a_device).unwrap();
    let mut b_mls = MlsClient::create(b_id, b_device).unwrap();
    for (client, mls) in [(&a, &a_mls), (&b, &b_mls)] {
        let identity = mls.public_identity();
        client
            .register_device_identity(
                &identity.device_id.to_string(),
                &RegisterDeviceIdentity {
                    signature_key: URL_SAFE_NO_PAD.encode(identity.signature_key),
                    name: Some("Clean-install acceptance device".into()),
                },
            )
            .await
            .unwrap();
    }
    let b_package = b_mls.generate_key_package().unwrap();
    b.publish_mls_key_packages(
        &b_device.to_string(),
        &PublishMlsKeyPackages {
            packages: vec![PublishMlsKeyPackage {
                reference: URL_SAFE_NO_PAD.encode(&b_package.reference),
                key_package: URL_SAFE_NO_PAD.encode(&b_package.key_package),
                cipher_suite: b_package.cipher_suite,
            }],
        },
    )
    .await
    .unwrap();
    a.request_friend(&b_handle).await.unwrap();
    b.accept_friend(UserId::from_raw(a_id).unwrap())
        .await
        .unwrap();
    let direct = a
        .open_direct_channel(UserId::from_raw(b_id).unwrap())
        .await
        .unwrap();
    assert!(direct.encrypted);
    let claimed = a.claim_mls_key_packages(direct.id.raw()).await.unwrap();
    assert_eq!(claimed.len(), 1);
    let b_identity = a
        .list_device_identities(UserId::from_raw(b_id).unwrap())
        .await
        .unwrap()
        .into_iter()
        .find(|identity| identity.device_id == b_device)
        .unwrap();
    let published = PublishedKeyPackage {
        user_id: b_id,
        device_id: b_device,
        signature_key: URL_SAFE_NO_PAD.decode(b_identity.signature_key).unwrap(),
        reference: URL_SAFE_NO_PAD.decode(&claimed[0].reference).unwrap(),
        key_package: URL_SAFE_NO_PAD.decode(&claimed[0].key_package).unwrap(),
        cipher_suite: claimed[0].cipher_suite,
    };
    let bootstrap = a_mls.create_group(direct.id.raw(), &[published]).unwrap();
    a.bootstrap_mls_group(
        direct.id.raw(),
        &BootstrapMlsGroup {
            group_id: URL_SAFE_NO_PAD.encode(&bootstrap.group_id),
            epoch: bootstrap.epoch,
            commit: URL_SAFE_NO_PAD.encode(&bootstrap.commit),
            welcomes: vec![MlsWelcomeUpload {
                device_id: b_device,
                key_package_reference: claimed[0].reference.clone(),
                payload: URL_SAFE_NO_PAD.encode(&bootstrap.welcome),
            }],
        },
    )
    .await
    .unwrap();
    let inbox = b.mls_inbox(&b_device.to_string()).await.unwrap();
    assert_eq!(inbox.len(), 1);
    b_mls
        .join_group(
            direct.id.raw(),
            &URL_SAFE_NO_PAD.decode(&inbox[0].payload).unwrap(),
        )
        .unwrap();
    b.acknowledge_mls_delivery(&b_device.to_string(), &inbox[0])
        .await
        .unwrap();

    let message_text = "clean install keeps this exact private DM";
    let context = MessageContext {
        channel_id: direct.id.raw(),
        author_id: a_id,
        nonce: format!("clean-install-{suffix}"),
    };
    let encrypted = a_mls.encrypt_message(&context, message_text, &[]).unwrap();
    let message = a
        .send_encrypted_message(
            direct.id.raw(),
            URL_SAFE_NO_PAD.encode(encrypted.ciphertext),
            URL_SAFE_NO_PAD.encode(encrypted.commitment),
            None,
            &context.nonce,
            &[],
        )
        .await
        .unwrap();
    assert!(message.content.is_empty());
    let transport = message.encryption.as_ref().unwrap();
    let b_decrypted = b_mls
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
    assert_eq!(b_decrypted.content, message_text);

    let history_payload = serde_json::to_vec(&serde_json::json!({
        "version": 2,
        "content": message_text,
        "attachments": [],
        "authorId": message.author_id.raw(),
        "replyTo": message.reply_to.map(MessageId::raw),
        "reactions": message.reactions,
        "sequence": message.sequence,
        "createdAt": message.created_at.to_rfc3339(),
        "editedAt": message.edited_at.map(|value| value.to_rfc3339()),
    }))
    .unwrap();
    let (a_nonce, a_ciphertext) =
        seal_private_history(&a_history_key, a_id, message.id.raw(), &history_payload).unwrap();
    a.put_private_history(&PrivateHistoryArchive {
        message_id: message.id,
        channel_id: direct.id,
        nonce: URL_SAFE_NO_PAD.encode(a_nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(a_ciphertext),
    })
    .await
    .unwrap();
    let (b_nonce, b_ciphertext) =
        seal_private_history(&b_history_key, b_id, message.id.raw(), &history_payload).unwrap();
    b.put_private_history(&PrivateHistoryArchive {
        message_id: message.id,
        channel_id: direct.id,
        nonce: URL_SAFE_NO_PAD.encode(b_nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(b_ciphertext),
    })
    .await
    .unwrap();
    let a_archives = a_reinstalled.private_history().await.unwrap();
    let b_archives = b.private_history().await.unwrap();
    assert_eq!(a_archives.len(), 1);
    assert_eq!(b_archives.len(), 1);
    assert_ne!(a_archives[0].ciphertext, b_archives[0].ciphertext);
    let a_archive_nonce: [u8; 24] = URL_SAFE_NO_PAD
        .decode(&a_archives[0].nonce)
        .unwrap()
        .try_into()
        .unwrap();
    let opened_history = open_private_history(
        &a_history_key,
        a_id,
        message.id.raw(),
        &a_archive_nonce,
        &URL_SAFE_NO_PAD.decode(&a_archives[0].ciphertext).unwrap(),
    )
    .unwrap();
    let opened_history: serde_json::Value = serde_json::from_slice(&opened_history).unwrap();
    assert_eq!(opened_history["version"], 2);
    assert_eq!(opened_history["content"], message_text);
    assert!(
        open_private_history(
            &b_history_key,
            b_id,
            message.id.raw(),
            &a_archive_nonce,
            &URL_SAFE_NO_PAD.decode(&a_archives[0].ciphertext).unwrap()
        )
        .is_err(),
        "account B's key must not decrypt account A's archive"
    );
    let reinstall_sync = a_reinstalled.fetch_sync().await.unwrap();
    assert_eq!(reinstall_sync.current_user.id.raw(), a_id);
    assert!(
        reinstall_sync
            .messages
            .iter()
            .any(|stored| stored.id == message.id)
    );

    let recovery_code = a_registered.recovery_codes[0].clone();
    let recovery_client = ApiClient::new(&endpoint, "").unwrap();
    let recovery_device = Uuid::now_v7();
    recovery_client.set_device_id(recovery_device.to_string());
    let recovered = recovery_client
        .recover_password(
            &a_email,
            &recovery_code,
            a_new_password,
            &recovery_device.to_string(),
        )
        .await
        .unwrap();
    let recovered_key = open_account_history_key_with_recovery_code(
        &wrapped_material(recovered.recovery_wrapped_key.as_ref().unwrap()),
        &recovery_code,
        a_id,
    )
    .unwrap();
    assert_eq!(recovered_key, a_history_key);
    establish_recovery(
        &recovery_client,
        a_id,
        a_new_password,
        &recovered.recovery_codes,
        &recovered_key,
    )
    .await;

    let final_client = ApiClient::new(&endpoint, "").unwrap();
    let final_device = Uuid::now_v7();
    final_client.set_device_id(final_device.to_string());
    final_client
        .login_password(&a_email, a_new_password, &final_device.to_string())
        .await
        .unwrap();
    let final_wrapper = final_client.account_key_vault().await.unwrap().unwrap();
    assert_eq!(
        open_account_history_key(&wrapped_material(&final_wrapper), a_new_password, a_id).unwrap(),
        a_history_key
    );
    let recovered_archives = final_client.private_history().await.unwrap();
    assert_eq!(recovered_archives.len(), 1);

    let guild = final_client
        .create_guild(&CreateGuild {
            name: format!("Recovery {suffix}"),
            accent: Some(0x007c_5cff),
        })
        .await
        .unwrap();
    assert!(
        !b.fetch_sync()
            .await
            .unwrap()
            .guilds
            .iter()
            .any(|value| value.id == guild.id),
        "account B must not see account A's unjoined server"
    );
    let voice = final_client
        .create_channel(
            guild.id.raw(),
            &CreateChannel {
                name: "voice".into(),
                kind: ChannelKind::Voice,
                encrypted: true,
            },
        )
        .await
        .unwrap();
    let invite = final_client
        .create_invite(
            guild.id.raw(),
            &CreateInvite {
                expires_in_seconds: Some(3600),
                max_uses: Some(1),
            },
        )
        .await
        .unwrap();
    b.accept_invite(&invite.code).await.unwrap();
    assert!(
        b.fetch_sync()
            .await
            .unwrap()
            .guilds
            .iter()
            .any(|value| value.id == guild.id)
    );
    let voice_grant = final_client
        .create_voice_grant(voice.id.raw())
        .await
        .unwrap();
    assert!(voice_grant.server_url.starts_with("wss://"));
    assert!(!voice_grant.token.is_empty());
    assert!(voice_grant.transport_encrypted);
    assert!(
        !voice_grant.end_to_end_encrypted,
        "the raw SFU grant must not claim client-side MLS encryption"
    );
    let mut voice_mls = MlsClient::create(a_id, final_device).unwrap();
    let voice_identity = voice_mls.public_identity();
    final_client
        .register_device_identity(
            &final_device.to_string(),
            &RegisterDeviceIdentity {
                signature_key: URL_SAFE_NO_PAD.encode(voice_identity.signature_key),
                name: Some("Clean-install acceptance voice device".into()),
            },
        )
        .await
        .unwrap();
    let voice_bootstrap = voice_mls.create_group(voice.id.raw(), &[]).unwrap();
    final_client
        .bootstrap_mls_group(
            voice.id.raw(),
            &BootstrapMlsGroup {
                group_id: URL_SAFE_NO_PAD.encode(&voice_bootstrap.group_id),
                epoch: voice_bootstrap.epoch,
                commit: URL_SAFE_NO_PAD.encode(&voice_bootstrap.commit),
                welcomes: Vec::new(),
            },
        )
        .await
        .unwrap();
    let voice_key = voice_mls
        .export_secret(
            voice.id.raw(),
            "EXOCORD_SFRAME_V1",
            &voice.id.raw().to_be_bytes(),
            32,
        )
        .unwrap();
    assert_eq!(voice_key.len(), 32);

    println!(
        "{}",
        serde_json::json!({
            "status": "passed",
            "accountIsolation": true,
            "cleanInstallPasswordRecovery": true,
            "cleanInstallRecoveryCodeRecovery": true,
            "privateDmRestored": true,
            "serverPersistence": true,
            "voiceGrant": true,
            "voiceE2eeClientKey": true,
            "accountA": a_id.to_string(),
            "accountB": b_id.to_string(),
            "messageId": MessageId::from_raw(message.id.raw()).unwrap().to_string()
        })
    );
}
