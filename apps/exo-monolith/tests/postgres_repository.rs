use std::{error::Error, net::TcpListener, time::Duration};

use chrono::Utc;
use exo_domain::{
    AttachmentId, AutomodAction, AutomodTrigger, ChannelKind, CreateAutomodRule, GuildPermissions,
    OverwriteTargetKind, RelationshipKind, ReportCategory, UpdateAutomodRule, User, UserId,
};
use exo_monolith::repository::{
    MessageWindow, MlsDeliveryRecordKind, MlsWelcomeRecord, NewAttachment, NewMessageEncryption,
    OperatorReportStatus, RelationshipAction, ReportEvidence, Repository, RepositoryError,
    VerifiedAttachment,
};
use pg_embed::{
    pg_enums::PgAuthMethod,
    pg_fetch::{PG_V17, PgFetchSettings},
    postgres::{PgEmbed, PgSettings},
};
use uuid::Uuid;

#[tokio::test]
#[ignore = "downloads and starts a real PostgreSQL 17 process"]
async fn migrations_transactions_membership_and_idempotency_survive_restart()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let port = available_port()?;
    let settings = PgSettings {
        database_dir: directory.path().join("cluster"),
        port,
        user: "postgres".into(),
        password: "exocord-test".into(),
        auth_method: PgAuthMethod::MD5,
        persistent: false,
        timeout: Some(Duration::from_secs(60)),
        migration_dir: None,
    };
    let fetch = PgFetchSettings {
        version: PG_V17,
        ..Default::default()
    };
    let mut postgres = PgEmbed::new(settings, fetch).await?;
    postgres.setup().await?;
    postgres.start_db().await?;
    let maintenance = sqlx::PgPool::connect(&postgres.full_db_uri("postgres")).await?;
    sqlx::query("CREATE DATABASE exocord_test")
        .execute(&maintenance)
        .await?;
    maintenance.close().await;
    let database_url = postgres.full_db_uri("exocord_test");

    let (repository, next_sequence) = Repository::connect_postgres(&database_url, 4).await?;
    assert_eq!(repository.storage_name(), "postgres");
    assert_eq!(next_sequence, 1);
    repository.ready().await?;

    let owner = user("owner", "Owner");
    let outsider = user("outsider", "Outsider");
    let blocked = user("blocked", "Blocked");
    repository
        .ensure_user(owner.clone(), Some("owner@example.test"))
        .await?;
    repository
        .ensure_user(outsider.clone(), Some("outsider@example.test"))
        .await?;
    repository
        .ensure_user(blocked.clone(), Some("blocked@example.test"))
        .await?;

    let created = repository
        .create_guild(owner.id, "Durable Home".into(), 0x785DFF)
        .await?;
    assert_eq!(created.channels.len(), 2);
    assert_eq!(repository.list_guilds(owner.id).await?.len(), 1);
    assert!(repository.list_guilds(outsider.id).await?.is_empty());
    assert!(matches!(
        repository
            .list_channels(outsider.id, created.guild.id)
            .await,
        Err(RepositoryError::NotFound("server"))
    ));
    let invite_hash = vec![9_u8; 32];
    repository
        .create_invite(
            owner.id,
            created.guild.id,
            "postgres-invite-code-123".into(),
            &invite_hash,
            Some(5),
            Some(Utc::now() + chrono::Duration::hours(1)),
        )
        .await?;
    let preview = repository
        .preview_invite("postgres-invite-code-123".into(), &invite_hash)
        .await?;
    assert_eq!(preview.member_count, 1);
    repository.accept_invite(outsider.id, &invite_hash).await?;
    repository.accept_invite(outsider.id, &invite_hash).await?;
    assert_eq!(
        repository
            .preview_invite("postgres-invite-code-123".into(), &invite_hash)
            .await?
            .uses,
        1
    );
    assert_eq!(repository.list_guilds(outsider.id).await?.len(), 1);
    assert_eq!(
        repository
            .list_members(owner.id, created.guild.id, 100)
            .await?
            .len(),
        2
    );
    let automod_rule = repository
        .create_automod_rule(
            owner.id,
            created.guild.id,
            CreateAutomodRule {
                name: "Durable credential guard".into(),
                enabled: true,
                trigger: AutomodTrigger::Keyword {
                    terms: vec!["private-key".into()],
                },
                action: AutomodAction::Timeout,
                duration_seconds: Some(600),
                explanation: "Credentials must remain private.".into(),
            },
        )
        .await?;
    let joined_snapshot = repository.snapshot(outsider.id, 0).await?;
    assert!(joined_snapshot.users.iter().any(|user| user.id == owner.id));
    assert!(
        joined_snapshot
            .users
            .iter()
            .any(|user| user.id == outsider.id)
    );
    let delegated = repository
        .create_role(
            owner.id,
            created.guild.id,
            "Channel steward".into(),
            0x69D7BD,
            GuildPermissions::MANAGE_CHANNELS | GuildPermissions::CREATE_INVITE,
        )
        .await?;
    let delegated = repository
        .update_role(
            owner.id,
            created.guild.id,
            delegated.id,
            "Community steward".into(),
            0x5FC9B0,
            delegated.permissions,
        )
        .await?;
    repository
        .set_member_role(owner.id, created.guild.id, outsider.id, delegated.id, true)
        .await?;
    let delegated_channel = repository
        .create_channel(
            outsider.id,
            created.guild.id,
            "delegated-room".into(),
            ChannelKind::Text,
            false,
        )
        .await?;
    assert_eq!(delegated_channel.name, "delegated-room");
    repository
        .set_member_role(owner.id, created.guild.id, outsider.id, delegated.id, false)
        .await?;
    assert!(matches!(
        repository
            .create_channel(
                outsider.id,
                created.guild.id,
                "should-fail".into(),
                ChannelKind::Text,
                false,
            )
            .await,
        Err(RepositoryError::Forbidden)
    ));
    repository
        .set_member_role(owner.id, created.guild.id, outsider.id, delegated.id, true)
        .await?;
    let audit_pool = sqlx::PgPool::connect(&database_url).await?;
    let role_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
         WHERE guild_id = $1 AND action_type BETWEEN 20 AND 24",
    )
    .bind(i64::try_from(created.guild.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert_eq!(role_audits, 5);
    let channel_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
         WHERE guild_id = $1 AND action_type BETWEEN 10 AND 12",
    )
    .bind(i64::try_from(created.guild.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert_eq!(channel_audits, 1);

    let text_channel = created
        .channels
        .iter()
        .find(|channel| channel.kind == ChannelKind::Text)
        .expect("default text channel");
    let voice_channel = created
        .channels
        .iter()
        .find(|channel| channel.kind == ChannelKind::Voice)
        .expect("default voice channel");
    let voice_access = repository
        .voice_access(outsider.id, voice_channel.id)
        .await?;
    assert!(
        voice_access
            .permissions
            .contains(GuildPermissions::CONNECT | GuildPermissions::SPEAK)
    );
    assert!(!voice_access.permissions.contains(GuildPermissions::STREAM));
    let first = repository
        .create_message(
            owner.id,
            text_channel.id,
            "one durable message".into(),
            None,
            "same-logical-send".into(),
            &[],
            1,
        )
        .await?;
    assert!(first.created);
    let retry = repository
        .create_message(
            owner.id,
            text_channel.id,
            "duplicate body is ignored".into(),
            None,
            "same-logical-send".into(),
            &[],
            2,
        )
        .await?;
    assert!(!retry.created);
    assert_eq!(retry.message.id, first.message.id);
    let reply = repository
        .create_message(
            owner.id,
            text_channel.id,
            "durable reply".into(),
            Some(first.message.id),
            "durable-reply".into(),
            &[],
            2,
        )
        .await?;
    assert_eq!(reply.message.reply_to, Some(first.message.id));
    let edited = repository
        .update_message(
            owner.id,
            text_channel.id,
            first.message.id,
            "durably edited".into(),
            None,
            None,
            "durable-edit".into(),
        )
        .await?;
    assert_eq!(edited.message.content, "durably edited");
    assert!(edited.message.edited_at.is_some());
    let reaction = repository
        .update_reaction(
            owner.id,
            text_channel.id,
            first.message.id,
            "👍".into(),
            true,
        )
        .await?;
    assert!(reaction.changed);
    assert_eq!(reaction.event.count, 1);
    let listed = repository
        .list_messages(
            owner.id,
            text_channel.id,
            exo_monolith::repository::MessageWindow {
                limit: 100,
                ..Default::default()
            },
        )
        .await?;
    let listed_first = listed
        .iter()
        .find(|message| message.id == first.message.id)
        .expect("edited message remains visible");
    assert_eq!(listed_first.content, "durably edited");
    assert_eq!(listed_first.reactions.len(), 1);
    assert!(listed_first.reactions[0].me);
    let report_evidence = serde_json::to_vec(&ReportEvidence {
        content: listed_first.content.clone(),
        encrypted: false,
        verified: true,
        attachments: Vec::new(),
        attachment_sha256: Vec::new(),
    })?;
    let report_receipt = repository
        .create_message_report(
            outsider.id,
            first.message.id,
            text_channel.id,
            owner.id,
            Some(created.guild.id),
            ReportCategory::Harassment,
            Some("PostgreSQL triage integration report.".into()),
            report_evidence,
            None,
        )
        .await?;
    let open_reports = repository
        .operator_reports(Some(OperatorReportStatus::Open), 10)
        .await?;
    assert_eq!(open_reports.len(), 1);
    assert_eq!(open_reports[0].id, report_receipt.id);
    assert_eq!(open_reports[0].evidence.content, "durably edited");
    assert_eq!(open_reports[0].reporter.id, outsider.id);
    assert_eq!(open_reports[0].author.id, owner.id);
    let resolved_report = repository
        .resolve_operator_report(
            report_receipt.id,
            OperatorReportStatus::Actioned,
            "Postgres integration operator",
            Some("Verified test resolution.".into()),
        )
        .await?;
    assert_eq!(resolved_report.status, "actioned");
    assert_eq!(
        resolved_report.handled_by_operator.as_deref(),
        Some("Postgres integration operator")
    );
    assert!(matches!(
        repository
            .resolve_operator_report(
                report_receipt.id,
                OperatorReportStatus::Dismissed,
                "Postgres integration operator",
                None,
            )
            .await,
        Err(RepositoryError::Conflict)
    ));
    repository
        .delete_message(owner.id, text_channel.id, reply.message.id)
        .await?;
    assert!(
        repository
            .list_messages(
                owner.id,
                text_channel.id,
                exo_monolith::repository::MessageWindow {
                    limit: 100,
                    ..Default::default()
                },
            )
            .await?
            .iter()
            .all(|message| message.id != reply.message.id)
    );

    let attachment_id = AttachmentId::new();
    let attachment_hash = [31_u8; 32];
    repository
        .reserve_attachment(NewAttachment {
            id: attachment_id,
            channel_id: text_channel.id,
            owner_id: owner.id,
            filename: "durable.txt".into(),
            declared_content_type: "text/plain".into(),
            file_size: 7,
            claimed_sha256: attachment_hash,
            object_key: "objects/test/durable".into(),
            public_url: "https://cdn.example.test/objects/test/durable".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
        })
        .await?;
    let completed_attachment = repository
        .complete_attachment(
            owner.id,
            attachment_id,
            &VerifiedAttachment {
                content_type: "text/plain".into(),
                size: 7,
                sha256: attachment_hash,
                width: None,
                height: None,
                animated: false,
            },
        )
        .await?;
    let attachment_message = repository
        .create_message(
            owner.id,
            text_channel.id,
            String::new(),
            None,
            "durable-attachment".into(),
            &[attachment_id],
            2,
        )
        .await?;
    assert_eq!(
        attachment_message.message.attachments,
        vec![completed_attachment.clone()]
    );

    repository
        .set_channel_overwrite(
            owner.id,
            text_channel.id,
            OverwriteTargetKind::Role,
            created.guild.id.raw(),
            GuildPermissions::empty(),
            GuildPermissions::VIEW_CHANNEL,
        )
        .await?;
    assert!(
        repository
            .list_channels(outsider.id, created.guild.id)
            .await?
            .iter()
            .all(|channel| channel.id != text_channel.id)
    );
    repository
        .set_channel_overwrite(
            owner.id,
            text_channel.id,
            OverwriteTargetKind::Member,
            outsider.id.raw(),
            GuildPermissions::VIEW_CHANNEL
                | GuildPermissions::READ_MESSAGE_HISTORY
                | GuildPermissions::SEND_MESSAGES,
            GuildPermissions::empty(),
        )
        .await?;
    assert!(
        repository
            .list_channels(outsider.id, created.guild.id)
            .await?
            .iter()
            .any(|channel| channel.id == text_channel.id)
    );
    let engine = exo_safety::AutomodEngine::compile(
        &repository.active_automod_rules(created.guild.id).await?,
    )?;
    let matched = engine
        .evaluate(&exo_safety::AutomodContext {
            guild_id: created.guild.id,
            author_id: outsider.id,
            content: "PRIVATE-KEY should not be posted",
            account_created_at: outsider.created_at,
            now: Utc::now(),
        })
        .expect("the durable automod rule matches");
    let enforcement = repository
        .apply_automod_match(created.guild.id, outsider.id, &matched)
        .await?;
    assert_eq!(enforcement.applied_action, AutomodAction::Timeout);
    repository
        .timeout_member(
            owner.id,
            created.guild.id,
            outsider.id,
            Some(Utc::now() + chrono::Duration::hours(1)),
            Some("durable timeout".into()),
        )
        .await?;
    assert!(matches!(
        repository.voice_access(outsider.id, voice_channel.id).await,
        Err(RepositoryError::NotFound("channel"))
    ));

    repository.accept_invite(blocked.id, &invite_hash).await?;
    repository
        .ban_member(
            owner.id,
            created.guild.id,
            blocked.id,
            Some("durable ban".into()),
            None,
        )
        .await?;
    assert!(matches!(
        repository.accept_invite(blocked.id, &invite_hash).await,
        Err(RepositoryError::Forbidden)
    ));
    let invalid_target_insert = sqlx::query(
        "INSERT INTO channel_overwrites
           (channel_id, target_id, target_type, allow_bits, deny_bits)
         VALUES ($1, $2, 1, 0, 0)",
    )
    .bind(i64::try_from(text_channel.id.raw())?)
    .bind(i64::try_from(blocked.id.raw())?)
    .execute(&audit_pool)
    .await;
    assert!(
        invalid_target_insert.is_err(),
        "the database trigger must reject non-member overwrite targets"
    );

    let outgoing = repository
        .request_relationship(owner.id, &outsider.handle)
        .await?;
    assert_eq!(outgoing.kind, RelationshipKind::Outgoing);
    assert_eq!(
        repository.list_relationships(outsider.id).await?[0].kind,
        RelationshipKind::Incoming
    );
    let accepted = repository
        .update_relationship(outsider.id, owner.id, RelationshipAction::Accept)
        .await?;
    assert_eq!(accepted.kind, RelationshipKind::Friend);
    let direct = repository
        .open_direct_channel(owner.id, outsider.id)
        .await?;
    assert!(direct.encrypted);
    assert_eq!(
        repository
            .open_direct_channel(outsider.id, owner.id)
            .await?
            .id,
        direct.id
    );
    assert!(matches!(
        repository
            .list_messages(
                blocked.id,
                direct.id,
                MessageWindow {
                    limit: 100,
                    ..MessageWindow::default()
                },
            )
            .await,
        Err(RepositoryError::NotFound("channel"))
    ));
    let owner_device = Uuid::now_v7();
    let outsider_device = Uuid::now_v7();
    repository
        .register_device_identity(owner.id, owner_device, [40_u8; 32], Some("Owner".into()))
        .await?;
    repository
        .register_device_identity(
            outsider.id,
            outsider_device,
            [41_u8; 32],
            Some("Outsider".into()),
        )
        .await?;
    let package_reference = [42_u8; 32];
    repository
        .publish_mls_key_packages(
            outsider.id,
            outsider_device,
            vec![(package_reference, vec![43_u8; 128], 1)],
        )
        .await?;
    repository
        .claim_mls_key_packages(owner.id, owner_device, direct.id)
        .await?;
    repository
        .bootstrap_mls_group(
            owner.id,
            owner_device,
            direct.id,
            vec![44_u8; 32],
            1,
            vec![45_u8; 128],
            vec![MlsWelcomeRecord {
                device_id: outsider_device,
                key_package_reference: package_reference,
                payload: vec![46_u8; 128],
            }],
        )
        .await?;
    let initial_inbox = repository.mls_inbox(outsider.id, outsider_device).await?;
    assert_eq!(initial_inbox.len(), 1);
    assert_eq!(initial_inbox[0].kind, MlsDeliveryRecordKind::Welcome);
    repository
        .acknowledge_mls_delivery(
            outsider.id,
            outsider_device,
            &initial_inbox[0].group_id,
            initial_inbox[0].epoch,
            initial_inbox[0].sequence,
        )
        .await?;
    let second_owner_device = Uuid::now_v7();
    let second_package_reference = [50_u8; 32];
    repository
        .register_device_identity(
            owner.id,
            second_owner_device,
            [51_u8; 32],
            Some("Owner laptop".into()),
        )
        .await?;
    repository
        .publish_mls_key_packages(
            owner.id,
            second_owner_device,
            vec![(second_package_reference, vec![52_u8; 128], 1)],
        )
        .await?;
    let claimed_update = repository
        .claim_mls_key_packages(owner.id, owner_device, direct.id)
        .await?;
    assert_eq!(claimed_update.len(), 1);
    assert_eq!(claimed_update[0].device_id, second_owner_device);
    repository
        .update_mls_group(
            owner.id,
            owner_device,
            direct.id,
            vec![44_u8; 32],
            2,
            vec![53_u8; 128],
            vec![MlsWelcomeRecord {
                device_id: second_owner_device,
                key_package_reference: second_package_reference,
                payload: vec![54_u8; 128],
            }],
            Vec::new(),
        )
        .await?;
    let existing_device_update = repository.mls_inbox(outsider.id, outsider_device).await?;
    assert_eq!(existing_device_update.len(), 1);
    assert_eq!(
        existing_device_update[0].kind,
        MlsDeliveryRecordKind::Commit
    );
    let new_device_update = repository.mls_inbox(owner.id, second_owner_device).await?;
    assert_eq!(new_device_update.len(), 1);
    assert_eq!(new_device_update[0].kind, MlsDeliveryRecordKind::Welcome);
    assert_eq!(
        repository
            .revoke_device_identity(owner.id, second_owner_device)
            .await?,
        vec![direct.id]
    );
    assert_eq!(
        repository
            .pending_mls_removals(owner.id, owner_device)
            .await?,
        vec![(direct.id, vec![second_owner_device])]
    );
    repository
        .update_mls_group(
            owner.id,
            owner_device,
            direct.id,
            vec![44_u8; 32],
            3,
            vec![55_u8; 128],
            Vec::new(),
            vec![second_owner_device],
        )
        .await?;
    assert!(
        repository
            .pending_mls_removals(owner.id, owner_device)
            .await?
            .is_empty()
    );
    assert!(matches!(
        repository.mls_inbox(owner.id, second_owner_device).await,
        Err(RepositoryError::Forbidden)
    ));
    let direct_message = repository
        .create_encrypted_message(
            owner.id,
            direct.id,
            NewMessageEncryption {
                ciphertext: vec![47_u8; 128],
                franking_commitment: [48_u8; 32],
                franking_tag: [0_u8; 32],
                sender_device_id: owner_device,
            },
            [49_u8; 32],
            None,
            "durable-private-message".into(),
            &[],
            3,
        )
        .await?;
    repository
        .acknowledge_read_state(outsider.id, direct.id, direct_message.message.id)
        .await?;
    drop(repository);

    let (reopened, resumed_sequence) = Repository::connect_postgres(&database_url, 4).await?;
    assert_eq!(resumed_sequence, 4);
    let reopened_reports = reopened
        .operator_reports(Some(OperatorReportStatus::Actioned), 10)
        .await?;
    assert_eq!(reopened_reports.len(), 1);
    assert_eq!(reopened_reports[0].id, report_receipt.id);
    let messages = reopened
        .list_messages(
            owner.id,
            text_channel.id,
            MessageWindow {
                limit: 100,
                ..MessageWindow::default()
            },
        )
        .await?;
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().any(|message| {
        message.content == "durably edited"
            && message.reactions.len() == 1
            && message.reactions[0].emoji == "👍"
            && message.reactions[0].me
    }));
    assert!(
        messages
            .iter()
            .any(|message| message.attachments == vec![completed_attachment.clone()])
    );
    assert_eq!(reopened.list_guilds(outsider.id).await?.len(), 1);
    let reopened_direct = reopened.list_direct_channels(owner.id).await?;
    assert_eq!(reopened_direct.len(), 1);
    assert_eq!(reopened_direct[0].id, direct.id);
    let reopened_private = &reopened
        .list_messages(
            outsider.id,
            direct.id,
            MessageWindow {
                limit: 100,
                ..MessageWindow::default()
            },
        )
        .await?[0];
    assert!(reopened_private.content.is_empty());
    assert!(reopened_private.encryption.is_some());
    let outsider_snapshot = reopened.snapshot(outsider.id, 0).await?;
    assert!(
        outsider_snapshot
            .read_states
            .iter()
            .any(|state| state.channel_id == direct.id
                && state.last_message_id == Some(direct_message.message.id))
    );
    let reopened_member = reopened
        .list_members(owner.id, created.guild.id, 100)
        .await?
        .into_iter()
        .find(|member| member.user.id == outsider.id)
        .expect("outsider remains a member");
    assert!(reopened_member.timeout_until.is_some());
    assert!(
        reopened
            .active_automod_rules(created.guild.id)
            .await?
            .iter()
            .any(|rule| rule.id == automod_rule.id)
    );
    let safety_audit = reopened
        .list_audit_log(owner.id, created.guild.id, None, 100)
        .await?;
    assert!(safety_audit.iter().any(|entry| entry.action_type == 50));
    assert!(safety_audit.iter().any(|entry| {
        entry.action_type == 62
            && entry.reason.as_deref() == Some("Credentials must remain private.")
    }));
    assert!(matches!(
        reopened.voice_access(outsider.id, voice_channel.id).await,
        Err(RepositoryError::NotFound("channel"))
    ));
    assert!(matches!(
        reopened
            .create_message(
                outsider.id,
                text_channel.id,
                "timeout must persist".into(),
                None,
                "timeout-persistence".into(),
                &[],
                3,
            )
            .await,
        Err(RepositoryError::NotFound("channel"))
    ));
    let bans = reopened.list_bans(owner.id, created.guild.id).await?;
    assert!(bans.iter().any(|ban| ban.user.id == blocked.id));
    assert!(matches!(
        reopened.accept_invite(blocked.id, &invite_hash).await,
        Err(RepositoryError::Forbidden)
    ));
    reopened
        .timeout_member(owner.id, created.guild.id, outsider.id, None, None)
        .await?;
    assert!(
        reopened
            .voice_access(outsider.id, voice_channel.id)
            .await?
            .permissions
            .contains(GuildPermissions::CONNECT | GuildPermissions::SPEAK)
    );
    reopened
        .create_message(
            outsider.id,
            text_channel.id,
            "restored after timeout".into(),
            None,
            "restored-after-timeout".into(),
            &[],
            5,
        )
        .await?;
    reopened
        .update_relationship(outsider.id, owner.id, RelationshipAction::Block)
        .await?;
    assert!(matches!(
        reopened
            .create_message(
                owner.id,
                direct.id,
                "blocked send".into(),
                None,
                "blocked-send".into(),
                &[],
                6,
            )
            .await,
        Err(RepositoryError::Forbidden)
    ));
    assert_eq!(
        reopened
            .list_messages(
                owner.id,
                direct.id,
                MessageWindow {
                    limit: 100,
                    ..MessageWindow::default()
                },
            )
            .await?
            .len(),
        1
    );
    reopened
        .unban_member(owner.id, created.guild.id, blocked.id, None)
        .await?;
    reopened.accept_invite(blocked.id, &invite_hash).await?;
    assert!(
        reopened
            .list_roles(owner.id, created.guild.id)
            .await?
            .iter()
            .any(|role| role.id == delegated.id && role.name == "Community steward")
    );
    assert!(
        reopened
            .list_members(owner.id, created.guild.id, 100)
            .await?
            .iter()
            .find(|member| member.user.id == outsider.id)
            .is_some_and(|member| member.roles.contains(&delegated.id))
    );
    let reopened_snapshot = reopened
        .snapshot(owner.id, resumed_sequence.saturating_sub(1))
        .await?;
    assert!(
        reopened_snapshot
            .channels
            .iter()
            .any(|channel| channel.id == text_channel.id)
    );
    assert!(reopened_snapshot.messages.iter().any(|message| {
        message
            .attachments
            .iter()
            .any(|attachment| attachment.id == attachment_id)
    }));
    let attachment_delete_started_at = Utc::now();
    reopened
        .delete_message(owner.id, text_channel.id, attachment_message.message.id)
        .await?;
    let detached_attachment = reopened.attachment_record(attachment_id).await?;
    assert_eq!(detached_attachment.message_id, None);
    assert!(
        detached_attachment.expires_at >= attachment_delete_started_at + chrono::Duration::days(6)
    );
    reopened
        .set_channel_overwrite(
            owner.id,
            delegated_channel.id,
            OverwriteTargetKind::Role,
            delegated.id.raw(),
            GuildPermissions::SEND_MESSAGES,
            GuildPermissions::empty(),
        )
        .await?;
    reopened
        .delete_role(owner.id, created.guild.id, delegated.id)
        .await?;
    assert!(
        !reopened
            .list_roles(owner.id, created.guild.id)
            .await?
            .iter()
            .any(|role| role.id == delegated.id)
    );
    let stale_role_overwrites: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_overwrites
         WHERE target_type = 0 AND target_id = $1",
    )
    .bind(i64::try_from(delegated.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert_eq!(stale_role_overwrites, 0);
    let role_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
         WHERE guild_id = $1 AND action_type BETWEEN 20 AND 24",
    )
    .bind(i64::try_from(created.guild.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert_eq!(role_audits, 6);
    reopened
        .update_automod_rule(
            owner.id,
            created.guild.id,
            automod_rule.id,
            UpdateAutomodRule {
                enabled: Some(false),
                ..UpdateAutomodRule::default()
            },
        )
        .await?;
    assert!(
        reopened
            .active_automod_rules(created.guild.id)
            .await?
            .is_empty()
    );
    reopened
        .delete_automod_rule(owner.id, created.guild.id, automod_rule.id)
        .await?;

    let lifecycle_owner = user("lifecycle-owner", "Lifecycle Owner");
    let lifecycle_member = user("lifecycle-member", "Lifecycle Member");
    reopened
        .ensure_user(
            lifecycle_owner.clone(),
            Some("lifecycle-owner@example.test"),
        )
        .await?;
    reopened
        .ensure_user(
            lifecycle_member.clone(),
            Some("lifecycle-member@example.test"),
        )
        .await?;
    let lifecycle_guild = reopened
        .create_guild(lifecycle_owner.id, "Ownership Lifecycle".into(), 0x69D7BD)
        .await?;
    let lifecycle_invite_hash = vec![92_u8; 32];
    reopened
        .create_invite(
            lifecycle_owner.id,
            lifecycle_guild.guild.id,
            "postgres-owner-lifecycle".into(),
            &lifecycle_invite_hash,
            Some(1),
            None,
        )
        .await?;
    reopened
        .accept_invite(lifecycle_member.id, &lifecycle_invite_hash)
        .await?;
    let blockers = reopened
        .prepare_account_deletion(lifecycle_owner.id, Utc::now())
        .await?;
    assert_eq!(blockers.len(), 1);
    assert_eq!(blockers[0].member_count, 2);
    reopened
        .transfer_guild_ownership(
            lifecycle_owner.id,
            lifecycle_guild.guild.id,
            lifecycle_member.id,
        )
        .await?;
    assert!(reopened.owned_guilds(lifecycle_owner.id).await?.is_empty());
    let deleted_lifecycle = reopened
        .delete_guild(
            lifecycle_member.id,
            lifecycle_guild.guild.id,
            &lifecycle_guild.guild.name,
            Utc::now(),
        )
        .await?;
    assert_eq!(deleted_lifecycle.member_ids.len(), 2);
    assert_eq!(deleted_lifecycle.voice_channel_ids.len(), 1);
    assert!(
        reopened
            .list_guilds(lifecycle_member.id)
            .await?
            .iter()
            .all(|guild| guild.id != lifecycle_guild.guild.id)
    );
    let ownership_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
         WHERE guild_id = $1 AND action_type IN (70, 71)",
    )
    .bind(i64::try_from(lifecycle_guild.guild.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert_eq!(ownership_audits, 2);

    let erasure_user = user("erase-me", "Erase Me");
    reopened
        .ensure_user(erasure_user.clone(), Some("erase-me@example.test"))
        .await?;
    reopened
        .request_relationship(erasure_user.id, &owner.handle)
        .await?;
    let erasure_guild = reopened
        .create_guild(erasure_user.id, "Erasure Archive".into(), 0x8B7CFF)
        .await?;
    let erasure_channel = erasure_guild
        .channels
        .iter()
        .find(|channel| channel.kind == ChannelKind::Text)
        .expect("default erasure text channel");
    reopened
        .create_message(
            erasure_user.id,
            erasure_channel.id,
            "shared history survives anonymization".into(),
            None,
            "erasure-history".into(),
            &[],
            99,
        )
        .await?;
    let erasure_device = Uuid::now_v7();
    reopened
        .register_device_identity(
            erasure_user.id,
            erasure_device,
            [91_u8; 32],
            Some("Erasure device".into()),
        )
        .await?;
    let export = reopened.account_data_export(erasure_user.id).await?;
    assert_eq!(export.messages.len(), 1);
    assert_eq!(export.relationships.len(), 1);
    assert_eq!(export.devices.len(), 1);

    assert!(
        reopened
            .prepare_account_deletion(erasure_user.id, Utc::now())
            .await?
            .is_empty()
    );
    reopened.anonymize_user(erasure_user.id, Utc::now()).await?;
    reopened.anonymize_user(erasure_user.id, Utc::now()).await?;
    let anonymized: (String, Option<String>, Option<String>, bool) = sqlx::query_as(
        "SELECT username, display_name, email, deleted_at IS NOT NULL
           FROM users WHERE id = $1",
    )
    .bind(i64::try_from(erasure_user.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert!(anonymized.0.starts_with("deleted-"));
    assert!(
        anonymized
            .1
            .as_deref()
            .is_some_and(|name| name.starts_with("Deleted User #"))
    );
    assert!(anonymized.2.is_none());
    assert!(anonymized.3);
    let retained_messages: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE author_id = $1")
            .bind(i64::try_from(erasure_user.id.raw())?)
            .fetch_one(&audit_pool)
            .await?;
    assert_eq!(retained_messages, 1);
    let retained_owner_membership: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM guild_members
            WHERE guild_id = $1 AND user_id = $2
         )",
    )
    .bind(i64::try_from(erasure_guild.guild.id.raw())?)
    .bind(i64::try_from(erasure_user.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert!(!retained_owner_membership);
    let retired_server: (bool, bool) = sqlx::query_as(
        "SELECT g.deleted_at IS NOT NULL,
                bool_and(c.deleted_at IS NOT NULL)
           FROM guilds g
           JOIN channels c ON c.guild_id = g.id
          WHERE g.id = $1
          GROUP BY g.id",
    )
    .bind(i64::try_from(erasure_guild.guild.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert!(retired_server.0);
    assert!(retired_server.1);
    let relationships: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_relationships
          WHERE user_id = $1 OR target_id = $1",
    )
    .bind(i64::try_from(erasure_user.id.raw())?)
    .fetch_one(&audit_pool)
    .await?;
    assert_eq!(relationships, 0);
    let device: (Option<String>, bool) = sqlx::query_as(
        "SELECT name, revoked_at IS NOT NULL
           FROM device_identities WHERE device_id = $1",
    )
    .bind(erasure_device)
    .fetch_one(&audit_pool)
    .await?;
    assert!(device.0.is_none());
    assert!(device.1);

    drop(reopened);
    audit_pool.close().await;
    postgres.stop_db().await?;
    Ok(())
}

fn user(handle: &str, display_name: &str) -> User {
    User {
        id: UserId::new(),
        handle: handle.into(),
        display_name: display_name.into(),
        avatar_url: None,
        created_at: Utc::now(),
    }
}

fn available_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr().map(|address| address.port())
}
