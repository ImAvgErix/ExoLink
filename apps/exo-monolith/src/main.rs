use std::net::SocketAddr;

use anyhow::Context;
use axum::http::HeaderValue;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use exo_monolith::{
    AppState, OperatorInfo, VoiceConfig,
    apple::AppleConfig,
    auth::{AuthService, EmailDelivery},
    build_router_with_allowed_origins,
    media::{AttachmentService, R2Config},
    repository::Repository,
};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let environment = std::env::var("EXOCORD_ENV").unwrap_or_else(|_| "development".into());
    let is_production = environment.eq_ignore_ascii_case("production");

    let bind = std::env::var("EXOCORD_BIND").unwrap_or_else(|_| "127.0.0.1:4100".into());
    let address: SocketAddr = bind
        .parse()
        .context("EXOCORD_BIND must be a socket address")?;
    let state_directory = std::env::var("EXOCORD_STATE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(".exocord"));
    std::fs::create_dir_all(&state_directory)?;
    let delivery = match (
        secret_environment("EXOCORD_RESEND_API_KEY")?,
        nonempty_environment("EXOCORD_EMAIL_FROM"),
    ) {
        (Some(api_key), Some(from)) => EmailDelivery::Resend { api_key, from },
        (None, None) if !is_production => EmailDelivery::DevelopmentConsole,
        (None, None) => EmailDelivery::Disabled,
        _ => anyhow::bail!("EXOCORD_RESEND_API_KEY and EXOCORD_EMAIL_FROM must be set together"),
    };
    let apple = apple_config_from_environment()?;
    let operator = operator_info_from_environment(is_production)?;
    let operator_token = match secret_environment("EXOCORD_OPERATOR_TOKEN")? {
        Some(value) => {
            validate_operator_token(&value)?;
            Some(value)
        }
        None if is_production => {
            anyhow::bail!("EXOCORD_OPERATOR_TOKEN is required in production")
        }
        None => None,
    };
    let voice = voice_config_from_environment(is_production)?;
    let attachments =
        attachment_service_from_environment(is_production, address, &state_directory)?;
    let franking_key = match secret_environment("EXOCORD_FRANKING_KEY")? {
        Some(value) => decode_secret("EXOCORD_FRANKING_KEY", &value)?,
        None if is_production => {
            anyhow::bail!("EXOCORD_FRANKING_KEY is required in production")
        }
        None => load_or_create_secret(&state_directory.join("message-franking-key"))?,
    };
    let cleanup_attachments = attachments.clone();
    let auth = AuthService::open(state_directory.join("auth.sqlite3"), delivery, apple)?;
    let allow_development_auth = !is_production
        && std::env::var("EXOCORD_ALLOW_DEV_AUTH").map_or(true, |value| value != "0");
    let trust_proxy_headers =
        std::env::var("EXOCORD_TRUST_PROXY_HEADERS").is_ok_and(|value| value == "1");
    let database_url = database_url_from_environment()?;
    let state = if let Some(database_url) = database_url {
        let max_connections = std::env::var("EXOCORD_DATABASE_MAX_CONNECTIONS")
            .map_or(Ok(20), |value| value.parse::<u32>())
            .context("EXOCORD_DATABASE_MAX_CONNECTIONS must be a positive integer")?;
        if max_connections == 0 {
            anyhow::bail!("EXOCORD_DATABASE_MAX_CONNECTIONS must be greater than zero");
        }
        let (repository, next_sequence) =
            Repository::connect_postgres(&database_url, max_connections)
                .await
                .context("PostgreSQL initialization failed")?;
        tracing::info!(
            storage = repository.storage_name(),
            "durable repository ready"
        );
        AppState::with_repository(auth, allow_development_auth, repository, next_sequence)
    } else {
        if is_production {
            anyhow::bail!(
                "PostgreSQL configuration is required in production; set EXOCORD_DATABASE_URL \
                 or the EXOCORD_DATABASE_HOST/USER/NAME/PASSWORD values"
            );
        }
        tracing::warn!("using the in-memory development repository");
        AppState::seeded_with_auth(auth, allow_development_auth)
    }
    .with_voice_config(voice)
    .with_attachment_service(attachments)
    .with_franking_key(franking_key)
    .with_operator_info(operator)
    .with_trusted_proxy_headers(trust_proxy_headers);
    let state = if let Some(token) = operator_token.as_deref() {
        state.with_operator_token(token)
    } else {
        state
    };
    drop(operator_token);
    let cleanup_repository = state.repository_handle();
    let cleanup_task = cleanup_attachments.available().then(|| {
        tokio::spawn(run_attachment_cleanup(
            cleanup_repository,
            cleanup_attachments,
        ))
    });
    let account_cleanup_task = tokio::spawn(run_account_deletion_cleanup(state.clone()));
    let app =
        build_router_with_allowed_origins(state, cors_origins_from_environment(is_production)?);
    let listener = tokio::net::TcpListener::bind(address).await?;

    tracing::info!(%address, "Exocord monolith listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    if let Some(cleanup_task) = cleanup_task {
        cleanup_task.abort();
    }
    account_cleanup_task.abort();
    Ok(())
}

async fn run_account_deletion_cleanup(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match state
            .finalize_due_account_deletions(chrono::Utc::now(), 100)
            .await
        {
            Ok(finalized) if finalized > 0 => {
                tracing::info!(finalized, "due account deletions anonymized");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "account deletion cleanup pass failed");
            }
        }
    }
}

async fn run_attachment_cleanup(repository: Repository, attachments: AttachmentService) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match repository
            .cleanup_expired_attachments(&attachments, chrono::Utc::now(), 100)
            .await
        {
            Ok(cleanup) if cleanup.reservations > 0 || cleanup.objects > 0 => {
                tracing::info!(
                    reservations = cleanup.reservations,
                    objects = cleanup.objects,
                    "expired attachment uploads cleaned"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "attachment cleanup pass failed");
            }
        }
    }
}

fn attachment_service_from_environment(
    is_production: bool,
    address: SocketAddr,
    state_directory: &std::path::Path,
) -> anyhow::Result<AttachmentService> {
    let storage =
        nonempty_environment("EXOCORD_ATTACHMENT_STORAGE").map(|value| value.to_ascii_lowercase());
    let storage = match storage.as_deref() {
        Some("local") => "local",
        Some("r2") => "r2",
        Some(_) => anyhow::bail!("EXOCORD_ATTACHMENT_STORAGE must be local or r2"),
        None if is_production => {
            anyhow::bail!("EXOCORD_ATTACHMENT_STORAGE is required in production")
        }
        None => "local",
    };
    match storage {
        "local" => {
            for r2_name in [
                "EXOCORD_R2_ENDPOINT",
                "EXOCORD_R2_BUCKET",
                "EXOCORD_R2_ACCESS_KEY_ID",
                "EXOCORD_R2_SECRET_ACCESS_KEY",
                "EXOCORD_CDN_URL",
            ] {
                if environment_source_present(r2_name) {
                    anyhow::bail!("{r2_name} cannot be set when EXOCORD_ATTACHMENT_STORAGE=local");
                }
            }
            let capability_key = match secret_environment("EXOCORD_ATTACHMENT_CAPABILITY_KEY")? {
                Some(value) => decode_secret("EXOCORD_ATTACHMENT_CAPABILITY_KEY", &value)?,
                None if is_production => anyhow::bail!(
                    "EXOCORD_ATTACHMENT_CAPABILITY_KEY is required for local production storage"
                ),
                None => load_or_create_secret(&state_directory.join("attachment-capability-key"))?,
            };
            let object_key = match secret_environment("EXOCORD_ATTACHMENT_OBJECT_KEY")? {
                Some(value) => decode_secret("EXOCORD_ATTACHMENT_OBJECT_KEY", &value)?,
                None if is_production => anyhow::bail!(
                    "EXOCORD_ATTACHMENT_OBJECT_KEY is required for local production storage"
                ),
                None => load_or_create_secret(&state_directory.join("attachment-object-key"))?,
            };
            let public_api_url = match nonempty_environment("EXOCORD_PUBLIC_API_URL") {
                Some(value) => validate_public_api_url(&value, is_production)?,
                None if is_production => {
                    anyhow::bail!("EXOCORD_PUBLIC_API_URL is required for local production storage")
                }
                None => format!("http://{address}"),
            };
            let default_max_storage_bytes = if is_production {
                5 * 1024 * 1024 * 1024
            } else {
                u64::MAX
            };
            let max_storage_bytes = nonempty_environment("EXOCORD_ATTACHMENT_MAX_STORAGE_BYTES")
                .map_or(Ok(default_max_storage_bytes), |value| value.parse::<u64>())
                .context("EXOCORD_ATTACHMENT_MAX_STORAGE_BYTES must be a positive integer")?;
            if max_storage_bytes == 0 {
                anyhow::bail!("EXOCORD_ATTACHMENT_MAX_STORAGE_BYTES must be greater than zero");
            }
            AttachmentService::local_with_limit(
                state_directory.join("attachments"),
                public_api_url,
                capability_key,
                object_key,
                max_storage_bytes,
            )
            .map_err(Into::into)
        }
        "r2" => {
            let endpoint = nonempty_environment("EXOCORD_R2_ENDPOINT");
            let bucket = nonempty_environment("EXOCORD_R2_BUCKET");
            let access_key_id = secret_environment("EXOCORD_R2_ACCESS_KEY_ID")?;
            let secret_access_key = secret_environment("EXOCORD_R2_SECRET_ACCESS_KEY")?;
            let cdn_url = nonempty_environment("EXOCORD_CDN_URL");
            let object_key = secret_environment("EXOCORD_ATTACHMENT_OBJECT_KEY")?;
            let (
                Some(endpoint),
                Some(bucket),
                Some(access_key_id),
                Some(secret_access_key),
                Some(cdn_url),
                Some(object_key),
            ) = (
                endpoint,
                bucket,
                access_key_id,
                secret_access_key,
                cdn_url,
                object_key,
            )
            else {
                anyhow::bail!(
                    "R2 storage requires EXOCORD_R2_ENDPOINT, EXOCORD_R2_BUCKET, \
                     EXOCORD_R2_ACCESS_KEY_ID, EXOCORD_R2_SECRET_ACCESS_KEY, \
                     EXOCORD_CDN_URL, and EXOCORD_ATTACHMENT_OBJECT_KEY"
                );
            };
            let endpoint = url::Url::parse(&endpoint).context("EXOCORD_R2_ENDPOINT is invalid")?;
            if endpoint.scheme() != "https" {
                anyhow::bail!("EXOCORD_R2_ENDPOINT must use HTTPS");
            }
            let cdn = url::Url::parse(&cdn_url).context("EXOCORD_CDN_URL is invalid")?;
            if cdn.scheme() != "https" {
                anyhow::bail!("EXOCORD_CDN_URL must use HTTPS");
            }
            AttachmentService::r2(
                R2Config {
                    endpoint,
                    bucket,
                    access_key_id,
                    secret_access_key,
                    cdn_url,
                },
                decode_secret("EXOCORD_ATTACHMENT_OBJECT_KEY", &object_key)?,
            )
            .map_err(Into::into)
        }
        _ => anyhow::bail!("the attachment storage mode is invalid"),
    }
}

fn load_or_create_secret(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(value) => value
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} must contain exactly 32 bytes", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut value = [0_u8; 32];
            getrandom::fill(&mut value).context("could not generate an attachment secret")?;
            std::fs::write(path, value)
                .with_context(|| format!("could not persist {}", path.display()))?;
            Ok(value)
        }
        Err(error) => Err(error)
            .with_context(|| format!("could not read attachment secret at {}", path.display())),
    }
}

fn decode_secret(name: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("{name} must be unpadded base64url"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to 32 bytes"))
}

fn validate_operator_token(value: &str) -> anyhow::Result<()> {
    let encoded = value
        .strip_prefix("exo_op_")
        .context("EXOCORD_OPERATOR_TOKEN must begin with exo_op_")?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .context("EXOCORD_OPERATOR_TOKEN must contain unpadded base64url")?
        .try_into()
        .map(|_: [u8; 32]| ())
        .map_err(|_| anyhow::anyhow!("EXOCORD_OPERATOR_TOKEN must encode exactly 32 random bytes"))
}

fn voice_config_from_environment(is_production: bool) -> anyhow::Result<Option<VoiceConfig>> {
    let values = (
        nonempty_environment("EXOCORD_LIVEKIT_URL"),
        secret_environment("EXOCORD_LIVEKIT_API_KEY")?,
        secret_environment("EXOCORD_LIVEKIT_API_SECRET")?,
    );
    match values {
        (Some(url), Some(api_key), Some(api_secret)) => VoiceConfig::new(url, api_key, api_secret)
            .map(Some)
            .map_err(anyhow::Error::msg),
        (None, None, None) if !is_production => Ok(Some(VoiceConfig::development())),
        (None, None, None) => anyhow::bail!(
            "EXOCORD_LIVEKIT_URL, EXOCORD_LIVEKIT_API_KEY, and \
             EXOCORD_LIVEKIT_API_SECRET are required in production"
        ),
        _ => anyhow::bail!(
            "EXOCORD_LIVEKIT_URL, EXOCORD_LIVEKIT_API_KEY, and \
             EXOCORD_LIVEKIT_API_SECRET must be set together"
        ),
    }
}

fn nonempty_environment(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn environment_source_present(name: &str) -> bool {
    nonempty_environment(name).is_some() || nonempty_environment(&format!("{name}_FILE")).is_some()
}

fn validate_public_api_url(value: &str, is_production: bool) -> anyhow::Result<String> {
    let parsed = url::Url::parse(value).context("EXOCORD_PUBLIC_API_URL must be a valid URL")?;
    let loopback = parsed.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host == "127.0.0.1"
            || host == "::1"
            || host == "[::1]"
    });
    let accepted_scheme =
        parsed.scheme() == "https" || (!is_production && parsed.scheme() == "http" && loopback);
    if !accepted_scheme
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        anyhow::bail!(
            "EXOCORD_PUBLIC_API_URL must be a credential-free HTTPS origin with no path, query, \
             or fragment; development additionally permits HTTP loopback"
        );
    }
    Ok(parsed.origin().ascii_serialization())
}

fn secret_environment(name: &str) -> anyhow::Result<Option<String>> {
    let direct = nonempty_environment(name);
    let file_name = format!("{name}_FILE");
    let file = nonempty_environment(&file_name);
    match (direct, file) {
        (Some(_), Some(_)) => {
            anyhow::bail!("{name} and {file_name} are mutually exclusive")
        }
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let value = std::fs::read_to_string(&path)
                .with_context(|| format!("could not read {file_name} at {path}"))?;
            let value = value.trim().to_owned();
            if value.is_empty() {
                anyhow::bail!("{file_name} points to an empty secret file");
            }
            Ok(Some(value))
        }
        (None, None) => Ok(None),
    }
}

fn database_url_from_environment() -> anyhow::Result<Option<String>> {
    let direct = secret_environment("EXOCORD_DATABASE_URL")?;
    let host = nonempty_environment("EXOCORD_DATABASE_HOST");
    let port = nonempty_environment("EXOCORD_DATABASE_PORT");
    let user = nonempty_environment("EXOCORD_DATABASE_USER");
    let name = nonempty_environment("EXOCORD_DATABASE_NAME");
    let password = secret_environment("EXOCORD_DATABASE_PASSWORD")?;
    let has_components =
        host.is_some() || port.is_some() || user.is_some() || name.is_some() || password.is_some();
    if direct.is_some() && has_components {
        anyhow::bail!(
            "EXOCORD_DATABASE_URL cannot be combined with EXOCORD_DATABASE_HOST/PORT/USER/NAME/PASSWORD"
        );
    }
    if let Some(direct) = direct {
        return Ok(Some(direct));
    }
    if !has_components {
        return Ok(None);
    }
    let (Some(host), Some(user), Some(name), Some(password)) = (host, user, name, password) else {
        anyhow::bail!(
            "EXOCORD_DATABASE_HOST, EXOCORD_DATABASE_USER, EXOCORD_DATABASE_NAME, and \
             EXOCORD_DATABASE_PASSWORD (or its _FILE form) must be set together"
        );
    };
    let port = port
        .map_or(Ok(5432_u16), |value| value.parse::<u16>())
        .context("EXOCORD_DATABASE_PORT must be a valid TCP port")?;
    if port == 0 {
        anyhow::bail!("EXOCORD_DATABASE_PORT must be greater than zero");
    }
    build_database_url(&host, port, &user, &name, &password).map(Some)
}

fn build_database_url(
    host: &str,
    port: u16,
    user: &str,
    name: &str,
    password: &str,
) -> anyhow::Result<String> {
    if name
        .chars()
        .any(|character| !character.is_ascii_alphanumeric() && !matches!(character, '_' | '-'))
    {
        anyhow::bail!(
            "EXOCORD_DATABASE_NAME may contain only ASCII letters, digits, underscores, and hyphens"
        );
    }
    let mut url = url::Url::parse("postgres://localhost/exocord")
        .context("the built-in database URL template is invalid")?;
    url.set_host(Some(host))
        .context("EXOCORD_DATABASE_HOST is invalid")?;
    url.set_port(Some(port))
        .map_err(|()| anyhow::anyhow!("EXOCORD_DATABASE_PORT is invalid"))?;
    url.set_username(user)
        .map_err(|()| anyhow::anyhow!("EXOCORD_DATABASE_USER is invalid"))?;
    url.set_password(Some(password))
        .map_err(|()| anyhow::anyhow!("EXOCORD_DATABASE_PASSWORD is invalid"))?;
    url.set_path(name);
    Ok(url.into())
}

fn apple_config_from_environment() -> anyhow::Result<Option<AppleConfig>> {
    let values = (
        nonempty_environment("EXOCORD_APPLE_CLIENT_ID"),
        nonempty_environment("EXOCORD_APPLE_TEAM_ID"),
        nonempty_environment("EXOCORD_APPLE_KEY_ID"),
        nonempty_environment("EXOCORD_APPLE_PRIVATE_KEY_FILE"),
        nonempty_environment("EXOCORD_APPLE_REDIRECT_URI"),
        secret_environment("EXOCORD_PROVIDER_TOKEN_KEY")?,
    );
    let (client_id, team_id, key_id, private_key_file, redirect_uri, provider_key) = match values {
        (None, None, None, None, None, None) => return Ok(None),
        (
            Some(client_id),
            Some(team_id),
            Some(key_id),
            Some(private_key_file),
            Some(redirect_uri),
            Some(provider_key),
        ) => (
            client_id,
            team_id,
            key_id,
            private_key_file,
            redirect_uri,
            provider_key,
        ),
        _ => anyhow::bail!(
            "EXOCORD_APPLE_CLIENT_ID, EXOCORD_APPLE_TEAM_ID, EXOCORD_APPLE_KEY_ID, \
             EXOCORD_APPLE_PRIVATE_KEY_FILE, EXOCORD_APPLE_REDIRECT_URI, and \
             EXOCORD_PROVIDER_TOKEN_KEY must be set together"
        ),
    };
    let private_key_pem = std::fs::read_to_string(&private_key_file)
        .with_context(|| format!("could not read Apple private key at {private_key_file}"))?;
    let key = URL_SAFE_NO_PAD
        .decode(provider_key)
        .context("EXOCORD_PROVIDER_TOKEN_KEY must be unpadded base64url")?;
    let provider_token_key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("EXOCORD_PROVIDER_TOKEN_KEY must decode to 32 bytes"))?;
    Ok(Some(AppleConfig::production(
        client_id,
        team_id,
        key_id,
        private_key_pem,
        redirect_uri,
        provider_token_key,
    )))
}

fn operator_info_from_environment(is_production: bool) -> anyhow::Result<OperatorInfo> {
    let name = nonempty_environment("EXOCORD_OPERATOR_NAME");
    let privacy_url = nonempty_environment("EXOCORD_PRIVACY_URL");
    let terms_url = nonempty_environment("EXOCORD_TERMS_URL");
    let abuse_email = nonempty_environment("EXOCORD_ABUSE_EMAIL");
    let support_email = nonempty_environment("EXOCORD_SUPPORT_EMAIL");

    if is_production && (name.is_none() || privacy_url.is_none() || abuse_email.is_none()) {
        anyhow::bail!(
            "EXOCORD_OPERATOR_NAME, EXOCORD_PRIVACY_URL, and EXOCORD_ABUSE_EMAIL are required in production"
        );
    }
    if !is_production
        && name.is_none()
        && privacy_url.is_none()
        && terms_url.is_none()
        && abuse_email.is_none()
        && support_email.is_none()
    {
        return Ok(OperatorInfo::development());
    }

    let name = name.unwrap_or_else(|| "Exocord".to_owned());
    if name.chars().count() > 100 || name.chars().any(char::is_control) {
        anyhow::bail!("EXOCORD_OPERATOR_NAME must be at most 100 characters with no controls");
    }
    let privacy_url = privacy_url
        .map(|value| validate_public_https_url("EXOCORD_PRIVACY_URL", &value))
        .transpose()?;
    let terms_url = terms_url
        .map(|value| validate_public_https_url("EXOCORD_TERMS_URL", &value))
        .transpose()?;
    let abuse_email = abuse_email
        .map(|value| validate_public_email("EXOCORD_ABUSE_EMAIL", &value))
        .transpose()?;
    let support_email = support_email
        .map(|value| validate_public_email("EXOCORD_SUPPORT_EMAIL", &value))
        .transpose()?
        .or_else(|| abuse_email.clone());

    Ok(OperatorInfo {
        name,
        privacy_url,
        terms_url,
        support_email,
        abuse_email,
    })
}

fn validate_public_https_url(name: &str, value: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(value).with_context(|| format!("{name} must be a valid URL"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("{name} must be a credential-free HTTPS URL without a query or fragment");
    }
    Ok(parsed.into())
}

fn validate_public_email(name: &str, value: &str) -> anyhow::Result<String> {
    if value.len() > 254
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.matches('@').count() != 1
    {
        anyhow::bail!("{name} must be one public email address");
    }
    let Some((local, domain)) = value.split_once('@') else {
        anyhow::bail!("{name} must be one public email address");
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        anyhow::bail!("{name} must be one public email address");
    }
    Ok(value.to_owned())
}

fn cors_origins_from_environment(is_production: bool) -> anyhow::Result<Option<Vec<HeaderValue>>> {
    let configured = nonempty_environment("EXOCORD_ALLOWED_ORIGINS");
    if configured.is_none() && !is_production {
        return Ok(None);
    }
    let configured = configured.unwrap_or_else(|| "http://tauri.localhost".into());
    parse_cors_origins(&configured).map(Some)
}

fn parse_cors_origins(configured: &str) -> anyhow::Result<Vec<HeaderValue>> {
    let mut normalized = std::collections::BTreeSet::new();
    for raw in configured.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            anyhow::bail!("EXOCORD_ALLOWED_ORIGINS contains an empty origin");
        }
        let parsed = url::Url::parse(raw)
            .with_context(|| format!("EXOCORD_ALLOWED_ORIGINS contains an invalid URL: {raw}"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            anyhow::bail!(
                "EXOCORD_ALLOWED_ORIGINS values must be HTTP(S) origins without credentials, \
                 paths, queries, or fragments: {raw}"
            );
        }
        normalized.insert(parsed.origin().ascii_serialization());
    }
    if normalized.is_empty() {
        anyhow::bail!("EXOCORD_ALLOWED_ORIGINS must contain at least one origin");
    }
    normalized
        .into_iter()
        .map(|origin| {
            HeaderValue::from_str(&origin)
                .with_context(|| format!("invalid CORS origin header: {origin}"))
        })
        .collect()
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("EXOCORD_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,exo_monolith=debug"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().compact())
        .init();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            tracing::error!(
                                %error,
                                "the interrupt signal listener failed; waiting for SIGTERM"
                            );
                            let _ = terminate.recv().await;
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    "the SIGTERM listener failed; waiting for an interrupt signal"
                );
                if let Err(interrupt_error) = tokio::signal::ctrl_c().await {
                    tracing::error!(
                        %interrupt_error,
                        "all shutdown signal listeners failed; keeping the server online"
                    );
                    std::future::pending::<()>().await;
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "the shutdown signal listener failed; keeping the server online");
            std::future::pending::<()>().await;
        }
    }
    tracing::info!("shutdown requested");
}

#[cfg(test)]
mod tests {
    use super::{
        build_database_url, parse_cors_origins, validate_operator_token, validate_public_api_url,
        validate_public_email, validate_public_https_url,
    };

    #[test]
    fn database_components_are_encoded_without_password_restrictions() {
        let built = build_database_url("postgres", 5432, "exo user", "exocord_alpha", "p@ss:/?#[]")
            .unwrap();
        let parsed = url::Url::parse(&built).unwrap();
        assert_eq!(parsed.host_str(), Some("postgres"));
        assert_eq!(parsed.port(), Some(5432));
        assert_eq!(parsed.username(), "exo%20user");
        assert_eq!(parsed.password(), Some("p%40ss%3A%2F%3F%23%5B%5D"));
        assert_eq!(parsed.path(), "/exocord_alpha");
    }

    #[test]
    fn database_name_rejects_path_syntax() {
        assert!(build_database_url("postgres", 5432, "exocord", "../other", "secret").is_err());
    }

    #[test]
    fn cors_origins_are_normalized_and_deduplicated() {
        let origins = parse_cors_origins(
            "http://tauri.localhost/, https://alpha.example.test:443, \
             http://tauri.localhost",
        )
        .unwrap();
        let values = origins
            .iter()
            .map(|origin| origin.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec!["http://tauri.localhost", "https://alpha.example.test"]
        );
    }

    #[test]
    fn cors_origins_reject_non_origins() {
        for invalid in [
            "*",
            "file:///tmp/index.html",
            "https://user@example.test",
            "https://example.test/path",
            "https://example.test?token=secret",
            "https://example.test#fragment",
            "https://example.test,",
        ] {
            assert!(parse_cors_origins(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn operator_urls_are_https_and_do_not_carry_tracking_or_credentials() {
        assert_eq!(
            validate_public_https_url("EXOCORD_PRIVACY_URL", "https://alpha.example.test/privacy")
                .unwrap(),
            "https://alpha.example.test/privacy"
        );
        for invalid in [
            "http://alpha.example.test/privacy",
            "https://user@alpha.example.test/privacy",
            "https://alpha.example.test/privacy?user=1",
            "https://alpha.example.test/privacy#section",
        ] {
            assert!(
                validate_public_https_url("EXOCORD_PRIVACY_URL", invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn operator_contacts_are_single_public_addresses() {
        assert_eq!(
            validate_public_email("EXOCORD_ABUSE_EMAIL", "abuse@alpha.example.test").unwrap(),
            "abuse@alpha.example.test"
        );
        for invalid in [
            "alpha.example.test",
            "a@@alpha.example.test",
            "a@localhost",
            "a @alpha.example.test",
        ] {
            assert!(
                validate_public_email("EXOCORD_ABUSE_EMAIL", invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn operator_token_has_a_distinct_prefix_and_full_random_payload() {
        assert!(
            validate_operator_token("exo_op_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok()
        );
        for invalid in [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "exo_at_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "exo_op_short",
            "exo_op_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            assert!(validate_operator_token(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn local_attachment_origin_is_https_in_production_and_loopback_in_development() {
        assert_eq!(
            validate_public_api_url("https://alpha.example.test/", true).unwrap(),
            "https://alpha.example.test"
        );
        assert_eq!(
            validate_public_api_url("http://127.0.0.1:4100", false).unwrap(),
            "http://127.0.0.1:4100"
        );
        assert!(validate_public_api_url("http://127.0.0.1:4100", true).is_err());
        for invalid in [
            "http://alpha.example.test",
            "https://user@alpha.example.test",
            "https://alpha.example.test/media",
            "https://alpha.example.test?token=secret",
        ] {
            assert!(validate_public_api_url(invalid, true).is_err(), "{invalid}");
        }
    }
}
