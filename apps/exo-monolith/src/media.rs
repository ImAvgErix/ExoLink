use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use exo_domain::{AttachmentId, ChannelId, UserId};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::{Digest, Sha256};
use url::Url;

use crate::repository::AttachmentRecord;

pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 10;
const MAX_IMAGE_PIXELS: u64 = 40_000_000;
const MAX_IMAGE_EDGE: usize = 16_384;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AttachmentService {
    backend: AttachmentBackend,
    object_key_secret: Arc<[u8; 32]>,
    http: Client,
}

#[derive(Clone)]
enum AttachmentBackend {
    Disabled,
    Local {
        root: Arc<PathBuf>,
        public_api_url: String,
        capability_secret: Arc<[u8; 32]>,
        max_storage_bytes: u64,
        io_lock: Arc<std::sync::Mutex<()>>,
    },
    R2(Arc<R2Config>),
}

#[derive(Clone, Debug)]
pub struct R2Config {
    pub endpoint: Url,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub cdn_url: String,
}

#[derive(Clone, Debug)]
pub struct PreparedUpload {
    pub object_key: String,
    pub public_url: String,
    pub upload_url: String,
    pub upload_headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct Inspection {
    pub verified_content_type: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub animated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("attachments are not configured on this server")]
    Disabled,
    #[error("the upload capability is invalid or expired")]
    InvalidCapability,
    #[error("the uploaded object is missing")]
    MissingObject,
    #[error("the uploaded object size does not match its reservation")]
    SizeMismatch,
    #[error("the uploaded object hash does not match its reservation")]
    HashMismatch,
    #[error("the uploaded file type does not match the declared type")]
    TypeMismatch,
    #[error("that file type is not accepted")]
    UnsupportedType,
    #[error("the image dimensions are invalid or exceed the safety limit")]
    UnsafeImage,
    #[error("the server attachment quota is full")]
    Capacity,
    #[error("attachment storage failed: {0}")]
    Storage(String),
}

impl AttachmentService {
    #[must_use]
    pub fn disabled(object_key_secret: [u8; 32]) -> Self {
        Self {
            backend: AttachmentBackend::Disabled,
            object_key_secret: Arc::new(object_key_secret),
            http: Client::new(),
        }
    }

    pub fn local(
        root: PathBuf,
        public_api_url: String,
        capability_secret: [u8; 32],
        object_key_secret: [u8; 32],
    ) -> Result<Self, MediaError> {
        Self::local_with_limit(
            root,
            public_api_url,
            capability_secret,
            object_key_secret,
            u64::MAX,
        )
    }

    pub fn local_with_limit(
        root: PathBuf,
        public_api_url: String,
        capability_secret: [u8; 32],
        object_key_secret: [u8; 32],
        max_storage_bytes: u64,
    ) -> Result<Self, MediaError> {
        Self::new(
            AttachmentBackend::Local {
                root: Arc::new(root),
                public_api_url: public_api_url.trim_end_matches('/').to_owned(),
                capability_secret: Arc::new(capability_secret),
                max_storage_bytes,
                io_lock: Arc::new(std::sync::Mutex::new(())),
            },
            object_key_secret,
        )
    }

    pub fn r2(config: R2Config, object_key_secret: [u8; 32]) -> Result<Self, MediaError> {
        Self::new(AttachmentBackend::R2(Arc::new(config)), object_key_secret)
    }

    fn new(backend: AttachmentBackend, object_key_secret: [u8; 32]) -> Result<Self, MediaError> {
        Ok(Self {
            backend,
            object_key_secret: Arc::new(object_key_secret),
            http: Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(45))
                .build()
                .map_err(|error| MediaError::Storage(error.to_string()))?,
        })
    }

    #[must_use]
    pub const fn available(&self) -> bool {
        !matches!(self.backend, AttachmentBackend::Disabled)
    }

    #[must_use]
    pub const fn storage_name(&self) -> &'static str {
        match self.backend {
            AttachmentBackend::Disabled => "disabled",
            AttachmentBackend::Local { .. } => "local",
            AttachmentBackend::R2(_) => "r2",
        }
    }

    pub fn prepare_upload(
        &self,
        id: AttachmentId,
        owner_id: UserId,
        channel_id: ChannelId,
        sha256: &[u8; 32],
        declared_content_type: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PreparedUpload, MediaError> {
        let object_token = keyed_hex(self.object_key_secret.as_ref(), sha256);
        let object_key = format!("objects/{}/{object_token}", &object_token[..2]);
        match &self.backend {
            AttachmentBackend::Disabled => Err(MediaError::Disabled),
            AttachmentBackend::Local {
                public_api_url,
                capability_secret,
                ..
            } => {
                let upload_claim = format!(
                    "upload:{id}:{owner_id}:{channel_id}:{}:{}",
                    expires_at.timestamp(),
                    hex::encode(sha256)
                );
                let upload_token = keyed_hex(capability_secret.as_ref(), upload_claim.as_bytes());
                let read_claim = format!("read:{id}:{object_key}");
                let read_token = keyed_hex(capability_secret.as_ref(), read_claim.as_bytes());
                Ok(PreparedUpload {
                    object_key,
                    public_url: format!(
                        "{public_api_url}/v1/attachments/{id}/content?token={read_token}"
                    ),
                    upload_url: format!(
                        "{public_api_url}/v1/attachments/{id}/content?token={upload_token}"
                    ),
                    upload_headers: BTreeMap::from([(
                        "content-type".to_owned(),
                        "application/octet-stream".to_owned(),
                    )]),
                })
            }
            AttachmentBackend::R2(config) => {
                let upload_content_type = if allowed_type(declared_content_type) {
                    declared_content_type
                } else {
                    "application/octet-stream"
                };
                let upload_headers = BTreeMap::from([
                    ("content-type".to_owned(), upload_content_type.to_owned()),
                    ("if-none-match".to_owned(), "*".to_owned()),
                ]);
                let upload_url =
                    presign_r2(config, "PUT", &object_key, 900, &upload_headers, Utc::now())?;
                Ok(PreparedUpload {
                    public_url: format!("{}/{}", config.cdn_url.trim_end_matches('/'), object_key),
                    object_key,
                    upload_url,
                    upload_headers,
                })
            }
        }
    }

    pub fn verify_upload_capability(
        &self,
        record: &AttachmentRecord,
        token: &str,
    ) -> Result<(), MediaError> {
        let AttachmentBackend::Local {
            capability_secret, ..
        } = &self.backend
        else {
            return Err(MediaError::InvalidCapability);
        };
        if record.expires_at <= Utc::now() {
            return Err(MediaError::InvalidCapability);
        }
        let claim = format!(
            "upload:{}:{}:{}:{}:{}",
            record.id,
            record.owner_id,
            record.channel_id,
            record.expires_at.timestamp(),
            hex::encode(record.claimed_sha256)
        );
        verify_keyed_hex(capability_secret.as_ref(), claim.as_bytes(), token)
    }

    pub fn verify_read_capability(
        &self,
        record: &AttachmentRecord,
        token: &str,
    ) -> Result<(), MediaError> {
        let AttachmentBackend::Local {
            capability_secret, ..
        } = &self.backend
        else {
            return Err(MediaError::InvalidCapability);
        };
        let claim = format!("read:{}:{}", record.id, record.object_key);
        verify_keyed_hex(capability_secret.as_ref(), claim.as_bytes(), token)
    }

    pub async fn store_local_upload(
        &self,
        record: &AttachmentRecord,
        bytes: Vec<u8>,
    ) -> Result<Inspection, MediaError> {
        let AttachmentBackend::Local {
            root,
            max_storage_bytes,
            io_lock,
            ..
        } = &self.backend
        else {
            return Err(MediaError::Disabled);
        };
        let inspection = inspect_bytes(record, &bytes)?;
        let path = safe_object_path(root, &record.object_key)?;
        let root = Arc::clone(root);
        let io_lock = Arc::clone(io_lock);
        let max_storage_bytes = *max_storage_bytes;
        let parent = path
            .parent()
            .ok_or_else(|| MediaError::Storage("object path has no parent".into()))?
            .to_owned();
        let temporary = path.with_extension(format!("upload-{}", uuid::Uuid::now_v7()));
        tokio::task::spawn_blocking(move || -> Result<(), MediaError> {
            let _guard = io_lock
                .lock()
                .map_err(|_| MediaError::Storage("attachment I/O lock is poisoned".into()))?;
            std::fs::create_dir_all(parent).map_err(storage_error)?;
            if path.exists() {
                return if path.metadata().map_err(storage_error)?.len() == inspection.size {
                    Ok(())
                } else {
                    Err(MediaError::Storage(
                        "an existing content-addressed object has a different size".into(),
                    ))
                };
            }
            let used = directory_file_bytes(&root)?;
            if used
                .checked_add(inspection.size)
                .is_none_or(|total| total > max_storage_bytes)
            {
                return Err(MediaError::Capacity);
            }
            if let Err(error) = std::fs::write(&temporary, bytes) {
                if let Err(cleanup_error) = std::fs::remove_file(&temporary)
                    && cleanup_error.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(
                        %cleanup_error,
                        path = %temporary.display(),
                        "failed attachment upload could not be cleaned up"
                    );
                }
                return Err(storage_error(error));
            }
            match std::fs::rename(&temporary, &path) {
                Ok(()) => Ok(()),
                Err(error) if path.exists() => {
                    if let Err(cleanup_error) = std::fs::remove_file(&temporary)
                        && cleanup_error.kind() != std::io::ErrorKind::NotFound
                    {
                        tracing::warn!(
                            %cleanup_error,
                            path = %temporary.display(),
                            "deduplicated attachment temporary file could not be cleaned up"
                        );
                    }
                    if path.metadata().map_err(storage_error)?.len() == inspection.size {
                        Ok(())
                    } else {
                        Err(storage_error(error))
                    }
                }
                Err(error) => {
                    if let Err(cleanup_error) = std::fs::remove_file(&temporary)
                        && cleanup_error.kind() != std::io::ErrorKind::NotFound
                    {
                        tracing::warn!(
                            %cleanup_error,
                            path = %temporary.display(),
                            "failed attachment temporary file could not be cleaned up"
                        );
                    }
                    Err(storage_error(error))
                }
            }
        })
        .await
        .map_err(|error| MediaError::Storage(error.to_string()))??;
        Ok(inspection)
    }

    pub async fn inspect_reserved_object(
        &self,
        record: &AttachmentRecord,
    ) -> Result<Inspection, MediaError> {
        match &self.backend {
            AttachmentBackend::Disabled => Err(MediaError::Disabled),
            AttachmentBackend::Local { root, .. } => {
                let path = safe_object_path(root, &record.object_key)?;
                let bytes = tokio::task::spawn_blocking(move || std::fs::read(path))
                    .await
                    .map_err(|error| MediaError::Storage(error.to_string()))?
                    .map_err(|error| {
                        if error.kind() == std::io::ErrorKind::NotFound {
                            MediaError::MissingObject
                        } else {
                            storage_error(error)
                        }
                    })?;
                inspect_bytes(record, &bytes)
            }
            AttachmentBackend::R2(config) => {
                let url = presign_r2(
                    config,
                    "GET",
                    &record.object_key,
                    120,
                    &BTreeMap::new(),
                    Utc::now(),
                )?;
                let response = self
                    .http
                    .get(url)
                    .send()
                    .await
                    .map_err(|error| MediaError::Storage(error.to_string()))?;
                if response.status().as_u16() == 404 {
                    return Err(MediaError::MissingObject);
                }
                if !response.status().is_success() {
                    return Err(MediaError::Storage(format!(
                        "R2 validation returned HTTP {}",
                        response.status()
                    )));
                }
                if response.content_length().is_some_and(|length| {
                    length > MAX_ATTACHMENT_BYTES || length != record.file_size
                }) {
                    return Err(MediaError::SizeMismatch);
                }
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|error| MediaError::Storage(error.to_string()))?;
                inspect_bytes(record, &bytes)
            }
        }
    }

    pub async fn read_local_object(
        &self,
        record: &AttachmentRecord,
    ) -> Result<Vec<u8>, MediaError> {
        let AttachmentBackend::Local { root, .. } = &self.backend else {
            return Err(MediaError::MissingObject);
        };
        let path = safe_object_path(root, &record.object_key)?;
        tokio::task::spawn_blocking(move || std::fs::read(path))
            .await
            .map_err(|error| MediaError::Storage(error.to_string()))?
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    MediaError::MissingObject
                } else {
                    storage_error(error)
                }
            })
    }

    pub async fn delete_object(&self, object_key: &str) -> Result<bool, MediaError> {
        match &self.backend {
            AttachmentBackend::Disabled => Ok(false),
            AttachmentBackend::Local { root, io_lock, .. } => {
                let path = safe_object_path(root, object_key)?;
                let io_lock = Arc::clone(io_lock);
                tokio::task::spawn_blocking(move || {
                    let _guard = io_lock.lock().map_err(|_| {
                        MediaError::Storage("attachment I/O lock is poisoned".into())
                    })?;
                    match std::fs::remove_file(path) {
                        Ok(()) => Ok(true),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                        Err(error) => Err(storage_error(error)),
                    }
                })
                .await
                .map_err(|error| MediaError::Storage(error.to_string()))?
            }
            AttachmentBackend::R2(config) => {
                let url = presign_r2(
                    config,
                    "DELETE",
                    object_key,
                    120,
                    &BTreeMap::new(),
                    Utc::now(),
                )?;
                let response = self
                    .http
                    .delete(url)
                    .send()
                    .await
                    .map_err(|error| MediaError::Storage(error.to_string()))?;
                if response.status().as_u16() == 404 {
                    return Ok(false);
                }
                if !response.status().is_success() {
                    return Err(MediaError::Storage(format!(
                        "R2 deletion returned HTTP {}",
                        response.status()
                    )));
                }
                Ok(true)
            }
        }
    }
}

fn inspect_bytes(record: &AttachmentRecord, bytes: &[u8]) -> Result<Inspection, MediaError> {
    let size = u64::try_from(bytes.len()).map_err(|_| MediaError::SizeMismatch)?;
    if size != record.file_size || size == 0 || size > MAX_ATTACHMENT_BYTES {
        return Err(MediaError::SizeMismatch);
    }
    let actual_hash: [u8; 32] = Sha256::digest(bytes).into();
    if actual_hash != record.claimed_sha256 {
        return Err(MediaError::HashMismatch);
    }
    if looks_like_active_document(bytes) {
        return Err(MediaError::UnsupportedType);
    }

    let detected = infer::get(bytes)
        .map(|kind| kind.mime_type().to_owned())
        .unwrap_or_else(|| {
            if std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0) {
                "text/plain".to_owned()
            } else {
                "application/octet-stream".to_owned()
            }
        });
    if !allowed_type(&detected) {
        return Err(MediaError::UnsupportedType);
    }
    let declared = normalize_content_type(&record.declared_content_type);
    if declared != "application/octet-stream"
        && declared != detected
        && !(declared == "image/jpeg" && detected == "image/jpg")
    {
        return Err(MediaError::TypeMismatch);
    }

    let (width, height) = if detected.starts_with("image/") {
        let dimensions = imagesize::blob_size(bytes).map_err(|_| MediaError::UnsafeImage)?;
        if dimensions.width == 0
            || dimensions.height == 0
            || dimensions.width > MAX_IMAGE_EDGE
            || dimensions.height > MAX_IMAGE_EDGE
            || (dimensions.width as u64).saturating_mul(dimensions.height as u64) > MAX_IMAGE_PIXELS
        {
            return Err(MediaError::UnsafeImage);
        }
        (
            Some(u32::try_from(dimensions.width).map_err(|_| MediaError::UnsafeImage)?),
            Some(u32::try_from(dimensions.height).map_err(|_| MediaError::UnsafeImage)?),
        )
    } else {
        (None, None)
    };
    Ok(Inspection {
        verified_content_type: detected.clone(),
        size,
        sha256: actual_hash,
        width,
        height,
        animated: matches!(detected.as_str(), "image/gif" | "image/webp"),
    })
}

fn looks_like_active_document(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(1024)];
    let Ok(sample) = std::str::from_utf8(sample) else {
        return false;
    };
    let sample = sample
        .trim_start_matches('\u{feff}')
        .trim_start()
        .to_ascii_lowercase();
    sample.starts_with("<!doctype html")
        || sample.starts_with("<html")
        || sample.starts_with("<script")
        || sample.starts_with("<svg")
        || (sample.starts_with("<?xml") && sample.contains("<svg"))
}

fn allowed_type(content_type: &str) -> bool {
    matches!(
        content_type,
        "image/jpeg"
            | "image/jpg"
            | "image/png"
            | "image/gif"
            | "image/webp"
            | "video/mp4"
            | "video/webm"
            | "audio/mpeg"
            | "audio/ogg"
            | "audio/wav"
            | "audio/x-wav"
            | "audio/flac"
            | "application/pdf"
            | "application/zip"
            | "application/x-7z-compressed"
            | "text/plain"
            | "application/octet-stream"
    )
}

fn normalize_content_type(value: &str) -> String {
    let value = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match value.as_str() {
        "" => "application/octet-stream".to_owned(),
        "image/jpg" => "image/jpeg".to_owned(),
        other => other.to_owned(),
    }
}

fn safe_object_path(root: &Path, object_key: &str) -> Result<PathBuf, MediaError> {
    if object_key.split('/').any(|segment| {
        segment.is_empty()
            || segment == "."
            || segment == ".."
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }) {
        return Err(MediaError::Storage("unsafe object key".into()));
    }
    Ok(object_key
        .split('/')
        .fold(root.to_owned(), |path, part| path.join(part)))
}

fn directory_file_bytes(root: &Path) -> Result<u64, MediaError> {
    let mut total = 0_u64;
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(storage_error(error)),
        };
        for entry in entries {
            let entry = entry.map_err(storage_error)?;
            let file_type = entry.file_type().map_err(storage_error)?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                total = total
                    .checked_add(entry.metadata().map_err(storage_error)?.len())
                    .ok_or_else(|| {
                        MediaError::Storage("attachment storage usage overflowed".into())
                    })?;
            }
        }
    }
    Ok(total)
}

#[allow(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts keys of every byte length by definition"
)]
fn keyed_hex(secret: &[u8], value: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(value);
    hex::encode(mac.finalize().into_bytes())
}

#[allow(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts keys of every byte length by definition"
)]
fn verify_keyed_hex(secret: &[u8], value: &[u8], token: &str) -> Result<(), MediaError> {
    let signature = hex::decode(token).map_err(|_| MediaError::InvalidCapability)?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(value);
    mac.verify_slice(&signature)
        .map_err(|_| MediaError::InvalidCapability)
}

fn presign_r2(
    config: &R2Config,
    method: &str,
    object_key: &str,
    expires_seconds: u32,
    signed_headers: &BTreeMap<String, String>,
    now: DateTime<Utc>,
) -> Result<String, MediaError> {
    let host = match (config.endpoint.host_str(), config.endpoint.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        _ => return Err(MediaError::Storage("R2 endpoint has no host".into())),
    };
    let date = now.format("%Y%m%d").to_string();
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let scope = format!("{date}/auto/s3/aws4_request");
    let mut headers = signed_headers.clone();
    headers.insert("host".to_owned(), host);
    let signed_header_names = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name.to_ascii_lowercase(), value.trim()))
        .collect::<String>();
    let mut query = BTreeMap::from([
        ("X-Amz-Algorithm".to_owned(), "AWS4-HMAC-SHA256".to_owned()),
        (
            "X-Amz-Content-Sha256".to_owned(),
            "UNSIGNED-PAYLOAD".to_owned(),
        ),
        (
            "X-Amz-Credential".to_owned(),
            format!("{}/{}", config.access_key_id, scope),
        ),
        ("X-Amz-Date".to_owned(), timestamp.clone()),
        ("X-Amz-Expires".to_owned(), expires_seconds.to_string()),
        (
            "X-Amz-SignedHeaders".to_owned(),
            signed_header_names.clone(),
        ),
    ]);
    let canonical_query_string = canonical_query(&query);
    let endpoint_path = config.endpoint.path().trim_end_matches('/');
    let canonical_uri = format!(
        "{}/{}/{}",
        endpoint_path,
        rfc3986(&config.bucket),
        object_key
            .split('/')
            .map(rfc3986)
            .collect::<Vec<_>>()
            .join("/")
    );
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_header_names}\nUNSIGNED-PAYLOAD"
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let date_key = hmac_bytes(
        format!("AWS4{}", config.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let region_key = hmac_bytes(&date_key, b"auto");
    let service_key = hmac_bytes(&region_key, b"s3");
    let signing_key = hmac_bytes(&service_key, b"aws4_request");
    let signature = hex::encode(hmac_bytes(&signing_key, string_to_sign.as_bytes()));
    query.insert("X-Amz-Signature".to_owned(), signature);
    let final_query = canonical_query(&query);
    let mut base = config.endpoint.as_str().trim_end_matches('/').to_owned();
    base.push_str(&canonical_uri);
    Ok(format!("{base}?{final_query}"))
}

fn canonical_query(values: &BTreeMap<String, String>) -> String {
    values
        .iter()
        .map(|(key, value)| format!("{}={}", rfc3986(key), rfc3986(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn rfc3986(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[allow(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts keys of every byte length by definition"
)]
fn hmac_bytes(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

fn storage_error(error: std::io::Error) -> MediaError {
    MediaError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use exo_domain::{ChannelId, UserId};

    #[test]
    fn local_capabilities_are_bound_to_the_complete_reservation() {
        let service = AttachmentService::local(
            PathBuf::from("ignored"),
            "http://127.0.0.1:4100".into(),
            [7; 32],
            [9; 32],
        )
        .unwrap();
        let id = AttachmentId::from_raw(41).unwrap();
        let owner_id = UserId::from_raw(42).unwrap();
        let channel_id = ChannelId::from_raw(43).unwrap();
        let sha256 = [5; 32];
        let expires_at = Utc::now() + chrono::Duration::minutes(15);
        let prepared = service
            .prepare_upload(id, owner_id, channel_id, &sha256, "image/png", expires_at)
            .unwrap();
        let token = Url::parse(&prepared.upload_url)
            .unwrap()
            .query_pairs()
            .find_map(|(key, value)| (key == "token").then(|| value.into_owned()))
            .unwrap();
        let record = AttachmentRecord {
            id,
            channel_id,
            owner_id,
            filename: "photo.png".into(),
            declared_content_type: "image/png".into(),
            verified_content_type: None,
            file_size: 12,
            claimed_sha256: sha256,
            verified_sha256: None,
            object_key: prepared.object_key,
            public_url: prepared.public_url,
            width: None,
            height: None,
            animated: false,
            ready: false,
            message_id: None,
            expires_at,
        };
        service.verify_upload_capability(&record, &token).unwrap();
        let mut changed = record;
        changed.owner_id = UserId::from_raw(44).unwrap();
        assert!(matches!(
            service.verify_upload_capability(&changed, &token),
            Err(MediaError::InvalidCapability)
        ));
    }

    #[test]
    fn r2_signatures_are_stable_and_encode_credentials() {
        let config = R2Config {
            endpoint: Url::parse("https://account.r2.cloudflarestorage.com").unwrap(),
            bucket: "exo media".into(),
            access_key_id: "access/key".into(),
            secret_access_key: "secret".into(),
            cdn_url: "https://cdn.example.test".into(),
        };
        let now = DateTime::parse_from_rfc3339("2026-07-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let url = presign_r2(&config, "GET", "objects/ab/cd", 120, &BTreeMap::new(), now).unwrap();
        assert!(url.contains("/exo%20media/objects/ab/cd?"));
        assert!(
            url.contains("X-Amz-Credential=access%2Fkey%2F20260729%2Fauto%2Fs3%2Faws4_request")
        );
        assert!(url.contains("X-Amz-Signature="));
    }

    #[test]
    fn active_documents_cannot_hide_behind_plain_text() {
        let bytes = b"<!doctype html><script>alert(1)</script>";
        let record = AttachmentRecord {
            id: AttachmentId::from_raw(51).unwrap(),
            channel_id: ChannelId::from_raw(52).unwrap(),
            owner_id: UserId::from_raw(53).unwrap(),
            filename: "notes.txt".into(),
            declared_content_type: "text/plain".into(),
            verified_content_type: None,
            file_size: u64::try_from(bytes.len()).unwrap(),
            claimed_sha256: Sha256::digest(bytes).into(),
            verified_sha256: None,
            object_key: "objects/aa/bb".into(),
            public_url: "https://cdn.example.test/objects/aa/bb".into(),
            width: None,
            height: None,
            animated: false,
            ready: false,
            message_id: None,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
        };
        assert!(matches!(
            inspect_bytes(&record, bytes),
            Err(MediaError::UnsupportedType)
        ));
    }

    #[tokio::test]
    async fn local_storage_limit_counts_objects_and_allows_deduplication() {
        let directory = tempfile::tempdir().unwrap();
        let first = b"first alpha attachment".to_vec();
        let second = b"second alpha attachment".to_vec();
        let service = AttachmentService::local_with_limit(
            directory.path().to_owned(),
            "https://alpha.example.test".into(),
            [7; 32],
            [9; 32],
            u64::try_from(first.len()).unwrap(),
        )
        .unwrap();
        let make_record = |id, object_key: &str, bytes: &[u8]| AttachmentRecord {
            id: AttachmentId::from_raw(id).unwrap(),
            channel_id: ChannelId::from_raw(52).unwrap(),
            owner_id: UserId::from_raw(53).unwrap(),
            filename: "notes.txt".into(),
            declared_content_type: "text/plain".into(),
            verified_content_type: None,
            file_size: u64::try_from(bytes.len()).unwrap(),
            claimed_sha256: Sha256::digest(bytes).into(),
            verified_sha256: None,
            object_key: object_key.into(),
            public_url: "https://alpha.example.test/file".into(),
            width: None,
            height: None,
            animated: false,
            ready: false,
            message_id: None,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
        };
        let first_record = make_record(61, "objects/aa/first", &first);
        service
            .store_local_upload(&first_record, first.clone())
            .await
            .unwrap();
        service
            .store_local_upload(&first_record, first)
            .await
            .unwrap();

        let second_record = make_record(62, "objects/bb/second", &second);
        assert!(matches!(
            service.store_local_upload(&second_record, second).await,
            Err(MediaError::Capacity)
        ));
    }
}
