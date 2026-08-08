use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use keyring::{Entry, Error};

const SERVICE: &str = "app.exocord.desktop";
static ENTRY_CREATION_LOCK: Mutex<()> = Mutex::new(());
static KEY_CREATION_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub struct CredentialVault {
    session: Arc<Entry>,
    device_key: Arc<Entry>,
    cache_key: Arc<Entry>,
    history_key: Arc<Entry>,
}

impl CredentialVault {
    /// Opens Windows Credential Manager entries owned by exactly one account.
    pub fn open(account_id: u64) -> Result<Self, String> {
        let prefix = format!("account-{account_id}");
        let session_entry =
            new_entry(SERVICE, &format!("{prefix}-refresh-session")).map_err(|error| {
                format!("the operating-system credential vault is unavailable: {error}")
            })?;
        let device_key_entry =
            new_entry(SERVICE, &format!("{prefix}-mls-device-key")).map_err(|error| {
                format!("the operating-system credential vault is unavailable: {error}")
            })?;
        let cache_key_entry =
            new_entry(SERVICE, &format!("{prefix}-local-cache-key")).map_err(|error| {
                format!("the operating-system credential vault is unavailable: {error}")
            })?;
        let history_key_entry =
            new_entry(SERVICE, &format!("{prefix}-history-key")).map_err(|error| {
                format!("the operating-system credential vault is unavailable: {error}")
            })?;
        Ok(Self {
            session: Arc::new(session_entry),
            device_key: Arc::new(device_key_entry),
            cache_key: Arc::new(cache_key_entry),
            history_key: Arc::new(history_key_entry),
        })
    }

    pub fn load(&self) -> Result<Option<String>, String> {
        match self.session.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(Error::NoEntry) => Ok(None),
            Err(error) => Err(format!(
                "the saved Exo Link session could not be read from the credential vault: {error}"
            )),
        }
    }

    pub fn save(&self, refresh_token: &str) -> Result<(), String> {
        self.session
            .set_password(refresh_token)
            .map_err(|error| format!("the Exo Link session could not be secured: {error}"))
    }

    pub fn clear(&self) -> Result<(), String> {
        match self.session.delete_credential() {
            Ok(()) | Err(Error::NoEntry) => Ok(()),
            Err(error) => Err(format!(
                "the saved Exo Link session could not be removed: {error}"
            )),
        }
    }

    /// Clears the saved session only when it still contains `expected`.
    ///
    /// Refresh tokens are one-time values. A stale process can therefore get
    /// a `RefreshReuse` response after another process has already persisted
    /// the replacement token. Never let that stale process erase the newer
    /// credential.
    pub fn clear_if_matches(&self, expected: &str) -> Result<bool, String> {
        if !refresh_token_matches(self.load()?.as_deref(), expected) {
            return Ok(false);
        }
        self.clear()?;
        Ok(true)
    }

    pub fn load_or_create_device_key(&self) -> Result<[u8; 32], String> {
        load_or_create_key(&self.device_key, "MLS device")
    }

    pub fn load_or_create_cache_key(&self) -> Result<[u8; 32], String> {
        load_or_create_key(&self.cache_key, "local cache")
    }

    pub fn clear_cache_key(&self) -> Result<(), String> {
        match self.cache_key.delete_credential() {
            Ok(()) | Err(Error::NoEntry) => Ok(()),
            Err(error) => Err(format!(
                "the local cache key could not be removed from the credential vault: {error}"
            )),
        }
    }

    pub fn load_history_key(&self) -> Result<Option<[u8; 32]>, String> {
        match self.history_key.get_password() {
            Ok(encoded) => decode_key(&encoded, "account history").map(Some),
            Err(Error::NoEntry) => Ok(None),
            Err(error) => Err(format!(
                "the account history key could not be read from the credential vault: {error}"
            )),
        }
    }

    pub fn save_history_key(&self, key: &[u8; 32]) -> Result<(), String> {
        self.history_key
            .set_password(&URL_SAFE_NO_PAD.encode(key))
            .map_err(|error| format!("the account history key could not be secured: {error}"))
    }
}

fn new_entry(service: &str, account: &str) -> Result<Entry, Error> {
    // keyring v1 initializes its process-global default store lazily. Serialize
    // entry creation so concurrent callers cannot observe the store between its
    // atomic guard being set and the Windows backend being installed.
    let _guard = ENTRY_CREATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Entry::new(service, account)
}

fn load_or_create_key(entry: &Entry, purpose: &str) -> Result<[u8; 32], String> {
    // Two startup paths must never both observe a missing key, return different
    // values, and race to persist the last one. Windows Credential Manager can
    // also expose a just-written value before set_password returns to another
    // caller, so serialize creation and read back the authoritative value.
    let _guard = KEY_CREATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match entry.get_password() {
        Ok(encoded) => decode_key(&encoded, purpose),
        Err(Error::NoEntry) => {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key)
                .map_err(|_| format!("secure randomness is unavailable for {purpose} setup"))?;
            entry
                .set_password(&URL_SAFE_NO_PAD.encode(key))
                .map_err(|error| format!("the {purpose} key could not be secured: {error}"))?;
            let stored = entry.get_password().map_err(|error| {
                format!("the newly secured {purpose} key could not be verified: {error}")
            })?;
            decode_key(&stored, purpose)
        }
        Err(error) => Err(format!(
            "the {purpose} key could not be read from the credential vault: {error}"
        )),
    }
}

fn decode_key(encoded: &str, purpose: &str) -> Result<[u8; 32], String> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| format!("the saved {purpose} key is not valid base64url"))?
        .try_into()
        .map_err(|_| format!("the saved {purpose} key does not contain 32 bytes"))
}

fn refresh_token_matches(current: Option<&str>, expected: &str) -> bool {
    current.is_some_and(|current| current == expected)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn windows_credential_manager_round_trip() {
        let account = format!("credential-smoke-{}", uuid::Uuid::now_v7());
        let entry = new_entry(SERVICE, &account).unwrap();
        entry.set_password("exo_rt_test-only").unwrap();
        assert_eq!(entry.get_password().unwrap(), "exo_rt_test-only");
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }

    #[test]
    fn windows_credential_manager_persists_random_cache_keys() {
        let account = format!("cache-key-smoke-{}", uuid::Uuid::now_v7());
        let entry = new_entry(SERVICE, &account).unwrap();
        let created = load_or_create_key(&entry, "test cache").unwrap();
        assert_ne!(created, [0_u8; 32]);
        assert_eq!(load_or_create_key(&entry, "test cache").unwrap(), created);
        entry.delete_credential().unwrap();
    }

    #[test]
    fn account_scopes_do_not_share_refresh_tokens() {
        let seed = uuid::Uuid::now_v7().as_u64_pair().1;
        let left = CredentialVault::open(seed).unwrap();
        let right = CredentialVault::open(seed.saturating_add(1)).unwrap();
        left.save("left-only").unwrap();
        right.save("right-only").unwrap();
        assert_eq!(left.load().unwrap().as_deref(), Some("left-only"));
        assert_eq!(right.load().unwrap().as_deref(), Some("right-only"));
        left.clear().unwrap();
        right.clear().unwrap();
    }
}

#[cfg(test)]
mod token_tests {
    use super::refresh_token_matches;

    #[test]
    fn stale_refresh_errors_only_match_the_token_that_was_used() {
        assert!(refresh_token_matches(Some("old"), "old"));
        assert!(!refresh_token_matches(Some("new"), "old"));
        assert!(!refresh_token_matches(None, "old"));
    }
}
