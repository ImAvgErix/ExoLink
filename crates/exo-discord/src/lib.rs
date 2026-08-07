use serde::{Deserialize, Serialize};
use url::Url;

pub const STANDARD_IDENTITY_SCOPES: &[&str] = &["identify"];
pub const STANDARD_GUILD_SCOPES: &[&str] = &["identify", "guilds"];
pub const SOCIAL_PRESENCE_SCOPES: &[&str] = &["openid", "sdk.social_layer_presence"];
pub const SOCIAL_COMMUNICATION_SCOPES: &[&str] = &["openid", "sdk.social_layer"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscordIntegrationMode {
    StandardOauth,
    SocialSdkDevelopment,
    SocialSdkApproved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Supported,
    DevelopmentRateLimited,
    RequiresDiscordApproval,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityMatrix {
    pub identity: Availability,
    pub guild_metadata: Availability,
    pub relationships: Availability,
    pub direct_messages: Availability,
    pub lobby_voice: Availability,
    pub existing_guild_voice: Availability,
}

#[must_use]
pub const fn capabilities(mode: DiscordIntegrationMode) -> CapabilityMatrix {
    match mode {
        DiscordIntegrationMode::StandardOauth => CapabilityMatrix {
            identity: Availability::Supported,
            guild_metadata: Availability::Supported,
            relationships: Availability::Unavailable,
            direct_messages: Availability::Unavailable,
            lobby_voice: Availability::Unavailable,
            existing_guild_voice: Availability::Unavailable,
        },
        DiscordIntegrationMode::SocialSdkDevelopment => CapabilityMatrix {
            identity: Availability::Supported,
            guild_metadata: Availability::Supported,
            relationships: Availability::Supported,
            direct_messages: Availability::DevelopmentRateLimited,
            lobby_voice: Availability::DevelopmentRateLimited,
            existing_guild_voice: Availability::Unavailable,
        },
        DiscordIntegrationMode::SocialSdkApproved => CapabilityMatrix {
            identity: Availability::Supported,
            guild_metadata: Availability::Supported,
            relationships: Availability::Supported,
            direct_messages: Availability::Supported,
            lobby_voice: Availability::Supported,
            existing_guild_voice: Availability::Unavailable,
        },
    }
}

#[derive(Clone, Debug)]
pub struct OAuthAuthorizationRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
    pub scopes: &'a [&'a str],
}

#[derive(Debug, thiserror::Error)]
pub enum DiscordIntegrationError {
    #[error("Discord OAuth configuration is missing {0}")]
    MissingField(&'static str),
    #[error("Discord OAuth redirect URI is invalid")]
    InvalidRedirect,
    #[error("Discord OAuth URL construction failed")]
    InvalidAuthorizationEndpoint,
}

/// Builds a native-safe authorization-code request with PKCE.
///
/// Token exchange and refresh-token storage deliberately stay server-side.
///
/// # Errors
///
/// Returns an error for missing identifiers, invalid redirect URIs, or an
/// invalid authorization endpoint.
pub fn authorization_url(
    request: &OAuthAuthorizationRequest<'_>,
) -> Result<Url, DiscordIntegrationError> {
    if request.client_id.trim().is_empty() {
        return Err(DiscordIntegrationError::MissingField("client_id"));
    }
    if request.state.trim().is_empty() {
        return Err(DiscordIntegrationError::MissingField("state"));
    }
    if request.code_challenge.trim().is_empty() {
        return Err(DiscordIntegrationError::MissingField("code_challenge"));
    }
    Url::parse(request.redirect_uri).map_err(|_| DiscordIntegrationError::InvalidRedirect)?;
    let mut url = Url::parse("https://discord.com/oauth2/authorize")
        .map_err(|_| DiscordIntegrationError::InvalidAuthorizationEndpoint)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", request.client_id)
        .append_pair("redirect_uri", request.redirect_uri)
        .append_pair("scope", &request.scopes.join(" "))
        .append_pair("state", request.state)
        .append_pair("code_challenge", request.code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscordLinkedIdentity {
    pub discord_user_id: String,
    pub username: String,
    pub global_name: Option<String>,
    pub avatar_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_oauth_never_claims_friend_or_dm_access() {
        let matrix = capabilities(DiscordIntegrationMode::StandardOauth);
        assert_eq!(matrix.relationships, Availability::Unavailable);
        assert_eq!(matrix.direct_messages, Availability::Unavailable);
        assert_eq!(matrix.existing_guild_voice, Availability::Unavailable);
    }

    #[test]
    fn social_sdk_does_not_claim_existing_guild_voice() {
        let matrix = capabilities(DiscordIntegrationMode::SocialSdkApproved);
        assert_eq!(matrix.lobby_voice, Availability::Supported);
        assert_eq!(matrix.existing_guild_voice, Availability::Unavailable);
    }

    #[test]
    fn oauth_request_uses_state_and_pkce() {
        let url = authorization_url(&OAuthAuthorizationRequest {
            client_id: "123",
            redirect_uri: "http://127.0.0.1/callback",
            state: "csrf-state",
            code_challenge: "pkce-challenge",
            scopes: STANDARD_IDENTITY_SCOPES,
        })
        .unwrap();
        let query = url.query().unwrap();
        assert!(query.contains("state=csrf-state"));
        assert!(query.contains("code_challenge=pkce-challenge"));
        assert!(query.contains("scope=identify"));
    }
}
