use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

const APPLE_ISSUER: &str = "https://appleid.apple.com";

#[derive(Clone)]
pub struct AppleConfig {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    pub private_key_pem: String,
    pub redirect_uri: String,
    pub provider_token_key: [u8; 32],
    pub authorize_url: String,
    pub token_url: String,
    pub jwks_url: String,
}

impl AppleConfig {
    #[must_use]
    pub fn production(
        client_id: String,
        team_id: String,
        key_id: String,
        private_key_pem: String,
        redirect_uri: String,
        provider_token_key: [u8; 32],
    ) -> Self {
        Self {
            client_id,
            team_id,
            key_id,
            private_key_pem,
            redirect_uri,
            provider_token_key,
            authorize_url: format!("{APPLE_ISSUER}/auth/authorize"),
            token_url: format!("{APPLE_ISSUER}/auth/token"),
            jwks_url: format!("{APPLE_ISSUER}/auth/keys"),
        }
    }
}

#[derive(Clone)]
pub struct AppleClient {
    http: Client,
    config: AppleConfig,
}

#[derive(Clone, Debug)]
pub struct VerifiedAppleIdentity {
    pub subject: String,
    pub email: String,
    pub refresh_token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AppleError {
    #[error("Apple configuration is invalid")]
    Configuration,
    #[error("Apple rejected the authorization code")]
    TokenExchange,
    #[error("Apple identity verification failed")]
    IdentityVerification,
    #[error("Apple did not return a verified email address")]
    MissingVerifiedEmail,
    #[error("Apple identity nonce did not match this login")]
    NonceMismatch,
    #[error("Apple authentication is temporarily unavailable")]
    Transport,
}

impl AppleClient {
    pub fn new(config: AppleConfig) -> Result<Self, AppleError> {
        Ok(Self {
            http: Client::builder()
                .connect_timeout(std::time::Duration::from_secs(3))
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|_| AppleError::Configuration)?,
            config,
        })
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedAppleIdentity, AppleError> {
        let client_secret = self.client_secret()?;
        let response = self
            .http
            .post(&self.config.token_url)
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", self.config.redirect_uri.as_str()),
            ])
            .send()
            .await
            .map_err(|_| AppleError::Transport)?;
        if !response.status().is_success() {
            return Err(AppleError::TokenExchange);
        }
        let tokens = response
            .json::<AppleTokenResponse>()
            .await
            .map_err(|_| AppleError::TokenExchange)?;
        let claims = self.verify_identity_token(&tokens.id_token).await?;
        if !constant_time_text_eq(claims.nonce.as_deref().unwrap_or_default(), expected_nonce) {
            return Err(AppleError::NonceMismatch);
        }
        let verified = match claims.email_verified {
            VerifiedClaim::Boolean(value) => value,
            VerifiedClaim::Text(value) => value.eq_ignore_ascii_case("true"),
        };
        if !verified {
            return Err(AppleError::MissingVerifiedEmail);
        }
        let email = claims.email.ok_or(AppleError::MissingVerifiedEmail)?;
        Ok(VerifiedAppleIdentity {
            subject: claims.sub,
            email,
            refresh_token: tokens.refresh_token,
        })
    }

    fn client_secret(&self) -> Result<String, AppleError> {
        let now = Utc::now();
        let claims = ClientSecretClaims {
            iss: &self.config.team_id,
            iat: now.timestamp(),
            exp: (now + Duration::minutes(5)).timestamp(),
            aud: APPLE_ISSUER,
            sub: &self.config.client_id,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.config.key_id.clone());
        let key = EncodingKey::from_ec_pem(self.config.private_key_pem.as_bytes())
            .map_err(|_| AppleError::Configuration)?;
        encode(&header, &claims, &key).map_err(|_| AppleError::Configuration)
    }

    async fn verify_identity_token(&self, token: &str) -> Result<AppleIdentityClaims, AppleError> {
        let header = decode_header(token).map_err(|_| AppleError::IdentityVerification)?;
        if header.alg != Algorithm::RS256 {
            return Err(AppleError::IdentityVerification);
        }
        let key_id = header.kid.ok_or(AppleError::IdentityVerification)?;
        let jwks = self
            .http
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(|_| AppleError::Transport)?
            .error_for_status()
            .map_err(|_| AppleError::Transport)?
            .json::<AppleJwkSet>()
            .await
            .map_err(|_| AppleError::IdentityVerification)?;
        let jwk = jwks
            .keys
            .iter()
            .find(|key| key.kid == key_id && key.kty == "RSA" && key.alg == "RS256")
            .ok_or(AppleError::IdentityVerification)?;
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|_| AppleError::IdentityVerification)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.set_issuer(&[APPLE_ISSUER]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        decode::<AppleIdentityClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|_| AppleError::IdentityVerification)
    }
}

#[derive(Serialize)]
struct ClientSecretClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
    aud: &'a str,
    sub: &'a str,
}

#[derive(Deserialize)]
struct AppleTokenResponse {
    id_token: String,
    refresh_token: String,
}

#[derive(Clone, Deserialize)]
struct AppleIdentityClaims {
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: VerifiedClaim,
    nonce: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum VerifiedClaim {
    Boolean(bool),
    Text(String),
}

impl Default for VerifiedClaim {
    fn default() -> Self {
        Self::Boolean(false)
    }
}

#[derive(Deserialize)]
struct AppleJwkSet {
    keys: Vec<AppleJwk>,
}

#[derive(Deserialize)]
struct AppleJwk {
    kty: String,
    kid: String,
    alg: String,
    n: String,
    e: String,
}

fn constant_time_text_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).unwrap_u8().eq(&1)
}

#[cfg(test)]
mod tests {
    use axum::{
        Json, Router,
        extract::State,
        routing::{get, post},
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;

    use super::*;

    const RSA_MODULUS: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
    const RSA_EXPONENT: &str = "AQAB";
    const CLIENT_ID: &str = "com.exocord.test";

    #[derive(Clone)]
    struct MockState {
        identity_token: String,
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
        sub: &'a str,
        email: &'a str,
        email_verified: bool,
        nonce: &'a str,
    }

    async fn token(State(state): State<MockState>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "access_token": "apple-access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "apple-refresh",
            "id_token": state.identity_token
        }))
    }

    async fn keys() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "apple-test-rsa",
                "use": "sig",
                "alg": "RS256",
                "n": RSA_MODULUS,
                "e": RSA_EXPONENT
            }]
        }))
    }

    async fn mock_client(nonce: &str, audience: &str) -> AppleClient {
        let now = Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("apple-test-rsa".into());
        let identity_token = encode(
            &header,
            &TestClaims {
                iss: APPLE_ISSUER,
                aud: audience,
                exp: now + 300,
                iat: now,
                sub: "apple-user-1",
                email: "relay@privaterelay.appleid.com",
                email_verified: true,
                nonce,
            },
            &EncodingKey::from_rsa_pem(include_bytes!(
                "../tests/fixtures/apple_test_rsa_private.pem"
            ))
            .unwrap(),
        )
        .unwrap();
        let app = Router::new()
            .route("/auth/token", post(token))
            .route("/auth/keys", get(keys))
            .with_state(MockState { identity_token });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        AppleClient::new(AppleConfig {
            client_id: CLIENT_ID.into(),
            team_id: "TESTTEAM01".into(),
            key_id: "TESTKEY001".into(),
            private_key_pem: include_str!("../tests/fixtures/apple_test_ec_private.pem").into(),
            redirect_uri: "https://example.com/v1/auth/apple/callback".into(),
            provider_token_key: [7; 32],
            authorize_url: format!("http://{address}/auth/authorize"),
            token_url: format!("http://{address}/auth/token"),
            jwks_url: format!("http://{address}/auth/keys"),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn exchange_requires_a_valid_signature_audience_and_nonce() {
        let client = mock_client("expected-nonce", CLIENT_ID).await;
        let identity = client
            .exchange_code("single-use-code", "expected-nonce")
            .await
            .unwrap();
        assert_eq!(identity.subject, "apple-user-1");
        assert!(identity.email.ends_with("privaterelay.appleid.com"));
        assert!(matches!(
            client.exchange_code("code", "wrong-nonce").await,
            Err(AppleError::NonceMismatch)
        ));

        let wrong_audience = mock_client("expected-nonce", "another-client").await;
        assert!(matches!(
            wrong_audience.exchange_code("code", "expected-nonce").await,
            Err(AppleError::IdentityVerification)
        ));
    }
}
