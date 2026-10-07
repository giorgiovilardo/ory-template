//! Verifies the JWT Oathkeeper adds to every logged-in request. Stateless: no
//! session lookups, just a signature check against Oathkeeper's public keys.

use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::Role;
use crate::state::AppState;

/// Unknown key ids trigger a JWKS refetch at most this often (key rotation
/// support without letting garbage tokens hammer Oathkeeper).
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Claims minted by Oathkeeper's `id_token` mutator (see oathkeeper.yml).
/// This is the JWT contract; each handler reads only what it needs.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub roles: Vec<Role>,
    /// "aal1" = password/social/code, "aal2" = passed 2FA.
    #[serde(default)]
    pub aal: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("token has no key id")]
    MissingKeyId,
    #[error("token signed with unknown key {0:?}")]
    UnknownKey(String),
    #[error("could not fetch signing keys: {0}")]
    Jwks(#[from] reqwest::Error),
    #[error(transparent)]
    Invalid(#[from] jsonwebtoken::errors::Error),
}

pub struct JwtVerifier {
    issuer: String,
    keys: RwLock<JwkSet>,
    remote: Option<RemoteJwks>,
}

struct RemoteJwks {
    url: String,
    http: reqwest::Client,
    last_fetch: Mutex<Option<Instant>>,
}

impl JwtVerifier {
    /// Keys are fetched from `jwks_url` on first use and refetched on unknown key ids.
    pub fn remote(jwks_url: String, issuer: String, http: reqwest::Client) -> Self {
        Self {
            issuer,
            keys: RwLock::new(JwkSet { keys: vec![] }),
            remote: Some(RemoteJwks {
                url: jwks_url,
                http,
                last_fetch: Mutex::new(None),
            }),
        }
    }

    /// Fixed keys, no network. For tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn from_jwks(keys: JwkSet, issuer: String) -> Self {
        Self {
            issuer,
            keys: RwLock::new(keys),
            remote: None,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<Claims, AuthError> {
        let kid = decode_header(token)?.kid.ok_or(AuthError::MissingKeyId)?;
        let key = self.key_for(&kid).await?;

        // Pin the algorithm: never trust the `alg` the token claims.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        Ok(decode::<Claims>(token, &key, &validation)?.claims)
    }

    async fn key_for(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        if let Some(key) = self.cached_key(kid)? {
            return Ok(key);
        }
        if let Some(remote) = &self.remote
            && remote.may_refresh()
        {
            let fresh: JwkSet = remote
                .http
                .get(&remote.url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            *self.keys.write().expect("jwks lock poisoned") = fresh;
            if let Some(key) = self.cached_key(kid)? {
                return Ok(key);
            }
        }
        Err(AuthError::UnknownKey(kid.to_owned()))
    }

    fn cached_key(&self, kid: &str) -> Result<Option<DecodingKey>, AuthError> {
        let keys = self.keys.read().expect("jwks lock poisoned");
        Ok(keys.find(kid).map(DecodingKey::from_jwk).transpose()?)
    }
}

impl RemoteJwks {
    fn may_refresh(&self) -> bool {
        let mut last = self.last_fetch.lock().expect("jwks lock poisoned");
        let allowed = last.is_none_or(|at| at.elapsed() >= MIN_REFRESH_INTERVAL);
        if allowed {
            *last = Some(Instant::now());
        }
        allowed
    }
}

/// Extractor: add `claims: Claims` to a handler's arguments to require a valid JWT.
impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::Unauthorized)?;
        state.verifier.verify(bearer.token()).await.map_err(|err| {
            tracing::debug!(%err, "rejected token");
            AppError::Unauthorized
        })
    }
}

/// Test helpers: a fixed Ed25519 key pair, so tests can mint "real" tokens offline.
#[cfg(test)]
pub mod testing {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    use super::*;

    pub const ISSUER: &str = "http://localhost:8080/";
    pub const KID: &str = "test-key";
    const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKv/ABhOfUH9W6xjz45q8YcU5EutEPsyUxood02hq03C
-----END PRIVATE KEY-----";
    const PUBLIC_X: &str = "uIY7GvdnKS8istVWUhwYskS2H0lVw3T_acQ7DvSvT3Q";

    pub fn verifier() -> JwtVerifier {
        let jwks = serde_json::from_value(json!({
            "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": PUBLIC_X, "kid": KID, "alg": "EdDSA", "use": "sig" }]
        }))
        .unwrap();
        JwtVerifier::from_jwks(jwks, ISSUER.to_owned())
    }

    /// Signs `claims` with the test key, merged over sensible defaults.
    pub fn token(claims: serde_json::Value) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut body = json!({ "iss": ISSUER, "sub": uuid::Uuid::new_v4(), "iat": now, "exp": now + 60, "roles": ["user"] });
        body.as_object_mut()
            .unwrap()
            .extend(claims.as_object().unwrap().clone());

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(KID.to_owned());
        encode(
            &header,
            &body,
            &EncodingKey::from_ed_pem(PRIVATE_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    use super::testing::*;
    use super::*;

    #[tokio::test]
    async fn accepts_valid_tokens() {
        let sub = Uuid::new_v4();
        let claims = verifier()
            .verify(&token(
                json!({ "sub": sub, "roles": ["admin", "user"], "aal": "aal2" }),
            ))
            .await
            .unwrap();

        assert_eq!(claims.sub, sub);
        assert_eq!(claims.roles, vec![Role::Admin, Role::User]);
        assert_eq!(claims.aal.as_deref(), Some("aal2"));
    }

    #[tokio::test]
    async fn rejects_expired_tokens() {
        let past = time::OffsetDateTime::now_utc().unix_timestamp() - 3600;
        let result = verifier().verify(&token(json!({ "exp": past }))).await;
        assert!(matches!(result, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn rejects_wrong_issuer() {
        let result = verifier()
            .verify(&token(json!({ "iss": "https://evil.example/" })))
            .await;
        assert!(matches!(result, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn rejects_unknown_key_ids() {
        let mut parts: Vec<String> = token(json!({})).split('.').map(str::to_owned).collect();
        parts[0] = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"other"}"#);
        let result = verifier().verify(&parts.join(".")).await;
        assert!(matches!(result, Err(AuthError::UnknownKey(k)) if k == "other"));
    }

    #[tokio::test]
    async fn rejects_other_algorithms() {
        // HS256 "signed" with the public key: the classic algorithm-confusion attack.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_owned());
        let forged = encode(
            &header,
            &json!({ "iss": ISSUER, "sub": Uuid::new_v4(), "exp": 9_999_999_999u64 }),
            &EncodingKey::from_secret(b"uIY7GvdnKS8istVWUhwYskS2H0lVw3T_acQ7DvSvT3Q"),
        )
        .unwrap();
        assert!(verifier().verify(&forged).await.is_err());
    }

    #[tokio::test]
    async fn rejects_tampered_tokens() {
        let mut parts: Vec<String> = token(json!({})).split('.').map(str::to_owned).collect();
        parts[1] = URL_SAFE_NO_PAD.encode(
            json!({ "iss": ISSUER, "sub": Uuid::new_v4(), "exp": 9_999_999_999u64, "roles": ["admin"] }).to_string(),
        );
        assert!(verifier().verify(&parts.join(".")).await.is_err());
    }
}
