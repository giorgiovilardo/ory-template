//! Verifies the JWT Oathkeeper adds to every logged-in request. Stateless: no
//! session lookups, just a signature check against Oathkeeper's public keys.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::time::Instant;
use uuid::Uuid;

use crate::error::AppError;

/// After a successful fetch, unknown key ids trigger another at most this often (key
/// rotation support without letting garbage tokens hammer Oathkeeper).
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// After a failed fetch, wait this long before trying again. Short, so a slow start of
/// Oathkeeper costs a second of 401s rather than half a minute, but nonzero, so an
/// outage doesn't turn every request into its own timeout.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(1);

/// Claims minted by Oathkeeper's `id_token` mutator (see oathkeeper.yml).
/// Only `sub` is read: email and roles are looked up in our own database, so the token
/// carries nothing a handler could trust over it.
#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
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
    /// Built once: the algorithm is pinned (never trust the `alg` the token claims).
    validation: Validation,
    /// Decoding keys by `kid`, converted once per JWKS fetch rather than once per request.
    keys: RwLock<HashMap<String, Arc<DecodingKey>>>,
    remote: Option<RemoteJwks>,
}

struct RemoteJwks {
    url: String,
    http: reqwest::Client,
    /// Held for the whole fetch, so requests that need keys wait for the one fetch in
    /// flight instead of failing or fetching again. Holds the earliest time the next
    /// fetch may start (`None`: never fetched, go ahead).
    next_fetch: Mutex<Option<Instant>>,
}

impl JwtVerifier {
    /// Keys are fetched from `jwks_url` on first use and refetched on unknown key ids.
    pub fn remote(jwks_url: String, issuer: &str, http: reqwest::Client) -> Self {
        Self {
            validation: validation(issuer),
            keys: RwLock::new(HashMap::new()),
            remote: Some(RemoteJwks {
                url: jwks_url,
                http,
                next_fetch: Mutex::new(None),
            }),
        }
    }

    /// Fixed keys, no network. For tests.
    #[cfg(test)]
    pub fn from_jwks(keys: &JwkSet, issuer: &str) -> Self {
        Self {
            validation: validation(issuer),
            keys: RwLock::new(decoding_keys(keys)),
            remote: None,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<Claims, AuthError> {
        let kid = decode_header(token)?.kid.ok_or(AuthError::MissingKeyId)?;
        let key = self.key_for(&kid).await?;

        Ok(decode::<Claims>(token, &key, &self.validation)?.claims)
    }

    async fn key_for(&self, kid: &str) -> Result<Arc<DecodingKey>, AuthError> {
        let unknown = || AuthError::UnknownKey(kid.to_owned());
        if let Some(key) = self.cached_key(kid) {
            return Ok(key);
        }
        let Some(remote) = &self.remote else {
            return Err(unknown());
        };
        let mut next_fetch = remote.next_fetch.lock().await;
        // The fetch we queued behind may have brought the key.
        if let Some(key) = self.cached_key(kid) {
            return Ok(key);
        }
        if next_fetch.is_some_and(|at| Instant::now() < at) {
            return Err(unknown());
        }
        // Only schedule the next fetch once this one has finished, and sooner if it
        // failed: a failure must not lock everyone out for the full interval.
        let fetched = remote.fetch().await;
        let wait = if fetched.is_ok() {
            MIN_REFRESH_INTERVAL
        } else {
            RETRY_AFTER_FAILURE
        };
        *next_fetch = Some(Instant::now() + wait);
        *self.keys.write().expect("jwks lock poisoned") = decoding_keys(&fetched?);
        self.cached_key(kid).ok_or_else(unknown)
    }

    fn cached_key(&self, kid: &str) -> Option<Arc<DecodingKey>> {
        self.keys
            .read()
            .expect("jwks lock poisoned")
            .get(kid)
            .cloned()
    }
}

fn validation(issuer: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    validation
}

/// Keys without a `kid` can't be selected by a token, and one the library can't convert
/// must not take the others down with it: both are skipped.
fn decoding_keys(jwks: &JwkSet) -> HashMap<String, Arc<DecodingKey>> {
    jwks.keys
        .iter()
        .filter_map(|jwk| {
            let kid = jwk.common.key_id.clone()?;
            match DecodingKey::from_jwk(jwk) {
                Ok(key) => Some((kid, Arc::new(key))),
                Err(err) => {
                    tracing::warn!(%kid, %err, "ignoring unusable signing key");
                    None
                }
            }
        })
        .collect()
}

impl RemoteJwks {
    async fn fetch(&self) -> Result<JwkSet, reqwest::Error> {
        self.http
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }
}

/// Extractor: add `claims: Claims` to a handler's arguments to require a valid JWT.
/// Works with any router state that provides the verifier (`#[derive(FromRef)]`).
impl<S> FromRequestParts<S> for Claims
where
    Arc<JwtVerifier>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::Unauthorized)?;
        let verifier = Arc::<JwtVerifier>::from_ref(state);
        verifier.verify(bearer.token()).await.map_err(|err| {
            tracing::debug!(%err, "rejected token");
            AppError::Unauthorized
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    use super::*;
    use crate::testing::*;

    #[tokio::test]
    async fn accepts_valid_tokens() {
        let sub = Uuid::new_v4();
        let claims = verifier()
            .verify(&token(json!({ "sub": sub })))
            .await
            .unwrap();

        assert_eq!(claims.sub, sub);
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
        let result = verifier().verify(&token_with_kid("other")).await;
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
            &EncodingKey::from_secret(PUBLIC_X.as_bytes()),
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

    /// A JWKS endpoint that counts requests, can be told to fail, and answers slowly
    /// enough for concurrent requests to overlap.
    struct JwksServer {
        url: String,
        hits: Arc<AtomicUsize>,
        failing: Arc<AtomicBool>,
    }

    async fn serve_jwks() -> JwksServer {
        let hits = Arc::new(AtomicUsize::new(0));
        let failing = Arc::new(AtomicBool::new(false));
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get({
                let (hits, failing) = (hits.clone(), failing.clone());
                move || async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if failing.load(Ordering::SeqCst) {
                        return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
                    }
                    Ok(axum::Json(jwks()))
                }
            }),
        );
        let url = format!("{}/jwks", crate::testing::spawn(app).await);
        JwksServer { url, hits, failing }
    }

    fn remote_verifier(server: &JwksServer) -> JwtVerifier {
        // No client timeout: it would race the paused test clock.
        JwtVerifier::remote(server.url.clone(), ISSUER, reqwest::Client::new())
    }

    #[tokio::test(start_paused = true)]
    async fn fetches_keys_on_first_use() {
        let server = serve_jwks().await;
        let verifier = remote_verifier(&server);
        assert!(verifier.verify(&token(json!({}))).await.is_ok());
        assert!(verifier.verify(&token(json!({}))).await.is_ok());
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_fetch_only_blocks_logins_briefly() {
        let server = serve_jwks().await;
        let verifier = remote_verifier(&server);
        let token = token(json!({}));

        server.failing.store(true, Ordering::SeqCst);
        assert!(matches!(
            verifier.verify(&token).await,
            Err(AuthError::Jwks(_))
        ));

        // Backing off: no new fetch, so no hammering a struggling Oathkeeper...
        server.failing.store(false, Ordering::SeqCst);
        assert!(matches!(
            verifier.verify(&token).await,
            Err(AuthError::UnknownKey(_))
        ));
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);

        // ...but only for a moment, not for MIN_REFRESH_INTERVAL.
        tokio::time::advance(RETRY_AFTER_FAILURE).await;
        assert!(verifier.verify(&token).await.is_ok());
        assert_eq!(server.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_requests_wait_for_the_one_fetch() {
        let server = serve_jwks().await;
        let verifier = Arc::new(remote_verifier(&server));
        let token = token(json!({}));

        let requests: Vec<_> = (0..8)
            .map(|_| {
                let (verifier, token) = (verifier.clone(), token.clone());
                tokio::spawn(async move { verifier.verify(&token).await })
            })
            .collect();
        for request in requests {
            request.await.unwrap().unwrap();
        }
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_key_ids_refetch_at_most_once_per_interval() {
        let server = serve_jwks().await;
        let verifier = remote_verifier(&server);
        let unknown = token_with_kid("other");

        for _ in 0..3 {
            assert!(matches!(
                verifier.verify(&unknown).await,
                Err(AuthError::UnknownKey(_))
            ));
        }
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);

        tokio::time::advance(MIN_REFRESH_INTERVAL).await;
        assert!(verifier.verify(&unknown).await.is_err());
        assert_eq!(server.hits.load(Ordering::SeqCst), 2);
    }
}
