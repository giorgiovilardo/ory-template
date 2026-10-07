//! Test support shared across modules: a fixed Ed25519 key pair, so tests can mint
//! "real" JWTs offline, and plumbing for driving routers.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt;

use uuid::Uuid;

use crate::auth::JwtVerifier;
use crate::kratos::{KratosIdentity, Traits};

pub const ISSUER: &str = "http://localhost:8080/";
pub const KID: &str = "test-key";
const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKv/ABhOfUH9W6xjz45q8YcU5EutEPsyUxood02hq03C
-----END PRIVATE KEY-----";
pub const PUBLIC_X: &str = "uIY7GvdnKS8istVWUhwYskS2H0lVw3T_acQ7DvSvT3Q";

pub fn jwks() -> serde_json::Value {
    json!({
        "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": PUBLIC_X, "kid": KID, "alg": "EdDSA", "use": "sig" }]
    })
}

pub fn verifier() -> JwtVerifier {
    JwtVerifier::from_jwks(&serde_json::from_value(jwks()).unwrap(), ISSUER)
}

/// Signs `claims` (a JSON object) with the test key, merged over sensible defaults.
pub fn token(claims: Value) -> String {
    let Value::Object(overrides) = claims else {
        panic!("claims must be a JSON object");
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut body = json!({ "iss": ISSUER, "sub": Uuid::new_v4(), "iat": now, "exp": now + 60 });
    body.as_object_mut().unwrap().extend(overrides);

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KID.to_owned());
    encode(
        &header,
        &body,
        &EncodingKey::from_ed_pem(PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// A valid test token whose header names key `kid` instead (signature unchanged).
pub fn token_with_kid(kid: &str) -> String {
    let token = token(json!({}));
    let (_, payload_and_signature) = token.split_once('.').unwrap();
    let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "EdDSA", "kid": kid }).to_string());
    format!("{header}.{payload_and_signature}")
}

/// A Kratos identity as the hydrator or CLI would get it.
pub fn identity(id: Uuid, email: &str) -> KratosIdentity {
    KratosIdentity {
        id,
        traits: Traits {
            email: email.parse().unwrap(),
        },
    }
}

/// Sends one request; the body is `Null` when the response isn't JSON.
pub async fn send(app: Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Serves `app` on an ephemeral local port; returns its base URL.
pub async fn spawn(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    url
}
