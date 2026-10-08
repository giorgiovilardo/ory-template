//! `POST /internal/kratos/identity`: Kratos' `web_hook` (kratos.yml), on the internal
//! listener only. Kratos calls it after saving a new identity (registration, every
//! method) and after a profile change (settings), with `{identity_id, email}`. It
//! creates the row (with the `user` role) or refreshes the email copy, so the row exists
//! from registration on and the hydrator never writes.
//!
//! Kratos runs it synchronously after the identity is saved (`response.parse: false`).
//! If it fails, Kratos reports the error to the user but the identity already exists;
//! the hydrator then serves an empty profile until `user-service reconcile` creates the
//! row. Idempotent, so Kratos' retries are safe.

use std::sync::Arc;

use axum::Router;
use axum::extract::{FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::routing::post;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::has_basic_credentials;
use crate::db;
use crate::error::{AppError, AppJson};
use crate::kratos::{KratosIdentity, Traits};
use crate::models::Email;

pub const WEBHOOK_USERNAME: &str = "kratos";

/// What the web hook needs: the database and Kratos' Basic password (its own, not the
/// hydrator's, so either can be rotated or leak without exposing the other).
#[derive(Clone)]
pub struct WebhookState {
    pub db: PgPool,
    pub password: Arc<str>,
}

pub fn router(state: WebhookState) -> Router {
    Router::new()
        .route("/internal/kratos/identity", post(identity_saved))
        .with_state(state)
}

/// Rendered by `kratos/webhooks/identity.jsonnet`.
#[derive(Debug, Deserialize)]
struct IdentitySaved {
    identity_id: Uuid,
    email: Email,
}

async fn identity_saved(
    State(state): State<WebhookState>,
    _: FromKratos,
    AppJson(body): AppJson<IdentitySaved>,
) -> Result<StatusCode, AppError> {
    let IdentitySaved { identity_id, email } = body;
    let identity = KratosIdentity {
        id: identity_id,
        traits: Traits { email },
    };
    db::sync_identity(&state.db, &identity).await?;
    tracing::debug!(id = %identity_id, "identity saved in Kratos: user-service data in sync");
    Ok(StatusCode::NO_CONTENT)
}

/// Extractor: the request carries Kratos' Basic credentials. Comes before the body
/// extractor, so callers without them get a 401 and learn nothing from parser errors.
struct FromKratos;

impl FromRequestParts<WebhookState> for FromKratos {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &WebhookState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let ok = has_basic_credentials(parts, WEBHOOK_USERNAME, &state.password);
        std::future::ready(if ok {
            Ok(Self)
        } else {
            Err(AppError::Unauthorized)
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, header};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::{Value, json};

    use super::*;
    use crate::models::Role;

    const PASSWORD: &str = "webhook-password";

    async fn call(db: &PgPool, body: &Value, password: Option<&str>) -> (StatusCode, Value) {
        let app = router(WebhookState {
            db: db.clone(),
            password: PASSWORD.into(),
        });
        let mut req = Request::post("/internal/kratos/identity")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(pw) = password {
            let creds = STANDARD.encode(format!("{WEBHOOK_USERNAME}:{pw}"));
            req = req.header(header::AUTHORIZATION, format!("Basic {creds}"));
        }
        crate::testing::send(app, req.body(Body::from(body.to_string())).unwrap()).await
    }

    #[sqlx::test]
    async fn registration_creates_the_user(db: PgPool) {
        let id = Uuid::new_v4();
        let body = json!({ "identity_id": id, "email": "Ada@Example.com" });

        // Kratos retries: twice is the same as once.
        for _ in 0..2 {
            let (status, _) = call(&db, &body, Some(PASSWORD)).await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
        let found = db::find_with_roles(&db, id).await.unwrap().unwrap();
        assert_eq!(found.user.email.as_ref(), "ada@example.com");
        assert_eq!(found.roles, vec![Role::User]);
    }

    #[sqlx::test]
    async fn an_email_change_refreshes_the_copy_and_keeps_the_roles(db: PgPool) {
        let id = Uuid::new_v4();
        call(
            &db,
            &json!({ "identity_id": id, "email": "old@example.com" }),
            Some(PASSWORD),
        )
        .await;
        db::grant_role(&db, id, Role::Admin).await.unwrap();

        call(
            &db,
            &json!({ "identity_id": id, "email": "new@example.com" }),
            Some(PASSWORD),
        )
        .await;
        let found = db::find_with_roles(&db, id).await.unwrap().unwrap();
        assert_eq!(found.user.email.as_ref(), "new@example.com");
        assert_eq!(found.roles, vec![Role::Admin, Role::User]);
    }

    #[sqlx::test]
    async fn requires_kratos_credentials_before_the_body(db: PgPool) {
        let body = json!({ "identity_id": Uuid::new_v4(), "email": "ada@example.com" });
        for password in [None, Some("wrong")] {
            assert_eq!(call(&db, &body, password).await.0, StatusCode::UNAUTHORIZED);
            assert_eq!(
                call(&db, &json!("garbage"), password).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            sqlx::query_scalar!("select count(*) from users")
                .fetch_one(&db)
                .await
                .unwrap(),
            Some(0)
        );
    }

    #[sqlx::test]
    async fn rejects_malformed_bodies(db: PgPool) {
        for body in [
            json!({ "identity_id": "nope", "email": "ada@example.com" }),
            json!({ "identity_id": Uuid::new_v4(), "email": "nope" }),
            json!({ "identity_id": Uuid::new_v4() }),
        ] {
            let (status, out) = call(&db, &body, Some(PASSWORD)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            assert_eq!(out["error"]["code"], "invalid_body");
        }
    }
}
