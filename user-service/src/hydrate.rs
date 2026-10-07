//! `POST /internal/hydrate`: called by Oathkeeper's hydrator mutator on every
//! logged-in request, before it mints the JWT. Adds `extra.profile` to the session.
//!
//! Contract (Oathkeeper v26, pipeline/mutate/mutator_hydrator.go):
//! - the body is the full AuthenticationSession: {subject, extra, header, match_context};
//! - the response REPLACES it, so everything must come back, untouched except `extra.profile`;
//! - `subject` must not change, and any non-200 response fails the user's request;
//! - Oathkeeper also forwards the original request headers (incl. the Kratos session
//!   cookie), so never log request headers here.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Basic;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;

use crate::db;
use crate::error::{AppError, AppJson};
use crate::kratos::KratosSession;
use crate::models::Profile;
use crate::state::AppState;

pub const HYDRATOR_USERNAME: &str = "oathkeeper";

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/internal/hydrate", post(hydrate))
        .with_state(state)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OathkeeperSession {
    pub subject: String,
    #[serde(default)]
    pub extra: Value,
    /// `header`, `match_context` and anything Oathkeeper adds later: passed through as-is.
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

async fn hydrate(
    State(state): State<AppState>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    AppJson(mut session): AppJson<OathkeeperSession>,
) -> Result<Json<OathkeeperSession>, AppError> {
    check_credentials(auth, &state.hydrator_password)?;

    // Typed view of the parts we need; `&Value` is a serde Deserializer, so no clone.
    let kratos = KratosSession::deserialize(&session.extra)
        .map_err(|err| AppError::BadRequest(format!("extra is not a Kratos session: {err}")))?;
    let identity = kratos.identity;
    if identity.id.to_string() != session.subject {
        return Err(AppError::BadRequest(
            "subject does not match identity.id".into(),
        ));
    }

    let user = db::find_or_create(&state.db, identity.id, &identity.traits.email).await?;
    let roles = db::roles_of(&state.db, user.id).await?;
    let profile = Profile {
        display_name: user.display_name.as_ref(),
        roles: &roles,
    };

    session
        .extra
        .as_object_mut()
        .ok_or_else(|| AppError::BadRequest("extra is not an object".into()))?
        .insert(
            "profile".into(),
            serde_json::to_value(profile).map_err(anyhow::Error::from)?,
        );
    Ok(Json(session))
}

fn check_credentials(
    auth: Option<TypedHeader<Authorization<Basic>>>,
    password: &str,
) -> Result<(), AppError> {
    let Some(TypedHeader(Authorization(basic))) = auth else {
        return Err(AppError::Unauthorized);
    };
    // Constant-time comparison: don't leak how much of the password matched.
    let user_ok = basic
        .username()
        .as_bytes()
        .ct_eq(HYDRATOR_USERNAME.as_bytes());
    let password_ok = basic.password().as_bytes().ct_eq(password.as_bytes());
    if (user_ok & password_ok).into() {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use http_body_util::BodyExt;
    use serde_json::json;
    use sqlx::PgPool;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::testing;
    use crate::models::Role;

    const PASSWORD: &str = "test-password";

    fn app(db: PgPool) -> Router {
        router(AppState {
            db,
            verifier: Arc::new(testing::verifier()),
            hydrator_password: PASSWORD.into(),
        })
    }

    /// The shape Oathkeeper sends: a real Kratos whoami response in `extra`.
    fn session(id: Uuid, email: &str) -> Value {
        json!({
            "subject": id.to_string(),
            "extra": {
                "id": "f0a5e7d9-0000-0000-0000-000000000000",
                "active": true,
                "authenticator_assurance_level": "aal1",
                "identity": {
                    "id": id,
                    "schema_id": "default",
                    "state": "active",
                    "traits": { "email": email },
                    "metadata_public": null
                }
            },
            "header": { "X-Something": ["kept"] },
            "match_context": { "regexp_capture_groups": [], "url": { "Path": "/app" }, "method": "GET", "header": {} }
        })
    }

    async fn call(db: &PgPool, body: &Value, password: Option<&str>) -> (StatusCode, Value) {
        let mut req =
            Request::post("/internal/hydrate").header(header::CONTENT_TYPE, "application/json");
        if let Some(pw) = password {
            let creds = STANDARD.encode(format!("{HYDRATOR_USERNAME}:{pw}"));
            req = req.header(header::AUTHORIZATION, format!("Basic {creds}"));
        }
        let res = app(db.clone())
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[sqlx::test]
    async fn adds_profile_and_preserves_everything_else(db: PgPool) {
        let id = Uuid::new_v4();
        let input = session(id, "Ada@Example.com");
        let (status, output) = call(&db, &input, Some(PASSWORD)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            output["extra"]["profile"],
            json!({ "display_name": null, "roles": ["user"] })
        );

        // Everything except extra.profile must round-trip unchanged.
        let mut without_profile = output.clone();
        without_profile["extra"]
            .as_object_mut()
            .unwrap()
            .remove("profile");
        assert_eq!(without_profile, input);

        let user = db::find_by_id(&db, id).await.unwrap().unwrap();
        assert_eq!(user.email.as_ref(), "ada@example.com");
    }

    #[sqlx::test]
    async fn reflects_current_roles(db: PgPool) {
        let id = Uuid::new_v4();
        call(&db, &session(id, "ada@example.com"), Some(PASSWORD)).await;
        db::grant_role(&db, id, Role::Admin, None).await.unwrap();

        let (_, output) = call(&db, &session(id, "ada@example.com"), Some(PASSWORD)).await;
        assert_eq!(
            output["extra"]["profile"]["roles"],
            json!(["admin", "user"])
        );
    }

    #[sqlx::test]
    async fn requires_credentials(db: PgPool) {
        let body = session(Uuid::new_v4(), "ada@example.com");
        assert_eq!(call(&db, &body, None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            call(&db, &body, Some("wrong")).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[sqlx::test]
    async fn rejects_mismatched_subject(db: PgPool) {
        let mut body = session(Uuid::new_v4(), "ada@example.com");
        body["subject"] = json!(Uuid::new_v4().to_string());
        assert_eq!(
            call(&db, &body, Some(PASSWORD)).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[sqlx::test]
    async fn rejects_non_kratos_extra(db: PgPool) {
        let mut body = session(Uuid::new_v4(), "ada@example.com");
        body["extra"] = json!({ "something": "else" });
        let (status, output) = call(&db, &body, Some(PASSWORD)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(output["error"]["code"], "bad_request");
    }
}
