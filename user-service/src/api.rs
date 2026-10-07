//! Public API, reached only through Oathkeeper (`/api/users/**`), which has already
//! authenticated the request and attached a JWT. Handlers just take `Claims`.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Deserializer, Serialize};

use crate::auth::Claims;
use crate::db;
use crate::error::{AppError, AppJson};
use crate::models::{DisplayName, Role, User};
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/users/me", get(get_me).patch(update_me))
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct MeResponse {
    #[serde(flatten)]
    user: User,
    roles: Vec<Role>,
}

async fn get_me(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<MeResponse>, AppError> {
    // The hydrator created the row before this request reached us; NotFound means
    // the request bypassed it (or the user was just deleted).
    let user = db::find_by_id(&state.db, claims.sub)
        .await?
        .ok_or(AppError::NotFound)?;
    me(&state, user).await
}

/// PATCH semantics: a missing field is left alone, `null` clears it.
#[derive(Debug, Deserialize)]
struct UpdateMe {
    #[serde(default, deserialize_with = "present")]
    display_name: Option<Option<String>>,
}

/// Distinguishes "field absent" (`None`, via `default`) from "field is null" (`Some(None)`).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

async fn update_me(
    State(state): State<AppState>,
    claims: Claims,
    AppJson(body): AppJson<UpdateMe>,
) -> Result<Json<MeResponse>, AppError> {
    let user = match body.display_name {
        None => db::find_by_id(&state.db, claims.sub).await?,
        Some(raw) => {
            // Parsed here (not in the struct) so a bad name gets its precise error code.
            let name = raw.map(DisplayName::try_from).transpose()?;
            db::set_display_name(&state.db, claims.sub, name.as_ref()).await?
        }
    };
    me(&state, user.ok_or(AppError::NotFound)?).await
}

async fn me(state: &AppState, user: User) -> Result<Json<MeResponse>, AppError> {
    let roles = db::roles_of(&state.db, user.id).await?;
    Ok(Json(MeResponse { user, roles }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::auth::testing;

    async fn call(
        db: &PgPool,
        method: Method,
        token: Option<String>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let app = router(AppState {
            db: db.clone(),
            verifier: Arc::new(testing::verifier()),
            hydrator_password: "unused".into(),
        });
        let mut req = Request::builder().method(method).uri("/api/users/me");
        if let Some(token) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        };
        let res = app.oneshot(req.unwrap()).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn existing_user(db: &PgPool) -> (Uuid, String) {
        let id = Uuid::new_v4();
        db::find_or_create(db, id, &"ada@example.com".parse().unwrap())
            .await
            .unwrap();
        (id, testing::token(json!({ "sub": id })))
    }

    #[sqlx::test]
    async fn get_me_returns_profile_and_roles(db: PgPool) {
        let (id, token) = existing_user(&db).await;
        let (status, body) = call(&db, Method::GET, Some(token), None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], json!(id));
        assert_eq!(body["email"], "ada@example.com");
        assert_eq!(body["display_name"], Value::Null);
        assert_eq!(body["roles"], json!(["user"]));
    }

    #[sqlx::test]
    async fn requires_a_valid_token(db: PgPool) {
        assert_eq!(
            call(&db, Method::GET, None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (status, body) = call(&db, Method::GET, Some("not.a.jwt".into()), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "unauthorized");
    }

    #[sqlx::test]
    async fn patch_sets_keeps_and_clears_display_name(db: PgPool) {
        let (_, token) = existing_user(&db).await;

        let (status, body) = call(
            &db,
            Method::PATCH,
            Some(token.clone()),
            Some(json!({ "display_name": " Ada " })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["display_name"], "Ada");

        let (_, body) = call(&db, Method::PATCH, Some(token.clone()), Some(json!({}))).await;
        assert_eq!(
            body["display_name"], "Ada",
            "absent field must not change anything"
        );

        let (_, body) = call(
            &db,
            Method::PATCH,
            Some(token),
            Some(json!({ "display_name": null })),
        )
        .await;
        assert_eq!(body["display_name"], Value::Null);
    }

    #[sqlx::test]
    async fn patch_rejects_invalid_names_with_precise_code(db: PgPool) {
        let (_, token) = existing_user(&db).await;
        let (status, body) = call(
            &db,
            Method::PATCH,
            Some(token),
            Some(json!({ "display_name": "   " })),
        )
        .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["code"], "display_name_empty");
    }

    #[sqlx::test]
    async fn patch_rejects_malformed_json_in_app_format(db: PgPool) {
        let (_, token) = existing_user(&db).await;
        let (status, body) = call(
            &db,
            Method::PATCH,
            Some(token),
            Some(json!({ "display_name": 42 })),
        )
        .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["code"], "invalid_body");
    }
}
