//! Public API, reached only through Oathkeeper (`/api/users/**`), which has already
//! authenticated the request and attached a JWT. Handlers just take `Claims`.

use std::sync::Arc;

use axum::extract::{FromRef, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::{Claims, JwtVerifier};
use crate::db;
use crate::error::{AppError, AppJson};
use crate::models::{DisplayName, Email, Role, User, UserWithRoles};

/// What the public router needs: the database, and the verifier `Claims` extracts with.
#[derive(Clone, FromRef)]
pub struct ApiState {
    pub db: PgPool,
    pub verifier: Arc<JwtVerifier>,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/users/me", get(get_me).patch(update_me))
        .with_state(state)
}

/// The `/api/users/me` body. Fields are listed, not `User` flattened, so a new column
/// reaches clients only by decision (as `Profile` does for JWTs): the exhaustive
/// destructuring in `from` stops compiling until the new field is placed or ignored.
#[derive(Debug, Serialize)]
struct MeResponse {
    id: Uuid,
    email: Email,
    display_name: Option<DisplayName>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
    roles: Vec<Role>,
}

impl From<UserWithRoles> for MeResponse {
    fn from(UserWithRoles { user, roles }: UserWithRoles) -> Self {
        let User {
            id,
            email,
            display_name,
            created_at,
            updated_at,
        } = user;
        Self {
            id,
            email,
            display_name,
            created_at,
            updated_at,
            roles,
        }
    }
}

async fn get_me(
    State(state): State<ApiState>,
    claims: Claims,
) -> Result<Json<MeResponse>, AppError> {
    // The hydrator created the row before this request reached us; NotFound means
    // the request bypassed it (or the user was just deleted).
    let found = db::find_with_roles(&state.db, claims.sub)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(found.into()))
}

/// PATCH semantics: a missing field is left alone, `null` clears it.
#[derive(Debug, Deserialize)]
struct UpdateMe {
    #[allow(
        clippy::option_option,
        reason = "absent / null / value is the PATCH contract"
    )]
    #[serde(default, deserialize_with = "present")]
    display_name: Option<Option<String>>,
}

/// Distinguishes "field absent" (`None`, via `default`) from "field is null" (`Some(None)`).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

async fn update_me(
    State(state): State<ApiState>,
    claims: Claims,
    AppJson(body): AppJson<UpdateMe>,
) -> Result<Json<MeResponse>, AppError> {
    let found = match body.display_name {
        None => db::find_with_roles(&state.db, claims.sub).await?,
        Some(raw) => {
            // Parsed here (not in the struct) so a bad name gets its precise error code.
            let name = raw.map(DisplayName::try_from).transpose()?;
            db::set_display_name(&state.db, claims.sub, name.as_ref()).await?
        }
    };
    Ok(Json(found.ok_or(AppError::NotFound)?.into()))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::*;
    use crate::testing;

    async fn call(
        db: &PgPool,
        method: Method,
        token: Option<String>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let app = router(ApiState {
            db: db.clone(),
            verifier: Arc::new(testing::verifier()),
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
        testing::send(app, req.unwrap()).await
    }

    async fn existing_user(db: &PgPool) -> (Uuid, String) {
        let id = Uuid::new_v4();
        db::sync_identity(db, &testing::identity(id, "ada@example.com"))
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
