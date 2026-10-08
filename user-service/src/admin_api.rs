//! The admin HTTP API (`/api/admin/users/**`), a thin adapter over `directory`, like the
//! CLI. Reached only through Oathkeeper (its own `users-admin-api` rule); every handler
//! takes `AdminClaims`, so every route requires the `admin` role (read from the
//! database). Each one maps its input to one directory call and the result to an
//! explicit response struct; errors map to `AppError` codes in `error.rs`.
//!
//! These routes are cookie-authenticated through Oathkeeper, and `SameSite=Lax` keeps
//! the cookie off cross-site POST/PUT/DELETE but not off GET: no GET here changes
//! anything. Every admin action is logged (`audit`), without tokens or recovery secrets.

use std::sync::Arc;

use axum::extract::{FromRef, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{AdminClaims, JwtVerifier};
use crate::directory::{
    Actor, Directory, DirectoryError, IdentityAdmin, Invited, ListedUser, UserDetails, UsersPage,
};
use crate::error::{AppError, AppJson, AppPath, AppQuery};
use crate::kratos::{Identity, IdentityState, RecoveryCode};
use crate::models::{Email, Role, StoredUser};

/// Default and maximum `page_size` of `GET /users`.
const DEFAULT_PAGE_SIZE: u16 = 50;
const MAX_PAGE_SIZE: u16 = 250;

/// What the admin router needs. Generic over the Kratos port so tests can use the fake.
pub struct AdminState<K> {
    pub db: PgPool,
    pub verifier: Arc<JwtVerifier>,
    pub directory: Arc<Directory<K>>,
}

impl<K> Clone for AdminState<K> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            verifier: self.verifier.clone(),
            directory: self.directory.clone(),
        }
    }
}

impl<K> FromRef<AdminState<K>> for PgPool {
    fn from_ref(state: &AdminState<K>) -> Self {
        state.db.clone()
    }
}

impl<K> FromRef<AdminState<K>> for Arc<JwtVerifier> {
    fn from_ref(state: &AdminState<K>) -> Self {
        state.verifier.clone()
    }
}

impl<K> FromRef<AdminState<K>> for Arc<Directory<K>> {
    fn from_ref(state: &AdminState<K>) -> Self {
        state.directory.clone()
    }
}

pub fn router<K: IdentityAdmin + 'static>(state: AdminState<K>) -> Router {
    Router::new()
        .route("/api/admin/users", get(list::<K>).post(invite::<K>))
        .route(
            "/api/admin/users/{id}",
            get(show::<K>).delete(delete_user::<K>),
        )
        .route(
            "/api/admin/users/{id}/roles/{role}",
            put(grant_role::<K>).delete(revoke_role::<K>),
        )
        .route("/api/admin/users/{id}/deactivate", post(deactivate::<K>))
        .route("/api/admin/users/{id}/activate", post(activate::<K>))
        .route(
            "/api/admin/users/{id}/sessions",
            delete(revoke_sessions::<K>),
        )
        .route("/api/admin/users/{id}/recovery", post(recover::<K>))
        .with_state(state)
}

type Dir<K> = State<Arc<Directory<K>>>;

/// Logs one admin action: who, what, on whom, and how it went (the error's code, not its
/// message, which can carry Kratos details). Never the request or the response.
fn audit<T>(
    admin: &AdminClaims,
    action: &'static str,
    target: Option<Uuid>,
    result: &Result<T, DirectoryError>,
) {
    let outcome = match result {
        Ok(_) => "ok",
        Err(err) => AppError::code_of(err),
    };
    // `None` (an action on no single user) leaves the field out.
    let target = target.map(tracing::field::display);
    tracing::info!(target: "audit", actor = %admin.sub, action, target, outcome);
}

/// A user as admin views list it. Fields are listed, not `Identity` flattened, so a new
/// Kratos or database field reaches clients only by decision: the exhaustive
/// destructuring in `from` stops compiling until the new field is placed or ignored.
#[derive(Debug, Serialize)]
struct UserResponse {
    id: Uuid,
    /// From Kratos, the source of truth (`null` only for an identity without one).
    email: Option<String>,
    /// `active` or `inactive` (deactivated).
    state: String,
    verified: bool,
    created_at: String,
    /// This service's data; `null` if the user has none yet.
    data: Option<StoredUser>,
}

impl From<ListedUser> for UserResponse {
    fn from(ListedUser { identity, stored }: ListedUser) -> Self {
        let verified = identity.verified();
        let Identity {
            id,
            traits,
            state,
            verifiable_addresses: _,
            created_at,
            credentials: _,
        } = identity;
        Self {
            id,
            email: traits.email,
            state,
            verified,
            created_at,
            data: stored.map(StoredUser::from),
        }
    }
}

#[derive(Debug, Serialize)]
struct UserDetailsResponse {
    #[serde(flatten)]
    user: UserResponse,
    /// Credential types the user can log in with: `password`, `oidc`, `passkey`, `totp`...
    login_methods: Vec<String>,
    active_sessions: usize,
}

impl From<UserDetails> for UserDetailsResponse {
    fn from(details: UserDetails) -> Self {
        let UserDetails {
            user,
            raw_identity: _,
            active_sessions,
        } = details;
        Self {
            login_methods: user.identity.credentials.keys().cloned().collect(),
            user: user.into(),
            active_sessions,
        }
    }
}

#[derive(Debug, Serialize)]
struct UsersResponse {
    users: Vec<UserResponse>,
    /// Pass as `page_token` for the next page; `null` on the last one.
    next_page_token: Option<String>,
}

impl From<UsersPage> for UsersResponse {
    fn from(
        UsersPage {
            users,
            next_page_token,
        }: UsersPage,
    ) -> Self {
        Self {
            users: users.into_iter().map(Into::into).collect(),
            next_page_token,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    email: Option<String>,
    page_size: Option<u16>,
    page_token: Option<String>,
}

/// `GET /users`: a page of users, or with `?email=` every user with that email.
async fn list<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppQuery(query): AppQuery<ListQuery>,
) -> Result<Json<UsersResponse>, AppError> {
    let ListQuery {
        email,
        page_size,
        page_token,
    } = query;
    if let Some(email) = email {
        if page_size.is_some() || page_token.is_some() {
            return Err(AppError::BadRequest(
                "`email` is a lookup and can't be combined with paging".into(),
            ));
        }
        let email: Email = email
            .parse()
            .map_err(|err| AppError::BadRequest(format!("email: {err}")))?;
        let result = directory.with_email(&email).await;
        audit(&admin, "find_by_email", None, &result);
        let users = result?.into_iter().map(Into::into).collect();
        return Ok(Json(UsersResponse {
            users,
            next_page_token: None,
        }));
    }
    let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(AppError::BadRequest(format!(
            "page_size must be between 1 and {MAX_PAGE_SIZE}"
        )));
    }
    let result = directory.page(page_size, page_token.as_deref()).await;
    audit(&admin, "list_users", None, &result);
    Ok(Json(result?.into()))
}

async fn show<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppPath(id): AppPath<Uuid>,
) -> Result<Json<UserDetailsResponse>, AppError> {
    let result = directory.details(id).await;
    audit(&admin, "show_user", Some(id), &result);
    Ok(Json(result?.into()))
}

#[derive(Debug, Deserialize)]
struct InviteRequest {
    email: Email,
}

/// Secrets: sent once, to the admin, never stored or logged by us, and not cacheable.
#[derive(Serialize)]
struct RecoveryResponse {
    recovery_link: String,
    recovery_code: String,
    expires_at: Option<String>,
}

impl From<RecoveryCode> for RecoveryResponse {
    fn from(code: RecoveryCode) -> Self {
        let RecoveryCode {
            recovery_link,
            recovery_code,
            expires_at,
        } = code;
        Self {
            recovery_link,
            recovery_code,
            expires_at,
        }
    }
}

const NO_STORE: [(header::HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];

#[derive(Serialize)]
struct InviteResponse {
    user: UserResponse,
    recovery: RecoveryResponse,
}

/// `POST /users`: creates a user with no password and returns a recovery link + code for
/// the admin to send. Creating users with a password is CLI-only (`add-user`, for dev
/// seeding): an admin should never know a user's password.
async fn invite<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppJson(body): AppJson<InviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result = directory.invite(&body.email).await;
    let target = result.as_ref().ok().map(|invited| invited.user.identity.id);
    audit(&admin, "invite_user", target, &result);
    let Invited { user, recovery } = result?;
    let response = InviteResponse {
        user: user.into(),
        recovery: recovery.into(),
    };
    Ok((StatusCode::CREATED, NO_STORE, Json(response)))
}

#[derive(Debug, Serialize)]
struct RolesResponse {
    roles: Vec<Role>,
}

/// `PUT`: idempotent, granting a role the user has is fine.
async fn grant_role<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppPath((id, role)): AppPath<(Uuid, Role)>,
) -> Result<Json<RolesResponse>, AppError> {
    let result = directory.grant_role(id, role).await;
    audit(&admin, grant_action(role), Some(id), &result);
    Ok(Json(RolesResponse {
        roles: result?.roles,
    }))
}

async fn revoke_role<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppPath((id, role)): AppPath<(Uuid, Role)>,
) -> Result<Json<RolesResponse>, AppError> {
    let result = directory
        .revoke_role(Actor::Admin(admin.sub), id, role)
        .await;
    audit(&admin, revoke_action(role), Some(id), &result);
    Ok(Json(RolesResponse {
        roles: result?.roles,
    }))
}

fn grant_action(role: Role) -> &'static str {
    match role {
        Role::Admin => "grant_role:admin",
        Role::User => "grant_role:user",
    }
}

fn revoke_action(role: Role) -> &'static str {
    match role {
        Role::Admin => "revoke_role:admin",
        Role::User => "revoke_role:user",
    }
}

async fn deactivate<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppPath(id): AppPath<Uuid>,
) -> Result<StatusCode, AppError> {
    let result = directory.deactivate(Actor::Admin(admin.sub), id).await;
    audit(&admin, "deactivate", Some(id), &result);
    result?;
    Ok(StatusCode::NO_CONTENT)
}

async fn activate<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppPath(id): AppPath<Uuid>,
) -> Result<StatusCode, AppError> {
    let result = directory
        .accounts()
        .set_state(id, IdentityState::Active)
        .await;
    audit(&admin, "activate", Some(id), &result);
    result?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_sessions<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppPath(id): AppPath<Uuid>,
) -> Result<StatusCode, AppError> {
    let result = directory.accounts().revoke_sessions(id).await;
    audit(&admin, "revoke_sessions", Some(id), &result);
    result?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST`: every call mints a new code.
async fn recover<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppPath(id): AppPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let result = directory.accounts().recovery_code(id).await;
    audit(&admin, "recovery_code", Some(id), &result);
    Ok((NO_STORE, Json(RecoveryResponse::from(result?))))
}

/// Deleting again after a partial failure (`internal`) finishes the job.
async fn delete_user<K: IdentityAdmin>(
    State(directory): Dir<K>,
    admin: AdminClaims,
    AppPath(id): AppPath<Uuid>,
) -> Result<StatusCode, AppError> {
    let result = directory.delete(Actor::Admin(admin.sub), id).await;
    audit(&admin, "delete_user", Some(id), &result);
    result?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{HeaderMap, Method, Request};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::directory::fake::{FakeIdentity, FakeKratos, Op};
    use crate::{db, testing};

    struct Fixture {
        db: PgPool,
        kratos: FakeKratos,
        admin: Uuid,
    }

    struct Response {
        status: StatusCode,
        headers: HeaderMap,
        body: Value,
    }

    impl Fixture {
        /// One admin to act as.
        async fn new(db: PgPool) -> Self {
            let kratos = FakeKratos::default();
            let mut fixture = Self {
                db,
                kratos,
                admin: Uuid::nil(),
            };
            fixture.admin = fixture.user("admin@example.com").await;
            db::grant_role(&fixture.db, fixture.admin, Role::Admin)
                .await
                .unwrap();
            fixture
        }

        /// A user with a Kratos identity and a row.
        async fn user(&self, email: &str) -> Uuid {
            let id = self.kratos.add(FakeIdentity::new(email));
            db::sync_identity(&self.db, &testing::identity(id, email))
                .await
                .unwrap();
            id
        }

        async fn call(
            &self,
            actor: Option<Uuid>,
            method: Method,
            path: &str,
            body: Option<Value>,
        ) -> Response {
            let app = router(AdminState {
                db: self.db.clone(),
                verifier: Arc::new(testing::verifier()),
                directory: Arc::new(Directory::new(self.db.clone(), self.kratos.clone())),
            });
            let mut req = Request::builder().method(method).uri(path);
            if let Some(sub) = actor {
                let token = testing::token(json!({ "sub": sub }));
                req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let req = match body {
                Some(body) => req
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string())),
                None => req.body(Body::empty()),
            };
            let res = app.oneshot(req.unwrap()).await.unwrap();
            let (status, headers) = (res.status(), res.headers().clone());
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            Response {
                status,
                headers,
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            }
        }

        async fn as_admin(&self, method: Method, path: &str) -> Response {
            self.call(Some(self.admin), method, path, None).await
        }
    }

    fn routes(id: Uuid) -> Vec<(Method, String)> {
        let user = format!("/api/admin/users/{id}");
        vec![
            (Method::GET, "/api/admin/users".into()),
            (Method::POST, "/api/admin/users".into()),
            (Method::GET, user.clone()),
            (Method::DELETE, user.clone()),
            (Method::PUT, format!("{user}/roles/admin")),
            (Method::DELETE, format!("{user}/roles/user")),
            (Method::POST, format!("{user}/deactivate")),
            (Method::POST, format!("{user}/activate")),
            (Method::DELETE, format!("{user}/sessions")),
            (Method::POST, format!("{user}/recovery")),
        ]
    }

    #[sqlx::test]
    async fn every_route_requires_the_admin_role(db: PgPool) {
        let f = Fixture::new(db).await;
        let user = f.user("ada@example.com").await;
        let body = json!({ "email": "new@example.com" });

        for (method, path) in routes(user) {
            let res = f
                .call(None, method.clone(), &path, Some(body.clone()))
                .await;
            assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{method} {path}");
            assert_eq!(res.body["error"]["code"], "unauthorized");

            let res = f
                .call(Some(user), method.clone(), &path, Some(body.clone()))
                .await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{method} {path}");
            assert_eq!(res.body["error"]["code"], "forbidden");
        }
        // Nothing happened.
        assert_eq!(f.kratos.get(user).unwrap().state, IdentityState::Active);
        assert!(f.kratos.get_by_email("new@example.com").is_none());
        assert_eq!(db::roles_of(&f.db, user).await.unwrap(), vec![Role::User]);
    }

    #[sqlx::test]
    async fn lists_users_page_by_page(db: PgPool) {
        let f = Fixture::new(db).await;
        f.user("ada@example.com").await;
        let no_row = f.kratos.add(FakeIdentity::new("bob@example.com"));

        let first = f
            .as_admin(Method::GET, "/api/admin/users?page_size=2")
            .await;
        assert_eq!(first.status, StatusCode::OK);
        assert_eq!(first.body["users"].as_array().unwrap().len(), 2);
        let token = first.body["next_page_token"].as_str().unwrap();

        let second = f
            .as_admin(
                Method::GET,
                &format!("/api/admin/users?page_size=2&page_token={token}"),
            )
            .await;
        let rest = second.body["users"].as_array().unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(second.body["next_page_token"], Value::Null);

        let all: Vec<Value> = [first.body["users"].as_array().unwrap(), rest]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        let bob = all.iter().find(|u| u["id"] == json!(no_row)).unwrap();
        assert_eq!(
            bob,
            &json!({
                "id": no_row,
                "email": "bob@example.com",
                "state": "active",
                "verified": true,
                "created_at": "2026-01-02T03:04:05.000000Z",
                "data": null,
            })
        );
        let admin = all.iter().find(|u| u["id"] == json!(f.admin)).unwrap();
        assert_eq!(admin["data"]["roles"], json!(["admin", "user"]));
        assert_eq!(admin["data"]["display_name"], Value::Null);
    }

    #[sqlx::test]
    async fn rejects_bad_listing_queries(db: PgPool) {
        let f = Fixture::new(db).await;
        for query in [
            "page_size=0",
            "page_size=251",
            "page_size=lots",
            "email=nope",
            "email=ada@example.com&page_size=2",
            "page_token=crafted",
        ] {
            let res = f
                .as_admin(Method::GET, &format!("/api/admin/users?{query}"))
                .await;
            assert_eq!(res.status, StatusCode::BAD_REQUEST, "{query}");
            assert_eq!(res.body["error"]["code"], "bad_request", "{query}");
        }
    }

    #[sqlx::test]
    async fn looks_users_up_by_email(db: PgPool) {
        let f = Fixture::new(db).await;
        let ada = f.user("ada@example.com").await;

        let res = f
            .as_admin(Method::GET, "/api/admin/users?email=Ada@Example.com")
            .await;
        assert_eq!(res.status, StatusCode::OK);
        assert_eq!(res.body["users"][0]["id"], json!(ada));
        assert_eq!(res.body["users"].as_array().unwrap().len(), 1);

        let res = f
            .as_admin(Method::GET, "/api/admin/users?email=nobody@example.com")
            .await;
        assert_eq!(res.body, json!({ "users": [], "next_page_token": null }));
    }

    #[sqlx::test]
    async fn shows_one_user(db: PgPool) {
        let f = Fixture::new(db).await;
        let ada = f.user("ada@example.com").await;

        let res = f
            .as_admin(Method::GET, &format!("/api/admin/users/{ada}"))
            .await;
        assert_eq!(res.status, StatusCode::OK);
        assert_eq!(res.body["email"], "ada@example.com");
        assert_eq!(res.body["data"]["roles"], json!(["user"]));
        assert_eq!(res.body["login_methods"], json!([]));
        assert_eq!(res.body["active_sessions"], 0);

        let res = f
            .as_admin(Method::GET, &format!("/api/admin/users/{}", Uuid::new_v4()))
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND);
        assert_eq!(res.body["error"]["code"], "not_found");

        let res = f.as_admin(Method::GET, "/api/admin/users/not-a-uuid").await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert_eq!(res.body["error"]["code"], "bad_request");
    }

    #[sqlx::test]
    async fn invites_a_user(db: PgPool) {
        let f = Fixture::new(db).await;
        let invite = |email: &str| {
            f.call(
                Some(f.admin),
                Method::POST,
                "/api/admin/users",
                Some(json!({ "email": email })),
            )
        };

        let res = invite(" Ada@Example.com").await;
        assert_eq!(res.status, StatusCode::CREATED);
        assert_eq!(res.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(res.body["user"]["email"], "ada@example.com");
        assert_eq!(res.body["user"]["data"]["roles"], json!(["user"]));
        assert_eq!(res.body["recovery"]["recovery_code"], "123456");
        assert!(res.body["recovery"]["recovery_link"].is_string());
        assert!(res.body["recovery"]["expires_at"].is_string());
        let id: Uuid = serde_json::from_value(res.body["user"]["id"].clone()).unwrap();
        assert_eq!(f.kratos.get(id).unwrap().password, None);

        let res = invite("ada@example.com").await;
        assert_eq!(res.status, StatusCode::CONFLICT);
        assert_eq!(res.body["error"]["code"], "conflict");
        assert_eq!(
            res.body["error"]["message"],
            "An identity with the same identifier already exists."
        );

        let res = invite("nope").await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(res.body["error"]["code"], "invalid_body");
    }

    #[sqlx::test]
    async fn grants_and_revokes_roles(db: PgPool) {
        let f = Fixture::new(db).await;
        let ada = f.user("ada@example.com").await;
        let roles = format!("/api/admin/users/{ada}/roles");

        for _ in 0..2 {
            let res = f.as_admin(Method::PUT, &format!("{roles}/admin")).await;
            assert_eq!(res.status, StatusCode::OK);
            assert_eq!(res.body, json!({ "roles": ["admin", "user"] }));
        }
        let res = f.as_admin(Method::DELETE, &format!("{roles}/admin")).await;
        assert_eq!(res.body, json!({ "roles": ["user"] }));

        let res = f.as_admin(Method::PUT, &format!("{roles}/superuser")).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);

        let mine = format!("/api/admin/users/{}/roles/admin", f.admin);
        let res = f.as_admin(Method::DELETE, &mine).await;
        assert_eq!(res.status, StatusCode::CONFLICT);
        assert_eq!(res.body["error"]["code"], "self_action");
    }

    #[sqlx::test]
    async fn deactivates_and_activates(db: PgPool) {
        let f = Fixture::new(db).await;
        let ada = f.user("ada@example.com").await;
        let user = format!("/api/admin/users/{ada}");

        let res = f
            .as_admin(Method::POST, &format!("{user}/deactivate"))
            .await;
        assert_eq!(res.status, StatusCode::NO_CONTENT);
        assert_eq!(f.kratos.get(ada).unwrap().state, IdentityState::Inactive);
        let res = f.as_admin(Method::POST, &format!("{user}/activate")).await;
        assert_eq!(res.status, StatusCode::NO_CONTENT);
        assert_eq!(f.kratos.get(ada).unwrap().state, IdentityState::Active);

        let mine = format!("/api/admin/users/{}/deactivate", f.admin);
        let res = f.as_admin(Method::POST, &mine).await;
        assert_eq!(res.body["error"]["code"], "self_action");
    }

    #[sqlx::test]
    async fn revokes_sessions_and_mints_recovery_codes(db: PgPool) {
        let f = Fixture::new(db).await;
        let ada = f.kratos.add(FakeIdentity {
            sessions: 3,
            ..FakeIdentity::new("ada@example.com")
        });
        let user = format!("/api/admin/users/{ada}");

        let res = f
            .as_admin(Method::DELETE, &format!("{user}/sessions"))
            .await;
        assert_eq!(res.status, StatusCode::NO_CONTENT);
        assert_eq!(f.kratos.get(ada).unwrap().sessions, 0);

        let res = f.as_admin(Method::POST, &format!("{user}/recovery")).await;
        assert_eq!(res.status, StatusCode::OK);
        assert_eq!(res.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(res.body["recovery_code"], "123456");

        f.kratos.fail(Op::Recovery);
        let res = f.as_admin(Method::POST, &format!("{user}/recovery")).await;
        assert_eq!(res.status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            res.body["error"],
            json!({ "code": "kratos_error", "message": "internal error" })
        );
    }

    #[sqlx::test]
    async fn deletes_users_but_not_yourself_or_the_last_admin(db: PgPool) {
        let f = Fixture::new(db).await;
        let ada = f.user("ada@example.com").await;

        let res = f
            .as_admin(Method::DELETE, &format!("/api/admin/users/{ada}"))
            .await;
        assert_eq!(res.status, StatusCode::NO_CONTENT);
        assert!(f.kratos.get(ada).is_none());
        let res = f
            .as_admin(Method::DELETE, &format!("/api/admin/users/{ada}"))
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND);

        let res = f
            .as_admin(Method::DELETE, &format!("/api/admin/users/{}", f.admin))
            .await;
        assert_eq!(res.body["error"]["code"], "self_action");

        // An admin whose own account was just deactivated can't remove the only
        // active admin left.
        let bob = f.user("bob@example.com").await;
        db::grant_role(&f.db, bob, Role::Admin).await.unwrap();
        f.kratos.fail(Op::Delete); // not reached: the guard refuses first
        Directory::new(f.db.clone(), f.kratos.clone())
            .accounts()
            .set_state(bob, IdentityState::Inactive)
            .await
            .unwrap();
        let res = f
            .call(
                Some(bob),
                Method::DELETE,
                &format!("/api/admin/users/{}", f.admin),
                None,
            )
            .await;
        assert_eq!(res.status, StatusCode::CONFLICT);
        assert_eq!(res.body["error"]["code"], "last_admin");
    }
}
