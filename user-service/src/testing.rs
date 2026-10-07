//! Plumbing shared by the router tests.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

use crate::auth::testing;
use crate::state::{ApiState, HydrateState};

pub fn api_state(db: PgPool) -> ApiState {
    ApiState {
        db,
        verifier: Arc::new(testing::verifier()),
    }
}

pub fn hydrate_state(db: PgPool, password: &str) -> HydrateState {
    HydrateState {
        db,
        password: password.into(),
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
