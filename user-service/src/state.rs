use std::sync::Arc;

use sqlx::PgPool;

use crate::auth::JwtVerifier;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub verifier: Arc<JwtVerifier>,
    pub hydrator_password: Arc<str>,
}
