use std::sync::Arc;

use sqlx::PgPool;

use crate::auth::JwtVerifier;

/// State of the public router: what it needs to verify a JWT and read the user.
#[derive(Clone)]
pub struct ApiState {
    pub db: PgPool,
    pub verifier: Arc<JwtVerifier>,
}

/// State of the internal router: the database and the hydrator's Basic password.
#[derive(Clone)]
pub struct HydrateState {
    pub db: PgPool,
    pub password: Arc<str>,
}
