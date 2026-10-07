use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

const DEFAULT_PUBLIC_ADDR: &str = "0.0.0.0:3000";
const DEFAULT_INTERNAL_ADDR: &str = "0.0.0.0:3001";
const DEFAULT_KRATOS_ADMIN_URL: &str = "http://kratos:4434";

pub struct Config {
    pub database_url: String,
    /// Basic-auth password Oathkeeper uses for `/internal/hydrate`.
    pub hydrator_password: String,
    pub jwks_url: String,
    pub jwt_issuer: String,
    /// Routed through Oathkeeper: `/api/users/**`.
    pub public_addr: SocketAddr,
    /// Never routed through Oathkeeper: `/internal/hydrate`.
    pub internal_addr: SocketAddr,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            hydrator_password: required("HYDRATOR_PASSWORD")?,
            jwks_url: optional("JWKS_URL", "http://oathkeeper:4456/.well-known/jwks.json"),
            jwt_issuer: optional("JWT_ISSUER", "http://localhost:8080/"),
            public_addr: public_addr()?,
            internal_addr: socket_addr("INTERNAL_ADDR", DEFAULT_INTERNAL_ADDR)?,
        })
    }
}

pub fn required(name: &str) -> anyhow::Result<String> {
    env::var(name).with_context(|| format!("missing environment variable {name}"))
}

pub fn optional(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn socket_addr(name: &str, default: &str) -> anyhow::Result<SocketAddr> {
    let raw = optional(name, default);
    raw.parse()
        .with_context(|| format!("{name} must be an ip:port address, got {raw:?}"))
}

/// Shared with `healthcheck`, which only needs the port.
pub fn public_addr() -> anyhow::Result<SocketAddr> {
    socket_addr("PUBLIC_ADDR", DEFAULT_PUBLIC_ADDR)
}

pub fn kratos_admin_url() -> String {
    optional("KRATOS_ADMIN_URL", DEFAULT_KRATOS_ADMIN_URL)
}

pub async fn connect_pool(database_url: &str) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .context("connecting to the database")
}

pub fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?)
}
