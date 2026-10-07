use std::env;

use anyhow::Context;

pub struct Config {
    pub database_url: String,
    /// Basic-auth password Oathkeeper uses for `/internal/hydrate`.
    pub hydrator_password: String,
    pub jwks_url: String,
    pub jwt_issuer: String,
    /// Routed through Oathkeeper: `/api/users/**`.
    pub public_addr: String,
    /// Never routed through Oathkeeper: `/internal/hydrate`.
    pub internal_addr: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            hydrator_password: required("HYDRATOR_PASSWORD")?,
            jwks_url: optional("JWKS_URL", "http://oathkeeper:4456/.well-known/jwks.json"),
            jwt_issuer: optional("JWT_ISSUER", "http://localhost:8080/"),
            public_addr: optional("PUBLIC_ADDR", "0.0.0.0:3000"),
            internal_addr: optional("INTERNAL_ADDR", "0.0.0.0:3001"),
        })
    }
}

pub fn required(name: &str) -> anyhow::Result<String> {
    env::var(name).with_context(|| format!("missing environment variable {name}"))
}

pub fn optional(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}
