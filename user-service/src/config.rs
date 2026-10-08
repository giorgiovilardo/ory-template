//! Settings shared by the subcommands, as clap argument groups: each subcommand
//! flattens in exactly the ones it needs. Every setting is a flag that falls back to
//! an environment variable (the flag wins), and `--help` lists both. Secrets have their
//! values hidden from `--help`.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Args;

#[derive(Args)]
pub struct Database {
    #[arg(
        id = "database_url",
        value_name = "URL",
        long = "database-url",
        env = "DATABASE_URL",
        hide_env_values = true
    )]
    pub url: String,
    /// Connection pool size.
    #[arg(
        id = "db_max_connections",
        value_name = "N",
        long = "db-max-connections",
        env = "DB_MAX_CONNECTIONS",
        default_value_t = 10
    )]
    pub max_connections: u32,
}

#[derive(Args)]
pub struct KratosAdmin {
    #[arg(
        id = "kratos_admin_url",
        value_name = "URL",
        long = "kratos-admin-url",
        env = "KRATOS_ADMIN_URL",
        default_value = "http://kratos:4434"
    )]
    pub url: String,
}

/// Shared with `healthcheck`, which probes it.
#[derive(Args)]
pub struct PublicAddr {
    /// Routed through Oathkeeper: `/api/users/**`.
    #[arg(
        id = "public_addr",
        value_name = "ADDR",
        long = "public-addr",
        env = "PUBLIC_ADDR",
        default_value = "0.0.0.0:3000"
    )]
    pub addr: SocketAddr,
}

#[derive(Args)]
pub struct ServeConfig {
    #[command(flatten)]
    pub database: Database,
    /// The admin API acts on Kratos identities through it.
    #[command(flatten)]
    pub kratos_admin: KratosAdmin,
    /// Basic-auth password Oathkeeper uses for `/internal/hydrate`.
    #[arg(long, env = "HYDRATOR_PASSWORD", hide_env_values = true)]
    pub hydrator_password: String,
    #[arg(
        long,
        env = "JWKS_URL",
        default_value = "http://oathkeeper:4456/.well-known/jwks.json"
    )]
    pub jwks_url: String,
    #[arg(long, env = "JWT_ISSUER", default_value = "http://localhost:8080/")]
    pub jwt_issuer: String,
    #[command(flatten)]
    pub public: PublicAddr,
    /// Never routed through Oathkeeper: `/internal/hydrate`.
    #[arg(long, env = "INTERNAL_ADDR", default_value = "0.0.0.0:3001")]
    pub internal_addr: SocketAddr,
}

pub fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?)
}
