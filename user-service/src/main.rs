mod api;
mod auth;
mod cli;
mod config;
mod db;
mod error;
mod hydrate;
mod kratos;
mod models;
mod state;
#[cfg(test)]
mod testing;

use std::sync::Arc;

use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::auth::JwtVerifier;
use crate::config::Config;
use crate::state::{ApiState, HydrateState};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,user_service=debug,sqlx=warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    // Only the server needs worker threads: the one-shot subcommands (the healthcheck
    // runs every 30s for the container's life) get a single-threaded runtime.
    let mut runtime = match args.as_slice() {
        [] | ["serve"] => tokio::runtime::Builder::new_multi_thread(),
        _ => tokio::runtime::Builder::new_current_thread(),
    };
    runtime.enable_all().build()?.block_on(run(&args))
}

async fn run(args: &[&str]) -> anyhow::Result<()> {
    match args {
        [] | ["serve"] => serve().await,
        ["migrate"] => cli::migrate().await,
        ["healthcheck"] => cli::healthcheck().await,
        ["grant-role", email, role] => cli::grant_role(email, role).await,
        ["revoke-role", email, role] => cli::revoke_role(email, role).await,
        ["forget-user", email_or_id] => cli::forget_user(email_or_id).await,
        _ => {
            eprintln!("{}", cli::USAGE);
            std::process::exit(2);
        }
    }
}

async fn serve() -> anyhow::Result<()> {
    let config = Config::from_env()?;

    let db = config::connect_pool(&config.database_url).await?;
    // No migrations here: the one-shot `user-service migrate` job runs them before
    // this starts (see docker-compose.yml), so serving never needs DDL rights.

    let http = config::http_client()?;
    let api_state = ApiState {
        db: db.clone(),
        verifier: Arc::new(JwtVerifier::remote(
            config.jwks_url,
            config.jwt_issuer,
            http,
        )),
    };
    let hydrate_state = HydrateState {
        db,
        password: config.hydrator_password.into(),
    };

    // Two listeners: Oathkeeper routes only to the public one, so the internal
    // endpoint is unreachable from outside regardless of path rules.
    // TraceLayer's default spans log method + path only, never headers (the hydrator
    // receives the raw Kratos session cookie).
    let public = axum::serve(
        TcpListener::bind(config.public_addr).await?,
        api::router(api_state).layer(TraceLayer::new_for_http()),
    )
    .with_graceful_shutdown(shutdown_signal());
    let internal = axum::serve(
        TcpListener::bind(config.internal_addr).await?,
        hydrate::router(hydrate_state).layer(TraceLayer::new_for_http()),
    )
    .with_graceful_shutdown(shutdown_signal());

    tracing::info!(public = %config.public_addr, internal = %config.internal_addr, "listening");
    tokio::try_join!(public.into_future(), internal.into_future())?;
    Ok(())
}

/// Ctrl-C locally, SIGTERM from `docker stop`.
async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("ctrl-c handler") };
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm handler")
            .recv()
            .await;
    };
    tokio::select! {
        () = ctrl_c => {},
        () = sigterm => {},
    }
    tracing::info!("shutting down");
}
