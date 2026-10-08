mod admin;
mod admin_api;
mod api;
mod auth;
mod cli;
mod config;
mod db;
mod directory;
mod error;
mod hydrate;
mod kratos;
mod models;
mod server;
#[cfg(test)]
mod testing;
mod webhook;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,user_service=debug,sqlx=warn".into()),
        )
        .init();

    let command = Cli::parse().command;

    // Only the server needs worker threads: the one-shot subcommands (the healthcheck
    // runs every 30s for the container's life) get a single-threaded runtime.
    let mut runtime = if matches!(command, Command::Serve(_)) {
        tokio::runtime::Builder::new_multi_thread()
    } else {
        tokio::runtime::Builder::new_current_thread()
    };
    runtime.enable_all().build()?.block_on(command.run())
}
