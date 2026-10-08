//! The command line: `serve`, the one-shot `migrate` and `healthcheck`, and the user-admin
//! commands (bodies in `admin.rs`). Admin commands run inside the container:
//! `docker compose exec user-service /user-service grant-role me@x.com admin`.
//! Granting roles needs no admin API, which avoids the "who grants the first admin" problem.

use std::str::FromStr;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::config::{self, Database, KratosAdmin, PublicAddr, ServeConfig};
use crate::models::{Email, EmailError, Role};
use crate::{admin, db, server};

#[derive(Parser)]
#[command(
    version,
    about = "Owns user data (profile, roles), keyed by the Kratos identity id"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Serve the public API and the internal hydrator endpoint.
    Serve(ServeConfig),
    /// Apply pending migrations, then exit.
    Migrate {
        #[command(flatten)]
        database: Database,
    },
    /// Exit 0 if the local server answers `/health` (the image has no curl).
    Healthcheck {
        #[command(flatten)]
        public: PublicAddr,
    },
    /// List every user: Kratos identity, login state, verification, roles.
    Users {
        #[command(flatten)]
        database: Database,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Show one user as JSON: the full Kratos identity, active sessions, this service's data.
    User {
        email: Email,
        #[command(flatten)]
        database: Database,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Create a user with a password and an already-verified email (dev seeding).
    AddUser {
        email: Email,
        password: String,
        #[command(flatten)]
        database: Database,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Grant a role to the Kratos identity with this email.
    GrantRole {
        email: Email,
        role: Role,
        #[command(flatten)]
        database: Database,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Revoke a role from the Kratos identity with this email.
    RevokeRole {
        email: Email,
        role: Role,
        #[command(flatten)]
        database: Database,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Log a user out everywhere: delete all their sessions.
    RevokeSessions {
        email: Email,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Block a user: their sessions stop working at once and login is refused.
    Deactivate {
        email: Email,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Unblock a deactivated user (their suspended sessions work again).
    Activate {
        email: Email,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Print a one-hour account recovery link and code to send to the user.
    Recover {
        email: Email,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Delete a user for good: the Kratos identity, then this service's data.
    DeleteUser {
        email: Email,
        #[command(flatten)]
        database: Database,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
    /// Delete only this service's data for a user (e.g. left over after a failed `delete-user`).
    ForgetUser {
        /// An email (looked up in Kratos) or a Kratos identity id.
        target: EmailOrId,
        #[command(flatten)]
        database: Database,
        #[command(flatten)]
        kratos_admin: KratosAdmin,
    },
}

#[derive(Clone)]
pub enum EmailOrId {
    Email(Email),
    Id(Uuid),
}

impl FromStr for EmailOrId {
    type Err = EmailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse() {
            Ok(id) => Ok(Self::Id(id)),
            Err(_) => s.parse().map(Self::Email),
        }
    }
}

impl Command {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Serve(config) => server::serve(config).await,
            Self::Migrate { database } => migrate(&database).await,
            Self::Healthcheck { public } => healthcheck(&public).await,
            Self::Users {
                database,
                kratos_admin,
            } => admin::users(&database, &kratos_admin).await,
            Self::User {
                email,
                database,
                kratos_admin,
            } => admin::user(&email, &database, &kratos_admin).await,
            Self::AddUser {
                email,
                password,
                database,
                kratos_admin,
            } => admin::add_user(&email, &password, &database, &kratos_admin).await,
            Self::GrantRole {
                email,
                role,
                database,
                kratos_admin,
            } => admin::grant_role(&email, role, &database, &kratos_admin).await,
            Self::RevokeRole {
                email,
                role,
                database,
                kratos_admin,
            } => admin::revoke_role(&email, role, &database, &kratos_admin).await,
            Self::RevokeSessions {
                email,
                kratos_admin,
            } => admin::revoke_sessions(&email, &kratos_admin).await,
            Self::Deactivate {
                email,
                kratos_admin,
            } => admin::deactivate(&email, &kratos_admin).await,
            Self::Activate {
                email,
                kratos_admin,
            } => admin::activate(&email, &kratos_admin).await,
            Self::Recover {
                email,
                kratos_admin,
            } => admin::recover(&email, &kratos_admin).await,
            Self::DeleteUser {
                email,
                database,
                kratos_admin,
            } => admin::delete_user(&email, &database, &kratos_admin).await,
            Self::ForgetUser {
                target,
                database,
                kratos_admin,
            } => admin::forget_user(&target, &database, &kratos_admin).await,
        }
    }
}

/// Applies pending migrations (embedded in the binary at compile time) and exits.
/// Run as a one-shot job before `serve`; sqlx takes a Postgres advisory lock, so
/// concurrent runs are safe.
async fn migrate(database: &Database) -> anyhow::Result<()> {
    let db = db::connect(database).await?;
    let migrator = sqlx::migrate!();
    migrator.run(&db).await.context("running migrations")?;
    let latest = migrator.iter().map(|m| m.version).max().unwrap_or(0);
    println!("migrations up to date (latest version: {latest})");
    Ok(())
}

/// Docker healthcheck: the image is `FROM scratch`, so there's no curl/wget to use.
async fn healthcheck(public: &PublicAddr) -> anyhow::Result<()> {
    let port = public.addr.port();
    let res = config::http_client()?
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await?;
    if !res.status().is_success() {
        bail!("unhealthy: {}", res.status());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_line_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_typed_arguments() {
        let cli = Cli::try_parse_from([
            "user-service",
            "grant-role",
            " Ada@Example.com",
            "admin",
            "--database-url",
            "postgres://example",
        ])
        .unwrap();
        let Command::GrantRole { email, role, .. } = cli.command else {
            panic!("expected grant-role");
        };
        assert_eq!(email.as_ref(), "ada@example.com");
        assert_eq!(role, Role::Admin);

        let args = |email, role| {
            Cli::try_parse_from([
                "user-service",
                "grant-role",
                email,
                role,
                "--database-url",
                "x",
            ])
        };
        assert!(args("nope", "admin").is_err());
        assert!(args("a@b.c", "superuser").is_err());
    }

    #[test]
    fn kratos_only_commands_need_no_database() {
        for command in ["revoke-sessions", "deactivate", "activate", "recover"] {
            let cli = Cli::try_parse_from(["user-service", command, "Ada@Example.com"]);
            assert!(cli.is_ok(), "{command}");
        }
        let cli = Cli::try_parse_from([
            "user-service",
            "add-user",
            "ada@example.com",
            "S3cret pass!",
            "--database-url",
            "x",
        ])
        .unwrap();
        let Command::AddUser { password, .. } = cli.command else {
            panic!("expected add-user");
        };
        assert_eq!(password, "S3cret pass!");
    }

    #[test]
    fn forget_user_takes_an_email_or_an_id() {
        let id = Uuid::new_v4();
        assert!(matches!(id.to_string().parse(), Ok(EmailOrId::Id(parsed)) if parsed == id));
        assert!(matches!(
            "ada@example.com".parse::<EmailOrId>(),
            Ok(EmailOrId::Email(_))
        ));
        assert!("neither".parse::<EmailOrId>().is_err());
    }
}
