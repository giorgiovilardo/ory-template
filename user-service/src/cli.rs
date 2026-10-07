//! The command line. Admin subcommands run inside the container:
//! `docker compose exec user-service /user-service grant-role me@x.com admin`.
//! Granting roles needs no admin API, which avoids the "who grants the first admin" problem.

use std::str::FromStr;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::{self, Database, KratosAdmin, PublicAddr, ServeConfig};
use crate::models::{Email, EmailError, Role};
use crate::{db, kratos, server};

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
    /// Exit 0 if the local server answers `/healthz` (the image has no curl).
    Healthcheck {
        #[command(flatten)]
        public: PublicAddr,
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
    /// Delete this service's data for a user (Kratos deletion is separate).
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
            Self::GrantRole {
                email,
                role,
                database,
                kratos_admin,
            } => grant_role(&email, role, &database, &kratos_admin).await,
            Self::RevokeRole {
                email,
                role,
                database,
                kratos_admin,
            } => revoke_role(&email, role, &database, &kratos_admin).await,
            Self::ForgetUser {
                target,
                database,
                kratos_admin,
            } => forget_user(&target, &database, &kratos_admin).await,
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

/// Finds the Kratos identity that logs in with this email. Kratos is the only
/// reliable email -> id mapping: our `users.email` is a copy that is neither unique
/// nor current (it's refreshed only when the user makes a request), so matching on
/// it can pick another account or miss the right one.
async fn identity_for(
    email: &Email,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<kratos::KratosIdentity> {
    kratos::find_identity_by_email(&config::http_client()?, &kratos_admin.url, email)
        .await
        .context("looking up the user in Kratos")?
        .with_context(|| format!("no Kratos identity with email {email}"))
}

async fn grant_role(
    email: &Email,
    role: Role,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let identity = identity_for(email, kratos_admin).await?;
    let db = db::connect(database).await?;
    // Creates the row for users who registered but never made a request through
    // Oathkeeper, and refreshes a stale email copy.
    let id = identity.id;
    db::sync_identity(&db, &identity).await?;
    if db::grant_role(&db, id, role).await? {
        println!("{email} ({id}): granted {role}");
    } else {
        println!("{email} ({id}): already has {role}");
    }
    print_roles(&db, id).await
}

async fn revoke_role(
    email: &Email,
    role: Role,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let id = identity_for(email, kratos_admin).await?.id;
    let db = db::connect(database).await?;
    if db::find_by_id(&db, id).await?.is_none() {
        bail!("{email} ({id}) has no user-service data, so no roles");
    }
    if db::revoke_role(&db, id, role).await? {
        println!("{email} ({id}): revoked {role}");
    } else {
        println!("{email} ({id}): did not have {role}");
    }
    print_roles(&db, id).await
}

async fn print_roles(db: &PgPool, id: Uuid) -> anyhow::Result<()> {
    let roles = db::roles_of(db, id).await?;
    let names: Vec<&str> = roles.iter().map(|role| role.as_str()).collect();
    println!(
        "roles now: [{}] (in the JWT from the next request on)",
        names.join(", ")
    );
    Ok(())
}

/// Deletes this service's data for a user. Kratos deletion is separate (`just delete-user`
/// does both, Kratos first). An email is looked up in Kratos, so it fails if the identity
/// is already gone; an id works for data left behind after that.
async fn forget_user(
    target: &EmailOrId,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let (label, id) = match target {
        EmailOrId::Id(id) => (id.to_string(), *id),
        EmailOrId::Email(email) => {
            let id = identity_for(email, kratos_admin).await?.id;
            (format!("{email} ({id})"), id)
        }
    };
    let db = db::connect(database).await?;
    if db::delete_user(&db, id).await? {
        println!("{label}: user-service data deleted");
    } else {
        println!("{label}: no user-service data (never logged in through Oathkeeper)");
    }
    Ok(())
}

/// Docker healthcheck: the image is `FROM scratch`, so there's no curl/wget to use.
async fn healthcheck(public: &PublicAddr) -> anyhow::Result<()> {
    let port = public.addr.port();
    let res = config::http_client()?
        .get(format!("http://127.0.0.1:{port}/healthz"))
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
