//! Admin subcommands, run inside the container:
//! `docker compose exec user-service user-service grant-role me@x.com admin`.
//! Granting roles needs no admin API, which avoids the "who grants the first admin" problem.

use anyhow::{Context, bail};
use sqlx::PgPool;

use crate::config::{optional, required};
use crate::models::{Email, Role, User};
use crate::{db, kratos};

pub const USAGE: &str = "usage: user-service [serve | migrate | healthcheck | grant-role EMAIL ROLE | revoke-role EMAIL ROLE | forget-user EMAIL]";

async fn connect() -> anyhow::Result<PgPool> {
    PgPool::connect(&required("DATABASE_URL")?)
        .await
        .context("connecting to the database")
}

/// Applies pending migrations (embedded in the binary at compile time) and exits.
/// Run as a one-shot job before `serve`; sqlx takes a Postgres advisory lock, so
/// concurrent runs are safe.
pub async fn migrate() -> anyhow::Result<()> {
    let db = connect().await?;
    sqlx::migrate!()
        .run(&db)
        .await
        .context("running migrations")?;
    let latest = sqlx::migrate!()
        .iter()
        .map(|m| m.version)
        .max()
        .unwrap_or(0);
    println!("migrations up to date (latest version: {latest})");
    Ok(())
}

fn parse_email(email: &str) -> anyhow::Result<Email> {
    email
        .parse()
        .with_context(|| format!("invalid email {email:?}"))
}

/// Finds the user here, or creates them from their Kratos identity (users who
/// registered but never made a request through Oathkeeper have no row yet).
async fn resolve_user(db: &PgPool, email: &Email) -> anyhow::Result<User> {
    if let Some(user) = db::find_by_email(db, email).await? {
        return Ok(user);
    }
    let admin_url = optional("KRATOS_ADMIN_URL", "http://kratos:4434");
    let identity = kratos::find_identity_by_email(&reqwest::Client::new(), &admin_url, email)
        .await
        .context("looking up the user in Kratos")?
        .with_context(|| format!("no Kratos identity with email {email}"))?;
    Ok(db::find_or_create(db, identity.id, &identity.traits.email).await?)
}

pub async fn grant_role(email: &str, role: &str) -> anyhow::Result<()> {
    let (email, role) = (parse_email(email)?, role.parse::<Role>()?);
    let db = connect().await?;
    let user = resolve_user(&db, &email).await?;
    if db::grant_role(&db, user.id, role, None).await? {
        println!("{email}: granted {role}");
    } else {
        println!("{email}: already has {role}");
    }
    print_roles(&db, &user).await
}

pub async fn revoke_role(email: &str, role: &str) -> anyhow::Result<()> {
    let (email, role) = (parse_email(email)?, role.parse::<Role>()?);
    let db = connect().await?;
    let user = db::find_by_email(&db, &email)
        .await?
        .with_context(|| format!("no user with email {email}"))?;
    if db::revoke_role(&db, user.id, role).await? {
        println!("{email}: revoked {role}");
    } else {
        println!("{email}: did not have {role}");
    }
    print_roles(&db, &user).await
}

async fn print_roles(db: &PgPool, user: &User) -> anyhow::Result<()> {
    let roles = db::roles_of(db, user.id).await?;
    let names: Vec<&str> = roles.iter().map(Role::as_str).collect();
    println!(
        "roles now: [{}] (in the JWT from the next request on)",
        names.join(", ")
    );
    Ok(())
}

/// Deletes this service's data for a user. Kratos deletion is separate (`just delete-user` does both).
pub async fn forget_user(email: &str) -> anyhow::Result<()> {
    let email = parse_email(email)?;
    let db = connect().await?;
    match db::find_by_email(&db, &email).await? {
        Some(user) => {
            db::delete_user(&db, user.id).await?;
            println!("{email}: user-service data deleted");
        }
        None => println!("{email}: no user-service data (never logged in through Oathkeeper)"),
    }
    Ok(())
}

/// Docker healthcheck: the image is `FROM scratch`, so there's no curl/wget to use.
pub async fn healthcheck() -> anyhow::Result<()> {
    let port = optional("PUBLIC_ADDR", "0.0.0.0:3000")
        .rsplit(':')
        .next()
        .unwrap_or("3000")
        .to_owned();
    let res = reqwest::get(format!("http://127.0.0.1:{port}/healthz")).await?;
    if !res.status().is_success() {
        bail!("unhealthy: {}", res.status());
    }
    Ok(())
}
