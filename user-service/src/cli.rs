//! Admin subcommands, run inside the container:
//! `docker compose exec user-service user-service grant-role me@x.com admin`.
//! Granting roles needs no admin API, which avoids the "who grants the first admin" problem.

use anyhow::{Context, bail};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::{self, required};
use crate::models::{Email, Role, User};
use crate::{db, kratos};

pub const USAGE: &str = "usage: user-service [serve | migrate | healthcheck | grant-role EMAIL ROLE | revoke-role EMAIL ROLE | forget-user EMAIL|ID]";

async fn connect() -> anyhow::Result<PgPool> {
    config::connect_pool(&required("DATABASE_URL")?).await
}

/// Applies pending migrations (embedded in the binary at compile time) and exits.
/// Run as a one-shot job before `serve`; sqlx takes a Postgres advisory lock, so
/// concurrent runs are safe.
pub async fn migrate() -> anyhow::Result<()> {
    let db = connect().await?;
    let migrator = sqlx::migrate!();
    migrator.run(&db).await.context("running migrations")?;
    let latest = migrator.iter().map(|m| m.version).max().unwrap_or(0);
    println!("migrations up to date (latest version: {latest})");
    Ok(())
}

fn parse_email(email: &str) -> anyhow::Result<Email> {
    email
        .parse()
        .with_context(|| format!("invalid email {email:?}"))
}

/// Finds the Kratos identity that logs in with this email. Kratos is the only
/// reliable email -> id mapping: our `users.email` is a copy that is neither unique
/// nor current (it's refreshed only when the user makes a request), so matching on
/// it can pick another account or miss the right one.
async fn identity_for(email: &Email) -> anyhow::Result<kratos::KratosIdentity> {
    kratos::find_identity_by_email(&config::http_client()?, &config::kratos_admin_url(), email)
        .await
        .context("looking up the user in Kratos")?
        .with_context(|| format!("no Kratos identity with email {email}"))
}

pub async fn grant_role(email: &str, role: &str) -> anyhow::Result<()> {
    let (email, role) = (parse_email(email)?, role.parse::<Role>()?);
    let identity = identity_for(&email).await?;
    let db = connect().await?;
    // Creates the row for users who registered but never made a request through
    // Oathkeeper, and refreshes a stale email copy.
    let user = db::find_or_create(&db, identity.id, &identity.traits.email)
        .await?
        .user;
    if db::grant_role(&db, user.id, role, None).await? {
        println!("{email} ({}): granted {role}", user.id);
    } else {
        println!("{email} ({}): already has {role}", user.id);
    }
    print_roles(&db, &user).await
}

pub async fn revoke_role(email: &str, role: &str) -> anyhow::Result<()> {
    let (email, role) = (parse_email(email)?, role.parse::<Role>()?);
    let identity = identity_for(&email).await?;
    let db = connect().await?;
    let user = db::find_by_id(&db, identity.id).await?.with_context(|| {
        format!(
            "{email} ({}) has no user-service data, so no roles",
            identity.id
        )
    })?;
    if db::revoke_role(&db, user.id, role).await? {
        println!("{email} ({}): revoked {role}", user.id);
    } else {
        println!("{email} ({}): did not have {role}", user.id);
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

/// Deletes this service's data for a user. Kratos deletion is separate (`just delete-user`
/// does both, this first). Takes an email (looked up in Kratos, so it fails if the
/// identity is already gone) or a Kratos identity id (for data left behind after that).
pub async fn forget_user(email_or_id: &str) -> anyhow::Result<()> {
    let (label, id) = match email_or_id.parse::<Uuid>() {
        Ok(id) => (id.to_string(), id),
        Err(_) => {
            let email = parse_email(email_or_id)?;
            let identity = identity_for(&email).await?;
            (format!("{email} ({})", identity.id), identity.id)
        }
    };
    let db = connect().await?;
    if db::delete_user(&db, id).await? {
        println!("{label}: user-service data deleted");
    } else {
        println!("{label}: no user-service data (never logged in through Oathkeeper)");
    }
    Ok(())
}

/// Docker healthcheck: the image is `FROM scratch`, so there's no curl/wget to use.
pub async fn healthcheck() -> anyhow::Result<()> {
    let port = config::public_addr()?.port();
    let res = config::http_client()?
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .await?;
    if !res.status().is_success() {
        bail!("unhealthy: {}", res.status());
    }
    Ok(())
}
