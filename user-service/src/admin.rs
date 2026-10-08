//! The user-admin subcommands. A user is a Kratos identity (login, sessions, whether
//! they may log in) plus this service's row (profile, roles); these commands act on
//! both, so there is one place to manage "a user".
//!
//! Users are named by email and resolved through Kratos to an identity id. Kratos is
//! the only reliable email -> id mapping: our `users.email` is a copy that is neither
//! unique nor current (it's refreshed only when the user makes a request), so matching
//! on it can pick another account or miss the right one.

use std::collections::HashMap;

use anyhow::{Context, bail};
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::cli::EmailOrId;
use crate::config::{self, Database, KratosAdmin};
use crate::db;
use crate::kratos::{AdminApi, IdentityState, KratosIdentity};
use crate::models::{DisplayName, Email, Role, User, UserWithRoles};

fn kratos(kratos_admin: &KratosAdmin) -> anyhow::Result<AdminApi> {
    Ok(AdminApi::new(config::http_client()?, &kratos_admin.url))
}

async fn identity_for(api: &AdminApi, email: &Email) -> anyhow::Result<KratosIdentity> {
    api.find_by_email(email)
        .await
        .context("looking up the user in Kratos")?
        .with_context(|| format!("no Kratos identity with email {email}"))
}

pub async fn users(database: &Database, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let identities = kratos(kratos_admin)?.list().await?;
    let db = db::connect(database).await?;
    let roles: HashMap<Uuid, Vec<Role>> = db::all_roles(&db).await?.into_iter().collect();

    println!(
        "{:36}  {:32}  {:8}  {:8}  {:10}  CREATED",
        "ID", "EMAIL", "STATE", "VERIFIED", "ROLES"
    );
    for identity in &identities {
        let roles = roles.get(&identity.id).map_or("-".to_owned(), |roles| {
            let names: Vec<&str> = roles.iter().map(|role| role.as_str()).collect();
            names.join(",")
        });
        let created = identity
            .created_at
            .get(..19)
            .unwrap_or(&identity.created_at);
        println!(
            "{:36}  {:32}  {:8}  {:8}  {:10}  {}",
            identity.id,
            identity.traits.email.as_deref().unwrap_or(""),
            identity.state,
            if identity.verified() { "yes" } else { "no" },
            roles,
            created.replace('T', " "),
        );
    }
    println!(
        "\n{} user(s). Roles \"-\": no user-service data yet (created on their first request).",
        identities.len()
    );
    Ok(())
}

/// What `user` shows of this service's row; the id and email are already in the
/// Kratos identity. Fields are listed (exhaustive destructuring below), so a new column
/// shows up here only by decision, as in `MeResponse`.
#[derive(Serialize)]
struct StoredUser {
    display_name: Option<DisplayName>,
    roles: Vec<Role>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl From<UserWithRoles> for StoredUser {
    fn from(UserWithRoles { user, roles }: UserWithRoles) -> Self {
        let User {
            id: _,
            email: _,
            display_name,
            created_at,
            updated_at,
        } = user;
        Self {
            display_name,
            roles,
            created_at,
            updated_at,
        }
    }
}

pub async fn user(
    email: &Email,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let api = kratos(kratos_admin)?;
    let id = identity_for(&api, email).await?.id;
    let identity = api.identity(id).await?;
    let active_sessions = api.active_sessions(id).await?;
    let db = db::connect(database).await?;
    let stored = db::find_with_roles(&db, id).await?.map(StoredUser::from);

    let shown = json!({
        "identity": identity,
        "active_sessions": active_sessions,
        "user_service": stored,
    });
    println!("{}", serde_json::to_string_pretty(&shown)?);
    Ok(())
}

pub async fn add_user(
    email: &Email,
    password: &str,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    // Connect first, so a bad database setting fails before Kratos has the identity.
    let db = db::connect(database).await?;
    let identity = kratos(kratos_admin)?
        .create_identity(email, password)
        .await?;
    let id = identity.id;
    println!("{email} ({id}): created, email verified");
    // The hydrator would create the row on their first request anyway; doing it now
    // lets `users` show their roles straight away.
    db::sync_identity(&db, &identity).await.context(
        "creating the user-service data (the Kratos identity exists; \
         the data is created on the user's first request)",
    )?;
    print_roles(&db, id).await
}

pub async fn grant_role(
    email: &Email,
    role: Role,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let identity = identity_for(&kratos(kratos_admin)?, email).await?;
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

pub async fn revoke_role(
    email: &Email,
    role: Role,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let id = identity_for(&kratos(kratos_admin)?, email).await?.id;
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

pub async fn revoke_sessions(email: &Email, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let api = kratos(kratos_admin)?;
    let id = identity_for(&api, email).await?.id;
    api.revoke_sessions(id).await?;
    println!("{email} ({id}): all sessions revoked (logged out everywhere)");
    Ok(())
}

pub async fn deactivate(email: &Email, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let api = kratos(kratos_admin)?;
    let id = identity_for(&api, email).await?.id;
    api.set_state(id, IdentityState::Inactive).await?;
    println!(
        "{email} ({id}): deactivated. Existing sessions stop working immediately and login is refused."
    );
    println!(
        "Sessions are suspended, not deleted: `activate` brings them back. \
         Use `revoke-sessions` too for a permanent ban."
    );
    Ok(())
}

pub async fn activate(email: &Email, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let api = kratos(kratos_admin)?;
    let id = identity_for(&api, email).await?.id;
    api.set_state(id, IdentityState::Active).await?;
    println!("{email} ({id}): active again");
    Ok(())
}

pub async fn recover(email: &Email, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let api = kratos(kratos_admin)?;
    let id = identity_for(&api, email).await?.id;
    let code = api.recovery_code(id).await?;
    println!(
        "Send this to {email} (valid 1h):\n  link: {}\n  code: {}",
        code.recovery_link, code.recovery_code
    );
    Ok(())
}

/// Deletes the Kratos identity, then this service's data. Kratos first: once the
/// identity is gone, no request can reach us for this user, so nothing can re-create
/// the row we're about to delete. (The other way round, a request in between would
/// leave an orphan.) If the second step fails, `forget-user <id>` finishes the job.
pub async fn delete_user(
    email: &Email,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let api = kratos(kratos_admin)?;
    let id = identity_for(&api, email).await?.id;
    // Connect first, so a bad database setting fails before anything is deleted.
    let db = db::connect(database).await?;
    api.delete_identity(id).await?;
    println!("{email} ({id}): deleted from Kratos");
    let deleted = db::delete_user(&db, id).await.with_context(|| {
        format!("deleting the user-service data; finish with `forget-user {id}`")
    })?;
    if deleted {
        println!("{email} ({id}): user-service data deleted");
    } else {
        println!("{email} ({id}): no user-service data (never logged in through Oathkeeper)");
    }
    Ok(())
}

/// Deletes only this service's data for a user. An email is looked up in Kratos, so it
/// fails if the identity is already gone; an id works for data left behind after that.
pub async fn forget_user(
    target: &EmailOrId,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let (label, id) = match target {
        EmailOrId::Id(id) => (id.to_string(), *id),
        EmailOrId::Email(email) => {
            let id = identity_for(&kratos(kratos_admin)?, email).await?.id;
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
