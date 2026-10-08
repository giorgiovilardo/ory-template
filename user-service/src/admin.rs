//! The user-admin subcommands: a thin adapter over `directory`. Each one builds what it
//! needs from config, resolves the email to a Kratos identity id, calls the directory,
//! and prints the result. The logic (and what "a user" is) lives in `directory.rs`.

use serde_json::json;
use uuid::Uuid;

use crate::cli::EmailOrId;
use crate::config::{self, Database, KratosAdmin};
use crate::db;
use crate::directory::{Accounts, Actor, Directory, DirectoryError, Reconciled};
use crate::kratos::{AdminApi, IdentityState};
use crate::models::{Email, Role, StoredUser};

fn kratos(kratos_admin: &KratosAdmin) -> anyhow::Result<AdminApi> {
    Ok(AdminApi::new(config::http_client()?, &kratos_admin.url))
}

fn accounts(kratos_admin: &KratosAdmin) -> anyhow::Result<Accounts<AdminApi>> {
    Ok(Accounts::new(kratos(kratos_admin)?))
}

/// Connects first, so a bad database setting fails before anything happens in Kratos.
async fn directory(
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<Directory<AdminApi>> {
    Ok(Directory::new(
        db::connect(database).await?,
        kratos(kratos_admin)?,
    ))
}

async fn id_for(accounts: &Accounts<AdminApi>, email: &Email) -> anyhow::Result<Uuid> {
    Ok(accounts.resolve(email).await?.id)
}

pub async fn users(database: &Database, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let users = directory(database, kratos_admin).await?.all_users().await?;

    println!(
        "{:36}  {:32}  {:8}  {:8}  {:10}  CREATED",
        "ID", "EMAIL", "STATE", "VERIFIED", "ROLES"
    );
    for user in &users {
        let identity = &user.identity;
        let roles = user
            .stored
            .as_ref()
            .map_or("-".to_owned(), |stored| role_names(&stored.roles).join(","));
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
        "\n{} user(s). Roles \"-\": no user-service data (`reconcile` creates it).",
        users.len()
    );
    Ok(())
}

pub async fn user(
    email: &Email,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let directory = directory(database, kratos_admin).await?;
    let id = id_for(directory.accounts(), email).await?;
    let details = directory.details(id).await?;

    let shown = json!({
        "identity": details.raw_identity,
        "active_sessions": details.active_sessions,
        "user_service": details.user.stored.map(StoredUser::from),
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
    let added = directory(database, kratos_admin)
        .await?
        .add_user(email, password)
        .await?;
    println!("{email} ({}): created, email verified", added.user.id);
    print_roles(&added.roles);
    Ok(())
}

pub async fn grant_role(
    email: &Email,
    role: Role,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let directory = directory(database, kratos_admin).await?;
    let id = id_for(directory.accounts(), email).await?;
    let change = directory.grant_role(id, role).await?;
    if change.changed {
        println!("{email} ({id}): granted {role}");
    } else {
        println!("{email} ({id}): already has {role}");
    }
    print_roles(&change.roles);
    Ok(())
}

pub async fn revoke_role(
    email: &Email,
    role: Role,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let directory = directory(database, kratos_admin).await?;
    let id = id_for(directory.accounts(), email).await?;
    let change = directory.revoke_role(Actor::Operator, id, role).await?;
    if change.changed {
        println!("{email} ({id}): revoked {role}");
    } else {
        println!("{email} ({id}): did not have {role}");
    }
    print_roles(&change.roles);
    Ok(())
}

fn role_names(roles: &[Role]) -> Vec<&'static str> {
    roles.iter().map(|role| role.as_str()).collect()
}

fn print_roles(roles: &[Role]) {
    println!(
        "roles now: [{}] (in the JWT from the next request on)",
        role_names(roles).join(", ")
    );
}

pub async fn revoke_sessions(email: &Email, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let accounts = accounts(kratos_admin)?;
    let id = id_for(&accounts, email).await?;
    accounts.revoke_sessions(id).await?;
    println!("{email} ({id}): all sessions revoked (logged out everywhere)");
    Ok(())
}

pub async fn deactivate(email: &Email, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let accounts = accounts(kratos_admin)?;
    let id = id_for(&accounts, email).await?;
    accounts.set_state(id, IdentityState::Inactive).await?;
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
    let accounts = accounts(kratos_admin)?;
    let id = id_for(&accounts, email).await?;
    accounts.set_state(id, IdentityState::Active).await?;
    println!("{email} ({id}): active again");
    Ok(())
}

pub async fn recover(email: &Email, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let accounts = accounts(kratos_admin)?;
    let id = id_for(&accounts, email).await?;
    let code = accounts.recovery_code(id).await?;
    println!(
        "Send this to {email} (valid 1h):\n  link: {}\n  code: {}",
        code.recovery_link, code.recovery_code
    );
    Ok(())
}

/// The Kratos identity, then this service's data (see `Directory::delete` for why in
/// that order). If the second step fails, `forget-user <id>` finishes the job.
pub async fn delete_user(
    email: &Email,
    database: &Database,
    kratos_admin: &KratosAdmin,
) -> anyhow::Result<()> {
    let directory = directory(database, kratos_admin).await?;
    let id = id_for(directory.accounts(), email).await?;
    let deleted = directory
        .delete(Actor::Operator, id)
        .await
        .map_err(|err| match err {
            DirectoryError::DataLeftBehind { .. } => {
                anyhow::Error::new(err).context(format!("finish with `forget-user {id}`"))
            }
            err => err.into(),
        })?;
    println!("{email} ({id}): deleted from Kratos");
    if deleted.had_data {
        println!("{email} ({id}): user-service data deleted");
    } else {
        println!("{email} ({id}): no user-service data");
    }
    Ok(())
}

pub async fn reconcile(database: &Database, kratos_admin: &KratosAdmin) -> anyhow::Result<()> {
    let done = directory(database, kratos_admin).await?.reconcile().await?;
    let report = |ids: &[Uuid], what: &str| {
        if !ids.is_empty() {
            println!("{} {what}:", ids.len());
            for id in ids {
                println!("  {id}");
            }
        }
    };
    report(
        &done.created,
        "user(s) had no user-service data: created, with the `user` role",
    );
    report(&done.refreshed, "stale email copy(ies): refreshed");
    report(
        &done.skipped,
        "Kratos identity(ies) without a valid email: skipped",
    );
    report(
        &done.orphans,
        "row(s) without a Kratos identity: left alone, remove with `forget-user <id>`",
    );
    if done == Reconciled::default() {
        println!("in sync: every Kratos identity has its user-service data");
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
    let directory = directory(database, kratos_admin).await?;
    let (label, id) = match target {
        EmailOrId::Id(id) => (id.to_string(), *id),
        EmailOrId::Email(email) => {
            let id = id_for(directory.accounts(), email).await?;
            (format!("{email} ({id})"), id)
        }
    };
    if directory.forget(id).await? {
        println!("{label}: user-service data deleted");
    } else {
        println!("{label}: no user-service data");
    }
    Ok(())
}
