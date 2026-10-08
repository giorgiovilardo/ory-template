//! All SQL lives here, written with sqlx's compile-time-checked macros: a typo in a
//! table, column or type is a compile error. Building needs either a database
//! (`DATABASE_URL` in user-service/.env) or the offline data in `.sqlx/`
//! (regenerate with `cargo sqlx prepare` after changing a query).
//!
//! Custom types need a hint in the SQL: `email as "email: Email"`. Values written are
//! validated by their types; values read back are trusted (`#[sqlx(transparent)]`),
//! since only validated values are ever written.

use std::time::Duration;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::Database;
use crate::kratos::KratosIdentity;
use crate::models::{DisplayName, Email, Role, User, UserWithRoles};

pub async fn connect(database: &Database) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(database.max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database.url)
        .await
        .context("connecting to the database")
}

/// The flat shape every user-with-roles query selects, so the mapping lives in one place.
struct UserWithRolesRow {
    id: Uuid,
    email: Email,
    display_name: Option<DisplayName>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    roles: Vec<Role>,
}

impl From<UserWithRolesRow> for UserWithRoles {
    fn from(row: UserWithRolesRow) -> Self {
        Self {
            user: User {
                id: row.id,
                email: row.email,
                display_name: row.display_name,
                created_at: row.created_at,
                updated_at: row.updated_at,
            },
            roles: row.roles,
        }
    }
}

pub async fn find_by_id(db: &PgPool, id: Uuid) -> sqlx::Result<Option<User>> {
    sqlx::query_as!(
        User,
        r#"select id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at
           from users where id = $1"#,
        id
    )
    .fetch_optional(db)
    .await
}

/// The user and their roles in one query (a single snapshot, one round trip).
pub async fn find_with_roles(db: &PgPool, id: Uuid) -> sqlx::Result<Option<UserWithRoles>> {
    sqlx::query_as!(
        UserWithRolesRow,
        r#"select id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at,
                  array(select role from user_roles where user_id = users.id order by role) as "roles!: Vec<Role>"
           from users where id = $1"#,
        id
    )
    .fetch_optional(db)
    .await
    .map(|row| row.map(Into::into))
}

/// Brings our copy in line with the Kratos identity, the source of truth, and returns the
/// user and their roles: creates the user (with the `user` role) on first sight and
/// refreshes the email copy when Kratos' differs. The common case is one SELECT and no
/// write; a miss or an email change takes one more statement.
pub async fn sync_identity(db: &PgPool, identity: &KratosIdentity) -> sqlx::Result<UserWithRoles> {
    let (id, email) = (identity.id, &identity.traits.email);
    if let Some(found) = find_with_roles(db, id).await?
        && &found.user.email == email
    {
        return Ok(found);
    }
    upsert(db, id, email).await
}

/// Insert-or-refresh in one statement, so there is nothing to race: `on conflict do
/// update` waits for a concurrent insert and re-inserts if the row was deleted meanwhile.
/// The default role is granted only when this statement inserted the row (`xmax = 0`),
/// so a refresh never restores a revoked `user` role. Roles are not read back for that
/// case: a CTE can't see rows written by its siblings, and a new user has just the one.
async fn upsert(db: &PgPool, id: Uuid, email: &Email) -> sqlx::Result<UserWithRoles> {
    sqlx::query_as!(
        UserWithRolesRow,
        r#"with upserted as (
               insert into users (id, email) values ($1, $2)
               on conflict (id) do update set email = excluded.email
               returning id, email, display_name, created_at, updated_at, (xmax = 0) as "inserted!"
           ), granted as (
               insert into user_roles (user_id, role)
               select id, $3 from upserted where "inserted!"
           )
           select id as "id!", email as "email!: Email", display_name as "display_name: DisplayName",
                  created_at as "created_at!", updated_at as "updated_at!",
                  case when "inserted!" then array[$3]
                       else array(select role from user_roles where user_id = upserted.id order by role)
                  end as "roles!: Vec<Role>"
           from upserted"#,
        id,
        email as &Email,
        Role::User as Role
    )
    .fetch_one(db)
    .await
    .map(Into::into)
}

pub async fn roles_of(db: &PgPool, id: Uuid) -> sqlx::Result<Vec<Role>> {
    sqlx::query_scalar!(
        r#"select role as "role: Role" from user_roles where user_id = $1 order by role"#,
        id
    )
    .fetch_all(db)
    .await
}

pub async fn has_role(db: &PgPool, id: Uuid, role: Role) -> sqlx::Result<bool> {
    sqlx::query_scalar!(
        r#"select exists (select 1 from user_roles where user_id = $1 and role = $2) as "exists!""#,
        id,
        role as Role
    )
    .fetch_one(db)
    .await
}

/// Serializes the checks-then-changes that take admin access away (see
/// `Directory::guard`) until the transaction ends. Any constant would do; this one is
/// only ever used here.
pub async fn lock_admin_changes(tx: &mut PgConnection) -> sqlx::Result<()> {
    const ADMIN_CHANGES: i64 = 0x7573_6572_6164_6d6e; // "useradmn"
    sqlx::query!("select from pg_advisory_xact_lock($1)", ADMIN_CHANGES)
        .execute(tx)
        .await?;
    Ok(())
}

pub async fn admin_ids(conn: &mut PgConnection) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar!(
        "select user_id from user_roles where role = $1",
        Role::Admin as Role
    )
    .fetch_all(conn)
    .await
}

/// Every user id with a row (for `reconcile`).
pub async fn all_user_ids(db: &PgPool) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar!("select id from users")
        .fetch_all(db)
        .await
}

/// The users among `ids` that have a row, with their roles, in one query (for listings).
/// Ids without a row (no data yet) are simply absent.
pub async fn find_many_with_roles(db: &PgPool, ids: &[Uuid]) -> sqlx::Result<Vec<UserWithRoles>> {
    sqlx::query_as!(
        UserWithRolesRow,
        r#"select id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at,
                  array(select role from user_roles where user_id = users.id order by role) as "roles!: Vec<Role>"
           from users where id = any($1)"#,
        ids
    )
    .fetch_all(db)
    .await
    .map(|rows| rows.into_iter().map(Into::into).collect())
}

/// `None` clears the display name. Returns `None` if the user doesn't exist.
/// The roles come from the same statement as the update.
pub async fn set_display_name(
    db: &PgPool,
    id: Uuid,
    name: Option<&DisplayName>,
) -> sqlx::Result<Option<UserWithRoles>> {
    sqlx::query_as!(
        UserWithRolesRow,
        r#"with updated as (
               update users set display_name = $2 where id = $1
               returning id, email, display_name, created_at, updated_at
           )
           select id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at,
                  array(select role from user_roles where user_id = updated.id order by role) as "roles!: Vec<Role>"
           from updated"#,
        id,
        name as Option<&DisplayName>
    )
    .fetch_optional(db)
    .await
    .map(|row| row.map(Into::into))
}

/// Returns false if the user already had the role.
pub async fn grant_role(db: &PgPool, id: Uuid, role: Role) -> sqlx::Result<bool> {
    let result = sqlx::query!(
        "insert into user_roles (user_id, role) values ($1, $2)
         on conflict (user_id, role) do nothing",
        id,
        role as Role
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Returns false if the user didn't have the role.
pub async fn revoke_role(db: &PgPool, id: Uuid, role: Role) -> sqlx::Result<bool> {
    let result = sqlx::query!(
        "delete from user_roles where user_id = $1 and role = $2",
        id,
        role as Role
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Deletes the user and (by cascade) their roles. Returns false if there was no such user.
pub async fn delete_user(db: &PgPool, id: Uuid) -> sqlx::Result<bool> {
    let result = sqlx::query!("delete from users where id = $1", id)
        .execute(db)
        .await?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::identity;

    fn email(s: &str) -> Email {
        s.parse().unwrap()
    }

    #[sqlx::test]
    async fn creates_user_with_default_role_once(db: PgPool) {
        let id = Uuid::new_v4();
        let first = sync_identity(&db, &identity(id, "ada@example.com"))
            .await
            .unwrap();
        let second = sync_identity(&db, &identity(id, "ada@example.com"))
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.user.display_name, None);
        assert_eq!(first.roles, vec![Role::User]);
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![Role::User]);
    }

    #[sqlx::test]
    async fn refreshes_changed_email(db: PgPool) {
        let id = Uuid::new_v4();
        let before = sync_identity(&db, &identity(id, "old@example.com"))
            .await
            .unwrap();
        grant_role(&db, id, Role::Admin).await.unwrap();
        let found = sync_identity(&db, &identity(id, "new@example.com"))
            .await
            .unwrap();

        assert_eq!(found.user.email, email("new@example.com"));
        assert!(found.user.updated_at > before.user.updated_at);
        assert_eq!(found.roles, vec![Role::Admin, Role::User]);
    }

    #[sqlx::test]
    async fn refreshing_the_email_keeps_revoked_roles_revoked(db: PgPool) {
        let id = Uuid::new_v4();
        sync_identity(&db, &identity(id, "old@example.com"))
            .await
            .unwrap();
        revoke_role(&db, id, Role::User).await.unwrap();
        let found = sync_identity(&db, &identity(id, "new@example.com"))
            .await
            .unwrap();

        assert_eq!(found.roles, vec![]);
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![]);
    }

    #[sqlx::test]
    async fn concurrent_first_requests_create_one_user(db: PgPool) {
        let id = Uuid::new_v4();
        let ada = identity(id, "ada@example.com");
        let (a, b) = tokio::join!(sync_identity(&db, &ada), sync_identity(&db, &ada));

        assert_eq!(a.unwrap().user.id, b.unwrap().user.id);
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![Role::User]);
    }

    #[sqlx::test]
    async fn survives_the_user_being_deleted_mid_refresh(db: PgPool) {
        // forget-user can delete the row between sync_identity's SELECT and UPDATE.
        // Interleaving is down to scheduling, so run enough rounds to hit it.
        let id = Uuid::new_v4();
        for round in 0..300 {
            sync_identity(&db, &identity(id, &format!("old{round}@example.com")))
                .await
                .unwrap();
            let new = identity(id, &format!("new{round}@example.com"));
            let (found, _) = tokio::join!(sync_identity(&db, &new), delete_user(&db, id));
            assert_eq!(found.unwrap().user.email, new.traits.email, "round {round}");
        }
    }

    #[sqlx::test]
    async fn reads_roles_with_the_user(db: PgPool) {
        let id = Uuid::new_v4();
        assert_eq!(find_with_roles(&db, id).await.unwrap(), None);

        sync_identity(&db, &identity(id, "ada@example.com"))
            .await
            .unwrap();
        grant_role(&db, id, Role::Admin).await.unwrap();
        let found = find_with_roles(&db, id).await.unwrap().unwrap();
        assert_eq!(found.roles, vec![Role::Admin, Role::User]);

        revoke_role(&db, id, Role::User).await.unwrap();
        revoke_role(&db, id, Role::Admin).await.unwrap();
        let found = find_with_roles(&db, id).await.unwrap().unwrap();
        assert_eq!(found.roles, vec![]);
    }

    #[sqlx::test]
    async fn grants_and_revokes_roles(db: PgPool) {
        let id = Uuid::new_v4();
        sync_identity(&db, &identity(id, "ada@example.com"))
            .await
            .unwrap();

        assert!(!has_role(&db, id, Role::Admin).await.unwrap());
        assert!(grant_role(&db, id, Role::Admin).await.unwrap());
        assert!(!grant_role(&db, id, Role::Admin).await.unwrap());
        assert!(has_role(&db, id, Role::Admin).await.unwrap());
        assert_eq!(
            roles_of(&db, id).await.unwrap(),
            vec![Role::Admin, Role::User]
        );

        assert!(revoke_role(&db, id, Role::Admin).await.unwrap());
        assert!(!revoke_role(&db, id, Role::Admin).await.unwrap());
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![Role::User]);
    }

    #[sqlx::test]
    async fn finds_many_users_with_their_roles(db: PgPool) {
        let (ada, bob, nobody) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        sync_identity(&db, &identity(ada, "ada@example.com"))
            .await
            .unwrap();
        sync_identity(&db, &identity(bob, "bob@example.com"))
            .await
            .unwrap();
        grant_role(&db, ada, Role::Admin).await.unwrap();
        revoke_role(&db, bob, Role::User).await.unwrap();

        let mut found = find_many_with_roles(&db, &[ada, bob, nobody])
            .await
            .unwrap();
        found.sort_by_key(|u| u.user.id != ada);
        let found: Vec<_> = found.into_iter().map(|u| (u.user.id, u.roles)).collect();
        assert_eq!(
            found,
            vec![(ada, vec![Role::Admin, Role::User]), (bob, vec![])]
        );
        assert_eq!(find_many_with_roles(&db, &[]).await.unwrap().len(), 0);
    }

    #[sqlx::test]
    async fn sets_and_clears_display_name(db: PgPool) {
        let id = Uuid::new_v4();
        sync_identity(&db, &identity(id, "ada@example.com"))
            .await
            .unwrap();
        let name = DisplayName::try_from("Ada".to_owned()).unwrap();

        let found = set_display_name(&db, id, Some(&name))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.user.display_name, Some(name));
        assert_eq!(found.roles, vec![Role::User]);

        let found = set_display_name(&db, id, None).await.unwrap().unwrap();
        assert_eq!(found.user.display_name, None);

        assert_eq!(
            set_display_name(&db, Uuid::new_v4(), None).await.unwrap(),
            None
        );
    }

    #[sqlx::test]
    async fn deleting_a_user_removes_their_roles(db: PgPool) {
        let id = Uuid::new_v4();
        sync_identity(&db, &identity(id, "ada@example.com"))
            .await
            .unwrap();

        assert!(delete_user(&db, id).await.unwrap());
        assert!(!delete_user(&db, id).await.unwrap());
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![]);
    }
}
