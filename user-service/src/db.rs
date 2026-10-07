//! All SQL lives here, written with sqlx's compile-time-checked macros: a typo in a
//! table, column or type is a compile error. Building needs either a database
//! (`DATABASE_URL` in user-service/.env) or the offline data in `.sqlx/`
//! (regenerate with `cargo sqlx prepare` after changing a query).
//!
//! Custom types need a hint in the SQL: `email as "email: Email"`. Values written are
//! validated by their types; values read back are trusted (`#[sqlx(transparent)]`),
//! since only validated values are ever written.

use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{DisplayName, Email, Role, User, UserWithRoles};

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
    let row = sqlx::query!(
        r#"select id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at,
                  array(select role from user_roles where user_id = users.id order by role) as "roles!: Vec<Role>"
           from users where id = $1"#,
        id
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|row| UserWithRoles {
        user: User {
            id: row.id,
            email: row.email,
            display_name: row.display_name,
            created_at: row.created_at,
            updated_at: row.updated_at,
        },
        roles: row.roles,
    }))
}

/// Returns the user and their roles, creating the user (with the `user` role) on first
/// sight and refreshing the email copy when Kratos' differs. The common case is one
/// SELECT and no write; a miss or an email change takes one more statement.
pub async fn find_or_create(db: &PgPool, id: Uuid, email: &Email) -> sqlx::Result<UserWithRoles> {
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
    let row = sqlx::query!(
        r#"with upserted as (
               insert into users (id, email) values ($1, $2)
               on conflict (id) do update set email = excluded.email, updated_at = now()
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
    .await?;
    Ok(UserWithRoles {
        user: User {
            id: row.id,
            email: row.email,
            display_name: row.display_name,
            created_at: row.created_at,
            updated_at: row.updated_at,
        },
        roles: row.roles,
    })
}

pub async fn roles_of(db: &PgPool, id: Uuid) -> sqlx::Result<Vec<Role>> {
    sqlx::query_scalar!(
        r#"select role as "role: Role" from user_roles where user_id = $1 order by role"#,
        id
    )
    .fetch_all(db)
    .await
}

/// `None` clears the display name. Returns `None` if the user doesn't exist.
/// The roles come from the same statement as the update.
pub async fn set_display_name(
    db: &PgPool,
    id: Uuid,
    name: Option<&DisplayName>,
) -> sqlx::Result<Option<UserWithRoles>> {
    let row = sqlx::query!(
        r#"with updated as (
               update users set display_name = $2, updated_at = now() where id = $1
               returning id, email, display_name, created_at, updated_at
           )
           select id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at,
                  array(select role from user_roles where user_id = updated.id order by role) as "roles!: Vec<Role>"
           from updated"#,
        id,
        name as Option<&DisplayName>
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|row| UserWithRoles {
        user: User {
            id: row.id,
            email: row.email,
            display_name: row.display_name,
            created_at: row.created_at,
            updated_at: row.updated_at,
        },
        roles: row.roles,
    }))
}

/// Returns false if the user already had the role.
pub async fn grant_role(
    db: &PgPool,
    id: Uuid,
    role: Role,
    granted_by: Option<Uuid>,
) -> sqlx::Result<bool> {
    let result = sqlx::query!(
        "insert into user_roles (user_id, role, granted_by) values ($1, $2, $3)
         on conflict (user_id, role) do nothing",
        id,
        role as Role,
        granted_by
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

    fn email(s: &str) -> Email {
        s.parse().unwrap()
    }

    #[sqlx::test]
    async fn creates_user_with_default_role_once(db: PgPool) {
        let id = Uuid::new_v4();
        let first = find_or_create(&db, id, &email("ada@example.com"))
            .await
            .unwrap();
        let second = find_or_create(&db, id, &email("ada@example.com"))
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
        find_or_create(&db, id, &email("old@example.com"))
            .await
            .unwrap();
        grant_role(&db, id, Role::Admin, None).await.unwrap();
        let found = find_or_create(&db, id, &email("new@example.com"))
            .await
            .unwrap();

        assert_eq!(found.user.email, email("new@example.com"));
        assert!(found.user.updated_at >= found.user.created_at);
        assert_eq!(found.roles, vec![Role::Admin, Role::User]);
    }

    #[sqlx::test]
    async fn refreshing_the_email_keeps_revoked_roles_revoked(db: PgPool) {
        let id = Uuid::new_v4();
        find_or_create(&db, id, &email("old@example.com"))
            .await
            .unwrap();
        revoke_role(&db, id, Role::User).await.unwrap();
        let found = find_or_create(&db, id, &email("new@example.com"))
            .await
            .unwrap();

        assert_eq!(found.roles, vec![]);
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![]);
    }

    #[sqlx::test]
    async fn concurrent_first_requests_create_one_user(db: PgPool) {
        let id = Uuid::new_v4();
        let e = email("ada@example.com");
        let (a, b) = tokio::join!(find_or_create(&db, id, &e), find_or_create(&db, id, &e));

        assert_eq!(a.unwrap().user.id, b.unwrap().user.id);
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![Role::User]);
    }

    #[sqlx::test]
    async fn survives_the_user_being_deleted_mid_refresh(db: PgPool) {
        // forget-user can delete the row between find_or_create's SELECT and UPDATE.
        // Interleaving is down to scheduling, so run enough rounds to hit it.
        let id = Uuid::new_v4();
        for round in 0..300 {
            find_or_create(&db, id, &email(&format!("old{round}@example.com")))
                .await
                .unwrap();
            let new = email(&format!("new{round}@example.com"));
            let (found, _) = tokio::join!(find_or_create(&db, id, &new), delete_user(&db, id));
            assert_eq!(found.unwrap().user.email, new, "round {round}");
        }
    }

    #[sqlx::test]
    async fn reads_roles_with_the_user(db: PgPool) {
        let id = Uuid::new_v4();
        assert_eq!(find_with_roles(&db, id).await.unwrap(), None);

        find_or_create(&db, id, &email("ada@example.com"))
            .await
            .unwrap();
        grant_role(&db, id, Role::Admin, None).await.unwrap();
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
        find_or_create(&db, id, &email("ada@example.com"))
            .await
            .unwrap();

        assert!(grant_role(&db, id, Role::Admin, None).await.unwrap());
        assert!(!grant_role(&db, id, Role::Admin, None).await.unwrap());
        assert_eq!(
            roles_of(&db, id).await.unwrap(),
            vec![Role::Admin, Role::User]
        );

        assert!(revoke_role(&db, id, Role::Admin).await.unwrap());
        assert!(!revoke_role(&db, id, Role::Admin).await.unwrap());
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![Role::User]);
    }

    #[sqlx::test]
    async fn sets_and_clears_display_name(db: PgPool) {
        let id = Uuid::new_v4();
        find_or_create(&db, id, &email("ada@example.com"))
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
        find_or_create(&db, id, &email("ada@example.com"))
            .await
            .unwrap();

        assert!(delete_user(&db, id).await.unwrap());
        assert!(!delete_user(&db, id).await.unwrap());
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![]);
    }
}
