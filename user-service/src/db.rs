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

use crate::models::{DisplayName, Email, Role, User};

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

pub async fn find_by_email(db: &PgPool, email: &Email) -> sqlx::Result<Option<User>> {
    sqlx::query_as!(
        User,
        r#"select id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at
           from users where email = $1"#,
        email as &Email
    )
    .fetch_optional(db)
    .await
}

/// Returns the user, creating them (with the `user` role) on first sight and
/// refreshing the email copy when Kratos' differs. The common case is one SELECT
/// and no write.
pub async fn find_or_create(db: &PgPool, id: Uuid, email: &Email) -> sqlx::Result<User> {
    if let Some(user) = find_by_id(db, id).await? {
        if &user.email == email {
            return Ok(user);
        }
        return sqlx::query_as!(
            User,
            r#"update users set email = $2, updated_at = now() where id = $1
               returning id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at"#,
            id,
            email as &Email
        )
        .fetch_one(db)
        .await;
    }

    let mut tx = db.begin().await?;
    let created = sqlx::query_as!(
        User,
        r#"insert into users (id, email) values ($1, $2)
           on conflict (id) do nothing
           returning id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at"#,
        id,
        email as &Email
    )
    .fetch_optional(&mut *tx)
    .await?;

    match created {
        Some(user) => {
            sqlx::query!(
                "insert into user_roles (user_id, role) values ($1, $2)",
                id,
                Role::User as Role
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(user)
        }
        // A concurrent request created the user between our SELECT and INSERT.
        None => {
            tx.commit().await?;
            find_by_id(db, id).await?.ok_or(sqlx::Error::RowNotFound)
        }
    }
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
pub async fn set_display_name(
    db: &PgPool,
    id: Uuid,
    name: Option<&DisplayName>,
) -> sqlx::Result<Option<User>> {
    sqlx::query_as!(
        User,
        r#"update users set display_name = $2, updated_at = now() where id = $1
           returning id, email as "email: Email", display_name as "display_name: DisplayName", created_at, updated_at"#,
        id,
        name as Option<&DisplayName>
    )
    .fetch_optional(db)
    .await
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
        assert_eq!(first.display_name, None);
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![Role::User]);
    }

    #[sqlx::test]
    async fn refreshes_changed_email(db: PgPool) {
        let id = Uuid::new_v4();
        find_or_create(&db, id, &email("old@example.com"))
            .await
            .unwrap();
        let user = find_or_create(&db, id, &email("new@example.com"))
            .await
            .unwrap();

        assert_eq!(user.email, email("new@example.com"));
        assert!(user.updated_at >= user.created_at);
    }

    #[sqlx::test]
    async fn concurrent_first_requests_create_one_user(db: PgPool) {
        let id = Uuid::new_v4();
        let e = email("ada@example.com");
        let (a, b) = tokio::join!(find_or_create(&db, id, &e), find_or_create(&db, id, &e));

        assert_eq!(a.unwrap().id, b.unwrap().id);
        assert_eq!(roles_of(&db, id).await.unwrap(), vec![Role::User]);
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

        let user = set_display_name(&db, id, Some(&name))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.display_name, Some(name));

        let user = set_display_name(&db, id, None).await.unwrap().unwrap();
        assert_eq!(user.display_name, None);

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
