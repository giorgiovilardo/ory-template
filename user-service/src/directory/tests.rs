use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::fake::{FakeIdentity, FakeKratos, Op};
use super::*;

fn email(s: &str) -> Email {
    s.parse().unwrap()
}

fn directory(db: &PgPool) -> (Directory<FakeKratos>, FakeKratos) {
    let kratos = FakeKratos::default();
    (Directory::new(db.clone(), kratos.clone()), kratos)
}

/// A user with both halves: the Kratos identity and the row (with the `user` role).
async fn existing_user(db: &PgPool, kratos: &FakeKratos, address: &str) -> Uuid {
    let id = kratos.add(FakeIdentity::new(address));
    db::sync_identity(db, &crate::testing::identity(id, address))
        .await
        .unwrap();
    id
}

/// Two pools on the same test database, the second already closed so every query on it
/// fails: the database half of an operation fails after the Kratos half succeeded.
async fn open_and_closed(options: PgPoolOptions, connect: PgConnectOptions) -> (PgPool, PgPool) {
    let open = options.clone().connect_with(connect.clone()).await.unwrap();
    let closed = options.connect_with(connect).await.unwrap();
    closed.close().await;
    (open, closed)
}

#[sqlx::test]
async fn resolves_an_email_to_exactly_one_identity(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let accounts = directory.accounts();
    let ada = kratos.add(FakeIdentity::new("ada@example.com"));

    assert_eq!(
        accounts
            .resolve(&email(" Ada@Example.com"))
            .await
            .unwrap()
            .id,
        ada
    );
    assert!(matches!(
        accounts.resolve(&email("nobody@example.com")).await,
        Err(DirectoryError::NoSuchEmail(e)) if e == email("nobody@example.com")
    ));

    let other = kratos.add(FakeIdentity::new("ada@example.com"));
    let err = accounts
        .resolve(&email("ada@example.com"))
        .await
        .unwrap_err();
    let DirectoryError::AmbiguousEmail { ids, .. } = &err else {
        panic!("expected ambiguity, got {err:?}");
    };
    assert!(ids.contains(&ada) && ids.contains(&other));
    assert!(err.to_string().contains(&ada.to_string()), "{err}");
}

#[sqlx::test]
async fn lists_every_user_with_their_data(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let ada = existing_user(&db, &kratos, "ada@example.com").await;
    let bob = kratos.add(FakeIdentity::new("bob@example.com"));
    // More than one page of the walk.
    for i in 0..LIST_ALL_PAGE_SIZE {
        kratos.add(FakeIdentity::new(&format!("user{i}@example.com")));
    }

    let users = directory.all_users().await.unwrap();
    assert_eq!(users.len(), usize::from(LIST_ALL_PAGE_SIZE) + 2);
    let find = |id| users.iter().find(|u| u.identity.id == id).unwrap();
    assert_eq!(find(ada).stored.as_ref().unwrap().roles, vec![Role::User]);
    assert!(find(bob).stored.is_none(), "no row yet");
}

#[sqlx::test]
async fn shows_a_users_details(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let id = existing_user(&db, &kratos, "ada@example.com").await;

    let details = directory.details(id).await.unwrap();
    assert_eq!(details.raw_identity["traits"]["email"], "ada@example.com");
    assert_eq!(details.raw_identity["id"], json!(id));
    assert_eq!(details.stored.unwrap().roles, vec![Role::User]);

    assert!(matches!(
        directory.details(Uuid::new_v4()).await,
        Err(DirectoryError::NoSuchUser(_))
    ));
}

#[sqlx::test]
async fn adds_a_user_with_both_halves(db: PgPool) {
    let (directory, kratos) = directory(&db);

    let added = directory
        .add_user(&email("ada@example.com"), "S3cret-pass!")
        .await
        .unwrap();
    assert_eq!(added.roles, vec![Role::User]);
    let identity = kratos.get(added.user.id).unwrap();
    assert_eq!(identity.password.as_deref(), Some("S3cret-pass!"));

    let err = directory
        .add_user(&email("ada@example.com"), "x")
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Conflict(_)), "{err:?}");
}

#[sqlx::test]
async fn adding_reports_an_identity_left_without_data(
    options: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let (_, closed) = open_and_closed(options, connect).await;
    let (directory, kratos) = directory(&closed);

    let err = directory
        .add_user(&email("ada@example.com"), "S3cret-pass!")
        .await
        .unwrap_err();
    let DirectoryError::DataNotCreated { id, .. } = err else {
        panic!("expected DataNotCreated, got {err:?}");
    };
    assert!(kratos.get(id).is_some(), "the identity is kept");
}

#[sqlx::test]
async fn granting_creates_missing_data(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let id = kratos.add(FakeIdentity::new("ada@example.com"));

    let change = directory.grant_role(id, Role::Admin).await.unwrap();
    assert_eq!(
        change,
        RoleChange {
            changed: true,
            roles: vec![Role::Admin, Role::User]
        }
    );
    let again = directory.grant_role(id, Role::Admin).await.unwrap();
    assert!(!again.changed);

    assert!(matches!(
        directory.grant_role(Uuid::new_v4(), Role::Admin).await,
        Err(DirectoryError::NoSuchUser(_))
    ));
}

#[sqlx::test]
async fn revoking_needs_data(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let id = existing_user(&db, &kratos, "ada@example.com").await;

    let change = directory.revoke_role(id, Role::User).await.unwrap();
    assert_eq!(
        change,
        RoleChange {
            changed: true,
            roles: vec![]
        }
    );
    assert!(!directory.revoke_role(id, Role::User).await.unwrap().changed);

    let no_row = kratos.add(FakeIdentity::new("bob@example.com"));
    assert!(matches!(
        directory.revoke_role(no_row, Role::User).await,
        Err(DirectoryError::NoUserData(i)) if i == no_row
    ));
}

#[sqlx::test]
async fn kratos_only_operations(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let accounts = directory.accounts();
    let id = kratos.add(FakeIdentity {
        sessions: 2,
        ..FakeIdentity::new("ada@example.com")
    });

    accounts.revoke_sessions(id).await.unwrap();
    assert_eq!(kratos.get(id).unwrap().sessions, 0);
    accounts.revoke_sessions(id).await.unwrap(); // none left: still fine
    accounts
        .set_state(id, IdentityState::Inactive)
        .await
        .unwrap();
    assert_eq!(kratos.get(id).unwrap().state, IdentityState::Inactive);
    let code = accounts.recovery_code(id).await.unwrap();
    assert!(code.recovery_link.contains(&id.to_string()));

    let nobody = Uuid::new_v4();
    for result in [
        accounts.revoke_sessions(nobody).await,
        accounts.set_state(nobody, IdentityState::Active).await,
        accounts.recovery_code(nobody).await.map(drop),
    ] {
        assert!(matches!(result, Err(DirectoryError::NoSuchUser(i)) if i == nobody));
    }
}

#[sqlx::test]
async fn deletes_both_halves(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let id = existing_user(&db, &kratos, "ada@example.com").await;
    let no_row = kratos.add(FakeIdentity::new("bob@example.com"));

    assert_eq!(
        directory.delete(id).await.unwrap(),
        Deleted { had_data: true }
    );
    assert!(kratos.get(id).is_none());
    assert!(db::find_by_id(&db, id).await.unwrap().is_none());

    assert_eq!(
        directory.delete(no_row).await.unwrap(),
        Deleted { had_data: false }
    );
    assert!(matches!(
        directory.delete(id).await,
        Err(DirectoryError::NoSuchUser(_))
    ));
}

#[sqlx::test]
async fn delete_keeps_the_data_when_kratos_fails(db: PgPool) {
    // Kratos goes first: if it fails, nothing is deleted at all.
    let (directory, kratos) = directory(&db);
    let id = existing_user(&db, &kratos, "ada@example.com").await;
    kratos.fail(Op::Delete);

    assert!(matches!(
        directory.delete(id).await,
        Err(DirectoryError::Kratos(_))
    ));
    assert!(kratos.get(id).is_some());
    assert!(db::find_by_id(&db, id).await.unwrap().is_some());
}

#[sqlx::test]
async fn delete_reports_data_left_behind(options: PgPoolOptions, connect: PgConnectOptions) {
    let (db, closed) = open_and_closed(options, connect).await;
    let kratos = FakeKratos::default();
    let id = existing_user(&db, &kratos, "ada@example.com").await;
    let broken = Directory::new(closed, kratos.clone());

    let err = broken.delete(id).await.unwrap_err();
    assert!(
        matches!(err, DirectoryError::DataLeftBehind { id: i, .. } if i == id),
        "{err:?}"
    );
    assert!(kratos.get(id).is_none(), "the identity is gone");

    // `forget` finishes the job.
    let directory = Directory::new(db.clone(), kratos);
    assert!(directory.forget(id).await.unwrap());
    assert!(!directory.forget(id).await.unwrap());
}
