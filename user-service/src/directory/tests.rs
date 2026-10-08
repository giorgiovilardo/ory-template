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
    assert_eq!(details.user.stored.unwrap().roles, vec![Role::User]);
    assert_eq!(details.user.identity.state, "active");

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

    let change = directory
        .revoke_role(Actor::Operator, id, Role::User)
        .await
        .unwrap();
    assert_eq!(
        change,
        RoleChange {
            changed: true,
            roles: vec![]
        }
    );
    assert!(
        !directory
            .revoke_role(Actor::Operator, id, Role::User)
            .await
            .unwrap()
            .changed
    );

    let no_row = kratos.add(FakeIdentity::new("bob@example.com"));
    assert!(matches!(
        directory.revoke_role(Actor::Operator, no_row, Role::User).await,
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
        directory.delete(Actor::Operator, id).await.unwrap(),
        Deleted { had_data: true }
    );
    assert!(kratos.get(id).is_none());
    assert!(db::find_by_id(&db, id).await.unwrap().is_none());

    assert_eq!(
        directory.delete(Actor::Operator, no_row).await.unwrap(),
        Deleted { had_data: false }
    );
    assert!(matches!(
        directory.delete(Actor::Operator, id).await,
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
        directory.delete(Actor::Operator, id).await,
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

    let err = broken.delete(Actor::Operator, id).await.unwrap_err();
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

#[sqlx::test]
async fn pages_through_users(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let with_row = existing_user(&db, &kratos, "ada@example.com").await;
    for i in 0..4 {
        kratos.add(FakeIdentity::new(&format!("user{i}@example.com")));
    }

    let mut seen = Vec::new();
    let mut token = None;
    loop {
        let page = directory.page(2, token.as_deref()).await.unwrap();
        assert!(page.users.len() <= 2);
        seen.extend(page.users);
        match page.next_page_token {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert_eq!(seen.len(), 5);
    let ada = seen.iter().find(|u| u.identity.id == with_row).unwrap();
    assert_eq!(ada.stored.as_ref().unwrap().roles, vec![Role::User]);
}

#[sqlx::test]
async fn looks_up_every_user_with_an_email(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let ada = existing_user(&db, &kratos, "ada@example.com").await;
    kratos.add(FakeIdentity::new("bob@example.com"));

    let found = directory
        .with_email(&email("ada@example.com"))
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].identity.id, ada);
    assert!(found[0].stored.is_some());

    let twin = kratos.add(FakeIdentity::new("ada@example.com"));
    let found = directory
        .with_email(&email("ada@example.com"))
        .await
        .unwrap();
    assert_eq!(found.len(), 2, "a lookup returns every match");
    assert!(
        found
            .iter()
            .any(|u| u.identity.id == twin && u.stored.is_none())
    );

    assert!(
        directory
            .with_email(&email("nobody@example.com"))
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test]
async fn invites_without_a_password(db: PgPool) {
    let (directory, kratos) = directory(&db);

    let invited = directory.invite(&email("ada@example.com")).await.unwrap();
    let id = invited.user.identity.id;
    let identity = kratos.get(id).unwrap();
    assert_eq!(identity.password, None);
    assert!(!identity.verified, "proven by following the recovery link");
    assert_eq!(invited.user.stored.unwrap().roles, vec![Role::User]);
    assert!(invited.recovery.recovery_link.contains(&id.to_string()));

    let err = directory
        .invite(&email("ada@example.com"))
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Conflict(_)), "{err:?}");
}

#[sqlx::test]
async fn failed_invites_leave_nothing_behind(options: PgPoolOptions, connect: PgConnectOptions) {
    let (db, closed) = open_and_closed(options, connect).await;

    // The row can't be written: the identity is deleted again.
    let (broken, kratos) = directory(&closed);
    assert!(broken.invite(&email("ada@example.com")).await.is_err());
    assert!(kratos.get_by_email("ada@example.com").is_none());

    // No recovery code: identity and row are both deleted again.
    let (directory, kratos) = directory(&db);
    kratos.fail(Op::Recovery);
    let err = directory
        .invite(&email("ada@example.com"))
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Kratos(_)), "{err:?}");
    assert!(kratos.get_by_email("ada@example.com").is_none());
    let rows = sqlx::query_scalar!("select count(*) from users")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(rows, Some(0));
}

#[sqlx::test]
async fn deleting_again_finishes_a_partial_delete(
    options: PgPoolOptions,
    connect: PgConnectOptions,
) {
    let (db, closed) = open_and_closed(options, connect).await;
    let kratos = FakeKratos::default();
    let id = existing_user(&db, &kratos, "ada@example.com").await;
    let broken = Directory::new(closed, kratos.clone());
    assert!(broken.delete(Actor::Operator, id).await.is_err());

    let directory = Directory::new(db.clone(), kratos);
    assert_eq!(
        directory.delete(Actor::Operator, id).await.unwrap(),
        Deleted { had_data: true }
    );
    assert!(db::find_by_id(&db, id).await.unwrap().is_none());
    assert!(matches!(
        directory.delete(Actor::Operator, id).await,
        Err(DirectoryError::NoSuchUser(_))
    ));
}

async fn admin_ids(db: &PgPool) -> Vec<Uuid> {
    db::admin_ids(&mut db.acquire().await.unwrap())
        .await
        .unwrap()
}

/// Two admins with rows and the admin role, both active in Kratos.
async fn two_admins(db: &PgPool, kratos: &FakeKratos) -> (Uuid, Uuid) {
    let ada = existing_user(db, kratos, "ada@example.com").await;
    let bob = existing_user(db, kratos, "bob@example.com").await;
    for id in [ada, bob] {
        db::grant_role(db, id, Role::Admin).await.unwrap();
    }
    (ada, bob)
}

#[sqlx::test]
async fn admins_cant_remove_their_own_access(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let (ada, _) = two_admins(&db, &kratos).await;
    let me = Actor::Admin(ada);

    for result in [
        directory.revoke_role(me, ada, Role::Admin).await.map(drop),
        directory.deactivate(me, ada).await,
        directory.delete(me, ada).await.map(drop),
    ] {
        assert!(
            matches!(result, Err(DirectoryError::SelfAction)),
            "{result:?}"
        );
    }
    assert!(db::has_role(&db, ada, Role::Admin).await.unwrap());
    assert_eq!(kratos.get(ada).unwrap().state, IdentityState::Active);

    // Dropping their own `user` role takes no admin access away.
    assert!(directory.revoke_role(me, ada, Role::User).await.is_ok());
}

#[sqlx::test]
async fn the_last_active_admin_stays(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let (ada, bob) = two_admins(&db, &kratos).await;
    let carol = existing_user(&db, &kratos, "carol@example.com").await;

    // Bob is inactive, so Ada is the only active admin: nobody can remove her...
    directory
        .accounts()
        .set_state(bob, IdentityState::Inactive)
        .await
        .unwrap();
    let as_bob = Actor::Admin(bob);
    for result in [
        directory
            .revoke_role(as_bob, ada, Role::Admin)
            .await
            .map(drop),
        directory.deactivate(as_bob, ada).await,
        directory.delete(as_bob, ada).await.map(drop),
    ] {
        assert!(
            matches!(result, Err(DirectoryError::LastAdmin(id)) if id == ada),
            "{result:?}"
        );
    }

    // ...but anyone else, inactive admins included, can be.
    let as_ada = Actor::Admin(ada);
    directory.deactivate(as_ada, carol).await.unwrap();
    directory
        .revoke_role(as_ada, bob, Role::Admin)
        .await
        .unwrap();

    // The CLI is how you get back in, so the rules don't apply to it.
    directory
        .revoke_role(Actor::Operator, ada, Role::Admin)
        .await
        .unwrap();
    assert_eq!(admin_ids(&db).await.len(), 0, "nobody is admin now");
}

#[sqlx::test]
async fn two_admins_cant_remove_each_other_at_once(db: PgPool) {
    let (directory, kratos) = directory(&db);
    let (ada, bob) = two_admins(&db, &kratos).await;

    for _ in 0..20 {
        let (a, b) = tokio::join!(
            directory.revoke_role(Actor::Admin(ada), bob, Role::Admin),
            directory.revoke_role(Actor::Admin(bob), ada, Role::Admin),
        );
        let refused = [&a, &b]
            .iter()
            .filter(|r| matches!(r, Err(DirectoryError::LastAdmin(_))))
            .count();
        assert_eq!(refused, 1, "{a:?} {b:?}");
        assert_eq!(admin_ids(&db).await.len(), 1);
        // Restore for the next round.
        for id in [ada, bob] {
            db::grant_role(&db, id, Role::Admin).await.unwrap();
        }
    }
}
