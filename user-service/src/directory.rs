//! The user directory: the one place that manages "a user", which is a Kratos identity
//! (login, sessions, whether they may log in) plus this service's row (profile, roles).
//! The CLI (`admin.rs`) is a thin adapter over it: it parses input, calls one method,
//! and presents the typed result or error. Nothing here prints or reads config.
//!
//! Users are addressed by Kratos identity id. Emails are resolved through Kratos, the
//! only reliable email -> id mapping: our `users.email` is a copy that is neither unique
//! nor current, so matching on it can pick another account or miss the right one.
//!
//! Kratos sits behind the `IdentityAdmin` port, implemented by `kratos::AdminApi`, so the
//! logic here is tested against an in-memory fake (`directory/fake.rs`).

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::db;
use crate::kratos::{
    Identity, IdentityPage, IdentityState, KratosError, KratosIdentity, RecoveryCode, Traits,
};
use crate::models::{Email, Role, UserWithRoles};

#[cfg(test)]
pub mod fake;
#[cfg(test)]
mod tests;

/// Page size when walking every identity.
const LIST_ALL_PAGE_SIZE: u16 = 250;

/// What the directory needs from the Kratos admin API. Methods return `Send` futures so
/// callers generic over the port (HTTP handlers) stay `Send`.
pub trait IdentityAdmin: Send + Sync {
    /// Every identity whose email is `email`; picking one is the caller's decision.
    fn identities_with_email(
        &self,
        email: &Email,
    ) -> impl Future<Output = Result<Vec<KratosIdentity>, KratosError>> + Send;

    fn list_page(
        &self,
        page_size: u16,
        page_token: Option<&str>,
    ) -> impl Future<Output = Result<IdentityPage, KratosError>> + Send;

    /// The full identity, as Kratos returns it.
    fn identity(&self, id: Uuid) -> impl Future<Output = Result<Value, KratosError>> + Send;

    fn active_sessions(&self, id: Uuid) -> impl Future<Output = Result<usize, KratosError>> + Send;

    fn create_identity(
        &self,
        email: &Email,
        password: Option<&str>,
    ) -> impl Future<Output = Result<KratosIdentity, KratosError>> + Send;

    fn revoke_sessions(&self, id: Uuid) -> impl Future<Output = Result<(), KratosError>> + Send;

    fn set_state(
        &self,
        id: Uuid,
        state: IdentityState,
    ) -> impl Future<Output = Result<(), KratosError>> + Send;

    fn recovery_code(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<RecoveryCode, KratosError>> + Send;

    fn delete_identity(&self, id: Uuid) -> impl Future<Output = Result<(), KratosError>> + Send;

    /// Every identity, page by page.
    fn all_identities(&self) -> impl Future<Output = Result<Vec<Identity>, KratosError>> + Send {
        async move {
            let mut identities = Vec::new();
            let mut token = None;
            loop {
                let page = self.list_page(LIST_ALL_PAGE_SIZE, token.as_deref()).await?;
                let empty = page.identities.is_empty();
                identities.extend(page.identities);
                match page.next_page_token {
                    Some(next) if !empty => token = Some(next),
                    _ => return Ok(identities),
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("no Kratos identity with email {0}")]
    NoSuchEmail(Email),
    #[error("no Kratos identity with id {0}")]
    NoSuchUser(Uuid),
    #[error("several Kratos identities have the email {email}: {}", list(.ids))]
    AmbiguousEmail { email: Email, ids: Vec<Uuid> },
    #[error("{0} has no user-service data, so no roles")]
    NoUserData(Uuid),
    #[error("the Kratos identity {0} has no valid email")]
    InvalidIdentity(Uuid),
    /// Kratos' page tokens are opaque: only one it handed out is valid.
    #[error("invalid page_token: pass back a next_page_token as is")]
    InvalidPageToken,
    /// Kratos refused because of existing data, e.g. the email is taken.
    #[error(transparent)]
    Conflict(KratosError),
    /// An admin tried to revoke their own admin role, deactivate or delete themselves.
    #[error("admins can't remove their own access; ask another admin")]
    SelfAction,
    #[error("{0} is the last active admin")]
    LastAdmin(Uuid),
    #[error("the Kratos identity {id} exists, but creating its user-service data failed")]
    DataNotCreated {
        id: Uuid,
        #[source]
        source: sqlx::Error,
    },
    /// Only the second step of a delete failed: deleting again (or `forget`) finishes it.
    #[error("deleted the Kratos identity {id}, but not its user-service data")]
    DataLeftBehind {
        id: Uuid,
        #[source]
        source: sqlx::Error,
    },
    #[error(transparent)]
    Kratos(KratosError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

fn list(ids: &[Uuid]) -> String {
    ids.iter().fold(String::new(), |mut out, id| {
        let sep = if out.is_empty() { "" } else { ", " };
        let _ = write!(out, "{sep}{id}");
        out
    })
}

impl From<KratosError> for DirectoryError {
    fn from(err: KratosError) -> Self {
        match err.status() {
            Some(StatusCode::CONFLICT) => Self::Conflict(err),
            _ => Self::Kratos(err),
        }
    }
}

/// For calls naming an identity: Kratos' 404 means there is no such user.
fn about(id: Uuid) -> impl Fn(KratosError) -> DirectoryError {
    move |err| match err.status() {
        Some(StatusCode::NOT_FOUND) => DirectoryError::NoSuchUser(id),
        _ => err.into(),
    }
}

type Result<T, E = DirectoryError> = std::result::Result<T, E>;

/// Who is acting, for the lockout rules. They protect admins from locking each other
/// (or themselves) out through the HTTP API. The CLI is `Operator`: access to the
/// container is its authority and it is the way back in after a lockout, so the rules
/// don't apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    Operator,
    Admin(Uuid),
}

/// A user in a listing: the Kratos identity, plus this service's data if it has any.
#[derive(Debug)]
pub struct ListedUser {
    pub identity: Identity,
    pub stored: Option<UserWithRoles>,
}

#[derive(Debug)]
pub struct UsersPage {
    pub users: Vec<ListedUser>,
    pub next_page_token: Option<String>,
}

#[derive(Debug)]
pub struct UserDetails {
    pub user: ListedUser,
    /// The whole identity as Kratos returned it, linked social logins included.
    pub raw_identity: Value,
    pub active_sessions: usize,
}

#[derive(Debug)]
pub struct Invited {
    pub user: ListedUser,
    pub recovery: RecoveryCode,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RoleChange {
    /// False if the user already had (or already lacked) the role.
    pub changed: bool,
    pub roles: Vec<Role>,
}

/// What `reconcile` did, by identity id.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Identities without a row: created, with the `user` role.
    pub created: Vec<Uuid>,
    /// Rows whose email copy was stale: refreshed.
    pub refreshed: Vec<Uuid>,
    /// Identities without a valid email, left alone.
    pub skipped: Vec<Uuid>,
    /// Rows with no Kratos identity (e.g. after a failed delete): reported, not deleted.
    pub orphans: Vec<Uuid>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Deleted {
    /// False if this service had no data for the user.
    pub had_data: bool,
}

/// The operations that only touch Kratos, so the CLI can run them without a database.
pub struct Accounts<K> {
    kratos: K,
}

impl<K: IdentityAdmin> Accounts<K> {
    pub fn new(kratos: K) -> Self {
        Self { kratos }
    }

    /// The one identity with this email. Refuses to pick when several have it: the
    /// caller is about to act on the result.
    pub async fn resolve(&self, email: &Email) -> Result<KratosIdentity> {
        let mut found = self.kratos.identities_with_email(email).await?;
        match found.len() {
            0 => Err(DirectoryError::NoSuchEmail(email.clone())),
            1 => Ok(found.remove(0)),
            _ => Err(DirectoryError::AmbiguousEmail {
                email: email.clone(),
                ids: found.iter().map(|identity| identity.id).collect(),
            }),
        }
    }

    /// Deletes every session: logged out everywhere. Kratos answers 404 both when the
    /// identity doesn't exist and when it has no sessions, so a 404 is told apart by
    /// looking the identity up: no sessions means nothing to do.
    pub async fn revoke_sessions(&self, id: Uuid) -> Result<()> {
        match self.kratos.revoke_sessions(id).await {
            Err(err) if err.status() == Some(StatusCode::NOT_FOUND) => {
                self.identity(id).await?;
                Ok(())
            }
            result => Ok(result?),
        }
    }

    /// `Inactive` suspends the sessions and refuses logins; `Active` restores them.
    /// Unguarded: admins deactivate through `Directory::deactivate`.
    pub async fn set_state(&self, id: Uuid, state: IdentityState) -> Result<()> {
        self.kratos.set_state(id, state).await.map_err(about(id))
    }

    /// A one-hour recovery link and code, for an admin to send to the user.
    pub async fn recovery_code(&self, id: Uuid) -> Result<RecoveryCode> {
        self.kratos.recovery_code(id).await.map_err(about(id))
    }

    /// The identity, typed, and as Kratos returned it.
    async fn identity(&self, id: Uuid) -> Result<(Identity, Value)> {
        let raw = self.kratos.identity(id).await.map_err(about(id))?;
        let identity =
            Identity::deserialize(&raw).map_err(|_| DirectoryError::InvalidIdentity(id))?;
        Ok((identity, raw))
    }

    /// Whether the identity exists and may log in.
    async fn is_active(&self, id: Uuid) -> Result<bool> {
        match self.identity(id).await {
            Ok((identity, _)) => Ok(identity.state == "active"),
            Err(DirectoryError::NoSuchUser(_)) => Ok(false),
            Err(err) => Err(err),
        }
    }
}

/// Everything that touches both Kratos and this service's database.
pub struct Directory<K> {
    db: PgPool,
    accounts: Accounts<K>,
}

impl<K: IdentityAdmin> Directory<K> {
    pub fn new(db: PgPool, kratos: K) -> Self {
        Self {
            db,
            accounts: Accounts::new(kratos),
        }
    }

    pub fn accounts(&self) -> &Accounts<K> {
        &self.accounts
    }

    fn kratos(&self) -> &K {
        &self.accounts.kratos
    }

    /// Every user, in Kratos' order.
    pub async fn all_users(&self) -> Result<Vec<ListedUser>> {
        let identities = self.kratos().all_identities().await?;
        self.with_stored(identities).await
    }

    /// One page of users, in Kratos' order. `page_token` is the previous page's
    /// `next_page_token`, passed through as is.
    pub async fn page(&self, page_size: u16, page_token: Option<&str>) -> Result<UsersPage> {
        let page = match self.kratos().list_page(page_size, page_token).await {
            Err(err) if page_token.is_some() && err.status() == Some(StatusCode::BAD_REQUEST) => {
                return Err(DirectoryError::InvalidPageToken);
            }
            page => page?,
        };
        Ok(UsersPage {
            users: self.with_stored(page.identities).await?,
            next_page_token: page.next_page_token,
        })
    }

    /// Every user with this email (usually one; Kratos doesn't make emails unique across
    /// login methods). A lookup, so several matches are a result, not an error.
    pub async fn with_email(&self, email: &Email) -> Result<Vec<ListedUser>> {
        let mut identities = Vec::new();
        for found in self.kratos().identities_with_email(email).await? {
            identities.push(self.accounts.identity(found.id).await?.0);
        }
        self.with_stored(identities).await
    }

    async fn with_stored(&self, identities: Vec<Identity>) -> Result<Vec<ListedUser>> {
        let ids: Vec<Uuid> = identities.iter().map(|identity| identity.id).collect();
        let mut stored: HashMap<Uuid, UserWithRoles> = db::find_many_with_roles(&self.db, &ids)
            .await?
            .into_iter()
            .map(|found| (found.user.id, found))
            .collect();
        Ok(identities
            .into_iter()
            .map(|identity| ListedUser {
                stored: stored.remove(&identity.id),
                identity,
            })
            .collect())
    }

    pub async fn details(&self, id: Uuid) -> Result<UserDetails> {
        let (identity, raw_identity) = self.accounts.identity(id).await?;
        let active_sessions = self.kratos().active_sessions(id).await.map_err(about(id))?;
        let stored = db::find_with_roles(&self.db, id).await?;
        Ok(UserDetails {
            user: ListedUser { identity, stored },
            raw_identity,
            active_sessions,
        })
    }

    /// Creates a Kratos identity with a password and a verified email, then its row with
    /// the `user` role. For dev seeding. If the row fails, the identity is kept.
    pub async fn add_user(&self, email: &Email, password: &str) -> Result<UserWithRoles> {
        let identity = self.kratos().create_identity(email, Some(password)).await?;
        db::sync_identity(&self.db, &identity)
            .await
            .map_err(|source| DirectoryError::DataNotCreated {
                id: identity.id,
                source,
            })
    }

    /// Creates a Kratos identity with no credentials and its row with the `user` role,
    /// then a recovery link + code for the admin to send: following it, the user sets
    /// their own password (or passkey). All or nothing: nobody has the link until this
    /// returns, so after a failure the identity is deleted again and a retry starts clean.
    pub async fn invite(&self, email: &Email) -> Result<Invited> {
        let created = self.kratos().create_identity(email, None).await?;
        let id = created.id;
        let completed = async {
            db::sync_identity(&self.db, &created).await?;
            let recovery = self.accounts.recovery_code(id).await?;
            let (identity, _) = self.accounts.identity(id).await?;
            let stored = db::find_with_roles(&self.db, id).await?;
            Ok::<_, DirectoryError>(Invited {
                user: ListedUser { identity, stored },
                recovery,
            })
        }
        .await;
        if completed.is_err()
            && let Err(err) = self.delete(Actor::Operator, id).await
        {
            tracing::error!(%id, error = %err, "could not undo a failed invite");
        }
        completed
    }

    /// Creates the row for a user who has none yet (and refreshes a stale email copy)
    /// first, so this works for anyone with a Kratos identity.
    pub async fn grant_role(&self, id: Uuid, role: Role) -> Result<RoleChange> {
        let identity = self.kratos_identity(id).await?;
        db::sync_identity(&self.db, &identity).await?;
        let changed = db::grant_role(&self.db, id, role).await?;
        let roles = db::roles_of(&self.db, id).await?;
        Ok(RoleChange { changed, roles })
    }

    /// Revoking `admin` is guarded (see `AdminGuard`).
    pub async fn revoke_role(&self, actor: Actor, id: Uuid, role: Role) -> Result<RoleChange> {
        if db::find_by_id(&self.db, id).await?.is_none() {
            return Err(DirectoryError::NoUserData(id));
        }
        let guard = match role {
            Role::Admin => self.guard(actor, id).await?,
            Role::User => None,
        };
        let changed = db::revoke_role(&self.db, id, role).await?;
        drop(guard);
        let roles = db::roles_of(&self.db, id).await?;
        Ok(RoleChange { changed, roles })
    }

    /// Blocks the user: sessions stop working at once and login is refused. Guarded.
    pub async fn deactivate(&self, actor: Actor, id: Uuid) -> Result<()> {
        let guard = self.guard(actor, id).await?;
        self.accounts.set_state(id, IdentityState::Inactive).await?;
        drop(guard);
        Ok(())
    }

    /// Deletes the Kratos identity, then this service's data. Kratos first: once the
    /// identity is gone, no request can reach us for this user, so nothing can re-create
    /// the row we're about to delete. (The other way round, a request in between would
    /// leave an orphan.) If the second step fails, deleting again finishes the job: an
    /// identity that is already gone just has its data deleted. Guarded.
    pub async fn delete(&self, actor: Actor, id: Uuid) -> Result<Deleted> {
        let guard = self.guard(actor, id).await?;
        let identity_gone = match self.kratos().delete_identity(id).await.map_err(about(id)) {
            Ok(()) => false,
            Err(DirectoryError::NoSuchUser(_)) => true,
            Err(err) => return Err(err),
        };
        drop(guard);
        let had_data = db::delete_user(&self.db, id)
            .await
            .map_err(|source| DirectoryError::DataLeftBehind { id, source })?;
        if identity_gone && !had_data {
            return Err(DirectoryError::NoSuchUser(id));
        }
        Ok(Deleted { had_data })
    }

    /// Brings this service's rows in line with Kratos: creates the missing ones and
    /// refreshes stale email copies. Kratos' web hook normally does both, so this is for
    /// whatever it missed: a failed hook, identities made through Kratos' admin API, users
    /// from before the hook existed. Idempotent. Orphan rows are only reported: deleting
    /// data is `forget`'s job, on purpose.
    pub async fn reconcile(&self) -> Result<Reconciled> {
        // Rows first: one created after this by a new registration can't be mistaken
        // for an orphan, since its identity will be in the listing below.
        let rows = db::all_user_ids(&self.db).await?;
        let users = self.all_users().await?;
        let known: HashSet<Uuid> = users.iter().map(|user| user.identity.id).collect();

        let mut done = Reconciled::default();
        for ListedUser { identity, stored } in users {
            let id = identity.id;
            let Some(email) = identity
                .traits
                .email
                .and_then(|email| email.parse::<Email>().ok())
            else {
                done.skipped.push(id);
                continue;
            };
            match stored {
                None => done.created.push(id),
                Some(stored) if stored.user.email != email => done.refreshed.push(id),
                Some(_) => continue,
            }
            let identity = KratosIdentity {
                id,
                traits: Traits { email },
            };
            db::sync_identity(&self.db, &identity).await?;
        }
        done.orphans = rows.into_iter().filter(|id| !known.contains(id)).collect();
        Ok(done)
    }

    /// Deletes only this service's data. Returns false if there was none.
    pub async fn forget(&self, id: Uuid) -> Result<bool> {
        Ok(db::delete_user(&self.db, id).await?)
    }

    /// The lockout rules, for an admin about to take admin access away from `target`
    /// (revoke its admin role, deactivate or delete it): nobody can do it to themselves,
    /// and the last active admin stays. "Active" lives in Kratos, so the check can't be
    /// one SQL statement; instead every such check-then-act holds a transaction-scoped
    /// advisory lock until the action is done (drop the guard after acting). Otherwise
    /// two admins removing each other at the same moment would both see the other and
    /// leave nobody.
    async fn guard(&self, actor: Actor, target: Uuid) -> Result<Option<AdminGuard>> {
        let Actor::Admin(me) = actor else {
            return Ok(None);
        };
        if me == target {
            return Err(DirectoryError::SelfAction);
        }
        let mut lock = self.db.begin().await?;
        db::lock_admin_changes(&mut lock).await?;
        let admins = db::admin_ids(&mut lock).await?;
        if admins.contains(&target) && self.accounts.is_active(target).await? {
            let mut another_active = false;
            for other in admins.into_iter().filter(|id| *id != target) {
                if self.accounts.is_active(other).await? {
                    another_active = true;
                    break;
                }
            }
            if !another_active {
                return Err(DirectoryError::LastAdmin(target));
            }
        }
        Ok(Some(AdminGuard(lock)))
    }

    /// The identity's id and validated email, the input of `db::sync_identity`.
    async fn kratos_identity(&self, id: Uuid) -> Result<KratosIdentity> {
        let raw = self.kratos().identity(id).await.map_err(about(id))?;
        KratosIdentity::deserialize(&raw).map_err(|_| DirectoryError::InvalidIdentity(id))
    }
}

/// Holds the advisory lock taken by `Directory::guard`; dropping it (rolling back the
/// transaction, which wrote nothing) releases the lock.
struct AdminGuard(
    #[expect(dead_code, reason = "held for its drop")] Transaction<'static, Postgres>,
);
