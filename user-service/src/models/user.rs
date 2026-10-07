use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{DisplayName, Email, Role};

/// A row of `users`. Fields are public: every invariant lives in the field types,
/// and rows are only ever built from the database (`db.rs`), never from client input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    /// Kratos identity id = JWT `sub`.
    pub id: Uuid,
    /// Copy of the Kratos login email; Kratos owns it.
    pub email: Email,
    pub display_name: Option<DisplayName>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// A user together with their roles, read in one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserWithRoles {
    pub user: User,
    pub roles: Vec<Role>,
}

/// What the hydrator adds to the Oathkeeper session as `extra.profile`, and therefore
/// what ends up in every JWT. Kept separate from `User` so a new column never leaks
/// into tokens by accident: every claim is an explicit decision.
#[derive(Debug, Serialize)]
pub struct Profile<'a> {
    pub display_name: Option<&'a DisplayName>,
    pub roles: &'a [Role],
}
