use std::fmt;
use std::str::FromStr;

use serde::de::IntoDeserializer;
use serde::{Deserialize, Serialize};

/// Global role. Stored as text in `user_roles.role`, serialized lowercase in JSON and JWTs.
///
/// Adding a variant also needs a migration that updates the `user_roles.role` check constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub const ALL: [Role; 2] = [Role::Admin, Role::User];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "unknown role {0:?} (expected one of: {expected})",
    expected = Role::ALL.map(|role| role.as_str()).join(", ")
)]
pub struct UnknownRole(String);

impl FromStr for Role {
    type Err = UnknownRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Reuse the serde derive so the accepted spellings can't drift from it.
        Self::deserialize(IntoDeserializer::<serde::de::value::Error>::into_deserializer(s))
            .map_err(|_| UnknownRole(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_forms_agree() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>().unwrap(), role);
            assert_eq!(serde_json::to_string(&role).unwrap(), format!("\"{role}\""));
        }
    }

    #[test]
    fn rejects_unknown_roles() {
        assert!("superuser".parse::<Role>().is_err());
        assert!("Admin".parse::<Role>().is_err());
        assert_eq!(
            "x".parse::<Role>().unwrap_err().to_string(),
            r#"unknown role "x" (expected one of: admin, user)"#
        );
    }
}
