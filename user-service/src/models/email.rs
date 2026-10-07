use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

const MAX_LEN: usize = 320;

/// A normalized (trimmed, lowercased) email address.
///
/// Emails reach this service from Kratos, which already validated them against the
/// identity schema, so this is a sanity check rather than full RFC 5322 validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(try_from = "String", into = "String")]
#[sqlx(transparent)]
pub struct Email(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmailError {
    #[error("email is empty")]
    Empty,
    #[error("email is longer than {MAX_LEN} characters")]
    TooLong,
    #[error("email must contain exactly one '@' with text on both sides and no spaces")]
    Malformed,
}

impl EmailError {
    /// Stable machine-readable code for API responses.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "email_empty",
            Self::TooLong => "email_too_long",
            Self::Malformed => "email_malformed",
        }
    }
}

impl TryFrom<String> for Email {
    type Error = EmailError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let email = raw.trim().to_lowercase();

        if email.is_empty() {
            return Err(EmailError::Empty);
        }
        if email.len() > MAX_LEN {
            return Err(EmailError::TooLong);
        }
        match email.split_once('@') {
            Some((local, domain))
                if !local.is_empty()
                    && !domain.is_empty()
                    && !domain.contains('@')
                    && !email.contains(char::is_whitespace) =>
            {
                Ok(Self(email))
            }
            _ => Err(EmailError::Malformed),
        }
    }
}

impl FromStr for Email {
    type Err = EmailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<Email> for String {
    fn from(email: Email) -> Self {
        email.0
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_valid_emails() {
        let email: Email = "  Ada.Lovelace+test@Example.COM ".parse().unwrap();
        assert_eq!(email.as_ref(), "ada.lovelace+test@example.com");
    }

    #[test]
    fn rejects_invalid_emails() {
        let cases = [
            ("", EmailError::Empty),
            ("   ", EmailError::Empty),
            ("no-at-sign", EmailError::Malformed),
            ("@example.com", EmailError::Malformed),
            ("ada@", EmailError::Malformed),
            ("ada@@example.com", EmailError::Malformed),
            ("a@b@example.com", EmailError::Malformed),
            ("ada lovelace@example.com", EmailError::Malformed),
        ];
        for (input, expected) in cases {
            assert_eq!(input.parse::<Email>(), Err(expected), "input: {input:?}");
        }
    }

    #[test]
    fn rejects_too_long() {
        let input = format!("{}@example.com", "a".repeat(MAX_LEN));
        assert_eq!(input.parse::<Email>(), Err(EmailError::TooLong));
    }

    #[test]
    fn deserializing_validates() {
        let email: Email = serde_json::from_str(r#"" Ada@Example.com""#).unwrap();
        assert_eq!(email.as_ref(), "ada@example.com");

        let err = serde_json::from_str::<Email>(r#""nope""#).unwrap_err();
        assert!(err.to_string().contains("exactly one '@'"), "got: {err}");
    }

    #[test]
    fn serializes_as_plain_string() {
        let email: Email = "ada@example.com".parse().unwrap();
        assert_eq!(
            serde_json::to_string(&email).unwrap(),
            r#""ada@example.com""#
        );
    }

    #[test]
    fn errors_have_message_and_stable_code() {
        assert_eq!(EmailError::Empty.to_string(), "email is empty");
        assert_eq!(EmailError::Empty.code(), "email_empty");
    }
}
