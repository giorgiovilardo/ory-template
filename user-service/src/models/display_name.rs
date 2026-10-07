use serde::{Deserialize, Serialize};

const MAX_CHARS: usize = 100;

/// A user's public name: trimmed, 1..=100 characters, no control characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(try_from = "String", into = "String")]
#[sqlx(transparent)]
pub struct DisplayName(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DisplayNameError {
    #[error("display name is empty")]
    Empty,
    #[error("display name is longer than {MAX_CHARS} characters")]
    TooLong,
    #[error("display name contains control characters")]
    ControlCharacters,
}

impl DisplayNameError {
    /// Stable machine-readable code for API responses.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "display_name_empty",
            Self::TooLong => "display_name_too_long",
            Self::ControlCharacters => "display_name_control_characters",
        }
    }
}

impl TryFrom<String> for DisplayName {
    type Error = DisplayNameError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let name = raw.trim();

        if name.is_empty() {
            return Err(DisplayNameError::Empty);
        }
        // Characters, not bytes: "Zoë" is 3 characters but 4 bytes.
        if name.chars().count() > MAX_CHARS {
            return Err(DisplayNameError::TooLong);
        }
        if name.chars().any(char::is_control) {
            return Err(DisplayNameError::ControlCharacters);
        }
        Ok(Self(name.to_owned()))
    }
}

impl From<DisplayName> for String {
    fn from(name: DisplayName) -> Self {
        name.0
    }
}

impl AsRef<str> for DisplayName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<DisplayName, DisplayNameError> {
        DisplayName::try_from(s.to_owned())
    }

    #[test]
    fn trims_valid_names() {
        assert_eq!(parse("  Ada Lovelace ").unwrap().as_ref(), "Ada Lovelace");
    }

    #[test]
    fn counts_characters_not_bytes() {
        assert!(parse(&"ë".repeat(MAX_CHARS)).is_ok());
        assert_eq!(
            parse(&"ë".repeat(MAX_CHARS + 1)),
            Err(DisplayNameError::TooLong)
        );
    }

    #[test]
    fn rejects_invalid_names() {
        assert_eq!(parse(""), Err(DisplayNameError::Empty));
        assert_eq!(parse(" \t "), Err(DisplayNameError::Empty));
        assert_eq!(
            parse("Ada\u{0}Lovelace"),
            Err(DisplayNameError::ControlCharacters)
        );
        assert_eq!(
            parse("Ada\nLovelace"),
            Err(DisplayNameError::ControlCharacters)
        );
    }

    #[test]
    fn deserializing_validates() {
        assert!(serde_json::from_str::<DisplayName>(r#""Ada""#).is_ok());
        assert!(serde_json::from_str::<DisplayName>(r#""  ""#).is_err());
    }
}
