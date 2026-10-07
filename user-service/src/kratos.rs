//! What this service reads from Kratos. Only the fields we use are modeled; serde
//! ignores the rest, so Kratos adding fields never breaks us.

use serde::Deserialize;
use uuid::Uuid;

use crate::models::Email;

/// The Kratos session, as Oathkeeper puts it in the hydrator's `extra`
/// (`extra_from: "@this"` = the whole `/sessions/whoami` response).
#[derive(Debug, Deserialize)]
pub struct KratosSession {
    pub identity: KratosIdentity,
}

#[derive(Debug, Deserialize)]
pub struct KratosIdentity {
    pub id: Uuid,
    pub traits: Traits,
}

/// Mirrors kratos/identity.schema.json. Change one, change the other.
#[derive(Debug, Deserialize)]
pub struct Traits {
    pub email: Email,
}

/// Looks up an identity by login email through the Kratos admin API.
pub async fn find_identity_by_email(
    http: &reqwest::Client,
    admin_url: &str,
    email: &Email,
) -> anyhow::Result<Option<KratosIdentity>> {
    let identities: Vec<KratosIdentity> = http
        .get(format!("{admin_url}/admin/identities"))
        .query(&[("credentials_identifier", email.as_ref())])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(identities.into_iter().next())
}
