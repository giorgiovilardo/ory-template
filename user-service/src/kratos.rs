//! What this service reads from Kratos, and the admin API client behind the
//! `IdentityAdmin` port (`directory.rs`). Only the fields we use are modeled; serde
//! ignores the rest, so Kratos adding fields never breaks us.

use std::collections::BTreeMap;

use reqwest::header::{HeaderMap, LINK};
use reqwest::{RequestBuilder, Response, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::directory::IdentityAdmin;
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

/// An identity as the admin API returns it. Parsed leniently: one identity with an odd
/// email (or a missing field) must not make a whole listing fail.
#[derive(Debug, Clone, Deserialize)]
pub struct Identity {
    pub id: Uuid,
    #[serde(default)]
    pub traits: IdentityTraits,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub verifiable_addresses: Vec<VerifiableAddress>,
    #[serde(default)]
    pub created_at: String,
    /// Login methods by type (`password`, `oidc`, `totp`, ...). Only the keys are used.
    #[serde(default)]
    pub credentials: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct IdentityTraits {
    pub email: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifiableAddress {
    #[serde(default)]
    pub verified: bool,
}

impl Identity {
    pub fn verified(&self) -> bool {
        self.verifiable_addresses.iter().any(|a| a.verified)
    }

    fn matching(self, wanted: &Email) -> Option<KratosIdentity> {
        let email: Email = self.traits.email?.parse().ok()?;
        (&email == wanted).then_some(KratosIdentity {
            id: self.id,
            traits: Traits { email },
        })
    }
}

/// One page of the identity list. `next_page_token` is Kratos' opaque cursor, `None` on
/// the last page.
#[derive(Debug)]
pub struct IdentityPage {
    pub identities: Vec<Identity>,
    pub next_page_token: Option<String>,
}

/// Whether an identity may log in. `Inactive` suspends its sessions (they stop working
/// at once) and refuses logins; back to `Active`, the suspended sessions work again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityState {
    Active,
    Inactive,
}

/// Secrets: never log them.
#[derive(Deserialize)]
#[expect(clippy::struct_field_names, reason = "Kratos' field names")]
pub struct RecoveryCode {
    pub recovery_link: String,
    pub recovery_code: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCode").finish_non_exhaustive()
    }
}

/// A failed call to the Kratos admin API. `Status` carries Kratos' own explanation,
/// which is what an admin needs to see, e.g. "An identity with the same identifier
/// already exists".
#[derive(Debug, thiserror::Error)]
pub enum KratosError {
    #[error("{what}: could not reach the Kratos admin API")]
    Transport {
        what: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{what} -> {status}: {reason}")]
    Status {
        what: String,
        status: StatusCode,
        reason: String,
    },
    #[error("{what}: unexpected response from the Kratos admin API")]
    Response {
        what: String,
        #[source]
        source: reqwest::Error,
    },
}

impl KratosError {
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Status { status, .. } => Some(*status),
            Self::Transport { .. } | Self::Response { .. } => None,
        }
    }

    /// Kratos' explanation, when it answered with an error.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Status { reason, .. } => Some(reason),
            Self::Transport { .. } | Self::Response { .. } => None,
        }
    }
}

/// The Kratos admin API (reference: <https://www.ory.sh/docs/kratos/reference/api>).
/// It can do anything to any identity, so it is only ever reachable on the compose
/// network and 127.0.0.1.
pub struct AdminApi {
    http: reqwest::Client,
    url: String,
}

impl AdminApi {
    pub fn new(http: reqwest::Client, url: &str) -> Self {
        Self {
            http,
            url: url.trim_end_matches('/').to_owned(),
        }
    }

    fn identities(&self) -> String {
        format!("{}/admin/identities", self.url)
    }

    fn identity_url(&self, id: Uuid) -> String {
        format!("{}/admin/identities/{id}", self.url)
    }

    /// Sends the request; a non-2xx response becomes `KratosError::Status` with Kratos'
    /// `error.reason`, else `error.message`, else the raw body. Also returns the
    /// "METHOD /path" label for later errors.
    async fn send(&self, request: RequestBuilder) -> Result<(String, Response), KratosError> {
        let request = request.build().map_err(|source| KratosError::Transport {
            what: "building a request".to_owned(),
            source,
        })?;
        let what = format!("{} {}", request.method(), request.url().path());
        let response = match self.http.execute(request).await {
            Ok(response) => response,
            Err(source) => return Err(KratosError::Transport { what, source }),
        };
        let status = response.status();
        if status.is_success() {
            return Ok((what, response));
        }
        let body = response.text().await.unwrap_or_default();
        let reason = serde_json::from_str::<ErrorBody>(&body)
            .ok()
            .and_then(|b| b.error.reason.or(b.error.message))
            .unwrap_or(body);
        Err(KratosError::Status {
            what,
            status,
            reason,
        })
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<T, KratosError> {
        let (what, response) = self.send(request).await?;
        response
            .json()
            .await
            .map_err(|source| KratosError::Response { what, source })
    }
}

impl IdentityAdmin for AdminApi {
    /// Tries the credentials index first (one cheap request). That index lists the
    /// identifiers an identity can log in with, which may not include an identity that
    /// registered through a social provider, so on a miss this scans every identity's
    /// `traits.email`. That's linear in the number of users, which is fine for admin
    /// lookups.
    async fn identities_with_email(
        &self,
        email: &Email,
    ) -> Result<Vec<KratosIdentity>, KratosError> {
        let mut by_credentials: Vec<KratosIdentity> = self
            .send_json(
                self.http
                    .get(self.identities())
                    .query(&[("credentials_identifier", email.as_ref())]),
            )
            .await?;
        if !by_credentials.is_empty() {
            by_credentials.dedup_by_key(|identity| identity.id);
            return Ok(by_credentials);
        }
        Ok(self
            .all_identities()
            .await?
            .into_iter()
            .filter_map(|identity| identity.matching(email))
            .collect())
    }

    async fn list_page(
        &self,
        page_size: u16,
        page_token: Option<&str>,
    ) -> Result<IdentityPage, KratosError> {
        let mut query = vec![("page_size", page_size.to_string())];
        if let Some(token) = page_token {
            query.push(("page_token", token.to_owned()));
        }
        let (what, response) = self
            .send(self.http.get(self.identities()).query(&query))
            .await?;
        let next_page_token = next_page_token(response.headers());
        let identities = response
            .json()
            .await
            .map_err(|source| KratosError::Response { what, source })?;
        Ok(IdentityPage {
            identities,
            next_page_token,
        })
    }

    /// The full identity as Kratos returns it, including linked social logins.
    async fn identity(&self, id: Uuid) -> Result<Value, KratosError> {
        self.send_json(
            self.http
                .get(self.identity_url(id))
                .query(&[("include_credential", "oidc")]),
        )
        .await
    }

    async fn active_sessions(&self, id: Uuid) -> Result<usize, KratosError> {
        let sessions: Vec<Value> = self
            .send_json(
                self.http
                    .get(format!("{}/sessions", self.identity_url(id)))
                    .query(&[("active", "true")]),
            )
            .await?;
        Ok(sessions.len())
    }

    /// With a password, the identity logs in with it and its email is marked verified,
    /// so the user can log in right away (dev seeding). Without one it has no
    /// credentials yet: an invite, completed through a recovery link.
    async fn create_identity(
        &self,
        email: &Email,
        password: Option<&str>,
    ) -> Result<KratosIdentity, KratosError> {
        let body = match password {
            Some(password) => json!({
                "schema_id": "default",
                "traits": { "email": email },
                "credentials": { "password": { "config": { "password": password } } },
                "verifiable_addresses": [
                    { "value": email, "via": "email", "verified": true, "status": "completed" }
                ],
            }),
            None => json!({ "schema_id": "default", "traits": { "email": email } }),
        };
        self.send_json(self.http.post(self.identities()).json(&body))
            .await
    }

    /// Deletes every session of the identity: logged out everywhere.
    async fn revoke_sessions(&self, id: Uuid) -> Result<(), KratosError> {
        self.send(
            self.http
                .delete(format!("{}/sessions", self.identity_url(id))),
        )
        .await?;
        Ok(())
    }

    async fn set_state(&self, id: Uuid, state: IdentityState) -> Result<(), KratosError> {
        let patch = json!([{ "op": "replace", "path": "/state", "value": state }]);
        self.send(self.http.patch(self.identity_url(id)).json(&patch))
            .await?;
        Ok(())
    }

    /// A one-hour recovery link and code, for an admin to send to the user.
    async fn recovery_code(&self, id: Uuid) -> Result<RecoveryCode, KratosError> {
        let body = json!({ "identity_id": id, "expires_in": "1h" });
        self.send_json(
            self.http
                .post(format!("{}/admin/recovery/code", self.url))
                .json(&body),
        )
        .await
    }

    async fn delete_identity(&self, id: Uuid) -> Result<(), KratosError> {
        self.send(self.http.delete(self.identity_url(id))).await?;
        Ok(())
    }
}

/// Kratos' error body: `{"error": {"code": 409, "message": "...", "reason": "..."}}`.
#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    reason: Option<String>,
    message: Option<String>,
}

/// Kratos paginates with `Link: </admin/identities?page_size=..&page_token=..>; rel="next"`;
/// the last page has no `next`. Only the token matters: the next request is built the
/// same way as the first.
fn next_page_token(headers: &HeaderMap) -> Option<String> {
    let base = Url::parse("http://kratos/").ok()?;
    headers
        .get_all(LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter(|link| link.contains("rel=\"next\""))
        .find_map(|link| {
            let target = link.split_once('<')?.1.split_once('>')?.0;
            let url = base.join(target).ok()?;
            url.query_pairs()
                .find(|(key, _)| key == "page_token")
                .map(|(_, token)| token.into_owned())
        })
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    fn link(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(LINK, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn api(url: &str) -> AdminApi {
        AdminApi::new(reqwest::Client::new(), url)
    }

    #[test]
    fn follows_the_next_link() {
        let headers = link(
            "</admin/identities?page_size=1&page_token=00000000-0000-0000-0000-000000000000>; rel=\"first\",\
             </admin/identities?page_size=1&page_token=7ba28093-1c1a-4727-b664-bf2b842ca431>; rel=\"next\"",
        );
        assert_eq!(
            next_page_token(&headers).as_deref(),
            Some("7ba28093-1c1a-4727-b664-bf2b842ca431")
        );
    }

    #[test]
    fn last_page_has_no_next() {
        let headers = link("</admin/identities?page_size=1&page_token=0>; rel=\"first\"");
        assert_eq!(next_page_token(&headers), None);
        assert_eq!(next_page_token(&HeaderMap::new()), None);
    }

    /// A Kratos admin API whose credentials index knows nobody (like a social-login-only
    /// identity) and whose identity list has two pages.
    async fn mock_kratos(second_page: serde_json::Value) -> String {
        use axum::extract::Query;
        use std::collections::HashMap;

        let app = axum::Router::new().route(
            "/admin/identities",
            axum::routing::get(move |Query(q): Query<HashMap<String, String>>| {
                let second_page = second_page.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    let body = if q.contains_key("credentials_identifier") {
                        json!([])
                    } else if q.get("page_token").map(String::as_str) == Some("p2") {
                        second_page
                    } else {
                        headers.insert(
                            LINK,
                            HeaderValue::from_static(
                                "</admin/identities?page_size=250&page_token=p2>; rel=\"next\"",
                            ),
                        );
                        json!([
                            { "id": Uuid::new_v4(), "traits": { "email": "bob@example.com" } },
                            { "id": Uuid::new_v4(), "traits": { "email": "garbage" } },
                        ])
                    };
                    (headers, axum::Json(body))
                }
            }),
        );
        crate::testing::spawn(app).await
    }

    #[tokio::test]
    async fn finds_identities_the_credentials_index_misses() {
        let id = Uuid::new_v4();
        let url = mock_kratos(json!([
            { "id": id, "traits": { "email": "Ada@Example.com" } }
        ]))
        .await;

        let wanted: Email = "ada@example.com".parse().unwrap();
        let found = api(&url).identities_with_email(&wanted).await.unwrap();
        assert_eq!(found.len(), 1, "found on the second page");
        assert_eq!(found[0].id, id);
        assert_eq!(found[0].traits.email, wanted);

        let nobody: Email = "nobody@example.com".parse().unwrap();
        assert!(
            api(&url)
                .identities_with_email(&nobody)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn returns_every_identity_with_the_email() {
        let url = mock_kratos(json!([
            { "id": Uuid::new_v4(), "traits": { "email": "bob@example.com" } }
        ]))
        .await;

        let wanted: Email = "bob@example.com".parse().unwrap();
        let found = api(&url).identities_with_email(&wanted).await.unwrap();
        assert_eq!(found.len(), 2, "one per page");
    }

    #[tokio::test]
    async fn lists_every_page_leniently() {
        let url = mock_kratos(json!([
            { "id": Uuid::new_v4(), "traits": {}, "state": "inactive",
              "verifiable_addresses": [{ "verified": false }, { "verified": true }] }
        ]))
        .await;

        let listed = api(&url).all_identities().await.unwrap();
        assert_eq!(listed.len(), 3);
        let last = &listed[2];
        assert_eq!(last.traits.email, None);
        assert_eq!(last.state, "inactive");
        assert!(last.verified());
        assert!(!listed[0].verified());
    }

    #[tokio::test]
    async fn errors_carry_the_kratos_reason() {
        let app = axum::Router::new().route(
            "/admin/identities",
            axum::routing::post(|| async {
                (
                    axum::http::StatusCode::CONFLICT,
                    axum::Json(json!({ "error": {
                        "code": 409,
                        "message": "The resource could not be created due to a conflict",
                        "reason": "An identity with the same identifier already exists."
                    } })),
                )
            }),
        );
        let url = crate::testing::spawn(app).await;

        let email: Email = "ada@example.com".parse().unwrap();
        let err = api(&url)
            .create_identity(&email, Some("pw"))
            .await
            .unwrap_err();
        assert_eq!(err.status(), Some(StatusCode::CONFLICT));
        assert_eq!(
            err.to_string(),
            "POST /admin/identities -> 409 Conflict: An identity with the same identifier already exists."
        );
    }

    #[test]
    fn matches_on_normalized_email_and_tolerates_odd_ones() {
        let wanted: Email = "ada@example.com".parse().unwrap();
        let listed = |email: Option<&str>| Identity {
            id: Uuid::new_v4(),
            traits: IdentityTraits {
                email: email.map(str::to_owned),
            },
            state: String::new(),
            verifiable_addresses: Vec::new(),
            created_at: String::new(),
            credentials: BTreeMap::new(),
        };
        assert!(listed(Some(" Ada@Example.com")).matching(&wanted).is_some());
        assert!(listed(Some("bob@example.com")).matching(&wanted).is_none());
        assert!(listed(Some("not an email")).matching(&wanted).is_none());
        assert!(listed(None).matching(&wanted).is_none());
    }
}
