//! What this service reads from Kratos, and the admin API client the CLI uses. Only the
//! fields we use are modeled; serde ignores the rest, so Kratos adding fields never
//! breaks us.

use anyhow::Context;
use reqwest::{RequestBuilder, Response, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

/// An identity from the unfiltered list. Parsed leniently: one identity with an odd
/// email (or a missing field) must not make a whole listing fail.
#[derive(Debug, Deserialize)]
pub struct ListedIdentity {
    pub id: Uuid,
    #[serde(default)]
    pub traits: ListedTraits,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub verifiable_addresses: Vec<VerifiableAddress>,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListedTraits {
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifiableAddress {
    #[serde(default)]
    pub verified: bool,
}

impl ListedIdentity {
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

/// Whether an identity may log in. `Inactive` suspends its sessions (they stop working
/// at once) and refuses logins; back to `Active`, the suspended sessions work again.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityState {
    Active,
    Inactive,
}

#[derive(Debug, Deserialize)]
pub struct RecoveryCode {
    pub recovery_link: String,
    pub recovery_code: String,
}

const PAGE_SIZE: &str = "250";

/// The Kratos admin API (reference: <https://www.ory.sh/docs/kratos/reference/api>).
/// It can do anything to any identity, so it is only ever reachable on the compose
/// network and 127.0.0.1; only the CLI talks to it, never the server.
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

    /// Sends the request; a non-2xx response becomes an error carrying Kratos' own
    /// explanation (`error.reason`, else `error.message`), which is what an admin needs
    /// to see, e.g. "An identity with the same identifier already exists".
    async fn send(&self, request: RequestBuilder) -> anyhow::Result<Response> {
        let request = request.build()?;
        let what = format!("{} {}", request.method(), request.url().path());
        let response = self
            .http
            .execute(request)
            .await
            .with_context(|| format!("{what}: could not reach the Kratos admin API"))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = response.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ErrorBody>(&body)
            .ok()
            .and_then(|b| b.error.reason.or(b.error.message))
            .unwrap_or(body);
        anyhow::bail!("{what} -> {status}: {detail}")
    }

    /// Looks up an identity by email.
    ///
    /// Tries the credentials index first (one cheap request). That index lists the
    /// identifiers an identity can log in with, which may not include an identity that
    /// registered through a social provider, so on a miss this scans every identity's
    /// `traits.email`. That's linear in the number of users, which is fine for an admin
    /// CLI. If the scan finds several identities with the email it refuses to pick one:
    /// the caller is about to act on it.
    pub async fn find_by_email(&self, email: &Email) -> anyhow::Result<Option<KratosIdentity>> {
        let by_credentials: Vec<KratosIdentity> = self
            .send(
                self.http
                    .get(self.identities())
                    .query(&[("credentials_identifier", email.as_ref())]),
            )
            .await?
            .json()
            .await?;
        if let Some(identity) = by_credentials.into_iter().next() {
            return Ok(Some(identity));
        }

        let mut matches: Vec<KratosIdentity> = self
            .list()
            .await?
            .into_iter()
            .filter_map(|listed| listed.matching(email))
            .collect();
        match matches.len() {
            0 | 1 => Ok(matches.pop()),
            _ => {
                let ids: Vec<String> = matches.iter().map(|m| m.id.to_string()).collect();
                anyhow::bail!(
                    "several Kratos identities have the email {email}: {}",
                    ids.join(", ")
                )
            }
        }
    }

    /// Every identity, following the pagination links.
    pub async fn list(&self) -> anyhow::Result<Vec<ListedIdentity>> {
        let mut identities = Vec::new();
        let mut next = Some(Url::parse_with_params(
            &self.identities(),
            [("page_size", PAGE_SIZE)],
        )?);
        while let Some(url) = next {
            let response = self.send(self.http.get(url.as_str())).await?;
            next = next_page(&url, response.headers());
            let page: Vec<ListedIdentity> = response.json().await?;
            if page.is_empty() {
                break;
            }
            identities.extend(page);
        }
        Ok(identities)
    }

    /// The full identity as Kratos returns it, including linked social logins.
    pub async fn identity(&self, id: Uuid) -> anyhow::Result<Value> {
        Ok(self
            .send(
                self.http
                    .get(self.identity_url(id))
                    .query(&[("include_credential", "oidc")]),
            )
            .await?
            .json()
            .await?)
    }

    pub async fn active_sessions(&self, id: Uuid) -> anyhow::Result<usize> {
        let sessions: Vec<Value> = self
            .send(
                self.http
                    .get(format!("{}/sessions", self.identity_url(id)))
                    .query(&[("active", "true")]),
            )
            .await?
            .json()
            .await?;
        Ok(sessions.len())
    }

    /// Creates an identity that logs in with this email and password. The email is
    /// marked verified, so the user can log in right away.
    pub async fn create_identity(
        &self,
        email: &Email,
        password: &str,
    ) -> anyhow::Result<KratosIdentity> {
        let body = json!({
            "schema_id": "default",
            "traits": { "email": email },
            "credentials": { "password": { "config": { "password": password } } },
            "verifiable_addresses": [
                { "value": email, "via": "email", "verified": true, "status": "completed" }
            ],
        });
        Ok(self
            .send(self.http.post(self.identities()).json(&body))
            .await?
            .json()
            .await?)
    }

    /// Deletes every session of the identity: logged out everywhere.
    pub async fn revoke_sessions(&self, id: Uuid) -> anyhow::Result<()> {
        self.send(
            self.http
                .delete(format!("{}/sessions", self.identity_url(id))),
        )
        .await?;
        Ok(())
    }

    pub async fn set_state(&self, id: Uuid, state: IdentityState) -> anyhow::Result<()> {
        let patch = json!([{ "op": "replace", "path": "/state", "value": state }]);
        self.send(self.http.patch(self.identity_url(id)).json(&patch))
            .await?;
        Ok(())
    }

    /// A one-hour recovery link and code, for an admin to send to the user.
    pub async fn recovery_code(&self, id: Uuid) -> anyhow::Result<RecoveryCode> {
        let body = json!({ "identity_id": id, "expires_in": "1h" });
        Ok(self
            .send(
                self.http
                    .post(format!("{}/admin/recovery/code", self.url))
                    .json(&body),
            )
            .await?
            .json()
            .await?)
    }

    pub async fn delete_identity(&self, id: Uuid) -> anyhow::Result<()> {
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

/// Kratos paginates with `Link: </admin/identities?...>; rel="next"` (relative to the
/// current page); the last page has no `next`.
fn next_page(current: &Url, headers: &reqwest::header::HeaderMap) -> Option<Url> {
    headers
        .get_all(reqwest::header::LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter(|link| link.contains("rel=\"next\""))
        .find_map(|link| {
            let target = link.split_once('<')?.1.split_once('>')?.0;
            current.join(target).ok()
        })
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue, LINK};

    use super::*;

    fn link(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(LINK, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn current() -> Url {
        Url::parse("http://kratos:4434/admin/identities?page_size=1").unwrap()
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
            next_page(&current(), &headers).map(String::from).as_deref(),
            Some(
                "http://kratos:4434/admin/identities?page_size=1&page_token=7ba28093-1c1a-4727-b664-bf2b842ca431"
            )
        );
    }

    #[test]
    fn last_page_has_no_next() {
        let headers = link("</admin/identities?page_size=1&page_token=0>; rel=\"first\"");
        assert_eq!(next_page(&current(), &headers), None);
        assert_eq!(next_page(&current(), &HeaderMap::new()), None);
    }

    /// A Kratos admin API whose credentials index knows nobody (like a social-login-only
    /// identity) and whose identity list has two pages.
    async fn mock_kratos(second_page: serde_json::Value) -> String {
        use axum::extract::Query;
        use axum::http::{HeaderMap, HeaderValue};
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
        let found = api(&url)
            .find_by_email(&wanted)
            .await
            .unwrap()
            .expect("found on the second page");
        assert_eq!(found.id, id);
        assert_eq!(found.traits.email, wanted);

        let nobody: Email = "nobody@example.com".parse().unwrap();
        assert!(api(&url).find_by_email(&nobody).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn refuses_to_pick_between_identities_with_the_same_email() {
        let url = mock_kratos(json!([
            { "id": Uuid::new_v4(), "traits": { "email": "bob@example.com" } }
        ]))
        .await;

        let wanted: Email = "bob@example.com".parse().unwrap();
        let err = api(&url).find_by_email(&wanted).await.unwrap_err();
        assert!(
            err.to_string().contains("several Kratos identities"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn lists_every_page_leniently() {
        let url = mock_kratos(json!([
            { "id": Uuid::new_v4(), "traits": {}, "state": "inactive",
              "verifiable_addresses": [{ "verified": false }, { "verified": true }] }
        ]))
        .await;

        let listed = api(&url).list().await.unwrap();
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
            .create_identity(&email, "pw")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "POST /admin/identities -> 409 Conflict: An identity with the same identifier already exists."
        );
    }

    #[test]
    fn matches_on_normalized_email_and_tolerates_odd_ones() {
        let wanted: Email = "ada@example.com".parse().unwrap();
        let listed = |email: Option<&str>| ListedIdentity {
            id: Uuid::new_v4(),
            traits: ListedTraits {
                email: email.map(str::to_owned),
            },
            state: String::new(),
            verifiable_addresses: Vec::new(),
            created_at: String::new(),
        };
        assert!(listed(Some(" Ada@Example.com")).matching(&wanted).is_some());
        assert!(listed(Some("bob@example.com")).matching(&wanted).is_none());
        assert!(listed(Some("not an email")).matching(&wanted).is_none());
        assert!(listed(None).matching(&wanted).is_none());
    }
}
