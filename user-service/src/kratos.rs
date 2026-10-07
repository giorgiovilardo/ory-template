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

const PAGE_SIZE: &str = "250";

/// Looks up an identity by email through the Kratos admin API.
///
/// Tries the credentials index first (one cheap request). That index lists the
/// identifiers an identity can log in with, which may not include an identity that
/// registered through a social provider, so on a miss this scans every identity's
/// `traits.email`. That's linear in the number of users, which is fine for an admin
/// CLI. If the scan finds several identities with the email it refuses to pick one:
/// the caller is about to grant or revoke a role.
pub async fn find_identity_by_email(
    http: &reqwest::Client,
    admin_url: &str,
    email: &Email,
) -> anyhow::Result<Option<KratosIdentity>> {
    let by_credentials: Vec<KratosIdentity> = http
        .get(format!("{admin_url}/admin/identities"))
        .query(&[("credentials_identifier", email.as_ref())])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if let Some(identity) = by_credentials.into_iter().next() {
        return Ok(Some(identity));
    }

    let mut matches = Vec::new();
    let mut page_token = None::<String>;
    loop {
        let mut request = http
            .get(format!("{admin_url}/admin/identities"))
            .query(&[("page_size", PAGE_SIZE)]);
        if let Some(token) = &page_token {
            request = request.query(&[("page_token", token)]);
        }
        let response = request.send().await?.error_for_status()?;
        page_token = next_page_token(response.headers());
        let page: Vec<ListedIdentity> = response.json().await?;
        matches.extend(page.into_iter().filter_map(|listed| listed.matching(email)));
        if page_token.is_none() {
            break;
        }
    }

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

/// An identity from the unfiltered list. Parsed leniently: one identity with an odd
/// email must not make the whole scan fail.
#[derive(Debug, Deserialize)]
struct ListedIdentity {
    id: Uuid,
    traits: ListedTraits,
}

#[derive(Debug, Deserialize)]
struct ListedTraits {
    email: Option<String>,
}

impl ListedIdentity {
    fn matching(self, wanted: &Email) -> Option<KratosIdentity> {
        let email: Email = self.traits.email?.parse().ok()?;
        (&email == wanted).then_some(KratosIdentity {
            id: self.id,
            traits: Traits { email },
        })
    }
}

/// Kratos paginates with `Link: <...?page_token=X>; rel="next"`; the last page has no `next`.
fn next_page_token(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get_all(reqwest::header::LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter(|link| link.contains("rel=\"next\""))
        .find_map(|link| {
            let url = link.split_once('<')?.1.split_once('>')?.0;
            let query = url.split_once('?')?.1;
            query
                .split('&')
                .find_map(|pair| pair.strip_prefix("page_token="))
                .map(str::to_owned)
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

    #[test]
    fn reads_the_next_page_token() {
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
        use axum::http::{HeaderMap, HeaderValue};
        use serde_json::json;
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        url
    }

    #[tokio::test]
    async fn finds_identities_the_credentials_index_misses() {
        let id = Uuid::new_v4();
        let url = mock_kratos(serde_json::json!([
            { "id": id, "traits": { "email": "Ada@Example.com" } }
        ]))
        .await;

        let wanted: Email = "ada@example.com".parse().unwrap();
        let found = find_identity_by_email(&reqwest::Client::new(), &url, &wanted)
            .await
            .unwrap()
            .expect("found on the second page");
        assert_eq!(found.id, id);
        assert_eq!(found.traits.email, wanted);

        let nobody: Email = "nobody@example.com".parse().unwrap();
        assert!(
            find_identity_by_email(&reqwest::Client::new(), &url, &nobody)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn refuses_to_pick_between_identities_with_the_same_email() {
        let url = mock_kratos(serde_json::json!([
            { "id": Uuid::new_v4(), "traits": { "email": "bob@example.com" } }
        ]))
        .await;

        let wanted: Email = "bob@example.com".parse().unwrap();
        let err = find_identity_by_email(&reqwest::Client::new(), &url, &wanted)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("several Kratos identities"),
            "{err}"
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
        };
        assert!(listed(Some(" Ada@Example.com")).matching(&wanted).is_some());
        assert!(listed(Some("bob@example.com")).matching(&wanted).is_none());
        assert!(listed(Some("not an email")).matching(&wanted).is_none());
        assert!(listed(None).matching(&wanted).is_none());
    }
}
