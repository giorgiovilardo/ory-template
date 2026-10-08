//! An in-memory Kratos admin API for testing the directory. Cloning shares the state, so
//! a test keeps a handle to inspect (or break) what the directory sees.

// Everything here is synchronous, but `async fn` mirrors the port's signatures.
#![allow(clippy::unused_async_trait_impl)]

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use reqwest::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

use super::IdentityAdmin;
use crate::kratos::{
    Identity, IdentityPage, IdentityState, KratosError, KratosIdentity, RecoveryCode,
};
use crate::models::Email;

#[derive(Debug, Clone)]
pub struct FakeIdentity {
    pub email: String,
    pub state: IdentityState,
    pub verified: bool,
    pub password: Option<String>,
    pub sessions: usize,
}

impl FakeIdentity {
    pub fn new(email: &str) -> Self {
        Self {
            email: email.to_owned(),
            state: IdentityState::Active,
            verified: true,
            password: None,
            sessions: 0,
        }
    }
}

/// Port methods, by name, for `fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Create,
    Delete,
    Recovery,
    SetState,
}

#[derive(Default)]
struct State {
    /// Ordered, so pagination is deterministic.
    identities: BTreeMap<Uuid, FakeIdentity>,
    failing: HashSet<Op>,
}

#[derive(Clone, Default)]
pub struct FakeKratos {
    state: Arc<Mutex<State>>,
}

impl FakeKratos {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// Adds an identity; returns its id.
    pub fn add(&self, identity: FakeIdentity) -> Uuid {
        let id = Uuid::new_v4();
        self.state().identities.insert(id, identity);
        id
    }

    pub fn get(&self, id: Uuid) -> Option<FakeIdentity> {
        self.state().identities.get(&id).cloned()
    }

    pub fn get_by_email(&self, email: &str) -> Option<FakeIdentity> {
        self.state()
            .identities
            .values()
            .find(|identity| identity.email == email)
            .cloned()
    }

    /// From now on, `op` fails as if Kratos answered 500.
    pub fn fail(&self, op: Op) {
        self.state().failing.insert(op);
    }

    fn check(&self, op: Op) -> Result<(), KratosError> {
        if self.state().failing.contains(&op) {
            return Err(status(
                StatusCode::INTERNAL_SERVER_ERROR,
                "injected failure",
            ));
        }
        Ok(())
    }

    fn with<T>(&self, id: Uuid, f: impl FnOnce(&mut FakeIdentity) -> T) -> Result<T, KratosError> {
        self.state()
            .identities
            .get_mut(&id)
            .map(f)
            .ok_or_else(not_found)
    }
}

pub fn status(status: StatusCode, reason: &str) -> KratosError {
    KratosError::Status {
        what: "FAKE".to_owned(),
        status,
        reason: reason.to_owned(),
    }
}

fn not_found() -> KratosError {
    status(StatusCode::NOT_FOUND, "Unable to locate the resource")
}

fn to_json(id: Uuid, identity: &FakeIdentity) -> Value {
    json!({
        "id": id,
        "schema_id": "default",
        "traits": { "email": identity.email },
        "state": identity.state,
        "verifiable_addresses": [{ "value": identity.email, "verified": identity.verified }],
        "credentials": if identity.password.is_some() { json!({ "password": {} }) } else { json!({}) },
        "created_at": "2026-01-02T03:04:05.000000Z",
    })
}

impl IdentityAdmin for FakeKratos {
    async fn identities_with_email(
        &self,
        email: &Email,
    ) -> Result<Vec<KratosIdentity>, KratosError> {
        Ok(self
            .state()
            .identities
            .iter()
            .filter(|(_, identity)| identity.email.parse().ok().as_ref() == Some(email))
            .map(|(id, _)| crate::testing::identity(*id, email.as_ref()))
            .collect())
    }

    async fn list_page(
        &self,
        page_size: u16,
        page_token: Option<&str>,
    ) -> Result<IdentityPage, KratosError> {
        // Like Kratos: a token it didn't hand out is a 400.
        let after: Option<Uuid> = page_token
            .map(str::parse)
            .transpose()
            .map_err(|_| status(StatusCode::BAD_REQUEST, "The page token is invalid"))?;
        let state = self.state();
        let mut rest = state
            .identities
            .iter()
            .filter(|(id, _)| after.is_none_or(|after| **id > after));
        let identities: Vec<_> = rest
            .by_ref()
            .take(page_size.into())
            .map(|(id, identity)| {
                serde_json::from_value::<Identity>(to_json(*id, identity)).unwrap()
            })
            .collect();
        let next_page_token = match (rest.next(), identities.last()) {
            (Some(_), Some(last)) => Some(last.id.to_string()),
            _ => None,
        };
        Ok(IdentityPage {
            identities,
            next_page_token,
        })
    }

    async fn identity(&self, id: Uuid) -> Result<Value, KratosError> {
        self.with(id, |identity| to_json(id, identity))
    }

    async fn active_sessions(&self, id: Uuid) -> Result<usize, KratosError> {
        self.with(id, |identity| identity.sessions)
    }

    async fn create_identity(
        &self,
        email: &Email,
        password: Option<&str>,
    ) -> Result<KratosIdentity, KratosError> {
        self.check(Op::Create)?;
        if !self.identities_with_email(email).await?.is_empty() {
            return Err(status(
                StatusCode::CONFLICT,
                "An identity with the same identifier already exists.",
            ));
        }
        let id = self.add(FakeIdentity {
            password: password.map(str::to_owned),
            verified: password.is_some(),
            ..FakeIdentity::new(email.as_ref())
        });
        Ok(crate::testing::identity(id, email.as_ref()))
    }

    /// Like Kratos: 404 when there are no sessions to delete, too.
    async fn revoke_sessions(&self, id: Uuid) -> Result<(), KratosError> {
        let had = self.with(id, |identity| std::mem::take(&mut identity.sessions))?;
        if had == 0 {
            return Err(not_found());
        }
        Ok(())
    }

    async fn set_state(&self, id: Uuid, state: IdentityState) -> Result<(), KratosError> {
        self.check(Op::SetState)?;
        self.with(id, |identity| identity.state = state)
    }

    async fn recovery_code(&self, id: Uuid) -> Result<RecoveryCode, KratosError> {
        self.check(Op::Recovery)?;
        self.with(id, |_| RecoveryCode {
            recovery_link: format!("http://kratos/recovery?identity={id}"),
            recovery_code: "123456".to_owned(),
            expires_at: Some("2026-01-02T04:04:05Z".to_owned()),
        })
    }

    async fn delete_identity(&self, id: Uuid) -> Result<(), KratosError> {
        self.check(Op::Delete)?;
        self.state()
            .identities
            .remove(&id)
            .map(drop)
            .ok_or_else(not_found)
    }
}
