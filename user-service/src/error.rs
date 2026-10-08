use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::directory::DirectoryError;
use crate::models::DisplayNameError;

/// Every handler returns `Result<_, AppError>`; this is the only place that decides
/// status codes and the error body: `{"error": {"code": "...", "message": "..."}}`.
/// Clients branch on `code` (stable); `message` is for humans and may change.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    DisplayName(#[from] DisplayNameError),
    #[error(transparent)]
    Json(#[from] JsonRejection),
    #[error(transparent)]
    Path(#[from] PathRejection),
    #[error(transparent)]
    Query(#[from] QueryRejection),
    #[error("{0}")]
    BadRequest(String),
    #[error("missing or invalid credentials")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("not found")]
    NotFound,
    #[error("request timed out")]
    Timeout,
    #[error(transparent)]
    Directory(#[from] DirectoryError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::DisplayName(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.code()),
            Self::Json(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_body"),
            Self::Path(_) | Self::Query(_) | Self::BadRequest(_) => {
                (StatusCode::BAD_REQUEST, "bad_request")
            }
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Timeout => (StatusCode::SERVICE_UNAVAILABLE, "timeout"),
            Self::Directory(e) => directory_status_and_code(e),
            Self::Database(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        }
    }

    /// The `code` a directory error is answered with (for audit logs).
    pub fn code_of(err: &DirectoryError) -> &'static str {
        directory_status_and_code(err).1
    }
}

fn directory_status_and_code(err: &DirectoryError) -> (StatusCode, &'static str) {
    match err {
        DirectoryError::NoSuchEmail(_)
        | DirectoryError::NoSuchUser(_)
        | DirectoryError::NoUserData(_) => (StatusCode::NOT_FOUND, "not_found"),
        DirectoryError::InvalidPageToken => (StatusCode::BAD_REQUEST, "bad_request"),
        DirectoryError::AmbiguousEmail { .. } => (StatusCode::CONFLICT, "ambiguous_email"),
        DirectoryError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        DirectoryError::SelfAction => (StatusCode::CONFLICT, "self_action"),
        DirectoryError::LastAdmin(_) => (StatusCode::CONFLICT, "last_admin"),
        // Kratos failed or answered something unexpected: its details stay in our logs.
        DirectoryError::InvalidIdentity(_) | DirectoryError::Kratos(_) => {
            (StatusCode::BAD_GATEWAY, "kratos_error")
        }
        DirectoryError::DataNotCreated { .. }
        | DirectoryError::DataLeftBehind { .. }
        | DirectoryError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = if status.is_server_error() {
            // Log the details, never send them: they can leak schema or query details.
            tracing::error!(error = ?self, "request failed");
            "internal error".to_owned()
        } else if let Self::Directory(DirectoryError::Conflict(kratos)) = &self {
            // Kratos' reason ("an identity with this email already exists"), not the
            // request line it came from.
            kratos.reason().unwrap_or("conflict").to_owned()
        } else {
            self.to_string()
        };
        (
            status,
            Json(json!({ "error": { "code": code, "message": message } })),
        )
            .into_response()
    }
}

/// `Json` extractor whose failures (malformed JSON, wrong types) come back in the
/// `AppError` format instead of axum's plain-text rejection.
#[derive(FromRequest)]
#[from_request(via(Json), rejection(AppError))]
pub struct AppJson<T>(pub T);

/// `Path`, with failures (a malformed id, an unknown role) in the `AppError` format.
#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(AppError))]
pub struct AppPath<T>(pub T);

/// `Query`, with failures in the `AppError` format.
#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(AppError))]
pub struct AppQuery<T>(pub T);
