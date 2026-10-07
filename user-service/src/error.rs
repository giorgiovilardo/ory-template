use axum::Json;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::models::{DisplayNameError, EmailError};

/// Every handler returns `Result<_, AppError>`; this is the only place that decides
/// status codes and the error body: `{"error": {"code": "...", "message": "..."}}`.
/// Clients branch on `code` (stable); `message` is for humans and may change.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Email(#[from] EmailError),
    #[error(transparent)]
    DisplayName(#[from] DisplayNameError),
    #[error(transparent)]
    Json(#[from] JsonRejection),
    #[error("{0}")]
    BadRequest(String),
    #[error("missing or invalid credentials")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Email(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.code()),
            Self::DisplayName(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.code()),
            Self::Json(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_body"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Database(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let message = if status.is_server_error() {
            // Log the details, never send them: they can leak schema or query details.
            tracing::error!(error = ?self, "request failed");
            "internal error".to_owned()
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
