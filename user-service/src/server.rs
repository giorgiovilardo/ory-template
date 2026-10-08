//! `serve`: the long-running process. Two listeners on one database pool: Oathkeeper
//! routes only to the public one, so the internal endpoints (the hydrator, Kratos' web
//! hook) are unreachable from outside regardless of path rules.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::admin_api::{self, AdminState};
use crate::api::{self, ApiState};
use crate::auth::JwtVerifier;
use crate::config::{self, ServeConfig};
use crate::db;
use crate::directory::Directory;
use crate::error::AppError;
use crate::hydrate::{self, HydrateState};
use crate::kratos::AdminApi;
use crate::webhook::{self, WebhookState};

/// Under Oathkeeper's hydrator `give_up_after` (2s, oathkeeper.yml), so a stalled database
/// fails fast and leaves room for its retry. Every query here is a single small statement.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

/// The admin API calls Kratos, sometimes several times per request (a guarded change
/// checks which admins are still active). Its own budget, so `/me` and the hydrator
/// keep theirs.
const ADMIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve(config: ServeConfig) -> anyhow::Result<()> {
    let db = db::connect(&config.database).await?;
    // No migrations here: the one-shot `user-service migrate` job runs them before
    // this starts (see docker-compose.yml), so serving never needs DDL rights.

    let verifier = Arc::new(JwtVerifier::remote(
        config.jwks_url,
        &config.jwt_issuer,
        config::http_client()?,
    ));
    let api_state = ApiState {
        db: db.clone(),
        verifier: verifier.clone(),
    };
    let admin_state = AdminState {
        db: db.clone(),
        verifier,
        directory: Arc::new(Directory::new(
            db.clone(),
            AdminApi::new(config::http_client()?, &config.kratos_admin.url),
        )),
    };
    let hydrate_state = HydrateState {
        db: db.clone(),
        password: config.hydrator_password.into(),
    };
    let webhook_state = WebhookState {
        db,
        password: config.kratos_webhook_password.into(),
    };

    let public_routes = with_timeout(api::router(api_state), REQUEST_TIMEOUT).merge(with_timeout(
        admin_api::router(admin_state),
        ADMIN_REQUEST_TIMEOUT,
    ));
    let public = axum::serve(
        TcpListener::bind(config.public.addr).await?,
        with_tracing(public_routes),
    )
    .with_graceful_shutdown(shutdown_signal());
    let internal = axum::serve(
        TcpListener::bind(config.internal_addr).await?,
        with_tracing(with_timeout(
            hydrate::router(hydrate_state).merge(webhook::router(webhook_state)),
            REQUEST_TIMEOUT,
        )),
    )
    .with_graceful_shutdown(shutdown_signal());

    tracing::info!(public = %config.public.addr, internal = %config.internal_addr, "listening");
    tokio::try_join!(public.into_future(), internal.into_future())?;
    Ok(())
}

/// Outermost on both listeners. `TraceLayer`'s default spans log method + path only,
/// never headers (the hydrator receives the raw Kratos session cookie); being outermost,
/// it also records timeouts.
fn with_tracing(router: Router) -> Router {
    router.layer(TraceLayer::new_for_http())
}

/// Bounds every request of `router`'s routes, pool wait and query included
/// (`acquire_timeout` only covers the wait). Layered per router before merging, so each
/// keeps its own budget. The timeout comes back in the usual error format, via `AppError`.
fn with_timeout(router: Router, budget: Duration) -> Router {
    router.layer(middleware::from_fn_with_state(budget, timeout))
}

async fn timeout(State(budget): State<Duration>, req: Request, next: Next) -> Response {
    tokio::time::timeout(budget, next.run(req))
        .await
        .unwrap_or_else(|_| AppError::Timeout.into_response())
}

/// Ctrl-C locally, SIGTERM from `docker stop`.
async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("ctrl-c handler") };
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm handler")
            .recv()
            .await;
    };
    tokio::select! {
        () = ctrl_c => {},
        () = sigterm => {},
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;

    use super::*;
    use crate::testing;

    fn sleeping(path: &str, duration: Duration) -> Router {
        Router::new().route(
            path,
            get(move || async move { tokio::time::sleep(duration).await }),
        )
    }

    async fn status_of(app: Router, path: &str) -> (StatusCode, serde_json::Value) {
        testing::send(app, Request::get(path).body(Body::empty()).unwrap()).await
    }

    #[tokio::test(start_paused = true)]
    async fn slow_requests_time_out_in_the_error_format() {
        let app = with_timeout(sleeping("/", REQUEST_TIMEOUT * 2), REQUEST_TIMEOUT);
        let (status, body) = status_of(app, "/").await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "timeout");
    }

    #[tokio::test(start_paused = true)]
    async fn each_router_keeps_its_own_budget() {
        let slow = REQUEST_TIMEOUT * 2;
        let app = with_timeout(sleeping("/me", slow), REQUEST_TIMEOUT).merge(with_timeout(
            sleeping("/admin", slow),
            ADMIN_REQUEST_TIMEOUT,
        ));

        assert_eq!(
            status_of(app.clone(), "/me").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(status_of(app, "/admin").await.0, StatusCode::OK);
    }
}
