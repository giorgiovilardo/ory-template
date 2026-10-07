//! `serve`: the long-running process. Two listeners on one database pool: Oathkeeper
//! routes only to the public one, so the internal endpoint is unreachable from outside
//! regardless of path rules.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::api::{self, ApiState};
use crate::auth::JwtVerifier;
use crate::config::{self, ServeConfig};
use crate::db;
use crate::error::AppError;
use crate::hydrate::{self, HydrateState};

/// Under Oathkeeper's hydrator `give_up_after` (2s, oathkeeper.yml), so a stalled database
/// fails fast and leaves room for its retry. Every query here is a single small statement.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn serve(config: ServeConfig) -> anyhow::Result<()> {
    let db = db::connect(&config.database).await?;
    // No migrations here: the one-shot `user-service migrate` job runs them before
    // this starts (see docker-compose.yml), so serving never needs DDL rights.

    let api_state = ApiState {
        db: db.clone(),
        verifier: Arc::new(JwtVerifier::remote(
            config.jwks_url,
            &config.jwt_issuer,
            config::http_client()?,
        )),
    };
    let hydrate_state = HydrateState {
        db,
        password: config.hydrator_password.into(),
    };

    let public = axum::serve(
        TcpListener::bind(config.public.addr).await?,
        with_middleware(api::router(api_state)),
    )
    .with_graceful_shutdown(shutdown_signal());
    let internal = axum::serve(
        TcpListener::bind(config.internal_addr).await?,
        with_middleware(hydrate::router(hydrate_state)),
    )
    .with_graceful_shutdown(shutdown_signal());

    tracing::info!(public = %config.public.addr, internal = %config.internal_addr, "listening");
    tokio::try_join!(public.into_future(), internal.into_future())?;
    Ok(())
}

/// What every request goes through, on both listeners. `TraceLayer`'s default spans log
/// method + path only, never headers (the hydrator receives the raw Kratos session
/// cookie); it's outermost, so it also records timeouts.
fn with_middleware(router: Router) -> Router {
    router
        .layer(middleware::from_fn(timeout))
        .layer(TraceLayer::new_for_http())
}

/// Bounds every request, pool wait and query included (`acquire_timeout` only covers
/// the wait). The timeout comes back in the usual error format, via `AppError`.
async fn timeout(req: Request, next: Next) -> Response {
    tokio::time::timeout(REQUEST_TIMEOUT, next.run(req))
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

    #[tokio::test(start_paused = true)]
    async fn slow_requests_time_out_in_the_error_format() {
        let app = with_middleware(Router::new().route(
            "/",
            get(|| async { tokio::time::sleep(REQUEST_TIMEOUT * 2).await }),
        ));
        let req = Request::get("/").body(Body::empty()).unwrap();
        let (status, body) = testing::send(app, req).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "timeout");
    }
}
