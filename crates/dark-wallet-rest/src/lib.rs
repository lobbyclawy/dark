//! dark-wallet-rest — REST wallet daemon for dark.
//!
//! A thin HTTP facade over [`dark_client::ArkClient`] that exposes a curated
//! subset of the Ark protocol as REST + SSE, so browsers and other HTTP
//! clients can drive dark without a gRPC proxy.
//!
//! # Overview
//!
//! ```no_run
//! use dark_wallet_rest::{Config, RestServer};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Config::default();
//!     let server = RestServer::start(&config).await?;
//!     server.join().await?;
//!     Ok(())
//! }
//! ```

pub mod api;
pub mod auth;
pub mod codec;
pub mod config;
pub mod dto;
pub mod error;
pub mod state;

pub use config::Config;
pub use state::AppState;

use anyhow::Context;
use axum::routing::get;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;
#[cfg(feature = "swagger-ui")]
use utoipa_swagger_ui::SwaggerUi;

const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

const API_DESCRIPTION: &str = "\
REST wallet daemon for dark, an Ark protocol server for Bitcoin L2.

Exposes a curated subset of the gRPC surface as HTTP + JSON, with SSE for \
server-streamed events. Signer-path RPCs (tree nonces, tree signatures, \
forfeit signing) remain gRPC-only by design.

All endpoints return JSON. Binary fields (PSBTs, pubkeys, signatures) are \
hex-encoded strings unless noted. Amounts are denominated in satoshis.";

#[derive(OpenApi)]
#[openapi(
    paths(ping),
    nest(
        (path = "/v1", api = api::v1::V1ApiDoc),
    ),
    info(
        title = "dark-wallet-rest",
        version = CRATE_VERSION,
        description = API_DESCRIPTION,
    ),
    security(("bearer" = [])),
    modifiers(&BearerSecurity),
)]
pub struct ApiDoc;

struct BearerSecurity;

impl Modify for BearerSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("macaroon")
                    .build(),
            ),
        );
    }
}

/// A running REST server with a cancellation token for graceful shutdown.
pub struct RestServer {
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
}

impl RestServer {
    /// Start the REST server on the configured socket.
    pub async fn start(config: &Config) -> anyhow::Result<Self> {
        let state = AppState::connect(config).await?;

        let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi()).split_for_parts();

        if config.auth_disabled {
            warn!("auth is disabled — all /v1 routes are unauthenticated");
        }

        let v1 = api::v1::router();
        let v1 = if config.auth_disabled {
            v1
        } else {
            v1.route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth::guard_auth,
            ))
        };

        let app = {
            let app = router
                .route("/ping", get(ping))
                .route(
                    "/openapi.json",
                    get({
                        let api_for_route = api.clone();
                        move || {
                            let api = api_for_route.clone();
                            async move { axum::Json(api) }
                        }
                    }),
                )
                .nest("/v1", v1);

            #[cfg(feature = "swagger-ui")]
            let app = app.merge(SwaggerUi::new("/docs").url("/openapi.json", api.clone()));

            app.layer(cors_layer())
                .layer(TraceLayer::new_for_http())
                .with_state(state)
                .fallback(error::route_not_found)
        };

        let listener = tokio::net::TcpListener::bind(config.listen_addr)
            .await
            .with_context(|| format!("bind {}", config.listen_addr))?;
        info!(addr = %config.listen_addr, "dark-wallet-rest listening");

        let shutdown = CancellationToken::new();
        let shutdown_child = shutdown.clone();
        let handle = tokio::spawn(async move {
            let serve = axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async move {
                    shutdown_child.cancelled().await;
                });
            if let Err(e) = serve.await {
                error!(error = ?e, "server error");
            } else {
                info!("server stopped");
            }
        });

        Ok(Self { shutdown, handle })
    }

    /// Trigger a graceful shutdown.
    pub fn stop(&self) {
        self.shutdown.cancel();
    }

    /// Wait for the server task to complete.
    pub async fn join(self) -> anyhow::Result<()> {
        self.handle.await.context("server task panicked")
    }

    /// Stop and wait.
    pub async fn stop_wait(self) -> anyhow::Result<()> {
        self.stop();
        self.join().await
    }
}

fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any)
}

#[utoipa::path(
    get,
    path = "/ping",
    summary = "Liveness probe",
    security(()),
    responses((status = 200, description = "Returns `pong`"))
)]
pub async fn ping() -> &'static str {
    "pong"
}
