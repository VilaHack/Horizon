pub mod authentication;
mod configuration;
pub mod email;
pub mod error;
mod state;
mod user;

use std::sync::Arc;

use axum::http::{
    Method,
    header::{ACCEPT, CONTENT_TYPE},
};
pub use state::State;

use crate::error::Context;

#[derive(axum::extract::FromRequest)]
#[from_request(via(axum::Json), rejection(error::Error))]
pub struct Json<T>(T);

use axum::{
    extract::Request,
    middleware::{self, Next},
    response::Response,
};

/// Used as a middleware layer for the axum service
async fn metrics(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    let status = response.status().to_string();

    metrics::counter!("requests_total", "method" => method, "path" => path, "status" => status)
        .increment(1);

    response
}

/// Run Horizon
///
/// # Errors
/// Will return an error if:
/// - It can't find a valid configuration file
/// - It can't connect to the database
/// - It can't bind to the configured address
pub async fn run() -> Result<(), error::Error> {
    let state = State::initialize()
        .await
        .context("Initializing the state")?;

    let cors_layer = tower_http::cors::CorsLayer::new()
        .allow_origin(state.configuration.http.allowed_origins.clone())
        .allow_methods([Method::POST])
        .allow_headers([ACCEPT, CONTENT_TYPE]);

    let bind_address = state.configuration.http.bind_address;

    let metrics_layer = state
        .configuration
        .observability
        .opentelemetry
        .is_some()
        .then(|| middleware::from_fn(metrics));

    let router = axum::Router::new()
        .nest("/api/v0/auth", authentication::router())
        .layer(
            tower::ServiceBuilder::new()
                .layer(cors_layer)
                .option_layer(metrics_layer),
        )
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(bind_address)
        .await
        .context("Starting the TCP listener")?;

    log::info!("Starting server at {bind_address}...");

    axum::serve(listener, router)
        .await
        .context("Serving the http service")
}
