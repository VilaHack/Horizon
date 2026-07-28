pub mod authentication;
mod configuration;
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

    let router = axum::Router::new()
        .nest("/api/v0/auth", authentication::router())
        .layer(cors_layer)
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(bind_address)
        .await
        .context("Starting the TCP listener")?;

    log::info!("Starting server at {bind_address}...");

    axum::serve(listener, router)
        .await
        .context("Serving the http service")
}
