mod handlers;

use std::sync::Arc;

use axum::{Router, routing::post};

pub fn router() -> Router<Arc<crate::State>> {
    Router::new().route("/login", post(handlers::login))
}
