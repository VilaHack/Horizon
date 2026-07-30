mod handlers;

use std::sync::Arc;

use axum::{Router, routing::post};

const SESSION_COOKIE: &str = "session_id";

pub fn router() -> Router<Arc<crate::State>> {
    Router::new()
        .route("/signup", post(handlers::signup))
        .route("/login", post(handlers::login))
        .route("/logout", post(handlers::logout))
        .route("/logout_all", post(handlers::logout_all))
}
