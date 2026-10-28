mod handlers;

use std::sync::Arc;

use axum::{
    Router,
    routing::{post},
};

const SESSION_COOKIE: &str = "horizon_session";

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    handlers::signup,
    handlers::request_email_verification,
    handlers::verify_email,
    handlers::login,
    handlers::csrf,
    handlers::logout,
    handlers::logout_all,
    handlers::request_password_reset,
    handlers::reset_password,
    handlers::change_password
))]
pub struct AuthApiDocs;

pub fn router() -> Router<Arc<crate::State>> {
    Router::new()
        .route("/signup", post(handlers::signup))
        .route(
            "/request_email_verification",
            post(handlers::request_email_verification),
        )
        .route("/verify_email", post(handlers::verify_email))
        .route("/login", post(handlers::login))
        .route("/csrf", post(handlers::csrf))
        .route("/logout", post(handlers::logout))
        .route("/logout_all", post(handlers::logout_all))
        .route(
            "/request_password_reset",
            post(handlers::request_password_reset),
        )
        .route("/reset_password", post(handlers::reset_password))
        .route("/change_password", post(handlers::change_password))
}
