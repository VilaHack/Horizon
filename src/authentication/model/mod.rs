mod auth;
pub mod credentials;
pub mod session;
mod token;

pub use auth::Auth;
pub use token::{Token, VerificationToken, deserialize_token};

#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(credentials::Credentials,)))]
pub struct AuthModelDocs;
