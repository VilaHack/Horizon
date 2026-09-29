mod auth;
mod credentials;
mod session;
mod token;

pub use auth::Auth;
pub use credentials::Credentials;
pub use session::{Scope, Session, scoped};
pub use token::{Token, VerificationToken};

#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(Credentials,)))]
pub struct AuthModelDocs;
