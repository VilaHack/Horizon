mod api;
mod model;

pub use api::{AuthApiDocs, router};
pub use model::AuthModelDocs;
pub use model::{Auth, Credentials, Scope, Session, Token, scoped};
