pub mod api;
mod model;

pub use model::{Auth, Token, VerificationToken, credentials, deserialize_token, session};

pub mod openapi {
    pub use crate::authentication::{api::AuthApiDocs, model::AuthModelDocs};
}
