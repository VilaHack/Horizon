pub mod authentication;
mod configuration;
pub mod error;
mod state;
mod user;

pub use state::State;

#[derive(axum::extract::FromRequest)]
#[from_request(via(axum::Json), rejection(error::Error))]
pub struct Json<T>(T);
