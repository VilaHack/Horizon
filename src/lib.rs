mod authentication;
mod configuration;
pub mod error;

pub struct State {
    configuration: configuration::Config,
    database: mongodb::Database,
}
