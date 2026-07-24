pub mod authentication;
mod configuration;
pub mod error;

use std::time::Duration;

use mongodb::{
    Client, IndexModel,
    bson::doc,
    options::{ClientOptions, IndexOptions},
};

use logforth::{
    append::opentelemetry::OpentelemetryLogBuilder, filter::env_filter::EnvFilterBuilder,
};
use opentelemetry_otlp::{LogExporter, Protocol, WithExportConfig};

use authentication::Session;
use configuration::Configuration;
use error::{Context, Error, ErrorKind};

use crate::configuration::Telemetry;

/// Represents Horizon's state
pub struct State {
    configuration: configuration::Configuration,
    database: mongodb::Database,
}

impl State {
    /// Initialize Horizon's state
    ///
    /// It gathers it's configuration from the default paths and establishes the database
    /// connection, creating indexes if they didn't exist already
    ///
    /// # Errors
    /// Will error if no valid config file can be found and if it can't communicate with the
    /// database
    pub async fn initialize() -> Result<Self, Error> {
        let configuration = Configuration::from_default_locations()
            .context("Getting configuration from default locations")?;

        Self::initialize_logging(&configuration.telemetry).context("Initializing logging")?;
        eprintln!("Switching to logging over opentelemetry");

        let database = Self::initialize_database(&configuration)
            .await
            .context("Initializing database")?;

        Ok(Self {
            configuration,
            database,
        })
    }

    fn initialize_logging(configuration: &Telemetry) -> Result<(), Error> {
        let Ok(filter_builder) = EnvFilterBuilder::try_from_spec(&configuration.filter) else {
            todo!()
        };

        let filter = filter_builder.build();

        let exporter = LogExporter::builder()
            .with_tonic()
            .with_endpoint(&configuration.otlp_endpoint)
            .with_protocol(Protocol::Grpc)
            .build()
            .map_err(|err| {
                Error::new_with_source(
                    ErrorKind::Unexpected,
                    "Something unexpected happened".into(),
                    None,
                    "Building the otlp log exporter",
                    anyhow::Error::new(err),
                )
            })?;

        let appender = OpentelemetryLogBuilder::new(configuration.service_name.clone(), exporter)
            .label("service.name", configuration.service_name.clone())
            .build();

        logforth::starter_log::builder()
            .dispatch(|b| b.filter(filter).append(appender))
            .apply();

        log::trace!("Horizon is starting. Now emitting logs over otlp.");

        Ok(())
    }

    async fn initialize_database(
        configuration: &Configuration,
    ) -> Result<mongodb::Database, Error> {
        let options = ClientOptions::parse(configuration.database.uri.clone())
            .await
            .context("Parsing client options from connection string")?;

        let Some(database) = Client::with_options(options)
            .context("Creating a client from client options")?
            .default_database()
        else {
            return Err(Error::new(
                ErrorKind::Unexpected,
                "Something unexpected happened".into(),
                None,
                "Trying to connect to default database which is missing",
            ));
        };

        let ttl_index_options = {
            let mut options = IndexOptions::default();

            options.expire_after = Some(Duration::from_millis(
                configuration
                    .authentication
                    .session_timeout_ms
                    .unsigned_abs(),
            ));

            options
        };

        let indexes = [
            IndexModel::builder()
                .keys(doc! { "_id": 1, "csrf_token_hmac": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "last_seen_at": 1 })
                .options(ttl_index_options)
                .build(),
        ];

        _ = database
            .collection::<Session>("sessions")
            .create_indexes(indexes)
            .await
            .context("Creating session indexes")?;

        Ok(database)
    }
}
