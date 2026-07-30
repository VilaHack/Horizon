use std::time::Duration;

use mongodb::{
    Client, IndexModel,
    bson::doc,
    options::{ClientOptions, IndexOptions},
};

use logforth::{
    append::{Stderr, opentelemetry::OpentelemetryLogBuilder},
    bridge::log::LogBridge,
    filter::rustlog::RustLogFilterBuilder,
    layout::TextLayout,
};

use metrics_opentelemetry::{
    OpenTelemetryMetrics, OpenTelemetryRecorder, metrics, opentelemetry::metrics::MeterProvider,
};

use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::{LogExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

use crate::{
    authentication::Session,
    configuration::{Configuration, Observability},
    error::{Context, Error, ErrorKind},
    user::User,
};

/// Represents Horizon's state
pub struct State {
    pub configuration: Configuration,
    pub database: mongodb::Database,
    _meter_provider: Option<SdkMeterProvider>,
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

        initialize_logging(&configuration.observability).context("Initializing logging")?;

        let meter_provider = initialize_metrics(&configuration.observability);

        let database = initialize_database(&configuration)
            .await
            .context("Initializing database")?;

        log::trace!("State initialized.");

        Ok(Self {
            configuration,
            database,
            _meter_provider: meter_provider,
        })
    }
}

fn initialize_logging(configuration: &Observability) -> Result<(), Error> {
    // Filtering is done by logforth.
    log::set_max_level(log::LevelFilter::Trace);

    let filter = RustLogFilterBuilder::try_from_spec(&configuration.filter)
        .map_err(|err| {
            Error::new_with_source(
                ErrorKind::Unexpected,
                "Something unexpected happened".into(),
                "Parsing logging filter",
                anyhow::Error::new(err),
            )
        })?
        .build();

    // Clone is not implemented on this logforth version, thus I have to construct the filter
    // twice. I submitted a patch upstream, which got accepted. Now we need it to get released:
    // https://github.com/fast/logforth/pull/237
    let filter2 = RustLogFilterBuilder::try_from_spec(&configuration.filter)
        .map_err(|err| {
            Error::new_with_source(
                ErrorKind::Unexpected,
                "Something unexpected happened".into(),
                "Parsing logging filter",
                anyhow::Error::new(err),
            )
        })?
        .build();

    let mut builder = logforth::core::builder();

    if let Some(otlp_config) = &configuration.opentelemetry {
        let appender = {
            let exporter = LogExporter::builder()
                .with_tonic()
                .with_endpoint(&otlp_config.endpoint)
                .with_protocol(Protocol::Grpc)
                .build()
                .map_err(|err| {
                    Error::new_with_source(
                        ErrorKind::Unexpected,
                        "Something unexpected happened".into(),
                        "Building the otlp log exporter",
                        anyhow::Error::new(err),
                    )
                })?;

            OpentelemetryLogBuilder::new(otlp_config.service_name.clone(), exporter)
                .label("service.name", otlp_config.service_name.clone())
                .build()
        };

        builder = builder.dispatch(|b| b.filter(filter).append(appender));

        eprintln!("Switching to logging over opentelemetry.");
    }

    if configuration.stderr {
        builder = builder.dispatch(|b| {
            b.filter(filter2)
                .append(Stderr::default().with_layout(TextLayout::default()))
        });
    }

    _ = log::set_boxed_logger(Box::new(LogBridge::new(builder.build())));

    log::trace!(
        "Initialized logging. Using opentelemetry: {}, using stderr: {}",
        configuration.opentelemetry.is_some(),
        configuration.stderr
    );

    Ok(())
}

fn initialize_metrics(configuration: &Observability) -> Option<SdkMeterProvider> {
    configuration.opentelemetry.as_ref().map_or_else(
        || {
            log::trace!("Skipped initializing metrics. Opentelemetry is not configured.");

            None
        },
        |otel_config| {
            let reader = PeriodicReader::builder(InMemoryMetricExporter::default())
                .with_interval(Duration::from_millis(100))
                .build();

            let provider = SdkMeterProvider::builder().with_reader(reader).build();

            let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
                .with_attributes([
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    KeyValue::new(
                        "deployment.environment.name",
                        otel_config.service_name.clone(),
                    ),
                ])
                .build();

            let recorder = OpenTelemetryRecorder::new(OpenTelemetryMetrics::new(
                provider.meter_with_scope(scope),
            ));

            _ = metrics::set_global_recorder(recorder);

            metrics::describe_counter!(
                "requests_total",
                metrics::Unit::Count,
                "Total number of requests"
            );

            log::trace!("Initialized metrics.");

            Some(provider)
        },
    )
}

async fn initialize_database(configuration: &Configuration) -> Result<mongodb::Database, Error> {
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

    let unique_index_optins = {
        let mut options = IndexOptions::default();

        options.unique = Some(true);

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

    _ = database
        .collection::<User>("users")
        .create_index(
            IndexModel::builder()
                .keys(doc! { "auth.email": 1, })
                .options(unique_index_optins)
                .build(),
        )
        .await
        .context("Creating user indexes")?;

    log::trace!("Connected to database.");

    Ok(database)
}
