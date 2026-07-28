use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use axum::http::HeaderValue;
use lettre::{message::Mailbox, transport::smtp::authentication::Credentials};
use mongodb::options::ConnectionString;

use serde::Deserialize;

use crate::error::{Context, Error, ErrorKind};

mod headervalues {
    use axum::http::HeaderValue;
    use serde::{Deserialize, Deserializer};

    #[allow(clippy::missing_errors_doc)]
    pub fn deserialize<'de, D>(d: D) -> Result<Vec<HeaderValue>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strs: Vec<String> = Vec::deserialize(d)?;
        strs.into_iter()
            .map(|s| HeaderValue::from_str(&s).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Authentication configuration
#[derive(Deserialize, Debug)]
pub struct Authentication {
    /// Secret key used for the HMAC algorithm
    pub key: [u8; 32],
    /// How long in ms it takes for a session to be considered stale
    pub session_timeout_ms: i64,
    /// Domain the session cookie will be configured for
    pub domain: String,
}

#[derive(Deserialize, Debug)]
pub struct Http {
    /// Socket address the HTTP server will bind to
    pub bind_address: SocketAddr,

    /// Set of CORS allowed origins
    #[serde(with = "headervalues")]
    pub allowed_origins: Vec<HeaderValue>,
}

#[derive(Deserialize, Debug)]
pub struct Database {
    #[allow(clippy::doc_markdown)]
    /// MongoDB connection string
    pub uri: ConnectionString,
}

#[derive(Deserialize, Debug)]
pub struct EmailTemplate {
    pub subject: String,
    /// Path to the liquid template containing the path
    pub body: PathBuf,
}

#[derive(Deserialize, Debug)]
pub struct EmailTemplates {
    /// Email verification message template
    pub verification: EmailTemplate,
    /// Forgotten password reset message template
    pub forgot_password: EmailTemplate,
    /// Application acceptance message template
    pub application_acceptance: EmailTemplate,
}

#[derive(Deserialize, Debug)]
pub struct Email {
    /// SMTP relay
    pub relay: String,
    /// SMTP relay credentials: `authentication_identity` (username) and `secret` (password)
    pub credentials: Credentials,
    /// Mailbox emails will be sent from (Mailbox format: `Name <email@host.net>`)
    pub send_from: Mailbox,
    /// Reply to mailbox emails will be sent with (Mailbox format: `Name <email@host.net>`)
    pub reply_to: Mailbox,
    /// Set of email templates supported by Horizon
    pub templates: EmailTemplates,
}

#[derive(Deserialize, Debug)]
pub struct OpenTelemetry {
    pub endpoint: String,
    /// Service name that will be reported to opentelemetry.
    ///
    /// This is useful if you have several deployments pushing logs to the same opentelemetry
    /// collector; for example if you have a staging backend and a production one.
    pub service_name: String,
}

#[derive(Deserialize, Debug)]
pub struct Observability {
    /// Set of log filters in the `log` crate's filter format
    pub filter: String,
    pub opentelemetry: Option<OpenTelemetry>,
    #[serde(default)]
    pub stderr: bool,
}

/// Horizon's configuration
#[derive(Deserialize, Debug)]
pub struct Configuration {
    pub authentication: Authentication,
    pub http: Http,
    pub database: Database,
    pub smtp: Email,
    pub observability: Observability,
}

impl Configuration {
    // using `eprintln` instead of loging because logging isn't active yet when this runs
    pub fn from_default_locations() -> Result<Self, Error> {
        let mut paths: Vec<PathBuf> = vec![
            "/etc/horizon/horizon.toml".into(),
            "/etc/horizon/configuration.toml".into(),
            "/etc/horizon/config.toml".into(),
        ];

        if let Some(path) = std::env::args().nth(1) {
            paths.insert(0, path.into());
        }

        let mut configuration = None;

        for path in paths {
            match Self::read_from_path(&path) {
                Ok(config) => {
                    eprintln!("Successfully read config from {}", path.display());
                    configuration = Some(config);
                    break;
                }
                Err(err) => {
                    eprintln!("Could not read config from {}: {err:#?}", path.display());
                }
            }
        }

        configuration.map_or_else(
            || {
                eprintln!("Configuration could not be built from default paths");
                Err(Error::new(
                    ErrorKind::Unexpected,
                    "Could not get build configuration from default paths".into(),
                    "Building configuration none of the default paths contain a valid file",
                ))
            },
            Ok,
        )
    }

    /// Reads the configuration given a path to the config file
    ///
    /// # Errors
    /// Will return an error if the file is not readable by the backend of if it's incorrectly
    /// formatted.
    pub fn read_from_path(path: &Path) -> Result<Self, Error> {
        let config = &fs::read_to_string(path).context("Trying to read the config file")?;

        toml::from_str(config).map_err(|err| {
            Error::new_with_source(
                ErrorKind::Unexpected,
                "Something unexpected happened".into(),
                "Trying to parse configuration file",
                anyhow::Error::new(err),
            )
        })
    }
}
