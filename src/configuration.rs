use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use axum::http::HeaderValue;
use lettre::{message::Mailbox, transport::smtp::authentication::Credentials};
use mongodb::options::ConnectionString;

use serde::Deserialize;

use crate::{
    authentication::HmacKey,
    error::{Context, Error, ErrorKind},
};

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
    pub key: HmacKey,
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

/// Horizon's configuration
#[derive(Deserialize, Debug)]
pub struct Config {
    /// Set of log filters in the `log` crate's filter format
    pub log_level: String,

    pub authentication: Authentication,
    pub http: Http,
    #[allow(clippy::doc_markdown)]
    /// MongoDB client configuration
    pub database: Database,
    pub smtp: Email,
}

impl Config {
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
                None,
                "Trying to parse configuration file",
                anyhow::Error::new(err),
            )
        })
    }
}
