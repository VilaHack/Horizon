use mongodb::bson::Uuid;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Error type used by Horizon
#[derive(Debug, serde::Serialize)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    request_id: Uuid,
    #[serde(skip_serializing)]
    context: Vec<&'static str>,
    #[serde(skip_serializing)]
    source: Option<anyhow::Error>,
}

impl Error {
    /// Return the error's kind
    #[must_use]
    pub fn kind(self) -> ErrorKind {
        self.kind
    }

    /// Return the error's message
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

pub trait Context {
    #[must_use]
    fn add_context(self, context: impl Into<&'static str>) -> Self;
}

impl<T> Context for Result<T, Error> {
    /// Add context if the result is an `Error`
    fn add_context(mut self, context: impl Into<&'static str>) -> Self {
        if let Err(ref mut error) = self {
            error.context.push(context.into());
        }

        self
    }
}

/// All the possible errors that can be returned by Horizon
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum ErrorKind {
    // Authentication
    /// The JWT's issuer is not added to the configuration's `trusted_issuers` list
    JwtInvalidIssuer,
    /// The JWT's alg field is either missing, invalid or indicates an unsupported algorythm
    JwtInvalidAlgorythm,
    /// The JWT's signature does not match
    JwtInvalidSignature,
    /// The JWT's claim has an invalid format (for example, a string in place of an integer)
    JwtInvalidClaimFormat,
    /// The API call requires a JWT, and it was not provided
    JwtMissing,
    /// The JWT is either expired or immature
    JwtInvalidTimeRange,
    /// When signing a token, the secret key is not valid for the selected algorythm
    #[serde(rename = "unexpected")]
    JwtInvalidKey,
    /// When logging in, the credentials do not evaluate to any user's account
    InvalidCredentials,
    /// The JWT has been authenticated but doesn't grant sufficient permissions for the operation
    InsufficientPermissions,

    // General
    /// Something unexpected happened. See the message and the source for more information
    #[default]
    Unexpected,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let http_code = match self.kind {
            ErrorKind::JwtInvalidIssuer
            | ErrorKind::JwtInvalidAlgorythm
            | ErrorKind::JwtInvalidSignature
            | ErrorKind::JwtInvalidClaimFormat
            | ErrorKind::JwtMissing
            | ErrorKind::JwtInvalidTimeRange
            | ErrorKind::InvalidCredentials
            | ErrorKind::InsufficientPermissions => StatusCode::UNAUTHORIZED,

            ErrorKind::Unexpected | ErrorKind::JwtInvalidKey => {
                log::warn!("{self:#?}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        (http_code, Json(self)).into_response()
    }
}
