use mongodb::bson::Uuid;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// All the possible errors that can be returned by Horizon
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    // Authentication
    /// When logging in, the credentials do not evaluate to any user's account
    InvalidCredentials,
    /// When attempting to do any authenticated operation, the caller did not provide the session
    /// cookie
    SessionCookieMissing,
    /// When attempting to do any authenticated operation, the caller did not provide the anti-CSRF
    /// token header
    CsrfHeaderMissing,
    /// When attempting to do any authenticated operation, the provided session was not found
    SessionNotFound,
    /// When attempting to do a scoped authenticated operation and the caller does not have access
    /// to that scope
    InsufficientPermissions,

    // General
    /// Something unexpected happened. See the message and the source for more information
    #[default]
    Unexpected,
}

/// Error type used by Horizon
#[derive(Debug, serde::Serialize)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    request_id: Option<Uuid>,
    #[serde(skip_serializing)]
    context: Vec<&'static str>,
    #[serde(skip_serializing)]
    source: Option<anyhow::Error>,
}

impl Error {
    /// Create source error
    ///
    /// Try to not leak information through the error kind or message. The message should be
    /// something that is safe for anyone to know. Information can instead be gathered for debugging
    /// prom the source error and the context.
    pub fn new(
        kind: ErrorKind,
        message: String,
        request_id: Option<Uuid>,
        context: impl Into<&'static str>,
    ) -> Self {
        let context = vec![context.into()];

        Self {
            kind,
            message,
            request_id,
            context,
            source: None,
        }
    }

    /// Create a new error with a source
    ///
    /// This is a utility function for when implementing `From` for `Error` is not worth it.
    /// This is used for example when dealing with toml serialization errors. The configuration file
    /// is only ever read once, and thus only one error is ever going to be possibly handled. Thus,
    /// it's not worth it to implement From, for that singular error.
    pub fn new_with_source(
        kind: ErrorKind,
        message: String,
        request_id: Option<Uuid>,
        context: impl Into<&'static str>,
        source: anyhow::Error,
    ) -> Self {
        let context = vec![context.into()];

        Self {
            kind,
            message,
            request_id,
            context,
            source: Some(source),
        }
    }

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

/// Add context to an error
///
/// Context should always be concerning the exact operation and not the function it happens in. This
/// is to avoid duplicate context, since callers should be the ones adding that context.
///
/// ### For example:
/// Do:
/// ```ignore, rust
/// [
///     "Performing a MongoDB database operation",
///     "Finding out which user a token belongs to",
///     "Deleting all sessions",
///     "Fulfilling HTTP request"
/// ]
/// ```
///
/// Don't:
/// ```ignore, rust
/// [
///     "Performing a MongoDB database operation",
///     "Trying to find which user a token belongs to, so all sessions can be deleted",
///     "Trying to delete all sessions to fulfill a POST request",
///     "Trying to fulfill HTTP request"
/// ]
/// ```
///
/// Also avoid "Trying to", "Attempting to" and similar phrasings. You can word it more directly.
pub trait Context<T> {
    /// Convert to Horizon's error type if it isn's already and add context if the result is an `Error`
    ///
    /// # Errors
    /// It returns the same exact Result variant, as the one it's called on, it just converts
    /// whatever error type it carries into Horizon's `Error` type.
    fn context(self, context: impl Into<&'static str>) -> Result<T, Error>;

    /// Convert to Horizon's error type if it isn't already and add context if the result is an `Error`, including the `request_id`
    ///
    /// # Errors
    /// It returns the same exact Result variant, as the one it's called on, it just converts
    /// whatever error type it carries into Horizon's `Error` type.
    fn root_context(self, context: impl Into<&'static str>, request_id: Uuid) -> Result<T, Error>;
}

impl<T, E> Context<T> for Result<T, E>
where
    Error: From<E>,
{
    fn context(self, context: impl Into<&'static str>) -> Result<T, Error> {
        let mut mapped: Result<T, Error> = self.map_err(Into::into);

        if let Err(ref mut error) = mapped {
            error.context.push(context.into());
        }

        mapped
    }

    fn root_context(self, context: impl Into<&'static str>, request_id: Uuid) -> Result<T, Error> {
        let mut mapped: Result<T, Error> = self.map_err(Into::into);

        if let Err(ref mut error) = mapped {
            error.context.push(context.into());
            error.request_id = Some(request_id);
        }

        mapped
    }
}

impl IntoResponse for Error {
    fn into_response(mut self) -> Response {
        self.context.push("Fulfilling an HTTP request");

        let http_code = match self.kind {
            ErrorKind::InvalidCredentials
            | ErrorKind::SessionNotFound
            | ErrorKind::SessionCookieMissing
            | ErrorKind::CsrfHeaderMissing => {
                log::trace!("{self:#?}");
                StatusCode::UNAUTHORIZED
            }

            ErrorKind::InsufficientPermissions => {
                log::trace!("{self:#?}");
                StatusCode::FORBIDDEN
            }

            ErrorKind::Unexpected => {
                log::warn!("{self:#?}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        (http_code, Json(self)).into_response()
    }
}

impl From<mongodb::error::Error> for Error {
    fn from(value: mongodb::error::Error) -> Self {
        Self {
            kind: ErrorKind::Unexpected,
            message: "Something unexpected happened".into(),
            request_id: None,
            context: vec!["Performing a MongoDB database operation"],
            source: Some(anyhow::Error::new(value)),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Unexpected,
            message: "Something unexpected happened".into(),
            request_id: None,
            context: vec!["Performing an IO operation"],
            source: Some(anyhow::Error::new(value)),
        }
    }
}

impl From<hex::FromHexError> for Error {
    fn from(value: hex::FromHexError) -> Self {
        Self {
            kind: ErrorKind::Unexpected,
            message: "Something unexpected happened".into(),
            request_id: None,
            context: vec!["Decoding from hex"],
            source: Some(anyhow::Error::new(value)),
        }
    }
}
