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
    /// Create source error
    pub fn new(
        kind: ErrorKind,
        message: String,
        request_id: Uuid,
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
            error.request_id = request_id;
        }

        mapped
    }
}

/// All the possible errors that can be returned by Horizon
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    // Authentication
    /// When logging in, the credentials do not evaluate to any user's account
    InvalidCredentials,
    /// When attempting to do any authenticated operation, the provided session was not found
    SessionNotFound,

    // General
    /// Something unexpected happened. See the message and the source for more information
    #[default]
    Unexpected,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let http_code = match self.kind {
            ErrorKind::InvalidCredentials | ErrorKind::SessionNotFound => StatusCode::UNAUTHORIZED,

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
            request_id: Uuid::new(),
            context: vec!["MongoDB database operation"],
            source: Some(anyhow::Error::new(value)),
        }
    }
}
