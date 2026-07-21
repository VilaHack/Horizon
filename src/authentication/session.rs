use mongodb::{
    Database,
    bson::{DateTime, Uuid, doc},
};

use crate::{
    authentication::token::{HmacKey, Token},
    error::{Context, Error, ErrorKind},
};

/// Represents which type of operations a user can access
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Scope {
    /// Can manage events
    Event,
    /// Can manage puzzles
    Puzzle,
    /// Can scan QRs to register checkins or participations
    Scan,
}

/// Represents a user's session
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Session {
    _id: String,
    csrf_token_hmac: String,
    last_seen_at: DateTime,
    user: Uuid,
    team: Option<Uuid>,
    scopes: Vec<Scope>,
}

/// Projection of user used only for building sessions
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
struct User {
    team: Option<Uuid>,
    scopes: Vec<Scope>,
}

impl Session {
    /// Create a new session for the given user
    ///
    /// Returns the hex-encoded `session_token`
    ///
    /// # Errors
    /// May return an error if there's an issue communicating with the database
    #[allow(clippy::new_ret_no_self)]
    pub async fn new(
        user: Uuid,
        key: &HmacKey,
        database: &Database,
        request_id: Uuid,
    ) -> Result<String, Error> {
        let token = Token::new();

        let user_projection: Option<User> = database
            .collection("users")
            .find_one(doc! { "_id": user })
            .projection(doc! {"team": 1, "scopes": 1})
            .await
            .root_context("Fetching projected user for session creation", request_id)?;

        let Some(User { team, scopes }) = user_projection else {
            return Err(Error::new(
                ErrorKind::Unexpected,
                "Something unexpected happened while trying to create a new session for the user"
                    .into(),
                request_id,
                "Attempting to create a new session, the passed user doesn't exist",
            ));
        };

        let session = Self {
            _id: token.hmac(key),
            csrf_token_hmac: String::with_capacity(0),
            last_seen_at: DateTime::now(),
            user,
            team,
            scopes,
        };

        _ = database
            .collection("sessions")
            .insert_one(session)
            .await
            .root_context("Inserting new session", request_id)?;

        Ok(token.hex())
    }

    /// Adds a new anti-CSRF token for the given session
    ///
    /// Returns the hex-encoded `csrf_token`
    ///
    /// # Errors
    /// Will return an error if the session doesn't exist.
    ///
    /// May return an error if there's an issue communicating with the database.
    pub async fn new_csrf_token(
        session_token: String,
        key: &HmacKey,
        database: &Database,
        request_id: Uuid,
    ) -> Result<String, Error> {
        let token: String = Token::try_from(&session_token).unwrap().hmac(key);
        let csrf_token = Token::new();

        let session: Option<String> = database
            .collection("sessions")
            .find_one_and_update(
                doc! { "_id": token },
                doc! { "csrf_token_hmac": csrf_token.hmac(key) },
            )
            .projection(doc! {"_id": 1})
            .await
            .root_context(
                "Attempting to add a new anti-CSRF token to a session",
                request_id,
            )?;

        if session.is_none() {
            Err(Error::new(
                ErrorKind::SessionNotFound,
                "Could not issue a new anti-CSRF token, the session it was requested for was not found".into(),
                request_id,
                "Attempting to issue a new csrf_token",
            ))
        } else {
            Ok(csrf_token.hex())
        }
    }
}
