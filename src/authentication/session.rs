use mongodb::{
    Database,
    bson::{DateTime, Uuid, doc},
};

use crate::{
    authentication::token::{HmacKey, Token},
    configuration::Authentication,
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
#[allow(clippy::used_underscore_binding)]
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
    ///
    /// Will return an error if the `user` doesn't exist
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
            .root_context("Getting a user's team and scopes", request_id)?;

        let Some(User { team, scopes }) = user_projection else {
            return Err(Error::new(
                ErrorKind::Unexpected,
                "Something unexpected happened while trying to create a new session".into(),
                Some(request_id),
                "Creating a new session, the passed user doesn't exist",
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
            .root_context("Inserting a new session", request_id)?;

        Ok(token.hex())
    }

    /// Given a session token, get the associated session, updating the `last_seen_at` timestamp
    ///
    /// # Errors
    /// Will return an error if the given session token doesn't belong to any active sessions
    ///
    /// May return an error if there's an issue communicating with the database
    pub async fn get(
        session_token: Token,
        key: &HmacKey,
        auth_config: &Authentication,
        database: &Database,
        request_id: Uuid,
    ) -> Result<Self, Error> {
        let token = session_token.hmac(key);

        let now = DateTime::now();
        let fresh_before = now.saturating_add_millis(-auth_config.session_timeout_ms);

        let Some(session) = database
            .collection::<Self>("sessions")
            .find_one_and_update(
                doc! {                                        // While MongoDB has more accurate time
                    "_id": token,                             // here, doing it like this lets us
                    "last_seen_at": { "$gte": fresh_before }, // take advantage of indexes better
                },
                doc! { "$set": { "last_seen_at": now } },
            )
            .await
            .root_context("Getting and updating a session", request_id)?
        else {
            return Err(Error::new(
                ErrorKind::SessionNotFound,
                "No valid session found for the provided token".into(),
                Some(request_id),
                "Getting and updating a session that doesn't exist",
            ));
        };

        Ok(session)
    }

    /// Adds a new anti-CSRF token for the given session
    ///
    /// Returns the hex-encoded `csrf_token`
    ///
    /// # Errors
    /// Will return an error if the session doesn't exist in the database. This should practically
    /// never happen, as it would be caused by a TOCTOU scenario.
    ///
    /// May return an error if there's an issue communicating with the database.
    pub async fn new_csrf_token(
        &self,
        key: &HmacKey,
        database: &Database,
        request_id: Uuid,
    ) -> Result<Token, Error> {
        let csrf_token = Token::new();

        let session: Option<String> = database
            .collection("sessions")
            .find_one_and_update(
                doc! { "_id": &self._id },
                doc! { "csrf_token_hmac": csrf_token.hmac(key) },
            )
            .projection(doc! {"_id": 1})
            .await
            .root_context("Adding a new anti-CSRF token to a session", request_id)?;

        if session.is_none() {
            Err(Error::new(
                ErrorKind::Unexpected,
                "Something unexpected happened while trying to issue a CSRF token".into(),
                Some(request_id),
                "Adding a new anti-CSRF token to a session that doesn't exist",
            ))
        } else {
            Ok(csrf_token)
        }
    }

    /// Deletes a session
    ///
    /// This essentially logs out the user for the session
    ///
    /// # Errors
    /// Will return an error if the session doesn't exist in the database. This should practically
    /// never happen, as it would be caused by a TOCTOU scenario.
    ///
    /// May return an error if there's an issue communicating with the database
    pub async fn delete(&self, database: &Database, request_id: Uuid) -> Result<(), Error> {
        let session: Option<String> = database
            .collection("sessions")
            .find_one_and_delete(doc! { "_id": &self._id })
            .projection(doc! {"_id": 1})
            .await
            .root_context("Deleting a session", request_id)?;

        if session.is_none() {
            Err(Error::new(
                ErrorKind::Unexpected,
                "Something unexpected happened while trying to delete a session".into(),
                Some(request_id),
                "Deleting a session that doesn't exist",
            ))
        } else {
            Ok(())
        }
    }

    /// Deletes all sessions associated with the user
    ///
    /// Logs out all of the user's sessions
    ///
    /// # Errors
    /// Will return an error if the user doesn't have any sessions or if the user itself doesn't
    /// exist. This should practically never happen, as it would be caused by a TOCTOU scenario.
    ///
    /// May return an error if there's an issue communicating with the database
    pub async fn delete_all(&self, database: &Database, request_id: Uuid) -> Result<(), Error> {
        let result = database
            .collection::<Self>("sessions")
            .delete_many(doc! { "user": &self.user })
            .await
            .root_context("", request_id)?;

        if result.deleted_count > 0 {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::SessionNotFound,
                "Something unexpected happened while trying to delete sessions".into(),
                Some(request_id),
                "Deleting zero sessions",
            ))
        }
    }
}
