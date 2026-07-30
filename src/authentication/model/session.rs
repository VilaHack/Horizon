use std::sync::Arc;

use axum::{extract::FromRequestParts, http::request::Parts};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use mongodb::{
    Database,
    bson::{DateTime, Uuid, doc},
};

use crate::{
    State,
    authentication::model::token::{HmacKey, Token},
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

#[derive(Debug, serde::Deserialize)]
struct ProjectedAuth {
    scopes: Vec<Scope>,
}

/// Projection of user used only for building sessions
#[derive(Debug, serde::Deserialize)]
struct ProjectedUser {
    team: Option<Uuid>,
    auth: ProjectedAuth,
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
    pub async fn new(user: Uuid, key: &HmacKey, database: &Database) -> Result<String, Error> {
        let token = Token::new();

        let user_projection: Option<ProjectedUser> = database
            .collection("users")
            .find_one(doc! { "_id": user })
            .projection(doc! { "team": 1, "auth.scopes": 1 })
            .await
            .context("Getting a user's team and scopes")?;

        let Some(ProjectedUser {
            team,
            auth: ProjectedAuth { scopes },
        }) = user_projection
        else {
            return Err(Error::new(
                ErrorKind::Unexpected,
                "Something unexpected happened while trying to create a new session".into(),
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
            .context("Inserting a new session")?;

        Ok(token.hex())
    }

    /// Given a session token and it's csrf token, get the associated session,
    /// updating the `last_seen_at` timestamp
    ///
    /// # Errors
    /// Will return an error if the given session token doesn't belong to any active sessions
    ///
    /// May return an error if there's an issue communicating with the database
    pub async fn get(
        session_token: Token,
        csrf_token: Token,
        auth_config: &Authentication,
        database: &Database,
    ) -> Result<Self, Error> {
        let now = DateTime::now();
        let fresh_before = now.saturating_add_millis(-(auth_config.session_timeout_ms.abs()));

        let Some(session) = database
            .collection::<Self>("sessions")
            .find_one_and_update(
                doc! {
                    "_id": session_token.hmac(&auth_config.key),
                    "csrf_token_hmac": csrf_token.hmac(&auth_config.key),
                    "last_seen_at": { "$gte": fresh_before }, // While MongoDB has more accurate time
                }, // take advantage of indexes better
                doc! { "$set": { "last_seen_at": now } }, // here, doing it like this lets us
            )
            .await
            .context("Getting and updating a session")?
        else {
            return Err(Error::new(
                ErrorKind::SessionNotFound,
                "No valid session found for the provided token".into(),
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
    pub async fn new_csrf_token(&self, key: &HmacKey, database: &Database) -> Result<Token, Error> {
        let csrf_token = Token::new();

        let session: Option<String> = database
            .collection("sessions")
            .find_one_and_update(
                doc! { "_id": &self._id },
                doc! { "csrf_token_hmac": csrf_token.hmac(key) },
            )
            .projection(doc! {"_id": 1})
            .await
            .context("Adding a new anti-CSRF token to a session")?;

        if session.is_none() {
            Err(Error::new(
                ErrorKind::Unexpected,
                "Something unexpected happened while trying to issue a CSRF token".into(),
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
    pub async fn delete(&self, database: &Database) -> Result<(), Error> {
        let session: Option<String> = database
            .collection("sessions")
            .find_one_and_delete(doc! { "_id": &self._id })
            .projection(doc! {"_id": 1})
            .await
            .context("Deleting a session")?;

        if session.is_none() {
            Err(Error::new(
                ErrorKind::Unexpected,
                "Something unexpected happened while trying to delete a session".into(),
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
    pub async fn delete_all(&self, database: &Database) -> Result<(), Error> {
        let result = database
            .collection::<Self>("sessions")
            .delete_many(doc! { "user": &self.user })
            .await
            .context("Deleting all user sessions for a user")?;

        if result.deleted_count > 0 {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::SessionNotFound,
                "Something unexpected happened".into(),
                "Deleting zero sessions",
            ))
        }
    }
}

impl FromRequestParts<Arc<State>> for Session {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<State>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .expect("CookieJar::from_request_parts is `Infallible`");

        let Some(session_cookie) = jar.get("horizon_session").map(Cookie::value) else {
            return Err(Error::new(
                ErrorKind::SessionCookieMissing,
                "A session cookie was not provided for an operation requiring authentication"
                    .into(),
                "Retrieving the session cookie from the cookie jar",
            ));
        };

        let session_token =
            Token::try_from(session_cookie).context("Building a token from the session cookie")?;

        let Some(csrf_token) = parts.headers.get("X-CSRF-Token") else {
            return Err(Error::new(
                ErrorKind::CsrfHeaderMissing,
                "An anti-CSRF token was not provided for an operation requiring authentication"
                    .into(),
                "Retrieving the CSRF header from the header map",
            ));
        };

        let csrf_token = csrf_token.to_str().map_err(|err| {
            Error::new_with_source(
                ErrorKind::Unexpected,
                "Something unexpected happened".into(),
                "Converting a header value to a &str",
                anyhow::Error::new(err),
            )
        })?;

        let csrf_token =
            Token::try_from(csrf_token).context("Building a token from the CSRF header value")?;

        Self::get(
            session_token,
            csrf_token,
            &state.configuration.authentication,
            &state.database,
        )
        .await
        .context("Getting a session")
    }
}

pub mod scoped {
    use std::sync::Arc;

    use axum::{extract::FromRequestParts, http::request::Parts};

    use crate::{
        State,
        authentication::{Scope, Session},
        error::{Error, ErrorKind},
    };

    pub trait RequiredScope {
        const SCOPE: Scope;
    }

    /// See `ScopedSession`
    pub struct Scan;
    impl RequiredScope for Scan {
        const SCOPE: Scope = Scope::Scan;
    }

    /// See `ScopedSession`
    pub struct Event;
    impl RequiredScope for Event {
        const SCOPE: Scope = Scope::Event;
    }

    /// See `ScopedSession`
    pub struct Puzzle;
    impl RequiredScope for Puzzle {
        const SCOPE: Scope = Scope::Puzzle;
    }

    /// Helper struct for allwing you to easily scope-guard endpoints
    ///
    /// For example:
    /// ```ignore, rust
    /// pub async fn check_in(
    ///     session: ScopedSession<Scan>,
    ///     Query(attendee_id): Query(Id),
    ///     State(state): State<Arc<Bstate>>,
    /// ) -> Result<Json<CheckinResponse>, Error> {
    ///     // ...
    /// }
    /// ```
    pub struct ScopedSession<S> {
        session: Session,
        _marker: std::marker::PhantomData<S>,
    }

    impl<S> std::ops::Deref for ScopedSession<S> {
        type Target = Session;

        fn deref(&self) -> &Session {
            &self.session
        }
    }

    impl<S> FromRequestParts<Arc<State>> for ScopedSession<S>
    where
        S: RequiredScope,
    {
        type Rejection = Error;

        async fn from_request_parts(
            parts: &mut Parts,
            state: &Arc<State>,
        ) -> Result<Self, Self::Rejection> {
            let session = Session::from_request_parts(parts, state).await?;

            if !session.scopes.contains(&S::SCOPE) {
                return Err(Error::new(
                    ErrorKind::InsufficientPermissions,
                    "The caller doesn't have sufficient permissions to do this operation".into(),
                    "Verifying scope",
                ));
            }

            Ok(Self {
                session,
                _marker: std::marker::PhantomData,
            })
        }
    }
}
