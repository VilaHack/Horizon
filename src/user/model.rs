use mongodb::{
    Database,
    bson::{DateTime, Uuid},
    error::{ErrorKind as MdbErr, WriteFailure::WriteError},
};

use crate::{
    authentication::{Auth, Credentials, Token, VerificationToken},
    error::{Context, Error},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct User {
    _id: Uuid,
    auth: Auth,
    // application: Option<Application>,
    // team: Option<Uuid>,
}

impl User {
    /// Insert the (new) user to the database
    ///
    /// Returns the raw email verification token if the user has been created. Otherwise returns
    /// `None`
    ///
    /// # Errors
    /// Will return an error if an user with that email already exists
    ///
    /// May return an error if there's an issue communicating with the database
    pub async fn insert(
        &mut self,
        database: &Database,
        key: &[u8; 32],
    ) -> Result<Option<String>, Error> {
        let token = Token::new();

        // Keep the code on the database instead
        self.auth.email_verification_token = Some(VerificationToken {
            code: token.hmac(key),
            created_at: DateTime::now(),
        });

        let result = database.collection::<Self>("users").insert_one(self).await;

        // If the error MongoDB returns is a write faliure, it probably means there exists a user
        // with the given email. None is used to indicate everything went well but no user was created
        let result = match result {
            Ok(_) => Ok(Some(token.hex())),
            Err(err) => match *err.kind {
                MdbErr::Write(WriteError(_)) => Ok(None),
                _ => Err(err),
            },
        };

        result.context("Inserting new user to database")
    }
}

impl TryFrom<Credentials> for User {
    type Error = Error;

    /// Creates a new user from the given credentials
    fn try_from(value: Credentials) -> Result<Self, Self::Error> {
        Ok(Self {
            _id: Uuid::new(),
            auth: value
                .try_into()
                .context("Creating a user from Credentials")?,
        })
    }
}
