use mongodb::{Database, bson::Uuid, error::ErrorKind as MdbErr, error::WriteFailure::WriteError};

use crate::{
    authentication::{Auth, Credentials, Token},
    error::{Context, Error, ErrorKind::Unexpected},
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
        let Some(ref mut email_verification_token) = self.auth.email_verification_token else {
            return Err(Error::new(
                Unexpected,
                "Something unexpected happened".into(),
                "Getting email_verification_token from new user instance",
            ));
        };

        let token = Token::try_from(&email_verification_token.code[..])
            .context("Building token from String")?;

        email_verification_token.code = token.hmac(key);

        let result = database.collection::<Self>("users").insert_one(self).await;

        // If the error MongoDB returns is a write faliure, it probably means there exists a user
        // with the given email
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
            auth: value.try_into().context("meow")?,
        })
    }
}
