use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use mongodb::bson::DateTime;

use crate::{
    authentication::{Credentials, Scope, Token},
    error::{Context, Error},
};

/// Represents a user's authentication details, as stored on the database
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Auth {
    pub email: String,
    pub password: String,
    pub email_verified: bool,
    pub created_at: DateTime,
    pub scopes: Vec<Scope>,
    pub email_verification_token: Option<VerificationToken>,
    pub password_reset_token: Option<VerificationToken>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct VerificationToken {
    pub code: String,
    pub created_at: DateTime,
}

impl TryFrom<Credentials> for Auth {
    type Error = Error;

    /// Creates a new Auth subdocument from the credentials
    ///
    /// **Important!** the `email_verification_token` is the raw value, not the hmac, it has to get
    /// replaced!
    fn try_from(value: Credentials) -> Result<Self, Self::Error> {
        let password = Argon2::default()
            .hash_password(value.password.as_bytes(), &SaltString::generate(&mut OsRng))
            .context("Hashing password")?
            .to_string();

        let token = Token::new();

        Ok(Self {
            email: value.email,
            password,
            email_verified: false,
            created_at: DateTime::now(),
            scopes: Vec::with_capacity(0),
            email_verification_token: Some(VerificationToken {
                code: token.hex(),
                created_at: DateTime::now(),
            }),
            password_reset_token: None,
        })
    }
}
