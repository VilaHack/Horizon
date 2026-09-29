use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};

use mongodb::{
    Database,
    bson::{DateTime, doc},
};

use crate::{
    authentication::{Credentials, Scope, Token, VerificationToken, model::token::HmacKey},
    error::{Context, Error, ErrorKind},
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

impl Auth {
    /// Verifies an account from an token received via email
    ///
    /// # Errors
    /// No unhappy paths. Will only return an error if the token doesn't exist or is expired.
    pub async fn verify_email(
        token: &Token,
        database: &Database,
        key: HmacKey,
    ) -> Result<(), Error> {
        let now = DateTime::now();
        let fresh_after = now.saturating_add_millis(-1000 * 60 * 30); // 30m ago

        let filter = doc! {
            "auth.email_verification_token.code": token.hmac(&key),
            "auth.email_verification_token.created_at": doc! { "$gte": fresh_after },
        };

        let update = doc! {
            "$set": doc! { "auth.email_verified": true },
            "$unset": doc! { "auth.email_verification_token": "" },
        };

        let result = database
            .collection::<Self>("users")
            .update_one(filter, update)
            .await?;

        if result.matched_count == 0 {
            return Err(Error::new(
                ErrorKind::EmailTokenNotFound,
                String::from("The token doesn't exist or is expired"),
                "Verifying an account via email",
            ));
        }

        Ok(())
    }
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

        Ok(Self {
            email: value.email,
            password,
            email_verified: false,
            created_at: DateTime::now(),
            scopes: Vec::with_capacity(0),
            email_verification_token: None,
            password_reset_token: None,
        })
    }
}
