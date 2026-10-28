use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};

use mongodb::{
    Database,
    bson::{DateTime, doc},
};

use crate::{
    authentication::{
        Token, VerificationToken, credentials::Credentials, model::token::HmacKey, session::Scope,
    },
    email,
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
        key: &HmacKey,
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
            .await
            .context("Setting email as verified")?;

        if result.matched_count == 0 {
            return Err(Error::new(
                ErrorKind::EmailTokenNotFound,
                String::from("The token doesn't exist or is expired"),
                "Verifying an account via email",
            ));
        }

        Ok(())
    }

    /// Set a new password reset token for the user with the given email
    ///
    /// Technically this can leak information on which users exist on the platform?
    /// In the 1 minute time window after an user has requested a password reset, an attacker could
    /// run an enumeration attack and find that user. Frankly I'm not sure how worried I should be
    /// about this
    ///
    /// # Errors
    /// Will return an error if there's an issue communicating with the database.
    /// Will also return an error if it is called while a token created less than a minute ago exists.
    pub async fn new_password_reset_token(
        email: email::Address,
        database: &Database,
        key: &HmacKey,
    ) -> Result<Option<Token>, Error> {
        let token = Token::new();
        let now = DateTime::now();
        let one_minute_ago = now.saturating_add_millis(-1000 * 60); // 1m ago

        // No more than one token per minute can be generated
        let token_is_too_recent = doc! {
            "auth.email": &email.email,
            "auth.password_reset_token.created_at": { "$gt": one_minute_ago },
        };

        if database
            .collection::<Self>("users")
            .find_one(token_is_too_recent)
            .await
            .context("Checking for a recent password reset token")?
            .is_some()
        {
            return Err(Error::new(
                ErrorKind::EmailRequestTooSoon,
                String::from("A password reset was requested too soon. Try again in a minute"),
                "Setting a new password reset token",
            ));
        }

        let filter = doc! {
            "auth.email": &email.email,
            "$or": [
                { "auth.password_reset_token.created_at": { "$lte": one_minute_ago } },
                { "auth.password_reset_token.created_at": { "$exists": false } },
            ],
        };

        let set_new_token = doc! {
            "$set": {
                "auth.password_reset_token": {
                    "code": token.hmac(&key),
                    "created_at": now,
                }
            }
        };

        if database
            .collection::<Self>("users")
            .update_one(filter, set_new_token)
            .await
            .context("Setting a new password reset token")?
            .matched_count
            == 1
        {
            return Ok(Some(token));
        }

        Ok(None)
    }

    /// Set a new email verification token for the user with the given email
    ///
    /// Same leak possible here as with the new_password_reset_token method
    ///
    /// # Errors
    /// Will return an error if there's an issue communicating with the database.
    /// Will also return an error if it is called while a token created less than a minute ago exists.
    pub async fn new_email_verification_token(
        email: email::Address,
        database: &Database,
        key: &HmacKey,
    ) -> Result<Option<Token>, Error> {
        let token = Token::new();
        let now = DateTime::now();
        let one_minute_ago = now.saturating_add_millis(-1000 * 60); // 1m ago

        // No more than one token per minute can be generated
        let token_is_too_recent = doc! {
            "auth.email": &email.email,
            "auth.email_verification_token.created_at": { "$gt": one_minute_ago },
        };

        if database
            .collection::<Self>("users")
            .find_one(token_is_too_recent)
            .await
            .context("Checking for a recent password reset token")?
            .is_some()
        {
            return Err(Error::new(
                ErrorKind::EmailRequestTooSoon,
                String::from("A password reset was requested too soon. Try again in a minute"),
                "Setting a new password reset token",
            ));
        }

        let filter = doc! {
            "auth.email": &email.email,
            "$or": [
                { "auth.email_verification_token.created_at": { "$lte": one_minute_ago } },
                { "auth.email_verification_token.created_at": { "$exists": false } },
            ],
        };

        let set_new_token = doc! {
            "$set": {
                "auth.email_verification_token": {
                    "code": token.hmac(&key),
                    "created_at": now,
                }
            }
        };

        if database
            .collection::<Self>("users")
            .update_one(filter, set_new_token)
            .await
            .context("Setting a new password reset token")?
            .matched_count
            == 1
        {
            return Ok(Some(token));
        }

        Ok(None)
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
            .hash_password(
                value.password.0.as_bytes(),
                &SaltString::generate(&mut OsRng),
            )
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
