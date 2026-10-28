use std::fmt::Display;

use mongodb::{
    Database,
    bson::{DateTime, Uuid, doc},
};

use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};

use crate::{
    authentication::credentials::Credentials,
    authentication::{Token, deserialize_token, model::token::HmacKey},
    error::{Context, Error, ErrorKind},
    user::User,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(try_from = "String")]
#[into_params(names("password"))]
pub struct Password(pub String);

impl Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<String> for Password {
    type Error = Error;

    /// Converts a String into a Password
    ///
    /// A Password is just a String with these rules enforced:
    /// - Must be at least 12 characters
    /// - Must contain at least one lowercase letter
    /// - Must contain at least one uppercase letter
    /// - Must contain at least one number
    /// - Must contain at least one symbol
    ///
    /// Characters considered symbols:
    /// ```txt
    /// ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
    /// ```
    ///
    /// The bare minimum password that follows the requirements is considered to be of "decent"
    /// strength by current standards (as long as it isn't in a dictionary).
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut count = 0;
        let mut has_lowercase = false;
        let mut has_uppercase = false;
        let mut has_digit = false;
        let mut has_punctuation = false;

        for c in value.chars() {
            count += 1;

            if c.is_lowercase() {
                has_lowercase = true;
            } else if c.is_uppercase() {
                has_uppercase = true;
            } else if c.is_ascii_digit() {
                has_digit = true;
            } else if c.is_ascii_punctuation() {
                has_punctuation = true;
            }
        }

        if count < 12 {
            return Err(Error::new(
                ErrorKind::WeakPassword,
                "Passwords must be at least 12 characters".into(),
                "Checking password strength",
            ));
        }

        if !has_lowercase {
            return Err(Error::new(
                ErrorKind::WeakPassword,
                "The password must contain at least one lowercase letter".into(),
                "Checking password strength",
            ));
        }

        if !has_uppercase {
            return Err(Error::new(
                ErrorKind::WeakPassword,
                "The password must contain at least one uppercase letter".into(),
                "Checking password strength",
            ));
        }

        if !has_digit {
            return Err(Error::new(
                ErrorKind::WeakPassword,
                "The password must contain at least one number".into(),
                "Checking password strength",
            ));
        }

        if !has_punctuation {
            return Err(Error::new(
                ErrorKind::WeakPassword,
                "The password must contain at least one symbol".into(),
                "Checking password strength",
            ));
        }

        Ok(Self(value))
    }
}

impl<'de> serde::Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;

        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// Used to reset an account's password
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, utoipa::ToSchema, utoipa::IntoParams,
)]
#[schema(example = json!({
    "token": "f6551672a90f577ea24569c048076d322fce5679fdaa70cf0f82354d82bdf40b",
    "password": "Sup3r_5ecure_P4ssw0rd"
}))]
pub struct ResetForm {
    /// The reset token sent via email
    #[serde(deserialize_with = "deserialize_token")]
    pub token: [u8; 32],
    /// The new desired password
    pub new_password: Password,
}

impl ResetForm {
    /// Sets the new password and exhausts the reset token. Returns the user's ID
    ///
    /// # Errors
    /// Will return an error if there's an issue communicating with the database or hashing the password.
    pub async fn reset_password(&self, database: &Database, key: &HmacKey) -> Result<Uuid, Error> {
        let now = DateTime::now();
        let fresh_after = now.saturating_add_millis(-1000 * 60 * 30); // 30m ago

        let token = Token::from(self.token);

        let filter = doc! {
            "auth.password_reset_token.code": token.hmac(key),
            "auth.password_reset_token.created_at": doc! { "$gte": fresh_after },
        };

        let password = Argon2::default()
            .hash_password(
                self.new_password.0.as_bytes(),
                &SaltString::generate(&mut OsRng),
            )
            .context("Hashing password")?
            .to_string();

        let update = doc! {
            "$unset": doc! { "auth.password_reset_token": "" },
            "$set": doc! { "auth.password": password },
        };

        let user = database
            .collection::<User>("users")
            .find_one_and_update(filter, update)
            .await
            .context("Resetting password")?
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::EmailTokenNotFound,
                    "The token doesn't exist or is expired".into(),
                    "Resetting password via email",
                )
            })?;

        Ok(user.id())
    }
}

/// Used to change an account's password
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, utoipa::ToSchema, utoipa::IntoParams,
)]
pub struct ChangeForm {
    /// Current credentials for the user
    pub credentials: Credentials,
    /// The new desired password
    pub new_password: Password,
}

impl ChangeForm {
    /// Sets the new password
    ///
    /// # Errors
    /// Will return an error if there's an issue communicating with the database or hashing the password.
    ///
    /// Will also return an error if the credentials on the form evaluate to a correct user, but this
    /// user doesn't match the one the reset was requested from; or if the user magically stops existing
    /// right after the reset was requested
    pub async fn change_password(&self, user: Uuid, database: &Database) -> Result<(), Error> {
        let id = self
            .credentials
            .verify(database)
            .await
            .context("Verifying credentials")?;

        if user != id {
            log::warn!(
                "User [{user}] tried to change password with the correct credentials from user [{id}]"
            );
            return Err(Error::new(
                ErrorKind::InvalidCredentials,
                "Incorrect email or password".into(),
                "The credentials on the password reset form evaluate to a different user than the session this was called from",
            ));
        }

        let password = Argon2::default()
            .hash_password(
                self.new_password.0.as_bytes(),
                &SaltString::generate(&mut OsRng),
            )
            .context("Hashing password")?
            .to_string();

        let update = doc! {
            "$set": doc! { "auth.password": password },
        };

        let _ = database
            .collection::<User>("users")
            .find_one_and_update(doc! { "_id": id }, update)
            .await
            .context("Resetting password")?
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unexpected,
                    "Something went wrong while trying to change the password".into(),
                    "Changing password, the user suddenly doesn't exist",
                )
            })?;

        Ok(())
    }
}
