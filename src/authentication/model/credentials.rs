use mongodb::{
    Database,
    bson::{Uuid, doc},
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};

use crate::error::{Context, Error, ErrorKind};

/// Represents a user's login credentials
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, utoipa::ToSchema, utoipa::IntoParams,
)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

#[derive(Debug, serde::Deserialize)]
struct AuthProjection {
    #[serde(rename = "password")]
    password_hash: String,
}

#[derive(Debug, serde::Deserialize)]
struct UserProjection {
    #[serde(rename = "_id")]
    id: Uuid,

    auth: AuthProjection,
}

impl Credentials {
    /// Returns the `Uuid` of the user the credentials belong to.
    ///
    /// # Errors
    /// Will return an error if the credentials don't belong to any user
    ///
    /// May return an error if there's an issue communicating with the database
    pub async fn verify(&self, database: &Database) -> Result<Uuid, Error> {
        let projected_user = database
            .collection::<UserProjection>("users")
            .find_one(doc! { "auth.email": &self.email })
            .projection(doc! { "_id": 1, "auth.password": 1, })
            .await
            .context("Getting a user's password hash")?;

        let Some(UserProjection {
            id,
            auth: AuthProjection { password_hash },
        }) = projected_user
        else {
            return Err(Error::new(
                ErrorKind::InvalidCredentials,
                "Incorrect email or password".into(),
                "Getting a password hash, user doesn't exist",
            ));
        };

        Argon2::default()
            .verify_password(
                self.password.as_bytes(),
                &PasswordHash::new(&password_hash)?,
            )
            .context("Verifying password")?;

        // By this point the password has been verified to be correct.

        Ok(id)
    }
}
