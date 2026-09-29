use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;

pub type HmacKey = [u8; 32];

/// A random token
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct Token {
    #[serde(deserialize_with = "deserialize_token")]
    token: [u8; 32],
}

impl Token {
    /// Creates a new random token
    #[must_use]
    pub fn new() -> Self {
        let mut token = Self { token: [0; 32] };

        rand::rng().fill_bytes(&mut token.token);

        token
    }

    /// Returns the token encoded as hex on a `String`.
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.token)
    }

    /// Returns the token's HMAC as hex on a `String`, given the HMAC key
    ///
    /// # Panics
    /// Should never painc unless the `hmac` dependency breaks and changes the sha256 key size
    #[must_use]
    pub fn hmac(&self, key: &HmacKey) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac dependency broke");
        mac.update(&self.token);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verifies if the given HMAC matches the token, given the HMAC key
    ///
    /// # Panics
    /// Should never painc unless the `hmac` dependency breaks and changes the sha256 key size
    #[must_use]
    pub fn verify(&self, hmac: &str, key: &HmacKey) -> bool {
        let Ok(hmac) = hex::decode(hmac) else {
            return false;
        };

        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac dependency broke");
        mac.update(&self.token);
        mac.verify_slice(&hmac[..]).is_ok()
    }
}

impl TryFrom<&str> for Token {
    type Error = hex::FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut token = Self { token: [0; 32] };

        hex::decode_to_slice(value, &mut token.token)?;

        Ok(token)
    }
}

impl Default for Token {
    fn default() -> Self {
        Self::new()
    }
}

/// Token deserializer
///
/// This is used to tokens can be sent via json as a hex encoded string instead of an array of
/// numbers
///
/// # Errors
/// Returns an error if the string isn't valid hex or if doesn't represent exacly 32 bytes.
fn deserialize_token<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::{Deserialize, de};

    let value = String::deserialize(deserializer)?;

    let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;

    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| de::Error::invalid_length(bytes.len(), &"exactly 32 bytes"))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct VerificationToken {
    pub code: String,
    pub created_at: mongodb::bson::DateTime,
}
