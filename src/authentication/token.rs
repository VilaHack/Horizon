use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;

pub type HmacKey = [u8; 32];

/// A random token
pub struct Token {
    token: [u8; 32],
}

impl Token {
    /// Creates a new random token
    pub fn new() -> Self {
        let mut token = Self { token: [0; 32] };

        rand::rng().fill_bytes(&mut token.token);

        token
    }

    /// Returns the token encoded as hex on a `String`.
    pub fn hex(&self) -> String {
        hex::encode(self.token)
    }

    /// Returns the token's HMAC as hex on a `String`, given the HMAC key
    pub fn hmac(&self, key: &HmacKey) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac dependency broke");
        mac.update(&self.token);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verifies if the given HMAC matches the token, given the HMAC key
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
