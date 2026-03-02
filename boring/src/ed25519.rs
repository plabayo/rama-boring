//! Ed25519 key wrappers built on top of [`crate::pkey::PKey`].

use crate::error::ErrorStack;
use crate::pkey::{PKey, Private, Public};
use crate::rand::rand_bytes;
use crate::sign::{Signer, Verifier};

pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

/// An Ed25519 private key.
#[derive(Clone, Debug)]
pub struct Ed25519PrivateKey(PKey<Private>);

/// An Ed25519 public key.
#[derive(Clone, Debug)]
pub struct Ed25519PublicKey(PKey<Public>);

impl Ed25519PrivateKey {
    /// Generates a new Ed25519 private key.
    pub fn generate() -> Result<Self, ErrorStack> {
        let mut key = [0_u8; PRIVATE_KEY_LENGTH];
        rand_bytes(&mut key)?;
        Self::from_private_key_bytes(&key)
    }

    /// Constructs an Ed25519 private key from raw bytes.
    pub fn from_private_key_bytes(key: &[u8; PRIVATE_KEY_LENGTH]) -> Result<Self, ErrorStack> {
        PKey::from_ed25519_private_key(key).map(Self)
    }

    /// Returns the underlying `PKey`.
    #[must_use]
    pub fn as_pkey(&self) -> &PKey<Private> {
        &self.0
    }

    /// Returns the private key in raw form.
    pub fn private_key_bytes(&self) -> Result<[u8; PRIVATE_KEY_LENGTH], ErrorStack> {
        let mut key = [0_u8; PRIVATE_KEY_LENGTH];
        let len = self.0.raw_private_key(&mut key)?.len();
        if len == PRIVATE_KEY_LENGTH {
            Ok(key)
        } else {
            Err(ErrorStack::internal_error_str(
                "unexpected Ed25519 private key length",
            ))
        }
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> Result<Ed25519PublicKey, ErrorStack> {
        let mut key = [0_u8; PUBLIC_KEY_LENGTH];
        let len = self.0.raw_public_key(&mut key)?.len();
        if len != PUBLIC_KEY_LENGTH {
            return Err(ErrorStack::internal_error_str(
                "unexpected Ed25519 public key length",
            ));
        }
        Ed25519PublicKey::from_public_key_bytes(&key)
    }

    /// Signs `message` with Ed25519.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LENGTH], ErrorStack> {
        let mut signer = Signer::new_without_digest(&self.0)?;
        let mut signature = [0_u8; SIGNATURE_LENGTH];
        let len = signer.sign_oneshot(&mut signature, message)?;
        if len == SIGNATURE_LENGTH {
            Ok(signature)
        } else {
            Err(ErrorStack::internal_error_str(
                "unexpected Ed25519 signature length",
            ))
        }
    }
}

impl Ed25519PublicKey {
    /// Constructs an Ed25519 public key from raw bytes.
    pub fn from_public_key_bytes(key: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, ErrorStack> {
        PKey::from_ed25519_public_key(key).map(Self)
    }

    /// Returns the underlying `PKey`.
    #[must_use]
    pub fn as_pkey(&self) -> &PKey<Public> {
        &self.0
    }

    /// Returns the public key in raw form.
    pub fn public_key_bytes(&self) -> Result<[u8; PUBLIC_KEY_LENGTH], ErrorStack> {
        let mut key = [0_u8; PUBLIC_KEY_LENGTH];
        let len = self.0.raw_public_key(&mut key)?.len();
        if len == PUBLIC_KEY_LENGTH {
            Ok(key)
        } else {
            Err(ErrorStack::internal_error_str(
                "unexpected Ed25519 public key length",
            ))
        }
    }

    /// Verifies `signature` for `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
        let mut verifier = Verifier::new_without_digest(&self.0)?;
        verifier.verify_oneshot(signature, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify_smoke() {
        let private_key = Ed25519PrivateKey::generate().unwrap();
        let public_key = private_key.public_key().unwrap();
        let message = b"rama-ed25519-smoke";
        let signature = private_key.sign(message).unwrap();
        assert!(public_key.verify(message, &signature).unwrap());
        assert!(!public_key
            .verify(b"rama-ed25519-smoke-tampered", &signature)
            .unwrap());
    }
}
