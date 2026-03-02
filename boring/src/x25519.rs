//! X25519 key wrappers built on top of [`crate::pkey::PKey`].

use crate::derive::Deriver;
use crate::error::ErrorStack;
use crate::pkey::{PKey, Private, Public};
use crate::rand::rand_bytes;

pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SHARED_SECRET_LENGTH: usize = 32;

/// An X25519 private key.
#[derive(Clone, Debug)]
pub struct X25519PrivateKey(PKey<Private>);

/// An X25519 public key.
#[derive(Clone, Debug)]
pub struct X25519PublicKey(PKey<Public>);

impl X25519PrivateKey {
    /// Generates a new X25519 private key.
    pub fn generate() -> Result<Self, ErrorStack> {
        let mut key = [0_u8; PRIVATE_KEY_LENGTH];
        rand_bytes(&mut key)?;
        Self::from_private_key_bytes(&key)
    }

    /// Constructs an X25519 private key from raw bytes.
    pub fn from_private_key_bytes(key: &[u8; PRIVATE_KEY_LENGTH]) -> Result<Self, ErrorStack> {
        PKey::from_x25519_private_key(key).map(Self)
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
                "unexpected X25519 private key length",
            ))
        }
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> Result<X25519PublicKey, ErrorStack> {
        let mut key = [0_u8; PUBLIC_KEY_LENGTH];
        let len = self.0.raw_public_key(&mut key)?.len();
        if len != PUBLIC_KEY_LENGTH {
            return Err(ErrorStack::internal_error_str(
                "unexpected X25519 public key length",
            ));
        }
        X25519PublicKey::from_public_key_bytes(&key)
    }

    /// Derives a shared secret with `peer_public_key`.
    pub fn derive_shared_secret(
        &self,
        peer_public_key: &X25519PublicKey,
    ) -> Result<[u8; SHARED_SECRET_LENGTH], ErrorStack> {
        let mut deriver = Deriver::new(&self.0)?;
        deriver.set_peer(&peer_public_key.0)?;
        let mut shared = [0_u8; SHARED_SECRET_LENGTH];
        let len = deriver.derive(&mut shared)?;
        if len == SHARED_SECRET_LENGTH {
            Ok(shared)
        } else {
            Err(ErrorStack::internal_error_str(
                "unexpected X25519 shared secret length",
            ))
        }
    }
}

impl X25519PublicKey {
    /// Constructs an X25519 public key from raw bytes.
    pub fn from_public_key_bytes(key: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, ErrorStack> {
        PKey::from_x25519_public_key(key).map(Self)
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
                "unexpected X25519 public key length",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_derive_smoke() {
        let private_key_a = X25519PrivateKey::generate().unwrap();
        let private_key_b = X25519PrivateKey::generate().unwrap();
        let public_key_a = private_key_a.public_key().unwrap();
        let public_key_b = private_key_b.public_key().unwrap();

        let shared_ab = private_key_a.derive_shared_secret(&public_key_b).unwrap();
        let shared_ba = private_key_b.derive_shared_secret(&public_key_a).unwrap();

        assert_eq!(shared_ab, shared_ba);
        assert_ne!(shared_ab, [0_u8; SHARED_SECRET_LENGTH]);
    }
}
