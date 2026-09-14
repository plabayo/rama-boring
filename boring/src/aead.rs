//! Authenticated encryption with reusable keys.
use crate::{cvt, error::ErrorStack, ffi};
use std::{fmt, ptr::NonNull};

/// AEADs with a 96-bit nonce and a 128-bit authentication tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    fn as_ptr(self) -> *const ffi::EVP_AEAD {
        unsafe {
            match self {
                Self::Aes128Gcm => ffi::EVP_aead_aes_128_gcm(),
                Self::Aes256Gcm => ffi::EVP_aead_aes_256_gcm(),
                Self::ChaCha20Poly1305 => ffi::EVP_aead_chacha20_poly1305(),
            }
        }
    }
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            _ => 32,
        }
    }
}

/// A prepared AEAD key. Nonces must never repeat for encryption with one key.
pub struct AeadKey(NonNull<ffi::EVP_AEAD_CTX>);

// EVP_AEAD_CTX explicitly permits concurrent seal/open operations.
unsafe impl Send for AeadKey {}
unsafe impl Sync for AeadKey {}
impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKey")
    }
}
impl Drop for AeadKey {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_AEAD_CTX_free(self.0.as_ptr());
        }
    }
}
impl AeadKey {
    pub fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self, ErrorStack> {
        ffi::init();
        let ptr = unsafe { ffi::EVP_AEAD_CTX_new(algorithm.as_ptr(), key.as_ptr(), key.len(), 16) };
        NonNull::new(ptr).map(Self).ok_or_else(ErrorStack::get)
    }

    /// Encrypt in place. The last 16 bytes of `buffer` are reserved for the tag.
    pub fn seal_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), ErrorStack> {
        let Some(input_len) = buffer.len().checked_sub(16) else {
            return Err(ErrorStack::get());
        };
        let mut len = 0;
        unsafe {
            cvt(ffi::EVP_AEAD_CTX_seal(
                self.0.as_ptr(),
                buffer.as_mut_ptr(),
                &mut len,
                buffer.len(),
                nonce.as_ptr(),
                nonce.len(),
                buffer.as_ptr(),
                input_len,
                aad.as_ptr(),
                aad.len(),
            ))?;
        }
        Ok(())
    }

    /// Authenticate and decrypt in place, returning the plaintext prefix.
    pub fn open_in_place<'a>(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a mut [u8], ErrorStack> {
        let mut len = 0;
        unsafe {
            cvt(ffi::EVP_AEAD_CTX_open(
                self.0.as_ptr(),
                buffer.as_mut_ptr(),
                &mut len,
                buffer.len(),
                nonce.as_ptr(),
                nonce.len(),
                buffer.as_ptr(),
                buffer.len(),
                aad.as_ptr(),
                aad.len(),
            ))?;
        }
        Ok(&mut buffer[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_vectors_and_authentication_failures() {
        // BoringSSL crypto/cipher/test vectors.
        for (algorithm, key, nonce, plaintext, aad, sealed) in [
            (
                Algorithm::Aes128Gcm,
                "3881e7be1bb3bbcaff20bdb78e5d1b67",
                "dcf5b7ae2d7552e2297fcfa9",
                "0a2714aa7d",
                "c60c64bbf7",
                "5626f96ecbff4c4f1d92b0abb1d0820833d9eb83c7",
            ),
            (
                Algorithm::Aes256Gcm,
                "73ad7bbbbc640c845a150f67d058b279849370cd2c1f3c67c4dd6c869213e13a",
                "a330a184fc245812f4820caa",
                "f0535fe211",
                "e91428be04",
                "e9b8a896da9115ed79f26a030c14947b3e454db9e7",
            ),
            (
                Algorithm::ChaCha20Poly1305,
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "070000004041424344454647",
                "31323334353637383961626364656630",
                "31",
                "ae49da6934cb77822c83ed9852e46c9edac9c841c168379dcf8f2bb8e22d6da2",
            ),
        ] {
            let key = AeadKey::new(algorithm, &hex::decode(key).unwrap()).unwrap();
            let nonce = hex::decode(nonce).unwrap().try_into().unwrap();
            let plaintext = hex::decode(plaintext).unwrap();
            let aad = hex::decode(aad).unwrap();
            let expected = hex::decode(sealed).unwrap();
            let mut ciphertext = plaintext.clone();
            ciphertext.resize(plaintext.len() + 16, 0);
            key.seal_in_place(&nonce, &aad, &mut ciphertext).unwrap();
            assert_eq!(ciphertext, expected);
            assert_eq!(
                key.open_in_place(&nonce, &aad, &mut ciphertext).unwrap(),
                plaintext
            );
            for offset in 0..expected.len() {
                let mut corrupted = expected.clone();
                corrupted[offset] ^= 1;
                assert!(key.open_in_place(&nonce, &aad, &mut corrupted).is_err());
            }
            assert!(key
                .open_in_place(&nonce, b"wrong aad", &mut expected.clone())
                .is_err());
            assert!(key.seal_in_place(&nonce, &aad, &mut [0; 15]).is_err());
            assert!(AeadKey::new(algorithm, &[0; 1]).is_err());
        }
    }
}
