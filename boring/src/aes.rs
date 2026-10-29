//! Low level AES IGE and key wrapping functionality
//!
//! AES ECB, CBC, XTS, CTR, CFB, GCM and other conventional symmetric encryption
//! modes are found in [`symm`].  This is the implementation of AES IGE and key wrapping
//!
//! Advanced Encryption Standard (AES) provides symmetric key cipher that
//! the same key is used to encrypt and decrypt data.  This implementation
//! uses 128, 192, or 256 bit keys.  This module provides functions to
//! create a new key with [`new_encrypt`].
//!
//! [`new_encrypt`]: struct.AesKey.html#method.new_encrypt
//!
//! The [`symm`] module should be used in preference to this module in most cases.
//! The IGE block cypher is a non-traditional cipher mode.  More traditional AES
//! encryption methods are found in the [`Crypter`] and [`Cipher`] structs.
//!
//! [`symm`]: ../symm/index.html
//! [`Crypter`]: ../symm/struct.Crypter.html
//! [`Cipher`]: ../symm/struct.Cipher.html
//!
//! # Examples
//!
//! ## Key wrapping
//! ```rust
//! use rama_boring::aes::{AesKey, unwrap_key, wrap_key};
//!
//! let kek = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//! let key_to_wrap = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
//!
//! let enc_key = AesKey::new_encrypt(kek).unwrap();
//! let mut ciphertext = [0u8; 24];
//! wrap_key(&enc_key, None, &mut ciphertext, &key_to_wrap[..]).unwrap();
//! let dec_key = AesKey::new_decrypt(kek).unwrap();
//! let mut orig_key = [0u8; 16];
//! unwrap_key(&dec_key, None, &mut orig_key, &ciphertext[..]).unwrap();
//!
//! assert_eq!(&orig_key[..], &key_to_wrap[..]);
//! ```
//!
use crate::ffi;
use crate::libc_types::c_int;
use openssl_macros::corresponds;
use std::mem::MaybeUninit;
use std::ptr;

/// Provides Error handling for parsing keys.
#[derive(Debug)]
pub struct KeyError(());

/// The key used to encrypt or decrypt cipher blocks.
pub struct AesKey(ffi::AES_KEY);

/// An encryption-only AES key schedule, erased when dropped.
/// This primitive provides no authentication or message framing.
pub struct AesEncryptKey(AesKey);

impl AesEncryptKey {
    pub fn new(key: &[u8]) -> Result<Self, KeyError> {
        AesKey::new_encrypt(key).map(Self)
    }

    /// Encrypt exactly one block with the prepared encryption schedule.
    pub fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut output = [0; 16];
        unsafe {
            ffi::AES_encrypt(input.as_ptr(), output.as_mut_ptr(), &self.0 .0);
        }
        output
    }
}

impl Drop for AesEncryptKey {
    fn drop(&mut self) {
        unsafe {
            ffi::OPENSSL_cleanse(
                std::ptr::addr_of_mut!(self.0 .0).cast(),
                std::mem::size_of::<ffi::AES_KEY>(),
            );
        }
    }
}

impl AesKey {
    /// Prepares a key for encryption.
    ///
    /// # Failure
    ///
    /// Returns an error if the key is not 128, 192, or 256 bits.
    #[corresponds(AES_set_encrypt_key)]
    pub fn new_encrypt(key: &[u8]) -> Result<AesKey, KeyError> {
        unsafe {
            assert!(key.len() <= c_int::MAX as usize / 8);

            // SAFETY: `AES_set_encrypt_key` only writes the `4 * (rounds + 1)`
            // round-key words it needs (44 for AES-128, 52 for AES-192), so the
            // schedule starts zeroed: every byte of `AES_KEY` is then
            // initialized and `assume_init` below is valid for its integer fields.
            let mut aes_key = MaybeUninit::<ffi::AES_KEY>::zeroed();
            let r = ffi::AES_set_encrypt_key(
                key.as_ptr(),
                (key.len() * 8).try_into().map_err(|_| KeyError(()))?,
                aes_key.as_mut_ptr(),
            );
            if r == 0 {
                Ok(AesKey(aes_key.assume_init()))
            } else {
                Err(KeyError(()))
            }
        }
    }

    /// Prepares a key for decryption.
    ///
    /// # Failure
    ///
    /// Returns an error if the key is not 128, 192, or 256 bits.
    #[corresponds(AES_set_decrypt_key)]
    pub fn new_decrypt(key: &[u8]) -> Result<AesKey, KeyError> {
        unsafe {
            assert!(key.len() <= c_int::MAX as usize / 8);

            // SAFETY: zeroed for the same reason as in `new_encrypt`.
            let mut aes_key = MaybeUninit::<ffi::AES_KEY>::zeroed();
            let r = ffi::AES_set_decrypt_key(
                key.as_ptr(),
                (key.len() * 8).try_into().map_err(|_| KeyError(()))?,
                aes_key.as_mut_ptr(),
            );

            if r == 0 {
                Ok(AesKey(aes_key.assume_init()))
            } else {
                Err(KeyError(()))
            }
        }
    }
}

/// Wrap a key, according to [RFC 3394](https://tools.ietf.org/html/rfc3394)
///
/// * `key`: The key-encrypting-key to use. Must be a encrypting key
/// * `iv`: The IV to use. You must use the same IV for both wrapping and unwrapping
/// * `out`: The output buffer to store the ciphertext
/// * `in_`: The input buffer, storing the key to be wrapped
///
/// Returns the number of bytes written into `out`
///
/// # Panics
///
/// Panics if either `out` or `in_` do not have sizes that are a multiple of 8, or if
/// `out` is not 8 bytes longer than `in_`
#[corresponds(AES_wrap_key)]
pub fn wrap_key(
    key: &AesKey,
    iv: Option<[u8; 8]>,
    out: &mut [u8],
    in_: &[u8],
) -> Result<usize, KeyError> {
    unsafe {
        assert!(out.len() >= in_.len() + 8); // Ciphertext is 64 bits longer (see 2.2.1)

        let written = ffi::AES_wrap_key(
            std::ptr::addr_of!(key.0),
            iv.as_ref().map_or(ptr::null(), |iv| iv.as_ptr()),
            out.as_mut_ptr(),
            in_.as_ptr(),
            in_.len(),
        );
        if written <= 0 {
            Err(KeyError(()))
        } else {
            Ok(written as usize)
        }
    }
}

/// Unwrap a key, according to [RFC 3394](https://tools.ietf.org/html/rfc3394)
///
/// * `key`: The key-encrypting-key to decrypt the wrapped key. Must be a decrypting key
/// * `iv`: The same IV used for wrapping the key
/// * `out`: The buffer to write the unwrapped key to
/// * `in_`: The input ciphertext
///
/// Returns the number of bytes written into `out`
///
/// # Panics
///
/// Panics if `in_` is shorter than 8 bytes or if `out` is shorter than
/// `in_.len() - 8` bytes.
#[corresponds(AES_unwrap_key)]
pub fn unwrap_key(
    key: &AesKey,
    iv: Option<[u8; 8]>,
    out: &mut [u8],
    in_: &[u8],
) -> Result<usize, KeyError> {
    // `AES_unwrap_key` writes `in_len - 8` bytes to `out` on success.
    assert!(in_.len() >= 8 && out.len() >= in_.len() - 8);

    // SAFETY: `AES_unwrap_key` reads `in_len` bytes from `in_` and, by the
    // assert above, `out` has room for the `in_len - 8` bytes it writes. `out`
    // is derived from `as_mut_ptr`, so the write goes through a unique borrow.
    // `iv` is either null or points to the 8 bytes of the local array.
    let written = unsafe {
        ffi::AES_unwrap_key(
            std::ptr::addr_of!(key.0),
            iv.as_ref().map_or(ptr::null(), |iv| iv.as_ptr().cast()),
            out.as_mut_ptr(),
            in_.as_ptr().cast(),
            in_.len(),
        )
    };

    if written <= 0 {
        Err(KeyError(()))
    } else {
        Ok(written as usize)
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;

    #[test]
    fn encrypt_block_known_answers() {
        let block = <[u8; 16]>::from_hex("00112233445566778899aabbccddeeff").unwrap();
        for (key, expected) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let key = AesEncryptKey::new(&Vec::from_hex(key).unwrap()).unwrap();
            assert_eq!(
                key.encrypt_block(&block),
                <[u8; 16]>::from_hex(expected).unwrap()
            );
            assert_eq!(
                key.encrypt_block(&block),
                <[u8; 16]>::from_hex(expected).unwrap()
            );
        }
        assert!(AesEncryptKey::new(&[0; 15]).is_err());
    }

    // from the RFC https://tools.ietf.org/html/rfc3394#section-2.2.3
    #[test]
    fn test_wrap_unwrap() {
        let raw_key = Vec::from_hex("000102030405060708090A0B0C0D0E0F").unwrap();
        let key_data = Vec::from_hex("00112233445566778899AABBCCDDEEFF").unwrap();
        let expected_ciphertext =
            Vec::from_hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();

        let enc_key = AesKey::new_encrypt(&raw_key).unwrap();
        let mut wrapped = [0; 24];
        assert_eq!(
            wrap_key(&enc_key, None, &mut wrapped, &key_data).unwrap(),
            24
        );
        assert_eq!(&wrapped[..], &expected_ciphertext[..]);

        let dec_key = AesKey::new_decrypt(&raw_key).unwrap();
        let mut unwrapped = [0; 16];
        assert_eq!(
            unwrap_key(&dec_key, None, &mut unwrapped, &wrapped).unwrap(),
            16
        );
        assert_eq!(&unwrapped[..], &key_data[..]);
    }

    #[test]
    #[should_panic]
    fn unwrap_key_rejects_short_output() {
        let raw_key = [7u8; 32];
        let enc_key = AesKey::new_encrypt(&raw_key).unwrap();
        let mut wrapped = [0; 24];
        wrap_key(&enc_key, None, &mut wrapped, &[0x42; 16]).unwrap();

        // 16 bytes would be written; a 1-byte output must be refused before
        // any native code runs.
        let dec_key = AesKey::new_decrypt(&raw_key).unwrap();
        let mut output = [0xaa; 32];
        let _ = unwrap_key(&dec_key, None, &mut output[..1], &wrapped);
    }

    #[test]
    #[should_panic]
    fn unwrap_key_rejects_input_shorter_than_iv() {
        let dec_key = AesKey::new_decrypt(&[7u8; 16]).unwrap();
        let _ = unwrap_key(&dec_key, None, &mut [], &[0; 4]);
    }

    #[test]
    fn unwrap_key_accepts_larger_output() {
        let raw_key = [7u8; 24];
        let enc_key = AesKey::new_encrypt(&raw_key).unwrap();
        let mut wrapped = [0; 24];
        wrap_key(&enc_key, None, &mut wrapped, &[0x42; 16]).unwrap();

        let dec_key = AesKey::new_decrypt(&raw_key).unwrap();
        let mut output = [0xaa; 32];
        assert_eq!(
            unwrap_key(&dec_key, None, &mut output, &wrapped).unwrap(),
            16
        );
        assert_eq!(output[..16], [0x42; 16]);
        assert_eq!(output[16..], [0xaa; 16]);
    }

    #[test]
    fn short_key_schedules_are_fully_initialized() {
        // AES-128/192 schedules use fewer than the 60 round-key words in
        // `AES_KEY`; the unused tail must still be initialized (zero).
        for (len, used) in [(16, 44), (24, 52)] {
            for key in [
                AesKey::new_encrypt(&vec![7; len]).unwrap(),
                AesKey::new_decrypt(&vec![7; len]).unwrap(),
            ] {
                assert!(key.0.rd_key[used..].iter().all(|w| *w == 0));
            }
        }
    }
}
