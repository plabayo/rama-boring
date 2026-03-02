//! Public/private key processing.
//!
//! Asymmetric public key algorithms solve the problem of establishing and sharing
//! secret keys to securely send and receive messages.
//! This system uses a pair of keys: a public key, which can be freely
//! distributed, and a private key, which is kept to oneself. An entity may
//! encrypt information using a user's public key. The encrypted information can
//! only be deciphered using that user's private key.
//!
//! This module offers support for five popular algorithms:
//!
//! * RSA
//!
//! * DSA
//!
//! * Diffie-Hellman
//!
//! * Elliptic Curves
//!
//! * HMAC
//!
//! These algorithms rely on hard mathematical problems - namely integer factorization,
//! discrete logarithms, and elliptic curve relationships - that currently do not
//! yield efficient solutions. This property ensures the security of these
//! cryptographic algorithms.
//!
//! # Example
//!
//! Generate a 2048-bit RSA public/private key pair and print the public key.
//!
//! ```rust
//! use rama_boring::rsa::Rsa;
//! use rama_boring::pkey::PKey;
//! use std::str;
//!
//! let rsa = Rsa::generate(2048).unwrap();
//! let pkey = PKey::from_rsa(rsa).unwrap();
//!
//! let pub_key: Vec<u8> = pkey.public_key_to_pem().unwrap();
//! println!("{:?}", str::from_utf8(pub_key.as_slice()).unwrap());
//! ```

use crate::ffi;
use crate::libc_types::{c_int, c_long};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::ffi::CString;
use std::fmt;
use std::mem;
use std::ptr;

use crate::bio::MemBioSlice;
use crate::dh::Dh;
use crate::dsa::Dsa;
use crate::ec::EcKey;
use crate::error::ErrorStack;
use crate::rsa::Rsa;
use crate::util::{invoke_passwd_cb, CallbackState};
use crate::{cvt, cvt_0i, cvt_p};

/// A tag type indicating that a key only has parameters.
pub enum Params {}

/// A tag type indicating that a key only has public components.
pub enum Public {}

/// A tag type indicating that a key has private components.
pub enum Private {}

/// An identifier of a kind of key.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Id(c_int);

impl Id {
    pub const RSA: Id = Id(ffi::EVP_PKEY_RSA);
    pub const RSAPSS: Id = Id(ffi::EVP_PKEY_RSA_PSS);
    pub const DSA: Id = Id(ffi::EVP_PKEY_DSA);
    pub const DH: Id = Id(ffi::EVP_PKEY_DH);
    pub const EC: Id = Id(ffi::EVP_PKEY_EC);
    pub const ED25519: Id = Id(ffi::EVP_PKEY_ED25519);
    pub const ED448: Id = Id(ffi::EVP_PKEY_ED448);
    pub const X25519: Id = Id(ffi::EVP_PKEY_X25519);
    pub const X448: Id = Id(ffi::EVP_PKEY_X448);

    /// Creates a `Id` from an integer representation.
    #[must_use]
    pub fn from_raw(value: c_int) -> Id {
        Id(value)
    }

    /// Returns the integer representation of the `Id`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[must_use]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

/// A trait indicating that a key has parameters.
#[allow(clippy::missing_safety_doc)]
pub unsafe trait HasParams {}

unsafe impl HasParams for Params {}

unsafe impl<T> HasParams for T where T: HasPublic {}

/// A trait indicating that a key has public components.
#[allow(clippy::missing_safety_doc)]
pub unsafe trait HasPublic {}

unsafe impl HasPublic for Public {}

unsafe impl<T> HasPublic for T where T: HasPrivate {}

/// A trait indicating that a key has private components.
#[allow(clippy::missing_safety_doc)]
pub unsafe trait HasPrivate {}

unsafe impl HasPrivate for Private {}

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_PKEY;
    fn drop = ffi::EVP_PKEY_free;

    /// A public or private key.
    pub struct PKey<T>;
    /// Reference to [`PKey`].
    pub struct PKeyRef<T>;
}

impl<T> ToOwned for PKeyRef<T> {
    type Owned = PKey<T>;

    fn to_owned(&self) -> PKey<T> {
        unsafe {
            EVP_PKEY_up_ref(self.as_ptr());
            PKey::from_ptr(self.as_ptr())
        }
    }
}

impl<T> PKeyRef<T> {
    /// Returns a copy of the internal RSA key.
    #[corresponds(EVP_PKEY_get1_RSA)]
    pub fn rsa(&self) -> Result<Rsa<T>, ErrorStack> {
        unsafe {
            let rsa = cvt_p(ffi::EVP_PKEY_get1_RSA(self.as_ptr()))?;
            Ok(Rsa::from_ptr(rsa))
        }
    }

    /// Returns a copy of the internal DSA key.
    #[corresponds(EVP_PKEY_get1_DSA)]
    pub fn dsa(&self) -> Result<Dsa<T>, ErrorStack> {
        unsafe {
            let dsa = cvt_p(ffi::EVP_PKEY_get1_DSA(self.as_ptr()))?;
            Ok(Dsa::from_ptr(dsa))
        }
    }

    /// Returns a copy of the internal DH key.
    #[corresponds(EVP_PKEY_get1_DH)]
    pub fn dh(&self) -> Result<Dh<T>, ErrorStack> {
        unsafe {
            let dh = cvt_p(ffi::EVP_PKEY_get1_DH(self.as_ptr()))?;
            Ok(Dh::from_ptr(dh))
        }
    }

    /// Returns a copy of the internal elliptic curve key.
    #[corresponds(EVP_PKEY_get1_EC_KEY)]
    pub fn ec_key(&self) -> Result<EcKey<T>, ErrorStack> {
        unsafe {
            let ec_key = cvt_p(ffi::EVP_PKEY_get1_EC_KEY(self.as_ptr()))?;
            Ok(EcKey::from_ptr(ec_key))
        }
    }

    /// Returns the `Id` that represents the type of this key.
    #[corresponds(EVP_PKEY_id)]
    #[must_use]
    pub fn id(&self) -> Id {
        unsafe { Id::from_raw(ffi::EVP_PKEY_id(self.as_ptr())) }
    }

    /// Returns the maximum size of a signature in bytes.
    #[corresponds(EVP_PKEY_size)]
    #[must_use]
    pub fn size(&self) -> usize {
        unsafe { ffi::EVP_PKEY_size(self.as_ptr()) as usize }
    }
}

impl<T> PKeyRef<T>
where
    T: HasPublic,
{
    to_pem! {
        /// Serializes the public key into a PEM-encoded SubjectPublicKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN PUBLIC KEY-----`.
        #[corresponds(PEM_write_bio_PUBKEY)]
        public_key_to_pem,
        ffi::PEM_write_bio_PUBKEY
    }

    to_der! {
        /// Serializes the public key into a DER-encoded SubjectPublicKeyInfo structure.
        #[corresponds(i2d_PUBKEY)]
        public_key_to_der,
        ffi::i2d_PUBKEY
    }

    /// Returns the size of the key.
    ///
    /// This corresponds to the bit length of the modulus of an RSA key, and the bit length of the
    /// group order for an elliptic curve key, for example.
    #[must_use]
    pub fn bits(&self) -> u32 {
        unsafe { ffi::EVP_PKEY_bits(self.as_ptr()) as u32 }
    }

    /// Compares the public component of this key with another.
    #[must_use]
    pub fn public_eq<U>(&self, other: &PKeyRef<U>) -> bool
    where
        U: HasPublic,
    {
        unsafe { ffi::EVP_PKEY_cmp(self.as_ptr(), other.as_ptr()) == 1 }
    }

    /// Returns the length of the "raw" form of the public key. Only supported for certain key types.
    #[corresponds(EVP_PKEY_get_raw_public_key)]
    pub fn raw_public_key_len(&self) -> Result<usize, ErrorStack> {
        unsafe {
            let mut size = 0;
            _ = cvt_0i(ffi::EVP_PKEY_get_raw_public_key(
                self.as_ptr(),
                std::ptr::null_mut(),
                &mut size,
            ))?;
            Ok(size)
        }
    }

    /// Outputs a copy of the "raw" form of the public key. Only supported for certain key types.
    ///
    /// Returns the used portion of `out`.
    #[corresponds(EVP_PKEY_get_raw_public_key)]
    pub fn raw_public_key<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], ErrorStack> {
        unsafe {
            let mut size = out.len();
            _ = cvt_0i(ffi::EVP_PKEY_get_raw_public_key(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut size,
            ))?;
            Ok(&out[..size])
        }
    }
}

impl<T> PKeyRef<T>
where
    T: HasPrivate,
{
    private_key_to_pem! {
        /// Serializes the private key to a PEM-encoded PKCS#8 PrivateKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN PRIVATE KEY-----`.
        #[corresponds(PEM_write_bio_PKCS8PrivateKey)]
        private_key_to_pem_pkcs8,
        /// Serializes the private key to a PEM-encoded PKCS#8 EncryptedPrivateKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN ENCRYPTED PRIVATE KEY-----`.
        #[corresponds(PEM_write_bio_PKCS8PrivateKey)]
        private_key_to_pem_pkcs8_passphrase,
        ffi::PEM_write_bio_PKCS8PrivateKey
    }

    to_der! {
        /// Serializes the private key to a DER-encoded key type specific format.
        #[corresponds(i2d_PrivateKey)]
        private_key_to_der,
        ffi::i2d_PrivateKey
    }

    // This isn't actually PEM output, but `i2d_PKCS8PrivateKey_bio` is documented to be
    // "identical to the corresponding PEM function", and it's declared in pem.h.
    private_key_to_pem! {
        /// Serializes the private key to a DER-encoded PKCS#8 PrivateKeyInfo structure.
        #[corresponds(i2d_PKCS8PrivateKey_bio)]
        private_key_to_der_pkcs8,
        /// Serializes the private key to a DER-encoded PKCS#8 EncryptedPrivateKeyInfo structure.
        #[corresponds(i2d_PKCS8PrivateKey_bio)]
        private_key_to_der_pkcs8_passphrase,
        ffi::i2d_PKCS8PrivateKey_bio
    }

    /// Returns the length of the "raw" form of the private key. Only supported for certain key types.
    #[corresponds(EVP_PKEY_get_raw_private_key)]
    pub fn raw_private_key_len(&self) -> Result<usize, ErrorStack> {
        unsafe {
            let mut size = 0;
            _ = cvt_0i(ffi::EVP_PKEY_get_raw_private_key(
                self.as_ptr(),
                std::ptr::null_mut(),
                &mut size,
            ))?;
            Ok(size)
        }
    }

    /// Outputs a copy of the "raw" form of the private key. Only supported for certain key types.
    ///
    /// Returns the used portion of `out`.
    #[corresponds(EVP_PKEY_get_raw_private_key)]
    pub fn raw_private_key<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], ErrorStack> {
        unsafe {
            let mut size = out.len();
            _ = cvt_0i(ffi::EVP_PKEY_get_raw_private_key(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut size,
            ))?;
            Ok(&out[..size])
        }
    }
}

impl<T> fmt::Debug for PKey<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let alg = match self.id() {
            Id::RSA => "RSA",
            Id::RSAPSS => "RSAPSS",
            Id::DSA => "DSA",
            Id::DH => "DH",
            Id::EC => "EC",
            Id::ED25519 => "Ed25519",
            Id::ED448 => "Ed448",
            _ => "unknown",
        };
        fmt.debug_struct("PKey").field("algorithm", &alg).finish()
        // TODO: Print details for each specific type of key
    }
}

impl<T> Clone for PKey<T> {
    fn clone(&self) -> PKey<T> {
        PKeyRef::to_owned(self)
    }
}

impl<T> PKey<T> {
    /// Creates a new `PKey` containing an RSA key.
    #[corresponds(EVP_PKEY_assign_RSA)]
    pub fn from_rsa(rsa: Rsa<T>) -> Result<PKey<T>, ErrorStack> {
        unsafe {
            let evp = cvt_p(ffi::EVP_PKEY_new())?;
            let pkey = PKey::from_ptr(evp);
            cvt(ffi::EVP_PKEY_assign(
                pkey.0,
                ffi::EVP_PKEY_RSA,
                rsa.as_ptr().cast(),
            ))?;
            mem::forget(rsa);
            Ok(pkey)
        }
    }

    /// Creates a new `PKey` containing an elliptic curve key.
    #[corresponds(EVP_PKEY_assign_EC_KEY)]
    pub fn from_ec_key(ec_key: EcKey<T>) -> Result<PKey<T>, ErrorStack> {
        unsafe {
            let evp = cvt_p(ffi::EVP_PKEY_new())?;
            let pkey = PKey::from_ptr(evp);
            cvt(ffi::EVP_PKEY_assign(
                pkey.0,
                ffi::EVP_PKEY_EC,
                ec_key.as_ptr().cast(),
            ))?;
            mem::forget(ec_key);
            Ok(pkey)
        }
    }

    /// Creates a new `PKey` containing a DSA key.
    #[corresponds(EVP_PKEY_assign_DSA)]
    pub fn from_dsa(dsa: Dsa<T>) -> Result<PKey<T>, ErrorStack> {
        unsafe {
            let evp = cvt_p(ffi::EVP_PKEY_new())?;
            let pkey = PKey::from_ptr(evp);
            cvt(ffi::EVP_PKEY_assign(
                pkey.0,
                ffi::EVP_PKEY_DSA,
                dsa.as_ptr().cast(),
            ))?;
            mem::forget(dsa);
            Ok(pkey)
        }
    }

    /// Creates a new `PKey` containing a DH key or parameters.
    #[corresponds(EVP_PKEY_assign_DH)]
    pub fn from_dh(dh: Dh<T>) -> Result<PKey<T>, ErrorStack>
    where
        T: HasParams,
    {
        unsafe {
            let evp = cvt_p(ffi::EVP_PKEY_new())?;
            let pkey = PKey::from_ptr(evp);
            cvt(ffi::EVP_PKEY_assign(
                pkey.0,
                ffi::EVP_PKEY_DH,
                dh.as_ptr().cast(),
            ))?;
            mem::forget(dh);
            Ok(pkey)
        }
    }
}

impl PKey<Private> {
    private_key_from_pem! {
        /// Deserializes a private key from a PEM-encoded key type specific format.
        #[corresponds(PEM_read_bio_PrivateKey)]
        private_key_from_pem,

        /// Deserializes a private key from a PEM-encoded encrypted key type specific format.
        #[corresponds(PEM_read_bio_PrivateKey)]
        private_key_from_pem_passphrase,

        /// Deserializes a private key from a PEM-encoded encrypted key type specific format.
        ///
        /// The callback should fill the password into the provided buffer and return its length.
        #[corresponds(PEM_read_bio_PrivateKey)]
        private_key_from_pem_callback,
        PKey<Private>,
        ffi::PEM_read_bio_PrivateKey
    }

    from_der! {
        /// Decodes a DER-encoded private key.
        ///
        /// This function will automatically attempt to detect the underlying key format, and
        /// supports the unencrypted PKCS#8 PrivateKeyInfo structures as well as key type specific
        /// formats.
        #[corresponds(d2i_AutoPrivateKey)]
        private_key_from_der,
        PKey<Private>,
        ffi::d2i_AutoPrivateKey,
        ::libc::c_long
    }

    /// Deserializes a DER-formatted PKCS#8 unencrypted private key.
    ///
    /// This method is mainly for interoperability reasons. Encrypted keyfiles should be preferred.
    pub fn private_key_from_pkcs8(der: &[u8]) -> Result<PKey<Private>, ErrorStack> {
        unsafe {
            ffi::init();
            let len = der.len().min(c_long::MAX as usize) as c_long;
            let p8inf = cvt_p(ffi::d2i_PKCS8_PRIV_KEY_INFO(
                ptr::null_mut(),
                &mut der.as_ptr(),
                len,
            ))?;
            let res = cvt_p(ffi::EVP_PKCS82PKEY(p8inf)).map(|p| PKey::from_ptr(p));
            ffi::PKCS8_PRIV_KEY_INFO_free(p8inf);
            res
        }
    }

    /// Deserializes a DER-formatted PKCS#8 private key, using a callback to retrieve the password
    /// if the key is encrypted.
    ///
    /// The callback should copy the password into the provided buffer and return the number of
    /// bytes written.
    pub fn private_key_from_pkcs8_callback<F>(
        der: &[u8],
        callback: F,
    ) -> Result<PKey<Private>, ErrorStack>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>,
    {
        unsafe {
            ffi::init();
            let mut cb = CallbackState::new(callback);
            let bio = MemBioSlice::new(der)?;
            cvt_p(ffi::d2i_PKCS8PrivateKey_bio(
                bio.as_ptr(),
                ptr::null_mut(),
                Some(invoke_passwd_cb::<F>),
                std::ptr::addr_of_mut!(cb).cast(),
            ))
            .map(|p| PKey::from_ptr(p))
        }
    }

    /// Deserializes a DER-formatted PKCS#8 private key, using the supplied password if the key is
    /// encrypted.
    ///
    /// # Panics
    ///
    /// Panics if `passphrase` contains an embedded null.
    pub fn private_key_from_pkcs8_passphrase(
        der: &[u8],
        passphrase: &[u8],
    ) -> Result<PKey<Private>, ErrorStack> {
        unsafe {
            ffi::init();
            let bio = MemBioSlice::new(der)?;
            let passphrase = CString::new(passphrase).map_err(ErrorStack::internal_error)?;
            cvt_p(ffi::d2i_PKCS8PrivateKey_bio(
                bio.as_ptr(),
                ptr::null_mut(),
                None,
                passphrase.as_ptr().cast_mut().cast(),
            ))
            .map(|p| PKey::from_ptr(p))
        }
    }
}

impl PKey<Public> {
    from_pem! {
        /// Decodes a PEM-encoded SubjectPublicKeyInfo structure.
        ///
        /// The input should have a header of `-----BEGIN PUBLIC KEY-----`.
        #[corresponds(PEM_read_bio_PUBKEY)]
        public_key_from_pem,
        PKey<Public>,
        ffi::PEM_read_bio_PUBKEY
    }

    from_der! {
        /// Decodes a DER-encoded SubjectPublicKeyInfo structure.
        #[corresponds(d2i_PUBKEY)]
        public_key_from_der,
        PKey<Public>,
        ffi::d2i_PUBKEY,
        ::libc::c_long
    }
}

use crate::ffi::EVP_PKEY_up_ref;

#[cfg(test)]
mod tests {
    use hex::FromHex as _;

    use crate::bn::BigNum;
    use crate::dh::Dh;
    use crate::dsa::Dsa;
    use crate::ec::EcKey;
    use crate::nid::Nid;
    use crate::rsa::Rsa;
    use crate::symm::Cipher;

    use super::*;

    #[test]
    fn test_to_password() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let pem = pkey
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_128_cbc(), b"foobar")
            .unwrap();
        PKey::private_key_from_pem_passphrase(&pem, b"foobar").unwrap();
        assert!(PKey::private_key_from_pem_passphrase(&pem, b"fizzbuzz").is_err());
    }

    #[test]
    fn test_unencrypted_pkcs8() {
        let key = include_bytes!("../test/pkcs8-nocrypt.der");
        PKey::private_key_from_pkcs8(key).unwrap();
    }

    #[test]
    fn test_encrypted_pkcs8_passphrase() {
        let key = include_bytes!("../test/pkcs8.der");
        PKey::private_key_from_pkcs8_passphrase(key, b"mypass").unwrap();
    }

    #[test]
    fn test_encrypted_pkcs8_callback() {
        let mut password_queried = false;
        let key = include_bytes!("../test/pkcs8.der");
        PKey::private_key_from_pkcs8_callback(key, |password| {
            password_queried = true;
            password[..6].copy_from_slice(b"mypass");
            Ok(6)
        })
        .unwrap();
        assert!(password_queried);
    }

    #[test]
    fn test_private_key_from_pem() {
        let key = include_bytes!("../test/key.pem");
        PKey::private_key_from_pem(key).unwrap();
    }

    #[test]
    fn test_public_key_from_pem() {
        let key = include_bytes!("../test/key.pem.pub");
        PKey::public_key_from_pem(key).unwrap();
    }

    #[test]
    fn test_public_key_from_der() {
        let key = include_bytes!("../test/key.der.pub");
        PKey::public_key_from_der(key).unwrap();
    }

    #[test]
    fn test_private_key_from_der() {
        let key = include_bytes!("../test/key.der");
        PKey::private_key_from_der(key).unwrap();
    }

    #[test]
    fn test_pem() {
        let key = include_bytes!("../test/key.pem");
        let key = PKey::private_key_from_pem(key).unwrap();

        let priv_key = key.private_key_to_pem_pkcs8().unwrap();
        let pub_key = key.public_key_to_pem().unwrap();

        // As a super-simple verification, just check that the buffers contain
        // the `PRIVATE KEY` or `PUBLIC KEY` strings.
        assert!(priv_key.windows(11).any(|s| s == b"PRIVATE KEY"));
        assert!(pub_key.windows(10).any(|s| s == b"PUBLIC KEY"));
    }

    #[test]
    fn test_der_pkcs8() {
        let key = include_bytes!("../test/key.der");
        let key = PKey::private_key_from_der(key).unwrap();

        let priv_key = key.private_key_to_der_pkcs8().unwrap();

        // Check that this has the correct PKCS#8 version number and algorithm.
        assert_eq!(hex::encode(&priv_key[4..=6]), "020100"); // Version 0
        assert_eq!(hex::encode(&priv_key[9..=19]), "06092a864886f70d010101"); // Algorithm RSA/PKCS#1
    }

    #[test]
    fn test_rsa_accessor() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        pkey.rsa().unwrap();
        assert_eq!(pkey.id(), Id::RSA);
        assert!(pkey.dsa().is_err());
    }

    #[test]
    fn test_ec_key_accessor() {
        let ec_key = EcKey::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        pkey.ec_key().unwrap();
        assert_eq!(pkey.id(), Id::EC);
        assert!(pkey.rsa().is_err());
    }

    #[test]
    fn test_dsa_from_and_accessor() {
        let dsa = Dsa::generate(2048).unwrap();
        let pkey = PKey::from_dsa(dsa).unwrap();
        pkey.dsa().unwrap();
        assert_eq!(pkey.id(), Id::DSA);
        assert!(pkey.rsa().is_err());
        assert!(pkey.ec_key().is_err());
    }

    #[test]
    fn test_dh_from_and_accessor() {
        let p = BigNum::from_hex_str(
            "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF\
             4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B47\
             58C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B6\
             3ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5\
             140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710\
             C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597",
        )
        .unwrap();
        let g = BigNum::from_hex_str(
            "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED\
             4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A\
             57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5\
             045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E\
             052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67E\
             B6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659",
        )
        .unwrap();
        let q = BigNum::from_hex_str(
            "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3",
        )
        .unwrap();
        let dh = Dh::from_params(p, g, q).unwrap();

        let pkey = PKey::from_dh(dh).unwrap();
        pkey.dh().unwrap();
        assert_eq!(pkey.id(), Id::DH);
        assert!(pkey.rsa().is_err());
        assert!(pkey.ec_key().is_err());
    }

    #[test]
    fn test_raw_accessors() {
        const ED25519_PRIVATE_KEY_DER: &str = concat!(
            "302e020100300506032b6570042204207c8c6497f9960d5595d7815f550569e5",
            "f77764ac97e63e339aaa68cc1512b683"
        );
        let pkey =
            PKey::private_key_from_der(&Vec::from_hex(ED25519_PRIVATE_KEY_DER).unwrap()).unwrap();
        assert_eq!(pkey.id(), Id::ED25519);

        let priv_len = pkey.raw_private_key_len().unwrap();
        assert_eq!(priv_len, 32);
        let mut raw_private_key_buf = [0; 40];
        let raw_private_key = pkey.raw_private_key(&mut raw_private_key_buf).unwrap();
        assert_eq!(raw_private_key.len(), 32);
        assert_ne!(raw_private_key, [0; 32]);
        pkey.raw_private_key(&mut [0; 5])
            .expect_err("buffer too small");

        let pub_len = pkey.raw_public_key_len().unwrap();
        assert_eq!(pub_len, 32);
        let mut raw_public_key_buf = [0; 40];
        let raw_public_key = pkey.raw_public_key(&mut raw_public_key_buf).unwrap();
        assert_eq!(raw_public_key.len(), 32);
        assert_ne!(raw_public_key, [0; 32]);
        assert_ne!(raw_public_key, raw_private_key);
        pkey.raw_public_key(&mut [0; 5])
            .expect_err("buffer too small");
    }
}
