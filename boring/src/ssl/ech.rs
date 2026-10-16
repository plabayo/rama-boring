use crate::ffi;
use crate::libc_types::c_int;
use foreign_types::ForeignType;

use crate::error::ErrorStack;
use crate::hpke::HpkeKey;
use crate::{cvt_0i, cvt_p};

pub struct SslEchKeysBuilder {
    keys: SslEchKeys,
}

impl SslEchKeysBuilder {
    pub fn new() -> Result<SslEchKeysBuilder, ErrorStack> {
        unsafe {
            ffi::init();
            let keys = cvt_p(ffi::SSL_ECH_KEYS_new())?;

            Ok(SslEchKeysBuilder::from_ptr(keys))
        }
    }

    pub unsafe fn from_ptr(keys: *mut ffi::SSL_ECH_KEYS) -> Self {
        Self {
            keys: SslEchKeys::from_ptr(keys),
        }
    }

    pub fn add_key(
        &mut self,
        is_retry_config: bool,
        ech_config: &[u8],
        key: HpkeKey,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_ECH_KEYS_add(
                self.keys.as_ptr(),
                c_int::from(is_retry_config),
                ech_config.as_ptr(),
                ech_config.len(),
                key.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    pub fn build(self) -> SslEchKeys {
        self.keys
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_ECH_KEYS;
    fn drop = ffi::SSL_ECH_KEYS_free;

    pub struct SslEchKeys;
}

impl SslEchKeys {
    pub fn builder() -> Result<SslEchKeysBuilder, ErrorStack> {
        SslEchKeysBuilder::new()
    }
}

/// HPKE cipher suites supported for ECH GREASE. The KEM is always
/// DHKEM(X25519, HKDF-SHA256), with a 32-byte encapsulated key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum EchGreaseCipherSuite {
    /// KDF 1, AEAD 1.
    HkdfSha256Aes128Gcm,
    /// KDF 1, AEAD 2.
    HkdfSha256Aes256Gcm,
    /// KDF 1, AEAD 3.
    HkdfSha256ChaCha20Poly1305,
}

impl EchGreaseCipherSuite {
    /// The wire KDF and AEAD identifiers, respectively.
    pub const fn ids(self) -> (u16, u16) {
        match self {
            Self::HkdfSha256Aes128Gcm => (1, 1),
            Self::HkdfSha256Aes256Gcm => (1, 2),
            Self::HkdfSha256ChaCha20Poly1305 => (1, 3),
        }
    }
}

/// The algorithms and lengths of an ECH GREASE extension, never its keys or bytes.
///
/// Apply with [`super::ClientHelloShape::with_ech_grease`]. GREASE must also be
/// enabled with [`super::SslRef::set_enable_ech_grease`], and TLS 1.3 must be
/// offered. A usable real ECH configuration takes precedence; this shape only
/// applies when BoringSSL falls back to GREASE. An unusable configuration still
/// follows the native ECH rejection policy.
///
/// Each new handshake generates fresh X25519 encapsulation, random payload and
/// config ID, independently of [`super::GreaseValues`]. A HelloRetryRequest
/// reuses the first GREASE extension byte for byte. A new connection, including
/// one made with real ECH retry configs, must be configured separately.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EchGreaseShape {
    cipher_suite: EchGreaseCipherSuite,
    payload_len: u16,
}

impl EchGreaseShape {
    /// The X25519 encapsulated key length. Other KEMs are not supported here.
    pub const ENCAPSULATED_KEY_LEN: usize = 32;
    /// Minimum payload length, including the AEAD's 16-byte tag.
    pub const MIN_PAYLOAD_LEN: usize = 16;
    /// Largest payload that fits the TLS extensions block with ECH framing.
    /// The complete ClientHello must also fit its length prefixes: other
    /// extensions reduce the available space. If it does not fit, the
    /// handshake fails before writing a ClientHello.
    pub const MAX_PAYLOAD_LEN: usize = 65_489;

    /// Selects an exact payload length in bytes, including the AEAD tag.
    /// Lengths need not be multiples of 32.
    pub fn new(cipher_suite: EchGreaseCipherSuite, payload_len: usize) -> Result<Self, ErrorStack> {
        if !(Self::MIN_PAYLOAD_LEN..=Self::MAX_PAYLOAD_LEN).contains(&payload_len) {
            return Err(ErrorStack::internal_error_str(
                "invalid ECH GREASE payload length",
            ));
        }
        Ok(Self {
            cipher_suite,
            payload_len: payload_len as u16,
        })
    }

    /// Validates algorithms and lengths retained from a captured extension.
    /// Accepts KDF 1, AEAD 1/2/3, and exactly 32 encapsulation bytes.
    /// No captured cryptographic bytes or config ID are accepted.
    pub fn from_wire(
        kdf_id: u16,
        aead_id: u16,
        encapsulated_key_len: usize,
        payload_len: usize,
    ) -> Result<Self, ErrorStack> {
        if kdf_id != 1 || encapsulated_key_len != Self::ENCAPSULATED_KEY_LEN {
            return Err(ErrorStack::internal_error_str(
                "unsupported ECH GREASE KDF or KEM length",
            ));
        }
        let suite = match aead_id {
            1 => EchGreaseCipherSuite::HkdfSha256Aes128Gcm,
            2 => EchGreaseCipherSuite::HkdfSha256Aes256Gcm,
            3 => EchGreaseCipherSuite::HkdfSha256ChaCha20Poly1305,
            _ => {
                return Err(ErrorStack::internal_error_str(
                    "unsupported ECH GREASE AEAD",
                ))
            }
        };
        Self::new(suite, payload_len)
    }

    /// The selected HPKE cipher suite.
    pub const fn cipher_suite(self) -> EchGreaseCipherSuite {
        self.cipher_suite
    }

    /// The exact wire payload length, including the AEAD tag.
    pub const fn payload_len(self) -> usize {
        self.payload_len as usize
    }
}
