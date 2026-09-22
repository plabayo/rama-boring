use super::{buffer::CryptoBuffer, SslSignatureAlgorithm};
use crate::error::ErrorStack;
use crate::ex_data::Index;
use crate::pkey::{PKeyRef, Private};
use crate::ssl::callbacks;
use crate::ssl::PrivateKeyMethod;
use crate::x509::X509Ref;
use crate::{cvt, cvt_0i, cvt_n, cvt_p};
use crate::{ffi, free_data_box};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::any::TypeId;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::mem;
use std::ptr;
use std::sync::{LazyLock, Mutex};

static SSL_CREDENTIAL_INDEXES: LazyLock<Mutex<HashMap<TypeId, c_int>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_CREDENTIAL;
    fn drop = ffi::SSL_CREDENTIAL_free;

    /// A credential.
    pub struct SslCredential;
}

impl Clone for SslCredential {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl ToOwned for SslCredentialRef {
    type Owned = SslCredential;

    fn to_owned(&self) -> SslCredential {
        unsafe { SslCredential::from_ptr(ffi::SSL_CREDENTIAL_dup_ref(self.as_ptr())) }
    }
}

impl SslCredential {
    /// Creates an X.509 credential builder. Configure a chain and private key (or
    /// private key method) before adding the built credential to a context or SSL.
    #[corresponds(SSL_CREDENTIAL_new_x509)]
    pub fn builder() -> Result<SslCredentialBuilder, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(ffi::SSL_CREDENTIAL_new_x509()).map(|p| SslCredentialBuilder(Self::from_ptr(p)))
        }
    }

    /// Returns a new extra data index.
    ///
    /// Each invocation of this function is guaranteed to return a distinct index. These can be used
    /// to store data in the context that can be retrieved later by callbacks, for example.
    #[corresponds(SSL_C_get_ex_new_index)]
    pub fn new_ex_index<T>() -> Result<Index<Self, T>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            ffi::init();
            let idx = cvt_n(get_new_ssl_credential_idx(Some(free_data_box::<T>)))?;
            Ok(Index::from_raw(idx))
        }
    }

    // FIXME should return a result?
    pub(crate) fn cached_ex_index<T>() -> Index<Self, T>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            let idx = *SSL_CREDENTIAL_INDEXES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(TypeId::of::<T>())
                .or_insert_with(|| Self::new_ex_index::<T>().unwrap().as_raw());
            Index::from_raw(idx)
        }
    }
}

impl SslCredentialRef {
    /// Whether the credential has the certificate and key material it requires.
    /// This does not validate the chain against a trust store.
    #[corresponds(SSL_CREDENTIAL_is_complete)]
    #[must_use]
    pub fn is_complete(&self) -> bool {
        unsafe { ffi::SSL_CREDENTIAL_is_complete(self.as_ptr()) != 0 }
    }

    /// Returns a reference to the extra data at the specified index.
    #[corresponds(SSL_CREDENTIAL_get_ex_data)]
    #[must_use]
    pub fn ex_data<T>(&self, index: Index<SslCredential, T>) -> Option<&T> {
        unsafe {
            let data = ffi::SSL_CREDENTIAL_get_ex_data(self.as_ptr(), index.as_raw());
            if data.is_null() {
                None
            } else {
                Some(&*(data as *const T))
            }
        }
    }

    // Unsafe because SSL contexts are not guaranteed to be unique, we call
    // this only from SslCredentialBuilder.
    #[corresponds(SSL_CREDENTIAL_get_ex_data)]
    pub(crate) unsafe fn ex_data_mut<T>(
        &mut self,
        index: Index<SslCredential, T>,
    ) -> Option<&mut T> {
        let data = ffi::SSL_CREDENTIAL_get_ex_data(self.as_ptr(), index.as_raw());
        if data.is_null() {
            None
        } else {
            Some(&mut *(data as *mut T))
        }
    }

    // Unsafe because SSL contexts are not guaranteed to be unique, we call
    // this only from SslCredentialBuilder.
    #[corresponds(SSL_CREDENTIAL_set_ex_data)]
    pub(crate) unsafe fn replace_ex_data<T>(
        &mut self,
        index: Index<SslCredential, T>,
        data: T,
    ) -> Option<T> {
        if let Some(old) = self.ex_data_mut(index) {
            return Some(mem::replace(old, data));
        }

        unsafe {
            let data = Box::into_raw(Box::new(data)) as *mut c_void;
            ffi::SSL_CREDENTIAL_set_ex_data(self.as_ptr(), index.as_raw(), data);
        }

        None
    }
}

/// A builder for [`SslCredential`].
///
/// Create it with [`SslCredential::builder`]. Building consumes the mutable
/// configuration so credentials added to contexts or SSL objects stay immutable.
pub struct SslCredentialBuilder(SslCredential);

impl SslCredentialBuilder {
    /// Whether the required certificate and private key material is configured.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.0.is_complete()
    }

    /// Sets the certificate chain in leaf-first order, copying each certificate.
    ///
    /// The chain must be non-empty. If a private key is already configured, the
    /// leaf's public key must match it. On error, native configuration may have
    /// been partially updated; configure a valid chain before using the builder.
    #[corresponds(SSL_CREDENTIAL_set1_cert_chain)]
    pub fn set_certificate_chain<I, C>(&mut self, certificates: I) -> Result<(), ErrorStack>
    where
        I: IntoIterator<Item = C>,
        C: AsRef<X509Ref>,
    {
        let buffers: Vec<_> = certificates
            .into_iter()
            .map(|cert| CryptoBuffer::new(&cert.as_ref().to_der()?))
            .collect::<Result<_, ErrorStack>>()?;
        let pointers: Vec<_> = buffers.iter().map(|b| b.as_ptr()).collect();
        unsafe {
            cvt(ffi::SSL_CREDENTIAL_set1_cert_chain(
                self.0.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
            ))
        }
    }

    /// Sets signing algorithm preferences for this credential's private key.
    #[corresponds(SSL_CREDENTIAL_set1_signing_algorithm_prefs)]
    pub fn set_signing_algorithm_prefs(
        &mut self,
        prefs: &[SslSignatureAlgorithm],
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_CREDENTIAL_set1_signing_algorithm_prefs(
                self.0.as_ptr(),
                prefs.as_ptr().cast(),
                prefs.len(),
            ))
        }
    }

    /// Sets the binary trust anchor ID of the issuer of the final certificate.
    /// An empty slice clears it. Enable [`Self::set_must_match_issuer`] for this
    /// metadata to affect selection. This does not establish trust in that issuer.
    #[corresponds(SSL_CREDENTIAL_set1_trust_anchor_id)]
    pub fn set_trust_anchor_id(&mut self, id: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_CREDENTIAL_set1_trust_anchor_id(
                self.0.as_ptr(),
                id.as_ptr(),
                id.len(),
            ))
        }
    }

    /// Adds a trust anchor group inclusion: `base` followed by a component in the
    /// inclusive range `min..=max`. The base is a binary trust anchor ID.
    /// Prefer CA-provided [`Self::set_certificate_properties`] when available.
    #[corresponds(SSL_CREDENTIAL_add1_trust_anchor_group_inclusion)]
    pub fn add_trust_anchor_group_inclusion(
        &mut self,
        base: &[u8],
        min: u64,
        max: u64,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_CREDENTIAL_add1_trust_anchor_group_inclusion(
                self.0.as_ptr(),
                base.as_ptr(),
                base.len(),
                min,
                max,
            ))
        }
    }

    /// Conditions this credential on the peer's requested CAs or trust anchor IDs.
    ///
    /// Enabled credentials must have a correctly ordered chain. Put these before
    /// broadly usable fallback credentials in the context's preference list.
    #[corresponds(SSL_CREDENTIAL_set_must_match_issuer)]
    pub fn set_must_match_issuer(&mut self, enabled: bool) {
        unsafe { ffi::SSL_CREDENTIAL_set_must_match_issuer(self.0.as_ptr(), enabled.into()) }
    }

    /// Parses a serialized CertificatePropertyList and applies recognized metadata.
    ///
    /// Uses the format supported by the bundled BoringSSL, including the outer
    /// u16 length. Does not enable issuer matching. On error, earlier properties
    /// may already have been applied; discard or reconfigure the builder.
    #[corresponds(SSL_CREDENTIAL_set1_certificate_properties)]
    pub fn set_certificate_properties(&mut self, properties: &[u8]) -> Result<(), ErrorStack> {
        let buffer = CryptoBuffer::new(properties)?;
        unsafe {
            cvt(ffi::SSL_CREDENTIAL_set1_certificate_properties(
                self.0.as_ptr(),
                buffer.as_ptr(),
            ))
        }
    }

    /// Sets the stapled OCSP response for this credential, copying the bytes.
    #[corresponds(SSL_CREDENTIAL_set1_ocsp_response)]
    pub fn set_ocsp_response(&mut self, response: &[u8]) -> Result<(), ErrorStack> {
        let buffer = CryptoBuffer::new(response)?;
        unsafe {
            cvt(ffi::SSL_CREDENTIAL_set1_ocsp_response(
                self.0.as_ptr(),
                buffer.as_ptr(),
            ))
        }
    }

    /// Sets this credential's serialized SignedCertificateTimestampList.
    /// Includes the outer u16 length and each SCT's u16 length; bytes are copied.
    #[corresponds(SSL_CREDENTIAL_set1_signed_cert_timestamp_list)]
    pub fn set_signed_cert_timestamp_list(&mut self, timestamps: &[u8]) -> Result<(), ErrorStack> {
        let buffer = CryptoBuffer::new(timestamps)?;
        unsafe {
            cvt(ffi::SSL_CREDENTIAL_set1_signed_cert_timestamp_list(
                self.0.as_ptr(),
                buffer.as_ptr(),
            ))
        }
    }

    /// Sets or overwrites the extra data at the specified index.
    ///
    /// This can be used to provide data to callbacks registered with the context. Use the
    /// `SslCredential::new_ex_index` method to create an `Index`.
    ///
    /// Any previous value will be returned and replaced by the new one.
    #[corresponds(SSL_CREDENTIAL_set_ex_data)]
    pub fn replace_ex_data<T>(&mut self, index: Index<SslCredential, T>, data: T) -> Option<T> {
        unsafe { self.0.replace_ex_data(index, data) }
    }

    /// Sets the private key of the credential.
    #[corresponds(SSL_CREDENTIAL_set1_private_key)]
    pub fn set_private_key(&mut self, private_key: &PKeyRef<Private>) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_CREDENTIAL_set1_private_key(
                self.0.as_ptr(),
                private_key.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Configures a custom private key method on the credential.
    ///
    /// See [`PrivateKeyMethod`] for more details.
    #[corresponds(SSL_CREDENTIAL_set_private_key_method)]
    pub fn set_private_key_method<M>(&mut self, method: M) -> Result<(), ErrorStack>
    where
        M: PrivateKeyMethod,
    {
        unsafe {
            self.replace_ex_data(SslCredential::cached_ex_index::<M>(), method);

            cvt_0i(ffi::SSL_CREDENTIAL_set_private_key_method(
                self.0.as_ptr(),
                &ffi::SSL_PRIVATE_KEY_METHOD {
                    sign: Some(callbacks::raw_sign::<M>),
                    decrypt: Some(callbacks::raw_decrypt::<M>),
                    complete: Some(callbacks::raw_complete::<M>),
                },
            ))
            .map(|_| ())
        }
    }

    #[must_use]
    pub fn build(self) -> SslCredential {
        self.0
    }
}

unsafe fn get_new_ssl_credential_idx(f: ffi::CRYPTO_EX_free) -> c_int {
    ffi::SSL_CREDENTIAL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, f)
}
