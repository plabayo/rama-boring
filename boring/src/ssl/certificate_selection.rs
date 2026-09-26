use super::{
    buffer::CryptoBuffer, SelectCertError, Ssl, SslContext, SslContextBuilder, SslRef,
    SslSignatureAlgorithm,
};
use crate::{ex_data::Index, ffi, stack::StackRef};
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use std::{
    ffi::{c_int, c_void},
    ptr, slice,
    sync::{Arc, LazyLock},
};

/// Certificate-selection state, available only while the selection callback runs.
/// Copy request metadata before moving it into an asynchronous operation.
/// Borrowed metadata prevents mutating the SSL while that metadata is still used:
///
/// ```compile_fail
/// use rama_boring::ssl::CertificateSelection;
/// fn change(mut selection: CertificateSelection<'_>) {
///     let algorithms = selection.peer_verify_algorithms();
///     selection.ssl_mut().clear_certificates();
///     assert!(!algorithms.is_empty());
/// }
/// ```
pub struct CertificateSelection<'ssl>(pub(super) &'ssl mut SslRef);

impl CertificateSelection<'_> {
    pub fn ssl(&self) -> &SslRef {
        self.0
    }

    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.0
    }

    /// Signature algorithms the peer can verify. Empty if the peer omitted them.
    #[corresponds(SSL_get0_peer_verify_algorithms)]
    pub fn peer_verify_algorithms(&self) -> &[SslSignatureAlgorithm] {
        unsafe {
            let mut algorithms = ptr::null();
            let len = ffi::SSL_get0_peer_verify_algorithms(self.0.as_ptr(), &mut algorithms);
            if len == 0 {
                &[]
            } else {
                // SslSignatureAlgorithm is a transparent u16 wrapper. The view
                // cannot outlive the callback or coexist with a mutable SSL borrow.
                slice::from_raw_parts(algorithms.cast(), len)
            }
        }
    }

    /// Client certificate types requested by the server. Empty for TLS 1.3
    /// and on servers; use signature algorithms for TLS 1.3.
    #[corresponds(SSL_get0_certificate_types)]
    pub fn certificate_types(&self) -> &[u8] {
        unsafe {
            let mut types = ptr::null();
            let len = ffi::SSL_get0_certificate_types(self.0.as_ptr(), &mut types);
            if len == 0 {
                &[]
            } else {
                slice::from_raw_parts(types, len)
            }
        }
    }

    /// DER-encoded CA distinguished names requested by the server, in wire order.
    /// Empty on servers or when no CA names were sent. These are selection hints,
    /// not trust anchors.
    #[corresponds(SSL_get0_server_requested_CAs)]
    pub fn requested_ca_names(&self) -> impl Iterator<Item = &[u8]> {
        let names = unsafe {
            let names = if self.0.is_server() {
                ptr::null()
            } else {
                ffi::SSL_get0_server_requested_CAs(self.0.as_ptr())
            };
            if names.is_null() {
                None
            } else {
                Some(StackRef::<CryptoBuffer>::from_ptr(names.cast_mut()))
            }
        };
        names.into_iter().flatten().map(|name| unsafe {
            let len = ffi::CRYPTO_BUFFER_len(name.as_ptr());
            if len == 0 {
                &[][..]
            } else {
                slice::from_raw_parts(ffi::CRYPTO_BUFFER_data(name.as_ptr()), len)
            }
        })
    }
}

type CertificateCallback =
    Arc<dyn Fn(CertificateSelection<'_>) -> Result<(), SelectCertError> + Send + Sync>;

// One slot per SSL, so replacing a different closure type also releases captures.
struct ConnectionCallback(Option<CertificateCallback>);
struct ContextCallback(CertificateCallback);

static CONNECTION_CALLBACK_INDEX: LazyLock<Index<Ssl, ConnectionCallback>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());
static CONTEXT_CALLBACK_INDEX: LazyLock<Index<SslContext, ContextCallback>> =
    LazyLock::new(|| SslContext::new_ex_index().unwrap());

pub(super) fn clear_connection_callback(ssl: &mut SslRef) {
    if let Some(callback) = ssl.ex_data_mut(*CONNECTION_CALLBACK_INDEX) {
        callback.0 = None;
    }
}

impl SslContextBuilder {
    /// Selects the local certificate after peer extensions have been processed.
    /// On clients, runs only when the server requests a client certificate.
    /// Resumed client sessions do not request a fresh certificate. On servers,
    /// runs before the resumption decision. Rejected ECH skips client selection.
    /// Callback errors produce a native `internal_error` alert.
    ///
    /// Configure credentials through [`CertificateSelection::ssl_mut`]. `Ok(())`
    /// continues with the configured credentials. To omit a client certificate or
    /// replace all candidates, first call [`SslRef::clear_certificates`]; otherwise
    /// inherited modern credentials are tried before newly added credentials, and
    /// the legacy certificate is tried last. An empty list permits
    /// an anonymous response, while a nonempty list with no usable credential fails.
    /// [`SelectCertError::ERROR`] aborts; [`SelectCertError::RETRY`] pauses with
    /// [`super::ErrorCode::WANT_X509_LOOKUP`]. This does not replace peer verification.
    #[corresponds(SSL_CTX_set_cert_cb)]
    pub fn set_certificate_callback<F>(&mut self, callback: F)
    where
        F: Fn(CertificateSelection<'_>) -> Result<(), SelectCertError> + Send + Sync + 'static,
    {
        self.replace_ex_data(*CONTEXT_CALLBACK_INDEX, ContextCallback(Arc::new(callback)));
        unsafe {
            ffi::SSL_CTX_set_cert_cb(self.as_ptr(), Some(context_callback), ptr::null_mut());
        }
    }
}

impl SslRef {
    /// Overrides this connection's certificate-selection callback.
    /// Changing SSL contexts replaces this override and the credential configuration.
    /// Replacing an active async selection aborts the handshake.
    /// See [`SslContextBuilder::set_certificate_callback`].
    #[corresponds(SSL_set_cert_cb)]
    pub fn set_certificate_callback<F>(&mut self, callback: F)
    where
        F: Fn(CertificateSelection<'_>) -> Result<(), SelectCertError> + Send + Sync + 'static,
    {
        self.replace_ex_data(
            *CONNECTION_CALLBACK_INDEX,
            ConnectionCallback(Some(Arc::new(callback))),
        );
        unsafe {
            ffi::SSL_set_cert_cb(self.as_ptr(), Some(connection_callback), ptr::null_mut());
        }
        super::async_callbacks::invalidate_certificate_selection(self);
    }

    /// Removes all credential candidates, including the inherited legacy
    /// certificate chain and private key. The SSL context is unchanged.
    #[corresponds(SSL_certs_clear)]
    pub fn clear_certificates(&mut self) {
        unsafe {
            ffi::SSL_certs_clear(self.as_ptr());
        }
    }
}

unsafe extern "C" fn context_callback(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int {
    // Retain the callback even if it replaces itself or switches SSL contexts.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let callback = ssl
        .ssl_context()
        .ex_data(*CONTEXT_CALLBACK_INDEX)
        .expect("BUG: certificate callback missing")
        .0
        .clone();
    callback_result(callback(CertificateSelection(ssl)))
}

unsafe extern "C" fn connection_callback(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int {
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let callback = ssl
        .ex_data(*CONNECTION_CALLBACK_INDEX)
        .and_then(|callback| callback.0.clone())
        .expect("BUG: connection certificate callback missing");
    callback_result(callback(CertificateSelection(ssl)))
}

fn callback_result(result: Result<(), SelectCertError>) -> c_int {
    match result {
        Ok(()) => 1,
        Err(SelectCertError::RETRY) => -1,
        Err(_) => 0,
    }
}
