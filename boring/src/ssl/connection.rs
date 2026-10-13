//! Per-connection wire settings, observation of handshake messages, and
//! negotiated-state getters that complement the context-level configuration.

use super::{
    callbacks, CertificateCompressionAlgorithm, Ssl, SslContext, SslContextBuilder, SslRef,
    SESSION_CTX_INDEX,
};
use crate::{cvt, error::ErrorStack, ffi, stack::StackRef, x509::X509};
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use std::{ffi::CStr, fmt, slice, sync::Arc};

/// How a client handles a TLS 1.2 server's renegotiation request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SslRenegotiateMode(ffi::ssl_renegotiate_mode_t);

impl SslRenegotiateMode {
    /// Refuse renegotiation (the default).
    pub const NEVER: Self = Self(ffi::ssl_renegotiate_mode_t::ssl_renegotiate_never);
    /// Allow one renegotiation, as some servers use for client authentication.
    pub const ONCE: Self = Self(ffi::ssl_renegotiate_mode_t::ssl_renegotiate_once);
    /// Allow any number of renegotiations.
    pub const FREELY: Self = Self(ffi::ssl_renegotiate_mode_t::ssl_renegotiate_freely);
    /// Ignore renegotiation requests.
    pub const IGNORE: Self = Self(ffi::ssl_renegotiate_mode_t::ssl_renegotiate_ignore);
    /// Renegotiate only through `SSL_renegotiate`.
    pub const EXPLICIT: Self = Self(ffi::ssl_renegotiate_mode_t::ssl_renegotiate_explicit);
}

/// Why 0-RTT data was or was not accepted on a connection.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SslEarlyDataReason(ffi::ssl_early_data_reason_t);

impl SslEarlyDataReason {
    /// The handshake has not progressed far enough to know.
    pub const UNKNOWN: Self = Self(ffi::ssl_early_data_reason_t::ssl_early_data_unknown);
    /// Early data was accepted.
    pub const ACCEPTED: Self = Self(ffi::ssl_early_data_reason_t::ssl_early_data_accepted);
    /// Early data was disabled locally.
    pub const DISABLED: Self = Self(ffi::ssl_early_data_reason_t::ssl_early_data_disabled);
    /// The peer declined early data.
    pub const PEER_DECLINED: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_peer_declined);
    /// A HelloRetryRequest rejected early data.
    pub const HELLO_RETRY_REQUEST: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_hello_retry_request);
    /// The negotiated ALPN protocol differed from the session's.
    pub const ALPN_MISMATCH: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_alpn_mismatch);
    /// QUIC transport parameters or early data context differed.
    pub const QUIC_PARAMETER_MISMATCH: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_quic_parameter_mismatch);
    /// The negotiated protocol version does not support early data.
    pub const PROTOCOL_VERSION: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_protocol_version);
    /// The client offered no session.
    pub const NO_SESSION_OFFERED: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_no_session_offered);
    /// The server did not resume the offered session.
    pub const SESSION_NOT_RESUMED: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_session_not_resumed);
    /// The session does not allow early data.
    pub const UNSUPPORTED_FOR_SESSION: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_unsupported_for_session);
    /// Channel ID was negotiated.
    pub const CHANNEL_ID: Self = Self(ffi::ssl_early_data_reason_t::ssl_early_data_channel_id);
    /// The ticket's age was too far off.
    pub const TICKET_AGE_SKEW: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_ticket_age_skew);
    /// The negotiated ALPS settings differed from the session's.
    pub const ALPS_MISMATCH: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_alps_mismatch);

    /// The native, stable name of this reason.
    #[corresponds(SSL_early_data_reason_string)]
    #[must_use]
    pub fn as_str(&self) -> Option<&'static str> {
        unsafe {
            let ptr = ffi::SSL_early_data_reason_string(self.0);
            if ptr.is_null() {
                None
            } else {
                CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }

    /// The raw native value.
    #[must_use]
    pub fn as_raw(&self) -> u32 {
        self.0 .0
    }
}

impl fmt::Debug for SslEarlyDataReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(name) => f.write_str(name),
            None => write!(f, "SslEarlyDataReason({})", self.as_raw()),
        }
    }
}

/// The record content type of an observed message.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SslContentType(i32);

impl SslContentType {
    pub const CHANGE_CIPHER_SPEC: Self = Self(ffi::SSL3_RT_CHANGE_CIPHER_SPEC);
    pub const ALERT: Self = Self(ffi::SSL3_RT_ALERT);
    /// A complete handshake message, including its 4-byte header.
    pub const HANDSHAKE: Self = Self(ffi::SSL3_RT_HANDSHAKE);
    /// A record header (TLS over TCP only).
    pub const HEADER: Self = Self(ffi::SSL3_RT_HEADER);
    /// The encrypted ClientHelloInner of an ECH handshake.
    pub const CLIENT_HELLO_INNER: Self = Self(ffi::SSL3_RT_CLIENT_HELLO_INNER);
    /// A DTLS acknowledgement.
    pub const ACK: Self = Self(ffi::SSL3_RT_ACK);
    /// A legacy SSLv2-compatible ClientHello.
    pub const V2_CLIENT_HELLO: Self = Self(0);

    /// The raw native value.
    #[must_use]
    pub fn as_raw(&self) -> i32 {
        self.0
    }
}

/// A protocol message observed by a message callback.
///
/// Handshake messages are seen in plaintext in both directions, including
/// TLS 1.3 messages that are encrypted on the wire and messages carried by QUIC.
#[derive(Debug, Copy, Clone)]
pub struct SslMessage<'a> {
    written: bool,
    version: i32,
    content_type: SslContentType,
    bytes: &'a [u8],
}

impl<'a> SslMessage<'a> {
    /// Whether this side sent the message, rather than received it.
    #[must_use]
    pub fn is_written(&self) -> bool {
        self.written
    }

    /// The protocol version in effect: zero for record headers.
    #[must_use]
    pub fn version(&self) -> i32 {
        self.version
    }

    #[must_use]
    pub fn content_type(&self) -> SslContentType {
        self.content_type
    }

    /// The message bytes. For [`SslContentType::HANDSHAKE`] these start with the
    /// handshake type and 24-bit length.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The handshake message type, for handshake messages.
    #[must_use]
    pub fn handshake_type(&self) -> Option<u8> {
        if self.content_type == SslContentType::HANDSHAKE
            || self.content_type == SslContentType::CLIENT_HELLO_INNER
        {
            self.bytes.first().copied()
        } else {
            None
        }
    }

    pub(super) unsafe fn from_raw(
        write_p: i32,
        version: i32,
        content_type: i32,
        buf: *const std::ffi::c_void,
        len: usize,
    ) -> Self {
        let bytes = if len == 0 || buf.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(buf.cast::<u8>(), len) }
        };
        Self {
            written: write_p != 0,
            version,
            content_type: SslContentType(content_type),
            bytes,
        }
    }
}

impl SslContextBuilder {
    /// Observes every protocol message of connections made with this context.
    ///
    /// The callback runs synchronously inside the handshake and record layer and
    /// must only observe. It costs nothing on connections without a callback.
    #[corresponds(SSL_CTX_set_msg_callback)]
    pub fn set_msg_callback<F>(&mut self, callback: F)
    where
        F: Fn(&SslRef, SslMessage<'_>) + 'static + Sync + Send,
    {
        unsafe {
            self.replace_ex_data(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_set_msg_callback(self.as_ptr(), Some(callbacks::raw_ctx_msg::<F>));
        }
    }

    /// Sets how many TLS 1.3 session tickets a server issues after each
    /// handshake, capped at 16; zero disables tickets.
    #[corresponds(SSL_CTX_set_num_tickets)]
    pub fn set_num_tickets(&mut self, num_tickets: usize) {
        unsafe {
            ffi::SSL_CTX_set_num_tickets(self.as_ptr(), num_tickets);
        }
    }

    /// Runs certificate verification, including custom verifiers, again when a
    /// client resumes a session, instead of trusting the earlier result.
    #[corresponds(SSL_CTX_set_reverify_on_resume)]
    pub fn set_reverify_on_resume(&mut self, enabled: bool) {
        unsafe { ffi::SSL_CTX_set_reverify_on_resume(self.as_ptr(), enabled.into()) }
    }

    /// Caps the plaintext size of records sent by connections of this context,
    /// clamped to 512..=16384 bytes.
    #[corresponds(SSL_CTX_set_max_send_fragment)]
    pub fn set_max_send_fragment(&mut self, max: usize) {
        unsafe {
            ffi::SSL_CTX_set_max_send_fragment(self.as_ptr(), max);
        }
    }
}

impl SslRef {
    /// Observes this connection's protocol messages, replacing any context callback.
    /// See [`SslContextBuilder::set_msg_callback`].
    #[corresponds(SSL_set_msg_callback)]
    pub fn set_msg_callback<F>(&mut self, callback: F)
    where
        F: Fn(&SslRef, SslMessage<'_>) + 'static + Sync + Send,
    {
        unsafe {
            self.replace_ex_data(Ssl::cached_ex_index::<Arc<F>>(), Arc::new(callback));
            ffi::SSL_set_msg_callback(self.as_ptr(), Some(callbacks::raw_ssl_msg::<F>));
        }
    }

    /// Sets the cipher suite values this client offers, in order, replacing the
    /// context's list for this connection only. See
    /// [`SslContextBuilder::set_raw_cipher_list`].
    #[corresponds(RAMA_SSL_set_raw_cipher_list)]
    pub fn set_raw_cipher_list(&mut self, cipher_list: &[u16]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RAMA_SSL_set_raw_cipher_list(
                self.as_ptr(),
                cipher_list.as_ptr(),
                cipher_list.len(),
            ))
            .map(|_| ())
        }
    }

    /// Like [`SslContextBuilder::set_cipher_list`], for this connection only.
    #[corresponds(SSL_set_cipher_list)]
    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list =
            std::ffi::CString::new(cipher_list).map_err(ErrorStack::internal_error)?;
        unsafe {
            cvt(ffi::SSL_set_cipher_list(
                self.as_ptr(),
                cipher_list.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Like [`SslContextBuilder::set_strict_cipher_list`], for this connection
    /// only. A server uses it as its cipher preference, so it can pin the
    /// cipher a relay negotiated on its other leg.
    #[corresponds(SSL_set_strict_cipher_list)]
    pub fn set_strict_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list =
            std::ffi::CString::new(cipher_list).map_err(ErrorStack::internal_error)?;
        unsafe {
            cvt(ffi::SSL_set_strict_cipher_list(
                self.as_ptr(),
                cipher_list.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets this server's TLS 1.3 cipher preference: the first listed cipher
    /// the client offered is selected, otherwise the native choice applies. A
    /// relay can pin the cipher its other leg negotiated. An empty list restores
    /// the native choice. Fails for an ID that is not a TLS 1.3 cipher suite.
    ///
    /// TLS 1.2 ciphers follow [`Self::set_strict_cipher_list`].
    #[corresponds(RAMA_SSL_set_tls13_server_ciphers)]
    pub fn set_tls13_server_ciphers(&mut self, cipher_ids: &[u16]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RAMA_SSL_set_tls13_server_ciphers(
                self.as_ptr(),
                cipher_ids.as_ptr(),
                cipher_ids.len(),
            ))
            .map(|_| ())
        }
    }

    /// Selects which of the context's registered certificate compression
    /// algorithms this connection uses, in preference order: a client offers
    /// them in this order and a server prefers them in this order. An empty
    /// list disables certificate compression for this connection.
    ///
    /// Fails for an algorithm the context did not register or a repeated one.
    #[corresponds(RAMA_SSL_set_cert_compression_algs)]
    pub fn set_certificate_compression_algorithms(
        &mut self,
        algorithms: &[CertificateCompressionAlgorithm],
    ) -> Result<(), ErrorStack> {
        let ids: Vec<u16> = algorithms.iter().map(|algorithm| algorithm.0).collect();
        unsafe {
            cvt(ffi::RAMA_SSL_set_cert_compression_algs(
                self.as_ptr(),
                ids.as_ptr(),
                ids.len(),
            ))
            .map(|_| ())
        }
    }

    /// Requests signed certificate timestamps from the server.
    #[corresponds(SSL_enable_signed_cert_timestamps)]
    pub fn enable_signed_cert_timestamps(&mut self) {
        unsafe { ffi::SSL_enable_signed_cert_timestamps(self.as_ptr()) }
    }

    /// Requests an OCSP response from the server.
    #[corresponds(SSL_enable_ocsp_stapling)]
    pub fn enable_ocsp_stapling(&mut self) {
        unsafe { ffi::SSL_enable_ocsp_stapling(self.as_ptr()) }
    }

    /// Caps the plaintext size of records this connection sends, clamped to
    /// 512..=16384 bytes.
    #[corresponds(SSL_set_max_send_fragment)]
    pub fn set_max_send_fragment(&mut self, max: usize) {
        unsafe {
            ffi::SSL_set_max_send_fragment(self.as_ptr(), max);
        }
    }

    /// Sets how this client answers a TLS 1.2 server's renegotiation request.
    #[corresponds(SSL_set_renegotiate_mode)]
    pub fn set_renegotiate_mode(&mut self, mode: SslRenegotiateMode) {
        unsafe { ffi::SSL_set_renegotiate_mode(self.as_ptr(), mode.0) }
    }

    /// Frees the handshake configuration once the handshake completes, saving
    /// memory on long-lived connections. Disables renegotiation.
    #[corresponds(SSL_set_shed_handshake_config)]
    pub fn set_shed_handshake_config(&mut self, enabled: bool) {
        unsafe { ffi::SSL_set_shed_handshake_config(self.as_ptr(), enabled.into()) }
    }

    /// Lets a server avoid a TLS 1.3 interoperability bug of JDK 11 clients.
    #[corresponds(SSL_set_jdk11_workaround)]
    pub fn set_jdk11_workaround(&mut self, enabled: bool) {
        unsafe { ffi::SSL_set_jdk11_workaround(self.as_ptr(), enabled.into()) }
    }

    /// Uses the QUIC draft transport parameters codepoint (0xffa5) instead of 57.
    #[corresponds(SSL_set_quic_use_legacy_codepoint)]
    pub fn set_quic_use_legacy_codepoint(&mut self, enabled: bool) {
        unsafe { ffi::SSL_set_quic_use_legacy_codepoint(self.as_ptr(), enabled.into()) }
    }

    /// Why 0-RTT data was accepted or rejected.
    #[corresponds(SSL_get_early_data_reason)]
    #[must_use]
    pub fn early_data_reason(&self) -> SslEarlyDataReason {
        SslEarlyDataReason(unsafe { ffi::SSL_get_early_data_reason(self.as_ptr()) })
    }

    /// The peer's certificate chain, leaf included, on clients and servers alike.
    #[corresponds(SSL_get_peer_full_cert_chain)]
    #[must_use]
    pub fn peer_full_cert_chain(&self) -> Option<&StackRef<X509>> {
        unsafe {
            let ptr = ffi::SSL_get_peer_full_cert_chain(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(ptr))
            }
        }
    }

    /// Whether the connection uses the extended master secret (TLS 1.2 and
    /// earlier; always true for TLS 1.3).
    #[corresponds(SSL_get_extms_support)]
    #[must_use]
    pub fn extended_master_secret_support(&self) -> bool {
        unsafe { ffi::SSL_get_extms_support(self.as_ptr()) == 1 }
    }

    /// Whether the peer supports secure renegotiation (RFC 5746).
    #[corresponds(SSL_get_secure_renegotiation_support)]
    #[must_use]
    pub fn secure_renegotiation_support(&self) -> bool {
        unsafe { ffi::SSL_get_secure_renegotiation_support(self.as_ptr()) == 1 }
    }

    /// Seconds between the client's and server's view of a resumed ticket's age.
    #[corresponds(SSL_get_ticket_age_skew)]
    #[must_use]
    pub fn ticket_age_skew(&self) -> i32 {
        unsafe { ffi::SSL_get_ticket_age_skew(self.as_ptr()) }
    }
}

// Resolve the context that registered the callback: routing may change contexts.
pub(super) fn session_context(ssl: &SslRef) -> Option<&SslContext> {
    ssl.ex_data(*SESSION_CTX_INDEX)
}
