//! Per-connection wire settings, observation of handshake messages, and
//! negotiated-state getters that complement the context-level configuration.

use super::{
    callbacks, CertificateCompressionAlgorithm, EchGreaseShape, ExtensionType, Ssl, SslContext,
    SslContextBuilder, SslRef, SESSION_CTX_INDEX,
};
use crate::{cvt, error::ErrorStack, ffi, stack::StackRef, x509::X509};
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use std::{ffi::CStr, fmt, slice, sync::Arc};

bitflags::bitflags! {
    /// ClientHello lists that get a native GREASE value, first in the list (for
    /// extensions: first and last). This only applies to native lists: a list
    /// or extension order set explicitly is exact, and its GREASE codepoints
    /// are its only GREASE slots.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct GreaseLists: u32 {
        const CIPHERS = ffi::RAMA_SSL_GREASE_CIPHERS as u32;
        const GROUPS = ffi::RAMA_SSL_GREASE_GROUPS as u32;
        const KEY_SHARES = ffi::RAMA_SSL_GREASE_KEY_SHARES as u32;
        const VERSIONS = ffi::RAMA_SSL_GREASE_VERSIONS as u32;
        const SIGNATURE_ALGORITHMS = ffi::RAMA_SSL_GREASE_SIGNATURE_ALGORITHMS as u32;
        const EXTENSIONS = ffi::RAMA_SSL_GREASE_EXTENSIONS as u32;
    }
}

/// How GREASE values are chosen.
///
/// Fresh and seeded GREASE slots of one list get distinct values (a key share
/// must not repeat a group), and the n-th GREASE values of supported_groups and
/// key_share match, as browsers send them. A list holds at most 16 GREASE
/// slots, one per GREASE codepoint; setters reject more.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub enum GreaseValues {
    /// Random per connection, as browsers do.
    #[default]
    Fresh,
    /// Derived from a seed: reproducible, for tests and pinned variants.
    Seeded(u64),
    /// Exactly the GREASE codepoints listed, so a relay can mirror its peer.
    /// Slots without a listed codepoint stay fresh.
    Pinned,
}

/// What to do with listed values a connection cannot negotiate: unknown
/// extensions, groups, versions and signature algorithms.
///
/// Raw cipher lists are always sent as listed, and unknown key shares are
/// always dropped (they need a key), whatever the policy.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub enum UnknownValues {
    /// Leave them out.
    #[default]
    Drop,
    /// Fail the handshake, naming the value.
    Forbid,
    /// Send them as listed. If the server then selects or answers one, the
    /// handshake fails.
    Preserve,
}

/// ClientHello padding.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub enum Padding {
    /// BoringSSL's rule: over TCP, pad a 256–511 byte ClientHello to 512 bytes.
    #[default]
    Native,
    /// No padding extension.
    Off,
    /// Pad the ClientHello, handshake header included, to this many bytes when
    /// it is at least 4 bytes shorter (the padding extension's own header).
    ///
    /// Padding is placed last, before pre_shared_key. Like native padding (and
    /// browsers), it only applies to the first ClientHello: a ClientHello sent
    /// after a HelloRetryRequest is not padded.
    ToLength(u16),
}

/// The cross-cutting choices that shape one connection's ClientHello.
///
/// Lists (ciphers, groups, key shares, versions, signature algorithms and the
/// extension order) are set with their own setters, as they appear on the wire:
/// a GREASE codepoint in a list marks a GREASE slot at that position, and a set
/// list has no other GREASE values. The extension order orders: the extensions
/// it lists come first, then the other extensions this connection enables,
/// natively. Which extensions are sent follows from the connection's settings. This shape decides what those
/// GREASE slots become, which native lists get GREASE, what happens to values
/// the connection cannot negotiate, the padding, and the bodies of GREASE and
/// preserved extensions. Everything left unset keeps BoringSSL's behaviour.
/// All of it is combined when the ClientHello is written, so the order in
/// which settings are applied does not matter.
///
/// With a real ECH configuration, GREASE slots and preserved extensions of the
/// extension order do not apply (the encrypted ClientHello references the outer
/// extensions natively); the order of known extensions still does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloShape {
    grease_lists: Option<GreaseLists>,
    grease_values: GreaseValues,
    unknown_values: UnknownValues,
    padding: Padding,
    legacy_extensions: bool,
    ec_point_formats: bool,
    omit_psk_key_exchange_modes: bool,
    ech_grease: Option<EchGreaseShape>,
    extension_bodies: Vec<(ExtensionType, Vec<u8>)>,
}

impl ClientHelloShape {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Native lists that get a GREASE value, replacing the context's GREASE
    /// settings for this connection. Unset, the context's settings apply.
    pub fn set_grease_lists(&mut self, lists: GreaseLists) -> &mut Self {
        self.grease_lists = Some(lists);
        self
    }

    #[must_use]
    pub fn with_grease_lists(mut self, lists: GreaseLists) -> Self {
        self.set_grease_lists(lists);
        self
    }

    pub fn set_grease_values(&mut self, values: GreaseValues) -> &mut Self {
        self.grease_values = values;
        self
    }

    #[must_use]
    pub fn with_grease_values(mut self, values: GreaseValues) -> Self {
        self.set_grease_values(values);
        self
    }

    pub fn set_unknown_values(&mut self, values: UnknownValues) -> &mut Self {
        self.unknown_values = values;
        self
    }

    #[must_use]
    pub fn with_unknown_values(mut self, values: UnknownValues) -> Self {
        self.set_unknown_values(values);
        self
    }

    pub fn set_padding(&mut self, padding: Padding) -> &mut Self {
        self.padding = padding;
        self
    }

    #[must_use]
    pub fn with_padding(mut self, padding: Padding) -> Self {
        self.set_padding(padding);
        self
    }

    /// Sends initial EMS and renegotiation_info with a TLS 1.3 minimum to match browser hellos.
    pub fn set_legacy_extensions(&mut self, enabled: bool) -> &mut Self {
        self.legacy_extensions = enabled;
        self
    }

    #[must_use]
    pub fn with_legacy_extensions(mut self, enabled: bool) -> Self {
        self.set_legacy_extensions(enabled);
        self
    }

    /// Sends ec_point_formats, listing only uncompressed points (`[0]`), with
    /// a TLS 1.3 minimum, as clients that also speak TLS 1.2 do. Below a
    /// TLS 1.3 minimum it is always sent. A TLS 1.3 server never echoes it,
    /// so negotiation is unchanged. Once sent, the extension order orders it
    /// like any other extension.
    pub fn set_ec_point_formats(&mut self, enabled: bool) -> &mut Self {
        self.ec_point_formats = enabled;
        self
    }

    #[must_use]
    pub fn with_ec_point_formats(mut self, enabled: bool) -> Self {
        self.set_ec_point_formats(enabled);
        self
    }

    /// Omits psk_key_exchange_modes from a ClientHello offering TLS 1.3, as
    /// clients that never resume do.
    ///
    /// A pre_shared_key requires psk_key_exchange_modes (RFC 8446, section
    /// 4.2.9), so such a connection does not resume: it offers no session,
    /// TLS 1.2 ones included, and so no early data, whatever session was set
    /// or cached. A configured PSK credential fails the handshake with
    /// `NO_SUPPORTED_PSK_MODE`. Tickets a server sends anyway still reach the
    /// new-session callback; a later connection that sends the extension may
    /// resume them.
    pub fn set_omit_psk_key_exchange_modes(&mut self, omit: bool) -> &mut Self {
        self.omit_psk_key_exchange_modes = omit;
        self
    }

    #[must_use]
    pub fn with_omit_psk_key_exchange_modes(mut self, omit: bool) -> Self {
        self.set_omit_psk_key_exchange_modes(omit);
        self
    }

    /// Overrides ECH GREASE algorithms and payload length. `None` restores
    /// BoringSSL's randomized, hardware-dependent defaults. This does not
    /// enable GREASE; see [`EchGreaseShape`] for enablement, real ECH and retry
    /// behavior. This setting is independent of [`GreaseValues`].
    pub fn set_ech_grease(&mut self, shape: Option<EchGreaseShape>) -> &mut Self {
        self.ech_grease = shape;
        self
    }

    #[must_use]
    pub fn with_ech_grease(mut self, shape: Option<EchGreaseShape>) -> Self {
        self.set_ech_grease(shape);
        self
    }

    /// The body sent for extension `id` of the extension order: a GREASE
    /// codepoint or a preserved extension BoringSSL does not build. GREASE
    /// extensions default to an empty first and one-byte later body; preserved
    /// extensions default to an empty body. A later body for `id` replaces it.
    pub fn set_extension_body(&mut self, id: ExtensionType, body: impl Into<Vec<u8>>) -> &mut Self {
        let body = body.into();
        match self
            .extension_bodies
            .iter_mut()
            .find(|(known, _)| *known == id)
        {
            Some((_, existing)) => *existing = body,
            None => self.extension_bodies.push((id, body)),
        }
        self
    }

    #[must_use]
    pub fn with_extension_body(mut self, id: ExtensionType, body: impl Into<Vec<u8>>) -> Self {
        self.set_extension_body(id, body);
        self
    }
}

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
    // The native enum is `i32` on MSVC and `u32` elsewhere.
    #[allow(clippy::unnecessary_cast)]
    pub fn as_raw(&self) -> u32 {
        self.0 .0 as u32
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
    /// The plaintext ClientHelloInner that ECH encrypts, handshake header and
    /// reconstructed outer extensions included.
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
    /// handshake, capped at 16; zero disables tickets. A connection reads it
    /// from its session context, the one it was created with, even after a
    /// context switch; [`SslRef::set_num_tickets`] overrides it per connection.
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
            let replaced =
                self.replace_ex_data(Ssl::cached_ex_index::<Arc<F>>(), Arc::new(callback));
            ffi::SSL_set_msg_callback(self.as_ptr(), Some(callbacks::raw_ssl_msg::<F>));
            crate::unwind::drop_contained(replaced);
        }
    }

    /// Sets the cipher suite values this client offers, in order, replacing the
    /// context's list for this connection only. See
    /// [`SslContextBuilder::set_raw_cipher_list`]: the list is exact, and its
    /// GREASE codepoints are its only GREASE slots.
    ///
    /// A client must set it before writing its ClientHello, a server before its
    /// handshake completes.
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
    ///
    /// A client must set it before writing its ClientHello, a server before its
    /// handshake completes.
    #[corresponds(SSL_set_cipher_list)]
    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list =
            std::ffi::CString::new(cipher_list).map_err(ErrorStack::internal_error)?;
        self.check_wire_settings_mutable()?;
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
    ///
    /// A client must set it before writing its ClientHello, a server before its
    /// handshake completes.
    #[corresponds(SSL_set_strict_cipher_list)]
    pub fn set_strict_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list =
            std::ffi::CString::new(cipher_list).map_err(ErrorStack::internal_error)?;
        self.check_wire_settings_mutable()?;
        unsafe {
            cvt(ffi::SSL_set_strict_cipher_list(
                self.as_ptr(),
                cipher_list.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    pub(super) fn check_wire_settings_mutable(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::RAMA_SSL_can_set_wire_settings(self.as_ptr())).map(|_| ()) }
    }

    /// Orders this server's response extensions within its ServerHello and
    /// EncryptedExtensions: listed extensions first, in order, then the rest
    /// natively. A relay can mirror the order its origin used. Only what the
    /// server answers is ordered; extensions the client did not send are never
    /// added. It takes effect when set before the ServerHello is written, for
    /// example from the early ClientHello callback. Fails once the handshake
    /// completed or for more than 256 IDs.
    #[corresponds(RAMA_SSL_set_server_extension_order)]
    pub fn set_server_extension_order(&mut self, ids: &[u16]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RAMA_SSL_set_server_extension_order(
                self.as_ptr(),
                ids.as_ptr(),
                ids.len(),
            ))
            .map(|_| ())
        }
    }

    /// Sets this server's TLS 1.3 cipher preference: the first listed cipher
    /// the client offered is selected, otherwise the native choice applies. An
    /// empty list restores the native choice. To accept only these ciphers, see
    /// [`Self::set_strict_tls13_server_ciphers`].
    ///
    /// Has no effect on a client. Fails once the handshake completed or for an
    /// ID that is not a TLS 1.3 cipher suite. TLS 1.2 ciphers follow
    /// [`Self::set_strict_cipher_list`].
    #[corresponds(RAMA_SSL_set_tls13_server_ciphers)]
    pub fn set_tls13_server_ciphers(&mut self, cipher_ids: &[u16]) -> Result<(), ErrorStack> {
        self.tls13_server_ciphers(cipher_ids, false)
    }

    /// Like [`Self::set_tls13_server_ciphers`], but the handshake fails when the
    /// client offered none of these ciphers. A relay pins the cipher its other
    /// leg negotiated this way. Fails for an empty list.
    #[corresponds(RAMA_SSL_set_tls13_server_ciphers)]
    pub fn set_strict_tls13_server_ciphers(
        &mut self,
        cipher_ids: &[u16],
    ) -> Result<(), ErrorStack> {
        self.tls13_server_ciphers(cipher_ids, true)
    }

    fn tls13_server_ciphers(&mut self, cipher_ids: &[u16], strict: bool) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RAMA_SSL_set_tls13_server_ciphers(
                self.as_ptr(),
                cipher_ids.as_ptr(),
                cipher_ids.len(),
                strict.into(),
            ))
            .map(|_| ())
        }
    }

    /// Sets how many TLS 1.3 session tickets this server issues after its
    /// handshake, capped at 16, replacing
    /// [`SslContextBuilder::set_num_tickets`] for this connection; zero
    /// disables tickets. Has no effect on a client. Fails once the handshake
    /// completed.
    #[corresponds(RAMA_SSL_set_num_tickets)]
    pub fn set_num_tickets(&mut self, num_tickets: usize) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::RAMA_SSL_set_num_tickets(self.as_ptr(), num_tickets)).map(|_| ()) }
    }

    /// Selects which of the context's registered certificate compression
    /// algorithms this connection uses, in preference order: a client offers
    /// them in this order, and only accepts certificates compressed with one
    /// of them; a server prefers them in this order. An empty list disables
    /// certificate compression for this connection.
    ///
    /// Fails for an algorithm the context did not register or a repeated one,
    /// for a client once it wrote its ClientHello, and for a server once its
    /// handshake completed.
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

    /// Applies a [`ClientHelloShape`] to this client before its handshake
    /// starts, replacing any shape applied earlier as a whole.
    ///
    /// Everything is validated first: on error, nothing changes. Fails for a
    /// server, once the ClientHello was written, for an extension body
    /// BoringSSL builds itself, or for a body over 65535 bytes.
    #[corresponds(RAMA_SSL_set_client_hello_shape)]
    pub fn set_client_hello_shape(&mut self, shape: &ClientHelloShape) -> Result<(), ErrorStack> {
        let (grease_values, grease_seed) = match shape.grease_values {
            GreaseValues::Fresh => (ffi::RAMA_SSL_GREASE_VALUES_FRESH, 0),
            GreaseValues::Seeded(seed) => (ffi::RAMA_SSL_GREASE_VALUES_SEEDED, seed),
            GreaseValues::Pinned => (ffi::RAMA_SSL_GREASE_VALUES_PINNED, 0),
        };
        let unknown_values = match shape.unknown_values {
            UnknownValues::Drop => ffi::RAMA_SSL_UNKNOWN_DROP,
            UnknownValues::Forbid => ffi::RAMA_SSL_UNKNOWN_FORBID,
            UnknownValues::Preserve => ffi::RAMA_SSL_UNKNOWN_PRESERVE,
        };
        let (padding, padding_length) = match shape.padding {
            Padding::Native => (ffi::RAMA_SSL_PADDING_NATIVE, 0),
            Padding::Off => (ffi::RAMA_SSL_PADDING_OFF, 0),
            Padding::ToLength(length) => (ffi::RAMA_SSL_PADDING_TO_LENGTH, usize::from(length)),
        };
        let bodies: Vec<ffi::RAMA_SSL_EXTENSION_BODY> = shape
            .extension_bodies
            .iter()
            .map(|(id, body)| ffi::RAMA_SSL_EXTENSION_BODY {
                id: id.0,
                body: body.as_ptr(),
                len: body.len(),
            })
            .collect();
        let native = ffi::RAMA_SSL_CLIENT_HELLO_SHAPE {
            grease_lists_set: shape.grease_lists.is_some().into(),
            grease_lists: shape.grease_lists.map_or(0, |lists| lists.bits()),
            grease_values: grease_values as _,
            grease_seed,
            unknown_values: unknown_values as _,
            padding: padding as _,
            padding_length,
            extension_bodies: bodies.as_ptr(),
            num_extension_bodies: bodies.len(),
            legacy_extensions: shape.legacy_extensions.into(),
            ech_grease_kdf_id: shape.ech_grease.map_or(0, |s| s.cipher_suite().ids().0),
            ech_grease_aead_id: shape.ech_grease.map_or(0, |s| s.cipher_suite().ids().1),
            ech_grease_payload_len: shape.ech_grease.map_or(0, |s| s.payload_len()),
            ec_point_formats: shape.ec_point_formats.into(),
            omit_psk_key_exchange_modes: shape.omit_psk_key_exchange_modes.into(),
        };
        unsafe { cvt(ffi::RAMA_SSL_set_client_hello_shape(self.as_ptr(), &native)).map(|_| ()) }
    }

    /// Sets the groups this client lists in supported_groups, exactly as on the
    /// wire, repeats included: GREASE codepoints are GREASE slots, and groups it cannot negotiate
    /// follow [`UnknownValues`]. The supported ones also become the groups this
    /// connection negotiates. Fails if none is supported. A later
    /// [`Self::set_curves`] or [`Self::set_curves_list`] replaces this list.
    #[corresponds(RAMA_SSL_set_raw_supported_groups)]
    pub fn set_raw_supported_groups(&mut self, groups: &[u16]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RAMA_SSL_set_raw_supported_groups(
                self.as_ptr(),
                groups.as_ptr(),
                groups.len(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the groups this client sends key shares for, in order, exactly as
    /// on the wire: GREASE codepoints are GREASE key shares. A group must also
    /// be a supported group; others are never sent (they need a key), whatever
    /// the [`UnknownValues`] policy, and later repeats of a group are dropped
    /// (RFC 8446 forbids them). With no key share left, the client sends an
    /// empty list, asking the server for a HelloRetryRequest.
    #[corresponds(RAMA_SSL_set_raw_key_shares)]
    pub fn set_raw_key_shares(&mut self, groups: &[u16]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RAMA_SSL_set_raw_key_shares(
                self.as_ptr(),
                groups.as_ptr(),
                groups.len(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the versions this client lists in supported_versions, exactly as
    /// on the wire, repeats included: GREASE codepoints are GREASE slots, and versions outside the
    /// configured minimum and maximum follow [`UnknownValues`].
    #[corresponds(RAMA_SSL_set_raw_supported_versions)]
    pub fn set_raw_supported_versions(&mut self, versions: &[u16]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RAMA_SSL_set_raw_supported_versions(
                self.as_ptr(),
                versions.as_ptr(),
                versions.len(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the signature algorithms this client lists, exactly as on the wire,
    /// repeats included (Safari repeats one): GREASE codepoints are GREASE slots, and algorithms BoringSSL does not
    /// implement follow [`UnknownValues`]. The server's choice is still checked
    /// against [`Self::set_verify_algorithm_prefs`].
    #[corresponds(RAMA_SSL_set_raw_signature_algorithms)]
    pub fn set_raw_signature_algorithms(&mut self, algorithms: &[u16]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RAMA_SSL_set_raw_signature_algorithms(
                self.as_ptr(),
                algorithms.as_ptr(),
                algorithms.len(),
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

    /// The IANA ID of the group the handshake negotiated, if any: the raw value
    /// behind [`Self::curve`], including groups without a name here.
    #[corresponds(SSL_get_group_id)]
    #[must_use]
    pub fn group_id(&self) -> Option<u16> {
        match unsafe { ffi::SSL_get_group_id(self.as_ptr()) } {
            0 => None,
            id => Some(id),
        }
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
