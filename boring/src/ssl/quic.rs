//! Transport-independent TLS handshakes for QUIC.

use super::{
    async_callbacks::TASK_WAKER_INDEX, error::InnerError, Error, ErrorCode, Ssl, SslCipherRef,
    SslRef,
};
use crate::{cvt, error::ErrorStack, ffi};
use foreign_types::{ForeignType, ForeignTypeRef};
use std::{
    fmt,
    panic::{catch_unwind, AssertUnwindSafe},
    slice,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

/// TLS encryption level, independent of QUIC packet number spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EncryptionLevel {
    Initial = 0,
    EarlyData = 1,
    Handshake = 2,
    Application = 3,
}

impl EncryptionLevel {
    fn as_raw(self) -> ffi::ssl_encryption_level_t {
        match self {
            Self::Initial => ffi::ssl_encryption_level_t::ssl_encryption_initial,
            Self::EarlyData => ffi::ssl_encryption_level_t::ssl_encryption_early_data,
            Self::Handshake => ffi::ssl_encryption_level_t::ssl_encryption_handshake,
            Self::Application => ffi::ssl_encryption_level_t::ssl_encryption_application,
        }
    }

    fn from_raw(level: ffi::ssl_encryption_level_t) -> Self {
        match level {
            ffi::ssl_encryption_level_t::ssl_encryption_initial => Self::Initial,
            ffi::ssl_encryption_level_t::ssl_encryption_early_data => Self::EarlyData,
            ffi::ssl_encryption_level_t::ssl_encryption_handshake => Self::Handshake,
            ffi::ssl_encryption_level_t::ssl_encryption_application => Self::Application,
            _ => unreachable!("BoringSSL supplied an unknown encryption level"),
        }
    }
}

/// Callbacks run synchronously inside a handshake operation. Borrowed bytes must be
/// copied before retaining them; retained secrets must be protected by the caller.
/// No callback receives the SSL object, preventing recursive handshake operations.
pub trait QuicMethod: Send + Sync + 'static {
    fn set_read_secret(
        &self,
        level: EncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), ErrorStack>;
    fn set_write_secret(
        &self,
        level: EncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), ErrorStack>;
    fn add_handshake_data(&self, level: EncryptionLevel, data: &[u8]) -> Result<(), ErrorStack>;
    fn flush_flight(&self) -> Result<(), ErrorStack>;
    fn send_alert(&self, level: EncryptionLevel, alert: u8) -> Result<(), ErrorStack>;
}

/// Failure of a QUIC handshake operation.
#[derive(Debug)]
pub enum QuicError {
    Tls(Error),
    Callback(ErrorStack),
    CallbackPanicked,
    InvalidState,
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(error) => error.fmt(f),
            Self::Callback(error) => write!(f, "QUIC callback failed: {error}"),
            Self::CallbackPanicked => f.write_str("QUIC callback panicked"),
            Self::InvalidState => f.write_str("QUIC TLS operation is invalid in the current state"),
        }
    }
}

impl std::error::Error for QuicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tls(error) => Some(error),
            Self::Callback(error) => Some(error),
            Self::CallbackPanicked | Self::InvalidState => None,
        }
    }
}

/// A successful step can still require peer input or completion of early data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeStatus {
    Complete,
    WantRead,
    EarlyData,
    EarlyDataRejected,
}

struct Callbacks {
    method: Arc<dyn QuicMethod>,
    failure: Mutex<Option<QuicError>>,
}

/// Owns a TLS session without a TLS record stream or socket.
/// Configuration must restrict the session to TLS 1.3 before construction.
pub struct QuicConnection {
    ssl: Ssl,
    callbacks: Arc<Callbacks>,
    failed: bool,
    early_data_rejected: bool,
    // Only `poll_handshake` installs a task waker, so synchronous use skips it.
    task_waker: bool,
}

impl fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicConnection")
            .field("finished", &self.ssl.is_init_finished())
            .finish_non_exhaustive()
    }
}

impl QuicConnection {
    pub fn new(mut ssl: Ssl, method: Arc<dyn QuicMethod>) -> Result<Self, ErrorStack> {
        let callbacks = Arc::new(Callbacks {
            method,
            failure: Mutex::new(None),
        });
        ssl.set_ex_data(Ssl::cached_ex_index::<Arc<Callbacks>>(), callbacks.clone());
        // The method table is static and its state is owned by SSL's ex-data.
        unsafe {
            cvt(ffi::SSL_set_quic_method(ssl.as_ptr(), &METHOD))?;
        }
        Ok(Self {
            ssl,
            callbacks,
            failed: false,
            early_data_rejected: false,
            task_waker: false,
        })
    }

    /// Select the server role before starting the handshake.
    pub fn set_accept_state(&mut self) {
        unsafe {
            ffi::SSL_set_accept_state(self.ssl.as_ptr());
        }
    }
    /// Select the client role before starting the handshake.
    pub fn set_connect_state(&mut self) {
        unsafe {
            ffi::SSL_set_connect_state(self.ssl.as_ptr());
        }
    }

    pub fn ssl(&self) -> &SslRef {
        &self.ssl
    }
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        &mut self.ssl
    }

    pub fn set_transport_parameters(&mut self, params: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_set_quic_transport_params(
                self.ssl.as_ptr(),
                params.as_ptr(),
                params.len(),
            ))
            .map(|_| ())
        }
    }

    pub fn peer_transport_parameters(&self) -> &[u8] {
        let mut ptr = std::ptr::null();
        let mut len = 0;
        unsafe {
            ffi::SSL_get_peer_quic_transport_params(self.ssl.as_ptr(), &mut ptr, &mut len);
            if len == 0 {
                &[]
            } else {
                slice::from_raw_parts(ptr, len)
            }
        }
    }

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        unsafe {
            ffi::SSL_set_early_data_enabled(self.ssl.as_ptr(), i32::from(enabled));
        }
    }

    pub fn set_early_data_context(&mut self, context: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_set_quic_early_data_context(
                self.ssl.as_ptr(),
                context.as_ptr(),
                context.len(),
            ))
            .map(|_| ())
        }
    }

    pub fn early_data_accepted(&self) -> bool {
        unsafe { ffi::SSL_early_data_accepted(self.ssl.as_ptr()) != 0 }
    }

    /// Resume TLS after reporting rejection to the transport and resetting early state.
    pub fn reset_early_data_rejection(&mut self) -> Result<(), QuicError> {
        if self.failed || !self.early_data_rejected {
            return Err(QuicError::InvalidState);
        }
        unsafe {
            ffi::SSL_reset_early_data_reject(self.ssl.as_ptr());
        }
        self.early_data_rejected = false;
        Ok(())
    }

    pub fn max_handshake_flight_len(&self, level: EncryptionLevel) -> usize {
        unsafe { ffi::SSL_quic_max_handshake_flight_len(self.ssl.as_ptr(), level.as_raw()) }
    }

    pub fn provide_data(&mut self, level: EncryptionLevel, data: &[u8]) -> Result<(), QuicError> {
        if self.failed {
            return Err(QuicError::InvalidState);
        }
        unsafe {
            ffi::ERR_clear_error();
        }
        let ret = unsafe {
            ffi::SSL_provide_quic_data(self.ssl.as_ptr(), level.as_raw(), data.as_ptr(), data.len())
        };
        self.check_boolean_result(ret)
    }

    pub fn process_post_handshake(&mut self) -> Result<(), QuicError> {
        if self.failed || !self.ssl.is_init_finished() {
            return Err(QuicError::InvalidState);
        }
        unsafe {
            ffi::ERR_clear_error();
        }
        let ret = unsafe { ffi::SSL_process_quic_post_handshake(self.ssl.as_ptr()) };
        self.check_boolean_result(ret)
    }

    /// Permanently stop TLS and drop pending asynchronous callback work now.
    ///
    /// A QUIC transport may retain this connection while it drains packets. After
    /// this call no callback factory, future or finish closure runs again and every
    /// operation returns [`QuicError::InvalidState`]. Repeated calls are harmless.
    /// This does not undo external effects or cancel independently spawned tasks.
    pub fn abort_handshake(&mut self) {
        self.failed = true;
        self.task_waker = false;
        super::async_callbacks::cancel_pending(&mut self.ssl);
    }

    /// Advance the handshake like [`Self::handshake`], registering the waker of `cx`
    /// for asynchronous certificate selection, verification, session lookup and
    /// private-key callbacks.
    ///
    /// `Pending` means such a callback is waiting: poll again once woken, without
    /// waiting for peer input. `Ready(Ok(HandshakeStatus::WantRead))` instead waits
    /// for peer CRYPTO data. While pending, the latest waker stays installed, so a
    /// [`Self::handshake`] call in between resumes the same work instead of
    /// abandoning it. The waker is released once a step no longer waits on a
    /// callback. Cancel with [`Self::abort_handshake`] or by dropping this connection.
    ///
    /// A synchronous callback that requests a retry also yields `Pending`, but
    /// nothing wakes the task for it.
    pub fn poll_handshake(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<HandshakeStatus, QuicError>> {
        let installed = self.task_waker
            && self
                .ssl
                .ex_data(*TASK_WAKER_INDEX)
                .and_then(Option::as_ref)
                .is_some_and(|waker| waker.will_wake(cx.waker()));
        if !installed && !self.failed {
            self.ssl.set_task_waker(Some(cx.waker().clone()));
            self.task_waker = true;
        }
        match self.handshake() {
            Err(QuicError::Tls(error)) if callback_pending(error.code()) => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    /// Advance the handshake.
    ///
    /// A [`QuicError::Tls`] whose [`Error::would_block`] holds reports a callback
    /// waiting on asynchronous work. It is not terminal: call again once that work
    /// is ready. Asynchronous callbacks need the task waker that
    /// [`Self::poll_handshake`] installs; without one they fail the handshake.
    pub fn handshake(&mut self) -> Result<HandshakeStatus, QuicError> {
        if self.failed {
            return Err(QuicError::InvalidState);
        }
        unsafe {
            ffi::ERR_clear_error();
        }
        let ret = unsafe { ffi::SSL_do_handshake(self.ssl.as_ptr()) };
        let result = self.check_result(ret);
        if self.task_waker {
            self.release_task_waker(&result);
        }
        result
    }

    // Out of line so synchronous handshakes keep a single untaken branch.
    #[cold]
    #[inline(never)]
    fn release_task_waker(&mut self, result: &Result<HandshakeStatus, QuicError>) {
        if !matches!(result, Err(QuicError::Tls(error)) if callback_pending(error.code())) {
            self.ssl.set_task_waker(None);
            self.task_waker = false;
        }
    }

    fn check_boolean_result(&mut self, ret: i32) -> Result<(), QuicError> {
        match self.check_result(ret)? {
            HandshakeStatus::Complete | HandshakeStatus::EarlyData => Ok(()),
            _ => {
                self.failed = true;
                Err(QuicError::InvalidState)
            }
        }
    }

    fn check_result(&mut self, ret: i32) -> Result<HandshakeStatus, QuicError> {
        if let Some(error) = self
            .callbacks
            .failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            self.failed = true;
            return Err(error);
        }
        if ret > 0 {
            return Ok(if self.ssl.is_init_finished() {
                HandshakeStatus::Complete
            } else {
                HandshakeStatus::EarlyData
            });
        }
        let code = self.ssl.error_code(ret);
        if code == ErrorCode::WANT_READ {
            return Ok(HandshakeStatus::WantRead);
        }
        if code.as_raw() == ffi::SSL_ERROR_EARLY_DATA_REJECTED {
            self.early_data_rejected = true;
            return Ok(HandshakeStatus::EarlyDataRejected);
        }
        // Retry codes describe paused callback work, not a poisoned session.
        if !callback_pending(code) {
            self.failed = true;
        }
        Err(QuicError::Tls(Error {
            code,
            cause: Some(InnerError::Ssl(ErrorStack::get())),
        }))
    }
}

// The retry codes of `Error::would_block`, excluding transport readiness.
fn callback_pending(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::WANT_X509_LOOKUP
            | ErrorCode::PENDING_CERTIFICATE
            | ErrorCode::WANT_CERTIFICATE_VERIFY
            | ErrorCode::WANT_PRIVATE_KEY_OPERATION
            | ErrorCode::PENDING_SESSION
            | ErrorCode::PENDING_TICKET
    )
}

// Each trampoline catches both user panics and conversion failures before returning to C.
unsafe fn invoke(
    ssl: *mut ffi::SSL,
    call: impl FnOnce(&dyn QuicMethod) -> Result<(), ErrorStack>,
) -> i32 {
    let ssl = unsafe { SslRef::from_ptr(ssl) };
    let Some(state) = ssl.ex_data(Ssl::cached_ex_index::<Arc<Callbacks>>()) else {
        return 0;
    };
    let result = catch_unwind(AssertUnwindSafe(|| call(state.method.as_ref())));
    let error = match result {
        Ok(Ok(())) => return 1,
        Ok(Err(error)) => QuicError::Callback(error),
        Err(payload) => {
            // A user-defined panic payload can itself panic when dropped.
            if let Err(nested) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
                std::mem::forget(nested);
            }
            QuicError::CallbackPanicked
        }
    };
    let mut failure = state.failure.lock().unwrap_or_else(|e| e.into_inner());
    if failure.is_none() {
        *failure = Some(error);
    }
    0
}

unsafe extern "C" fn read_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    len: usize,
) -> i32 {
    unsafe {
        invoke(ssl, |method| {
            method.set_read_secret(
                EncryptionLevel::from_raw(level),
                SslCipherRef::from_ptr(cipher.cast_mut()),
                slice::from_raw_parts(secret, len),
            )
        })
    }
}
unsafe extern "C" fn write_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    len: usize,
) -> i32 {
    unsafe {
        invoke(ssl, |method| {
            method.set_write_secret(
                EncryptionLevel::from_raw(level),
                SslCipherRef::from_ptr(cipher.cast_mut()),
                slice::from_raw_parts(secret, len),
            )
        })
    }
}
unsafe extern "C" fn handshake_data(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> i32 {
    unsafe {
        invoke(ssl, |method| {
            method.add_handshake_data(
                EncryptionLevel::from_raw(level),
                if len == 0 {
                    &[]
                } else {
                    slice::from_raw_parts(data, len)
                },
            )
        })
    }
}
unsafe extern "C" fn flush(ssl: *mut ffi::SSL) -> i32 {
    unsafe { invoke(ssl, |method| method.flush_flight()) }
}
unsafe extern "C" fn alert(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    alert: u8,
) -> i32 {
    unsafe {
        invoke(ssl, |method| {
            method.send_alert(EncryptionLevel::from_raw(level), alert)
        })
    }
}

static METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
    set_read_secret: Some(read_secret),
    set_write_secret: Some(write_secret),
    add_handshake_data: Some(handshake_data),
    flush_flight: Some(flush),
    send_alert: Some(alert),
};

#[cfg(test)]
mod tests;
