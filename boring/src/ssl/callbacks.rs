//! `extern "C"` trampolines that BoringSSL calls into Rust callbacks.
//!
//! # Trampoline contract
//!
//! Each trampoline is registered through the setter(s) or method table named
//! in its `# Safety` section. BoringSSL, as caller, must ensure that:
//!
//! - object arguments are non-null, properly aligned, initialized native objects
//!   that remain live for the call. Access through the trampoline-created wrappers
//!   must not conflict with accesses on another thread or through other Rust
//!   references. The driving native frame is suspended while the callback runs;
//!   it must not invalidate callback-borrowed input during reentrant operations;
//! - the owner and ex_data slot named by the individual contract contain the
//!   specified concrete callback or method type. Context callbacks use
//!   `SslContext::cached_ex_index`, connection callbacks use their stated
//!   `Ssl::cached_ex_index` or dedicated index, and credentials use
//!   `SslCredential::cached_ex_index`. Built context slots are immutable;
//!   replaceable connection callbacks are retained independently before user code;
//! - nonempty input buffers contain initialized bytes in a single live allocation,
//!   are at most `isize::MAX` bytes long, and remain readable and unmodified for
//!   the entire callback borrow, including during user code. Empty input buffers
//!   may have any pointer and are normalized with `slice_or_empty`;
//! - each nonempty output is non-null, properly aligned for its pointee, and readable and
//!   writable over its entire stated extent in one live allocation, with byte
//!   size at most `isize::MAX`. Except for access through the callback's derived
//!   references, outputs are exclusively accessible for the call and are disjoint
//!   from inputs, other outputs, and callback-accessible object storage. Outputs
//!   may begin uninitialized only when they are written before being read or
//!   exposed to safe user code. Empty byte-buffer outputs may have any pointer
//!   and are normalized by `zeroed_out_buf`; scalar outputs are never empty;
//! - C-string inputs are initialized through a terminating NUL in one live
//!   allocation, within `isize::MAX` bytes, and remain unmodified for the call.
//!   They are non-null unless the individual contract explicitly permits null.
//!
//! A native context passed to `raw_remove_session` may be undergoing destruction.
//! Its ex_data is available until that callback returns, but it must not be
//! retained or exposed to user code as an ordinary `SslContextRef`.
//!
//! The trampolines never let a panic unwind into C (`unwind::catch`).
#![forbid(unsafe_op_in_unsafe_fn)]

use super::async_callbacks::{cancel_pending, cancel_session_lookup};
use super::{
    AlpnError, CertificateCompressor, ClientHello, GetSessionPendingError, PrivateKeyMethod,
    PrivateKeyMethodError, SelectCertError, SniError, Ssl, SslAlert, SslContext, SslContextRef,
    SslInfoCallbackAlert, SslInfoCallbackMode, SslInfoCallbackValue, SslRef, SslSession,
    SslSessionRef, SslSignatureAlgorithm, SslVerifyError, CERT_COMPRESSED_INDEX,
    CERT_DECOMPRESSED_INDEX, SESSION_CTX_INDEX,
};
use crate::error::ErrorStack;
use crate::ffi;
use crate::hmac::HmacCtxRef;
use crate::libc_types::{c_char, c_int, c_uchar, c_uint, c_void};
use crate::ssl::TicketKeyCallbackResult;
use crate::symm::CipherCtxRef;
use crate::unwind;
use crate::x509::{X509StoreContext, X509StoreContextRef, X509VerifyError};
use foreign_types::ForeignType;
use foreign_types::ForeignTypeRef;
use std::ffi::CStr;
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::slice;
use std::str;
use std::sync::Arc;

/// Zeroes a native output buffer and returns it as a mutable slice.
///
/// Native code often passes uninitialized output buffers to callbacks; safe
/// user code may read any `&mut [u8]` it receives, so the bytes must be
/// initialized first.
///
/// # Safety
///
/// If `len > 0`, the caller must ensure that `buf` is non-null and spans `len`
/// readable and writable bytes in one allocation that stays live for all of
/// `'a`, that `len` does not exceed `isize::MAX`, and that during `'a` those
/// bytes are only accessed through the returned slice. The bytes may start
/// uninitialized.
///
/// If these hold, the result is `&mut []` when `len == 0` or `buf` is null, and
/// otherwise the `len` zeroed bytes at `buf`.
unsafe fn zeroed_out_buf<'a>(buf: *mut u8, len: usize) -> &'a mut [u8] {
    if buf.is_null() || len == 0 {
        return &mut [];
    }
    // SAFETY: `buf` is non-null and valid for writes of `len` bytes (`# Safety`).
    unsafe { ptr::write_bytes(buf, 0, len) };
    // SAFETY: the `len` bytes are now initialized, valid for reads and writes,
    // and exclusively ours for `'a` (`# Safety`).
    unsafe { slice::from_raw_parts_mut(buf, len) }
}

/// # Safety
///
/// The [trampoline contract](self) for `SslContextBuilder::set_verify_callback`.
/// `x509_ctx` is the store context being verified, exclusively accessible for
/// this call, with the `SSL` at `X509StoreContext::ssl_idx`. The SSL's original
/// session context (`SESSION_CTX_INDEX`) holds `F`.
pub(super) unsafe extern "C" fn raw_verify<F>(
    preverify_ok: c_int,
    x509_ctx: *mut ffi::X509_STORE_CTX,
) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

            let ssl_idx =
                X509StoreContext::ssl_idx().expect("BUG: store context ssl index missing");
            let verify_idx = SslContext::cached_ex_index::<F>();

            // Own a reference to the context holding the callback, so the
            // callback stays alive for the whole call even if the user code
            // it runs changes which context the connection uses.
            let ssl_context = unwind::LeakOnUnwind::new(
                ctx.ex_data(ssl_idx)
                    .and_then(|ssl| ssl.ex_data(*SESSION_CTX_INDEX))
                    .cloned(),
            );
            let Some(verify) = ssl_context.as_ref().and_then(|c| c.ex_data(verify_idx)) else {
                return 0;
            };
            // SAFETY: `verify` lives in the ex_data of `ssl_context`, which this
            // frame owns a reference to until the call returns; the ex_data of
            // a built context is never replaced. Widening the borrow only
            // detaches it from the `ctx` borrow so `ctx` can be passed as `&mut`.
            let verify = unsafe { &*std::ptr::from_ref::<F>(verify) };

            c_int::from(verify(preverify_ok != 0, ctx))
        },
        // SAFETY: the trampoline contract keeps the store context alive and
        // exclusively accessible after the unwound user callback releases it.
        |message| unsafe { verify_panicked(x509_ctx, message) },
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_custom_verify_callback`. `out_alert` is valid for
/// a one-byte write. The session context (`SESSION_CTX_INDEX`) holds `F`.
pub(super) unsafe extern "C" fn raw_custom_verify<F>(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
) -> ffi::ssl_verify_result_t
where
    F: Fn(&mut SslRef) -> Result<(), SslVerifyError> + 'static + Sync + Send,
{
    let callback = |ssl: &mut SslRef| {
        let custom_verify_idx = SslContext::cached_ex_index::<F>();

        // SSL_set_SSL_CTX preserves the verification callback installed at SSL_new.
        let ssl_context = unwind::LeakOnUnwind::new(ssl.ex_data(*SESSION_CTX_INDEX).cloned());
        let callback = ssl_context
            .as_ref()
            .and_then(|ctx| ctx.ex_data(custom_verify_idx))
            .ok_or(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?;

        callback(ssl)
    };

    unsafe { raw_custom_verify_callback(ssl, out_alert, callback) }
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_cert_verify_callback`. `x509_ctx` is the store
/// context being verified, with the `SSL` at `X509StoreContext::ssl_idx`, and
/// the connection's current context (`SSL_get_SSL_CTX`) holds `F`.
pub(super) unsafe extern "C" fn raw_cert_verify<F>(
    x509_ctx: *mut ffi::X509_STORE_CTX,
    _arg: *mut c_void,
) -> c_int
where
    F: Fn(&mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

            let ssl_idx =
                X509StoreContext::ssl_idx().expect("BUG: store context ssl index missing");
            let verify_idx = SslContext::cached_ex_index::<F>();

            // BoringSSL dispatches this callback from the connection's current
            // context (`ssl->ctx`), which the connection may hold the last
            // reference to. Own a reference so the callback outlives the call.
            let ssl_context = unwind::LeakOnUnwind::new(
                ctx.ex_data(ssl_idx)
                    .expect("BUG: store context missing ssl")
                    .ssl_context()
                    .to_owned(),
            );
            let verify = ssl_context
                .ex_data(verify_idx)
                .expect("BUG: verify callback missing");

            // SAFETY: `verify` lives in the ex_data of `ssl_context`, which this
            // frame owns a reference to until the call returns; the ex_data of
            // a built context is never replaced. Widening the borrow only
            // detaches it from the `ctx` borrow so `ctx` can be passed as `&mut`.
            let verify = unsafe { &*std::ptr::from_ref::<F>(verify) };

            c_int::from(verify(ctx))
        },
        // SAFETY: the trampoline contract keeps the store context alive and
        // exclusively accessible after the unwound user callback releases it.
        |message| unsafe { verify_panicked(x509_ctx, message) },
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslRef::set_custom_verify_callback`. `out_alert` is valid for a one-byte
/// write. The connection's own ex_data holds `Arc<F>`.
pub(super) unsafe extern "C" fn ssl_raw_custom_verify<F>(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
) -> ffi::ssl_verify_result_t
where
    F: Fn(&mut SslRef) -> Result<(), SslVerifyError> + 'static + Sync + Send,
{
    let callback = |ssl: &mut SslRef| {
        let callback = unwind::LeakOnUnwind::new(
            ssl.ex_data(Ssl::cached_ex_index::<Arc<F>>())
                .cloned()
                .ok_or(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR))?,
        );

        callback(ssl)
    };

    unsafe { raw_custom_verify_callback(ssl, out_alert, callback) }
}

/// # Safety
///
/// Shared body of the custom-verify trampolines: `ssl` and `out_alert` must
/// satisfy the contract of the calling trampoline.
unsafe fn raw_custom_verify_callback(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
    callback: impl FnOnce(&mut SslRef) -> Result<(), SslVerifyError>,
) -> ffi::ssl_verify_result_t {
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
            let out_alert = unsafe { &mut *out_alert };

            match callback(ssl) {
                Ok(()) => ffi::ssl_verify_result_t::ssl_verify_ok,
                Err(SslVerifyError::Invalid(alert)) => {
                    *out_alert = alert.0 as u8;

                    ffi::ssl_verify_result_t::ssl_verify_invalid
                }
                Err(SslVerifyError::Retry) => ffi::ssl_verify_result_t::ssl_verify_retry,
            }
        },
        |message| {
            unwind::report(message);
            // SAFETY: the panicked callback no longer borrows the connection.
            cancel_pending(unsafe { SslRef::from_ptr_mut(ssl) });
            unsafe { *out_alert = SslAlert::INTERNAL_ERROR.0 as u8 };
            ffi::ssl_verify_result_t::ssl_verify_invalid
        },
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_psk_client_callback`. `hint` is null or a
/// NUL-terminated string; `identity` is writable for `max_identity_len` bytes
/// and `psk` for `max_psk_len` bytes, in disjoint buffers that may start
/// uninitialized. The session context holds `F`. Returns `0` or a PSK length
/// of at most `max_psk_len`, with `identity` NUL-terminated.
pub(super) unsafe extern "C" fn raw_client_psk<F>(
    ssl_ptr: *mut ffi::SSL,
    hint: *const c_char,
    identity: *mut c_char,
    max_identity_len: c_uint,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint
where
    F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8], &mut [u8]) -> Result<usize, ErrorStack>
        + 'static
        + Sync
        + Send,
{
    unwind::catch_reported(0, || {
        // SAFETY: guaranteed by the caller under the module's trampoline contract.

        let ssl = unsafe { SslRef::from_ptr_mut(ssl_ptr) };

        let hint = if hint.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(hint) }.to_bytes())
        };

        // Give the callback mutable slices into which it can write the identity and psk.
        //
        // SAFETY: BoringSSL passes `identity` valid for `max_identity_len`
        // bytes and `psk` valid for `max_psk_len` bytes, both stack buffers of
        // the handshake that outlive this call; `zeroed_out_buf` initializes
        // them before safe code can read them.
        //
        // The identity is read back as a NUL-terminated C string (`strdup`);
        // its final byte is forced to NUL after the callback returns, so a
        // callback filling the whole slice still leaves a terminated string.
        let identity_sl =
            unsafe { zeroed_out_buf(identity.cast::<u8>(), max_identity_len as usize) };
        let psk_sl = unsafe { zeroed_out_buf(psk, max_psk_len as usize) };
        let psk_cap = psk_sl.len();

        // SSL_new copies this callback; routing does not replace it.
        let ssl_context = unwind::LeakOnUnwind::new(ssl.ex_data(*SESSION_CTX_INDEX).cloned());
        let Some(callback) = ssl_context
            .as_ref()
            .and_then(|ctx| ctx.ex_data(SslContext::cached_ex_index::<F>()))
        else {
            return 0;
        };

        let result = callback(ssl, hint, &mut *identity_sl, psk_sl);
        if let Some(last) = identity_sl.last_mut() {
            *last = 0;
        }

        match result {
            // BoringSSL only `assert`s this bound on the client, so a larger
            // length would make release builds read past the PSK buffer.
            // `psk_len <= max_psk_len`, so the cast is lossless.
            Ok(psk_len) if psk_len <= psk_cap => psk_len as u32,
            Ok(psk_len) => {
                ErrorStack::internal_error_string(format!(
                    "PSK client callback returned {psk_len} bytes for a {psk_cap}-byte buffer"
                ))
                .put();
                0
            }
            Err(e) => {
                e.put();
                0
            }
        }
    })
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_psk_server_callback`. `identity` is null or a
/// NUL-terminated string; `psk` is writable for `max_psk_len` bytes and may
/// start uninitialized. The session context holds `F`. Returns `0` or a PSK
/// length of at most `max_psk_len`.
pub(super) unsafe extern "C" fn raw_server_psk<F>(
    ssl: *mut ffi::SSL,
    identity: *const c_char,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint
where
    F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8]) -> Result<usize, ErrorStack>
        + 'static
        + Sync
        + Send,
{
    unwind::catch_reported(0, || {
        // SAFETY: guaranteed by the caller under the module's trampoline contract.

        let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

        let identity = if identity.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(identity) }.to_bytes())
        };

        // Give the callback mutable slices into which it can write the psk.
        //
        // SAFETY: BoringSSL passes `psk` valid for `max_psk_len` bytes, an
        // uninitialized stack buffer that `zeroed_out_buf` initializes.
        let psk_sl = unsafe { zeroed_out_buf(psk, max_psk_len as usize) };
        let psk_cap = psk_sl.len();

        // SSL_new copies this callback; routing does not replace it.
        let ssl_context = unwind::LeakOnUnwind::new(ssl.ex_data(*SESSION_CTX_INDEX).cloned());
        let Some(callback) = ssl_context
            .as_ref()
            .and_then(|ctx| ctx.ex_data(SslContext::cached_ex_index::<F>()))
        else {
            return 0;
        };

        match callback(ssl, identity, psk_sl) {
            // `psk_len <= max_psk_len`, so the cast is lossless.
            Ok(psk_len) if psk_len <= psk_cap => psk_len as u32,
            Ok(psk_len) => {
                ErrorStack::internal_error_string(format!(
                    "PSK server callback returned {psk_len} bytes for a {psk_cap}-byte buffer"
                ))
                .put();
                0
            }
            Err(e) => {
                e.put();
                0
            }
        }
    })
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslRef::set_verify_callback`. `x509_ctx` is the store context being
/// verified, with the `SSL` at `X509StoreContext::ssl_idx`; that connection's
/// own ex_data holds `Arc<F>`.
pub(super) unsafe extern "C" fn ssl_raw_verify<F>(
    preverify_ok: c_int,
    x509_ctx: *mut ffi::X509_STORE_CTX,
) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

            let ssl_idx =
                X509StoreContext::ssl_idx().expect("BUG: store context ssl index missing");

            // The callback is stored per connection as an `Arc<F>`; cloning it
            // keeps it alive even if the connection's callback is replaced
            // while it runs.
            let callback = unwind::LeakOnUnwind::new(
                ctx.ex_data(ssl_idx)
                    .expect("BUG: store context missing ssl")
                    .ex_data(Ssl::cached_ex_index::<Arc<F>>())
                    .expect("BUG: ssl verify callback missing")
                    .clone(),
            );

            c_int::from(callback(preverify_ok != 0, ctx))
        },
        // SAFETY: the trampoline contract keeps the store context alive and
        // exclusively accessible after the unwound user callback releases it.
        |message| unsafe { verify_panicked(x509_ctx, message) },
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_servername_callback`. `al` is valid for reads and
/// writes of one `c_int`; `arg` is the servername arg that setter stored, a
/// pointer to the `F` in the ex_data of the context BoringSSL dispatches from
/// (the connection's current context or its session context).
pub(super) unsafe extern "C" fn raw_sni<F>(
    ssl: *mut ffi::SSL,
    al: *mut c_int,
    arg: *mut c_void,
) -> c_int
where
    F: Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError> + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
            let al = unsafe { &mut *al };

            // `arg` points to the `F` in the ex_data of the context BoringSSL
            // dispatched from: the connection's current context (`ssl->ctx`)
            // if that has an SNI callback, otherwise the session context.
            // Keep the current context alive for the whole call: the callback
            // may switch the connection to another context, which would
            // otherwise free the current one (and this callback) mid-call. The
            // session context is kept alive by the connection itself.
            let _current_context = unwind::LeakOnUnwind::new(ssl.ssl_context().to_owned());

            // SAFETY: `arg` was set by `SslContextBuilder::set_servername_callback`
            // to the `F` stored in that context's ex_data, which is never
            // replaced once the context is built. Whichever context dispatched
            // this call is kept alive until it returns (see above), so the
            // reference is valid for the whole call.
            let callback = unsafe { &*(arg as *const F) };

            let mut alert = SslAlert(*al);

            let r = callback(ssl, &mut alert);

            *al = alert.0;

            match r {
                Ok(()) => ffi::SSL_TLSEXT_ERR_OK,
                Err(e) => e.0,
            }
        },
        |message| {
            unwind::report(message);
            unsafe { *al = SslAlert::INTERNAL_ERROR.0 };
            ffi::SSL_TLSEXT_ERR_ALERT_FATAL
        },
    )
}

/// # Safety
///
/// `ptr` must be non-null, aligned and valid for writes of one `T` for `'a`,
/// with no other access during `'a`. The pointee may be uninitialized.
unsafe fn to_uninit<'a, T: 'a>(ptr: *mut T) -> &'a mut MaybeUninit<T> {
    assert!(!ptr.is_null());
    unsafe { &mut *ptr.cast::<MaybeUninit<T>>() }
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_ticket_key_callback`. `key_name` (16 bytes) and
/// `iv` (`EVP_MAX_IV_LENGTH` bytes) are writable; `evp_ctx` and `hmac_ctx` are
/// live, initialized but unkeyed contexts that nothing else accesses during
/// the call. The session context (`SESSION_CTX_INDEX`) holds `F`.
/// `encrypt` is 0 or 1. For 0, both arrays contain initialized input bytes;
/// for 1, they may be uninitialized and this trampoline initializes them.
/// `F` satisfies `SslContextBuilder::set_ticket_key_callback`'s success-context
/// obligations: successful callbacks leave usable cipher and HMAC contexts.
pub(super) unsafe extern "C" fn raw_ticket_key<F>(
    ssl: *mut ffi::SSL,
    key_name: *mut u8,
    iv: *mut u8,
    evp_ctx: *mut ffi::EVP_CIPHER_CTX,
    hmac_ctx: *mut ffi::HMAC_CTX,
    encrypt: c_int,
) -> c_int
where
    F: Fn(
            &SslRef,
            &mut [u8; 16],
            &mut [u8; ffi::EVP_MAX_IV_LENGTH as usize],
            &mut CipherCtxRef,
            &mut HmacCtxRef,
            bool,
        ) -> TicketKeyCallbackResult
        + 'static
        + Sync
        + Send,
{
    unwind::catch_reported(-1, || {
        // SAFETY: guaranteed by the caller under the module's trampoline contract.
        let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

        // BoringSSL invokes the ticket callback from the original session context.
        let ssl_context = unwind::LeakOnUnwind::new(ssl.ex_data(*SESSION_CTX_INDEX).cloned());
        let Some(callback) = ssl_context
            .as_ref()
            .and_then(|ctx| ctx.ex_data(SslContext::cached_ex_index::<F>()))
        else {
            return -1;
        };

        // SAFETY: the callback guarantees that key_name is 16 bytes
        let key_name =
            unsafe { to_uninit(key_name.cast::<[u8; ffi::SSL_TICKET_KEY_NAME_LEN as usize]>()) };

        // SAFETY: the callback provides 16 bytes iv
        //
        // https://github.com/google/boringssl/blob/main/ssl/ssl_session.cc#L331
        let iv = unsafe { to_uninit(iv.cast::<[u8; ffi::EVP_MAX_IV_LENGTH as usize]>()) };

        // When encrypting a new ticket, encrypt will be one.
        let encrypt = encrypt == 1;

        // Zero-initialize the key_name and iv, since the application is expected to populate these
        // fields in the encrypt mode.
        if encrypt {
            *key_name = MaybeUninit::zeroed();
            *iv = MaybeUninit::zeroed();
        }
        let key_name = unsafe { key_name.assume_init_mut() };
        let iv = unsafe { iv.assume_init_mut() };

        // The EVP_CIPHER_CTX and HMAC_CTX are owned by boringSSL.
        let evp_ctx = unsafe { CipherCtxRef::from_ptr_mut(evp_ctx) };
        let hmac_ctx = unsafe { HmacCtxRef::from_ptr_mut(hmac_ctx) };

        callback(ssl, key_name, iv, evp_ctx, hmac_ctx, encrypt).into()
    })
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_alpn_select_callback`. `out` and `outlen` are
/// valid for one write each; on success `*out` points into `inbuf` or to
/// memory that outlives the handshake, with `1..=255` bytes. The connection's
/// current context holds `F`.
pub(super) unsafe extern "C" fn raw_alpn_select<F>(
    ssl: *mut ffi::SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uchar,
    inbuf: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int
where
    F: for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError> + 'static + Sync + Send,
{
    unwind::catch_reported(ffi::SSL_TLSEXT_ERR_ALERT_FATAL, || {
        // SAFETY: guaranteed by the caller under the module's trampoline contract.
        let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
        let protos = unsafe { crate::util::slice_or_empty(inbuf, inlen as usize) };
        let out = unsafe { &mut *out };
        let outlen = unsafe { &mut *outlen };

        let ssl_context = unwind::LeakOnUnwind::new(ssl.ssl_context().to_owned());
        let callback = ssl_context
            .ex_data(SslContext::cached_ex_index::<F>())
            .expect("BUG: alpn callback missing");

        match callback(ssl, protos) {
            // The selection is reported through a one-byte length, and an
            // empty protocol is invalid; anything else would be truncated.
            Ok(proto) if !proto.is_empty() && proto.len() <= usize::from(c_uchar::MAX) => {
                *out = proto.as_ptr();
                // Lossless: `proto.len() <= c_uchar::MAX` was checked above.
                *outlen = proto.len() as c_uchar;

                ffi::SSL_TLSEXT_ERR_OK
            }
            Ok(proto) => {
                ErrorStack::internal_error_string(format!(
                    "ALPN select callback returned a {}-byte protocol (must be 1..=255 bytes)",
                    proto.len()
                ))
                .put();
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
            Err(e) => e.0,
        }
    })
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_select_certificate_callback`. `client_hello`
/// points to a live `SSL_CLIENT_HELLO` whose buffers outlive the call. The
/// connection's current context holds `F`.
pub(super) unsafe extern "C" fn raw_select_cert<F>(
    client_hello: *const ffi::SSL_CLIENT_HELLO,
) -> ffi::ssl_select_cert_result_t
where
    F: Fn(ClientHello<'_>) -> Result<(), SelectCertError> + Sync + Send + 'static,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let client_hello = ClientHello(unsafe { &*client_hello });

            let ssl_context =
                unwind::LeakOnUnwind::new(client_hello.ssl().ssl_context().to_owned());
            let callback = ssl_context
                .ex_data(SslContext::cached_ex_index::<F>())
                .expect("BUG: select cert callback missing");

            match callback(client_hello) {
                Ok(()) => ffi::ssl_select_cert_result_t::ssl_select_cert_success,
                Err(e) => e.0,
            }
        },
        |message| {
            unwind::report(message);
            // SAFETY: the panicked callback no longer borrows the connection.
            cancel_pending(unsafe { SslRef::from_ptr_mut((*client_hello).ssl) });
            ffi::ssl_select_cert_result_t::ssl_select_cert_error
        },
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_status_callback`. The connection's current
/// context holds `F`.
pub(super) unsafe extern "C" fn raw_tlsext_status<F>(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef) -> Result<bool, ErrorStack> + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

            let ssl_context = unwind::LeakOnUnwind::new(ssl.ssl_context().to_owned());
            let callback = ssl_context
                .ex_data(SslContext::cached_ex_index::<F>())
                .expect("BUG: ocsp callback missing");

            let ret = callback(ssl);

            if ssl.is_server() {
                match ret {
                    Ok(true) => ffi::SSL_TLSEXT_ERR_OK,
                    Ok(false) => ffi::SSL_TLSEXT_ERR_NOACK,
                    Err(e) => {
                        e.put();
                        ffi::SSL_TLSEXT_ERR_ALERT_FATAL
                    }
                }
            } else {
                match ret {
                    Ok(true) => 1,
                    Ok(false) => 0,
                    Err(e) => {
                        e.put();
                        -1
                    }
                }
            }
        },
        |message| {
            unwind::report(message);
            if unsafe { SslRef::from_ptr(ssl) }.is_server() {
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            } else {
                -1
            }
        },
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_new_session_callback`. `session` is a live session
/// whose reference moves to this call (returning `1` keeps it). The session
/// context holds `F`.
pub(super) unsafe extern "C" fn raw_new_session<F>(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int
where
    F: Fn(&mut SslRef, SslSession) + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
            let session = unsafe { SslSession::from_ptr(session) };

            let callback = ssl
                .ex_data(*SESSION_CTX_INDEX)
                .expect("BUG: session context missing")
                .ex_data(SslContext::cached_ex_index::<F>())
                .expect("BUG: new session callback missing");

            // SAFETY: We can make `callback` outlive `ssl` because it is a callback
            // stored in the session context set in `Ssl::new` so it is always
            // guaranteed to outlive the lifetime of this function's scope.
            let callback = unsafe { &*std::ptr::from_ref::<F>(callback) };

            callback(ssl, session);

            // the return code doesn't indicate error vs success, but whether or not we consumed the session
            1
        },
        // The session reference was owned before user code ran and is released
        // while unwinding: it was consumed either way.
        |_| 1,
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_remove_session_callback`. `ctx` holds `F`;
/// `session` is a live session borrowed for the call.
pub(super) unsafe extern "C" fn raw_remove_session<F>(
    ctx: *mut ffi::SSL_CTX,
    session: *mut ffi::SSL_SESSION,
) where
    F: Fn(&SslSessionRef) + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ctx = unsafe { SslContextRef::from_ptr(ctx) };
            let session = unsafe { SslSessionRef::from_ptr(session) };

            let callback = ctx
                .ex_data(SslContext::cached_ex_index::<F>())
                .expect("BUG: remove session callback missing");

            // `ctx` can already be in SSLContext's destructor. Use its ex_data
            // only while BoringSSL keeps it alive, and do not expose a retainable
            // SslContextRef to user code.
            callback(session);
        },
        |_| (),
    )
}

type DataPtr = *const c_uchar;

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_get_session_callback`. `data` is readable for
/// `len` bytes, `len >= 0`, and `copy` is valid for one write. A returned session carries
/// one reference for BoringSSL. The session context holds `F`.
pub(super) unsafe extern "C" fn raw_get_session<F>(
    ssl: *mut ffi::SSL,
    data: DataPtr,
    len: c_int,
    copy: *mut c_int,
) -> *mut ffi::SSL_SESSION
where
    F: Fn(&mut SslRef, &[u8]) -> Result<Option<SslSession>, GetSessionPendingError>
        + 'static
        + Sync
        + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
            let data = unsafe { crate::util::slice_or_empty(data, len as usize) };
            let copy = unsafe { &mut *copy };

            let callback = ssl
                .ex_data(*SESSION_CTX_INDEX)
                .expect("BUG: session context missing")
                .ex_data(SslContext::cached_ex_index::<F>())
                .expect("BUG: get session callback missing");

            // SAFETY: We can make `callback` outlive `ssl` because it is a callback
            // stored in the session context set in `Ssl::new` so it is always
            // guaranteed to outlive the lifetime of this function's scope.
            let callback = unsafe { &*std::ptr::from_ref::<F>(callback) };

            match callback(ssl, data) {
                Ok(Some(session)) => {
                    let p = session.into_ptr();

                    *copy = 0;

                    p
                }
                Ok(None) => ptr::null_mut(),
                Err(GetSessionPendingError) => unsafe { ffi::SSL_magic_pending_session_ptr() },
            }
        },
        |_| {
            // A miss falls back to a full handshake; drop any half-run lookup.
            cancel_session_lookup(unsafe { SslRef::from_ptr_mut(ssl) });
            ptr::null_mut()
        },
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_keylog_callback`. `line` is a NUL-terminated
/// string live for the call. The connection's current context holds `F`.
pub(super) unsafe extern "C" fn raw_keylog<F>(ssl: *const ffi::SSL, line: *const c_char)
where
    F: Fn(&SslRef, &str) + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr(ssl.cast_mut()) };
            let line = unsafe { CStr::from_ptr(line).to_string_lossy() };

            let callback = ssl
                .ssl_context()
                .ex_data(SslContext::cached_ex_index::<F>())
                .expect("BUG: get session callback missing");

            callback(ssl, &line);
        },
        |_| (),
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `set_private_key_method` (context or credential). `out` is writable
/// for `max_out` bytes (it may start uninitialized), `out_len` for one
/// `usize`, and `in_` readable for `in_len` bytes. `M` is stored either on the
/// selected credential at `SslCredential::cached_ex_index::<M>()`, or on the
/// context returned by `selected_credential_context` at
/// `SslContext::cached_ex_index::<M>()`. The latter can be a retained former
/// context after routing, rather than the current `SSL_get_SSL_CTX` context.
/// On success `*out_len <= max_out`.
pub(super) unsafe extern "C" fn raw_sign<M>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    signature_algorithm: u16,
    in_: *const u8,
    in_len: usize,
) -> ffi::ssl_private_key_result_t
where
    M: PrivateKeyMethod,
{
    // SAFETY: guaranteed by the caller under the module's trampoline contract.
    let input = unsafe { crate::util::slice_or_empty(in_, in_len) };

    let signature_algorithm = SslSignatureAlgorithm(signature_algorithm);

    let callback = |method: &M, ssl: &mut _, output: &mut _| {
        method.sign(ssl, input, signature_algorithm, output)
    };

    // SAFETY: guaranteed by the caller under the module's trampoline contract.
    unsafe { raw_private_key_callback(ssl, out, out_len, max_out, callback) }
}

/// # Safety
///
/// Same as `raw_sign`, without a signature algorithm.
pub(super) unsafe extern "C" fn raw_decrypt<M>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    in_: *const u8,
    in_len: usize,
) -> ffi::ssl_private_key_result_t
where
    M: PrivateKeyMethod,
{
    // SAFETY: guaranteed by the caller under the module's trampoline contract.
    let input = unsafe { crate::util::slice_or_empty(in_, in_len) };

    let callback = |method: &M, ssl: &mut _, output: &mut _| method.decrypt(ssl, input, output);

    // SAFETY: guaranteed by the caller under the module's trampoline contract.
    unsafe { raw_private_key_callback(ssl, out, out_len, max_out, callback) }
}

/// # Safety
///
/// Same as `raw_sign`, with no input buffer.
pub(super) unsafe extern "C" fn raw_complete<M>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
) -> ffi::ssl_private_key_result_t
where
    M: PrivateKeyMethod,
{
    // SAFETY: guaranteed by the caller under the module's trampoline contract.
    unsafe { raw_private_key_callback::<M>(ssl, out, out_len, max_out, M::complete) }
}

/// # Safety
///
/// Shared body of `raw_sign`, `raw_decrypt` and `raw_complete`: the
/// arguments must satisfy the calling trampoline's contract.
unsafe fn raw_private_key_callback<M>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    callback: impl FnOnce(&M, &mut SslRef, &mut [u8]) -> Result<usize, PrivateKeyMethodError>,
) -> ffi::ssl_private_key_result_t
where
    M: PrivateKeyMethod,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
            // SAFETY: BoringSSL passes an `out` buffer valid for writes of
            // `max_out` bytes (`ssl_private_key_method_st` in ssl.h). That
            // buffer is reserved but not initialized (`CBB_reserve`,
            // `InitForOverwrite`), and it is handed to a safe trait method
            // that may read it, so it is zeroed before the slice is created.
            let output = unsafe { zeroed_out_buf(out, max_out) };
            let out_len = unsafe { &mut *out_len };

            // Keep native owners alive independently of `ssl` while the callback can
            // mutate the connection. Credential-specific methods take precedence over
            // the legacy context method.
            let credential =
                unwind::LeakOnUnwind::new(ssl.selected_credential().map(ToOwned::to_owned));
            let ssl_context = unwind::LeakOnUnwind::new(
                super::credential::selected_credential_context(ssl).to_owned(),
            );
            let Some(method) = credential
                .as_ref()
                .and_then(|cred| cred.ex_data(super::SslCredential::cached_ex_index::<M>()))
                .or_else(|| ssl_context.ex_data(SslContext::cached_ex_index::<M>()))
            else {
                return ffi::ssl_private_key_result_t::ssl_private_key_failure;
            };

            match callback(method, ssl, output) {
                Ok(written) if written <= max_out => {
                    *out_len = written;

                    ffi::ssl_private_key_result_t::ssl_private_key_success
                }
                Ok(_) => ffi::ssl_private_key_result_t::ssl_private_key_failure,
                Err(err) => err.0,
            }
        },
        |message| {
            unwind::report(message);
            // SAFETY: the panicked callback no longer borrows the connection.
            cancel_pending(unsafe { SslRef::from_ptr_mut(ssl) });
            ffi::ssl_private_key_result_t::ssl_private_key_failure
        },
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_info_callback`. The connection's current
/// context holds `F`.
pub(super) unsafe extern "C" fn raw_info_callback<F>(
    ssl: *const ffi::SSL,
    mode: c_int,
    value: c_int,
) where
    F: Fn(&SslRef, SslInfoCallbackMode, SslInfoCallbackValue) + Send + Sync + 'static,
{
    unwind::catch(
        || {
            // Due to FFI signature requirements we have to pass a *const SSL into this function, but
            // foreign-types requires a *mut SSL to get the Rust SslRef
            let mut_ref = ssl.cast_mut();

            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr(mut_ref) };
            let ssl_context = ssl.ssl_context();

            let callback = ssl_context
                .ex_data(SslContext::cached_ex_index::<F>())
                .expect("BUG: info callback missing");

            let value = match mode {
                ffi::SSL_CB_READ_ALERT | ffi::SSL_CB_WRITE_ALERT => {
                    SslInfoCallbackValue::Alert(SslInfoCallbackAlert(value))
                }
                _ => SslInfoCallbackValue::Unit,
            };

            callback(ssl, SslInfoCallbackMode(mode), value);
        },
        |_| (),
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::add_certificate_compression_algorithm`. `out` is a
/// live, initialized `CBB` used only by this call; `input` is readable for
/// `input_len` bytes. The connection's current context holds `C`.
pub(super) unsafe extern "C" fn raw_ssl_cert_compress<C>(
    ssl: *mut ffi::SSL,
    out: *mut ffi::CBB,
    input: *const u8,
    input_len: usize,
) -> ::std::os::raw::c_int
where
    C: CertificateCompressor,
{
    unwind::catch_reported(0, || {
        const {
            assert!(C::CAN_COMPRESS);
        }

        // SAFETY: guaranteed by the caller under the module's trampoline contract.
        let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

        let ssl_context = ssl.ssl_context();
        let compressor = ssl_context
            .ex_data(SslContext::cached_ex_index::<C>())
            .expect("BUG: certificate compression missed");

        // SAFETY: BoringSSL passes `input` valid for `input_len` bytes; an empty
        // input may come with any pointer.
        let input_slice = unsafe { crate::util::slice_or_empty(input, input_len) };
        // SAFETY: `out` is the live, initialized `CBB` BoringSSL hands to the
        // compression callback for the duration of this call.
        let mut writer = unsafe { CryptoByteBuilder::from_ptr(out) };
        if compressor.compress(input_slice, &mut writer).is_err() {
            return 0;
        }

        ssl.set_ex_data(*CERT_COMPRESSED_INDEX, C::ALGORITHM);
        1
    })
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::add_certificate_compression_algorithm`. `out` is
/// valid for one write; `input` is readable for `input_len` bytes, and
/// `uncompressed_len` is peer-controlled (it may be `0`). On success `*out`
/// carries one `CRYPTO_BUFFER` reference for BoringSSL. The connection's
/// current context holds `C`.
pub(super) unsafe extern "C" fn raw_ssl_cert_decompress<C>(
    ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> ::std::os::raw::c_int
where
    C: CertificateCompressor,
{
    unwind::catch_reported(0, || {
        const {
            assert!(C::CAN_DECOMPRESS);
        }

        // SAFETY: guaranteed by the caller under the module's trampoline contract.
        let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

        let ssl_context = ssl.ssl_context();
        let compressor = ssl_context
            .ex_data(SslContext::cached_ex_index::<C>())
            .expect("BUG: certificate compression missed");

        let Ok(mut decompression_buffer) = CryptoBufferBuilder::with_capacity(uncompressed_len)
        else {
            return 0;
        };

        // SAFETY: BoringSSL passes `input` valid for `input_len` bytes; the
        // peer controls `input_len`, which may be zero.
        let input_slice = unsafe { crate::util::slice_or_empty(input, input_len) };

        if compressor
            .decompress(input_slice, decompression_buffer.as_writer())
            .is_err()
        {
            return 0;
        }

        let Ok(crypto_buffer) = decompression_buffer.build() else {
            return 0;
        };

        unsafe { *out = crypto_buffer };
        ssl.set_ex_data(*CERT_DECOMPRESSED_INDEX, C::ALGORITHM);
        1
    })
}

struct CryptoByteBuilder<'a>(
    // Safety invariant: points to a live, initialized `CBB` that nothing else
    // accesses for `'a`.
    *mut ffi::CBB,
    std::marker::PhantomData<&'a [u8]>,
);

impl CryptoByteBuilder<'_> {
    /// # Safety
    ///
    /// The caller must ensure that `ptr` points to a live, initialized `CBB`
    /// that nothing else accesses while the returned builder exists.
    unsafe fn from_ptr(ptr: *mut ffi::CBB) -> Self {
        Self(ptr, Default::default())
    }
}

impl std::io::Write for CryptoByteBuilder<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let success = unsafe { ffi::CBB_add_bytes(self.0, buf.as_ptr(), buf.len()) == 1 };
        if !success {
            return Err(std::io::Error::other("CBB_add_bytes failed"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let success = unsafe { ffi::CBB_flush(self.0) == 1 };
        if !success {
            return Err(std::io::Error::other("CBB_flush failed"));
        }
        Ok(())
    }
}

struct CryptoBufferBuilder<'a> {
    buffer: *mut ffi::CRYPTO_BUFFER,
    cursor: std::io::Cursor<&'a mut [u8]>,
}

impl<'a> CryptoBufferBuilder<'a> {
    fn with_capacity(capacity: usize) -> Result<CryptoBufferBuilder<'a>, ErrorStack> {
        let mut data: *mut u8 = std::ptr::null_mut();
        let buffer = unsafe { crate::cvt_p(ffi::CRYPTO_BUFFER_alloc(&mut data, capacity))? };
        // SAFETY: `CRYPTO_BUFFER_alloc` makes `data` point to `capacity`
        // writable bytes owned by `buffer`, which this builder owns. `Drop`
        // frees `buffer` before the `cursor` field is dropped, which is fine:
        // dropping a `Cursor<&mut [u8]>` never touches the bytes. A zero capacity (the peer controls
        // it) may come with a null `data`, hence `zeroed_out_buf`. The bytes
        // are zeroed so the slice never refers to uninitialized memory; the
        // cursor is only exposed as an opaque `impl Write`.
        let data = unsafe { zeroed_out_buf(data, capacity) };
        Ok(CryptoBufferBuilder {
            buffer,
            cursor: std::io::Cursor::new(data),
        })
    }

    fn as_writer(&mut self) -> &mut (impl std::io::Write + 'a) {
        &mut self.cursor
    }

    fn build(mut self) -> Result<*mut ffi::CRYPTO_BUFFER, ErrorStack> {
        let buffer_capacity = unsafe { ffi::CRYPTO_BUFFER_len(self.buffer) };
        if self.cursor.position() != buffer_capacity as u64 {
            // Make sure all bytes in buffer initialized as required by Boring SSL.
            return Err(ErrorStack::internal_error_str("invalid len"));
        }
        // Drop is no-op if the buffer is null
        Ok(mem::replace(&mut self.buffer, ptr::null_mut()))
    }
}

impl Drop for CryptoBufferBuilder<'_> {
    fn drop(&mut self) {
        if !self.buffer.is_null() {
            unsafe {
                rama_boring_sys::CRYPTO_BUFFER_free(self.buffer);
            }
        }
    }
}

// A panicking verifier rejects the chain with an application error; BoringSSL
// clears the reported panic itself when the verify mode ignores the result.
/// # Safety
///
/// The caller must provide a live, initialized, exclusively accessible
/// `X509_STORE_CTX` for this call, after the panicked callback releases its borrow.
#[cold]
#[inline(never)]
unsafe fn verify_panicked(x509_ctx: *mut ffi::X509_STORE_CTX, message: String) -> c_int {
    unwind::report(message);
    // SAFETY: the panicked callback no longer borrows the store context.
    unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) }
        .set_error(Err(X509VerifyError::APPLICATION_VERIFICATION));
    0
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslContextBuilder::set_msg_callback`. `buf` is readable for `len`
/// bytes. The session context holds `F`.
pub(super) unsafe extern "C" fn raw_ctx_msg<F>(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    ssl: *mut ffi::SSL,
    _: *mut c_void,
) where
    F: Fn(&SslRef, super::SslMessage<'_>) + 'static + Sync + Send,
{
    // Observation cannot fail the connection; a panic is contained.
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr(ssl) };
            let message =
                unsafe { super::SslMessage::from_raw(write_p, version, content_type, buf, len) };
            let Some(callback) = super::connection::session_context(ssl)
                .and_then(|ctx| ctx.ex_data(SslContext::cached_ex_index::<F>()))
            else {
                return;
            };
            callback(ssl, message);
        },
        |_| (),
    )
}

/// # Safety
///
/// The [trampoline contract](self) for
/// `SslRef::set_msg_callback`. `buf` is readable for `len` bytes; the
/// connection's own ex_data holds `Arc<F>`.
pub(super) unsafe extern "C" fn raw_ssl_msg<F>(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    ssl: *mut ffi::SSL,
    _: *mut c_void,
) where
    F: Fn(&SslRef, super::SslMessage<'_>) + 'static + Sync + Send,
{
    unwind::catch(
        || {
            // SAFETY: guaranteed by the caller under the module's trampoline contract.
            let ssl = unsafe { SslRef::from_ptr(ssl) };
            let message =
                unsafe { super::SslMessage::from_raw(write_p, version, content_type, buf, len) };
            // Clone the Arc: the callback may replace itself.
            let Some(callback) = ssl
                .ex_data(Ssl::cached_ex_index::<Arc<F>>())
                .cloned()
                .map(unwind::LeakOnUnwind::new)
            else {
                return;
            };
            callback(ssl, message);
        },
        |_| (),
    )
}
