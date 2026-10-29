use crate::error::ErrorStack;
use crate::libc_types::{c_char, c_int, c_void};
use crate::unwind;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::slice;

/// Wraps a user-supplied callback that runs while FFI frames are on the stack.
pub struct CallbackState<F> {
    /// The user callback. Taken out of the `Option` when called.
    cb: Option<F>,
}

impl<F> CallbackState<F> {
    pub fn new(callback: F) -> Self {
        CallbackState { cb: Some(callback) }
    }
}

/// Password callback function, passed to private key loading functions.
///
/// # Safety
///
/// The caller (BoringSSL's PEM code) must ensure that:
///
/// - `cb_state` points to a live `CallbackState<F>` that nothing else accesses
///   for the duration of the call;
/// - if `size > 0`, `buf` is non-null and valid for writes of `size` bytes.
///
/// If these hold, the return value is `0` on failure, or the number of
/// password bytes written to `buf`, which is at most `size`.
pub unsafe extern "C" fn invoke_passwd_cb<F>(
    buf: *mut c_char,
    size: c_int,
    _rwflag: c_int,
    cb_state: *mut c_void,
) -> c_int
where
    F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>,
{
    // SAFETY: by this function's `# Safety` contract `cb_state` points to a
    // live `CallbackState<F>` with no other active access.
    let callback = unsafe { &mut *cb_state.cast::<CallbackState<F>>() };

    // A negative size is treated as an empty buffer.
    let size = usize::try_from(size).unwrap_or(0);

    // A panic fails the key load with an error instead of unwinding through C.
    let result = unwind::catch(
        || {
            let pass_slice: &mut [u8] = if size == 0 {
                &mut []
            } else {
                // SAFETY: `buf` is non-null and valid for writes of `size`
                // bytes (`# Safety` contract). BoringSSL passes a stack buffer
                // that it has not initialized, so it is zeroed first: the
                // slice is handed to safe user code, which may read it.
                unsafe {
                    std::ptr::write_bytes(buf.cast::<u8>(), 0, size);
                    slice::from_raw_parts_mut(buf.cast::<u8>(), size)
                }
            };
            callback.cb.take().unwrap()(pass_slice)
        },
        |message| {
            Err(ErrorStack::internal_error_string(format!(
                "callback panicked: {message}"
            )))
        },
    );

    // The native caller reads `len` bytes from `buf`, so a length larger than
    // the buffer must never be returned.
    let result = result.and_then(|len| {
        if len <= size {
            Ok(len)
        } else {
            Err(ErrorStack::internal_error_string(format!(
                "password callback returned {len} bytes for a {size}-byte buffer"
            )))
        }
    });

    match result {
        // `len <= size <= c_int::MAX`, so the cast is lossless.
        Ok(len) => len as c_int,
        Err(err) => {
            err.put();
            0
        }
    }
}

/// Builds a slice from a native `(ptr, len)` pair that may be `(NULL, 0)`.
///
/// `slice::from_raw_parts` requires a non-null pointer even for an empty
/// slice, while BoringSSL commonly represents empty data as a null pointer.
///
/// # Safety
///
/// If `len > 0`, the caller must ensure that `ptr` is non-null, aligned, and
/// valid for reads of `len` initialized `T` values within one allocation, and
/// that the memory is not mutated for the returned lifetime `'a`.
///
/// If these hold, the result is `&[]` when `len == 0` or `ptr` is null, and
/// the `len` values at `ptr` otherwise.
pub(crate) unsafe fn slice_or_empty<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: `ptr` is non-null and `len > 0`, so the `# Safety` contract
        // gives exactly the obligations of `slice::from_raw_parts`.
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

#[allow(dead_code)]
pub trait ForeignTypeExt: ForeignType {
    unsafe fn from_ptr_opt(ptr: *mut Self::CType) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self::from_ptr(ptr))
        }
    }
}
impl<FT: ForeignType> ForeignTypeExt for FT {}

pub trait ForeignTypeRefExt: ForeignTypeRef {
    unsafe fn from_const_ptr<'a>(ptr: *const Self::CType) -> &'a Self {
        Self::from_ptr(ptr.cast_mut())
    }

    unsafe fn from_const_ptr_opt<'a>(ptr: *const Self::CType) -> Option<&'a Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self::from_const_ptr(ptr.cast_mut()))
        }
    }
}
impl<FT: ForeignTypeRef> ForeignTypeRefExt for FT {}
