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
/// `cb_state` is expected to be a pointer to a `CallbackState`.
pub unsafe extern "C" fn invoke_passwd_cb<F>(
    buf: *mut c_char,
    size: c_int,
    _rwflag: c_int,
    cb_state: *mut c_void,
) -> c_int
where
    F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>,
{
    let callback = &mut *cb_state.cast::<CallbackState<F>>();

    // A panic fails the key load with an error instead of unwinding through C.
    let result = unwind::catch(
        || {
            let pass_slice = slice::from_raw_parts_mut(buf.cast::<u8>(), size as usize);
            callback.cb.take().unwrap()(pass_slice)
        },
        |message| {
            Err(ErrorStack::internal_error_string(format!(
                "callback panicked: {message}"
            )))
        },
    );

    match result {
        Ok(len) => len as c_int,
        Err(err) => {
            err.put();
            0
        }
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
