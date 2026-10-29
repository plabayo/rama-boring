use crate::ffi;
use foreign_types::ForeignTypeRef;
use libc::c_char;
use std::convert::AsRef;
use std::ffi::CStr;
use std::fmt;
use std::ops::Deref;
use std::str;

use crate::stack::Stackable;

foreign_type_and_impl_send_sync! {
    type CType = c_char;
    fn drop = free;

    /// A NUL-terminated string allocated by BoringSSL.
    ///
    /// # Invariants
    ///
    /// The bytes up to the first NUL are valid UTF-8. Every constructor in this
    /// crate checks this before taking ownership of a string; callers of the
    /// unsafe `from_ptr` must uphold it themselves.
    pub struct OpensslString;
}

impl OpensslString {
    /// Takes ownership of a BoringSSL-allocated C string, checking that it is
    /// valid UTF-8.
    ///
    /// Returns an error (and frees the string) if `ptr` is null or not UTF-8.
    ///
    /// # Safety
    ///
    /// If `ptr` is non-null, the caller must ensure that it is the start of a
    /// live allocation made with `OPENSSL_malloc` that holds a NUL-terminated
    /// string, that nothing else owns or mutates it, and that ownership moves
    /// to this call (the string ends up in the result or is freed).
    pub(crate) unsafe fn from_c_ptr(
        ptr: *mut c_char,
    ) -> Result<OpensslString, crate::error::ErrorStack> {
        if ptr.is_null() {
            return Err(crate::error::ErrorStack::get());
        }
        // SAFETY: `ptr` is a live, NUL-terminated string that nothing else
        // mutates (`# Safety`); `bytes` is not used after it is freed below.
        let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
        if str::from_utf8(bytes).is_err() {
            // SAFETY: we own the `OPENSSL_malloc` allocation (`# Safety`) and
            // no wrapper owns it yet, so it is freed exactly once, here.
            unsafe { free(ptr) };
            return Err(crate::error::ErrorStack::internal_error_str(
                "string returned by BoringSSL is not valid UTF-8",
            ));
        }
        // SAFETY: the owned string is valid UTF-8, so the `OpensslString`
        // invariant holds from the moment the wrapper is constructed.
        Ok(unsafe { <OpensslString as foreign_types::ForeignType>::from_ptr(ptr) })
    }
}

impl fmt::Display for OpensslString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl fmt::Debug for OpensslString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl Stackable for OpensslString {
    type StackType = ffi::stack_st_OPENSSL_STRING;
}

impl AsRef<str> for OpensslString {
    fn as_ref(&self) -> &str {
        self
    }
}

impl AsRef<[u8]> for OpensslString {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Deref for OpensslStringRef {
    type Target = str;

    fn deref(&self) -> &str {
        // SAFETY: `self` wraps a live NUL-terminated string (type invariant).
        let slice = unsafe { CStr::from_ptr(self.as_ptr()) }.to_bytes();
        debug_assert!(str::from_utf8(slice).is_ok());
        // SAFETY: by the `OpensslString` invariant the bytes are valid UTF-8.
        unsafe { str::from_utf8_unchecked(slice) }
    }
}

impl AsRef<str> for OpensslStringRef {
    fn as_ref(&self) -> &str {
        self
    }
}

impl AsRef<[u8]> for OpensslStringRef {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for OpensslStringRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl fmt::Debug for OpensslStringRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

unsafe fn free(buf: *mut c_char) {
    crate::ffi::OPENSSL_free(buf.cast());
}
