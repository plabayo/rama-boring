//! Internal ownership for reference-counted native byte buffers.

use crate::{cvt_p, error::ErrorStack, ffi, stack::Stackable};
use foreign_types::ForeignType;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::CRYPTO_BUFFER;
    fn drop = ffi::CRYPTO_BUFFER_free;

    pub struct CryptoBuffer;
}

impl CryptoBuffer {
    pub(crate) fn new(bytes: &[u8]) -> Result<Self, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(ffi::CRYPTO_BUFFER_new(
                bytes.as_ptr(),
                bytes.len(),
                ptr::null_mut(),
            ))
            .map(|p| Self::from_ptr(p))
        }
    }
}

impl Stackable for CryptoBuffer {
    type StackType = ffi::stack_st_CRYPTO_BUFFER;
}
