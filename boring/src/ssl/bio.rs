use crate::ffi::{
    self, BIO_clear_retry_flags, BIO_new, BIO_set_retry_read, BIO_set_retry_write, BIO,
    BIO_CTRL_DGRAM_QUERY_MTU, BIO_CTRL_FLUSH,
};
use crate::libc_types::{c_char, c_int, c_long, c_void, strlen};
use std::io;
use std::io::prelude::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::util::slice_or_empty;
use std::ptr;
use std::slice;

use crate::cvt_p;
use crate::error::ErrorStack;
use crate::unwind;

pub struct StreamState<S> {
    pub stream: S,
    pub error: Option<io::Error>,
    /// The stream panicked; it is never used again and every later I/O fails.
    pub panicked: bool,
    pub dtls_mtu_size: c_long,
}

impl<S> StreamState<S> {
    // A panic leaves the stream in an unknown state: report it as an I/O error
    // and never touch the stream again.
    #[cold]
    #[inline(never)]
    fn poison(&mut self, payload: Box<dyn std::any::Any + Send>) {
        let message = unwind::contain(payload);
        self.panicked = true;
        self.set_error(io::Error::other(format!(
            "TLS transport stream panicked: {message}"
        )));
    }

    // The replaced error may own a stream-defined destructor, which runs where
    // unwinding is not allowed: contain it.
    #[inline(always)]
    fn set_error(&mut self, error: io::Error) {
        if let Some(replaced) = self.error.replace(error) {
            unwind::drop_contained(replaced);
        }
    }

    #[inline(always)]
    fn poisoned(&mut self) -> bool {
        if self.panicked {
            self.poisoned_again();
        }
        self.panicked
    }

    #[cold]
    #[inline(never)]
    fn poisoned_again(&mut self) {
        if self.error.is_none() {
            self.set_error(io::Error::other("TLS transport stream panicked earlier"));
        }
    }
}

/// Safe wrapper for BIO_METHOD
pub struct BioMethod(BIO_METHOD);

impl BioMethod {
    fn new<S: Read + Write>() -> BioMethod {
        BioMethod(BIO_METHOD::new::<S>())
    }
}

// SAFETY: the `BIO_METHOD` is fully set up in `BioMethod::new` and never
// mutated afterwards; BIOs only read it.
unsafe impl Sync for BioMethod {}
unsafe impl Send for BioMethod {}

pub fn new<S: Read + Write>(stream: S) -> Result<(*mut BIO, BioMethod), ErrorStack> {
    let method = BioMethod::new::<S>();

    let state = Box::new(StreamState {
        stream,
        error: None,
        panicked: false,
        dtls_mtu_size: 0,
    });

    unsafe {
        let bio = cvt_p(BIO_new(method.0.get()))?;
        BIO_set_data(bio, Box::into_raw(state).cast());
        BIO_set_init(bio, 1);

        Ok((bio, method))
    }
}

/// Takes the last I/O error recorded by the BIO.
///
/// # Safety
///
/// The caller must ensure that `bio` is a live BIO created by [`new::<S>`]
/// for this same `S`, whose stream has not been taken, and that nothing else
/// accesses its stream state during the call.
pub unsafe fn take_error<S>(bio: *mut BIO) -> Option<io::Error> {
    // SAFETY: forwarded from this function's `# Safety` contract.
    let state = unsafe { state::<S>(bio) };
    state.error.take()
}

/// Returns a shared reference to the BIO's stream.
///
/// # Safety
///
/// The caller must ensure that `bio` is a live BIO created by [`new::<S>`]
/// for this same `S`, whose stream is not taken and whose state is not freed
/// for `'a`, and that no exclusive access to the stream or its state happens
/// during `'a` (shared access, including other `get_ref` borrows, is fine).
pub unsafe fn get_ref<'a, S: 'a>(bio: *mut BIO) -> &'a S {
    // SAFETY: `bio` is a live BIO (`# Safety`).
    let data = unsafe { BIO_get_data(bio) }.cast::<StreamState<S>>();
    assert!(!data.is_null());
    // SAFETY: `data` points to the live, initialized `StreamState<S>` boxed
    // by `new::<S>` and kept alive for `'a` (`# Safety`). Only a shared
    // reference to the `stream` field is created: going through `state`
    // would create a `&mut StreamState` that overlaps other live `get_ref`
    // borrows.
    unsafe { &(*data).stream }
}

/// Returns an exclusive reference to the BIO's stream.
///
/// # Safety
///
/// The caller must ensure that `bio` is a live BIO created by [`new::<S>`]
/// for this same `S`, whose stream is not taken and whose state is not freed
/// for `'a`, and that nothing else accesses the stream state during `'a`.
pub unsafe fn get_mut<'a, S: 'a>(bio: *mut BIO) -> &'a mut S {
    // SAFETY: forwarded from this function's `# Safety` contract.
    unsafe { &mut state(bio).stream }
}

/// Moves the stream out of the BIO and frees its state.
///
/// # Safety
///
/// The caller must ensure that `bio` is a live BIO created by [`new::<S>`]
/// for this same `S`, whose stream has not been taken yet, and that no
/// reference into its stream state is alive. Afterwards the BIO has no
/// stream; it must not be used for I/O or passed to the other functions here.
pub unsafe fn take_stream<S>(bio: *mut BIO) -> S {
    assert!(!bio.is_null());

    let data = BIO_get_data(bio);

    assert!(!data.is_null());

    let state = Box::<StreamState<S>>::from_raw(data.cast());

    BIO_set_data(bio, ptr::null_mut());

    // A pending error may own a stream-defined destructor: contain it, as on
    // every other cleanup path.
    let StreamState { stream, error, .. } = *state;
    unwind::drop_contained(error);
    stream
}

/// Flushes the stream as the BIO does: never after it panicked, and a panic
/// poisons it and becomes an I/O error.
///
/// # Safety
///
/// Same contract as [`take_error`].
pub unsafe fn flush<S: Write>(bio: *mut BIO) -> io::Result<()> {
    // SAFETY: forwarded from this function's `# Safety` contract.
    let state = unsafe { state::<S>(bio) };
    if state.poisoned() {
        return Err(state
            .error
            .take()
            .unwrap_or_else(|| io::Error::other("TLS transport stream panicked earlier")));
    }
    match catch_unwind(AssertUnwindSafe(|| state.stream.flush())) {
        Ok(result) => result,
        Err(payload) => {
            state.poison(payload);
            Err(state
                .error
                .take()
                .unwrap_or_else(|| io::Error::other("TLS transport stream panicked")))
        }
    }
}

/// Records the DTLS MTU the BIO reports to BoringSSL.
///
/// # Panics
///
/// Panics if `mtu_size` does not fit in a positive `c_long`.
///
/// # Safety
///
/// Same contract as [`take_error`].
pub unsafe fn set_dtls_mtu_size<S>(bio: *mut BIO, mtu_size: usize) {
    if mtu_size as u64 > c_long::MAX as u64 {
        panic!("Given MTU size {mtu_size} can't be represented in a positive `c_long` range")
    }
    state::<S>(bio).dtls_mtu_size = mtu_size as c_long;
}

/// Returns the BIO's stream state.
///
/// # Safety
///
/// The caller must ensure that `bio` is a live BIO created by [`new::<S>`]
/// for this same `S` (so its data is a `Box<StreamState<S>>`), whose state is
/// not freed for `'a`, and that nothing else accesses that state during `'a`.
unsafe fn state<'a, S: 'a>(bio: *mut BIO) -> &'a mut StreamState<S> {
    let data = BIO_get_data(bio).cast::<StreamState<S>>();

    assert!(!data.is_null());

    &mut *data
}

unsafe extern "C" fn bwrite<S: Write>(bio: *mut BIO, buf: *const c_char, len: c_int) -> c_int {
    BIO_clear_retry_flags(bio);

    let Ok(len) = usize::try_from(len) else {
        return -1;
    };

    let state = state::<S>(bio);
    if state.poisoned() {
        return -1;
    }
    // SAFETY: `BIO_write` passes `buf` valid for reads of `len` bytes; an
    // empty write may come with a null pointer.
    let buf = unsafe { slice_or_empty(buf.cast::<u8>(), len) };

    match catch_unwind(AssertUnwindSafe(|| state.stream.write(buf))) {
        // `n <= len <= c_int::MAX`, so the cast is lossless.
        Ok(Ok(n)) if n <= len => n as c_int,
        Ok(Ok(n)) => {
            // A `Write` impl claiming more than it was given would make the
            // TLS stack consume bytes that were never written.
            state.set_error(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Write::write reported {n} bytes written for a {len}-byte buffer"),
            ));
            -1
        }
        Ok(Err(err)) => {
            if retriable_error(&err) {
                BIO_set_retry_write(bio);
            }
            state.set_error(err);
            -1
        }
        Err(payload) => {
            state.poison(payload);
            -1
        }
    }
}

unsafe extern "C" fn bread<S: Read>(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
    BIO_clear_retry_flags(bio);

    let Ok(len) = usize::try_from(len) else {
        return -1;
    };

    let state = state::<S>(bio);
    if state.poisoned() {
        return -1;
    }
    // SAFETY: `BIO_read` passes `buf` valid for writes of `len` bytes. The TLS
    // read buffer is `malloc`ed and not initialized, while a safe `Read` impl
    // may read the slice it is given, so it is zeroed before being exposed.
    let buf = unsafe {
        if buf.is_null() || len == 0 {
            &mut []
        } else {
            std::ptr::write_bytes(buf.cast::<u8>(), 0, len);
            slice::from_raw_parts_mut(buf.cast::<u8>(), len)
        }
    };

    match catch_unwind(AssertUnwindSafe(|| state.stream.read(buf))) {
        // `n <= len <= c_int::MAX`, so the cast is lossless.
        Ok(Ok(n)) if n <= len => n as c_int,
        Ok(Ok(n)) => {
            // A `Read` impl claiming more than the buffer holds would make the
            // TLS stack treat bytes past what was read as received data.
            state.set_error(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Read::read reported {n} bytes read into a {len}-byte buffer"),
            ));
            -1
        }
        Ok(Err(err)) => {
            if retriable_error(&err) {
                BIO_set_retry_read(bio);
            }
            state.set_error(err);
            -1
        }
        Err(payload) => {
            state.poison(payload);
            -1
        }
    }
}

#[allow(clippy::match_like_matches_macro)] // matches macro requires rust 1.42.0
fn retriable_error(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::NotConnected => true,
        _ => false,
    }
}

unsafe extern "C" fn bputs<S: Write>(bio: *mut BIO, s: *const c_char) -> c_int {
    bwrite::<S>(bio, s, strlen(s) as c_int)
}

unsafe extern "C" fn ctrl<S: Write>(
    bio: *mut BIO,
    cmd: c_int,
    _num: c_long,
    _ptr: *mut c_void,
) -> c_long {
    let state = state::<S>(bio);

    if cmd == BIO_CTRL_FLUSH {
        BIO_clear_retry_flags(bio);
        if state.poisoned() {
            return 0;
        }
        match catch_unwind(AssertUnwindSafe(|| state.stream.flush())) {
            Ok(Ok(())) => 1,
            Ok(Err(err)) => {
                if retriable_error(&err) {
                    BIO_set_retry_write(bio);
                }
                state.set_error(err);
                0
            }
            Err(payload) => {
                state.poison(payload);
                0
            }
        }
    } else if cmd == BIO_CTRL_DGRAM_QUERY_MTU {
        state.dtls_mtu_size
    } else {
        0
    }
}

unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    BIO_set_init(bio, 0);
    BIO_set_num(bio, 0);
    BIO_set_data(bio, ptr::null_mut());
    BIO_set_flags(bio, 0);
    1
}

unsafe extern "C" fn destroy<S>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    let data = BIO_get_data(bio);

    if !data.is_null() {
        // Called from C: a panicking stream destructor must not unwind.
        unwind::drop_contained(Box::<StreamState<S>>::from_raw(data.cast()));
        BIO_set_data(bio, ptr::null_mut());
    }

    BIO_set_init(bio, 0);
    1
}

use crate::ffi::{BIO_get_data, BIO_set_data, BIO_set_flags, BIO_set_init};

#[allow(bad_style)]
unsafe fn BIO_set_num(_bio: *mut ffi::BIO, _num: c_int) {}

#[allow(bad_style, clippy::upper_case_acronyms)]
struct BIO_METHOD(*mut ffi::BIO_METHOD);

impl BIO_METHOD {
    fn new<S: Read + Write>() -> BIO_METHOD {
        unsafe {
            let ptr = ffi::BIO_meth_new(ffi::BIO_TYPE_NONE, c"rust".as_ptr().cast());
            assert!(!ptr.is_null());
            let ret = BIO_METHOD(ptr);
            assert!(ffi::BIO_meth_set_write(ptr, Some(bwrite::<S>)) != 0);
            assert!(ffi::BIO_meth_set_read(ptr, Some(bread::<S>)) != 0);
            assert!(ffi::BIO_meth_set_puts(ptr, Some(bputs::<S>)) != 0);
            assert!(ffi::BIO_meth_set_ctrl(ptr, Some(ctrl::<S>)) != 0);
            assert!(ffi::BIO_meth_set_create(ptr, Some(create)) != 0);
            assert!(ffi::BIO_meth_set_destroy(ptr, Some(destroy::<S>)) != 0);
            ret
        }
    }

    fn get(&self) -> *mut ffi::BIO_METHOD {
        self.0
    }
}

impl Drop for BIO_METHOD {
    fn drop(&mut self) {
        unsafe {
            ffi::BIO_meth_free(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    /// An error source whose destructor panics.
    #[derive(Debug)]
    struct Doomed;

    impl std::fmt::Display for Doomed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("doomed")
        }
    }

    impl std::error::Error for Doomed {}

    impl Drop for Doomed {
        fn drop(&mut self) {
            panic!("error destructor");
        }
    }

    /// A transport whose flush panics, counting every call.
    struct Transport {
        calls: Arc<AtomicUsize>,
    }

    impl Read for Transport {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.calls.fetch_add(1, SeqCst);
            Ok(0)
        }
    }

    impl Write for Transport {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls.fetch_add(1, SeqCst);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.calls.fetch_add(1, SeqCst);
            panic!("flush")
        }
    }

    fn bio(calls: &Arc<AtomicUsize>) -> (*mut BIO, BioMethod) {
        new(Transport {
            calls: calls.clone(),
        })
        .unwrap()
    }

    isolated_test! {
        fn pending_errors_are_dropped_contained() {
            let calls = Arc::default();
            let (bio, _method) = bio(&calls);
            unsafe {
                let state = state::<Transport>(bio);
                state.error = Some(io::Error::other(Doomed));
                // Replacing it, as a failing transport call does, is contained.
                state.set_error(io::Error::other(Doomed));
                // So is extracting the stream with an error still pending.
                drop(take_stream::<Transport>(bio));
                ffi::BIO_free_all(bio);
            }
        }
    }

    isolated_test! {
        fn flushing_follows_the_transport_poison() {
            let calls = Arc::new(AtomicUsize::new(0));
            let (bio, _method) = bio(&calls);
            unsafe {
                let error = flush::<Transport>(bio).unwrap_err();
                assert!(error.to_string().contains("panicked: flush"), "{error}");
                let used = calls.load(SeqCst);
                for _ in 0..3 {
                    assert!(flush::<Transport>(bio).is_err());
                }
                assert_eq!(calls.load(SeqCst), used, "a poisoned stream was flushed");
                ffi::BIO_free_all(bio);
            }
        }
    }
}
