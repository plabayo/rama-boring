use super::mut_only::MutOnly;
use super::{
    CertificateSelection, ClientHello, GetSessionPendingError, PrivateKeyMethod,
    PrivateKeyMethodError, SelectCertError, Ssl, SslAlert, SslContextBuilder, SslRef, SslSession,
    SslSignatureAlgorithm, SslVerifyError, SslVerifyMode,
};
use crate::{error::ErrorStack, ex_data::Index, ffi};
use foreign_types::ForeignTypeRef;
use std::convert::identity;
use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{ready, Context, Poll, Waker};

/// The type of futures to pass to [`SslContextBuilder::set_async_select_certificate_callback`].
pub type BoxSelectCertFuture = ExDataFuture<Result<BoxSelectCertFinish, AsyncSelectCertError>>;

/// The type of callbacks returned by [`BoxSelectCertFuture`] methods.
pub type BoxSelectCertFinish = Box<dyn FnOnce(ClientHello<'_>) -> Result<(), AsyncSelectCertError>>;

/// Future returned by [`SslContextBuilder::set_async_certificate_callback`].
/// It owns its inputs; it cannot retain a borrow of the TLS connection or request:
///
/// ```compile_fail
/// use rama_boring::ssl::{AsyncSelectCertError, BoxCertificateFuture, CertificateSelection};
/// fn retain(selection: &CertificateSelection<'_>) -> BoxCertificateFuture {
///     let algorithms = selection.peer_verify_algorithms();
///     Box::pin(async move {
///         assert!(!algorithms.is_empty());
///         Err(AsyncSelectCertError)
///     })
/// }
/// ```
pub type BoxCertificateFuture = ExDataFuture<Result<BoxCertificateFinish, AsyncSelectCertError>>;

/// Installs the credentials once a [`BoxCertificateFuture`] completes.
/// Runs synchronously on the polling thread, at most once; never after cancellation.
pub type BoxCertificateFinish =
    Box<dyn FnOnce(CertificateSelection<'_>) -> Result<(), AsyncSelectCertError>>;

/// The type of futures returned by [`AsyncPrivateKeyMethod`] methods.
pub type BoxPrivateKeyMethodFuture =
    ExDataFuture<Result<BoxPrivateKeyMethodFinish, AsyncPrivateKeyMethodError>>;

/// The type of callbacks returned by [`BoxPrivateKeyMethodFuture`].
pub type BoxPrivateKeyMethodFinish =
    Box<dyn FnOnce(&mut SslRef, &mut [u8]) -> Result<usize, AsyncPrivateKeyMethodError>>;

/// The type of futures to pass to [`SslContextBuilder::set_async_get_session_callback`].
pub type BoxGetSessionFuture = ExDataFuture<Option<BoxGetSessionFinish>>;

/// The type of callbacks returned by [`BoxSelectCertFuture`] methods.
pub type BoxGetSessionFinish = Box<dyn FnOnce(&mut SslRef, &[u8]) -> Option<SslSession>>;

/// The type of futures to pass to [`SslContextBuilder::set_async_custom_verify_callback`].
pub type BoxCustomVerifyFuture = ExDataFuture<Result<BoxCustomVerifyFinish, SslAlert>>;

/// The type of callbacks returned by [`BoxCustomVerifyFuture`] methods.
pub type BoxCustomVerifyFinish = Box<dyn FnOnce(&mut SslRef) -> Result<(), SslAlert>>;

/// Convenience alias for futures stored in [`Ssl`] ex data by [`SslContextBuilder`] methods.
///
/// Public for documentation purposes.
pub type ExDataFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub(crate) static TASK_WAKER_INDEX: LazyLock<Index<Ssl, Option<Waker>>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());
static SELECT_CERT_STATE_INDEX: LazyLock<Index<Ssl, MutOnly<CallbackState<BoxSelectCertFuture>>>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());
static CERTIFICATE_SELECTION_STATE_INDEX: LazyLock<
    Index<Ssl, MutOnly<CallbackState<BoxCertificateFuture>>>,
> = LazyLock::new(|| Ssl::new_ex_index().unwrap());
pub(crate) static SELECT_PRIVATE_KEY_METHOD_FUTURE_INDEX: LazyLock<
    Index<Ssl, MutOnly<Option<BoxPrivateKeyMethodFuture>>>,
> = LazyLock::new(|| Ssl::new_ex_index().unwrap());
pub(crate) static SELECT_GET_SESSION_FUTURE_INDEX: LazyLock<
    Index<Ssl, MutOnly<Option<BoxGetSessionFuture>>>,
> = LazyLock::new(|| Ssl::new_ex_index().unwrap());
static CUSTOM_VERIFY_STATE_INDEX: LazyLock<
    Index<Ssl, MutOnly<CallbackState<BoxCustomVerifyFuture>>>,
> = LazyLock::new(|| Ssl::new_ex_index().unwrap());

enum CallbackState<F> {
    Idle,
    Running,
    Pending(F),
    Invalidated,
}

fn invalidate<F: Send + 'static>(
    ssl: &mut SslRef,
    index: Index<Ssl, MutOnly<CallbackState<F>>>,
) -> bool {
    let Some(state) = ssl.ex_data_mut(index).map(MutOnly::get_mut) else {
        return false;
    };
    match state {
        CallbackState::Idle => false,
        _ => {
            *state = CallbackState::Invalidated;
            true
        }
    }
}

// Reject even when a replacement context/callback would otherwise skip the hook.
pub(super) fn invalidate_certificate_selection(ssl: &mut SslRef) {
    let invalidated = invalidate(ssl, *CERTIFICATE_SELECTION_STATE_INDEX);
    let early_invalidated = ssl
        .ex_data_mut(*SELECT_CERT_STATE_INDEX)
        .is_some_and(|state| matches!(state.get_mut(), CallbackState::Invalidated));
    if invalidated || early_invalidated {
        unsafe {
            ffi::SSL_set_cert_cb(
                ssl.as_ptr(),
                Some(invalidated_certificate_callback),
                std::ptr::null_mut(),
            );
        }
    }
}

pub(super) fn invalidate_custom_verify(ssl: &mut SslRef) {
    if invalidate(ssl, *CUSTOM_VERIFY_STATE_INDEX) {
        // SSL_VERIFY_NONE would suppress a verification failure on clients.
        let mode = ssl.verify_mode() | SslVerifyMode::PEER;
        unsafe {
            ffi::SSL_set_custom_verify(
                ssl.as_ptr(),
                mode.bits() as _,
                Some(invalidated_verify_callback),
            );
        }
    }
}

pub(super) fn context_changed(ssl: &mut SslRef) {
    invalidate(ssl, *SELECT_CERT_STATE_INDEX);
    invalidate_certificate_selection(ssl);
    invalidate_custom_verify(ssl);
}

unsafe extern "C" fn invalidated_verify_callback(
    _: *mut ffi::SSL,
    alert: *mut u8,
) -> ffi::ssl_verify_result_t {
    unsafe {
        *alert = SslAlert::INTERNAL_ERROR.0 as u8;
    }
    ffi::ssl_verify_result_t::ssl_verify_invalid
}

unsafe extern "C" fn invalidated_certificate_callback(
    _: *mut ffi::SSL,
    _: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    0
}

impl SslContextBuilder {
    /// Sets a callback that is called before most [`ClientHello`] processing
    /// and before the decision whether to resume a session is made. The
    /// callback may inspect the [`ClientHello`] and configure the connection.
    ///
    /// This method uses a function that returns a future whose output is
    /// itself a closure that will be passed [`ClientHello`] to configure
    /// the connection based on the computations done in the future.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// Changing contexts while the factory or future is active aborts the handshake.
    /// Context routing remains supported in the finish closure.
    ///
    /// See [`SslContextBuilder::set_select_certificate_callback`] for the sync
    /// setter of this callback.
    pub fn set_async_select_certificate_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static,
    {
        self.set_select_certificate_callback(move |mut client_hello| {
            match with_callback_state(
                &mut client_hello,
                *SELECT_CERT_STATE_INDEX,
                ClientHello::ssl_mut,
                &callback,
                |hello, finish| {
                    // Context routing is the early callback's job, unlike late selection.
                    *callback_state(hello.ssl_mut(), *SELECT_CERT_STATE_INDEX) =
                        CallbackState::Idle;
                    finish(ClientHello(hello.0))
                },
                AsyncSelectCertError,
            ) {
                Poll::Ready(result) => result.map_err(|_| SelectCertError::ERROR),
                Poll::Pending => Err(SelectCertError::RETRY),
            }
        });
    }

    /// Asynchronously selects credentials using [`Self::set_certificate_callback`].
    /// The factory runs once per selection; its future is retained across retries
    /// and dropped with the SSL connection. Copy any borrowed request metadata
    /// into the future, then configure the SSL in the returned finish callback.
    /// Replacing the callback or changing contexts while its factory, future or finish is
    /// active aborts the handshake and discards the old selection. A pending
    /// selection does no transport I/O; callers should enforce a deadline.
    ///
    /// A task waker must be installed with [`SslRef::set_task_waker`];
    /// `rama-boring-tokio` handles this automatically.
    /// Dropping the SSL drops its pending future without calling the finish closure.
    /// This does not undo external effects or cancel independently spawned tasks.
    ///
    /// Install an authoritative credential after asynchronous work:
    /// ```
    /// use rama_boring::ssl::{AsyncSelectCertError, BoxCertificateFinish,
    ///     CertificateSelection, SslContextBuilder, SslCredential};
    /// fn configure(ctx: &mut SslContextBuilder, credential: SslCredential) {
    ///     ctx.set_async_certificate_callback(move |_| {
    ///         let credential = credential.clone();
    ///         Ok(Box::pin(async move {
    ///             // Await credential lookup or ingress authentication here.
    ///             Ok(Box::new(move |mut selection: CertificateSelection<'_>| {
    ///                 let ssl = selection.ssl_mut();
    ///                 ssl.clear_certificates();
    ///                 ssl.add_credential(&credential).map_err(|_| AsyncSelectCertError)
    ///             }) as BoxCertificateFinish)
    ///         }))
    ///     });
    /// }
    /// ```
    pub fn set_async_certificate_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut CertificateSelection<'_>) -> Result<BoxCertificateFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static,
    {
        self.set_certificate_callback(async_certificate_callback(callback));
    }

    /// Configures a custom private key method on the context.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// See [`AsyncPrivateKeyMethod`] for more details.
    pub fn set_async_private_key_method(&mut self, method: impl AsyncPrivateKeyMethod) {
        self.set_private_key_method(AsyncPrivateKeyMethodBridge(Box::new(method)));
    }

    /// Sets a callback that is called when a client proposed to resume a session
    /// but it was not found in the internal cache.
    ///
    /// The callback is passed a reference to the session ID provided by the client.
    /// It should return the session corresponding to that ID if available. This is
    /// only used for servers, not clients.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// See [`SslContextBuilder::set_get_session_callback`] for the sync setter
    /// of this callback.
    ///
    /// # Safety
    ///
    /// The returned [`SslSession`] must not be associated with a different [`SslContextBuilder`].
    ///
    /// [`SslContext`]: super::SslContext
    pub unsafe fn set_async_get_session_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &[u8]) -> Option<BoxGetSessionFuture> + Send + Sync + 'static,
    {
        let async_callback = move |ssl: &mut SslRef, id: &[u8]| {
            let fut_poll_result = with_ex_data_future(
                &mut *ssl,
                *SELECT_GET_SESSION_FUTURE_INDEX,
                |ssl| ssl,
                |ssl| callback(ssl, id).ok_or(()),
                |option| option.ok_or(()),
            );

            match fut_poll_result {
                Poll::Ready(Err(())) => Ok(None),
                Poll::Ready(Ok(finish)) => Ok(finish(ssl, id)),
                Poll::Pending => Err(GetSessionPendingError),
            }
        };

        self.set_get_session_callback(async_callback);
    }

    /// Configures certificate verification.
    ///
    /// The callback should return `Ok(())` if the certificate is valid.
    /// If the certificate is invalid, the callback should return `SslVerifyError::Invalid(alert)`.
    /// Some useful alerts include [`SslAlert::CERTIFICATE_EXPIRED`], [`SslAlert::CERTIFICATE_REVOKED`],
    /// [`SslAlert::UNKNOWN_CA`], [`SslAlert::BAD_CERTIFICATE`], [`SslAlert::CERTIFICATE_UNKNOWN`],
    /// and [`SslAlert::INTERNAL_ERROR`]. See RFC 5246 section 7.2.2 for their precise meanings.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting
    /// `SslContext` with [`SslRef::set_task_waker`].
    ///
    /// Replacing the verification callback or mode, or changing contexts, while
    /// this callback is active cancels verification and aborts the handshake.
    ///
    /// See [`SslContextBuilder::set_custom_verify_callback`] for the sync version of this method.
    ///
    /// # Panics
    ///
    /// This method panics if this `Ssl` is associated with a RPK context.
    pub fn set_async_custom_verify_callback<F>(&mut self, mode: SslVerifyMode, callback: F)
    where
        F: Fn(&mut SslRef) -> Result<BoxCustomVerifyFuture, SslAlert> + Send + Sync + 'static,
    {
        self.set_custom_verify_callback(mode, async_custom_verify_callback(callback));
    }
}

impl super::SslCredentialBuilder {
    /// Configures an asynchronous signer on this credential.
    /// See [`AsyncPrivateKeyMethod`] and [`SslRef::set_task_waker`].
    pub fn set_async_private_key_method(
        &mut self,
        method: impl AsyncPrivateKeyMethod,
    ) -> Result<(), ErrorStack> {
        self.set_private_key_method(AsyncPrivateKeyMethodBridge(Box::new(method)))
    }
}

impl SslRef {
    /// Overrides this connection's async certificate selection.
    /// See [`SslContextBuilder::set_async_certificate_callback`].
    pub fn set_async_certificate_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut CertificateSelection<'_>) -> Result<BoxCertificateFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static,
    {
        self.set_certificate_callback(async_certificate_callback(callback));
    }

    pub fn set_async_custom_verify_callback<F>(&mut self, mode: SslVerifyMode, callback: F)
    where
        F: Fn(&mut SslRef) -> Result<BoxCustomVerifyFuture, SslAlert> + Send + Sync + 'static,
    {
        self.set_custom_verify_callback(mode, async_custom_verify_callback(callback));
    }

    /// Sets the task waker to be used in async callbacks installed on this `Ssl`.
    pub fn set_task_waker(&mut self, waker: Option<Waker>) {
        self.replace_ex_data(*TASK_WAKER_INDEX, waker);
    }
}

fn callback_state<F: Send + 'static>(
    ssl: &mut SslRef,
    index: Index<Ssl, MutOnly<CallbackState<F>>>,
) -> &mut CallbackState<F> {
    if ssl.ex_data(index).is_none() {
        ssl.set_ex_data(index, MutOnly::new(CallbackState::Idle));
    }
    ssl.ex_data_mut(index).unwrap().get_mut()
}

type CallbackStateIndex<T, E> = Index<Ssl, MutOnly<CallbackState<ExDataFuture<Result<T, E>>>>>;

// Own the future while polling and keep the operation active through its finish.
fn with_callback_state<H, T: 'static, E: Copy + 'static>(
    handle: &mut H,
    index: CallbackStateIndex<T, E>,
    ssl_mut: impl Fn(&mut H) -> &mut SslRef,
    create: impl FnOnce(&mut H) -> Result<ExDataFuture<Result<T, E>>, E>,
    finish: impl FnOnce(&mut H, T) -> Result<(), E>,
    invalidated_error: E,
) -> Poll<Result<(), E>> {
    let state = callback_state(ssl_mut(handle), index);
    let future = match std::mem::replace(state, CallbackState::Running) {
        CallbackState::Idle => create(handle),
        CallbackState::Pending(future) => Ok(future),
        CallbackState::Running | CallbackState::Invalidated => {
            *state = CallbackState::Invalidated;
            return Poll::Ready(Err(invalidated_error));
        }
    };
    let result = (|| {
        let mut future = future?;
        if matches!(
            callback_state(ssl_mut(handle), index),
            CallbackState::Invalidated
        ) {
            return Poll::Ready(Err(invalidated_error));
        }
        let Some(waker) = ssl_mut(handle)
            .ex_data(*TASK_WAKER_INDEX)
            .cloned()
            .flatten()
        else {
            return Poll::Ready(Err(invalidated_error));
        };
        match future.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Pending => {
                *callback_state(ssl_mut(handle), index) = CallbackState::Pending(future);
                Poll::Pending
            }
            Poll::Ready(result) => {
                drop(future);
                Poll::Ready(result.and_then(|value| finish(handle, value)))
            }
        }
    })();
    let state = callback_state(ssl_mut(handle), index);
    if matches!(state, CallbackState::Invalidated) {
        Poll::Ready(Err(invalidated_error))
    } else {
        if result.is_ready() {
            *state = CallbackState::Idle;
        }
        result
    }
}

fn async_certificate_callback<F>(
    callback: F,
) -> impl Fn(CertificateSelection<'_>) -> Result<(), SelectCertError>
where
    F: Fn(&mut CertificateSelection<'_>) -> Result<BoxCertificateFuture, AsyncSelectCertError>
        + Send
        + Sync
        + 'static,
{
    move |mut selection| match with_callback_state(
        &mut selection,
        *CERTIFICATE_SELECTION_STATE_INDEX,
        CertificateSelection::ssl_mut,
        &callback,
        |selection, finish| finish(CertificateSelection(selection.ssl_mut())),
        AsyncSelectCertError,
    ) {
        Poll::Pending => Err(SelectCertError::RETRY),
        Poll::Ready(result) => result.map_err(|_| SelectCertError::ERROR),
    }
}

fn async_custom_verify_callback<F>(
    callback: F,
) -> impl Fn(&mut SslRef) -> Result<(), SslVerifyError>
where
    F: Fn(&mut SslRef) -> Result<BoxCustomVerifyFuture, SslAlert> + Send + Sync + 'static,
{
    move |ssl| match with_callback_state(
        &mut *ssl,
        *CUSTOM_VERIFY_STATE_INDEX,
        |ssl| ssl,
        &callback,
        |ssl, finish| finish(ssl),
        SslAlert::INTERNAL_ERROR,
    ) {
        Poll::Ready(result) => result.map_err(SslVerifyError::Invalid),
        Poll::Pending => Err(SslVerifyError::Retry),
    }
}

/// A fatal error to be returned from async select certificate callbacks.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AsyncSelectCertError;

/// Describes async private key hooks. This is used to off-load signing
/// operations to a custom, potentially asynchronous, backend. Metadata about the
/// key such as the type and size are parsed out of the certificate.
///
/// See [`PrivateKeyMethod`] for the sync version of those hooks.
///
/// [`ssl_private_key_method_st`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#ssl_private_key_method_st
pub trait AsyncPrivateKeyMethod: Send + Sync + 'static {
    /// Signs the message `input` using the specified signature algorithm.
    ///
    /// This method uses a function that returns a future whose output is
    /// itself a closure that will be passed `ssl` and `output`
    /// to finish writing the signature.
    ///
    /// See [`PrivateKeyMethod::sign`] for the sync version of this method.
    fn sign(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        signature_algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>;

    /// Decrypts `input`.
    ///
    /// This method uses a function that returns a future whose output is
    /// itself a closure that will be passed `ssl` and `output`
    /// to finish decrypting the input.
    ///
    /// See [`PrivateKeyMethod::decrypt`] for the sync version of this method.
    fn decrypt(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>;
}

/// A fatal error to be returned from async private key methods.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AsyncPrivateKeyMethodError;

struct AsyncPrivateKeyMethodBridge(Box<dyn AsyncPrivateKeyMethod>);

impl PrivateKeyMethod for AsyncPrivateKeyMethodBridge {
    fn sign(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        signature_algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        with_private_key_method(ssl, output, |ssl, output| {
            <dyn AsyncPrivateKeyMethod>::sign(&*self.0, ssl, input, signature_algorithm, output)
        })
    }

    fn decrypt(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        with_private_key_method(ssl, output, |ssl, output| {
            <dyn AsyncPrivateKeyMethod>::decrypt(&*self.0, ssl, input, output)
        })
    }

    fn complete(
        &self,
        ssl: &mut SslRef,
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        with_private_key_method(ssl, output, |_, _| {
            // This should never be reached, if it does, that's a bug on boring's side,
            // which called `complete` without having been returned to with a pending
            // future from `sign` or `decrypt`.

            if cfg!(debug_assertions) {
                panic!("BUG: boring called complete without a pending operation");
            }

            Err(AsyncPrivateKeyMethodError)
        })
    }
}

/// Creates and drives a private key method future.
///
/// This is a convenience function for the three methods of impl `PrivateKeyMethod``
/// for `dyn AsyncPrivateKeyMethod`. It relies on [`with_ex_data_future`] to
/// drive the future and then immediately calls the final [`BoxPrivateKeyMethodFinish`]
/// when the future is ready.
fn with_private_key_method(
    ssl: &mut SslRef,
    output: &mut [u8],
    create_fut: impl FnOnce(
        &mut SslRef,
        &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>,
) -> Result<usize, PrivateKeyMethodError> {
    let fut_poll_result = with_ex_data_future(
        ssl,
        *SELECT_PRIVATE_KEY_METHOD_FUTURE_INDEX,
        |ssl| ssl,
        |ssl| create_fut(ssl, output),
        identity,
    );

    let fut_result = match fut_poll_result {
        Poll::Ready(fut_result) => fut_result,
        Poll::Pending => return Err(PrivateKeyMethodError::RETRY),
    };

    let finish = fut_result.or(Err(PrivateKeyMethodError::FAILURE))?;

    finish(ssl, output).or(Err(PrivateKeyMethodError::FAILURE))
}

/// Creates and drives a future stored in `ssl_handle`'s `Ssl` at ex data index `index`.
///
/// This function won't even bother storing the future in `index` if the future
/// created by `create_fut` returns `Poll::Ready(_)` on the first poll call.
fn with_ex_data_future<H, R, T, E>(
    ssl_handle: &mut H,
    index: Index<Ssl, MutOnly<Option<ExDataFuture<R>>>>,
    get_ssl_mut: impl Fn(&mut H) -> &mut SslRef,
    create_fut: impl FnOnce(&mut H) -> Result<ExDataFuture<R>, E>,
    into_result: impl Fn(R) -> Result<T, E>,
) -> Poll<Result<T, E>> {
    let ssl = get_ssl_mut(ssl_handle);
    let waker = ssl
        .ex_data(*TASK_WAKER_INDEX)
        .cloned()
        .flatten()
        .expect("task waker should be set");

    let mut ctx = Context::from_waker(&waker);

    if let Some(data @ Some(_)) = ssl.ex_data_mut(index).map(MutOnly::get_mut) {
        let fut_result = into_result(ready!(data.as_mut().unwrap().as_mut().poll(&mut ctx)));

        *data = None;

        Poll::Ready(fut_result)
    } else {
        let mut fut = create_fut(ssl_handle)?;

        match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(fut_result) => Poll::Ready(into_result(fut_result)),
            Poll::Pending => {
                get_ssl_mut(ssl_handle).replace_ex_data(index, MutOnly::new(Some(fut)));

                Poll::Pending
            }
        }
    }
}
