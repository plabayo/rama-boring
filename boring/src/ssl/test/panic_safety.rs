//! Every Rust callback BoringSSL calls must contain its panics: the process keeps
//! running and the panic becomes an error of the affected operation (or, for
//! callbacks that only observe, is contained without affecting the handshake).
//! Each test runs in its own process, so a missing guard aborts only that test.

use crate::{
    pkey::PKey,
    ssl::{
        AsyncSelectCertError, BoxCertificateFinish, CertificateCompressionAlgorithm,
        CertificateCompressor, CertificateSelection, HandshakeError, MidHandshakeSslStream,
        PrivateKeyMethod, PrivateKeyMethodError, Ssl, SslContext, SslContextBuilder, SslFiletype,
        SslMethod, SslOptions, SslRef, SslSessionCacheMode, SslSignatureAlgorithm, SslStream,
        SslVerifyMode, SslVersion, StatusType,
    },
    x509::X509VerifyError,
};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc, Mutex,
    },
    task::Waker,
};

type Buffer = Arc<Mutex<VecDeque<u8>>>;

/// One end of an in-memory, nonblocking transport.
struct End {
    rx: Buffer,
    tx: Buffer,
}

impl Read for End {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.rx.lock().unwrap();
        if rx.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = rx.len().min(buf.len());
        for (slot, byte) in buf.iter_mut().zip(rx.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

impl Write for End {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx.lock().unwrap().extend(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ends() -> (End, End) {
    let (a, b) = (Buffer::default(), Buffer::default());
    (
        End {
            rx: a.clone(),
            tx: b.clone(),
        },
        End { rx: b, tx: a },
    )
}

enum Side<S> {
    Mid(MidHandshakeSslStream<S>),
    Done(SslStream<S>),
    Failed(String),
}

impl<S: Read + Write> Side<S> {
    fn from(result: Result<SslStream<S>, HandshakeError<S>>) -> Self {
        match result {
            Ok(stream) => Self::Done(stream),
            Err(HandshakeError::WouldBlock(mid)) => Self::Mid(mid),
            Err(HandshakeError::Failure(mid)) => Self::Failed(mid.error().to_string()),
            Err(HandshakeError::SetupFailure(error)) => Self::Failed(error.to_string()),
        }
    }

    fn step(self) -> Self {
        match self {
            Self::Mid(mid) => Self::from(mid.handshake()),
            other => other,
        }
    }

    #[track_caller]
    fn done(self) -> SslStream<S> {
        match self {
            Self::Done(stream) => stream,
            Self::Mid(_) => panic!("handshake stalled"),
            Self::Failed(error) => panic!("handshake failed: {error}"),
        }
    }

    /// The handshake failed because the named callback panicked.
    #[track_caller]
    fn panicked(&self, what: &str) {
        match self {
            Self::Failed(error) => assert!(
                error.contains(&format!("callback panicked: {what}")),
                "{error}"
            ),
            Self::Done(_) => panic!("handshake succeeded"),
            Self::Mid(_) => panic!("handshake stalled"),
        }
    }

    #[track_caller]
    fn failed(&self) {
        assert!(matches!(self, Self::Failed(_)), "handshake did not fail");
    }
}

/// Runs both handshakes over an in-memory transport until neither can progress.
fn handshake(client: Ssl, server: Ssl) -> (Side<End>, Side<End>) {
    let (a, b) = ends();
    let mut client = Side::from(client.connect(a));
    let mut server = Side::from(server.accept(b));
    for _ in 0..32 {
        client = client.step();
        server = server.step();
        if !matches!(client, Side::Mid(_)) && !matches!(server, Side::Mid(_)) {
            break;
        }
    }
    (client, server)
}

fn server_context() -> SslContextBuilder {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_certificate_chain_file("test/cert.pem").unwrap();
    ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    ctx
}

fn client_context() -> SslContextBuilder {
    SslContext::builder(SslMethod::tls()).unwrap()
}

fn connect(client: SslContextBuilder, server: SslContextBuilder) -> (Side<End>, Side<End>) {
    handshake(
        Ssl::new(&client.build()).unwrap(),
        Ssl::new(&server.build()).unwrap(),
    )
}

isolated_test! {
    fn context_verify_callback() {
        let mut client = client_context();
        client.set_verify_callback(SslVerifyMode::PEER, |_, _| panic!("verify"));
        connect(client, server_context()).0.panicked("verify");
    }
}

isolated_test! {
    fn ignored_verify_callback_still_records_the_failure() {
        let mut client = client_context();
        client.set_verify_callback(SslVerifyMode::NONE, |_, _| panic!("verify"));
        let (client, server) = connect(client, server_context());
        let client = client.done();
        server.done();
        assert_eq!(
            client.ssl().verify_result(),
            Err(X509VerifyError::APPLICATION_VERIFICATION)
        );
    }
}

isolated_test! {
    fn connection_verify_callback() {
        let mut client = Ssl::new(&client_context().build()).unwrap();
        client.set_verify_callback(SslVerifyMode::PEER, |_, _| panic!("verify"));
        let server = Ssl::new(&server_context().build()).unwrap();
        handshake(client, server).0.panicked("verify");
    }
}

isolated_test! {
    fn certificate_verify_callback() {
        let mut client = client_context();
        client.set_verify(SslVerifyMode::PEER);
        client.set_cert_verify_callback(|_| panic!("chain"));
        connect(client, server_context()).0.panicked("chain");
    }
}

isolated_test! {
    fn custom_verify_callbacks() {
        let mut client = client_context();
        client.set_custom_verify_callback(SslVerifyMode::PEER, |_| panic!("custom"));
        connect(client, server_context()).0.panicked("custom");

        let mut client = Ssl::new(&client_context().build()).unwrap();
        client.set_custom_verify_callback(SslVerifyMode::PEER, |_| panic!("custom"));
        let server = Ssl::new(&server_context().build()).unwrap();
        handshake(client, server).0.panicked("custom");
    }
}

isolated_test! {
    fn servername_callback() {
        let mut server = server_context();
        server.set_servername_callback(|_, _| panic!("sni"));
        let mut client = Ssl::new(&client_context().build()).unwrap();
        client.set_hostname("panic.test").unwrap();
        let (client, server) = handshake(client, Ssl::new(&server.build()).unwrap());
        server.panicked("sni");
        client.failed();
    }
}

isolated_test! {
    fn alpn_select_callback() {
        let mut server = server_context();
        server.set_alpn_select_callback(|_, _| panic!("alpn"));
        let mut client = client_context();
        client.set_alpn_protos(b"\x02h2").unwrap();
        let (client, server) = connect(client, server);
        server.panicked("alpn");
        client.failed();
    }
}

isolated_test! {
    fn early_certificate_selection_callback() {
        let mut server = server_context();
        server.set_select_certificate_callback(|_| panic!("early"));
        connect(client_context(), server).1.panicked("early");
    }
}

isolated_test! {
    fn certificate_callbacks() {
        let mut server = server_context();
        server.set_certificate_callback(|_| panic!("certificate"));
        connect(client_context(), server).1.panicked("certificate");

        let mut server = Ssl::new(&server_context().build()).unwrap();
        server.set_certificate_callback(|_| panic!("certificate"));
        let client = Ssl::new(&client_context().build()).unwrap();
        handshake(client, server).1.panicked("certificate");
    }
}

struct PanickingSigner;

impl PrivateKeyMethod for PanickingSigner {
    fn sign(
        &self,
        _: &mut SslRef,
        _: &[u8],
        _: SslSignatureAlgorithm,
        _: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        panic!("sign")
    }
    fn decrypt(
        &self,
        _: &mut SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError> {
        panic!("decrypt")
    }
    fn complete(&self, _: &mut SslRef, _: &mut [u8]) -> Result<usize, PrivateKeyMethodError> {
        panic!("complete")
    }
}

isolated_test! {
    fn private_key_method() {
        let mut server = SslContext::builder(SslMethod::tls()).unwrap();
        server.set_certificate_chain_file("test/cert.pem").unwrap();
        server.set_private_key_method(PanickingSigner);
        let (client, server) = connect(client_context(), server);
        server.panicked("sign");
        // BoringSSL sends no alert for a signing failure; the client never completes.
        assert!(!matches!(client, Side::Done(_)));
    }
}

isolated_test! {
    fn ocsp_status_callbacks() {
        let mut server = server_context();
        server.set_status_callback(|_| panic!("staple")).unwrap();
        let mut client = Ssl::new(&client_context().build()).unwrap();
        client.set_status_type(StatusType::OCSP).unwrap();
        handshake(client, Ssl::new(&server.build()).unwrap())
            .1
            .panicked("staple");

        let mut client = client_context();
        client.set_status_callback(|_| panic!("status")).unwrap();
        let mut client = Ssl::new(&client.build()).unwrap();
        client.set_status_type(StatusType::OCSP).unwrap();
        handshake(client, Ssl::new(&server_context().build()).unwrap())
            .0
            .panicked("status");
    }
}

isolated_test! {
    fn observing_callbacks_are_contained() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut client = client_context();
        client
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        client.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        let count = calls.clone();
        client.set_new_session_callback(move |_, _| {
            count.fetch_add(1, SeqCst);
            panic!("new session")
        });
        let count = calls.clone();
        client.set_keylog_callback(move |_, _| {
            count.fetch_add(1, SeqCst);
            panic!("keylog")
        });
        let count = calls.clone();
        client.set_info_callback(move |_, _, _| {
            count.fetch_add(1, SeqCst);
            panic!("info")
        });
        let (client, server) = connect(client, server_context());
        let client = client.done();
        server.done();
        assert!(client.ssl().session().is_some());
        // Each kind ran (keylog and info run several times) and was contained.
        assert!(calls.load(SeqCst) >= 3);
        assert!(crate::error::ErrorStack::get().errors().is_empty());
    }
}

isolated_test! {
    fn session_cache_callbacks_are_contained() {
        let mut server = server_context();
        server
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        server.set_options(SslOptions::NO_TICKET);
        server.set_session_id_context(b"panic").unwrap();
        server.set_session_cache_mode(
            SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL_LOOKUP,
        );
        let lookups = Arc::new(AtomicUsize::new(0));
        let count = lookups.clone();
        // A panicking lookup is a miss: the client falls back to a full handshake.
        unsafe {
            server.set_get_session_callback(move |_, _| {
                count.fetch_add(1, SeqCst);
                panic!("lookup")
            });
        }
        let removals = Arc::new(AtomicUsize::new(0));
        let count = removals.clone();
        server.set_remove_session_callback(move |_, _| {
            count.fetch_add(1, SeqCst);
            panic!("remove")
        });
        let server = server.build();
        let mut client = client_context();
        client.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        let client = client.build();

        let (first, accepted) =
            handshake(Ssl::new(&client).unwrap(), Ssl::new(&server).unwrap());
        let session = first.done().ssl().session().unwrap().to_owned();
        let cached = accepted.done().ssl().session().unwrap().to_owned();
        let mut resuming = Ssl::new(&client).unwrap();
        // Same client context and server as the session's origin.
        unsafe { resuming.set_session(&session).unwrap() };
        let (second, _) = handshake(resuming, Ssl::new(&server).unwrap());
        assert!(!second.done().ssl().session_reused());
        // Clients also send a random session ID on their first handshake.
        assert!(lookups.load(SeqCst) >= 1);

        // Same server context that cached the session.
        assert!(unsafe { server.remove_session(&cached) });
        assert_eq!(removals.load(SeqCst), 1);
    }
}

isolated_test! {
    fn psk_callbacks() {
        let psk_context = |client: bool| {
            let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
            ctx.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
            ctx.set_cipher_list("PSK-AES128-CBC-SHA").unwrap();
            if client {
                ctx.set_psk_client_callback(|_, _, identity, psk| {
                    identity[..4].copy_from_slice(b"user");
                    psk[..16].copy_from_slice(&[7; 16]);
                    Ok(16)
                });
            } else {
                ctx.set_psk_server_callback(|_, _, psk| {
                    psk[..16].copy_from_slice(&[7; 16]);
                    Ok(16)
                });
            }
            ctx
        };
        connect(psk_context(true), psk_context(false)).0.done();

        let mut client = psk_context(true);
        client.set_psk_client_callback(|_, _, _, _| panic!("client psk"));
        connect(client, psk_context(false)).0.panicked("client psk");

        let mut server = psk_context(false);
        server.set_psk_server_callback(|_, _, _| panic!("server psk"));
        connect(psk_context(true), server).1.panicked("server psk");
    }
}

isolated_test! {
    fn ticket_key_callback() {
        let mut server = server_context();
        unsafe {
            server.set_ticket_key_callback(|_, _, _, _, _, _| panic!("ticket"));
        }
        let mut client = client_context();
        client
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        client.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        connect(client, server).1.panicked("ticket");
    }
}

/// Advertises decompression, which panics.
struct DecompressPanics;

impl CertificateCompressor for DecompressPanics {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm(0xff01);
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, _: &[u8], _: &mut W) -> io::Result<()> {
        panic!("decompress")
    }
}

/// "Compresses" certificates by copying them.
struct CopyCompressor;

impl CertificateCompressor for CopyCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm(0xff01);
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = false;

    fn compress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        output.write_all(input)
    }
}

/// Panics while compressing.
struct CompressPanics;

impl CertificateCompressor for CompressPanics {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm(0xff01);
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = false;

    fn compress<W: Write>(&self, _: &[u8], _: &mut W) -> io::Result<()> {
        panic!("compress")
    }
}

isolated_test! {
    fn certificate_compression_callbacks() {
        let mut server = server_context();
        server
            .add_certificate_compression_algorithm(CompressPanics)
            .unwrap();
        let mut client = client_context();
        client
            .add_certificate_compression_algorithm(DecompressPanics)
            .unwrap();
        connect(client, server).1.panicked("compress");

        let mut server = server_context();
        server
            .add_certificate_compression_algorithm(CopyCompressor)
            .unwrap();
        let mut client = client_context();
        client
            .add_certificate_compression_algorithm(DecompressPanics)
            .unwrap();
        connect(client, server).0.panicked("decompress");
    }
}

isolated_test! {
    fn password_callback() {
        let pem = include_bytes!("../../../test/rsa-encrypted.pem");
        let error = PKey::private_key_from_pem_callback(pem, |_| panic!("password")).unwrap_err();
        assert!(
            error.to_string().contains("callback panicked: password"),
            "{error}"
        );
        // The same key still loads once the callback behaves.
        PKey::private_key_from_pem_callback(pem, |buf| {
            buf[..6].copy_from_slice(b"mypass");
            Ok(6)
        })
        .unwrap();
    }
}

struct PanicOnDrop;

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        panic!("destructor");
    }
}

isolated_test! {
    fn ex_data_destructors() {
        let mut ctx = client_context();
        ctx.set_ex_data(SslContext::new_ex_index().unwrap(), PanicOnDrop);
        let ctx = ctx.build();
        let mut ssl = Ssl::new(&ctx).unwrap();
        ssl.set_ex_data(Ssl::new_ex_index().unwrap(), PanicOnDrop);
        drop(ssl);
        drop(ctx);
    }
}

/// A transport that panics on the selected operation and counts every call.
struct Exploding {
    inner: End,
    read: bool,
    write: bool,
    flush: bool,
    calls: Arc<AtomicUsize>,
}

impl Read for Exploding {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.calls.fetch_add(1, SeqCst);
        assert!(!self.read, "blammo");
        self.inner.read(buf)
    }
}

impl Write for Exploding {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.calls.fetch_add(1, SeqCst);
        assert!(!self.write, "blammo");
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.calls.fetch_add(1, SeqCst);
        assert!(!self.flush, "blammo");
        Ok(())
    }
}

isolated_test! {
    fn panicking_transport_fails_the_handshake() {
        for operation in ["read", "write", "flush"] {
            let (a, b) = ends();
            let stream = Exploding {
                inner: a,
                read: operation == "read",
                write: operation == "write",
                flush: operation == "flush",
                calls: Arc::default(),
            };
            let mut server = Side::from(Ssl::new(&server_context().build()).unwrap().accept(b));
            let mut client = Side::from(Ssl::new(&client_context().build()).unwrap().connect(stream));
            for _ in 0..8 {
                client = client.step();
                server = server.step();
            }
            let Side::Failed(error) = &client else {
                panic!("{operation}: handshake did not fail");
            };
            assert!(
                error.contains("TLS transport stream panicked: blammo"),
                "{operation}: {error}"
            );
        }
    }
}

isolated_test! {
    fn poisoned_transport_is_never_used_again() {
        let (a, _b) = ends();
        let calls = Arc::new(AtomicUsize::new(0));
        let stream = Exploding {
            inner: a,
            read: true,
            write: false,
            flush: false,
            calls: calls.clone(),
        };
        let ssl = Ssl::new(&client_context().build()).unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();
        // The ClientHello is written, then the first read panics.
        let error = stream.connect().unwrap_err();
        assert!(error.to_string().contains("blammo"), "{error}");
        let used = calls.load(SeqCst);
        for _ in 0..3 {
            assert!(stream.connect().is_err());
            assert!(stream.write(b"late").is_err());
            assert!(stream.read(&mut [0; 8]).is_err());
        }
        assert_eq!(
            calls.load(SeqCst),
            used,
            "a poisoned stream was called again"
        );
    }
}

isolated_test! {
    fn transport_destructor() {
        struct Doomed(End, PanicOnDrop);
        impl Read for Doomed {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.read(buf)
            }
        }
        impl Write for Doomed {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.write(buf)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (a, _b) = ends();
        let ssl = Ssl::new(&client_context().build()).unwrap();
        drop(SslStream::new(ssl, Doomed(a, PanicOnDrop)).unwrap());
    }
}

#[derive(Clone, Copy, Debug)]
enum AsyncStage {
    Factory,
    Poll,
    Finish,
}

isolated_test! {
    fn async_certificate_selection_stages() {
        for stage in [AsyncStage::Factory, AsyncStage::Poll, AsyncStage::Finish] {
            let polls = Arc::new(AtomicUsize::new(0));
            let count = polls.clone();
            let mut server = server_context();
            server.set_async_certificate_callback(move |_| {
                if matches!(stage, AsyncStage::Factory) {
                    panic!("factory");
                }
                let count = count.clone();
                Ok(Box::pin(async move {
                    count.fetch_add(1, SeqCst);
                    if matches!(stage, AsyncStage::Poll) {
                        panic!("poll");
                    }
                    Ok(Box::new(|_: CertificateSelection<'_>| -> Result<(), AsyncSelectCertError> {
                        panic!("finish")
                    }) as BoxCertificateFinish)
                }))
            });
            let mut server = Ssl::new(&server.build()).unwrap();
            server.set_task_waker(Some(Waker::noop().clone()));
            let client = Ssl::new(&client_context().build()).unwrap();
            let (_, server) = handshake(client, server);
            let what = match stage {
                AsyncStage::Factory => "factory",
                AsyncStage::Poll => "poll",
                AsyncStage::Finish => "finish",
            };
            server.panicked(what);
            // A panicked future is dropped, never polled again.
            assert!(polls.load(SeqCst) <= 1, "{stage:?}");
        }
    }
}
