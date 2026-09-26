use super::server::Server;
use crate::ssl::{
    CertificateSelection, ErrorCode, HandshakeError, SelectCertError, Ssl, SslContext, SslMethod,
    SslVerifyMode, SslVersion,
};
use std::{
    io::Read,
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc,
    },
    time::Duration,
};

#[test]
fn certificate_selection_retry_uses_want_x509_lookup() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut server = Server::builder();
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        server.ctx().set_verify(SslVerifyMode::PEER);
        let server = server.build();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
        context.set_certificate_callback(move |selection| {
            assert!(!selection.peer_verify_algorithms().is_empty());
            if count.fetch_add(1, SeqCst) < 3 {
                Err(SelectCertError::RETRY)
            } else {
                Ok(())
            }
        });
        let socket = server.connect_tcp();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut result = Ssl::new(&context.build()).unwrap().connect(socket);
        for _ in 0..3 {
            let mid = match result {
                Err(HandshakeError::WouldBlock(mid)) => mid,
                _ => panic!("selection did not pause"),
            };
            assert_eq!(mid.error().code(), ErrorCode::WANT_X509_LOOKUP);
            result = mid.handshake();
        }
        let mut stream = result.unwrap();
        stream.read_exact(&mut [0]).unwrap();
        assert_eq!(calls.load(SeqCst), 4);
    }
}

struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.fetch_add(1, SeqCst);
    }
}

fn replacing_callback(
    probe: DropProbe,
    replace: bool,
) -> impl Fn(CertificateSelection<'_>) -> Result<(), SelectCertError> + Send + Sync {
    move |mut selection| {
        if replace {
            selection
                .ssl_mut()
                .set_certificate_callback(replacing_callback(DropProbe(probe.0.clone()), false));
            assert_eq!(
                probe.0.load(SeqCst),
                0,
                "executing callback was dropped during replacement"
            );
        }
        Ok(())
    }
}

#[test]
fn connection_callback_can_replace_itself_without_dropping_its_captures() {
    let mut server = Server::builder();
    server.ctx().set_verify(SslVerifyMode::PEER);
    let server = server.build();
    let dropped = Arc::new(AtomicUsize::new(0));
    let client = server.client().build();
    let mut client = client.builder();
    client
        .ssl()
        .set_certificate_callback(replacing_callback(DropProbe(dropped.clone()), true));
    let stream = client.connect();
    assert_eq!(dropped.load(SeqCst), 1);
    drop(stream);
    assert_eq!(dropped.load(SeqCst), 2);
}

struct NoopWake;
impl std::task::Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

#[test]
fn pending_selection_is_cancelled_by_every_callback_and_context_replacement() {
    use crate::ssl::{AsyncSelectCertError, BoxCertificateFinish};
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for replacement in 0..7 {
            let mut server = Server::builder();
            server.ctx().set_min_proto_version(Some(version)).unwrap();
            server.ctx().set_max_proto_version(Some(version)).unwrap();
            server.ctx().set_verify(SslVerifyMode::PEER);
            if replacement != 4 {
                server.should_error();
            }
            let server = server.build();
            let dropped = Arc::new(AtomicUsize::new(0));
            let finishes = Arc::new(AtomicUsize::new(0));
            let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (drop_count, finish_count, gate) =
                (dropped.clone(), finishes.clone(), ready.clone());
            let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
            ctx.set_async_certificate_callback(move |_| {
                let probe = DropProbe(drop_count.clone());
                let (finish_count, gate) = (finish_count.clone(), gate.clone());
                Ok(Box::pin(std::future::poll_fn(move |_| {
                    let _keep_alive = &probe;
                    if !gate.load(SeqCst) {
                        return std::task::Poll::Pending;
                    }
                    let count = finish_count.clone();
                    std::task::Poll::Ready(Ok(Box::new(move |_: CertificateSelection<'_>| {
                        count.fetch_add(1, SeqCst);
                        Ok(())
                    }) as BoxCertificateFinish))
                })))
            });
            let ctx = ctx.build();
            let mut ssl = Ssl::new(&ctx).unwrap();
            ssl.set_task_waker(Some(Arc::new(NoopWake).into()));
            let socket = server.connect_tcp();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut mid = match ssl.connect(socket) {
                Err(HandshakeError::WouldBlock(mid)) => mid,
                _ => panic!("selection did not pause"),
            };
            assert_eq!(mid.error().code(), ErrorCode::WANT_X509_LOOKUP);
            assert_eq!(dropped.load(SeqCst), 0);
            match replacement {
                0 => mid
                    .ssl_mut()
                    .set_async_certificate_callback(|_| Err(AsyncSelectCertError)),
                1 => {
                    mid.ssl_mut().set_certificate_callback(|_| Ok(()));
                    assert_eq!(dropped.load(SeqCst), 1);
                    mid.ssl_mut()
                        .set_async_certificate_callback(|_| Err(AsyncSelectCertError));
                }
                2 | 3 => {
                    let mut replacement_ctx = SslContext::builder(SslMethod::tls()).unwrap();
                    if replacement == 3 {
                        replacement_ctx
                            .set_async_certificate_callback(|_| Err(AsyncSelectCertError));
                    }
                    mid.ssl_mut()
                        .set_ssl_context(&replacement_ctx.build())
                        .unwrap();
                }
                4 => mid.ssl_mut().set_ssl_context(&ctx).unwrap(),
                6 => {
                    let other = SslContext::builder(SslMethod::tls()).unwrap().build();
                    mid.ssl_mut().set_ssl_context(&other).unwrap();
                    mid.ssl_mut().set_ssl_context(&ctx).unwrap();
                }
                _ => mid.get_ref().shutdown(std::net::Shutdown::Both).unwrap(),
            }
            ready.store(true, SeqCst);
            if replacement == 4 {
                // Setting the identical context is a native no-op, not reconfiguration.
                assert_eq!(dropped.load(SeqCst), 0);
                let mut stream = mid.handshake().unwrap();
                stream.read_exact(&mut [0]).unwrap();
                assert_eq!(finishes.load(SeqCst), 1);
            } else if replacement == 5 {
                let error = mid.handshake().unwrap_err();
                assert!(
                    matches!(&error, HandshakeError::Failure(mid) if mid.error().io_error().is_some())
                );
                // The error still owns the SSL. Completion must release the future
                // even when the next transport operation fails independently.
                assert_eq!(dropped.load(SeqCst), 1);
                assert_eq!(finishes.load(SeqCst), 1);
            } else {
                assert_eq!(
                    dropped.load(SeqCst),
                    1,
                    "pending future retained after replacement {replacement}"
                );
                assert!(matches!(mid.handshake(), Err(HandshakeError::Failure(_))));
                assert_eq!(finishes.load(SeqCst), 0);
            }
            assert_eq!(dropped.load(SeqCst), 1);
        }
    }
}

#[test]
fn discarded_certificate_callbacks_release_captures_immediately() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let probe = DropProbe(dropped.clone());
    ctx.set_certificate_callback(move |_| {
        let _keep = &probe;
        Ok(())
    });
    ctx.set_certificate_callback(|_| Ok(()));
    assert_eq!(dropped.load(SeqCst), 1);
    let ctx = ctx.build();
    let mut ssl = Ssl::new(&ctx).unwrap();
    for switch_context in [false, true] {
        let probe = DropProbe(dropped.clone());
        ssl.set_async_certificate_callback(move |_| {
            let _keep = &probe;
            Err(crate::ssl::AsyncSelectCertError)
        });
        if switch_context {
            let other = SslContext::builder(SslMethod::tls()).unwrap().build();
            ssl.set_ssl_context(&other).unwrap();
        } else {
            ssl.set_certificate_callback(|_| Ok(()));
        }
        assert_eq!(dropped.load(SeqCst), if switch_context { 3 } else { 2 });
    }
    drop(ssl);
    assert_eq!(dropped.load(SeqCst), 3);
}

#[test]
fn pending_custom_verification_cannot_survive_reconfiguration() {
    use crate::ssl::{BoxCustomVerifyFinish, SslAlert};
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for replacement in 0..6 {
            let mut server = Server::builder();
            server.ctx().set_min_proto_version(Some(version)).unwrap();
            server.ctx().set_max_proto_version(Some(version)).unwrap();
            if replacement != 5 {
                server.should_error();
            }
            let server = server.build();
            let dropped = Arc::new(AtomicUsize::new(0));
            let finishes = Arc::new(AtomicUsize::new(0));
            let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (drops, calls, gate) = (dropped.clone(), finishes.clone(), ready.clone());
            let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
            ctx.set_async_custom_verify_callback(SslVerifyMode::PEER, move |_| {
                let probe = DropProbe(drops.clone());
                let (calls, gate) = (calls.clone(), gate.clone());
                Ok(Box::pin(std::future::poll_fn(move |_| {
                    let _keep = &probe;
                    if !gate.load(SeqCst) {
                        return std::task::Poll::Pending;
                    }
                    let calls = calls.clone();
                    std::task::Poll::Ready(Ok(Box::new(move |_: &mut crate::ssl::SslRef| {
                        calls.fetch_add(1, SeqCst);
                        Ok(())
                    }) as BoxCustomVerifyFinish))
                })))
            });
            let ctx = ctx.build();
            let mut ssl = Ssl::new(&ctx).unwrap();
            ssl.set_task_waker(Some(Arc::new(NoopWake).into()));
            let socket = server.connect_tcp();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut mid = match ssl.connect(socket) {
                Err(HandshakeError::WouldBlock(mid)) => mid,
                _ => panic!("verification did not pause"),
            };
            match replacement {
                0 => mid
                    .ssl_mut()
                    .set_async_custom_verify_callback(SslVerifyMode::PEER, |_| {
                        Err(SslAlert::BAD_CERTIFICATE)
                    }),
                1 => mid
                    .ssl_mut()
                    .set_custom_verify_callback(SslVerifyMode::NONE, |_| Ok(())),
                2 => mid.ssl_mut().set_verify(SslVerifyMode::NONE),
                3 => mid
                    .ssl_mut()
                    .set_verify_callback(SslVerifyMode::NONE, |_, _| true),
                4 => {
                    let other = SslContext::builder(SslMethod::tls()).unwrap().build();
                    mid.ssl_mut().set_ssl_context(&other).unwrap();
                    mid.ssl_mut().set_ssl_context(&ctx).unwrap();
                    mid.ssl_mut().set_verify(SslVerifyMode::NONE);
                }
                _ => mid.ssl_mut().set_ssl_context(&ctx).unwrap(),
            }
            ready.store(true, SeqCst);
            if replacement == 5 {
                assert_eq!(dropped.load(SeqCst), 0);
                let mut stream = mid.handshake().unwrap();
                stream.read_exact(&mut [0]).unwrap();
                assert_eq!(finishes.load(SeqCst), 1);
            } else {
                assert_eq!(dropped.load(SeqCst), 1);
                assert!(matches!(mid.handshake(), Err(HandshakeError::Failure(_))));
                assert_eq!(finishes.load(SeqCst), 0);
            }
            assert_eq!(dropped.load(SeqCst), 1);
        }
    }
}

#[test]
fn pending_early_selection_cannot_be_bypassed_by_context_routing() {
    use crate::ssl::{AsyncSelectCertError, BoxSelectCertFinish, ClientHello, SslFiletype};
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
    };
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for replacement in 0..4 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            // Connect before spawning: a failed connect must not leave accept waiting.
            let socket = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
            let client = std::thread::spawn(move || {
                let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
                ctx.set_min_proto_version(Some(version)).unwrap();
                ctx.set_max_proto_version(Some(version)).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                match Ssl::new(&ctx.build()).unwrap().connect(socket) {
                    Ok(mut stream) => stream.read_exact(&mut [0]).is_ok(),
                    Err(_) => false,
                }
            });
            let dropped = Arc::new(AtomicUsize::new(0));
            let finishes = Arc::new(AtomicUsize::new(0));
            let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (drops, calls, gate) = (dropped.clone(), finishes.clone(), ready.clone());
            let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
            ctx.set_certificate_chain_file("test/cert.pem").unwrap();
            ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
                .unwrap();
            ctx.set_async_select_certificate_callback(move |_| {
                let (probe, calls, gate) = (DropProbe(drops.clone()), calls.clone(), gate.clone());
                Ok(Box::pin(std::future::poll_fn(move |_| {
                    let _keep = &probe;
                    if !gate.load(SeqCst) {
                        return std::task::Poll::Pending;
                    }
                    let calls = calls.clone();
                    std::task::Poll::Ready(Ok(Box::new(move |_: ClientHello<'_>| {
                        calls.fetch_add(1, SeqCst);
                        Ok(())
                    }) as BoxSelectCertFinish))
                })))
            });
            let ctx = ctx.build();
            let mut ssl = Ssl::new(&ctx).unwrap();
            ssl.set_task_waker(Some(Arc::new(NoopWake).into()));
            let socket = listener.accept().unwrap().0;
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut mid = match ssl.accept(socket) {
                Err(HandshakeError::WouldBlock(mid)) => mid,
                _ => panic!("early selection did not pause"),
            };
            if replacement == 3 {
                mid.ssl_mut().set_ssl_context(&ctx).unwrap();
            } else {
                let mut other = SslContext::builder(SslMethod::tls()).unwrap();
                other.set_certificate_chain_file("test/cert.pem").unwrap();
                other
                    .set_private_key_file("test/key.pem", SslFiletype::PEM)
                    .unwrap();
                if replacement == 1 {
                    other.set_async_select_certificate_callback(|_| Err(AsyncSelectCertError));
                }
                mid.ssl_mut().set_ssl_context(&other.build()).unwrap();
                if replacement == 2 {
                    mid.ssl_mut().set_ssl_context(&ctx).unwrap();
                }
                // A later certificate override must not remove the rejection hook.
                mid.ssl_mut().set_certificate_callback(|_| Ok(()));
            }
            ready.store(true, SeqCst);
            if replacement == 3 {
                assert_eq!(dropped.load(SeqCst), 0);
                mid.handshake().unwrap().write_all(&[0]).unwrap();
                assert_eq!(finishes.load(SeqCst), 1);
            } else {
                assert_eq!(dropped.load(SeqCst), 1);
                assert!(matches!(mid.handshake(), Err(HandshakeError::Failure(_))));
                assert_eq!(finishes.load(SeqCst), 0);
            }
            assert_eq!(client.join().unwrap(), replacement == 3);
            assert_eq!(dropped.load(SeqCst), 1);
        }
    }
}

#[test]
fn async_certificate_selection_without_a_waker_fails_without_panicking() {
    let mut server = Server::builder();
    server.ctx().set_verify(SslVerifyMode::PEER);
    server.should_error();
    let server = server.build();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    ctx.set_async_certificate_callback(move |_| {
        count.fetch_add(1, SeqCst);
        Ok(Box::pin(std::future::pending()))
    });
    let socket = server.connect_tcp();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert!(matches!(
        Ssl::new(&ctx.build()).unwrap().connect(socket),
        Err(HandshakeError::Failure(_))
    ));
    assert_eq!(calls.load(SeqCst), 0);
}

#[test]
fn selection_errors_send_internal_error_when_transport_is_writable() {
    use crate::ssl::{AsyncSelectCertError, BoxCertificateFinish};
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for stage in 0..3 {
            let mut server = Server::builder();
            server.ctx().set_min_proto_version(Some(version)).unwrap();
            server.ctx().set_max_proto_version(Some(version)).unwrap();
            server.ctx().set_verify(SslVerifyMode::PEER);
            server.err_cb(|error| {
                let message = error.to_string();
                assert!(message.contains("ALERT_INTERNAL_ERROR"), "{message}");
            });
            let server = server.build();
            let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
            ctx.set_async_certificate_callback(move |_| {
                if stage == 0 {
                    return Err(AsyncSelectCertError);
                }
                Ok(Box::pin(async move {
                    if stage == 1 {
                        return Err(AsyncSelectCertError);
                    }
                    Ok(
                        Box::new(|_: CertificateSelection<'_>| Err(AsyncSelectCertError))
                            as BoxCertificateFinish,
                    )
                }))
            });
            let mut ssl = Ssl::new(&ctx.build()).unwrap();
            ssl.set_task_waker(Some(Arc::new(NoopWake).into()));
            let socket = server.connect_tcp();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            assert!(matches!(
                ssl.connect(socket),
                Err(HandshakeError::Failure(_))
            ));
        }
    }
}

struct PendingSigner {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl crate::ssl::AsyncPrivateKeyMethod for PendingSigner {
    fn sign(
        &self,
        _: &mut crate::ssl::SslRef,
        _: &[u8],
        _: crate::ssl::SslSignatureAlgorithm,
        _: &mut [u8],
    ) -> Result<crate::ssl::BoxPrivateKeyMethodFuture, crate::ssl::AsyncPrivateKeyMethodError> {
        self.calls.fetch_add(1, SeqCst);
        let probe = DropProbe(self.drops.clone());
        Ok(Box::pin(async move {
            let _probe = probe;
            std::future::pending().await
        }))
    }
    fn decrypt(
        &self,
        _: &mut crate::ssl::SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<crate::ssl::BoxPrivateKeyMethodFuture, crate::ssl::AsyncPrivateKeyMethodError> {
        Err(crate::ssl::AsyncPrivateKeyMethodError)
    }
}

#[test]
fn async_signing_requires_a_waker_before_factory_and_resume() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for credential_level in [false, true] {
            for remove_while_pending in [false, true] {
                let (calls, drops) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
                let signer = PendingSigner {
                    calls: calls.clone(),
                    drops: drops.clone(),
                };
                let mut server = Server::builder();
                server.ctx().set_min_proto_version(Some(version)).unwrap();
                server.ctx().set_max_proto_version(Some(version)).unwrap();
                if credential_level {
                    let cert =
                        crate::x509::X509::from_pem(include_bytes!("../../../test/cert.pem"))
                            .unwrap();
                    let mut credential = crate::ssl::SslCredential::builder().unwrap();
                    credential.set_certificate_chain([&cert]).unwrap();
                    credential.set_async_private_key_method(signer).unwrap();
                    server.ctx().add_credential(&credential.build()).unwrap();
                } else {
                    server.ctx().set_async_private_key_method(signer);
                }
                if remove_while_pending {
                    server.ssl_cb(|ssl| ssl.set_task_waker(Some(Arc::new(NoopWake).into())));
                    let drops = drops.clone();
                    server.err_cb(move |error| {
                        let mut mid = match error {
                            HandshakeError::WouldBlock(mid) => mid,
                            other => panic!("signature did not pause: {other}"),
                        };
                        assert_eq!(drops.load(SeqCst), 0);
                        mid.ssl_mut().set_task_waker(None);
                        let error = mid.handshake().unwrap_err();
                        assert!(matches!(error, HandshakeError::Failure(_)));
                        assert_eq!(drops.load(SeqCst), 1);
                    });
                } else {
                    server.should_error();
                }
                let server = server.build();
                let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
                let socket = server.connect_tcp();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                assert!(Ssl::new(&ctx).unwrap().connect(socket).is_err());
                drop(server);
                assert_eq!(calls.load(SeqCst), usize::from(remove_while_pending));
                assert_eq!(drops.load(SeqCst), usize::from(remove_while_pending));
            }
        }
    }
}

#[test]
fn async_session_lookup_without_a_waker_is_a_cache_miss_without_factory_side_effects() {
    use crate::ssl::{SslOptions, SslSessionCacheMode};
    for install_waker in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut server = Server::builder();
        server.expected_connections_count(2);
        server
            .ctx()
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        server.ctx().set_options(SslOptions::NO_TICKET);
        server
            .ctx()
            .set_session_id_context(b"async-lookup-waker")
            .unwrap();
        server
            .ctx()
            .set_session_cache_mode(SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL);
        unsafe {
            // Always returns a miss, so no foreign session can be installed.
            server.ctx().set_async_get_session_callback(move |_, _| {
                count.fetch_add(1, SeqCst);
                Some(Box::pin(async { None }))
            });
        }
        if install_waker {
            server.ssl_cb(|ssl| ssl.set_task_waker(Some(Arc::new(NoopWake).into())));
        }
        let server = server.build();
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
        let ctx = ctx.build();
        let mut session: Option<crate::ssl::SslSession> = None;
        for _ in 0..2 {
            let mut ssl = Ssl::new(&ctx).unwrap();
            if let Some(session) = &session {
                // The session comes from the same context and server.
                unsafe {
                    ssl.set_session(session).unwrap();
                }
            }
            let socket = server.connect_tcp();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = ssl.connect(socket).unwrap();
            stream.read_exact(&mut [0]).unwrap();
            assert!(!stream.ssl().session_reused());
            session = Some(stream.ssl().session().unwrap().to_owned());
        }
        drop(server);
        assert_eq!(calls.load(SeqCst), usize::from(install_waker));
    }
}

#[test]
fn incompatible_context_routing_preserves_the_original_connection() {
    use foreign_types::{ForeignType, ForeignTypeRef};
    let x509 = SslContext::builder(SslMethod::tls()).unwrap().build();
    // No X.509 operations are performed on the buffer-only context or SSL.
    let buffers = SslContext::builder(unsafe { SslMethod::tls_with_buffer() })
        .unwrap()
        .build();
    for (original, destination) in [(&x509, &buffers), (&buffers, &x509)] {
        let mut ssl = Ssl::new(original).unwrap();
        let error = ssl.set_ssl_context(destination).unwrap_err();
        assert!(error.to_string().contains("X.509 certificate support"));
        assert_eq!(ssl.ssl_context().as_ptr(), original.as_ptr());
        ssl.set_ssl_context(original).unwrap();
    }
}

#[test]
fn incompatible_context_routing_in_sni_fails_without_panicking() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        // Routing is rejected before native code can mix X.509 and buffer methods.
        let buffers = SslContext::builder(unsafe { SslMethod::tls_with_buffer() })
            .unwrap()
            .build();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut server = Server::builder();
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        server.ctx().set_servername_callback(move |ssl, _| {
            count.fetch_add(1, SeqCst);
            ssl.set_ssl_context(&buffers)
                .map_err(|_| crate::ssl::SniError::ALERT_FATAL)
        });
        server.should_error();
        let server = server.build();
        let client = server.client().build();
        let mut client = client.builder();
        client.ssl().set_hostname("localhost").unwrap();
        assert!(matches!(client.connect_err(), HandshakeError::Failure(_)));
        drop(server);
        assert_eq!(calls.load(SeqCst), 1);
    }
}
