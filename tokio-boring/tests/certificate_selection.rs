use rama_boring::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{
        AsyncSelectCertError, BoxCertificateFinish, BoxCertificateFuture, CertificateSelection,
        Ssl, SslAcceptor, SslAcceptorBuilder, SslConnector, SslConnectorBuilder, SslCredential,
        SslMethod, SslSignatureAlgorithm, SslVerifyMode, SslVersion,
    },
    x509::{
        extension::{BasicConstraints, SubjectAlternativeName},
        X509Name, X509,
    },
};
use rama_boring_tokio::SslStreamBuilder;
use std::{
    error::Error,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc, OnceLock,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

const VERSIONS: [SslVersion; 2] = [SslVersion::TLS1_2, SslVersion::TLS1_3];
type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

struct Identity {
    cert: X509,
    key: PKey<Private>,
}
impl Identity {
    fn new(name: &str, issuer: Option<&Self>) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut subject = X509Name::builder().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&subject).unwrap();
        cert.set_issuer_name(issuer.map_or(&*subject, |i| i.cert.subject_name()))
            .unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        let mut constraints = BasicConstraints::new();
        constraints.critical();
        if issuer.is_none() {
            constraints.ca();
        }
        cert.append_extension(&constraints.build().unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&cert.x509v3_context(issuer.map(|i| &*i.cert), None))
            .unwrap();
        cert.append_extension(&san).unwrap();
        cert.sign(issuer.map_or(&key, |i| &i.key), MessageDigest::sha256())
            .unwrap();
        Self {
            cert: cert.build(),
            key,
        }
    }
    fn credential(&self) -> SslCredential {
        let mut cred = SslCredential::builder().unwrap();
        cred.set_certificate_chain([&self.cert]).unwrap();
        cred.set_private_key(&self.key).unwrap();
        cred.build()
    }
}
struct Materials {
    ca: Identity,
    server: Identity,
    client: Identity,
    other_ca: Identity,
    other_client: Identity,
}
fn material() -> &'static Materials {
    static MATERIAL: OnceLock<Materials> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let ca = Identity::new("test CA", None);
        let other_ca = Identity::new("other CA", None);
        Materials {
            server: Identity::new("server", Some(&ca)),
            client: Identity::new("client", Some(&ca)),
            other_client: Identity::new("other client", Some(&other_ca)),
            ca,
            other_ca,
        }
    })
}
fn server(version: SslVersion, mode: SslVerifyMode) -> SslAcceptorBuilder {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_min_proto_version(Some(version)).unwrap();
    b.set_max_proto_version(Some(version)).unwrap();
    b.set_certificate(&material().server.cert).unwrap();
    b.set_private_key(&material().server.key).unwrap();
    b.cert_store_mut()
        .add_cert(material().ca.cert.clone())
        .unwrap();
    b.add_client_ca(&material().ca.cert).unwrap();
    b.set_alpn_select_callback(|_, offered| {
        rama_boring::ssl::select_next_proto(b"\x02h2", offered)
            .ok_or(rama_boring::ssl::AlpnError::ALERT_FATAL)
    });
    b.set_verify(mode);
    b
}
fn client(version: SslVersion) -> SslConnectorBuilder {
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_min_proto_version(Some(version)).unwrap();
    b.set_max_proto_version(Some(version)).unwrap();
    b.cert_store_mut()
        .add_cert(material().ca.cert.clone())
        .unwrap();
    b.set_alpn_protos(b"\x02h2").unwrap();
    b
}

// Deliberately fragment records and return transient Pending from both directions.
#[derive(Debug)]
struct HiccupIo {
    inner: DuplexStream,
    read_pending: bool,
    write_pending: bool,
}
fn transport() -> (HiccupIo, HiccupIo) {
    let (a, b) = tokio::io::duplex(97);
    let wrap = |inner| HiccupIo {
        inner,
        read_pending: true,
        write_pending: true,
    };
    (wrap(a), wrap(b))
}
impl AsyncRead for HiccupIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_pending {
            self.read_pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.read_pending = true;
        let mut bytes = [0; 13];
        let len = out.remaining().min(bytes.len());
        let mut fragment = ReadBuf::new(&mut bytes[..len]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut fragment) {
            Poll::Ready(Ok(())) => {
                out.put_slice(fragment.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl AsyncWrite for HiccupIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_pending {
            self.write_pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.write_pending = true;
        Pin::new(&mut self.inner).poll_write(cx, &bytes[..bytes.len().min(11)])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
async fn bounded<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("handshake stalled")
}
async fn accept(io: HiccupIo, acceptor: SslAcceptor, expected: Option<Vec<u8>>) -> TestResult {
    let mut stream = rama_boring_tokio::accept(&acceptor, io)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        stream.ssl().peer_certificate().map(|c| c.to_der().unwrap()),
        expected
    );
    stream.write_all(b"accepted").await?;
    Ok(())
}
async fn connect(io: HiccupIo, ssl: Ssl) -> TestResult {
    let mut stream = SslStreamBuilder::new(ssl, io)
        .connect()
        .await
        .map_err(|e| e.to_string())?;
    // TLS 1.3 clients can finish locally before the server accepts their certificate.
    let mut response = [0; 8];
    stream.read_exact(&mut response).await?;
    assert_eq!(&response, b"accepted");
    Ok(())
}
async fn pair(
    acceptor: SslAcceptor,
    ssl: Ssl,
    expected: Option<&X509>,
) -> (TestResult, TestResult) {
    let (a, b) = transport();
    bounded(async {
        tokio::join!(
            accept(a, acceptor, expected.map(|c| c.to_der().unwrap())),
            connect(b, ssl)
        )
    })
    .await
}
fn client_ssl(b: SslConnectorBuilder) -> Ssl {
    b.build()
        .configure()
        .unwrap()
        .into_ssl(Some("localhost"))
        .unwrap()
}
fn install(cred: SslCredential) -> BoxCertificateFinish {
    Box::new(move |mut selection| {
        selection
            .ssl_mut()
            .add_credential(&cred)
            .map_err(|_| AsyncSelectCertError)
    })
}

#[tokio::test]
async fn delayed_selection_preserves_request_and_verification() {
    for version in VERSIONS {
        for per_connection in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let finishes = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let finished = finishes.clone();
            let callback = move |selection: &mut CertificateSelection<'_>| -> Result<BoxCertificateFuture, AsyncSelectCertError> {
                count.fetch_add(1, SeqCst);
                assert!(!selection.ssl().is_server());
                assert_eq!(selection.ssl().selected_alpn_protocol(), Some(&b"h2"[..]));
                assert_eq!(selection.requested_ca_names().map(<[u8]>::to_vec).collect::<Vec<_>>(), vec![material().ca.cert.subject_name().to_der().unwrap(), material().other_ca.cert.subject_name().to_der().unwrap()]);
                assert!(selection.peer_verify_algorithms().contains(&SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256));
                assert_eq!(selection.certificate_types().is_empty(), version == SslVersion::TLS1_3);
                assert_eq!(selection.ssl().peer_certificate().unwrap().to_der().unwrap(), material().server.cert.to_der().unwrap());
                let finished = finished.clone();
                Ok(Box::pin(async move {
                    for _ in 0..5 { tokio::task::yield_now().await; }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    Ok(Box::new(move |mut selection: CertificateSelection<'_>| {
                        finished.fetch_add(1, SeqCst);
                        assert!(!selection.requested_ca_names().collect::<Vec<_>>().is_empty());
                        selection.ssl_mut().add_credential(&material().client.credential()).unwrap();
                        Ok(())
                    }) as BoxCertificateFinish)
                }))
            };
            let mut c = client(version);
            let ssl = if per_connection {
                c.set_certificate_callback(|_| panic!("connection override was ignored"));
                let mut ssl = client_ssl(c);
                ssl.set_async_certificate_callback(callback);
                ssl
            } else {
                c.set_async_certificate_callback(callback);
                client_ssl(c)
            };
            let mut s = server(
                version,
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            );
            s.add_client_ca(&material().other_ca.cert).unwrap();
            let (s, c) = pair(s.build(), ssl, Some(&material().client.cert)).await;
            s.unwrap();
            c.unwrap();
            assert_eq!(calls.load(SeqCst), 1);
            assert_eq!(finishes.load(SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn no_request_does_not_invoke_selection() {
    for version in VERSIONS {
        let mut c = client(version);
        c.set_async_certificate_callback(|_| panic!("no CertificateRequest was sent"));
        let (s, c) = pair(
            server(version, SslVerifyMode::NONE).build(),
            client_ssl(c),
            None,
        )
        .await;
        s.unwrap();
        c.unwrap();
    }
}

#[tokio::test]
async fn empty_identity_is_allowed_only_when_server_accepts_it() {
    for version in VERSIONS {
        for required in [false, true] {
            let mut s = server(
                version,
                SslVerifyMode::PEER
                    | if required {
                        SslVerifyMode::FAIL_IF_NO_PEER_CERT
                    } else {
                        SslVerifyMode::NONE
                    },
            );
            s.set_client_ca_list(rama_boring::stack::Stack::new().unwrap());
            let mut c = client(version);
            c.set_async_certificate_callback(|selection| {
                assert_eq!(selection.requested_ca_names().count(), 0);
                Ok(Box::pin(async {
                    Ok(Box::new(|_: CertificateSelection<'_>| Ok(())) as BoxCertificateFinish)
                }))
            });
            let (s, c) = pair(s.build(), client_ssl(c), None).await;
            assert_eq!(s.is_err(), required);
            assert_eq!(c.is_err(), required);
        }
    }
}

#[tokio::test]
async fn errors_in_factory_future_and_finish_abort_handshake() {
    for version in VERSIONS {
        for stage in 0..3 {
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let mut c = client(version);
            c.set_async_certificate_callback(move |_| {
                count.fetch_add(1, SeqCst);
                if stage == 0 {
                    return Err(AsyncSelectCertError);
                }
                Ok(Box::pin(async move {
                    tokio::task::yield_now().await;
                    if stage == 1 {
                        return Err(AsyncSelectCertError);
                    }
                    Ok(
                        Box::new(|_: CertificateSelection<'_>| Err(AsyncSelectCertError))
                            as BoxCertificateFinish,
                    )
                }))
            });
            let (s, c) = pair(
                server(version, SslVerifyMode::PEER).build(),
                client_ssl(c),
                None,
            )
            .await;
            assert!(s.is_err());
            assert!(c.unwrap_err().to_string().contains("CERT_CB_ERROR"));
            assert_eq!(calls.load(SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn selection_does_not_bypass_server_or_client_trust() {
    for version in VERSIONS {
        for bad_server in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let mut c = client(version);
            c.set_async_certificate_callback(move |_| {
                count.fetch_add(1, SeqCst);
                Ok(Box::pin(async move {
                    Ok(install(if bad_server {
                        material().client.credential()
                    } else {
                        material().other_client.credential()
                    }))
                }))
            });
            let mut ssl = client_ssl(c);
            if bad_server {
                ssl.set_hostname("wrong.example").unwrap();
                ssl.param_mut().set_host("wrong.example").unwrap();
            }
            let (s, c) = pair(
                server(
                    version,
                    SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                )
                .build(),
                ssl,
                None,
            )
            .await;
            assert!(s.is_err());
            assert!(c.is_err());
            assert_eq!(calls.load(SeqCst), usize::from(!bad_server));
        }
    }
}

struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.fetch_add(1, SeqCst);
    }
}

#[tokio::test]
async fn cancelling_pending_selection_or_signature_drops_future_and_transport() {
    for signing in [false, true] {
        for (version, deadline) in VERSIONS.into_iter().flat_map(|v| [(v, false), (v, true)]) {
            let dropped = Arc::new(AtomicUsize::new(0));
            let observed = dropped.clone();
            let started = Arc::new(tokio::sync::Notify::new());
            let notify = started.clone();
            let mut c = client(version);
            if signing {
                let mut credential = SslCredential::builder().unwrap();
                credential
                    .set_certificate_chain([&material().client.cert])
                    .unwrap();
                credential
                    .set_async_private_key_method(DelayedSigner {
                        pending: Some((notify, observed)),
                        calls: Arc::new(AtomicUsize::new(0)),
                        fail: false,
                    })
                    .unwrap();
                let credential = credential.build();
                c.set_async_certificate_callback(move |_| {
                    let credential = credential.clone();
                    Ok(Box::pin(async move { Ok(install(credential)) }))
                });
            } else {
                c.set_async_certificate_callback(move |_| {
                    let probe = DropProbe(observed.clone());
                    notify.notify_one();
                    Ok(Box::pin(async move {
                        let _probe = probe;
                        std::future::pending::<()>().await;
                        unreachable!()
                    }))
                });
            }
            let (a, b) = transport();
            let s = server(version, SslVerifyMode::PEER).build();
            let mut client = Box::pin(connect(b, client_ssl(c)));
            let mut server = Box::pin(accept(a, s, None));
            bounded(async {
                tokio::select! {
                    _ = started.notified() => {},
                    result = &mut client => panic!("client completed while pending: {result:?}"),
                    result = &mut server => panic!("server completed while pending: {result:?}"),
                }
                if deadline {
                    assert!(tokio::time::timeout(Duration::from_millis(2), client)
                        .await
                        .is_err());
                } else {
                    drop(client);
                }
                assert_eq!(dropped.load(SeqCst), 1);
                assert!(
                    server.await.is_err(),
                    "cancelled client retained its transport"
                );
            })
            .await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_connections_keep_separate_pending_selections() {
    for independent_contexts in [false, true] {
        for version in VERSIONS {
            let id_index = Ssl::new_ex_index::<usize>().unwrap();
            let starts = Arc::new(AtomicUsize::new(0));
            let finishes = Arc::new(AtomicUsize::new(0));
            let configure = || {
                let count = starts.clone();
                let done = finishes.clone();
                let mut c = client(version);
                c.set_async_certificate_callback(move |selection| {
                    let id = *selection.ssl().ex_data(id_index).unwrap();
                    count.fetch_add(1, SeqCst);
                    let done = done.clone();
                    Ok(Box::pin(async move {
                        for _ in 0..id + 1 {
                            tokio::task::yield_now().await;
                        }
                        tokio::time::sleep(Duration::from_millis((id % 3) as u64)).await;
                        Ok(Box::new(move |mut selection: CertificateSelection<'_>| {
                            assert_eq!(*selection.ssl().ex_data(id_index).unwrap(), id);
                            done.fetch_add(1, SeqCst);
                            let identity = if id % 2 == 0 {
                                &material().client
                            } else {
                                &material().other_client
                            };
                            selection
                                .ssl_mut()
                                .add_credential(&identity.credential())
                                .unwrap();
                            Ok(())
                        }) as BoxCertificateFinish)
                    }))
                });
                c.build()
            };
            let shared = (!independent_contexts).then(&configure);
            let mut s = server(
                version,
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            );
            s.cert_store_mut()
                .add_cert(material().other_ca.cert.clone())
                .unwrap();
            let s = s.build();
            let work = (0..32).map(|id| {
                let c = shared.clone().unwrap_or_else(&configure);
                let mut ssl = c.configure().unwrap().into_ssl(Some("localhost")).unwrap();
                ssl.set_ex_data(id_index, id);
                let expected = if id % 2 == 0 {
                    &material().client.cert
                } else {
                    &material().other_client.cert
                };
                tokio::spawn(pair(s.clone(), ssl, Some(expected)))
            });
            for result in bounded(futures::future::join_all(work)).await {
                let (s, c) = result.unwrap();
                s.unwrap();
                c.unwrap();
            }
            assert_eq!(starts.load(SeqCst), 32);
            assert_eq!(finishes.load(SeqCst), 32);
        }
    }
}

#[tokio::test]
async fn server_selection_coexists_with_early_client_hello_callback() {
    for version in VERSIONS {
        let early = Arc::new(AtomicUsize::new(0));
        let count = early.clone();
        let mut s = server(version, SslVerifyMode::NONE);
        s.set_select_certificate_callback(move |mut hello| {
            hello.ssl_mut().clear_certificates();
            count.fetch_add(1, SeqCst);
            Ok(())
        });
        s.set_async_certificate_callback(move |selection| {
            assert_eq!(early.load(SeqCst), 1);
            assert!(selection.ssl().is_server());
            assert_eq!(selection.requested_ca_names().count(), 0);
            assert!(selection.certificate_types().is_empty());
            assert!(!selection.peer_verify_algorithms().is_empty());
            Ok(Box::pin(async {
                tokio::task::yield_now().await;
                Ok(install(material().server.credential()))
            }))
        });
        let (s, c) = pair(s.build(), client_ssl(client(version)), None).await;
        s.unwrap();
        c.unwrap();
    }
}

#[tokio::test]
async fn paused_egress_waits_for_ingress_verification_and_maps_identity() {
    use rama_boring::ssl::{BoxCustomVerifyFinish, SslAlert};
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    for version in VERSIONS {
        for failure in 0..3 {
            let reject_ingress = failure == 1;
            let bad_signature = failure == 2;
            let must_fail = failure != 0;
            let (request_tx, request_rx) = oneshot::channel();
            let ingress_started = Arc::new(tokio::sync::Notify::new());
            let ready = ingress_started.clone();
            let (identity_tx, identity_rx) = oneshot::channel::<SslCredential>();
            let exchange = Mutex::new(Some((request_tx, identity_rx)));
            let resolved = Arc::new(AtomicUsize::new(0));
            let count = resolved.clone();
            let mut egress = client(version);
            egress.set_async_certificate_callback(move |selection| {
                let names = selection
                    .requested_ca_names()
                    .map(<[u8]>::to_vec)
                    .collect::<Vec<_>>();
                let (request, identity) =
                    exchange.lock().unwrap().take().expect("factory ran twice");
                let count = count.clone();
                let ready = ready.clone();
                Ok(Box::pin(async move {
                    ready.notified().await;
                    tokio::task::yield_now().await;
                    request.send(names).map_err(|_| AsyncSelectCertError)?;
                    let credential = identity.await.map_err(|_| AsyncSelectCertError)?;
                    count.fetch_add(1, SeqCst);
                    Ok(install(credential))
                }))
            });
            let mut upstream = server(
                version,
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            );
            upstream
                .cert_store_mut()
                .add_cert(material().other_ca.cert.clone())
                .unwrap();
            let mut names = rama_boring::stack::Stack::new().unwrap();
            names
                .push(
                    X509Name::from_der(&material().other_ca.cert.subject_name().to_der().unwrap())
                        .unwrap(),
                )
                .unwrap();
            upstream.set_client_ca_list(names);
            let (upstream_io, egress_io) = transport();
            let (ingress_io, guest_io) = transport();
            let mut guest = client(version);
            guest.set_async_certificate_callback(move |selection| {
                assert_eq!(
                    selection
                        .requested_ca_names()
                        .map(<[u8]>::to_vec)
                        .collect::<Vec<_>>(),
                    vec![material().ca.cert.subject_name().to_der().unwrap()]
                );
                Ok(Box::pin(async move {
                    Ok(install(if bad_signature {
                        wrong_signer_credential()
                    } else {
                        material().client.credential()
                    }))
                }))
            });
            let driver = async {
                let checked = Arc::new(AtomicUsize::new(0));
                let count = checked.clone();
                let mut ingress = server(
                    version,
                    SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                );
                ingress.set_async_custom_verify_callback(
                    SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                    move |ssl| {
                        // Explicit leaf pinning represents application policy for this test.
                        assert_eq!(
                            ssl.peer_certificate().unwrap().to_der().unwrap(),
                            material().client.cert.to_der().unwrap()
                        );
                        let count = count.clone();
                        Ok(Box::pin(async move {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                            if reject_ingress {
                                return Err(SslAlert::ACCESS_DENIED);
                            }
                            Ok(Box::new(move |_: &mut _| {
                                count.fetch_add(1, SeqCst);
                                Ok(())
                            }) as BoxCustomVerifyFinish)
                        }))
                    },
                );
                // Both handshakes now pause in their own selection callbacks. The
                // ingress request policy is installed only after egress requests it.
                ingress.set_verify(SslVerifyMode::NONE);
                let request = Mutex::new(Some(request_rx));
                ingress.set_async_certificate_callback(move |_| {
                    let request = request.lock().unwrap().take().ok_or(AsyncSelectCertError)?;
                    ingress_started.notify_one();
                    Ok(Box::pin(async move {
                        let names = request.await.map_err(|_| AsyncSelectCertError)?;
                        if names != vec![material().other_ca.cert.subject_name().to_der().unwrap()]
                        {
                            return Err(AsyncSelectCertError);
                        }
                        Ok(Box::new(|mut selection: CertificateSelection<'_>| {
                            selection.ssl_mut().set_verify(
                                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                            );
                            Ok(())
                        }) as BoxCertificateFinish)
                    }))
                });
                let result = accept(
                    ingress_io,
                    ingress.build(),
                    Some(material().client.cert.to_der().unwrap()),
                )
                .await;
                if must_fail {
                    let error = result.unwrap_err().to_string();
                    if bad_signature {
                        assert_eq!(checked.load(SeqCst), 1);
                        assert!(error.contains("BAD_SIGNATURE"), "{error}");
                    }
                    drop(identity_tx);
                } else {
                    result.unwrap();
                    assert_eq!(checked.load(SeqCst), 1);
                    // Only release B after the complete ingress handshake proves possession of A.
                    identity_tx
                        .send(material().other_client.credential())
                        .unwrap_or_else(|_| panic!("egress stopped waiting for ingress"));
                }
            };
            let (upstream, egress, guest, ()) = bounded(async {
                tokio::join!(
                    accept(
                        upstream_io,
                        upstream.build(),
                        Some(material().other_client.cert.to_der().unwrap())
                    ),
                    connect(egress_io, client_ssl(egress)),
                    connect(guest_io, client_ssl(guest)),
                    driver,
                )
            })
            .await;
            assert_eq!(upstream.is_err(), must_fail);
            assert_eq!(egress.is_err(), must_fail);
            assert_eq!(guest.is_err(), must_fail);
            assert_eq!(resolved.load(SeqCst), usize::from(!must_fail));
        }
    }
}

struct WrongSigner;
impl rama_boring::ssl::PrivateKeyMethod for WrongSigner {
    fn sign(
        &self,
        _: &mut rama_boring::ssl::SslRef,
        input: &[u8],
        algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<usize, rama_boring::ssl::PrivateKeyMethodError> {
        assert_eq!(algorithm, SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256);
        let mut signer =
            rama_boring::sign::Signer::new(MessageDigest::sha256(), &material().other_client.key)
                .unwrap();
        signer.update(input).unwrap();
        Ok(signer.sign(output).unwrap())
    }
    fn decrypt(
        &self,
        _: &mut rama_boring::ssl::SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, rama_boring::ssl::PrivateKeyMethodError> {
        unreachable!()
    }
    fn complete(
        &self,
        _: &mut rama_boring::ssl::SslRef,
        _: &mut [u8],
    ) -> Result<usize, rama_boring::ssl::PrivateKeyMethodError> {
        unreachable!()
    }
}
fn wrong_signer_credential() -> SslCredential {
    let mut credential = SslCredential::builder().unwrap();
    credential
        .set_certificate_chain([&material().client.cert])
        .unwrap();
    credential.set_private_key_method(WrongSigner).unwrap();
    credential.build()
}

#[tokio::test]
async fn pending_selection_uses_latest_task_waker() {
    use std::sync::{atomic::AtomicBool, Mutex};
    use std::task::{Wake, Waker};
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, SeqCst);
        }
    }
    for version in VERSIONS {
        let ready = Arc::new(AtomicBool::new(false));
        let wake_slot = Arc::new(Mutex::new(None::<Waker>));
        let polls = Arc::new(AtomicUsize::new(0));
        let (done, slot, count) = (ready.clone(), wake_slot.clone(), polls.clone());
        let started = Arc::new(tokio::sync::Notify::new());
        let notify = started.clone();
        let starts = Arc::new(AtomicUsize::new(0));
        let created = starts.clone();
        let mut c = client(version);
        c.set_async_certificate_callback(move |_| {
            created.fetch_add(1, SeqCst);
            notify.notify_one();
            let (done, slot, count) = (done.clone(), slot.clone(), count.clone());
            Ok(Box::pin(futures::future::poll_fn(move |cx| {
                count.fetch_add(1, SeqCst);
                if done.load(SeqCst) {
                    Poll::Ready(Ok(install(material().client.credential())))
                } else {
                    *slot.lock().unwrap() = Some(cx.waker().clone());
                    Poll::Pending
                }
            })))
        });
        let (a, b) = transport();
        let mut s = Box::pin(accept(
            a,
            server(version, SslVerifyMode::PEER).build(),
            Some(material().client.cert.to_der().unwrap()),
        ));
        let mut c = Box::pin(connect(b, client_ssl(c)));
        bounded(async {
            tokio::select! {
                _ = started.notified() => {},
                result = &mut c => panic!("client completed early: {result:?}"),
                result = &mut s => panic!("server completed early: {result:?}"),
            }
            let old = Arc::new(WakeCount(AtomicUsize::new(0)));
            let new = Arc::new(WakeCount(AtomicUsize::new(0)));
            for tracker in [&old, &new] {
                let waker = Waker::from(tracker.clone());
                assert!(c
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending());
            }
            assert!(polls.load(SeqCst) >= 3);
            assert_eq!(starts.load(SeqCst), 1);
            ready.store(true, SeqCst);
            wake_slot.lock().unwrap().take().unwrap().wake();
            assert_eq!(old.0.load(SeqCst), 0);
            assert_eq!(new.0.load(SeqCst), 1);
            let (s, c) = tokio::join!(s, c);
            s.unwrap();
            c.unwrap();
        })
        .await;
    }
}

#[tokio::test]
async fn upstream_verification_callback_is_preserved() {
    use rama_boring::ssl::SslAlert;
    for version in VERSIONS {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut c = client(version);
        c.set_async_custom_verify_callback(SslVerifyMode::PEER, |_| {
            Ok(Box::pin(async {
                tokio::task::yield_now().await;
                Err(SslAlert::UNKNOWN_CA)
            }))
        });
        c.set_async_certificate_callback(move |_| {
            count.fetch_add(1, SeqCst);
            Ok(Box::pin(async {
                Ok(install(material().client.credential()))
            }))
        });
        let (s, c) = pair(
            server(version, SslVerifyMode::PEER).build(),
            client_ssl(c),
            None,
        )
        .await;
        assert!(s.is_err());
        assert_eq!(calls.load(SeqCst), 0);
        assert!(c
            .unwrap_err()
            .to_string()
            .contains("CERTIFICATE_VERIFY_FAILED"));
    }
}

#[tokio::test]
async fn resumed_sessions_do_not_request_a_fresh_client_identity() {
    use rama_boring::ssl::SslSessionCacheMode;
    use std::sync::Mutex;
    for version in VERSIONS {
        let selections = Arc::new(AtomicUsize::new(0));
        let count = selections.clone();
        let session = Arc::new(Mutex::new(None));
        let saved = session.clone();
        let mut c = client(version);
        c.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        c.set_new_session_callback(move |_, session| {
            *saved.lock().unwrap() = Some(session);
        });
        c.set_async_certificate_callback(move |_| {
            count.fetch_add(1, SeqCst);
            Ok(Box::pin(async {
                Ok(install(material().client.credential()))
            }))
        });
        let c = c.build();
        let mut s = server(
            version,
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        );
        s.set_session_id_context(b"certificate-selection-test")
            .unwrap();
        let s = s.build();
        for resumed in [false, true] {
            let mut ssl = c.configure().unwrap().into_ssl(Some("localhost")).unwrap();
            if resumed {
                // The session is reused with the same SSL context and peer.
                unsafe {
                    ssl.set_session(
                        session
                            .lock()
                            .unwrap()
                            .as_ref()
                            .expect("server did not issue a session"),
                    )
                    .unwrap();
                }
            }
            let (a, b) = transport();
            bounded(async {
                let server = async {
                    let mut stream = rama_boring_tokio::accept(&s, a).await.unwrap();
                    assert_eq!(stream.ssl().session_reused(), resumed);
                    assert_eq!(
                        stream.ssl().peer_certificate().unwrap().to_der().unwrap(),
                        material().client.cert.to_der().unwrap()
                    );
                    stream.write_all(b"accepted").await.unwrap();
                };
                let client = async {
                    let mut stream = SslStreamBuilder::new(ssl, b).connect().await.unwrap();
                    let mut ack = [0; 8];
                    stream.read_exact(&mut ack).await.unwrap();
                    assert_eq!(&ack, b"accepted");
                    assert_eq!(stream.ssl().session_reused(), resumed);
                };
                tokio::join!(server, client);
            })
            .await;
        }
        assert_eq!(selections.load(SeqCst), 1);
    }
}

#[tokio::test]
async fn replacing_selection_inside_its_factory_aborts_without_running_old_finish() {
    for version in VERSIONS {
        for replacement in 0..3 {
            let finishes = Arc::new(AtomicUsize::new(0));
            let count = finishes.clone();
            let mut c = client(version);
            c.set_async_certificate_callback(move |selection| {
                match replacement {
                    0 => selection
                        .ssl_mut()
                        .set_async_certificate_callback(|_| Err(AsyncSelectCertError)),
                    1 => selection.ssl_mut().set_certificate_callback(|_| Ok(())),
                    _ => {
                        let replacement = client(version).build();
                        selection
                            .ssl_mut()
                            .set_ssl_context(replacement.context())
                            .unwrap();
                    }
                }
                let count = count.clone();
                Ok(Box::pin(async move {
                    tokio::task::yield_now().await;
                    Ok(Box::new(move |_: CertificateSelection<'_>| {
                        count.fetch_add(1, SeqCst);
                        Ok(())
                    }) as BoxCertificateFinish)
                }))
            });
            let (s, c) = pair(
                server(version, SslVerifyMode::PEER).build(),
                client_ssl(c),
                None,
            )
            .await;
            assert_eq!(
                finishes.load(SeqCst),
                0,
                "old policy finished after replacement {replacement}"
            );
            assert!(s.is_err());
            assert!(c.unwrap_err().to_string().contains("CERT_CB_ERROR"));
        }
    }
}

#[tokio::test]
async fn clearing_credentials_removes_all_candidates_without_changing_the_context() {
    for version in VERSIONS {
        for modern in [false, true] {
            let mut c = client(version);
            c.set_certificate(&material().client.cert).unwrap();
            c.set_private_key(&material().client.key).unwrap();
            if modern {
                c.add_credential(&material().other_client.credential())
                    .unwrap();
            }
            let c = c.build();
            let mut s = server(version, SslVerifyMode::PEER);
            s.cert_store_mut()
                .add_cert(material().other_ca.cert.clone())
                .unwrap();
            let s = s.build();
            for clear in [true, false] {
                let mut ssl = c.configure().unwrap().into_ssl(Some("localhost")).unwrap();
                ssl.set_certificate_callback(move |mut selection| {
                    if clear {
                        selection.ssl_mut().clear_certificates();
                    }
                    Ok(())
                });
                let expected = if clear {
                    None
                } else if modern {
                    Some(&material().other_client.cert)
                } else {
                    Some(&material().client.cert)
                };
                let (s, c) = pair(s.clone(), ssl, expected).await;
                s.unwrap();
                c.unwrap();
            }
        }
    }
}

fn issuer_constrained_credential() -> SslCredential {
    let mut credential = SslCredential::builder().unwrap();
    credential
        .set_certificate_chain([&material().other_client.cert])
        .unwrap();
    credential
        .set_private_key(&material().other_client.key)
        .unwrap();
    credential.set_must_match_issuer(true);
    credential.build()
}

#[tokio::test]
async fn incompatible_mapping_cannot_fall_back_after_defaults_are_cleared() {
    for version in VERSIONS {
        for clear in [false, true] {
            let mut c = client(version);
            c.set_certificate(&material().client.cert).unwrap();
            c.set_private_key(&material().client.key).unwrap();
            c.set_certificate_callback(move |mut selection| {
                if clear {
                    selection.ssl_mut().clear_certificates();
                }
                selection
                    .ssl_mut()
                    .add_credential(&issuer_constrained_credential())
                    .unwrap();
                Ok(())
            });
            let (s, c) = pair(
                server(version, SslVerifyMode::PEER).build(),
                client_ssl(c),
                Some(&material().client.cert),
            )
            .await;
            assert_eq!(s.is_err(), clear);
            assert_eq!(c.is_err(), clear);
            if clear {
                assert!(c.unwrap_err().to_string().contains("NO_MATCHING_ISSUER"));
            }
        }
    }
}

#[tokio::test]
async fn incompatible_signature_algorithm_fails_instead_of_sending_no_certificate() {
    for version in VERSIONS {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut c = client(version);
        c.set_certificate_callback(move |mut selection| {
            count.fetch_add(1, SeqCst);
            assert_eq!(
                selection.peer_verify_algorithms(),
                &[SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256]
            );
            selection
                .ssl_mut()
                .add_credential(&material().client.credential())
                .unwrap();
            Ok(())
        });
        let mut s = server(version, SslVerifyMode::PEER);
        s.set_verify_algorithm_prefs(&[SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256])
            .unwrap();
        let (s, c) = pair(s.build(), client_ssl(c), None).await;
        assert_eq!(calls.load(SeqCst), 1);
        assert!(s.is_err());
        assert!(c
            .unwrap_err()
            .to_string()
            .contains("NO_COMMON_SIGNATURE_ALGORITHMS"));
    }
}

#[tokio::test]
async fn hello_retry_request_does_not_repeat_certificate_selection() {
    use rama_boring::ssl::SslCurve;
    let (client_calls, server_calls) =
        (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let count = client_calls.clone();
    let mut c = client(SslVersion::TLS1_3);
    c.set_curves(&[SslCurve::SECP256R1, SslCurve::SECP384R1])
        .unwrap();
    c.set_async_certificate_callback(move |selection| {
        assert!(selection.ssl().used_hello_retry_request());
        count.fetch_add(1, SeqCst);
        Ok(Box::pin(async {
            tokio::task::yield_now().await;
            Ok(install(material().client.credential()))
        }))
    });
    let count = server_calls.clone();
    let mut s = server(SslVersion::TLS1_3, SslVerifyMode::PEER);
    s.set_curves(&[SslCurve::SECP384R1]).unwrap();
    s.set_select_certificate_callback(|mut hello| {
        hello.ssl_mut().clear_certificates();
        Ok(())
    });
    s.set_async_certificate_callback(move |_| {
        count.fetch_add(1, SeqCst);
        Ok(Box::pin(async {
            tokio::task::yield_now().await;
            Ok(install(material().server.credential()))
        }))
    });
    let (s, c) = pair(s.build(), client_ssl(c), Some(&material().client.cert)).await;
    s.unwrap();
    c.unwrap();
    assert_eq!(client_calls.load(SeqCst), 1);
    assert_eq!(server_calls.load(SeqCst), 1);
}

#[tokio::test]
async fn sni_context_switch_replaces_a_connection_override_before_selection() {
    for version in VERSIONS {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut replacement = server(version, SslVerifyMode::NONE);
        replacement.set_certificate_callback(move |_| {
            count.fetch_add(1, SeqCst);
            Ok(())
        });
        let replacement = replacement.build();
        let mut s = server(version, SslVerifyMode::NONE);
        s.set_servername_callback(move |ssl, _| {
            ssl.set_ssl_context(replacement.context()).unwrap();
            Ok(())
        });
        let mut ssl = Ssl::new(s.build().context()).unwrap();
        ssl.set_certificate_callback(|_| panic!("SNI context switch should replace the override"));
        let (a, b) = transport();
        bounded(async {
            let server = async {
                let mut stream = SslStreamBuilder::new(ssl, a).accept().await.unwrap();
                stream.write_all(b"accepted").await.unwrap();
            };
            let ((), c) = tokio::join!(server, connect(b, client_ssl(client(version))));
            c.unwrap();
        })
        .await;
        assert_eq!(calls.load(SeqCst), 1);
    }
}

struct DelayedSigner {
    pending: Option<(Arc<tokio::sync::Notify>, Arc<AtomicUsize>)>,
    calls: Arc<AtomicUsize>,
    fail: bool,
}
impl rama_boring::ssl::AsyncPrivateKeyMethod for DelayedSigner {
    fn sign(
        &self,
        _: &mut rama_boring::ssl::SslRef,
        input: &[u8],
        algorithm: SslSignatureAlgorithm,
        _: &mut [u8],
    ) -> Result<
        rama_boring::ssl::BoxPrivateKeyMethodFuture,
        rama_boring::ssl::AsyncPrivateKeyMethodError,
    > {
        assert_eq!(algorithm, SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256);
        self.calls.fetch_add(1, SeqCst);
        if let Some((notify, drops)) = &self.pending {
            let probe = DropProbe(drops.clone());
            notify.notify_one();
            return Ok(Box::pin(async move {
                let _probe = probe;
                std::future::pending().await
            }));
        }
        let input = input.to_vec();
        let fail = self.fail;
        Ok(Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(2)).await;
            if fail {
                return Err(rama_boring::ssl::AsyncPrivateKeyMethodError);
            }
            let mut signer =
                rama_boring::sign::Signer::new(MessageDigest::sha256(), &material().client.key)
                    .unwrap();
            signer.update(&input).unwrap();
            let signature = signer.sign_to_vec().unwrap();
            Ok(Box::new(move |_: &mut _, output: &mut [u8]| {
                output[..signature.len()].copy_from_slice(&signature);
                Ok(signature.len())
            })
                as rama_boring::ssl::BoxPrivateKeyMethodFinish)
        }))
    }
    fn decrypt(
        &self,
        _: &mut rama_boring::ssl::SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<
        rama_boring::ssl::BoxPrivateKeyMethodFuture,
        rama_boring::ssl::AsyncPrivateKeyMethodError,
    > {
        unreachable!()
    }
}

#[tokio::test]
async fn selected_credential_supports_a_delayed_remote_signer() {
    for version in VERSIONS {
        for fail in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut credential = SslCredential::builder().unwrap();
            credential
                .set_certificate_chain([&material().client.cert])
                .unwrap();
            credential
                .set_async_private_key_method(DelayedSigner {
                    pending: None,
                    calls: calls.clone(),
                    fail,
                })
                .unwrap();
            let credential = credential.build();
            let mut c = client(version);
            c.set_async_certificate_callback(move |_| {
                let credential = credential.clone();
                Ok(Box::pin(async move {
                    tokio::task::yield_now().await;
                    Ok(install(credential))
                }))
            });
            let (s, c) = pair(
                server(version, SslVerifyMode::PEER).build(),
                client_ssl(c),
                Some(&material().client.cert),
            )
            .await;
            assert_eq!(calls.load(SeqCst), 1);
            assert_eq!(s.is_err(), fail);
            assert_eq!(c.is_err(), fail);
        }
    }
}

#[tokio::test]
async fn upstream_disconnect_while_pending_is_observed_when_selection_resumes() {
    use std::sync::Mutex;
    for version in VERSIONS {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let receiver = Mutex::new(Some(receiver));
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify = entered.clone();
        let dropped = Arc::new(AtomicUsize::new(0));
        let count = dropped.clone();
        let mut c = client(version);
        c.set_async_certificate_callback(move |_| {
            let receiver = receiver.lock().unwrap().take().unwrap();
            let probe = DropProbe(count.clone());
            notify.notify_one();
            Ok(Box::pin(async move {
                let _probe = probe;
                receiver.await.unwrap();
                Ok(install(material().client.credential()))
            }))
        });
        let (a, b) = transport();
        let mut server = Box::pin(accept(
            a,
            server(version, SslVerifyMode::PEER).build(),
            Some(material().client.cert.to_der().unwrap()),
        ));
        let mut client = Box::pin(connect(b, client_ssl(c)));
        bounded(async {
            tokio::select! {
                _ = entered.notified() => {},
                result = &mut server => panic!("server finished early: {result:?}"),
                result = &mut client => panic!("client finished early: {result:?}"),
            }
            drop(server);
            assert!(
                futures::poll!(&mut client).is_pending(),
                "selection does not poll transport"
            );
            sender.send(()).unwrap();
            assert!(client.await.is_err());
            assert_eq!(dropped.load(SeqCst), 1);
        })
        .await;
    }
}

#[tokio::test]
async fn inherited_modern_credentials_win_unless_mapping_clears_them() {
    let mapped = Identity::new("mapped", Some(&material().ca));
    for version in VERSIONS {
        for clear in [false, true] {
            let credential = mapped.credential();
            let mut c = client(version);
            c.add_credential(&material().client.credential()).unwrap();
            c.set_async_certificate_callback(move |_| {
                let credential = credential.clone();
                Ok(Box::pin(async move {
                    Ok(Box::new(move |mut selection: CertificateSelection<'_>| {
                        if clear {
                            selection.ssl_mut().clear_certificates();
                        }
                        selection.ssl_mut().add_credential(&credential).unwrap();
                        Ok(())
                    }) as BoxCertificateFinish)
                }))
            });
            let expected = if clear {
                &mapped.cert
            } else {
                &material().client.cert
            };
            let (s, c) = pair(
                server(version, SslVerifyMode::PEER).build(),
                client_ssl(c),
                Some(expected),
            )
            .await;
            s.unwrap();
            c.unwrap();
        }
    }
}

#[tokio::test]
async fn reconfiguring_certificate_selection_in_finish_aborts() {
    for version in VERSIONS {
        for change in 0..3 {
            let mut c = client(version);
            c.set_async_certificate_callback(move |_| {
                Ok(Box::pin(async move {
                    tokio::task::yield_now().await;
                    Ok(Box::new(move |mut selection: CertificateSelection<'_>| {
                        selection
                            .ssl_mut()
                            .add_credential(&material().client.credential())
                            .unwrap();
                        match change {
                            0 => selection
                                .ssl_mut()
                                .set_ssl_context(client(version).build().context())
                                .unwrap(),
                            1 => selection
                                .ssl_mut()
                                .set_certificate_callback(|_| panic!("replacement must not run")),
                            _ => {
                                let ctx = selection.ssl().ssl_context().to_owned();
                                selection.ssl_mut().set_ssl_context(&ctx).unwrap();
                            }
                        }
                        Ok(())
                    }) as BoxCertificateFinish)
                }))
            });
            let (s, c) = pair(
                server(version, SslVerifyMode::PEER).build(),
                client_ssl(c),
                Some(&material().client.cert),
            )
            .await;
            assert_eq!(s.is_ok(), change == 2);
            assert_eq!(c.is_ok(), change == 2);
        }
    }
}

#[tokio::test]
async fn custom_verify_reconfiguration_in_factory_and_finish_aborts() {
    use rama_boring::ssl::{BoxCustomVerifyFinish, SslAlert};
    for version in VERSIONS {
        for in_finish in [false, true] {
            let finishes = Arc::new(AtomicUsize::new(0));
            let count = finishes.clone();
            let mut c = client(version);
            c.set_async_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                if !in_finish {
                    ssl.set_async_custom_verify_callback(SslVerifyMode::PEER, |_| {
                        Err(SslAlert::BAD_CERTIFICATE)
                    });
                }
                let count = count.clone();
                Ok(Box::pin(async move {
                    Ok(Box::new(move |ssl: &mut rama_boring::ssl::SslRef| {
                        count.fetch_add(1, SeqCst);
                        ssl.set_verify(SslVerifyMode::NONE);
                        Ok(())
                    }) as BoxCustomVerifyFinish)
                }))
            });
            let (s, c) = pair(
                server(version, SslVerifyMode::NONE).build(),
                client_ssl(c),
                None,
            )
            .await;
            assert!(s.is_err());
            assert!(c.is_err());
            assert_eq!(finishes.load(SeqCst), usize::from(in_finish));
        }
    }
}

#[tokio::test]
async fn early_client_hello_context_routing_is_allowed_only_in_finish() {
    use rama_boring::ssl::{BoxSelectCertFinish, ClientHello};
    for version in VERSIONS {
        for in_finish in [false, true] {
            let finishes = Arc::new(AtomicUsize::new(0));
            let count = finishes.clone();
            let replacement = server(version, SslVerifyMode::NONE).build();
            let mut s = server(version, SslVerifyMode::NONE);
            s.set_async_select_certificate_callback(move |hello| {
                if !in_finish {
                    hello
                        .ssl_mut()
                        .set_ssl_context(replacement.context())
                        .unwrap();
                }
                let (count, replacement) = (count.clone(), replacement.clone());
                Ok(Box::pin(async move {
                    tokio::task::yield_now().await;
                    Ok(Box::new(move |mut hello: ClientHello<'_>| {
                        count.fetch_add(1, SeqCst);
                        hello
                            .ssl_mut()
                            .set_ssl_context(replacement.context())
                            .unwrap();
                        Ok(())
                    }) as BoxSelectCertFinish)
                }))
            });
            let (s, c) = pair(s.build(), client_ssl(client(version)), None).await;
            assert_eq!(s.is_ok(), in_finish);
            assert_eq!(c.is_ok(), in_finish);
            assert_eq!(finishes.load(SeqCst), usize::from(in_finish));
        }
    }
}

#[tokio::test]
async fn rejected_ech_skips_selection_and_sends_no_inherited_identity() {
    use rama_boring::{hpke::HpkeKey, ssl::SslEchKeys};
    let key = HpkeKey::dhkem_p256_sha256(include_bytes!("../../boring/test/echkey-2")).unwrap();
    let mut keys = SslEchKeys::builder().unwrap();
    keys.add_key(true, include_bytes!("../../boring/test/echconfig-2"), key)
        .unwrap();
    let s = server(SslVersion::TLS1_3, SslVerifyMode::PEER);
    s.set_ech_keys(&keys.build()).unwrap();
    let mut c = client(SslVersion::TLS1_3);
    c.add_credential(&material().client.credential()).unwrap();
    c.set_async_certificate_callback(|_| panic!("ECH rejection must skip selection"));
    // Accept the test server's outer identity to reach the ECH rejection path.
    c.set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
        assert_eq!(ssl.get_ech_name_override(), Some(&b"ech.com"[..]));
        Ok(())
    });
    let mut ssl = client_ssl(c);
    ssl.set_ech_config_list(include_bytes!("../../boring/test/echconfiglist"))
        .unwrap();
    let (a, b) = transport();
    bounded(async {
        let accept = async {
            let stream = SslStreamBuilder::new(Ssl::new(s.build().context()).unwrap(), a)
                .accept()
                .await
                .unwrap();
            assert!(stream.ssl().peer_certificate().is_none());
        };
        let connect = async {
            let error = SslStreamBuilder::new(ssl, b).connect().await.unwrap_err();
            assert!(error.to_string().contains("ECH_REJECTED"));
        };
        tokio::join!(accept, connect);
    })
    .await;
}

#[tokio::test]
async fn cancelling_a_wait_preserves_a_retained_handshake_and_its_selection() {
    use std::sync::Mutex;
    for version in VERSIONS {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let receiver = Mutex::new(Some(receiver));
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify = entered.clone();
        let dropped = Arc::new(AtomicUsize::new(0));
        let factories = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let (drops, starts, ends) = (dropped.clone(), factories.clone(), finishes.clone());
        let mut c = client(version);
        c.set_async_certificate_callback(move |_| {
            starts.fetch_add(1, SeqCst);
            let receiver = receiver.lock().unwrap().take().unwrap();
            let probe = DropProbe(drops.clone());
            let ends = ends.clone();
            notify.notify_one();
            Ok(Box::pin(async move {
                let _probe = probe;
                receiver.await.unwrap();
                Ok(Box::new(move |selection: CertificateSelection<'_>| {
                    ends.fetch_add(1, SeqCst);
                    install(material().client.credential())(selection)
                }) as BoxCertificateFinish)
            }))
        });
        let (a, b) = transport();
        let mut server = Box::pin(accept(
            a,
            server(version, SslVerifyMode::PEER).build(),
            Some(material().client.cert.to_der().unwrap()),
        ));
        let mut client = Box::pin(connect(b, client_ssl(c)));
        bounded(async {
            tokio::select! {
                _ = entered.notified() => {},
                result = &mut server => panic!("server finished early: {result:?}"),
                result = &mut client => panic!("client finished early: {result:?}"),
            }
            assert!(tokio::time::timeout(Duration::from_millis(2), &mut client)
                .await
                .is_err());
            assert_eq!(dropped.load(SeqCst), 0);
            assert_eq!(finishes.load(SeqCst), 0);
            sender.send(()).unwrap();
            let (s, c) = tokio::join!(server, client);
            s.unwrap();
            c.unwrap();
        })
        .await;
        assert_eq!(factories.load(SeqCst), 1);
        assert_eq!(finishes.load(SeqCst), 1);
        assert_eq!(dropped.load(SeqCst), 1);
    }
}

#[tokio::test]
async fn cancelling_handshake_drops_selection_but_not_a_borrowed_transport() {
    for version in VERSIONS {
        let dropped = Arc::new(AtomicUsize::new(0));
        let drops = dropped.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify = entered.clone();
        let mut c = client(version);
        c.set_async_certificate_callback(move |_| {
            let probe = DropProbe(drops.clone());
            notify.notify_one();
            Ok(Box::pin(async move {
                let _probe = probe;
                std::future::pending().await
            }))
        });
        let (a, mut b) = transport();
        let mut server = Box::pin(accept(
            a,
            server(version, SslVerifyMode::PEER).build(),
            None,
        ));
        bounded(async {
            let mut client = Box::pin(SslStreamBuilder::new(client_ssl(c), &mut b).connect());
            tokio::select! {
                _ = entered.notified() => {},
                result = &mut server => panic!("server finished early: {result:?}"),
                result = &mut client => panic!("client finished early: {result:?}"),
            }
            drop(client);
            assert_eq!(dropped.load(SeqCst), 1);
            assert!(futures::poll!(&mut server).is_pending());
            drop(b);
            assert!(server.await.is_err());
        })
        .await;
    }
}

fn configure_routing_verifier(
    ctx: &mut rama_boring::ssl::SslContextBuilder,
    kind: u8,
    calls: Arc<AtomicUsize>,
    allow: bool,
) {
    use rama_boring::ssl::{BoxCustomVerifyFinish, SslAlert, SslVerifyError};
    let mode = SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT;
    match kind {
        0 => ctx.set_custom_verify_callback(mode, move |_| {
            calls.fetch_add(1, SeqCst);
            if allow {
                Ok(())
            } else {
                Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))
            }
        }),
        1 => ctx.set_async_custom_verify_callback(mode, move |_| {
            calls.fetch_add(1, SeqCst);
            Ok(Box::pin(async move {
                tokio::task::yield_now().await;
                Ok(Box::new(move |_: &mut rama_boring::ssl::SslRef| {
                    if allow {
                        Ok(())
                    } else {
                        Err(SslAlert::BAD_CERTIFICATE)
                    }
                }) as BoxCustomVerifyFinish)
            }))
        }),
        _ => ctx.set_verify_callback(mode, move |valid, _| {
            calls.fetch_add(1, SeqCst);
            valid && allow
        }),
    }
}

#[tokio::test]
async fn sni_routing_preserves_the_original_verifier_and_its_captures() {
    for version in VERSIONS {
        for kind in 0..3 {
            for allow in [false, true] {
                for different_instance in [false, true] {
                    let original_calls = Arc::new(AtomicUsize::new(0));
                    let routed_calls = Arc::new(AtomicUsize::new(0));
                    let mut routed = server(version, SslVerifyMode::NONE);
                    if different_instance {
                        configure_routing_verifier(&mut routed, kind, routed_calls.clone(), !allow);
                    }
                    let routed = routed.build();
                    let mut s = server(version, SslVerifyMode::NONE);
                    configure_routing_verifier(&mut s, kind, original_calls.clone(), allow);
                    s.set_servername_callback(move |ssl, _| {
                        ssl.set_ssl_context(routed.context())
                            .map_err(|_| rama_boring::ssl::SniError::ALERT_FATAL)
                    });
                    let mut c = client(version);
                    c.add_credential(&material().client.credential()).unwrap();
                    let (s, c) =
                        pair(s.build(), client_ssl(c), Some(&material().client.cert)).await;
                    assert_eq!(
                        s.is_ok(),
                        allow,
                        "version={version:?}, kind={kind}, new callback={different_instance}"
                    );
                    assert_eq!(c.is_ok(), allow);
                    assert!(original_calls.load(SeqCst) > 0);
                    assert_eq!(routed_calls.load(SeqCst), 0);
                }
            }
        }
    }
}

#[tokio::test]
async fn routed_client_auth_policy_requires_explicit_per_connection_configuration() {
    for version in VERSIONS {
        for apply in [false, true] {
            let mode = SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT;
            let routed = server(version, mode).build();
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let mut s = server(version, SslVerifyMode::NONE);
            s.set_servername_callback(move |ssl, _| {
                ssl.set_ssl_context(routed.context())
                    .map_err(|_| rama_boring::ssl::SniError::ALERT_FATAL)?;
                count.fetch_add(1, SeqCst);
                if apply {
                    ssl.set_verify(mode);
                }
                Ok(())
            });
            let (s, c) = pair(s.build(), client_ssl(client(version)), None).await;
            assert_eq!(s.is_err(), apply);
            assert_eq!(c.is_err(), apply);
            assert_eq!(calls.load(SeqCst), 1);
        }
    }
}

struct RoutingSigner {
    key: PKey<Private>,
    calls: Arc<AtomicUsize>,
    finishes: Arc<AtomicUsize>,
    route: Option<rama_boring::ssl::SslContext>,
}
impl rama_boring::ssl::AsyncPrivateKeyMethod for RoutingSigner {
    fn sign(
        &self,
        ssl: &mut rama_boring::ssl::SslRef,
        input: &[u8],
        _: SslSignatureAlgorithm,
        _: &mut [u8],
    ) -> Result<
        rama_boring::ssl::BoxPrivateKeyMethodFuture,
        rama_boring::ssl::AsyncPrivateKeyMethodError,
    > {
        use rama_boring::ssl::{AsyncPrivateKeyMethodError, BoxPrivateKeyMethodFinish};
        self.calls.fetch_add(1, SeqCst);
        if let Some(ctx) = &self.route {
            ssl.set_ssl_context(ctx)
                .map_err(|_| AsyncPrivateKeyMethodError)?;
            // Repeated routing must not replace the selected credential's owner.
            let other = server(ssl.version().unwrap(), SslVerifyMode::NONE).build();
            ssl.set_ssl_context(other.context())
                .map_err(|_| AsyncPrivateKeyMethodError)?;
        }
        let (key, input, finishes) = (self.key.clone(), input.to_vec(), self.finishes.clone());
        Ok(Box::pin(async move {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
            Ok(
                Box::new(move |_: &mut rama_boring::ssl::SslRef, out: &mut [u8]| {
                    let mut signer = rama_boring::sign::Signer::new(MessageDigest::sha256(), &key)
                        .map_err(|_| AsyncPrivateKeyMethodError)?;
                    signer
                        .update(&input)
                        .map_err(|_| AsyncPrivateKeyMethodError)?;
                    let written = signer.sign(out).map_err(|_| AsyncPrivateKeyMethodError)?;
                    finishes.fetch_add(1, SeqCst);
                    Ok(written)
                }) as BoxPrivateKeyMethodFinish,
            )
        }))
    }
    fn decrypt(
        &self,
        _: &mut rama_boring::ssl::SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<
        rama_boring::ssl::BoxPrivateKeyMethodFuture,
        rama_boring::ssl::AsyncPrivateKeyMethodError,
    > {
        Err(rama_boring::ssl::AsyncPrivateKeyMethodError)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_signer_keeps_its_owner_across_context_switches() {
    for version in VERSIONS {
        for credential_level in [false, true] {
            for in_signer in [false, true] {
                for replacement_signer in [false, true] {
                    let (calls, finishes, wrong_calls) = (
                        Arc::new(AtomicUsize::new(0)),
                        Arc::new(AtomicUsize::new(0)),
                        Arc::new(AtomicUsize::new(0)),
                    );
                    let mut routed = server(version, SslVerifyMode::NONE);
                    if replacement_signer {
                        routed
                            .set_certificate(&material().other_client.cert)
                            .unwrap();
                        routed
                            .set_private_key(&material().other_client.key)
                            .unwrap();
                        routed.set_async_private_key_method(RoutingSigner {
                            key: material().other_client.key.clone(),
                            calls: wrong_calls.clone(),
                            finishes: Arc::new(AtomicUsize::new(0)),
                            route: None,
                        });
                    }
                    let routed = routed.build();
                    let signer = RoutingSigner {
                        key: material().server.key.clone(),
                        calls: calls.clone(),
                        finishes: finishes.clone(),
                        route: in_signer.then(|| routed.context().to_owned()),
                    };
                    let mut s = server(version, SslVerifyMode::NONE);
                    if credential_level {
                        let mut cred = SslCredential::builder().unwrap();
                        cred.set_certificate_chain([&material().server.cert])
                            .unwrap();
                        cred.set_async_private_key_method(signer).unwrap();
                        s.add_credential(&cred.build()).unwrap();
                    } else {
                        s.set_async_private_key_method(signer);
                    }
                    if !in_signer {
                        s.set_alpn_select_callback(move |ssl, offered| {
                            ssl.set_ssl_context(routed.context())
                                .map_err(|_| rama_boring::ssl::AlpnError::ALERT_FATAL)?;
                            rama_boring::ssl::select_next_proto(b"\x02h2", offered)
                                .ok_or(rama_boring::ssl::AlpnError::ALERT_FATAL)
                        });
                    }
                    let (s, c) = pair(s.build(), client_ssl(client(version)), None).await;
                    s.unwrap();
                    c.unwrap();
                    assert_eq!(calls.load(SeqCst), 1);
                    assert_eq!(finishes.load(SeqCst), 1);
                    assert_eq!(wrong_calls.load(SeqCst), 0);
                }
            }
        }
    }
}

#[tokio::test]
async fn routing_before_selection_uses_the_destination_signer() {
    for version in VERSIONS {
        let (calls, finishes) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let mut routed = server(version, SslVerifyMode::NONE);
        routed.set_async_private_key_method(RoutingSigner {
            key: material().server.key.clone(),
            calls: calls.clone(),
            finishes: finishes.clone(),
            route: None,
        });
        let routed = routed.build();
        let mut s = server(version, SslVerifyMode::NONE);
        s.set_select_certificate_callback(move |mut hello| {
            hello
                .ssl_mut()
                .set_ssl_context(routed.context())
                .map_err(|_| rama_boring::ssl::SelectCertError::ERROR)
        });
        let (s, c) = pair(s.build(), client_ssl(client(version)), None).await;
        s.unwrap();
        c.unwrap();
        assert_eq!(calls.load(SeqCst), 1);
        assert_eq!(finishes.load(SeqCst), 1);
    }
}

#[tokio::test]
async fn incompatible_first_credential_falls_back_to_the_second() {
    for version in VERSIONS {
        let mut c = client(version);
        c.set_certificate_callback(|mut selection| {
            let ssl = selection.ssl_mut();
            ssl.clear_certificates();
            ssl.add_credential(&issuer_constrained_credential())
                .map_err(|_| rama_boring::ssl::SelectCertError::ERROR)?;
            ssl.add_credential(&material().client.credential())
                .map_err(|_| rama_boring::ssl::SelectCertError::ERROR)
        });
        let (s, c) = pair(
            server(version, SslVerifyMode::PEER).build(),
            client_ssl(c),
            Some(&material().client.cert),
        )
        .await;
        s.unwrap();
        c.unwrap();
    }
}
