//! Regression tests for memory-safety bugs where safe code (including a
//! misbehaving callback, transport or peer) could cause undefined behavior.

use super::server::Server;
use super::{CERT, KEY, ROOT_CERT};
use crate::pkey::PKey;
use crate::ssl::test::private_key_method::Method;
use crate::ssl::{
    HandshakeError, PrivateKeyMethodError, Ssl, SslContext, SslContextBuilder, SslMethod,
    SslStream, SslVerifyMode, SslVersion,
};
use crate::x509::store::X509StoreBuilder;
use crate::x509::verify::X509VerifyParam;
use crate::x509::{X509StoreContext, X509};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn server_ctx() -> SslContextBuilder {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_certificate(&X509::from_pem(CERT).unwrap()).unwrap();
    ctx.set_private_key(&PKey::private_key_from_pem(KEY).unwrap())
        .unwrap();
    ctx
}

/// Sets a flag when dropped, to observe when a callback's captures are freed.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn client_hello_without_extensions_block_has_empty_extensions() {
    let seen_len = Arc::new(AtomicUsize::new(usize::MAX));
    let seen_len_cb = seen_len.clone();

    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback(move |hello| {
        // BoringSSL represents a missing extensions block as (NULL, 0).
        let extensions = hello.extensions();
        seen_len_cb.store(extensions.len(), Ordering::SeqCst);
        assert!(!hello.random().is_empty());
        assert!(!hello.ciphers().is_empty());
        assert!(!hello.as_bytes().is_empty());
        Ok(())
    });
    server.should_error();
    server.err_cb(|_| {});
    let server = server.build();

    // A TLS 1.2 ClientHello that ends right after the compression methods.
    let mut body = vec![0x03, 0x03];
    body.extend([0x11; 32]);
    body.push(0); // empty session id
    body.extend([0x00, 0x02, 0xc0, 0x2f]); // one cipher suite
    body.extend([0x01, 0x00]); // null compression
    let mut handshake = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
    handshake.extend(body);
    let mut record = vec![
        0x16,
        0x03,
        0x01,
        (handshake.len() >> 8) as u8,
        handshake.len() as u8,
    ];
    record.extend(handshake);

    let mut socket = server.connect_tcp();
    socket.write_all(&record).unwrap();
    let _ = socket.read(&mut [0; 64]);
    drop(socket);
    drop(server);

    assert_eq!(seen_len.load(Ordering::SeqCst), 0);
}

#[test]
fn shed_configuration_getters_do_not_return_null_references() {
    let server = Server::builder().build();
    let mut client = server.client().build().builder();
    client.ssl().set_verify(SslVerifyMode::NONE);
    client.ssl().set_shed_handshake_config(true);
    let mut stream = client.connect();

    assert_eq!(stream.ssl().ciphers().len(), 0);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = stream.ssl_mut().verify_param_mut();
    }));
    assert!(result.is_err());
}

#[test]
fn sni_callback_survives_switching_away_from_its_own_context() {
    let dropped = Arc::new(AtomicBool::new(false));
    let dropped_while_running = Arc::new(AtomicBool::new(true));
    let called = Arc::new(AtomicBool::new(false));

    let other = server_ctx().build();
    let mut switching = server_ctx();
    let flag = DropFlag(dropped.clone());
    let dropped_cb = dropped.clone();
    let dropped_while_running_cb = dropped_while_running.clone();
    let called_cb = called.clone();
    switching.set_servername_callback(move |ssl, _| {
        let _keep = &flag;
        // The connection holds the last reference to this callback's
        // context; switching away must not free the running callback.
        ssl.set_ssl_context(&other).unwrap();
        dropped_while_running_cb.store(dropped_cb.load(Ordering::SeqCst), Ordering::SeqCst);
        called_cb.store(true, Ordering::SeqCst);
        Ok(())
    });
    let switching = Mutex::new(Some(switching.build()));

    let mut server = Server::builder();
    server.ssl_cb(move |ssl| {
        if let Some(ctx) = switching.lock().unwrap().take() {
            ssl.set_ssl_context(&ctx).unwrap();
        }
    });
    let server = server.build();

    let mut client = server.client().build().builder();
    client.ssl().set_verify(SslVerifyMode::NONE);
    client.ssl().set_hostname("foobar.com").unwrap();
    client.connect();
    drop(server);

    assert!(called.load(Ordering::SeqCst));
    assert!(!dropped_while_running.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn verify_callbacks_cannot_get_a_mutable_ssl() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();
    let checked = Arc::new(AtomicUsize::new(0));
    let checked_cb = checked.clone();
    client.ctx().set_cert_verify_callback(move |ctx| {
        let idx = X509StoreContext::ssl_idx().unwrap();
        assert!(ctx.ex_data(idx).is_some());
        assert!(ctx.ex_data_mut(idx).is_none());
        checked_cb.fetch_add(1, Ordering::SeqCst);
        ctx.verify_cert().unwrap()
    });
    client.connect();
    assert_eq!(checked.load(Ordering::SeqCst), 1);
}

#[test]
fn verify_param_cannot_be_replaced_during_verification() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca().build().builder();
    let refused = Arc::new(AtomicBool::new(false));
    let refused_cb = refused.clone();
    // A host mismatch makes BoringSSL call the verify callback from
    // `check_id`, which keeps using the param it read before the call.
    client
        .ssl()
        .verify_param_mut()
        .set_host("not-the-cert-name.example")
        .unwrap();
    client
        .ssl()
        .set_verify_callback(SslVerifyMode::PEER, move |ok, ctx| {
            if !ok {
                let replaced = catch_unwind(AssertUnwindSafe(|| {
                    ctx.set_verify_param(X509VerifyParam::new().unwrap());
                }));
                if replaced.is_err() {
                    refused_cb.store(true, Ordering::SeqCst);
                }
                // The param is still usable after the refused replacement.
                ctx.verify_param_mut().set_depth(5);
            }
            true
        });
    client.connect();
    assert!(refused.load(Ordering::SeqCst));
}

#[test]
fn private_key_method_output_starts_zeroed() {
    let saw_uninit = Arc::new(AtomicBool::new(true));
    let saw_uninit_cb = saw_uninit.clone();

    let mut builder = Server::builder();
    builder
        .ctx()
        .set_private_key_method(Method::new().sign(move |_, _, _, output| {
            saw_uninit_cb.store(output.iter().any(|b| *b != 0), Ordering::SeqCst);
            Err(PrivateKeyMethodError::FAILURE)
        }));
    builder.should_error();
    builder.err_cb(|_| {});
    let server = builder.build();
    server.client_with_root_ca().connect_err();
    drop(server);

    assert!(!saw_uninit.load(Ordering::SeqCst));
}

/// One end of an in-memory, non-blocking transport.
#[derive(Debug)]
struct Pipe {
    rx: Arc<Mutex<VecDeque<u8>>>,
    tx: Arc<Mutex<VecDeque<u8>>>,
}

fn pipe_pair() -> (Pipe, Pipe) {
    let a = Arc::new(Mutex::new(VecDeque::new()));
    let b = Arc::new(Mutex::new(VecDeque::new()));
    (
        Pipe {
            rx: a.clone(),
            tx: b.clone(),
        },
        Pipe { rx: b, tx: a },
    )
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.rx.lock().unwrap();
        if rx.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = rx.len().min(buf.len());
        for (dst, src) in buf.iter_mut().zip(rx.drain(..n)) {
            *dst = src;
        }
        Ok(n)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx.lock().unwrap().extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

type Handshake<S> = Result<SslStream<S>, HandshakeError<S>>;

fn step<S: Read + Write>(r: Handshake<S>) -> Handshake<S> {
    match r {
        Err(HandshakeError::WouldBlock(mid)) => mid.handshake(),
        r => r,
    }
}

fn run_handshake<C: Read + Write, S: Read + Write>(
    mut client: Handshake<C>,
    mut server: Handshake<S>,
) -> (Handshake<C>, Handshake<S>) {
    for _ in 0..32 {
        client = step(client);
        server = step(server);
    }
    (client, server)
}

fn psk_context() -> SslContextBuilder {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.set_cipher_list("PSK-AES128-CBC-SHA").unwrap();
    ctx
}

fn psk_handshake(
    client_cb: impl Fn(&mut [u8], &mut [u8]) -> usize + Send + Sync + 'static,
) -> (bool, bool, Option<Vec<u8>>) {
    let mut client = psk_context();
    client.set_psk_client_callback(move |_, _, identity, psk| Ok(client_cb(identity, psk)));
    let mut server = psk_context();
    let seen_identity = Arc::new(Mutex::new(None));
    let seen_identity_cb = seen_identity.clone();
    server.set_psk_server_callback(move |_, identity, psk| {
        *seen_identity_cb.lock().unwrap() = identity.map(<[u8]>::to_vec);
        psk[..16].fill(7);
        Ok(16)
    });

    let (a, b) = pipe_pair();
    let client = Ssl::new(&client.build()).unwrap().connect(a);
    let server = Ssl::new(&server.build()).unwrap().accept(b);
    let (client, server) = run_handshake(client, server);
    let identity = seen_identity.lock().unwrap().clone();
    (client.is_ok(), server.is_ok(), identity)
}

#[test]
fn psk_client_callback_cannot_overstate_the_key_length() {
    let (client_ok, _, _) = psk_handshake(|identity, psk| {
        identity[0] = b'x';
        psk.fill(7);
        psk.len() + 1
    });
    assert!(!client_ok);
}

#[test]
fn psk_client_identity_is_always_nul_terminated() {
    let (client_ok, server_ok, identity) = psk_handshake(|identity, psk| {
        // Fill every byte of the identity slice: the terminator is outside it.
        identity.fill(b'x');
        psk[..16].fill(7);
        16
    });
    assert!(client_ok && server_ok);
    // The final byte of the slice is replaced by the NUL terminator.
    let identity = identity.unwrap();
    assert_eq!(identity.len(), 128);
    assert!(identity.iter().all(|b| *b == b'x'));
}

#[test]
fn psk_buffers_start_zeroed() {
    let zeroed = Arc::new(AtomicBool::new(false));
    let zeroed_cb = zeroed.clone();
    let (client_ok, server_ok, _) = psk_handshake(move |identity, psk| {
        zeroed_cb.store(
            identity.iter().chain(psk.iter()).all(|b| *b == 0),
            Ordering::SeqCst,
        );
        identity[0] = b'x';
        psk[..16].fill(7);
        16
    });
    assert!(client_ok && server_ok);
    assert!(zeroed.load(Ordering::SeqCst));
}

/// A transport wrapper whose `read` lies about how many bytes it read, and
/// that records whether the buffer it was handed was initialized (zero).
struct Lying {
    inner: Pipe,
    overstate: bool,
    overstate_write: bool,
    saw_nonzero: Arc<AtomicBool>,
}

impl Read for Lying {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.iter().any(|b| *b != 0) {
            self.saw_nonzero.store(true, Ordering::SeqCst);
        }
        let n = self.inner.read(buf)?;
        Ok(if self.overstate { buf.len() + 1 } else { n })
    }
}

impl Write for Lying {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        Ok(if self.overstate_write {
            buf.len() + 1
        } else {
            n
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn tls_pair(overstate: bool) -> (Handshake<Pipe>, Handshake<Lying>, Arc<AtomicBool>) {
    tls_pair_with(overstate, false)
}

fn tls_pair_with(
    overstate: bool,
    overstate_write: bool,
) -> (Handshake<Pipe>, Handshake<Lying>, Arc<AtomicBool>) {
    let mut client = SslContext::builder(SslMethod::tls()).unwrap();
    client.set_verify(SslVerifyMode::NONE);
    let (a, b) = pipe_pair();
    let saw_nonzero = Arc::new(AtomicBool::new(false));
    let lying = Lying {
        inner: b,
        overstate,
        overstate_write,
        saw_nonzero: saw_nonzero.clone(),
    };
    let client = Ssl::new(&client.build()).unwrap().connect(a);
    let server = Ssl::new(&server_ctx().build()).unwrap().accept(lying);
    (client, server, saw_nonzero)
}

#[test]
fn transport_reading_more_than_the_buffer_is_an_error() {
    let (client, server, _) = tls_pair(true);
    let (_, server) = run_handshake(client, server);
    let Err(HandshakeError::Failure(mid)) = server else {
        panic!("expected a handshake failure");
    };
    let io = mid.error().io_error().expect("expected an I/O error");
    assert_eq!(io.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn transport_read_buffer_starts_zeroed() {
    let (client, server, saw_nonzero) = tls_pair(false);
    let (client, server) = run_handshake(client, server);
    assert!(client.is_ok() && server.is_ok());
    assert!(!saw_nonzero.load(Ordering::SeqCst));
}

#[test]
fn verify_trust_store_root_still_verifies() {
    // Sanity check that the hardened verify paths still accept a valid chain.
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(X509::from_pem(ROOT_CERT).unwrap()).unwrap();
    let store = store.build();
    let leaf = X509::from_pem(CERT).unwrap();
    let chain = crate::stack::Stack::new().unwrap();
    let mut ctx = X509StoreContext::new().unwrap();
    assert!(ctx
        .init(&store, &leaf, &chain, |ctx| ctx.verify_cert())
        .unwrap());
}

#[test]
fn transport_writing_more_than_the_buffer_is_an_error() {
    let (client, server, _) = tls_pair_with(false, true);
    let (_, server) = run_handshake(client, server);
    let Err(HandshakeError::Failure(mid)) = server else {
        panic!("expected a handshake failure");
    };
    let io = mid.error().io_error().expect("expected an I/O error");
    assert_eq!(io.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn shared_stream_borrows_can_overlap() {
    let (client, server, _) = tls_pair(false);
    let (client, _server) = run_handshake(client, server);
    let client = client.unwrap();
    // Two live shared borrows of the transport at once.
    let a = client.get_ref();
    let b = client.get_ref();
    assert!(std::ptr::eq(a, b));
    assert!(a.rx.lock().is_ok() && b.tx.lock().is_ok());
}

#[test]
fn psk_server_callback_cannot_overstate_the_key_length() {
    let mut client = psk_context();
    client.set_psk_client_callback(|_, _, identity, psk| {
        identity[0] = b'x';
        psk[..16].fill(7);
        Ok(16)
    });
    let mut server = psk_context();
    server.set_psk_server_callback(|_, _, psk| {
        psk.fill(7);
        Ok(psk.len() + 1)
    });
    let (a, b) = pipe_pair();
    let client = Ssl::new(&client.build()).unwrap().connect(a);
    let server = Ssl::new(&server.build()).unwrap().accept(b);
    let (_, server) = run_handshake(client, server);
    assert!(server.is_err());
}

#[test]
fn private_key_method_cannot_overstate_the_output_length() {
    let mut builder = Server::builder();
    builder
        .ctx()
        .set_private_key_method(Method::new().sign(|_, _, _, output| Ok(output.len() + 1)));
    builder.should_error();
    builder.err_cb(|_| {});
    let server = builder.build();
    server.client_with_root_ca().connect_err();
}

static LONG_PROTOCOL: [u8; 256] = [b'a'; 256];

fn alpn_selection(len: usize) -> bool {
    let mut server = Server::builder();
    server
        .ctx()
        .set_alpn_select_callback(move |_, _| Ok(&LONG_PROTOCOL[..len]));
    server.should_error();
    server.err_cb(|_| {});
    let server = server.build();
    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x02h2").unwrap();
    client.ctx().set_verify(SslVerifyMode::NONE);
    let ok = client.build().builder().connect_err();
    matches!(ok, HandshakeError::Failure(_))
}

#[test]
fn alpn_selection_must_fit_the_one_byte_length() {
    // An empty or over-long selection would be truncated by the one-byte
    // length BoringSSL reads back; both now fail the handshake.
    assert!(alpn_selection(0));
    assert!(alpn_selection(256));
}

#[test]
fn native_shedding_without_rust_ex_data_is_detected() {
    use foreign_types::ForeignTypeRef;
    let server = Server::builder().build();
    let mut client = server.client().build().builder();
    client.ssl().set_verify(SslVerifyMode::NONE);
    // SAFETY: this is a live, exclusively borrowed SSL. Configure shedding
    // as a native integrator would, without the Rust setter's bookkeeping.
    unsafe { crate::ffi::SSL_set_shed_handshake_config(client.ssl().as_ptr(), 1) };
    let mut stream = client.connect();
    assert!(stream.ssl().handshake_config_shed());
    assert!(stream.ssl().ciphers().is_empty());
    assert!(stream.ssl_mut().certificate().is_none());
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = stream.ssl_mut().verify_param_mut();
    }))
    .is_err());
}
