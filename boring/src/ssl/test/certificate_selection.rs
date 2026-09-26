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
