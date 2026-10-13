use super::{capture_client_hello_extensions, server::Server};
use crate::ssl::{SslSessionCacheMode, SslVersion};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

const ALPN: u16 = 16;
const SUPPORTED_VERSIONS: u16 = 43;
const PRE_SHARED_KEY: u16 = 41;

#[test]
fn per_session_extension_order_concurrent_shared_context() {
    const CONNECTIONS: usize = 8;
    let mut server = Server::builder();
    server.expected_connections_count(CONNECTIONS + 1);
    let captured = capture_client_hello_extensions(&mut server);
    let server = server.build();
    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x02h2").unwrap();
    client
        .ctx()
        .set_extension_order(&[SUPPORTED_VERSIONS, ALPN])
        .unwrap();
    let client = client.build();
    let ready = Barrier::new(CONNECTIONS);

    // Set every plan before any handshake starts. A context-wide setter would
    // leave all connections with the final writer's plan instead of four each.
    thread::scope(|scope| {
        for index in 0..CONNECTIONS {
            let client = &client;
            let ready = &ready;
            scope.spawn(move || {
                let order = if index % 2 == 0 {
                    [ALPN, SUPPORTED_VERSIONS]
                } else {
                    [SUPPORTED_VERSIONS, ALPN]
                };
                let mut connection = client.builder();
                connection.ssl().set_extension_order(&order).unwrap();
                ready.wait();
                let _connected = connection.connect();
            });
        }
    });

    let _sibling = client.builder().connect();
    let captured = captured.lock().unwrap();
    assert_eq!(captured.len(), CONNECTIONS + 1);
    assert_eq!(
        captured[..CONNECTIONS]
            .iter()
            .filter(|ids| ids[..2] == [ALPN, SUPPORTED_VERSIONS])
            .count(),
        CONNECTIONS / 2
    );
    assert_eq!(
        captured[..CONNECTIONS]
            .iter()
            .filter(|ids| ids[..2] == [SUPPORTED_VERSIONS, ALPN])
            .count(),
        CONNECTIONS / 2
    );
    assert_eq!(captured[CONNECTIONS][..2], [SUPPORTED_VERSIONS, ALPN]);
}

#[test]
fn per_session_extension_order_preserves_tls13_resumption() {
    let mut server = Server::builder();
    server.expected_connections_count(3);
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let captured = capture_client_hello_extensions(&mut server);
    let server = server.build();
    let session = Arc::new(Mutex::new(None));
    let tickets = session.clone();
    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x02h2").unwrap();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client
        .ctx()
        .set_extension_order(&[SUPPORTED_VERSIONS, ALPN])
        .unwrap();
    client.ctx().set_new_session_callback(move |_, ticket| {
        *tickets.lock().unwrap() = Some(ticket);
    });
    let client = client.build();

    let mut first = client.builder();
    first
        .ssl()
        .set_extension_order(&[ALPN, SUPPORTED_VERSIONS])
        .unwrap();
    let first = first.connect();
    assert!(!first.ssl().session_reused());
    drop(first);

    let ticket = session
        .lock()
        .unwrap()
        .take()
        .expect("TLS 1.3 ticket received");
    let mut second = client.builder();
    // PSK remains last even when the session plan asks to put it first: its
    // binder and placement belong to the handshake, not capture replay.
    second
        .ssl()
        .set_extension_order(&[PRE_SHARED_KEY, SUPPORTED_VERSIONS, ALPN])
        .unwrap();
    // This ticket was authenticated using the same context and local server.
    unsafe {
        second.ssl().set_session(&ticket).unwrap();
    }
    let second = second.connect();
    assert!(second.ssl().session_reused());
    drop(second);

    let _sibling = client.builder().connect();
    let captured = captured.lock().unwrap();
    assert_eq!(captured.len(), 3);
    assert_eq!(captured[0][..2], [ALPN, SUPPORTED_VERSIONS]);
    assert_eq!(captured[1][..2], [SUPPORTED_VERSIONS, ALPN]);
    assert_eq!(captured[1].last(), Some(&PRE_SHARED_KEY));
    assert_eq!(captured[2][..2], [SUPPORTED_VERSIONS, ALPN]);
}
