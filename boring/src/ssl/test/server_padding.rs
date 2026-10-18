//! Exercise the real SSL owners and emitted handshake messages over TLS records
//! (the TCP transport format) and QUIC's handshake transport.
use super::{memory, wire};
use crate::ssl::{ClientHelloShape, ExtensionType, Ssl, SslRef, SslVersion, UnknownValues};
use std::sync::{Arc, Mutex};

const PADDING: u16 = 0x12e0;
type Messages = Arc<Mutex<Vec<Vec<u8>>>>;

fn capture(ssl: &mut SslRef, kind: u8) -> Messages {
    let messages = Messages::default();
    let out = messages.clone();
    ssl.set_msg_callback(move |_, message| {
        if message.is_written() && message.handshake_type() == Some(kind) {
            out.lock().unwrap().push(message.bytes().to_vec());
        }
    });
    messages
}

fn configure(
    client: &mut SslRef,
    server: &mut SslRef,
    request: Option<u16>,
    enabled: Option<bool>,
) {
    assert!(!client.server_sent_requested_padding());
    if let Some(request) = request {
        client.set_server_padding_request(123);
        client.set_server_padding_request(request);
    }
    if let Some(enabled) = enabled {
        server.set_server_padding_enabled(!enabled);
        server.set_server_padding_enabled(enabled);
    }
    client
        .set_extension_order(&[PADDING, 43, 0x1234, 10])
        .unwrap();
    client
        .set_client_hello_shape(
            &ClientHelloShape::new()
                .with_unknown_values(UnknownValues::Preserve)
                .with_extension_body(ExtensionType::from(0x1234), [7, 8]),
        )
        .unwrap();
    let error = client
        .set_client_hello_shape(
            &ClientHelloShape::new().with_extension_body(ExtensionType::from(PADDING), [0, 1]),
        )
        .unwrap_err();
    assert!(error
        .errors()
        .iter()
        .any(|e| e.reason() == Some("DUPLICATE_EXTENSION")));
}

fn check_wire(hello: &Messages, response: &Messages, request: Option<u16>, expected: bool) {
    let hello = hello.lock().unwrap();
    assert_eq!(hello.len(), 1);
    let hello = wire::ClientHello::parse(&hello[0]).unwrap();
    assert_eq!(
        hello
            .extensions
            .iter()
            .find(|(id, _)| *id == 0x1234)
            .unwrap()
            .1,
        [7, 8]
    );
    let ordered: Vec<_> = hello
        .extensions
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| [PADDING, 43, 0x1234, 10].contains(id))
        .collect();
    let expected_order: Vec<_> = [PADDING, 43, 0x1234, 10]
        .into_iter()
        .filter(|id| hello.extensions.iter().any(|(actual, _)| actual == id))
        .collect();
    assert_eq!(ordered, expected_order);
    let bodies: Vec<_> = hello
        .extensions
        .iter()
        .filter(|(id, _)| *id == PADDING)
        .collect();
    if let Some(request) = request {
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].1, request.to_be_bytes());
        assert_eq!(hello.extensions[0].0, PADDING);
    } else {
        assert!(bodies.is_empty());
    }
    let mut padding = None;
    for message in response.lock().unwrap().iter() {
        let mut r = wire::Reader::new(&message[4..]);
        let mut extensions = r.prefixed_u16().unwrap();
        r.finish().unwrap();
        while !extensions.is_empty() {
            let id = extensions.u16().unwrap();
            let body = extensions.prefixed_u16().unwrap().rest();
            if id == PADDING {
                assert!(padding.replace(body.to_vec()).is_none());
            }
        }
    }
    assert_eq!(
        padding,
        if expected {
            Some(vec![0; usize::from(request.unwrap())])
        } else {
            None
        }
    );
}

#[test]
fn server_padding_record_handshakes() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut ctx = memory::client_context();
        ctx.set_min_proto_version(Some(version)).unwrap();
        ctx.set_max_proto_version(Some(version)).unwrap();
        let ctx = ctx.build();
        let server_ctx = memory::server_context().build();
        // Reuse contexts, but never connection configuration.
        for request in [
            None,
            Some(0),
            Some(10),
            Some(16384),
            Some(16385),
            Some(u16::MAX),
            None,
        ] {
            for enabled in [None, Some(true), Some(false)] {
                let mut client = Ssl::new(&ctx).unwrap();
                let mut server = Ssl::new(&server_ctx).unwrap();
                configure(&mut client, &mut server, request, enabled);
                let hello = capture(&mut client, 1);
                let response = capture(&mut server, 8);
                let (client, server) = memory::handshake(client, server);
                let mut client = client.done();
                server.done();
                let expected = version == SslVersion::TLS1_3
                    && enabled == Some(true)
                    && request.is_some_and(|n| n <= 16384);
                assert_eq!(client.ssl().server_sent_requested_padding(), expected);
                check_wire(&hello, &response, request, expected);
                client.ssl_mut().set_server_padding_request(99);
                assert_eq!(client.ssl().server_sent_requested_padding(), expected);
            }
        }
    }
}

#[test]
fn server_padding_quic_handshakes_and_resumption() {
    use crate::ssl::quic::tests::{connection, contexts, pump, Record};
    let (client_ctx, server_ctx, tickets) = contexts();
    for request in [
        None,
        Some(0),
        Some(10),
        Some(16384),
        Some(16385),
        Some(u16::MAX),
        None,
    ] {
        for enabled in [None, Some(true), Some(false)] {
            for resumed in [false, true] {
                let c = Arc::new(Record::default());
                let s = Arc::new(Record::default());
                let mut client = connection(&client_ctx, false, c.clone());
                let mut server = connection(&server_ctx, true, s.clone());
                configure(client.ssl_mut(), server.ssl_mut(), request, enabled);
                if resumed {
                    let ticket = tickets.lock().unwrap().take().unwrap();
                    // The ticket was obtained using this same context.
                    unsafe {
                        client.ssl_mut().set_session(&ticket).unwrap();
                    }
                }
                let hello = capture(client.ssl_mut(), 1);
                let response = capture(server.ssl_mut(), 8);
                pump(&mut client, &mut server, &c, &s).unwrap();
                assert_eq!(client.ssl().session_reused(), resumed);
                let expected =
                    !resumed && enabled == Some(true) && request.is_some_and(|n| n <= 16384);
                assert_eq!(client.ssl().server_sent_requested_padding(), expected);
                check_wire(&hello, &response, request, expected);
            }
        }
    }
}

#[test]
fn server_padding_late_request_changes_validation_not_emitted_hello() {
    let mut client = Ssl::new(&memory::client_context().build()).unwrap();
    let mut server = Ssl::new(&memory::server_context().build()).unwrap();
    client.set_server_padding_request(10);
    server.set_server_padding_enabled(true);
    let hello = capture(&mut client, 1);
    let (a, b) = memory::ends();
    let mut client = match memory::Side::from(client.connect(a)) {
        memory::Side::Mid(client) => client,
        _ => panic!("expected pending ClientHello"),
    };
    client.ssl_mut().set_server_padding_request(11);
    let mut server = memory::Side::from(server.accept(b));
    let mut client = memory::Side::from(client.handshake());
    for _ in 0..8 {
        server = server.step();
        client = client.step();
    }
    client.panicked_or_failed_with("DECODE_ERROR");
    let hello = hello.lock().unwrap();
    let hello = wire::ClientHello::parse(&hello[0]).unwrap();
    assert_eq!(
        hello
            .extensions
            .iter()
            .find(|(id, _)| *id == PADDING)
            .unwrap()
            .1,
        [0, 10]
    );
}

#[test]
fn server_padding_tcp_handshake() {
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut server = Ssl::new(&memory::server_context().build()).unwrap();
    let mut client = Ssl::new(&memory::client_context().build()).unwrap();
    configure(&mut client, &mut server, Some(1000), Some(true));
    let hello = capture(&mut client, 1);
    let response = capture(&mut server, 8);
    let thread = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        server.accept(tcp).unwrap();
    });
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let client = client.connect(tcp).unwrap();
    thread.join().unwrap();
    assert!(client.ssl().server_sent_requested_padding());
    check_wire(&hello, &response, Some(1000), true);
}
