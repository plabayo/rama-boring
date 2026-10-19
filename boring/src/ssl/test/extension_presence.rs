//! Per-connection presence of ec_point_formats and psk_key_exchange_modes in
//! a ClientHello offering TLS 1.3, over TLS records and QUIC, with and without
//! sessions.

use super::memory::{client_context, handshake, server_context};
use super::wire;
use crate::ffi;
use crate::hash::MessageDigest;
use crate::ssl::quic::tests::{connection, contexts, pump, Record};
use crate::ssl::{
    ClientHelloShape, Ssl, SslContext, SslEarlyDataReason, SslRef, SslSession, SslSessionCacheMode,
    SslVersion,
};
use foreign_types::ForeignTypeRef;
use std::sync::{Arc, Mutex};

const EC_POINT_FORMATS: u16 = 11;
const PADDING: u16 = 21;
const PRE_SHARED_KEY: u16 = 41;
const EARLY_DATA: u16 = 42;
const SUPPORTED_VERSIONS: u16 = 43;
const PSK_KEY_EXCHANGE_MODES: u16 = 45;
const KEY_SHARE: u16 = 51;
/// Only uncompressed points.
const UNCOMPRESSED: &[u8] = &[1, 0];
/// Only psk_dhe_ke.
const PSK_DHE_KE: &[u8] = &[1, 1];

type Messages = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

/// Records every handshake message `ssl` writes or reads.
fn record(ssl: &mut SslRef) -> Messages {
    let messages = Messages::default();
    let sink = messages.clone();
    ssl.set_msg_callback(move |_, message| {
        if message.handshake_type().is_some() {
            sink.lock()
                .unwrap()
                .push((message.is_written(), message.bytes().to_vec()));
        }
    });
    messages
}

fn written(messages: &Messages, kind: u8) -> Vec<Vec<u8>> {
    of(messages, true, kind)
}

fn of(messages: &Messages, out: bool, kind: u8) -> Vec<Vec<u8>> {
    messages
        .lock()
        .unwrap()
        .iter()
        .filter(|(is_out, bytes)| *is_out == out && bytes[0] == kind)
        .map(|(_, bytes)| bytes.clone())
        .collect()
}

fn shape(ec_point_formats: bool, omit_psk_modes: bool) -> ClientHelloShape {
    ClientHelloShape::new()
        .with_ec_point_formats(ec_point_formats)
        .with_omit_psk_key_exchange_modes(omit_psk_modes)
}

/// The controls decide exactly these two extensions; the order orders 11 once
/// it is sent, and a server never echoes it in TLS 1.3.
#[track_caller]
fn check_hello(
    bytes: &[u8],
    ec_point_formats: bool,
    omit_psk_modes: bool,
    order: &[u16],
) -> Vec<u16> {
    let hello = wire::ClientHello::parse(bytes).expect("a well-formed ClientHello");
    assert_eq!(
        hello.extension(EC_POINT_FORMATS),
        ec_point_formats.then_some(UNCOMPRESSED)
    );
    assert_eq!(
        hello.extension(PSK_KEY_EXCHANGE_MODES),
        (!omit_psk_modes).then_some(PSK_DHE_KE)
    );
    let ids = hello.ids();
    let listed: Vec<u16> = order
        .iter()
        .copied()
        .filter(|id| ids.contains(id))
        .collect();
    assert_eq!(ids[..listed.len()], listed, "{ids:?}");
    ids
}

#[track_caller]
fn check_server_messages(messages: &Messages) {
    for bytes in of(messages, false, 2) {
        let hello = wire::ServerHello::parse(&bytes).unwrap();
        assert!(wire::find(&hello.extensions, EC_POINT_FORMATS).is_none());
    }
    for bytes in of(messages, false, 8) {
        let extensions = wire::encrypted_extensions(&bytes).unwrap();
        assert!(wire::find(&extensions, EC_POINT_FORMATS).is_none());
    }
}

fn tls13_client() -> SslContext {
    let mut ctx = client_context();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.build()
}

#[test]
fn defaults_keep_the_native_tls13_membership() {
    let ctx = tls13_client();
    for shape in [None, Some(ClientHelloShape::new())] {
        let mut client = Ssl::new(&ctx).unwrap();
        if let Some(shape) = &shape {
            client.set_client_hello_shape(shape).unwrap();
        }
        let messages = record(&mut client);
        handshake(client, Ssl::new(&server_context().build()).unwrap())
            .0
            .done();
        check_hello(&written(&messages, 1)[0], false, false, &[]);
    }
}

#[test]
fn presence_controls_over_tls_records() {
    let orders: [&[u16]; 3] = [
        &[],
        &[EC_POINT_FORMATS, SUPPORTED_VERSIONS, KEY_SHARE],
        &[
            KEY_SHARE,
            PSK_KEY_EXCHANGE_MODES,
            SUPPORTED_VERSIONS,
            EC_POINT_FORMATS,
        ],
    ];
    for min in [SslVersion::TLS1_3, SslVersion::TLS1_2] {
        let mut ctx = client_context();
        ctx.set_min_proto_version(Some(min)).unwrap();
        let ctx = ctx.build();
        for retry in [false, true] {
            let mut server_ctx = server_context();
            if retry {
                // The client's key share is X25519: the server asks again.
                server_ctx.set_curves_list("P-384").unwrap();
            }
            let server_ctx = server_ctx.build();
            for order in orders {
                for (ec, omit) in [(false, false), (true, false), (false, true), (true, true)] {
                    let mut client = Ssl::new(&ctx).unwrap();
                    client.set_extension_order(order).unwrap();
                    // A later shape replaces an earlier one as a whole.
                    client.set_client_hello_shape(&shape(!ec, !omit)).unwrap();
                    client.set_client_hello_shape(&shape(ec, omit)).unwrap();
                    let messages = record(&mut client);
                    let (client, _) = handshake(client, Ssl::new(&server_ctx).unwrap());
                    let client = client.done();
                    assert_eq!(client.ssl().version(), Some(SslVersion::TLS1_3));
                    assert_eq!(client.ssl().used_hello_retry_request(), retry);
                    let hellos = written(&messages, 1);
                    assert_eq!(hellos.len(), 1 + usize::from(retry));
                    // Below a TLS 1.3 minimum, ec_point_formats is always sent.
                    let ec = ec || min == SslVersion::TLS1_2;
                    let ids: Vec<Vec<u16>> = hellos
                        .iter()
                        .map(|hello| check_hello(hello, ec, omit, order))
                        .map(|ids| ids.into_iter().filter(|id| *id != PADDING).collect())
                        .collect();
                    if retry {
                        // The retry keeps membership and order; only a first
                        // ClientHello is padded.
                        assert_eq!(ids[0], ids[1]);
                    }
                    assert!(!ids[0].contains(&PRE_SHARED_KEY));
                    check_server_messages(&messages);
                }
            }
        }
    }
}

#[test]
fn presence_controls_with_a_tls12_server() {
    let mut server = server_context();
    server
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    let server = server.build();
    let mut ctx = client_context();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    let ctx = ctx.build();
    let mut client = Ssl::new(&ctx).unwrap();
    client.set_client_hello_shape(&shape(true, true)).unwrap();
    let messages = record(&mut client);
    let client = handshake(client, Ssl::new(&server).unwrap()).0.done();
    assert_eq!(client.ssl().version(), Some(SslVersion::TLS1_2));
    check_hello(&written(&messages, 1)[0], true, true, &[]);
    // A TLS 1.2 server echoes ec_point_formats, as natively.
    let hello = &of(&messages, false, 2)[0];
    let hello = wire::ServerHello::parse(hello).unwrap();
    assert!(wire::find(&hello.extensions, EC_POINT_FORMATS).is_some());
}

/// A client context that keeps the last session it receives.
fn session_client(min: SslVersion) -> (SslContext, Arc<Mutex<Vec<SslSession>>>) {
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let sink = sessions.clone();
    let mut ctx = client_context();
    ctx.set_min_proto_version(Some(min)).unwrap();
    ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    ctx.set_new_session_callback(move |_, session| sink.lock().unwrap().push(session));
    (ctx.build(), sessions)
}

/// Connects, then exchanges data so the client reads TLS 1.3 tickets.
fn connect(client: Ssl, server: &SslContext) -> (bool, Vec<Vec<u8>>) {
    use std::io::{Read, Write};
    let mut client = client;
    let messages = record(&mut client);
    let (client, server) = handshake(client, Ssl::new(server).unwrap());
    let (mut client, mut server) = (client.done(), server.done());
    client.write_all(b"ping").unwrap();
    let mut buf = [0; 4];
    server.read_exact(&mut buf).unwrap();
    server.write_all(b"pong").unwrap();
    client.read_exact(&mut buf).unwrap();
    (client.ssl().session_reused(), written(&messages, 1))
}

#[test]
fn omitted_psk_modes_never_offer_a_session_over_tls_records() {
    for (min, server_max) in [
        (SslVersion::TLS1_3, SslVersion::TLS1_3),
        // A TLS 1.2 session is offered by ID or ticket, not by a PSK, yet the
        // control still offers none.
        (SslVersion::TLS1_2, SslVersion::TLS1_2),
    ] {
        let mut server = server_context();
        server.set_max_proto_version(Some(server_max)).unwrap();
        let server = server.build();
        let (ctx, sessions) = session_client(min);
        let (reused, _) = connect(Ssl::new(&ctx).unwrap(), &server);
        assert!(!reused);
        let session = sessions.lock().unwrap().pop().expect("a session");
        sessions.lock().unwrap().clear();
        for session_first in [false, true] {
            let mut client = Ssl::new(&ctx).unwrap();
            // The session belongs to this client context and server; setting
            // it before or after the shape makes no difference.
            if session_first {
                unsafe { client.set_session(&session).unwrap() };
            }
            client.set_client_hello_shape(&shape(true, true)).unwrap();
            if !session_first {
                unsafe { client.set_session(&session).unwrap() };
            }
            let (reused, hellos) = connect(client, &server);
            assert!(!reused);
            let ids = check_hello(&hellos[0], true, true, &[]);
            assert!(!ids.contains(&PRE_SHARED_KEY));
            assert!(!ids.contains(&EARLY_DATA));
            if server_max == SslVersion::TLS1_3 {
                // Without psk_key_exchange_modes the server issues no ticket.
                assert!(sessions.lock().unwrap().is_empty());
            }
            // The TLS 1.2 session ID is fresh, not the session's.
            let hello = wire::ClientHello::parse(&hellos[0]).unwrap();
            assert_ne!(hello.session_id, session.id());
        }
        // The session itself is untouched: without the control it resumes.
        let mut client = Ssl::new(&ctx).unwrap();
        client.set_client_hello_shape(&shape(true, false)).unwrap();
        unsafe { client.set_session(&session).unwrap() };
        let (reused, hellos) = connect(client, &server);
        assert!(reused);
        let ids = check_hello(&hellos[0], true, false, &[]);
        assert_eq!(
            ids.contains(&PRE_SHARED_KEY),
            server_max == SslVersion::TLS1_3
        );
    }
}

/// An external PSK credential (RFC 9258) for clients and servers alike.
fn add_psk(ssl: &mut SslRef) {
    unsafe {
        let credential = ffi::SSL_CREDENTIAL_new_pre_shared_key(
            [7; 32].as_ptr(),
            32,
            b"identity".as_ptr(),
            8,
            MessageDigest::sha256().as_ptr(),
            b"context".as_ptr(),
            7,
        );
        assert!(!credential.is_null());
        assert_eq!(ffi::SSL_add1_credential(ssl.as_ptr(), credential), 1);
        ffi::SSL_CREDENTIAL_free(credential);
    }
}

/// A PSK credential needs psk_key_exchange_modes: the combination fails the
/// handshake before any ClientHello is written.
#[test]
fn psk_credentials_require_psk_modes() {
    let server = server_context().build();
    for omit in [false, true] {
        let mut client = Ssl::new(&tls13_client()).unwrap();
        add_psk(&mut client);
        client.set_client_hello_shape(&shape(true, omit)).unwrap();
        let messages = record(&mut client);
        let mut server = Ssl::new(&server).unwrap();
        add_psk(&mut server);
        let (client, _) = handshake(client, server);
        let hellos = written(&messages, 1);
        if omit {
            client.panicked_or_failed_with("NO_SUPPORTED_PSK_MODE");
            assert!(hellos.is_empty());
        } else {
            let client = client.done();
            assert!(client.ssl().peer_certificate().is_none(), "a PSK handshake");
            let ids = check_hello(&hellos[0], true, false, &[]);
            assert!(ids.contains(&PRE_SHARED_KEY));
        }
    }
}

#[test]
fn presence_controls_over_quic() {
    let (client_ctx, server_ctx, tickets) = contexts();
    let order = [SUPPORTED_VERSIONS, EC_POINT_FORMATS, KEY_SHARE];
    let run = |shape: Option<&ClientHelloShape>, ticket: Option<&SslSession>| {
        let c = Arc::new(Record::default());
        let s = Arc::new(Record::default());
        let mut client = connection(&client_ctx, false, c.clone());
        let mut server = connection(&server_ctx, true, s.clone());
        client.ssl_mut().set_extension_order(&order).unwrap();
        if let Some(shape) = shape {
            client.ssl_mut().set_client_hello_shape(shape).unwrap();
        }
        if let Some(ticket) = ticket {
            // Tickets come from this client context and server.
            unsafe { client.ssl_mut().set_session(ticket).unwrap() };
        }
        let messages = record(client.ssl_mut());
        pump(&mut client, &mut server, &c, &s).unwrap();
        check_server_messages(&messages);
        let hello = written(&messages, 1).remove(0);
        (client, hello)
    };
    for (ec, omit) in [(false, false), (true, false), (false, true), (true, true)] {
        let shape = shape(ec, omit);
        // Fresh connections: every one gets its own random and key shares.
        let (_, first) = run(Some(&shape), None);
        let (_, second) = run(Some(&shape), None);
        let ids = check_hello(&first, ec, omit, &order);
        assert_eq!(ids, check_hello(&second, ec, omit, &order));
        let (a, b) = (
            wire::ClientHello::parse(&first).unwrap(),
            wire::ClientHello::parse(&second).unwrap(),
        );
        assert_ne!(a.random, b.random);
        assert_ne!(a.extension(KEY_SHARE), b.extension(KEY_SHARE));
        // Without the extension, the BoringSSL server issues no ticket.
        assert_eq!(tickets.lock().unwrap().take().is_some(), !omit);
    }
    // A ticket from a default connection.
    run(None, None);
    let ticket = tickets.lock().unwrap().take().expect("a ticket");
    for omit in [true, false] {
        let (client, hello) = run(Some(&shape(true, omit)), Some(&ticket));
        let ids = check_hello(&hello, true, omit, &order);
        assert_eq!(ids.contains(&PRE_SHARED_KEY), !omit);
        assert_eq!(ids.contains(&EARLY_DATA), !omit);
        assert_eq!(client.ssl().session_reused(), !omit);
        assert_eq!(client.early_data_accepted(), !omit);
        assert_eq!(
            client.ssl().early_data_reason(),
            if omit {
                SslEarlyDataReason::NO_SESSION_OFFERED
            } else {
                SslEarlyDataReason::ACCEPTED
            }
        );
    }
}
