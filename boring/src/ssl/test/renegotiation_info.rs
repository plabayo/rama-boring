//! A ClientHello that omits renegotiation_info and signals RFC 5746 through
//! the SCSV in its raw cipher list instead, as some TLS 1.2 browser hellos do.

use super::memory::{client_context, ends, handshake, server_context, Buffer, End, Side};
use super::wire::{self, Extension};
use crate::ssl::{ClientHelloShape, Ssl, SslContext, SslRef, SslVersion};
use std::sync::{Arc, Mutex};

const EXTENDED_MASTER_SECRET: u16 = 23;
const RENEGOTIATION_INFO: u16 = 0xff01;
const SCSV: u16 = 0x00ff;
const ECDHE_RSA_AES128_GCM: u16 = 0xc02f;
/// An empty renegotiated_connection.
const EMPTY: &[u8] = &[0];

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

fn of(messages: &Messages, out: bool, kind: u8) -> Vec<Vec<u8>> {
    messages
        .lock()
        .unwrap()
        .iter()
        .filter(|(is_out, bytes)| *is_out == out && bytes[0] == kind)
        .map(|(_, bytes)| bytes.clone())
        .collect()
}

fn tls12_server() -> SslContext {
    let mut ctx = server_context();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.build()
}

/// A client offering only TLS 1.2, as those browser hellos do.
fn tls12_client(omit: Option<bool>, scsv: bool) -> Ssl {
    let mut ctx = client_context();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    let ciphers: &[u16] = if scsv {
        &[ECDHE_RSA_AES128_GCM, SCSV]
    } else {
        &[ECDHE_RSA_AES128_GCM]
    };
    ssl.set_raw_cipher_list(ciphers).unwrap();
    if let Some(omit) = omit {
        ssl.set_client_hello_shape(&ClientHelloShape::new().with_omit_renegotiation_info(omit))
            .unwrap();
    }
    ssl
}

/// The extension changes, EMS stays, and the SCSV is sent exactly as listed.
#[track_caller]
fn check_hello(bytes: &[u8], omit: bool, scsv: bool) {
    let hello = wire::ClientHello::parse(bytes).expect("a well-formed ClientHello");
    assert_eq!(
        hello.extension(RENEGOTIATION_INFO),
        (!omit).then_some(EMPTY)
    );
    assert_eq!(hello.extension(EXTENDED_MASTER_SECRET), Some(&[][..]));
    assert_eq!(hello.ciphers.contains(&SCSV), scsv);
}

#[test]
fn omitted_renegotiation_info_keeps_ems_over_tls12() {
    let server = tls12_server();
    for omit in [None, Some(false), Some(true)] {
        for scsv in [false, true] {
            let mut client = tls12_client(omit, scsv);
            let messages = record(&mut client);
            let client = handshake(client, Ssl::new(&server).unwrap()).0.done();
            let omit = omit == Some(true);
            check_hello(&of(&messages, true, 1)[0], omit, scsv);
            // The BoringSSL server answers either signal with an empty
            // renegotiation_info and ignores a client that sent none.
            let solicited = !omit || scsv;
            let reply = &of(&messages, false, 2)[0];
            let reply = wire::ServerHello::parse(reply).unwrap();
            assert_eq!(
                wire::find(&reply.extensions, RENEGOTIATION_INFO),
                solicited.then_some(EMPTY)
            );
            assert_eq!(client.ssl().version(), Some(SslVersion::TLS1_2));
            assert_eq!(client.ssl().secure_renegotiation_support(), solicited);
            assert!(client.ssl().extended_master_secret_support());
        }
    }
}

/// Puts `extension` into the ServerHello at the front of the client's input.
fn rewrite_server_hello(rx: &Buffer, extension: Extension<'static>) {
    let mut rx = rx.lock().unwrap();
    let bytes: Vec<u8> = rx.drain(..).collect();
    let message = wire::first_record_message(&bytes).expect("a ServerHello record");
    let mut hello = wire::ServerHello::parse(message).unwrap();
    hello.extensions.retain(|(id, _)| *id != extension.0);
    hello.extensions.push(extension);
    let rewritten = hello.reencode(message).unwrap();
    let end = 5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    let fragment = [&rewritten[..], &bytes[5 + message.len()..end]].concat();
    let len = u16::try_from(fragment.len()).unwrap().to_be_bytes();
    rx.extend(&bytes[..3]);
    rx.extend(len);
    rx.extend(fragment);
    rx.extend(&bytes[end..]);
}

/// The client's handshake after it reads a ServerHello carrying `extension`.
fn answered_with(client: Ssl, extension: Extension<'static>) -> Side<End> {
    let (a, b) = ends();
    let rx = a.rx.clone();
    let client = Side::from(client.connect(a));
    let _server = Side::from(Ssl::new(&tls12_server()).unwrap().accept(b));
    rewrite_server_hello(&rx, extension);
    client.step()
}

/// Without the SCSV, the client signalled nothing, so a renegotiation_info
/// reply is unsolicited. With it, the reply is checked as if the extension
/// had been sent: an initial handshake needs an empty renegotiated_connection.
#[test]
fn renegotiation_info_replies_follow_the_scsv() {
    answered_with(tls12_client(Some(true), false), (RENEGOTIATION_INFO, EMPTY))
        .panicked_or_failed_with("UNEXPECTED_EXTENSION");
    let stale: &[u8] = &[1, 0];
    for omit in [false, true] {
        answered_with(tls12_client(Some(omit), true), (RENEGOTIATION_INFO, stale))
            .panicked_or_failed_with("RENEGOTIATION_MISMATCH");
    }
}

/// TLS 1.3 negotiates no renegotiation, whatever the hello offered.
#[test]
fn tls13_handshakes_ignore_the_control() {
    let server = server_context().build();
    for (min, legacy) in [
        (SslVersion::TLS1_2, false),
        (SslVersion::TLS1_3, false),
        (SslVersion::TLS1_3, true),
    ] {
        for omit in [false, true] {
            let mut ctx = client_context();
            ctx.set_min_proto_version(Some(min)).unwrap();
            let mut client = Ssl::new(&ctx.build()).unwrap();
            client
                .set_raw_cipher_list(&[0x1301, ECDHE_RSA_AES128_GCM, SCSV])
                .unwrap();
            client
                .set_client_hello_shape(
                    &ClientHelloShape::new()
                        .with_legacy_extensions(legacy)
                        .with_omit_renegotiation_info(omit),
                )
                .unwrap();
            let messages = record(&mut client);
            let client = handshake(client, Ssl::new(&server).unwrap()).0.done();
            assert_eq!(client.ssl().version(), Some(SslVersion::TLS1_3));
            assert!(client.ssl().secure_renegotiation_support());
            let hello = &of(&messages, true, 1)[0];
            let hello = wire::ClientHello::parse(hello).unwrap();
            let sent = min == SslVersion::TLS1_2 || legacy;
            assert_eq!(
                hello.extension(RENEGOTIATION_INFO),
                (sent && !omit).then_some(EMPTY)
            );
            assert_eq!(
                hello.extension(EXTENDED_MASTER_SECRET),
                sent.then_some(&[][..])
            );
            let reply = &of(&messages, false, 2)[0];
            let reply = wire::ServerHello::parse(reply).unwrap();
            assert!(wire::find(&reply.extensions, RENEGOTIATION_INFO).is_none());
        }
    }
}
