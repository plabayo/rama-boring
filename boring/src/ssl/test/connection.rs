//! Per-connection wire settings, message observation and negotiated-state getters.

use super::memory::{client_context, connect, handshake, server_context, End};
use super::wire::{self, Reader};
use crate::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ExtensionType, SslContentType,
    SslContextBuilder, SslMessage, SslRef, SslRenegotiateMode, SslSignatureAlgorithm, SslStream,
    SslVersion,
};
use crate::ssl::{Ssl, SslVerifyMode};
use std::{
    io::{self, Read, Write},
    sync::{Arc, Mutex},
};

/// What a server saw of a ClientHello.
#[derive(Debug, Default, Clone)]
struct Hello {
    ciphers: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    fn extension(&self, id: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(ext, _)| *ext == id)
            .map(|(_, body)| body.as_slice())
    }
}

fn capture(server: &mut SslContextBuilder) -> Arc<Mutex<Vec<Hello>>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    server.set_select_certificate_callback(move |hello| {
        let ciphers = Reader::new(hello.ciphers()).u16s().expect("cipher list");
        let extensions = wire::extensions(Reader::new(hello.extensions()))
            .expect("extensions")
            .into_iter()
            .map(|(id, body)| (id, body.to_vec()))
            .collect();
        sink.lock().unwrap().push(Hello {
            ciphers,
            extensions,
        });
        Ok(())
    });
    captured
}

fn tls12(mut ctx: SslContextBuilder) -> SslContextBuilder {
    ctx.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx
}

#[test]
fn raw_cipher_list_applies_to_one_connection() {
    let mut server = server_context();
    let hellos = capture(&mut server);
    let server = server.build();
    let mut client = client_context();
    client.set_raw_cipher_list(&[0xc02f, 0x1301]).unwrap();
    let client = client.build();

    // Values unknown to BoringSSL are offered as-is; known ones negotiate.
    let mut custom = Ssl::new(&client).unwrap();
    custom
        .set_raw_cipher_list(&[0x1302, 0xcafe, 0x1301, 0xc030])
        .unwrap();
    handshake(custom, Ssl::new(&server).unwrap()).0.done();
    handshake(Ssl::new(&client).unwrap(), Ssl::new(&server).unwrap())
        .0
        .done();

    let hellos = hellos.lock().unwrap();
    assert_eq!(hellos[0].ciphers, [0x1302, 0xcafe, 0x1301, 0xc030]);
    assert_eq!(hellos[1].ciphers, [0xc02f, 0x1301], "context list changed");
}

#[test]
fn tls12_server_cipher_is_pinned_per_connection() {
    let server = tls12(server_context()).build();
    let client = tls12(client_context()).build();
    for (pin, id) in [
        ("ECDHE-RSA-AES256-GCM-SHA384", 0xc030),
        ("ECDHE-RSA-AES128-GCM-SHA256", 0xc02f),
    ] {
        let mut ssl = Ssl::new(&server).unwrap();
        ssl.set_strict_cipher_list(pin).unwrap();
        let (client, _) = handshake(Ssl::new(&client).unwrap(), ssl);
        let client = client.done();
        assert_eq!(client.ssl().current_cipher().unwrap().protocol_id(), id);
    }
    let mut ssl = Ssl::new(&server).unwrap();
    assert!(ssl.set_strict_cipher_list("NOT-A-CIPHER").is_err());
    assert!(ssl.set_cipher_list("bad\0list").is_err());
}

#[test]
fn tls13_server_cipher_preference_is_per_connection() {
    let server = server_context().build();
    let mut client = client_context();
    client
        .set_raw_cipher_list(&[0x1301, 0x1302, 0x1303])
        .unwrap();
    let client = client.build();
    for (preference, expected) in [
        (&[0x1303][..], 0x1303),
        (&[0x1302, 0x1303], 0x1302),
        (&[][..], 0x1301),
    ] {
        let mut ssl = Ssl::new(&server).unwrap();
        ssl.set_tls13_server_ciphers(preference).unwrap();
        let client = handshake(Ssl::new(&client).unwrap(), ssl).0.done();
        assert_eq!(
            client.ssl().current_cipher().unwrap().protocol_id(),
            expected,
            "{preference:x?}"
        );
    }

    // A preference the client did not offer falls back to the native choice.
    let mut only_aes128 = Ssl::new(&client_context().build()).unwrap();
    only_aes128.set_raw_cipher_list(&[0x1301]).unwrap();
    let mut ssl = Ssl::new(&server).unwrap();
    ssl.set_tls13_server_ciphers(&[0x1303]).unwrap();
    let client = handshake(only_aes128, ssl).0.done();
    assert_eq!(client.ssl().current_cipher().unwrap().protocol_id(), 0x1301);

    let mut ssl = Ssl::new(&server).unwrap();
    assert!(ssl.set_tls13_server_ciphers(&[0xc02f]).is_err());
    assert!(ssl.set_tls13_server_ciphers(&[0xcafe]).is_err());

    // A preference never overrides the server's compliance policy.
    let mut ssl = Ssl::new(&server).unwrap();
    ssl.set_compliance_policy(crate::ssl::CompliancePolicy::FIPS_202205)
        .unwrap();
    ssl.set_tls13_server_ciphers(&[0x1303]).unwrap();
    let mut offers_chacha = Ssl::new(&client_context().build()).unwrap();
    offers_chacha
        .set_raw_cipher_list(&[0x1303, 0x1301, 0x1302])
        .unwrap();
    let fips = handshake(offers_chacha, ssl).0.done();
    assert_ne!(fips.ssl().current_cipher().unwrap().protocol_id(), 0x1303);
}

/// "Compresses" by copying, under a configurable algorithm id.
struct Copy<const ID: u16>;

impl<const ID: u16> CertificateCompressor for Copy<ID> {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm(ID);
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        output.write_all(input)
    }
    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        output.write_all(input)
    }
}

const A: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm(0xff01);
const B: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm(0xff02);
const COMPRESS_CERTIFICATE: u16 = 27;

fn with_compressors(mut ctx: SslContextBuilder) -> SslContextBuilder {
    ctx.add_certificate_compression_algorithm(Copy::<0xff01>)
        .unwrap();
    ctx.add_certificate_compression_algorithm(Copy::<0xff02>)
        .unwrap();
    ctx
}

#[test]
fn certificate_compression_offer_is_per_connection() {
    let mut server = with_compressors(server_context());
    let hellos = capture(&mut server);
    let server = server.build();
    let client = with_compressors(client_context()).build();

    for algorithms in [&[B, A][..], &[A][..], &[][..]] {
        let mut ssl = Ssl::new(&client).unwrap();
        ssl.set_certificate_compression_algorithms(algorithms)
            .unwrap();
        handshake(ssl, Ssl::new(&server).unwrap()).0.done();
    }
    handshake(Ssl::new(&client).unwrap(), Ssl::new(&server).unwrap())
        .0
        .done();

    let offered = |hello: &Hello| {
        hello
            .extension(COMPRESS_CERTIFICATE)
            .map(|body| wire::u16_list(body, 1).expect("compression algorithms"))
    };
    let hellos = hellos.lock().unwrap();
    assert_eq!(offered(&hellos[0]), Some(vec![0xff02, 0xff01]));
    assert_eq!(offered(&hellos[1]), Some(vec![0xff01]));
    assert_eq!(
        offered(&hellos[2]),
        None,
        "an empty list disables compression"
    );
    assert_eq!(offered(&hellos[3]), Some(vec![0xff01, 0xff02]));

    let mut ssl = Ssl::new(&client).unwrap();
    let unregistered = CertificateCompressionAlgorithm::ZSTD;
    assert!(ssl
        .set_certificate_compression_algorithms(&[unregistered])
        .is_err());
    assert!(ssl.set_certificate_compression_algorithms(&[A, A]).is_err());
}

#[test]
fn certificate_compression_choice_is_per_connection_on_servers() {
    let server = with_compressors(server_context()).build();
    let client = with_compressors(client_context()).build();
    for (preference, expected) in [
        (Some(&[B][..]), Some(B)),
        (Some(&[B, A]), Some(B)),
        (Some(&[]), None),
        (None, Some(A)),
    ] {
        let mut ssl = Ssl::new(&server).unwrap();
        if let Some(preference) = preference {
            ssl.set_certificate_compression_algorithms(preference)
                .unwrap();
        }
        let client = handshake(Ssl::new(&client).unwrap(), ssl).0.done();
        assert_eq!(
            client.ssl().peer_certificate_compression_algorithm(),
            expected,
            "{preference:?}"
        );
    }
}

#[test]
fn status_requests_are_per_connection() {
    let mut server = server_context();
    let hellos = capture(&mut server);
    let server = server.build();
    let client = client_context().build();
    let mut ssl = Ssl::new(&client).unwrap();
    ssl.enable_ocsp_stapling();
    ssl.enable_signed_cert_timestamps();
    handshake(ssl, Ssl::new(&server).unwrap()).0.done();
    handshake(Ssl::new(&client).unwrap(), Ssl::new(&server).unwrap())
        .0
        .done();
    let hellos = hellos.lock().unwrap();
    let status = ExtensionType::STATUS_REQUEST.0;
    let sct = ExtensionType::CERTIFICATE_TIMESTAMP.0;
    assert!(hellos[0].extension(status).is_some());
    assert!(hellos[0].extension(sct).is_some());
    assert!(hellos[1].extension(status).is_none());
    assert!(hellos[1].extension(sct).is_none());
}

type Seen = Arc<Mutex<Vec<(bool, i32, Option<u8>, Vec<u8>)>>>;

fn observe(seen: &Seen) -> impl Fn(&SslRef, SslMessage<'_>) + Send + Sync + 'static {
    let seen = seen.clone();
    move |_, message| {
        seen.lock().unwrap().push((
            message.is_written(),
            message.content_type().as_raw(),
            message.handshake_type(),
            message.bytes().to_vec(),
        ));
    }
}

fn handshake_types(seen: &Seen, written: bool) -> Vec<u8> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(w, ..)| *w == written)
        .filter_map(|(_, _, handshake_type, _)| *handshake_type)
        .collect()
}

#[test]
fn message_callbacks_see_every_tls13_handshake_message() {
    let client_seen = Seen::default();
    let server_seen = Seen::default();
    let mut client = client_context();
    client.set_msg_callback(observe(&client_seen));
    let mut server = server_context();
    server.set_msg_callback(observe(&server_seen));
    let (client, server) = connect(client, server);
    client.done();
    server.done();

    // ClientHello, then ServerHello, EncryptedExtensions, Certificate,
    // CertificateVerify and Finished from the server, decrypted.
    assert_eq!(handshake_types(&client_seen, true), [1, 20]);
    assert_eq!(
        handshake_types(&client_seen, false)[..5],
        [2, 8, 11, 15, 20]
    );
    assert_eq!(handshake_types(&server_seen, false)[..2], [1, 20]);
    assert_eq!(handshake_types(&server_seen, true)[..5], [2, 8, 11, 15, 20]);

    let seen = client_seen.lock().unwrap();
    assert!(seen
        .iter()
        .any(|(_, content, ..)| *content == SslContentType::HEADER.as_raw()));
    // The ServerHello reveals the server's extension order (JA4S).
    let server_hello = &seen
        .iter()
        .find(|(written, _, ty, _)| !written && *ty == Some(2))
        .unwrap()
        .3;
    let mut ids = wire::ServerHello::parse(server_hello)
        .expect("a well-formed ServerHello")
        .ids();
    ids.sort_unstable();
    assert_eq!(ids, [43, 51], "supported_versions and key_share");
}

#[test]
fn connection_message_callback_replaces_the_context_one() {
    let context_seen = Seen::default();
    let connection_seen = Seen::default();
    let mut client = client_context();
    client.set_msg_callback(observe(&context_seen));
    let mut ssl = Ssl::new(&client.build()).unwrap();
    ssl.set_msg_callback(observe(&connection_seen));
    handshake(ssl, Ssl::new(&server_context().build()).unwrap())
        .0
        .done();
    assert!(context_seen.lock().unwrap().is_empty());
    assert!(!connection_seen.lock().unwrap().is_empty());
}

#[test]
fn max_send_fragment_splits_records() {
    let records = |fragment: Option<usize>| {
        let seen = Seen::default();
        let mut ssl = Ssl::new(&client_context().build()).unwrap();
        ssl.set_msg_callback(observe(&seen));
        if let Some(fragment) = fragment {
            ssl.set_max_send_fragment(fragment);
        }
        let (client, server) = handshake(ssl, Ssl::new(&server_context().build()).unwrap());
        let (mut client, mut server) = (client.done(), server.done());
        seen.lock().unwrap().clear();
        client.write_all(&[7; 2000]).unwrap();
        let mut buf = [0; 2000];
        server.read_exact(&mut buf).unwrap();
        let seen = seen.lock().unwrap();
        seen.iter()
            .filter(|(written, content, ..)| {
                *written && *content == SslContentType::HEADER.as_raw()
            })
            .count()
    };
    assert_eq!(records(None), 1);
    assert_eq!(records(Some(512)), 4);
    // The context-level setting applies to its connections.
    let seen = Seen::default();
    let mut ctx = client_context();
    ctx.set_max_send_fragment(512);
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_msg_callback(observe(&seen));
    let (client, server) = handshake(ssl, Ssl::new(&server_context().build()).unwrap());
    let (mut client, mut server) = (client.done(), server.done());
    seen.lock().unwrap().clear();
    client.write_all(&[7; 2000]).unwrap();
    server.read_exact(&mut [0; 2000]).unwrap();
    let written_headers = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(written, content, ..)| *written && *content == SslContentType::HEADER.as_raw())
        .count();
    assert_eq!(written_headers, 4);
    // Smaller values are clamped to 512.
    assert_eq!(records(Some(100)), 4);
}

fn exchange(client: &mut SslStream<End>, server: &mut SslStream<End>) {
    client.write_all(b"ping").unwrap();
    let mut buf = [0; 4];
    server.read_exact(&mut buf).unwrap();
    server.write_all(b"pong").unwrap();
    client.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"pong");
}

#[test]
fn message_metadata_and_constants() {
    assert_eq!(SslContentType::HANDSHAKE.as_raw(), 22);
    assert_eq!(SslContentType::ALERT.as_raw(), 21);
    assert_eq!(SslContentType::HEADER.as_raw(), 256);
    assert_eq!(crate::ssl::SslEarlyDataReason::ACCEPTED.as_raw(), 2);
    assert_eq!(crate::ssl::SslEarlyDataReason::UNKNOWN.as_raw(), 0);
    assert_eq!(
        format!("{:?}", crate::ssl::SslEarlyDataReason::ACCEPTED),
        "accepted"
    );

    let versions = Arc::new(Mutex::new(Vec::new()));
    let sink = versions.clone();
    let mut ssl = Ssl::new(&client_context().build()).unwrap();
    ssl.set_msg_callback(move |_, message| {
        sink.lock()
            .unwrap()
            .push((message.content_type(), message.version()));
    });
    handshake(ssl, Ssl::new(&server_context().build()).unwrap())
        .0
        .done();
    let versions = versions.lock().unwrap();
    // Record headers carry no version; messages carry the version in effect.
    assert!(versions
        .iter()
        .filter(|(content, _)| *content == SslContentType::HEADER)
        .all(|(_, version)| *version == 0));
    let last_message = versions
        .iter()
        .rev()
        .find(|(content, _)| *content == SslContentType::HANDSHAKE);
    assert_eq!(last_message.map(|(_, version)| *version), Some(0x0304));
}

#[test]
fn shed_configuration_is_released_after_the_handshake() {
    for shed in [false, true] {
        let mut client = Ssl::new(&client_context().build()).unwrap();
        client.set_shed_handshake_config(shed);
        let (client, server) = handshake(client, Ssl::new(&server_context().build()).unwrap());
        let (mut client, mut server) = (client.done(), server.done());
        exchange(&mut client, &mut server);
        // Settings that live in the handshake configuration are gone once shed.
        assert_eq!(client.ssl_mut().set_cipher_list("ALL").is_err(), shed);
        // Wire settings are fixed once the handshake completed, shed or not.
        assert!(client.ssl_mut().set_raw_cipher_list(&[0x1301]).is_err());
    }
}

#[test]
fn robustness_settings_keep_connections_working() {
    let mut client = Ssl::new(&client_context().build()).unwrap();
    client.set_shed_handshake_config(true);
    client.set_renegotiate_mode(SslRenegotiateMode::ONCE);
    let mut server = Ssl::new(&server_context().build()).unwrap();
    server.set_shed_handshake_config(true);
    server.set_jdk11_workaround(true);
    let (client, server) = handshake(client, server);
    let (mut client, mut server) = (client.done(), server.done());
    exchange(&mut client, &mut server);
    exchange(&mut client, &mut server);
}

#[test]
fn negotiated_state_getters() {
    let mut server = tls12(server_context());
    server.set_verify(SslVerifyMode::PEER);
    server.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()));
    let mut client = tls12(client_context());
    client.set_certificate_chain_file("test/cert.pem").unwrap();
    client
        .set_private_key_file("test/key.pem", crate::ssl::SslFiletype::PEM)
        .unwrap();
    // Nothing is negotiated before a handshake.
    let fresh = Ssl::new(&client_context().build()).unwrap();
    assert!(!fresh.extended_master_secret_support());
    assert!(!fresh.secure_renegotiation_support());
    let (client, server) = connect(client, server);
    let (client, server) = (client.done(), server.done());
    for ssl in [client.ssl(), server.ssl()] {
        assert!(ssl.extended_master_secret_support());
        assert!(ssl.secure_renegotiation_support());
        let chain = ssl.peer_full_cert_chain().expect("peer chain");
        assert_eq!(
            chain.get(0).unwrap().to_der().unwrap(),
            ssl.peer_certificate().unwrap().to_der().unwrap(),
            "the full chain starts with the leaf"
        );
    }

    let mut client = Ssl::new(&client_context().build()).unwrap();
    client
        .set_delegated_credential_schemes(&[SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256])
        .unwrap();
    let offered = Arc::new(Mutex::new(Vec::new()));
    let sink = offered.clone();
    let mut server = server_context();
    // Only meaningful while the server selects its certificate.
    server.set_certificate_callback(move |selection| {
        sink.lock()
            .unwrap()
            .extend_from_slice(selection.peer_delegation_algorithms());
        Ok(())
    });
    handshake(client, Ssl::new(&server.build()).unwrap())
        .1
        .done();
    assert_eq!(
        *offered.lock().unwrap(),
        [SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256]
    );
}

/// Extension IDs of a ServerHello or EncryptedExtensions as observed.
fn message_extension_ids(message: &[u8]) -> Vec<u16> {
    match message.first() {
        Some(2) => wire::ServerHello::parse(message).map(|hello| hello.ids()),
        Some(8) => wire::encrypted_extensions(message).map(|extensions| wire::ids(&extensions)),
        _ => None,
    }
    .unwrap_or_else(|| panic!("a well-formed ServerHello or EncryptedExtensions: {message:02x?}"))
}

/// The server's ServerHello and EncryptedExtensions extension orders, with the
/// order set from the server's early ClientHello callback, as a relay does.
fn server_orders(order: Option<Vec<u16>>, tls12: bool, alpn: bool) -> (Vec<u16>, Vec<u16>) {
    let seen = Seen::default();
    let mut client = if tls12 {
        self::tls12(client_context())
    } else {
        client_context()
    };
    if alpn {
        client.set_alpn_protos(b"\x02h2").unwrap();
    }
    let mut client = Ssl::new(&client.build()).unwrap();
    client.set_hostname("order.test").unwrap();
    client.set_msg_callback(observe(&seen));
    let mut server = server_context();
    server.set_alpn_select_callback(|_, protocols| {
        crate::ssl::select_next_proto(b"\x02h2", protocols).ok_or(crate::ssl::AlpnError::NOACK)
    });
    server.set_servername_callback(|_, _| Ok(()));
    server.set_select_certificate_callback(move |mut hello| {
        if let Some(order) = &order {
            hello.ssl_mut().set_server_extension_order(order).unwrap();
        }
        Ok(())
    });
    let (client, server) = handshake(client, Ssl::new(&server.build()).unwrap());
    client.done();
    server.done();
    let seen = seen.lock().unwrap();
    let ids = |handshake_type: u8| {
        seen.iter()
            .find(|(written, _, ty, _)| !written && *ty == Some(handshake_type))
            .map(|(.., bytes)| message_extension_ids(bytes))
            .unwrap_or_default()
    };
    (ids(2), ids(8))
}

const SERVER_NAME: u16 = 0;
const ALPN: u16 = 16;
const SUPPORTED_VERSIONS: u16 = 43;
const KEY_SHARE: u16 = 51;
const RENEGOTIATE: u16 = 0xff01;

#[test]
fn server_extension_order_applies_to_tls13_server_hello_and_encrypted_extensions() {
    let (hello, encrypted) = server_orders(None, false, true);
    assert_eq!(hello, [KEY_SHARE, SUPPORTED_VERSIONS], "native");
    assert_eq!(encrypted, [SERVER_NAME, ALPN], "native");

    let (hello, encrypted) = server_orders(
        Some(vec![SUPPORTED_VERSIONS, ALPN, KEY_SHARE, SERVER_NAME]),
        false,
        true,
    );
    assert_eq!(hello, [SUPPORTED_VERSIONS, KEY_SHARE]);
    assert_eq!(encrypted, [ALPN, SERVER_NAME]);

    // Unlisted extensions keep their native order after the listed ones.
    let (hello, encrypted) = server_orders(Some(vec![ALPN]), false, true);
    assert_eq!(hello, [KEY_SHARE, SUPPORTED_VERSIONS]);
    assert_eq!(encrypted, [ALPN, SERVER_NAME]);
}

#[test]
fn server_extension_order_applies_to_tls12_server_hello() {
    let (native, _) = server_orders(None, true, true);
    assert!(native.len() > 2, "{native:?}");
    let (ordered, _) = server_orders(Some(vec![ALPN, RENEGOTIATE]), true, true);
    assert_eq!(ordered[..2], [ALPN, RENEGOTIATE]);
    // Same set, only reordered.
    let (mut sorted_native, mut sorted_ordered) = (native.clone(), ordered.clone());
    sorted_native.sort_unstable();
    sorted_ordered.sort_unstable();
    assert_eq!(sorted_native, sorted_ordered);
    let rest: Vec<_> = native
        .iter()
        .copied()
        .filter(|id| ![ALPN, RENEGOTIATE].contains(id))
        .collect();
    assert_eq!(ordered[2..], rest[..], "the rest keeps native order");
}

#[test]
fn server_extension_order_never_answers_unoffered_extensions() {
    // The order lists ALPN, but this client offered none.
    let (_, encrypted) = server_orders(Some(vec![ALPN, SERVER_NAME]), false, false);
    assert_eq!(encrypted, [SERVER_NAME]);

    let (connected, _) = handshake(
        Ssl::new(&client_context().build()).unwrap(),
        Ssl::new(&server_context().build()).unwrap(),
    );
    let mut connected = connected.done();
    assert!(connected
        .ssl_mut()
        .set_server_extension_order(&[ALPN])
        .is_err());
    let mut ssl = Ssl::new(&server_context().build()).unwrap();
    assert!(ssl.set_server_extension_order(&[ALPN; 257]).is_err());
}

/// A real TLS 1.2 ClientHello with one extension removed, as a record.
fn client_hello_record_without(extension: u16) -> Vec<u8> {
    let hello = Arc::new(Mutex::new(Vec::new()));
    let sink = hello.clone();
    let mut client = Ssl::new(&tls12(client_context()).build()).unwrap();
    client.set_msg_callback(move |_, message| {
        if message.is_written() && message.handshake_type() == Some(1) {
            *sink.lock().unwrap() = message.bytes().to_vec();
        }
    });
    let (a, _b) = super::memory::ends();
    let _ = client.connect(a);
    let message = hello.lock().unwrap().clone();
    let mut hello = wire::ClientHello::parse(&message).expect("a well-formed ClientHello");
    assert!(
        hello.extension(extension).is_some(),
        "the client offers {extension}"
    );
    hello.extensions.retain(|(id, _)| *id != extension);
    let message = hello.encode();
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&message);
    record
}

#[test]
fn server_extension_order_never_answers_extensions_the_client_omitted() {
    // BoringSSL's TLS 1.2 ec_point_formats writer does not check the client
    // offered it: only the received-extension check keeps it out.
    const EC_POINT_FORMATS: u16 = 11;
    let record = client_hello_record_without(EC_POINT_FORMATS);
    for order in [None, Some(vec![EC_POINT_FORMATS, ALPN])] {
        let (client_end, server_end) = super::memory::ends();
        let mut ssl = Ssl::new(&tls12(server_context()).build()).unwrap();
        if let Some(order) = &order {
            ssl.set_server_extension_order(order).unwrap();
        }
        server_end.rx.lock().unwrap().extend(record.iter().copied());
        let _ = ssl.accept(server_end);
        let response: Vec<u8> = client_end.rx.lock().unwrap().iter().copied().collect();
        let server_hello = wire::first_record_message(&response)
            .unwrap_or_else(|| panic!("a handshake record answers: {order:?}"));
        let ids = message_extension_ids(server_hello);
        assert!(!ids.contains(&EC_POINT_FORMATS), "{order:?}: {ids:?}");
    }
}
