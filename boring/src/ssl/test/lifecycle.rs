//! Per-connection wire settings across a connection's lifecycle, checked on
//! the wire.

use super::credentials::credential;
use super::memory::{client_context, ends, handshake, server_context, End, Side};
use super::wire::{self, is_grease};
use crate::ffi;
use crate::hpke::HpkeKey;
use crate::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ClientHelloShape, ErrorCode,
    ExtensionType, GreaseLists, GreaseValues, Padding, SslContentType, SslContext,
    SslContextBuilder, SslCurve, SslEchKeys, SslMethod, SslRef, SslSession, SslSessionCacheMode,
    SslSignatureAlgorithm, SslStream, SslVersion, UnknownValues,
};
use crate::ssl::{SniError, Ssl, SslAlert};
use foreign_types::ForeignTypeRef;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

const SERVER_NAME: u16 = 0;
const STATUS_REQUEST: u16 = 5;
const SUPPORTED_GROUPS: u16 = 10;
const EC_POINT_FORMATS: u16 = 11;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const SIGNED_CERT_TIMESTAMP: u16 = 18;
const PADDING: u16 = 21;
const COMPRESS_CERTIFICATE: u16 = 27;
const PRE_SHARED_KEY: u16 = 41;
const SUPPORTED_VERSIONS: u16 = 43;
const KEY_SHARE: u16 = 51;
const RENEGOTIATE: u16 = 0xff01;
/// An extension BoringSSL does not implement.
const UNKNOWN_EXTENSION: u16 = 0xff42;

const X25519: u16 = 0x001d;
const P256: u16 = 0x0017;
const P384: u16 = 0x0018;
const X25519_MLKEM768: u16 = 0x11ec;
/// A real group BoringSSL does not implement.
const FFDHE2048: u16 = 0x0100;

const TLS12: SslVersion = SslVersion::TLS1_2;
const TLS13: SslVersion = SslVersion::TLS1_3;
const VERSIONS: [SslVersion; 2] = [TLS12, TLS13];

const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const NEW_SESSION_TICKET: u8 = 4;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const COMPRESSED_CERTIFICATE: u8 = 25;

/// A ClientHello as sent.
#[derive(Debug, Clone)]
struct Hello {
    len: usize,
    legacy_version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    fn parse(message: &[u8]) -> Self {
        let hello = wire::ClientHello::parse(message)
            .unwrap_or_else(|| panic!("a well-formed ClientHello: {message:02x?}"));
        Self {
            len: message.len(),
            legacy_version: hello.legacy_version,
            ciphers: hello.ciphers,
            extensions: hello
                .extensions
                .into_iter()
                .map(|(id, body)| (id, body.to_vec()))
                .collect(),
        }
    }

    fn ids(&self) -> Vec<u16> {
        self.extensions.iter().map(|(id, _)| *id).collect()
    }

    /// The extension IDs without padding, whose presence depends on length.
    fn unpadded_ids(&self) -> Vec<u16> {
        self.ids().into_iter().filter(|id| *id != PADDING).collect()
    }

    fn body(&self, id: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(ext, _)| *ext == id)
            .map(|(_, body)| body.as_slice())
    }

    fn list(&self, id: u16, prefix: usize) -> Option<Vec<u16>> {
        self.body(id).map(|body| {
            wire::u16_list(body, prefix).unwrap_or_else(|| panic!("malformed extension {id}"))
        })
    }

    fn groups(&self) -> Option<Vec<u16>> {
        self.list(SUPPORTED_GROUPS, 2)
    }

    fn versions(&self) -> Option<Vec<u16>> {
        self.list(SUPPORTED_VERSIONS, 1)
    }

    fn sigalgs(&self) -> Option<Vec<u16>> {
        self.list(SIGNATURE_ALGORITHMS, 2)
    }

    fn compression(&self) -> Option<Vec<u16>> {
        self.list(COMPRESS_CERTIFICATE, 1)
    }

    fn key_shares(&self) -> Option<Vec<u16>> {
        self.body(KEY_SHARE)
            .map(|body| wire::key_share_groups(body).expect("a well-formed key_share"))
    }

    /// Every GREASE value of every list sent, in order.
    fn grease(&self) -> Vec<u16> {
        [
            Some(self.ciphers.clone()),
            self.groups(),
            self.versions(),
            self.sigalgs(),
            self.key_shares(),
            Some(self.ids()),
        ]
        .into_iter()
        .flatten()
        .flatten()
        .filter(|value| is_grease(*value))
        .collect()
    }
}

/// Positions of GREASE values, with everything else exact.
fn shape(values: &[u16]) -> Vec<Option<u16>> {
    values
        .iter()
        .map(|value| (!is_grease(*value)).then_some(*value))
        .collect()
}

/// Whether `ids` starts with the extensions of `order` it contains, in order.
#[track_caller]
fn assert_ordered_prefix(ids: &[u16], order: &[u16], expected: &[u16]) {
    let listed: Vec<u16> = order
        .iter()
        .copied()
        .filter(|id| ids.contains(id))
        .collect();
    assert_eq!(listed, expected, "{ids:?}");
    assert_eq!(ids[..listed.len()], listed[..], "{ids:?}");
}

type Log = Arc<Mutex<Vec<(bool, SslContentType, Vec<u8>)>>>;

/// Records every message `ssl` sends and receives.
fn record(ssl: &mut SslRef) -> Log {
    let log = Log::default();
    let sink = log.clone();
    ssl.set_msg_callback(move |_, message| {
        sink.lock().unwrap().push((
            message.is_written(),
            message.content_type(),
            message.bytes().to_vec(),
        ));
    });
    log
}

fn messages(log: &Log, written: bool, content: SslContentType, kind: u8) -> Vec<Vec<u8>> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|(w, c, bytes)| *w == written && *c == content && bytes.first() == Some(&kind))
        .map(|(.., bytes)| bytes.clone())
        .collect()
}

fn client_hellos(log: &Log) -> Vec<Hello> {
    messages(log, true, SslContentType::HANDSHAKE, CLIENT_HELLO)
        .iter()
        .map(|message| Hello::parse(message))
        .collect()
}

/// A completed connection and what its client saw.
struct Connection {
    log: Log,
    client: SslStream<End>,
    server: SslStream<End>,
}

impl Connection {
    fn hellos(&self) -> Vec<Hello> {
        client_hellos(&self.log)
    }

    fn hello(&self) -> Hello {
        self.hellos().remove(0)
    }

    fn received(&self, kind: u8) -> Vec<Vec<u8>> {
        messages(&self.log, false, SslContentType::HANDSHAKE, kind)
    }

    /// Extension IDs of the last ServerHello (not a HelloRetryRequest) and of
    /// the EncryptedExtensions, if any.
    fn server_extensions(&self) -> (Vec<u16>, Vec<u16>) {
        let hello = self.received(SERVER_HELLO).pop().expect("a ServerHello");
        let hello = wire::ServerHello::parse(&hello).expect("a well-formed ServerHello");
        let encrypted = self
            .received(ENCRYPTED_EXTENSIONS)
            .first()
            .map(|message| {
                wire::ids(&wire::encrypted_extensions(message).expect("EncryptedExtensions"))
            })
            .unwrap_or_default();
        (hello.ids(), encrypted)
    }

    fn cipher(&self) -> u16 {
        self.client.ssl().current_cipher().unwrap().protocol_id()
    }

    fn tickets(&self) -> usize {
        self.received(NEW_SESSION_TICKET).len()
    }
}

fn exchange(client: &mut SslStream<End>, server: &mut SslStream<End>) {
    client.write_all(b"ping").unwrap();
    let mut buf = [0; 4];
    server.read_exact(&mut buf).unwrap();
    server.write_all(b"pong").unwrap();
    client.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"pong");
}

/// Completes a handshake, then exchanges application data so the client also
/// reads what follows the handshake, such as TLS 1.3 tickets.
#[track_caller]
fn connect(mut client: Ssl, server: Ssl) -> Connection {
    let log = record(&mut client);
    let (client, server) = handshake(client, server);
    let (mut client, mut server) = (client.done(), server.done());
    exchange(&mut client, &mut server);
    Connection {
        log,
        client,
        server,
    }
}

fn pin(ctx: &mut SslContextBuilder, version: SslVersion) {
    ctx.set_min_proto_version(Some(version)).unwrap();
    ctx.set_max_proto_version(Some(version)).unwrap();
}

fn client_with(version: SslVersion, configure: impl FnOnce(&mut SslContextBuilder)) -> Ssl {
    let mut ctx = client_context();
    pin(&mut ctx, version);
    configure(&mut ctx);
    Ssl::new(&ctx.build()).unwrap()
}

fn client(version: SslVersion) -> Ssl {
    client_with(version, |_| {})
}

fn server_with(version: SslVersion, configure: impl FnOnce(&mut SslContextBuilder)) -> Ssl {
    let mut ctx = server_context();
    pin(&mut ctx, version);
    configure(&mut ctx);
    Ssl::new(&ctx.build()).unwrap()
}

fn server(version: SslVersion) -> Ssl {
    server_with(version, |_| {})
}

/// "Compresses" by copying, under a configurable algorithm ID.
struct Copying<const ID: u16>;

impl<const ID: u16> CertificateCompressor for Copying<ID> {
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
const C: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm(0xff03);

fn register_a(ctx: &mut SslContextBuilder) {
    ctx.add_certificate_compression_algorithm(Copying::<0xff01>)
        .unwrap();
}

fn register_b(ctx: &mut SslContextBuilder) {
    ctx.add_certificate_compression_algorithm(Copying::<0xff02>)
        .unwrap();
}

fn register_all(ctx: &mut SslContextBuilder) {
    register_a(ctx);
    register_b(ctx);
    ctx.add_certificate_compression_algorithm(Copying::<0xff03>)
        .unwrap();
}

/// The algorithm of the CompressedCertificate the client received, if any.
fn compressed_with(connection: &Connection) -> Option<u16> {
    connection
        .received(COMPRESSED_CERTIFICATE)
        .first()
        .map(|message| {
            wire::compressed_certificate(message)
                .expect("a well-formed CompressedCertificate")
                .0
        })
}

// Client setters, TLS 1.2 and TLS 1.3.

#[test]
fn raw_cipher_lists_are_exact_in_both_versions() {
    const LISTED: [u16; 5] = [0xcafe, 0x1302, 0xc030, 0x1301, 0xc02f];
    for version in VERSIONS {
        let mut ssl = client(version);
        ssl.set_raw_cipher_list(&LISTED).unwrap();
        let done = connect(ssl, server(version));
        // Unknown ciphers and those of the other version are sent as listed.
        assert_eq!(done.hello().ciphers, LISTED, "{version:?}");
        // The first listed cipher of the negotiated version is selected.
        let expected = if version == TLS12 { 0xc030 } else { 0x1302 };
        assert_eq!(done.cipher(), expected, "{version:?}");
        let server_hello = done.received(SERVER_HELLO).pop().unwrap();
        assert_eq!(
            wire::ServerHello::parse(&server_hello).unwrap().cipher,
            expected
        );
    }
}

#[test]
fn raw_supported_groups_in_both_versions() {
    for version in VERSIONS {
        let mut ssl = client(version);
        ssl.set_raw_supported_groups(&[0x0a0a, P384, FFDHE2048, X25519_MLKEM768, P256])
            .unwrap();
        let done = connect(ssl, server(version));
        let groups = done.hello().groups().expect("supported_groups");
        // The unknown group is dropped. A TLS 1.2 ClientHello cannot negotiate
        // a post-quantum group, so it leaves that out too.
        let expected: &[Option<u16>] = if version == TLS12 {
            &[None, Some(P384), Some(P256)]
        } else {
            &[None, Some(P384), Some(X25519_MLKEM768), Some(P256)]
        };
        assert_eq!(shape(&groups), expected, "{version:?}");
        let group = done.client.ssl().group_id().expect("a negotiated group");
        let negotiable: &[u16] = if version == TLS12 {
            &[P384, P256]
        } else {
            &[P384, X25519_MLKEM768, P256]
        };
        assert!(negotiable.contains(&group), "{version:?}: {group:#x}");
        assert_eq!(done.server.ssl().group_id(), Some(group));
    }
}

#[test]
fn raw_key_shares_only_apply_to_tls13() {
    for version in VERSIONS {
        let mut ssl = client(version);
        ssl.set_raw_supported_groups(&[X25519, P256]).unwrap();
        ssl.set_raw_key_shares(&[P256, X25519]).unwrap();
        let done = connect(ssl, server(version));
        let hello = done.hello();
        let group = done.client.ssl().group_id().expect("a negotiated group");
        assert!([X25519, P256].contains(&group), "{version:?}: {group:#x}");
        if version == TLS12 {
            assert_eq!(hello.key_shares(), None, "TLS 1.2 has no key shares");
        } else {
            assert_eq!(hello.key_shares(), Some(vec![P256, X25519]));
            assert!(!done.client.ssl().used_hello_retry_request());
        }
    }
}

#[test]
fn raw_supported_versions_in_both_versions() {
    for version in VERSIONS {
        let mut ssl = client(version);
        ssl.set_raw_supported_versions(&[0x0a0a, 0x0304, 0x0303])
            .unwrap();
        let done = connect(ssl, server(version));
        let hello = done.hello();
        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(done.client.ssl().version(), Some(version));
        if version == TLS12 {
            // A client that cannot negotiate TLS 1.3 sends no supported_versions.
            assert_eq!(hello.versions(), None);
        } else {
            // TLS 1.2 is outside this client's range: dropped.
            assert_eq!(shape(&hello.versions().unwrap()), [None, Some(0x0304)]);
        }
    }
}

#[test]
fn raw_signature_algorithms_in_both_versions() {
    const PKCS1_SHA256: u16 = 0x0401;
    const PSS_SHA256: u16 = 0x0804;
    for version in VERSIONS {
        let mut ssl = client(version);
        ssl.set_raw_signature_algorithms(&[0x0a0a, PKCS1_SHA256, PSS_SHA256, 0x0403])
            .unwrap();
        let done = connect(ssl, server(version));
        assert_eq!(
            shape(&done.hello().sigalgs().unwrap()),
            [None, Some(PKCS1_SHA256), Some(PSS_SHA256), Some(0x0403)],
            "{version:?}"
        );
        let used = done.client.ssl().peer_signature_algorithm().unwrap();
        if version == TLS12 {
            assert!(
                [PKCS1_SHA256, PSS_SHA256]
                    .map(SslSignatureAlgorithm::from)
                    .contains(&used),
                "{used:?}"
            );
        } else {
            // TLS 1.3 forbids PKCS#1 signatures in CertificateVerify.
            assert_eq!(used, SslSignatureAlgorithm::from(PSS_SHA256));
        }
    }
}

#[test]
fn extension_orders_skip_extensions_a_version_does_not_send() {
    const ORDER: [u16; 5] = [
        KEY_SHARE,
        SUPPORTED_VERSIONS,
        SIGNATURE_ALGORITHMS,
        SUPPORTED_GROUPS,
        EC_POINT_FORMATS,
    ];
    for version in VERSIONS {
        // Context GREASE and permutation do not apply to a set order.
        let mut ssl = client_with(version, |ctx| {
            ctx.set_grease_enabled(true);
            ctx.set_permute_extensions(true);
        });
        ssl.set_extension_order(&ORDER).unwrap();
        let done = connect(ssl, server(version));
        let ids = done.hello().unpadded_ids();
        // TLS 1.2 sends no key_share or supported_versions; a TLS 1.3-only
        // client sends no ec_point_formats.
        let expected: &[u16] = if version == TLS12 {
            &[SIGNATURE_ALGORITHMS, SUPPORTED_GROUPS, EC_POINT_FORMATS]
        } else {
            &[
                KEY_SHARE,
                SUPPORTED_VERSIONS,
                SIGNATURE_ALGORITHMS,
                SUPPORTED_GROUPS,
            ]
        };
        assert_ordered_prefix(&ids, &ORDER, expected);
        assert!(!ids.iter().any(|id| is_grease(*id)), "{ids:x?}");
        // The rest follows in canonical order.
        let canonical = connect(client(version), server(version))
            .hello()
            .unpadded_ids();
        let rest: Vec<u16> = canonical
            .into_iter()
            .filter(|id| !ORDER.contains(id))
            .collect();
        assert_eq!(ids[expected.len()..], rest[..], "{version:?}");
    }
}

#[test]
fn grease_lists_only_apply_to_lists_a_version_sends() {
    for version in VERSIONS {
        let mut ssl = client(version);
        ssl.set_client_hello_shape(&ClientHelloShape::new().with_grease_lists(GreaseLists::all()))
            .unwrap();
        let done = connect(ssl, server(version));
        let hello = done.hello();
        assert!(is_grease(hello.ciphers[0]));
        assert!(is_grease(hello.groups().unwrap()[0]));
        assert!(is_grease(hello.sigalgs().unwrap()[0]));
        let ids = hello.unpadded_ids();
        assert!(
            is_grease(ids[0]) && is_grease(*ids.last().unwrap()),
            "{ids:x?}"
        );
        if version == TLS12 {
            assert_eq!(hello.key_shares(), None);
            assert_eq!(hello.versions(), None);
            assert_eq!(hello.grease().len(), 5);
        } else {
            assert!(is_grease(hello.key_shares().unwrap()[0]));
            assert!(is_grease(hello.versions().unwrap()[0]));
            assert_eq!(hello.grease().len(), 7);
        }

        // No list replaces the context's GREASE everywhere.
        let mut ssl = client_with(version, |ctx| {
            ctx.set_grease_enabled(true);
            ctx.set_grease_sigalgs_enabled(true);
        });
        ssl.set_client_hello_shape(
            &ClientHelloShape::new().with_grease_lists(GreaseLists::empty()),
        )
        .unwrap();
        let done = connect(ssl, server(version));
        assert_eq!(done.hello().grease(), [], "{version:?}");
    }
}

/// A client with a GREASE slot in every list.
fn slotted(version: SslVersion, values: GreaseValues) -> Ssl {
    let mut ssl = client(version);
    ssl.set_raw_cipher_list(&[0x1a1a, 0x1301, 0xc02f]).unwrap();
    ssl.set_raw_supported_groups(&[0x2a2a, X25519, P256])
        .unwrap();
    ssl.set_raw_key_shares(&[0x2a2a, X25519]).unwrap();
    ssl.set_raw_supported_versions(&[0x3a3a, 0x0304, 0x0303])
        .unwrap();
    ssl.set_raw_signature_algorithms(&[0x4a4a, 0x0804, 0x0401])
        .unwrap();
    ssl.set_extension_order(&[0x5a5a, SUPPORTED_GROUPS, 0x6a6a])
        .unwrap();
    ssl.set_client_hello_shape(&ClientHelloShape::new().with_grease_values(values))
        .unwrap();
    ssl
}

#[test]
fn pinned_grease_values_in_both_versions() {
    for version in VERSIONS {
        let done = connect(slotted(version, GreaseValues::Pinned), server(version));
        let hello = done.hello();
        assert_eq!(hello.ciphers, [0x1a1a, 0x1301, 0xc02f]);
        assert_eq!(hello.groups().unwrap(), [0x2a2a, X25519, P256]);
        assert_eq!(hello.sigalgs().unwrap(), [0x4a4a, 0x0804, 0x0401]);
        assert_eq!(hello.ids()[..3], [0x5a5a, SUPPORTED_GROUPS, 0x6a6a]);
        assert_eq!(hello.body(0x5a5a), Some(&[][..]));
        assert_eq!(hello.body(0x6a6a), Some(&[0][..]));
        if version == TLS12 {
            assert_eq!(hello.key_shares(), None);
            assert_eq!(hello.versions(), None);
        } else {
            assert_eq!(hello.key_shares().unwrap(), [0x2a2a, X25519]);
            assert_eq!(hello.versions().unwrap(), [0x3a3a, 0x0304]);
        }
    }
}

#[test]
fn seeded_grease_values_in_both_versions() {
    for version in VERSIONS {
        let grease = |seed| {
            connect(
                slotted(version, GreaseValues::Seeded(seed)),
                server(version),
            )
            .hello()
            .grease()
        };
        let expected_slots = if version == TLS12 { 5 } else { 7 };
        let first = grease(0);
        assert_eq!(first.len(), expected_slots, "{version:?}");
        assert_eq!(grease(0), first, "{version:?}: reproducible");
        assert!(
            (1..8).any(|seed| grease(seed) != first),
            "{version:?}: the seed matters"
        );
    }
}

/// A client listing values it cannot negotiate in every list.
fn with_unknown_values(version: SslVersion, policy: UnknownValues) -> Ssl {
    let mut ssl = client(version);
    ssl.set_raw_supported_groups(&[X25519, FFDHE2048, P256])
        .unwrap();
    // Ed448 is a real algorithm BoringSSL does not implement.
    ssl.set_raw_signature_algorithms(&[0x0804, 0x0808, 0x0403])
        .unwrap();
    ssl.set_raw_supported_versions(&[0x0304, 0x0302, 0x0303])
        .unwrap();
    ssl.set_extension_order(&[SUPPORTED_GROUPS, UNKNOWN_EXTENSION, SIGNATURE_ALGORITHMS])
        .unwrap();
    ssl.set_client_hello_shape(
        &ClientHelloShape::new()
            .with_unknown_values(policy)
            .with_extension_body(ExtensionType::from(UNKNOWN_EXTENSION), [1, 2]),
    )
    .unwrap();
    ssl
}

#[test]
fn unknown_value_policies_in_both_versions() {
    for version in VERSIONS {
        let done = connect(
            with_unknown_values(version, UnknownValues::Preserve),
            server(version),
        );
        let hello = done.hello();
        assert_eq!(hello.groups().unwrap(), [X25519, FFDHE2048, P256]);
        assert_eq!(hello.sigalgs().unwrap(), [0x0804, 0x0808, 0x0403]);
        assert_eq!(
            hello.ids()[..3],
            [SUPPORTED_GROUPS, UNKNOWN_EXTENSION, SIGNATURE_ALGORITHMS]
        );
        assert_eq!(hello.body(UNKNOWN_EXTENSION), Some(&[1, 2][..]));
        if version == TLS12 {
            assert_eq!(hello.versions(), None);
        } else {
            // Versions outside the configured range are kept as listed.
            assert_eq!(hello.versions().unwrap(), [0x0304, 0x0302, 0x0303]);
        }

        let done = connect(
            with_unknown_values(version, UnknownValues::Drop),
            server(version),
        );
        let hello = done.hello();
        assert_eq!(hello.groups().unwrap(), [X25519, P256]);
        assert_eq!(hello.sigalgs().unwrap(), [0x0804, 0x0403]);
        assert_eq!(hello.ids()[..2], [SUPPORTED_GROUPS, SIGNATURE_ALGORITHMS]);
        assert_eq!(hello.body(UNKNOWN_EXTENSION), None);
        if version == TLS13 {
            assert_eq!(hello.versions().unwrap(), [0x0304]);
        }

        let mut ssl = with_unknown_values(version, UnknownValues::Forbid);
        let log = record(&mut ssl);
        let (client, _) = handshake(ssl, server(version));
        client.panicked_or_failed_with("cannot be negotiated");
        assert!(client_hellos(&log).is_empty(), "nothing is sent");
    }
}

#[test]
fn padding_in_both_versions() {
    for version in VERSIONS {
        let padded = |padding| {
            let mut ssl = client(version);
            ssl.set_raw_key_shares(&[X25519]).unwrap();
            ssl.set_client_hello_shape(&ClientHelloShape::new().with_padding(padding))
                .unwrap();
            connect(ssl, server(version)).hello()
        };
        let hello = padded(Padding::ToLength(700));
        assert_eq!(hello.len, 700, "{version:?}");
        assert_eq!(hello.ids().last(), Some(&PADDING));
        let hello = padded(Padding::Off);
        assert_eq!(hello.body(PADDING), None, "{version:?}");
    }
}

#[test]
fn extension_bodies_in_both_versions() {
    for version in VERSIONS {
        let mut ssl = client(version);
        ssl.set_extension_order(&[0x0a0a, SUPPORTED_GROUPS, 0x1a1a, UNKNOWN_EXTENSION])
            .unwrap();
        ssl.set_client_hello_shape(
            &ClientHelloShape::new()
                .with_grease_values(GreaseValues::Pinned)
                .with_unknown_values(UnknownValues::Preserve)
                .with_extension_body(ExtensionType::from(0x0a0a), [7])
                // An explicit empty body replaces the second slot's default.
                .with_extension_body(ExtensionType::from(0x1a1a), [])
                .with_extension_body(ExtensionType::from(UNKNOWN_EXTENSION), [1, 2, 3]),
        )
        .unwrap();
        let done = connect(ssl, server(version));
        let hello = done.hello();
        assert_eq!(
            hello.ids()[..4],
            [0x0a0a, SUPPORTED_GROUPS, 0x1a1a, UNKNOWN_EXTENSION],
            "{version:?}"
        );
        assert_eq!(hello.body(0x0a0a), Some(&[7][..]));
        assert_eq!(hello.body(0x1a1a), Some(&[][..]));
        assert_eq!(hello.body(UNKNOWN_EXTENSION), Some(&[1, 2, 3][..]));
    }
}

#[test]
fn certificate_compression_offers_in_both_versions() {
    for version in VERSIONS {
        let negotiate = |algorithms: &[CertificateCompressionAlgorithm]| {
            let mut ssl = client_with(version, register_all);
            ssl.set_certificate_compression_algorithms(algorithms)
                .unwrap();
            connect(ssl, server_with(version, register_all))
        };
        let done = negotiate(&[C, A]);
        // Offered as listed in either version; only TLS 1.3 compresses.
        assert_eq!(done.hello().compression(), Some(vec![C.0, A.0]));
        if version == TLS12 {
            assert_eq!(
                done.client.ssl().peer_certificate_compression_algorithm(),
                None
            );
            assert_eq!(compressed_with(&done), None);
            assert_eq!(done.received(CERTIFICATE).len(), 1);
        } else {
            // The server prefers its own registration order among the offer.
            assert_eq!(
                done.client.ssl().peer_certificate_compression_algorithm(),
                Some(A)
            );
            assert_eq!(compressed_with(&done), Some(A.0));
        }
        let done = negotiate(&[]);
        assert_eq!(done.hello().compression(), None, "{version:?}");
        assert_eq!(compressed_with(&done), None);
    }
}

fn stapling_server(version: SslVersion) -> Ssl {
    let mut stapled = credential(&[], false);
    stapled.set_ocsp_response(b"ocsp response").unwrap();
    stapled
        .set_signed_cert_timestamp_list(&[0, 3, 0, 1, 42])
        .unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    pin(&mut ctx, version);
    ctx.add_credential(&stapled.build()).unwrap();
    Ssl::new(&ctx.build()).unwrap()
}

#[test]
fn status_requests_in_both_versions() {
    for version in VERSIONS {
        let mut ssl = client(version);
        ssl.enable_ocsp_stapling();
        let done = connect(ssl, stapling_server(version));
        assert!(done.hello().body(STATUS_REQUEST).is_some(), "{version:?}");
        assert_eq!(done.hello().body(SIGNED_CERT_TIMESTAMP), None);
        assert_eq!(done.client.ssl().ocsp_status(), Some(&b"ocsp response"[..]));
        assert_eq!(done.client.ssl().signed_cert_timestamp_list(), None);

        let mut ssl = client(version);
        ssl.enable_signed_cert_timestamps();
        let done = connect(ssl, stapling_server(version));
        assert_eq!(done.hello().body(SIGNED_CERT_TIMESTAMP), Some(&[][..]));
        assert_eq!(done.hello().body(STATUS_REQUEST), None);
        assert_eq!(
            done.client.ssl().signed_cert_timestamp_list(),
            Some(&[0, 3, 0, 1, 42][..])
        );
        assert_eq!(done.client.ssl().ocsp_status(), None);

        let done = connect(client(version), stapling_server(version));
        assert_eq!(done.hello().body(STATUS_REQUEST), None);
        assert_eq!(done.client.ssl().ocsp_status(), None);
    }
}

// Server setters, TLS 1.2 and TLS 1.3.

#[test]
fn strict_cipher_lists_pin_tls12_only() {
    for (pinned, id) in [
        ("ECDHE-RSA-AES128-GCM-SHA256", 0xc02f),
        ("ECDHE-RSA-AES256-GCM-SHA384", 0xc030),
    ] {
        for version in VERSIONS {
            let mut ssl = server(version);
            ssl.set_strict_cipher_list(pinned).unwrap();
            let done = connect(client(version), ssl);
            if version == TLS12 {
                assert_eq!(done.cipher(), id);
            } else {
                // TLS 1.3 ciphers are not configured by cipher strings.
                assert!(
                    (0x1301..=0x1303).contains(&done.cipher()),
                    "{:#x}",
                    done.cipher()
                );
            }
        }
    }
}

#[test]
fn tls13_server_ciphers_leave_tls12_alone() {
    for strict in [false, true] {
        for version in VERSIONS {
            let mut ssl = server(version);
            if strict {
                ssl.set_strict_tls13_server_ciphers(&[0x1302]).unwrap();
            } else {
                ssl.set_tls13_server_ciphers(&[0x1303, 0x1302]).unwrap();
            }
            let mut offer = client(version);
            offer
                .set_raw_cipher_list(&[0x1301, 0x1302, 0x1303, 0xc02f])
                .unwrap();
            let done = connect(offer, ssl);
            let expected = match (version == TLS12, strict) {
                (true, _) => 0xc02f,
                (false, true) => 0x1302,
                (false, false) => 0x1303,
            };
            assert_eq!(done.cipher(), expected, "{version:?} strict={strict}");
        }
    }
    // Strict, TLS 1.3 fails without a match; TLS 1.2 is unaffected.
    for version in VERSIONS {
        let mut ssl = server(version);
        ssl.set_strict_tls13_server_ciphers(&[0x1302]).unwrap();
        let mut offer = client(version);
        offer.set_raw_cipher_list(&[0x1301, 0xc02f]).unwrap();
        let (client_side, server_side) = handshake(offer, ssl);
        if version == TLS12 {
            client_side.done();
        } else {
            server_side.panicked_or_failed_with("NO_SHARED_CIPHER");
        }
    }
}

#[test]
fn server_extension_orders_in_both_versions() {
    const ORDER: [u16; 5] = [
        ALPN,
        SERVER_NAME,
        SUPPORTED_VERSIONS,
        KEY_SHARE,
        RENEGOTIATE,
    ];
    for version in VERSIONS {
        let mut ssl = client_with(version, |ctx| ctx.set_alpn_protos(b"\x02h2").unwrap());
        ssl.set_hostname("order.test").unwrap();
        let mut origin = server_with(version, |ctx| {
            ctx.set_alpn_select_callback(|_, protocols| {
                crate::ssl::select_next_proto(b"\x02h2", protocols)
                    .ok_or(crate::ssl::AlpnError::NOACK)
            });
            ctx.set_servername_callback(|_: &mut SslRef, _: &mut SslAlert| Ok::<(), SniError>(()));
        });
        origin.set_server_extension_order(&ORDER).unwrap();
        let done = connect(ssl, origin);
        let (hello, encrypted) = done.server_extensions();
        if version == TLS12 {
            assert_ordered_prefix(&hello, &ORDER, &[ALPN, SERVER_NAME, RENEGOTIATE]);
            assert!(encrypted.is_empty());
        } else {
            assert_eq!(hello, [SUPPORTED_VERSIONS, KEY_SHARE]);
            assert_eq!(encrypted, [ALPN, SERVER_NAME]);
        }
    }
}

#[test]
fn ticket_counts_only_apply_to_tls13() {
    for (count, tls13) in [(None, 2), (Some(0), 0), (Some(3), 3)] {
        for version in VERSIONS {
            let mut ssl = server_with(version, |ctx| ctx.set_num_tickets(2));
            if let Some(count) = count {
                ssl.set_num_tickets(count).unwrap();
            }
            let done = connect(client(version), ssl);
            // TLS 1.2 issues its one ticket within the handshake, whatever the count.
            let expected = if version == TLS12 { 1 } else { tls13 };
            assert_eq!(done.tickets(), expected, "{version:?} {count:?}");
        }
    }
}

#[test]
fn server_certificate_compression_choice_in_both_versions() {
    for version in VERSIONS {
        let mut ssl = server_with(version, register_all);
        ssl.set_certificate_compression_algorithms(&[C, B]).unwrap();
        let done = connect(client_with(version, register_all), ssl);
        assert_eq!(done.hello().compression(), Some(vec![A.0, B.0, C.0]));
        if version == TLS12 {
            assert_eq!(
                done.client.ssl().peer_certificate_compression_algorithm(),
                None
            );
            assert_eq!(done.received(CERTIFICATE).len(), 1);
        } else {
            assert_eq!(
                done.client.ssl().peer_certificate_compression_algorithm(),
                Some(C)
            );
            assert_eq!(compressed_with(&done), Some(C.0));
        }
    }
}

// ECH, HelloRetryRequest and resumption.

static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../../test/echconfiglist");
static ECH_CONFIG: &[u8] = include_bytes!("../../../test/echconfig");
static ECH_KEY: &[u8] = include_bytes!("../../../test/echkey");

#[test]
fn a_shaped_client_hello_with_ech_survives_a_hello_retry() {
    let mut keys = SslEchKeys::builder().unwrap();
    keys.add_key(
        true,
        ECH_CONFIG,
        HpkeKey::dhkem_p256_sha256(ECH_KEY).unwrap(),
    )
    .unwrap();
    let server = server_context();
    server.set_ech_keys(&keys.build()).unwrap();
    let mut server = server;
    // The client's only key share is X25519: the server asks for P-256.
    server.set_curves_list("P-256").unwrap();
    let mut ssl = Ssl::new(&client_context().build()).unwrap();
    ssl.set_ech_config_list(ECH_CONFIG_LIST).unwrap();
    ssl.set_hostname("foobar.com").unwrap();
    const KNOWN: [u16; 4] = [
        SUPPORTED_VERSIONS,
        KEY_SHARE,
        SUPPORTED_GROUPS,
        SIGNATURE_ALGORITHMS,
    ];
    ssl.set_extension_order(&[
        0x3a3a,
        KNOWN[0],
        KNOWN[1],
        KNOWN[2],
        KNOWN[3],
        0x4a4a,
        UNKNOWN_EXTENSION,
    ])
    .unwrap();
    ssl.set_raw_supported_groups(&[0x5a5a, X25519, P256])
        .unwrap();
    ssl.set_raw_key_shares(&[X25519]).unwrap();
    ssl.set_raw_cipher_list(&[0x6a6a, 0x1301, 0x1302]).unwrap();
    ssl.set_client_hello_shape(
        &ClientHelloShape::new()
            .with_grease_values(GreaseValues::Pinned)
            .with_grease_lists(GreaseLists::all())
            .with_unknown_values(UnknownValues::Preserve)
            .with_extension_body(ExtensionType::from(UNKNOWN_EXTENSION), [1]),
    )
    .unwrap();
    let mut log_ssl = ssl;
    let log = record(&mut log_ssl);
    let (client, server) = handshake(log_ssl, Ssl::new(&server.build()).unwrap());
    let (client, server) = (client.done(), server.done());
    assert!(client.ssl().ech_accepted());
    assert!(server.ssl().ech_accepted());
    assert!(client.ssl().used_hello_retry_request());
    assert_eq!(client.ssl().group_id(), Some(P256));

    let outer = client_hellos(&log);
    let inner: Vec<Hello> = messages(&log, true, SslContentType::CLIENT_HELLO_INNER, 1)
        .iter()
        .map(|message| Hello::parse(message))
        .collect();
    assert_eq!(
        outer.len(),
        2,
        "a ClientHelloOuter before and after the retry"
    );
    assert_eq!(
        inner.len(),
        2,
        "a ClientHelloInner before and after the retry"
    );
    for (n, hello) in outer.iter().enumerate() {
        let ids = hello.unpadded_ids();
        // The known extensions keep their order; the order's GREASE slots and
        // preserved extension do not apply, only native GREASE, first and last.
        assert!(is_grease(ids[0]), "outer {n}: {ids:x?}");
        assert_eq!(ids[1..5], KNOWN, "outer {n}: {ids:x?}");
        assert!(is_grease(*ids.last().unwrap()), "outer {n}: {ids:x?}");
        assert_eq!(ids.iter().filter(|id| is_grease(**id)).count(), 2);
        assert!(!ids.contains(&UNKNOWN_EXTENSION), "outer {n}");
    }
    for (n, hello) in inner.iter().enumerate() {
        let ids = hello.ids();
        let known: Vec<u16> = ids
            .iter()
            .copied()
            .filter(|id| KNOWN.contains(id))
            .collect();
        assert_eq!(known, KNOWN, "inner {n}: {ids:x?}");
        assert_eq!(ids.iter().filter(|id| is_grease(**id)).count(), 2);
        assert!(!ids.contains(&UNKNOWN_EXTENSION), "inner {n}");
    }
    // Raw lists are not part of the extension order: their pinned slots apply.
    for hello in outer.iter().chain(&inner) {
        assert_eq!(hello.ciphers, [0x6a6a, 0x1301, 0x1302]);
        assert_eq!(hello.groups().unwrap(), [0x5a5a, X25519, P256]);
    }
    assert_eq!(outer[0].key_shares().unwrap(), [X25519]);
    assert_eq!(inner[0].key_shares().unwrap(), [X25519]);
    assert_eq!(outer[1].key_shares().unwrap(), [P256]);
    assert_eq!(inner[1].key_shares().unwrap(), [P256]);
}

const PADDED_TO: u16 = 1200;

/// A client context that keeps the TLS 1.3 tickets it receives.
fn resuming_client() -> (SslContext, Arc<Mutex<Option<SslSession>>>) {
    let ticket = Arc::new(Mutex::new(None));
    let sink = ticket.clone();
    let mut ctx = client_context();
    ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    ctx.set_new_session_callback(move |_, session| {
        *sink.lock().unwrap() = Some(session);
    });
    (ctx.build(), ticket)
}

fn padded(ctx: &SslContext) -> Ssl {
    let mut ssl = Ssl::new(ctx).unwrap();
    ssl.set_raw_supported_groups(&[X25519, P384]).unwrap();
    ssl.set_raw_key_shares(&[X25519]).unwrap();
    // Padding and pre_shared_key keep their native positions, whatever the order.
    ssl.set_extension_order(&[
        SUPPORTED_VERSIONS,
        PRE_SHARED_KEY,
        KEY_SHARE,
        PADDING,
        SUPPORTED_GROUPS,
    ])
    .unwrap();
    ssl.set_client_hello_shape(&ClientHelloShape::new().with_padding(Padding::ToLength(PADDED_TO)))
        .unwrap();
    ssl
}

/// Connects once to obtain a ticket, then resumes with it.
fn resume(server: &SslContext) -> (Connection, Connection) {
    let (client, ticket) = resuming_client();
    let first = connect(padded(&client), Ssl::new(server).unwrap());
    assert!(!first.client.ssl().session_reused());
    let ticket = ticket.lock().unwrap().take().expect("a TLS 1.3 ticket");
    let mut ssl = padded(&client);
    // The ticket was issued to this client context by this server.
    unsafe { ssl.set_session(&ticket).unwrap() };
    let second = connect(ssl, Ssl::new(server).unwrap());
    (first, second)
}

#[test]
fn resumption_keeps_the_shape_and_pads_before_the_psk() {
    let mut server = server_context();
    pin(&mut server, TLS13);
    let (first, second) = resume(&server.build());
    let hello = first.hello();
    assert_eq!(hello.len, usize::from(PADDED_TO));
    assert_eq!(hello.ids().last(), Some(&PADDING));
    assert_eq!(hello.body(PRE_SHARED_KEY), None);

    assert!(second.client.ssl().session_reused());
    assert!(second.server.ssl().session_reused());
    let hellos = second.hellos();
    assert_eq!(hellos.len(), 1);
    let ids = hellos[0].ids();
    assert_eq!(ids[..3], [SUPPORTED_VERSIONS, KEY_SHARE, SUPPORTED_GROUPS]);
    assert_eq!(ids[ids.len() - 2..], [PADDING, PRE_SHARED_KEY], "{ids:?}");
    assert_eq!(hellos[0].len, usize::from(PADDED_TO));
}

#[test]
fn resumption_after_a_hello_retry_pads_only_the_first_client_hello() {
    let mut server = server_context();
    pin(&mut server, TLS13);
    // The client's key share is X25519: every handshake needs a retry.
    server.set_curves_list("P-384").unwrap();
    let (first, second) = resume(&server.build());
    assert!(first.client.ssl().used_hello_retry_request());

    assert!(second.client.ssl().session_reused());
    assert!(second.client.ssl().used_hello_retry_request());
    let hellos = second.hellos();
    assert_eq!(hellos.len(), 2);
    let ids = hellos[0].ids();
    assert_eq!(ids[ids.len() - 2..], [PADDING, PRE_SHARED_KEY], "{ids:?}");
    assert_eq!(hellos[0].len, usize::from(PADDED_TO));
    let ids = hellos[1].ids();
    assert_eq!(ids.last(), Some(&PRE_SHARED_KEY), "{ids:?}");
    assert!(!ids.contains(&PADDING), "the retry is not padded");
    assert_eq!(hellos[1].key_shares().unwrap(), [P384]);
    assert_eq!(ids[..3], [SUPPORTED_VERSIONS, KEY_SHARE, SUPPORTED_GROUPS]);
}

// Reuse after SSL_clear. The Rust API does not expose `SSL_clear`.

fn clear(ssl: &mut SslRef) -> bool {
    unsafe { ffi::SSL_clear(ssl.as_ptr()) == 1 }
}

/// Runs a cleared client's next handshake against `server` over a fresh
/// transport.
#[track_caller]
fn reconnect(client: &mut SslStream<End>, server: Ssl) -> SslStream<End> {
    let (a, b) = ends();
    *client.get_mut() = a;
    let mut server = Side::from(server.accept(b));
    let mut connected = false;
    for _ in 0..32 {
        if !connected {
            match client.connect() {
                Ok(()) => connected = true,
                Err(error) if error.code() == ErrorCode::WANT_READ => {}
                Err(error) => panic!("reconnect failed: {error}"),
            }
        }
        server = server.step();
        if connected && !matches!(server, Side::Mid(_)) {
            break;
        }
    }
    assert!(connected, "the client's handshake stalled");
    server.done()
}

fn compression_server() -> SslContext {
    let mut ctx = server_context();
    register_all(&mut ctx);
    ctx.build()
}

#[test]
fn wire_settings_persist_across_ssl_clear() {
    let mut ctx = client_context();
    register_all(&mut ctx);
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_raw_cipher_list(&[0x1302, 0x1301, 0xc02f]).unwrap();
    ssl.set_raw_supported_groups(&[P256, X25519]).unwrap();
    ssl.set_raw_key_shares(&[P256]).unwrap();
    ssl.set_raw_supported_versions(&[0x0304, 0x0303]).unwrap();
    ssl.set_raw_signature_algorithms(&[0x0804, 0x0403, 0x0401])
        .unwrap();
    ssl.set_extension_order(&[SUPPORTED_GROUPS, KEY_SHARE, 0x0a0a])
        .unwrap();
    ssl.set_certificate_compression_algorithms(&[B]).unwrap();
    ssl.set_client_hello_shape(
        &ClientHelloShape::new()
            .with_grease_values(GreaseValues::Pinned)
            .with_padding(Padding::ToLength(900)),
    )
    .unwrap();
    let server = compression_server();
    let mut done = connect(ssl, Ssl::new(&server).unwrap());
    assert!(clear(done.client.ssl_mut()));
    reconnect(&mut done.client, Ssl::new(&server).unwrap());
    assert_eq!(
        done.client.ssl().peer_certificate_compression_algorithm(),
        Some(B)
    );

    let hellos = done.hellos();
    assert_eq!(hellos.len(), 2);
    for hello in &hellos {
        assert_eq!(hello.ciphers, [0x1302, 0x1301, 0xc02f]);
        assert_eq!(hello.groups().unwrap(), [P256, X25519]);
        assert_eq!(hello.key_shares().unwrap(), [P256]);
        assert_eq!(hello.versions().unwrap(), [0x0304, 0x0303]);
        assert_eq!(hello.sigalgs().unwrap(), [0x0804, 0x0403, 0x0401]);
        assert_eq!(hello.compression().unwrap(), [B.0]);
        assert_eq!(hello.ids()[..3], [SUPPORTED_GROUPS, KEY_SHARE, 0x0a0a]);
        assert_eq!(hello.len, 900);
    }
    assert_eq!(hellos[1].ids(), hellos[0].ids());
}

#[test]
fn ssl_clear_keeps_a_set_extension_order_over_the_context() {
    type Configure = fn(&mut SslContextBuilder);
    let server = server_context().build();
    let client_with = |configure: Configure| {
        let mut ctx = client_context();
        configure(&mut ctx);
        Ssl::new(&ctx.build()).unwrap()
    };
    let canonical = connect(client_with(|_| {}), Ssl::new(&server).unwrap())
        .hello()
        .unpadded_ids();
    let contexts: [(&str, Configure); 2] = [
        ("permuting context", |ctx| ctx.set_permute_extensions(true)),
        ("ordered context", |ctx| {
            ctx.set_extension_order(&[SIGNATURE_ALGORITHMS, SUPPORTED_VERSIONS])
                .unwrap();
        }),
    ];
    for (context, configure) in contexts {
        for order in [&[SUPPORTED_GROUPS, KEY_SHARE][..], &[]] {
            let mut ssl = client_with(configure);
            ssl.set_extension_order(order).unwrap();
            let mut done = connect(ssl, Ssl::new(&server).unwrap());
            assert!(clear(done.client.ssl_mut()));
            reconnect(&mut done.client, Ssl::new(&server).unwrap());
            // The listed extensions, then the rest in canonical order.
            let expected: Vec<u16> = order
                .iter()
                .copied()
                .chain(canonical.iter().copied().filter(|id| !order.contains(id)))
                .collect();
            let hellos = done.hellos();
            assert_eq!(hellos.len(), 2);
            for (n, hello) in hellos.iter().enumerate() {
                assert_eq!(
                    hello.unpadded_ids(),
                    expected,
                    "{context}, order {order:?}, hello {n}"
                );
            }
        }
    }
}

#[test]
fn setters_apply_again_after_ssl_clear() {
    let mut ctx = client_context();
    register_all(&mut ctx);
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_raw_cipher_list(&[0x1302, 0x1301]).unwrap();
    // A small key share keeps the ClientHello under the padding target.
    ssl.set_raw_supported_groups(&[X25519, P256]).unwrap();
    ssl.set_raw_key_shares(&[X25519]).unwrap();
    ssl.set_extension_order(&[SUPPORTED_GROUPS, KEY_SHARE])
        .unwrap();
    ssl.set_certificate_compression_algorithms(&[B]).unwrap();
    ssl.set_client_hello_shape(&ClientHelloShape::new().with_padding(Padding::ToLength(900)))
        .unwrap();
    let server = compression_server();
    let mut done = connect(ssl, Ssl::new(&server).unwrap());
    // A completed handshake fixes the settings.
    assert!(done
        .client
        .ssl_mut()
        .set_raw_cipher_list(&[0x1301])
        .is_err());
    assert!(clear(done.client.ssl_mut()));
    let ssl = done.client.ssl_mut();
    ssl.set_raw_cipher_list(&[0x1301]).unwrap();
    ssl.set_raw_supported_groups(&[X25519]).unwrap();
    ssl.set_raw_key_shares(&[X25519]).unwrap();
    ssl.set_extension_order(&[KEY_SHARE, SUPPORTED_GROUPS])
        .unwrap();
    ssl.set_certificate_compression_algorithms(&[C, A]).unwrap();
    ssl.set_client_hello_shape(&ClientHelloShape::new().with_padding(Padding::Off))
        .unwrap();
    reconnect(&mut done.client, Ssl::new(&server).unwrap());
    assert_eq!(
        done.client.ssl().peer_certificate_compression_algorithm(),
        Some(A)
    );

    let hellos = done.hellos();
    assert_eq!(hellos.len(), 2);
    let (first, second) = (&hellos[0], &hellos[1]);
    assert_eq!(first.ciphers, [0x1302, 0x1301]);
    assert_eq!(first.ids()[..2], [SUPPORTED_GROUPS, KEY_SHARE]);
    assert_eq!(first.len, 900);
    assert_eq!(second.ciphers, [0x1301]);
    assert_eq!(second.groups().unwrap(), [X25519]);
    assert_eq!(second.key_shares().unwrap(), [X25519]);
    assert_eq!(second.ids()[..2], [KEY_SHARE, SUPPORTED_GROUPS]);
    assert_eq!(second.compression().unwrap(), [C.0, A.0]);
    assert_eq!(second.body(PADDING), None);
    // Fixed again once the second ClientHello is written.
    assert!(done
        .client
        .ssl_mut()
        .set_raw_cipher_list(&[0x1302])
        .is_err());
}

#[test]
fn ssl_clear_fails_once_the_configuration_is_shed() {
    for shed in [false, true] {
        let mut ssl = client(TLS13);
        ssl.set_shed_handshake_config(shed);
        let mut done = connect(ssl, server(TLS13));
        // BoringSSL: SSL_clear may not be used after shedding the configuration.
        assert_eq!(clear(done.client.ssl_mut()), !shed);
    }
}

// Context routing.

/// A server context with A, B and C that routes every connection to `routed`
/// from its early callback, then optionally sets the ticket count.
fn routing(routed: SslContext, tickets_after_routing: Option<usize>) -> SslContext {
    let mut ctx = server_context();
    register_all(&mut ctx);
    ctx.set_num_tickets(3);
    ctx.set_select_certificate_callback(move |mut hello| {
        let ssl = hello.ssl_mut();
        ssl.set_ssl_context(&routed).unwrap();
        if let Some(count) = tickets_after_routing {
            ssl.set_num_tickets(count).unwrap();
        }
        Ok(())
    });
    ctx.build()
}

fn routed(register: impl FnOnce(&mut SslContextBuilder)) -> SslContext {
    let mut ctx = server_context();
    register(&mut ctx);
    ctx.set_num_tickets(7);
    ctx.build()
}

#[test]
fn routed_compression_preferences_longer_than_the_registry_still_select() {
    let mut client_ctx = client_context();
    register_all(&mut client_ctx);
    let client_ctx = client_ctx.build();
    let only_a = routed(register_a);
    let b_then_a = routed(|ctx| {
        register_b(ctx);
        register_a(ctx);
    });
    for (routed, expected) in [(only_a, A), (b_then_a, B)] {
        let mut ssl = Ssl::new(&routing(routed, None)).unwrap();
        // Validated against the original context, which registers all three.
        ssl.set_certificate_compression_algorithms(&[C, B, A])
            .unwrap();
        let done = connect(Ssl::new(&client_ctx).unwrap(), ssl);
        assert_eq!(done.hello().compression(), Some(vec![A.0, B.0, C.0]));
        // C is preferred but not registered where the connection was routed.
        assert_eq!(
            done.client.ssl().peer_certificate_compression_algorithm(),
            Some(expected)
        );
        assert_eq!(compressed_with(&done), Some(expected.0));
    }
}

#[test]
fn routed_ticket_counts_come_from_the_session_context() {
    for (before_routing, after_routing, expected) in [
        // BoringSSL reads the count from the session context, the original
        // one, not from the context routed to (7).
        (None, None, 3),
        (Some(5), None, 5),
        (None, Some(1), 1),
        (Some(5), Some(0), 0),
    ] {
        let mut ssl = Ssl::new(&routing(routed(|_| {}), after_routing)).unwrap();
        if let Some(count) = before_routing {
            ssl.set_num_tickets(count).unwrap();
        }
        let done = connect(Ssl::new(&client_context().build()).unwrap(), ssl);
        assert_eq!(
            done.tickets(),
            expected,
            "{before_routing:?} {after_routing:?}"
        );
    }
}

// Raw supported groups invariants.

#[test]
fn raw_groups_set_before_accept_configure_a_server() {
    for version in VERSIONS {
        let clients: [fn(SslVersion) -> Ssl; 2] = [client, |version| {
            let mut ssl = client(version);
            ssl.set_raw_supported_groups(&[X25519, P256, P384]).unwrap();
            ssl.set_raw_key_shares(&[X25519]).unwrap();
            ssl
        }];
        for offer in clients {
            // A fresh `Ssl` takes the client setters: its role is chosen at accept.
            let mut ssl = server(version);
            ssl.set_raw_supported_groups(&[0x0a0a, P384, FFDHE2048, P256])
                .unwrap();
            let done = connect(offer(version), ssl);
            let group = done.server.ssl().group_id().expect("a negotiated group");
            assert!([P384, P256].contains(&group), "{version:?}: {group:#x}");
            assert_eq!(done.client.ssl().group_id(), Some(group));
        }
    }
}

isolated_test! {
    /// A server's raw group list longer than its context's: the per-group
    /// flags, read when the server's preference decides, must grow with it.
    fn raw_groups_longer_than_the_context_list_configure_a_server() {
        for version in VERSIONS {
            let mut ssl = server_with(version, |ctx| {
                ctx.set_curves_list("X25519").unwrap();
                ctx.set_options(crate::ssl::SslOptions::CIPHER_SERVER_PREFERENCE);
            });
            ssl.set_raw_supported_groups(&[X25519, P256, P384]).unwrap();
            let mut offer = client(version);
            offer.set_raw_supported_groups(&[P384]).unwrap();
            offer.set_raw_key_shares(&[P384]).unwrap();
            let done = connect(offer, ssl);
            assert_eq!(done.server.ssl().group_id(), Some(P384), "{version:?}");
        }
    }
}

#[test]
fn raw_groups_drop_a_native_key_share_selection_they_exclude() {
    let mut ssl = client(TLS13);
    ssl.set_client_key_shares(&[SslCurve::SECP256R1]).unwrap();
    ssl.set_raw_supported_groups(&[X25519, P384]).unwrap();
    let done = connect(ssl, server(TLS13));
    assert_eq!(done.hello().groups().unwrap(), [X25519, P384]);
    assert_eq!(done.hello().key_shares().unwrap(), [X25519]);
    assert!(!done.client.ssl().used_hello_retry_request());
    assert_eq!(done.client.ssl().group_id(), Some(X25519));

    // A selection that still fits the groups is kept.
    let mut ssl = client(TLS13);
    ssl.set_client_key_shares(&[SslCurve::SECP256R1]).unwrap();
    ssl.set_raw_supported_groups(&[X25519, P256]).unwrap();
    let p256_server = server_with(TLS13, |ctx| ctx.set_curves_list("P-256").unwrap());
    let done = connect(ssl, p256_server);
    assert_eq!(done.hello().key_shares().unwrap(), [P256]);
    assert!(!done.client.ssl().used_hello_retry_request());
    assert_eq!(done.client.ssl().group_id(), Some(P256));
}

// Context extension orders.

#[test]
fn an_empty_context_extension_order_is_canonical_without_grease() {
    let hello = |configure: &dyn Fn(&mut SslContextBuilder)| {
        connect(client_with(TLS13, configure), server(TLS13)).hello()
    };
    let canonical = hello(&|_| {}).unpadded_ids();
    assert!(!canonical.iter().any(|id| is_grease(*id)));
    for permute in [false, true] {
        let hello = hello(&|ctx| {
            ctx.set_grease_enabled(true);
            ctx.set_permute_extensions(permute);
            ctx.set_extension_order(&[]).unwrap();
        });
        assert_eq!(hello.unpadded_ids(), canonical, "permute={permute}");
        // Native lists keep the context's GREASE.
        assert!(is_grease(hello.ciphers[0]));
        assert!(is_grease(hello.groups().unwrap()[0]));
    }
    // Without an order, the context's GREASE extensions stay.
    let native = hello(&|ctx| ctx.set_grease_enabled(true)).unpadded_ids();
    assert!(is_grease(native[0]) && is_grease(*native.last().unwrap()));
    assert_eq!(native.iter().filter(|id| is_grease(**id)).count(), 2);
    assert_eq!(native[1..native.len() - 1], canonical[..]);
}
