//! Real browser ClientHellos, compiled into the per-connection wire API as a
//! mirroring proxy would, emitted by a real handshake and compared with the
//! capture field by field.
//!
//! Only per-connection values are normalized: the random, session ID bytes,
//! key share key exchange bytes and, for GREASE ECH, the config ID, the `enc`
//! bytes and the payload (whose length must be one GREASE ECH picks). Everything else
//! must match, unless listed as a fixture's known difference; a new
//! difference or a stale exception fails the test.

mod quic_initial;

use super::memory::{client_context, handshake, server_context};
use super::wire::{self, is_grease, ClientHello, Reader};
use crate::ffi;
use crate::ssl::quic::tests::{connection, contexts, pump, Record};
use crate::ssl::quic::QuicConnection;
use crate::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ClientHelloShape, ExtensionType,
    GreaseValues, Padding, Ssl, SslContextBuilder, SslMethod, SslOptions, SslRef,
    SslSignatureAlgorithm, SslVerifyMode, SslVersion, UnknownValues,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const SERVER_NAME: u16 = 0;
const STATUS_REQUEST: u16 = 5;
const SUPPORTED_GROUPS: u16 = 10;
const EC_POINT_FORMATS: u16 = 11;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const SCT: u16 = 18;
const PADDING: u16 = 21;
const EXTENDED_MASTER_SECRET: u16 = 23;
const COMPRESS_CERTIFICATE: u16 = 27;
const RECORD_SIZE_LIMIT: u16 = 28;
const DELEGATED_CREDENTIAL: u16 = 34;
const SESSION_TICKET: u16 = 35;
const PRE_SHARED_KEY: u16 = 41;
const SUPPORTED_VERSIONS: u16 = 43;
const PSK_KEY_EXCHANGE_MODES: u16 = 45;
const KEY_SHARE: u16 = 51;
const QUIC_TRANSPORT_PARAMETERS: u16 = 57;
const ALPS_OLD: u16 = 0x4469;
const ALPS: u16 = 0x44cd;
const TRUST_ANCHORS: u16 = 0xca34;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const RENEGOTIATION_INFO: u16 = 0xff01;
const QUIC_TRANSPORT_PARAMETERS_LEGACY: u16 = 0xffa5;

/// Extensions BoringSSL builds itself: the mirror enables them through their
/// setters (or relies on their native body) and never sends a body for them.
const NATIVE: &[u16] = &[
    SERVER_NAME,
    STATUS_REQUEST,
    SUPPORTED_GROUPS,
    EC_POINT_FORMATS,
    SIGNATURE_ALGORITHMS,
    ALPN,
    SCT,
    PADDING,
    EXTENDED_MASTER_SECRET,
    COMPRESS_CERTIFICATE,
    RECORD_SIZE_LIMIT,
    DELEGATED_CREDENTIAL,
    SESSION_TICKET,
    PRE_SHARED_KEY,
    SUPPORTED_VERSIONS,
    PSK_KEY_EXCHANGE_MODES,
    KEY_SHARE,
    QUIC_TRANSPORT_PARAMETERS,
    ALPS_OLD,
    ALPS,
    TRUST_ANCHORS,
    ENCRYPTED_CLIENT_HELLO,
    RENEGOTIATION_INFO,
    QUIC_TRANSPORT_PARAMETERS_LEGACY,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Quic,
}

/// A field of a ClientHello that differs from the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Difference {
    LegacyVersion,
    SessionIdLength,
    Ciphers,
    Compression,
    /// The relative order of the extensions both sides sent.
    ExtensionOrder,
    /// Captured but not sent.
    Missing(u16),
    /// Sent but not captured.
    Extra(u16),
    Body(u16),
}

struct Fixture {
    hello: &'static str,
    transport: Transport,
    /// Every difference from the capture, with the reason it is expected.
    known_differences: &'static [(Difference, &'static str)],
}

const NOT_IN_QUIC: &str = "BoringSSL builds it only when TLS 1.2 can be negotiated, which \
                           QUIC rules out, and refuses a body for an extension it builds";
/// HPKE AEAD IDs (RFC 9180).
const AES_128_GCM: u16 = 0x0001;
const CHACHA20_POLY1305: u16 = 0x0003;

/// A ClientHello reduced to what a mirror must reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Normalized {
    legacy_version: u16,
    session_id_len: usize,
    ciphers: Vec<u16>,
    compression: Vec<u8>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Normalized {
    fn new(hello: &ClientHello<'_>) -> Self {
        Self {
            legacy_version: hello.legacy_version,
            session_id_len: hello.session_id.len(),
            ciphers: hello.ciphers.clone(),
            compression: hello.compression.to_vec(),
            extensions: hello
                .extensions
                .iter()
                .map(|&(id, body)| (id, normalize(id, body)))
                .collect(),
        }
    }

    fn ids(&self) -> Vec<u16> {
        self.extensions.iter().map(|(id, _)| *id).collect()
    }

    fn body(&self, id: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, body)| body.as_slice())
    }
}

/// An extension body with its per-connection values replaced; see the module
/// documentation. A body that does not parse is kept as is.
fn normalize(id: u16, body: &[u8]) -> Vec<u8> {
    let normalized = match id {
        KEY_SHARE => key_shares_without_keys(body),
        ENCRYPTED_CLIENT_HELLO => grease_ech_shape(body),
        _ => None,
    };
    normalized.unwrap_or_else(|| body.to_vec())
}

fn key_shares_without_keys(body: &[u8]) -> Option<Vec<u8>> {
    let mut outer = Reader::new(body);
    let mut entries = outer.prefixed_u16()?;
    outer.finish()?;
    let mut out = body[..2].to_vec();
    while !entries.is_empty() {
        out.extend_from_slice(&entries.u16()?.to_be_bytes());
        let key = entries.prefixed_u16()?.rest();
        out.extend_from_slice(&u16::try_from(key.len()).unwrap().to_be_bytes());
        out.extend(std::iter::repeat_n(0, key.len()));
    }
    Some(out)
}

/// An outer encrypted_client_hello as its type, KDF, AEAD and `enc` length,
/// and whether its payload length is one BoringSSL's GREASE picks.
fn grease_ech_shape(body: &[u8]) -> Option<Vec<u8>> {
    let mut fields = Reader::new(body);
    let kind = fields.u8()?;
    let kdf = fields.u16()?;
    let aead = fields.u16()?;
    fields.u8()?;
    let enc = fields.prefixed_u16()?.rest();
    let payload = fields.prefixed_u16()?.rest();
    fields.finish()?;
    // 32 * [4, 7] plus the 16-byte tag of either GREASE AEAD.
    let plausible = (144..=240).contains(&payload.len()) && (payload.len() - 16) % 32 == 0;
    let mut out = vec![kind];
    out.extend_from_slice(&kdf.to_be_bytes());
    out.extend_from_slice(&aead.to_be_bytes());
    out.extend_from_slice(&u16::try_from(enc.len()).unwrap().to_be_bytes());
    out.push(plausible.into());
    Some(out)
}

/// Every field where `emitted` differs from `captured`, with both values.
fn differences(captured: &Normalized, emitted: &Normalized) -> BTreeMap<Difference, String> {
    let mut found = BTreeMap::new();
    let mut compare = |difference, captured: String, emitted: String| {
        if captured != emitted {
            found.insert(
                difference,
                format!("captured {captured}\n    emitted  {emitted}"),
            );
        }
    };
    compare(
        Difference::LegacyVersion,
        format!("{:#06x}", captured.legacy_version),
        format!("{:#06x}", emitted.legacy_version),
    );
    compare(
        Difference::SessionIdLength,
        captured.session_id_len.to_string(),
        emitted.session_id_len.to_string(),
    );
    compare(
        Difference::Ciphers,
        format!("{:04x?}", captured.ciphers),
        format!("{:04x?}", emitted.ciphers),
    );
    compare(
        Difference::Compression,
        format!("{:02x?}", captured.compression),
        format!("{:02x?}", emitted.compression),
    );
    let (ours, theirs) = (captured.ids(), emitted.ids());
    let common = |ids: &[u16], other: &[u16]| -> Vec<u16> {
        ids.iter()
            .copied()
            .filter(|id| other.contains(id))
            .collect()
    };
    compare(
        Difference::ExtensionOrder,
        format!("{:04x?}", common(&ours, &theirs)),
        format!("{:04x?}", common(&theirs, &ours)),
    );
    for id in &ours {
        match emitted.body(*id) {
            None => compare(Difference::Missing(*id), "sent".into(), "absent".into()),
            Some(body) => compare(
                Difference::Body(*id),
                hex::encode(captured.body(*id).unwrap()),
                hex::encode(body),
            ),
        }
    }
    for id in theirs.iter().filter(|id| !ours.contains(id)) {
        compare(Difference::Extra(*id), "absent".into(), "sent".into());
    }
    found
}

/// A certificate compression algorithm offered by a mirror: registered so it
/// can be listed, never used (the test server does not compress).
struct Offered<const ID: u16>;

impl<const ID: u16> CertificateCompressor for Offered<ID> {
    const ALGORITHM: CertificateCompressionAlgorithm = match ID {
        1 => CertificateCompressionAlgorithm::ZLIB,
        2 => CertificateCompressionAlgorithm::BROTLI,
        3 => CertificateCompressionAlgorithm::ZSTD,
        _ => panic!("no such algorithm"),
    };
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
}

/// A mirror's client context: every certificate compression algorithm it
/// can offer is registered, and each connection selects its own.
fn mirror_context(transport: Transport) -> SslContextBuilder {
    let mut ctx = match transport {
        Transport::Tcp => client_context(),
        Transport::Quic => {
            let mut ctx = crate::ssl::SslContext::builder(SslMethod::tls()).unwrap();
            ctx.set_verify(SslVerifyMode::NONE);
            ctx
        }
    };
    ctx.add_certificate_compression_algorithm(Offered::<1>)
        .unwrap();
    ctx.add_certificate_compression_algorithm(Offered::<2>)
        .unwrap();
    ctx.add_certificate_compression_algorithm(Offered::<3>)
        .unwrap();
    ctx
}

fn u16_list(body: &[u8], prefix: usize) -> Vec<u16> {
    wire::u16_list(body, prefix).expect("a well-formed list")
}

/// The contents of a body that is one two-byte length prefix.
fn u16_prefixed(body: &[u8]) -> &[u8] {
    let mut fields = Reader::new(body);
    let inner = fields.prefixed_u16().expect("a length-prefixed body");
    fields.finish().expect("nothing after the list");
    inner.rest()
}

/// The entries of a list of one-byte length-prefixed strings.
fn u8_prefixed_entries(list: &[u8]) -> Vec<&[u8]> {
    let mut list = Reader::new(list);
    let mut entries = Vec::new();
    while !list.is_empty() {
        entries.push(list.prefixed_u8().expect("a well-formed entry").rest());
    }
    entries
}

fn host_name(body: &[u8]) -> &str {
    let mut names = Reader::new(u16_prefixed(body));
    assert_eq!(names.u8(), Some(0), "a host_name entry");
    let name = names.prefixed_u16().expect("a host name").rest();
    names.finish().expect("one name");
    std::str::from_utf8(name).expect("an ASCII host name")
}

fn version(wire: u16) -> SslVersion {
    match wire {
        0x0301 => SslVersion::TLS1,
        0x0302 => SslVersion::TLS1_1,
        0x0303 => SslVersion::TLS1_2,
        0x0304 => SslVersion::TLS1_3,
        _ => panic!("no SslVersion for {wire:#06x}"),
    }
}

fn compression_algorithm(id: u16) -> CertificateCompressionAlgorithm {
    match id {
        1 => CertificateCompressionAlgorithm::ZLIB,
        2 => CertificateCompressionAlgorithm::BROTLI,
        3 => CertificateCompressionAlgorithm::ZSTD,
        _ => panic!("no CertificateCompressionAlgorithm for {id}"),
    }
}

/// Configures a client to send `hello` through the public per-connection API
/// only, as a mirroring proxy would. QUIC transport parameters are set on the
/// QUIC connection by the caller.
fn mirror(ssl: &mut SslRef, hello: &ClientHello<'_>, transport: Transport) {
    let mut shape = ClientHelloShape::new()
        .with_grease_values(GreaseValues::Pinned)
        .with_unknown_values(UnknownValues::Preserve)
        .with_padding(Padding::Off);
    ssl.set_raw_cipher_list(&hello.ciphers).unwrap();
    for &(id, body) in &hello.extensions {
        match id {
            SERVER_NAME => ssl.set_hostname(host_name(body)).unwrap(),
            STATUS_REQUEST => ssl.enable_ocsp_stapling(),
            SCT => ssl.enable_signed_cert_timestamps(),
            SUPPORTED_GROUPS => ssl.set_raw_supported_groups(&u16_list(body, 2)).unwrap(),
            SIGNATURE_ALGORITHMS => ssl
                .set_raw_signature_algorithms(&u16_list(body, 2))
                .unwrap(),
            KEY_SHARE => ssl
                .set_raw_key_shares(&wire::key_share_groups(body).expect("a key_share"))
                .unwrap(),
            SUPPORTED_VERSIONS => {
                let versions = u16_list(body, 1);
                ssl.set_raw_supported_versions(&versions).unwrap();
                let real: Vec<u16> = versions.into_iter().filter(|v| !is_grease(*v)).collect();
                let min = real.iter().min().expect("a real version");
                let max = real.iter().max().expect("a real version");
                ssl.set_min_proto_version(Some(version(*min))).unwrap();
                ssl.set_max_proto_version(Some(version(*max))).unwrap();
            }
            ALPN => ssl.set_alpn_protos(u16_prefixed(body)).unwrap(),
            ALPS | ALPS_OLD => {
                ssl.set_alps_use_new_codepoint(id == ALPS);
                for protocol in u8_prefixed_entries(u16_prefixed(body)) {
                    ssl.add_application_settings(protocol).unwrap();
                }
            }
            COMPRESS_CERTIFICATE => {
                let ids = wire::u16_list(body, 1).expect("a compression list");
                let algorithms: Vec<_> = ids.into_iter().map(compression_algorithm).collect();
                ssl.set_certificate_compression_algorithms(&algorithms)
                    .unwrap();
            }
            DELEGATED_CREDENTIAL => {
                let schemes: Vec<SslSignatureAlgorithm> = u16_list(body, 2)
                    .into_iter()
                    .map(SslSignatureAlgorithm::from)
                    .collect();
                ssl.set_delegated_credential_schemes(&schemes).unwrap();
            }
            RECORD_SIZE_LIMIT => {
                let mut fields = Reader::new(body);
                let limit = fields.u16().expect("a record size limit");
                fields.finish().expect("one value");
                ssl.set_record_size_limit(limit).unwrap();
            }
            TRUST_ANCHORS => ssl.set_requested_trust_anchors(u16_prefixed(body)).unwrap(),
            ENCRYPTED_CLIENT_HELLO => ssl.set_enable_ech_grease(true),
            PADDING => {
                let len = u16::try_from(hello.encode().len()).unwrap();
                shape.set_padding(Padding::ToLength(len));
            }
            QUIC_TRANSPORT_PARAMETERS | QUIC_TRANSPORT_PARAMETERS_LEGACY => {
                assert_eq!(transport, Transport::Quic);
                ssl.set_quic_use_legacy_codepoint(id == QUIC_TRANSPORT_PARAMETERS_LEGACY);
            }
            // Built natively, with a fixed body the comparison checks.
            EC_POINT_FORMATS
            | EXTENDED_MASTER_SECRET
            | SESSION_TICKET
            | PSK_KEY_EXCHANGE_MODES
            | RENEGOTIATION_INFO
            | PRE_SHARED_KEY => {}
            _ => {
                assert!(!NATIVE.contains(&id));
                shape.set_extension_body(ExtensionType::from(id), body);
            }
        }
    }
    if transport == Transport::Tcp && hello.extension(SESSION_TICKET).is_none() {
        ssl.set_options(SslOptions::NO_TICKET);
    }
    ssl.set_extension_order(&hello.ids()).unwrap();
    ssl.set_client_hello_shape(&shape).unwrap();
}

/// Records the first ClientHello `ssl` writes.
fn capture_client_hello(ssl: &mut SslRef) -> Arc<Mutex<Option<Vec<u8>>>> {
    let written = Arc::new(Mutex::new(None));
    let sink = written.clone();
    ssl.set_msg_callback(move |_, message| {
        if message.is_written() && message.handshake_type() == Some(1) {
            sink.lock()
                .unwrap()
                .get_or_insert_with(|| message.bytes().to_vec());
        }
    });
    written
}

/// Mirrors `hello`, runs a real handshake against a BoringSSL server, and
/// returns the ClientHello the client sent.
fn emit(hello: &ClientHello<'_>, transport: Transport) -> Vec<u8> {
    let ctx = mirror_context(transport).build();
    let mut client = Ssl::new(&ctx).unwrap();
    mirror(&mut client, hello, transport);
    let written = capture_client_hello(&mut client);
    match transport {
        Transport::Tcp => {
            let server = Ssl::new(&server_context().build()).unwrap();
            let (client, _) = handshake(client, server);
            client.done();
        }
        Transport::Quic => {
            let (_, server_ctx, _) = contexts();
            let c = Arc::new(Record::default());
            let s = Arc::new(Record::default());
            let mut client = QuicConnection::new(client, c.clone()).unwrap();
            client.set_connect_state();
            let parameters = hello
                .extension(QUIC_TRANSPORT_PARAMETERS)
                .or(hello.extension(QUIC_TRANSPORT_PARAMETERS_LEGACY))
                .expect("QUIC transport parameters");
            client.set_transport_parameters(parameters).unwrap();
            let mut server = connection(&server_ctx, true, s.clone());
            pump(&mut client, &mut server, &c, &s).expect("the QUIC handshake completes");
        }
    }
    let written = written.lock().unwrap().take();
    written.expect("a ClientHello")
}

fn check(fixture: &Fixture) {
    let captured = quic_initial::unhex(fixture.hello);
    let hello = ClientHello::parse(&captured).expect("a well-formed captured ClientHello");
    assert_eq!(hello.encode(), captured);
    let emitted = emit(&hello, fixture.transport);
    let sent = ClientHello::parse(&emitted).expect("a well-formed emitted ClientHello");
    let mut sent = Normalized::new(&sent);
    // Without AES hardware, BoringSSL's GREASE ECH picks ChaCha20-Poly1305
    // over the captured AES-128-GCM: only that AEAD field may differ.
    if unsafe { ffi::EVP_has_aes_hardware() } == 0 {
        if let Some((_, body)) = sent
            .extensions
            .iter_mut()
            .find(|(id, _)| *id == ENCRYPTED_CLIENT_HELLO)
        {
            if body.get(3..5) == Some(&CHACHA20_POLY1305.to_be_bytes()[..]) {
                body[3..5].copy_from_slice(&AES_128_GCM.to_be_bytes());
            }
        }
    }
    let found = differences(&Normalized::new(&hello), &sent);
    let expected: BTreeMap<_, _> = fixture.known_differences.iter().copied().collect();
    let report: String = found
        .iter()
        .map(|(difference, detail)| {
            let why = expected
                .get(difference)
                .map_or("UNDOCUMENTED".to_string(), |why| {
                    format!("documented: {why}")
                });
            format!("\n  {difference:x?} ({why})\n    {detail}")
        })
        .collect();
    let stale: Vec<_> = expected.keys().filter(|d| !found.contains_key(d)).collect();
    assert!(
        found.keys().eq(expected.keys()),
        "differences from the capture:{report}\n  documented but not found: {stale:x?}"
    );
}

#[test]
fn chrome_154_macos_tcp() {
    check(&Fixture {
        hello: include_str!("fixtures/chrome-154-macos-tcp-client-hello.hex"),
        transport: Transport::Tcp,
        known_differences: &[],
    });
}

#[test]
fn chrome_149_android_tcp() {
    check(&Fixture {
        hello: include_str!("fixtures/chrome-149-android-tcp-client-hello.hex"),
        transport: Transport::Tcp,
        known_differences: &[],
    });
}

#[test]
fn firefox_157_macos_tcp() {
    check(&Fixture {
        hello: include_str!("fixtures/firefox-157-macos-tcp-client-hello.hex"),
        transport: Transport::Tcp,
        known_differences: &[],
    });
}

const SAFARI_26_4_MACOS: &str = include_str!("fixtures/safari-26.4-macos-tcp-client-hello.hex");
const SAFARI_18_6_IOS: &str = include_str!("fixtures/safari-18.6-ios-tcp-client-hello.hex");

#[test]
fn safari_26_4_macos_tcp() {
    check(&Fixture {
        hello: SAFARI_26_4_MACOS,
        transport: Transport::Tcp,
        known_differences: &[],
    });
}

#[test]
fn safari_18_6_ios_tcp() {
    check(&Fixture {
        hello: SAFARI_18_6_IOS,
        transport: Transport::Tcp,
        known_differences: &[],
    });
}

#[test]
fn chrome_153_quic() {
    check(&Fixture {
        hello: include_str!("fixtures/chrome-153-quic-client-hello.hex"),
        transport: Transport::Quic,
        known_differences: &[],
    });
}

#[test]
fn firefox_156_quic() {
    check(&Fixture {
        hello: include_str!("fixtures/firefox-156-quic-client-hello.hex"),
        transport: Transport::Quic,
        known_differences: &[
            (Difference::Missing(EXTENDED_MASTER_SECRET), NOT_IN_QUIC),
            (Difference::Missing(RENEGOTIATION_INFO), NOT_IN_QUIC),
        ],
    });
}

/// The QUIC fixtures are exactly the CRYPTO stream of the captured Initial
/// datagrams.
#[test]
fn quic_fixtures_decrypt_from_the_captured_datagrams() {
    let flights = [
        (
            [
                include_str!("fixtures/quic/chrome-153-initial-1.hex"),
                include_str!("fixtures/quic/chrome-153-initial-2.hex"),
            ],
            include_str!("fixtures/chrome-153-quic-client-hello.hex"),
        ),
        (
            [
                include_str!("fixtures/quic/firefox-156-initial-1.hex"),
                include_str!("fixtures/quic/firefox-156-initial-2.hex"),
            ],
            include_str!("fixtures/firefox-156-quic-client-hello.hex"),
        ),
    ];
    for (datagrams, hello) in flights {
        let datagrams: Vec<_> = datagrams.iter().map(|d| quic_initial::unhex(d)).collect();
        let hello = quic_initial::unhex(hello);
        assert_eq!(
            quic_initial::client_hello(&datagrams).expect("authenticated Initial packets"),
            hello
        );
        // Either datagram alone holds only part of the ClientHello.
        for datagram in &datagrams {
            let part = quic_initial::client_hello(std::slice::from_ref(datagram));
            assert!(part.is_none_or(|part| part.len() < hello.len()));
        }
        // A flipped ciphertext bit fails authentication.
        let mut corrupted = datagrams.clone();
        corrupted[0][200] ^= 1;
        assert_eq!(quic_initial::client_hello(&corrupted), None);
    }
}
