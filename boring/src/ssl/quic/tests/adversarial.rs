//! A misbehaving server against a client using per-connection wire control.
//!
//! QUIC carries handshake messages in plaintext per encryption level, so a
//! relay between the endpoints can rewrite one server message before the
//! client reads it. A rewrite also breaks the transcript, failing the
//! handshake at Finished at the latest, so every test pins the error the
//! client raised at the rewritten message itself, and a control proves the
//! same relay path delivers the message intact.

use super::support::quic_context;
use super::{connection, step, Record};
use crate::{
    ffi,
    pkey::PKey,
    ssl::{
        quic::{EncryptionLevel, QuicConnection, QuicError},
        test::wire::{self, ServerHello},
        CertificateCompressionAlgorithm, CertificateCompressor, ClientHelloShape, ExtensionType,
        SslContext, SslContextBuilder, SslRef, SslVerifyMode, UnknownValues,
    },
    x509::X509,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering::SeqCst},
    Arc, Mutex,
};

const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const CERTIFICATE_VERIFY: u8 = 15;
const COMPRESSED_CERTIFICATE: u8 = 25;

const SUPPORTED_GROUPS: u16 = 10;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;
const COMPRESS_CERTIFICATE: u16 = 27;
const SUPPORTED_VERSIONS: u16 = 43;
const KEY_SHARE: u16 = 51;
const QUIC_TRANSPORT_PARAMETERS: u16 = 57;

const ILLEGAL_PARAMETER: u8 = 47;
const DECODE_ERROR: u8 = 50;
const DECRYPT_ERROR: u8 = 51;
const PROTOCOL_VERSION: u8 = 70;
const UNSUPPORTED_EXTENSION: u8 = 110;

const X25519: u16 = 0x001d;
const P256: u16 = 0x0017;
const TLS13: u16 = 0x0304;
const AES_128_GCM: u16 = 0x1301;
const AES_256_GCM: u16 = 0x1302;
const RSA_PSS_SHA256: u16 = 0x0804;
const RSA_PSS_SHA384: u16 = 0x0805;

/// Values a client can list but BoringSSL cannot negotiate.
const UNKNOWN_GROUP: u16 = 0x0100; // ffdhe2048
const UNKNOWN_VERSION: u16 = 0x7f1c; // a TLS 1.3 draft
const UNKNOWN_SIGALG: u16 = 0x0909;
const UNKNOWN_CIPHER: u16 = 0x13ff;
const UNKNOWN_EXTENSION: u16 = 0x4321;
const GREASE_EXTENSION: u16 = 0x0a0a;

/// The ServerHello random marking a HelloRetryRequest (RFC 8446, section 4.1.3).
const HELLO_RETRY_REQUEST: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// A client and a server joined by a relay that can rewrite server messages.
struct Session {
    client: QuicConnection,
    server: QuicConnection,
    c: Arc<Record>,
    s: Arc<Record>,
    /// Every handshake message the client wrote.
    written: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Session {
    fn new(client_ctx: &SslContext, server_ctx: &SslContext) -> Self {
        let c = Arc::new(Record::default());
        let s = Arc::new(Record::default());
        let mut client = connection(client_ctx, false, c.clone());
        let server = connection(server_ctx, true, s.clone());
        let written = Arc::new(Mutex::new(Vec::new()));
        let sink = written.clone();
        client.ssl_mut().set_msg_callback(move |_, message| {
            if message.is_written() && message.handshake_type().is_some() {
                sink.lock().unwrap().push(message.bytes().to_vec());
            }
        });
        Self {
            client,
            server,
            c,
            s,
            written,
        }
    }

    fn client_hellos(&self) -> Vec<Vec<u8>> {
        let written = self.written.lock().unwrap();
        written
            .iter()
            .filter(|message| message[0] == CLIENT_HELLO)
            .cloned()
            .collect()
    }

    /// The body of extension `id` in the first ClientHello.
    fn offered(&self, id: u16) -> Option<Vec<u8>> {
        let hellos = self.client_hellos();
        let hello = wire::ClientHello::parse(&hellos[0]).expect("a well-formed ClientHello");
        hello.extension(id).map(<[u8]>::to_vec)
    }

    /// Runs the handshake, passing each whole server message of handshake type
    /// `kind` through `edit` before the client reads it. Returns the client's
    /// result and how many messages `edit` saw; the server never fails.
    fn relay(
        &mut self,
        kind: u8,
        mut edit: impl FnMut(&[u8]) -> Vec<u8>,
    ) -> (Result<(), QuicError>, usize) {
        let mut seen = 0;
        let result = self.run(|message| {
            if message[0] != kind {
                return message.to_vec();
            }
            seen += 1;
            edit(message)
        });
        (result, seen)
    }

    fn run(&mut self, mut edit: impl FnMut(&[u8]) -> Vec<u8>) -> Result<(), QuicError> {
        // CRYPTO data reassembled into whole messages, per encryption level.
        let mut partial: [Vec<u8>; 4] = Default::default();
        for _ in 0..32 {
            step(&mut self.client)?;
            step(&mut self.server).expect("the server never fails");
            for (level, bytes) in std::mem::take(&mut *self.c.output.lock().unwrap()) {
                self.server
                    .provide_data(level, &bytes)
                    .expect("the server never fails");
                step(&mut self.server).expect("the server never fails");
            }
            for (level, bytes) in std::mem::take(&mut *self.s.output.lock().unwrap()) {
                let buffer = &mut partial[level as usize];
                buffer.extend_from_slice(&bytes);
                while let Some(len) = message_len(buffer) {
                    let message: Vec<u8> = buffer.drain(..len).collect();
                    self.client.provide_data(level, &edit(&message))?;
                    step(&mut self.client)?;
                }
            }
            if self.client.ssl().is_init_finished()
                && self.server.ssl().is_init_finished()
                && self.c.output.lock().unwrap().is_empty()
                && self.s.output.lock().unwrap().is_empty()
                && partial.iter().all(Vec::is_empty)
            {
                return Ok(());
            }
        }
        panic!("handshake failed to make progress");
    }

    /// The client failed closed: `reason` is the first TLS error it raised and
    /// `alert` the only alert it sent; it neither finished, nor derived
    /// application keys, nor wrote anything after the rewritten message.
    /// Returns the reason and detail of every TLS error on the stack.
    #[track_caller]
    fn assert_rejected(
        &self,
        result: Result<(), QuicError>,
        reason: &str,
        alert: u8,
    ) -> Vec<(String, Option<String>)> {
        let error = match result {
            Err(QuicError::Tls(error)) => error,
            other => panic!("expected a TLS failure, got {other:?}"),
        };
        let stack = error.ssl_error().expect("a BoringSSL error stack");
        // Signature failures stack the crypto library's own error first.
        let raised: Vec<_> = stack
            .errors()
            .iter()
            .filter(|error| error.library_reason(ffi::ERR_LIB_SSL).is_some())
            .map(|error| {
                (
                    error.reason().unwrap_or_default().to_owned(),
                    error.data().map(str::to_owned),
                )
            })
            .collect();
        assert_eq!(
            raised.first().map(|(raised, _)| raised.as_str()),
            Some(reason),
            "{stack}"
        );
        assert_eq!(*self.c.alerts.lock().unwrap(), [alert]);
        assert!(!self.client.ssl().is_init_finished());
        assert!(self.c.output.lock().unwrap().is_empty());
        assert!(!self
            .c
            .secrets
            .lock()
            .unwrap()
            .iter()
            .any(|(_, level, ..)| *level == EncryptionLevel::Application));
        raised
    }
}

/// The length of the whole handshake message at the front of `buffer`, once complete.
fn message_len(buffer: &[u8]) -> Option<usize> {
    let header = buffer.get(..4)?;
    let len =
        4 + (usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]));
    (buffer.len() >= len).then_some(len)
}

fn server_context(configure: impl FnOnce(&mut SslContextBuilder)) -> SslContext {
    let mut ctx = quic_context();
    ctx.set_certificate(&X509::from_pem(include_bytes!("../../../../test/cert.pem")).unwrap())
        .unwrap();
    ctx.set_private_key(
        &PKey::private_key_from_pem(include_bytes!("../../../../test/key.pem")).unwrap(),
    )
    .unwrap();
    configure(&mut ctx);
    ctx.build()
}

fn client_context(configure: impl FnOnce(&mut SslContextBuilder)) -> SslContext {
    let mut ctx = quic_context();
    ctx.set_verify(SslVerifyMode::NONE);
    configure(&mut ctx);
    ctx.build()
}

/// A session whose client preserves values BoringSSL cannot negotiate.
fn preserving(configure: impl FnOnce(&mut SslRef)) -> Session {
    preserving_with(&server_context(|_| {}), configure)
}

fn preserving_with(server_ctx: &SslContext, configure: impl FnOnce(&mut SslRef)) -> Session {
    let mut session = Session::new(&client_context(|_| {}), server_ctx);
    let ssl = session.client.ssl_mut();
    ssl.set_client_hello_shape(
        &ClientHelloShape::new()
            .with_unknown_values(UnknownValues::Preserve)
            .with_extension_body(ExtensionType::from(UNKNOWN_EXTENSION), [1, 2, 3]),
    )
    .unwrap();
    configure(ssl);
    session
}

/// `message`, a ServerHello, with the body of its extension `id` replaced.
fn with_server_hello_extension(message: &[u8], id: u16, body: &[u8]) -> Vec<u8> {
    let mut hello = ServerHello::parse(message).expect("a well-formed ServerHello");
    let extension = hello
        .extensions
        .iter_mut()
        .find(|(ext, _)| *ext == id)
        .expect("the server sent this extension");
    extension.1 = body;
    hello.reencode(message).unwrap()
}

/// `message`, a ServerHello, with `extra` appended to its extensions.
fn with_extra_server_hello_extension(message: &[u8], extra: Option<(u16, &[u8])>) -> Vec<u8> {
    let mut hello = ServerHello::parse(message).expect("a well-formed ServerHello");
    hello.extensions.extend(extra);
    hello.reencode(message).unwrap()
}

/// `message`, an EncryptedExtensions, with `extra` appended to its extensions.
fn with_extra_encrypted_extension(message: &[u8], extra: Option<(u16, &[u8])>) -> Vec<u8> {
    let mut extensions =
        wire::encrypted_extensions(message).expect("a well-formed EncryptedExtensions");
    extensions.extend(extra);
    wire::encode_encrypted_extensions(&extensions)
}

/// Certificate "compression" that copies, counting decompressions.
struct Identity<const ID: u16>(Arc<AtomicUsize>);

impl<const ID: u16> CertificateCompressor for Identity<ID> {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm(ID);
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        output.write_all(input)
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        self.0.fetch_add(1, SeqCst);
        output.write_all(input)
    }
}

const A: u16 = 0xff01;
const B: u16 = 0xff02;

/// The server compresses its certificate with A, which the client registered
/// alongside B, and the relay relabels it B. A connection restricted to A
/// rejects the relabelled certificate before B's decompressor runs. Without
/// the restriction B is offered and decompresses the same relabelled message,
/// which then fails the server's signature; unrelabelled, the restricted
/// connection completes with A.
#[test]
fn certificate_compressed_with_an_algorithm_the_connection_did_not_offer_is_rejected() {
    for (restricted, relabel) in [(true, true), (false, true), (true, false)] {
        let (a, b) = (Arc::default(), Arc::default());
        let client_ctx = client_context(|ctx| {
            ctx.add_certificate_compression_algorithm(Identity::<A>(Arc::clone(&a)))
                .unwrap();
            ctx.add_certificate_compression_algorithm(Identity::<B>(Arc::clone(&b)))
                .unwrap();
        });
        let server_ctx = server_context(|ctx| {
            ctx.add_certificate_compression_algorithm(Identity::<A>(Arc::default()))
                .unwrap();
        });
        let mut session = Session::new(&client_ctx, &server_ctx);
        if restricted {
            session
                .client
                .ssl_mut()
                .set_certificate_compression_algorithms(&[CertificateCompressionAlgorithm(A)])
                .unwrap();
        }
        let (result, seen) = session.relay(COMPRESSED_CERTIFICATE, |message| {
            let (algorithm, len, compressed) = wire::compressed_certificate(message).unwrap();
            assert_eq!(algorithm, A);
            wire::encode_compressed_certificate(if relabel { B } else { A }, len, compressed)
        });
        assert_eq!(seen, 1);
        let offered = wire::u16_list(&session.offered(COMPRESS_CERTIFICATE).unwrap(), 1);
        assert_eq!(
            offered.unwrap(),
            if restricted { vec![A] } else { vec![A, B] }
        );
        match (restricted, relabel) {
            (true, true) => {
                let raised = session.assert_rejected(
                    result,
                    "UNKNOWN_CERT_COMPRESSION_ALG",
                    ILLEGAL_PARAMETER,
                );
                assert_eq!(raised[0].1.as_deref(), Some(&*format!("alg={B}")));
                assert_eq!((a.load(SeqCst), b.load(SeqCst)), (0, 0));
            }
            (false, true) => {
                session.assert_rejected(result, "BAD_SIGNATURE", DECRYPT_ERROR);
                assert_eq!((a.load(SeqCst), b.load(SeqCst)), (0, 1));
            }
            _ => {
                result.unwrap();
                assert_eq!((a.load(SeqCst), b.load(SeqCst)), (1, 0));
            }
        }
    }
}

/// An empty per-connection list disables certificate compression, so the
/// client offers none. A CompressedCertificate the relay forges from the
/// server's Certificate is then rejected, though the context registered its
/// algorithm. With the context's algorithms in effect, the same forgery is
/// decompressed and only fails the server's signature.
#[test]
fn forged_compressed_certificate_is_rejected_when_compression_is_disabled() {
    for disabled in [true, false] {
        let decompressed = Arc::default();
        let client_ctx = client_context(|ctx| {
            ctx.add_certificate_compression_algorithm(Identity::<A>(Arc::clone(&decompressed)))
                .unwrap();
        });
        let mut session = Session::new(&client_ctx, &server_context(|_| {}));
        if disabled {
            session
                .client
                .ssl_mut()
                .set_certificate_compression_algorithms(&[])
                .unwrap();
        }
        let (result, seen) = session.relay(CERTIFICATE, |message| {
            let (CERTIFICATE, body) = wire::message(message).unwrap() else {
                unreachable!()
            };
            wire::encode_compressed_certificate(A, body.len(), body)
        });
        assert_eq!(seen, 1);
        assert_eq!(session.offered(COMPRESS_CERTIFICATE).is_none(), disabled);
        if disabled {
            let raised =
                session.assert_rejected(result, "UNKNOWN_CERT_COMPRESSION_ALG", ILLEGAL_PARAMETER);
            assert_eq!(raised[0].1.as_deref(), Some(&*format!("alg={A}")));
            assert_eq!(decompressed.load(SeqCst), 0);
        } else {
            session.assert_rejected(result, "BAD_SIGNATURE", DECRYPT_ERROR);
            assert_eq!(decompressed.load(SeqCst), 1);
        }
    }
}

/// The server's key share names a group the client lists only as a preserved
/// unknown value. The client holds no key for it and rejects the ServerHello;
/// relayed unchanged, the ServerHello completes the handshake.
#[test]
fn server_hello_selecting_a_preserved_unknown_group_is_rejected() {
    for rewrite in [true, false] {
        let mut session = preserving(|ssl| {
            ssl.set_raw_supported_groups(&[UNKNOWN_GROUP, X25519, P256])
                .unwrap();
        });
        let (result, seen) = session.relay(SERVER_HELLO, |message| {
            let hello = ServerHello::parse(message).unwrap();
            let share = wire::find(&hello.extensions, KEY_SHARE).unwrap();
            let (group, key) = wire::server_key_share(share).unwrap();
            assert_eq!(group, X25519);
            let group = if rewrite { UNKNOWN_GROUP } else { group };
            with_server_hello_extension(
                message,
                KEY_SHARE,
                &wire::encode_server_key_share(group, key),
            )
        });
        assert_eq!(seen, 1);
        let groups = wire::u16_list(&session.offered(SUPPORTED_GROUPS).unwrap(), 2);
        assert_eq!(groups.unwrap(), [UNKNOWN_GROUP, X25519, P256]);
        if rewrite {
            session.assert_rejected(result, "WRONG_CURVE", ILLEGAL_PARAMETER);
        } else {
            result.unwrap();
        }
    }
}

/// The server selects a version the client lists only as a preserved unknown
/// value. The client cannot speak it and rejects the ServerHello; relayed
/// unchanged, the ServerHello completes the handshake.
#[test]
fn server_hello_selecting_a_preserved_unknown_version_is_rejected() {
    for rewrite in [true, false] {
        let mut session = preserving(|ssl| {
            ssl.set_raw_supported_versions(&[UNKNOWN_VERSION, TLS13])
                .unwrap();
        });
        let (result, seen) = session.relay(SERVER_HELLO, |message| {
            let version = if rewrite { UNKNOWN_VERSION } else { TLS13 };
            with_server_hello_extension(message, SUPPORTED_VERSIONS, &version.to_be_bytes())
        });
        assert_eq!(seen, 1);
        let versions = wire::u16_list(&session.offered(SUPPORTED_VERSIONS).unwrap(), 1);
        assert_eq!(versions.unwrap(), [UNKNOWN_VERSION, TLS13]);
        if rewrite {
            session.assert_rejected(result, "UNSUPPORTED_PROTOCOL", PROTOCOL_VERSION);
        } else {
            result.unwrap();
        }
    }
}

/// The server selects a cipher suite the client lists only as an unknown
/// value, or a known one its raw list leaves out. The client rejects both;
/// with standard preferences the unlisted cipher passes this check and fails
/// only the server's signature, and relayed unchanged the ServerHello
/// completes the handshake.
#[test]
fn server_hello_selecting_an_unknown_or_unlisted_cipher_is_rejected() {
    for (raw, selected) in [
        (true, UNKNOWN_CIPHER),
        (true, AES_256_GCM),
        (false, AES_256_GCM),
        (true, AES_128_GCM),
    ] {
        let mut session = preserving(|ssl| {
            if raw {
                ssl.set_raw_cipher_list(&[UNKNOWN_CIPHER, AES_128_GCM])
                    .unwrap();
            }
        });
        let (result, seen) = session.relay(SERVER_HELLO, |message| {
            let mut hello = ServerHello::parse(message).unwrap();
            assert_eq!(hello.cipher, AES_128_GCM);
            hello.cipher = selected;
            hello.reencode(message).unwrap()
        });
        assert_eq!(seen, 1);
        let hellos = session.client_hellos();
        let offered = wire::ClientHello::parse(&hellos[0]).unwrap().ciphers;
        assert_eq!(offered.contains(&UNKNOWN_CIPHER), raw);
        match (raw, selected) {
            (true, AES_128_GCM) => result.unwrap(),
            (true, _) => {
                session.assert_rejected(result, "WRONG_CIPHER_RETURNED", ILLEGAL_PARAMETER);
            }
            _ => {
                session.assert_rejected(result, "BAD_SIGNATURE", DECRYPT_ERROR);
            }
        }
    }
}

/// The server's CertificateVerify claims a signature algorithm the client
/// lists only as a preserved unknown value. The client verifies the
/// certificate first, so its verifier ran and accepted, yet the handshake
/// fails at the algorithm check. Relabelled as another listed algorithm the
/// signature reaches verification and fails there; relayed unchanged, it
/// completes the handshake.
#[test]
fn certificate_verify_with_a_preserved_unknown_signature_algorithm_is_rejected() {
    for selected in [Some(UNKNOWN_SIGALG), Some(RSA_PSS_SHA384), None] {
        let verified = Arc::new(AtomicUsize::new(0));
        let counter = verified.clone();
        let mut session = preserving(|ssl| {
            ssl.set_raw_signature_algorithms(&[UNKNOWN_SIGALG, RSA_PSS_SHA256, RSA_PSS_SHA384])
                .unwrap();
            ssl.set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
                counter.fetch_add(1, SeqCst);
                Ok(())
            });
        });
        let (result, seen) = session.relay(CERTIFICATE_VERIFY, |message| {
            let (algorithm, signature) = wire::certificate_verify(message).unwrap();
            assert_eq!(algorithm, RSA_PSS_SHA256);
            wire::encode_certificate_verify(selected.unwrap_or(algorithm), signature)
        });
        assert_eq!(seen, 1);
        let listed = wire::u16_list(&session.offered(SIGNATURE_ALGORITHMS).unwrap(), 2);
        assert_eq!(
            listed.unwrap(),
            [UNKNOWN_SIGALG, RSA_PSS_SHA256, RSA_PSS_SHA384]
        );
        assert_eq!(verified.load(SeqCst), 1);
        match selected {
            Some(UNKNOWN_SIGALG) => {
                session.assert_rejected(result, "WRONG_SIGNATURE_TYPE", ILLEGAL_PARAMETER);
            }
            Some(_) => {
                session.assert_rejected(result, "BAD_SIGNATURE", DECRYPT_ERROR);
            }
            None => result.unwrap(),
        }
    }
}

/// The server must retry with P-256, but the relay makes its
/// HelloRetryRequest ask for a group the client lists only as a preserved
/// unknown value. The client cannot build that key share: it rejects the
/// request without writing a second ClientHello. Relayed unchanged, the retry
/// completes the handshake on P-256.
#[test]
fn hello_retry_request_for_a_preserved_unknown_group_is_rejected() {
    for rewrite in [true, false] {
        let server_ctx = server_context(|ctx| ctx.set_curves_list("P-256").unwrap());
        let mut session = preserving_with(&server_ctx, |ssl| {
            ssl.set_raw_supported_groups(&[UNKNOWN_GROUP, X25519, P256])
                .unwrap();
            ssl.set_raw_key_shares(&[X25519]).unwrap();
        });
        let mut retries = 0;
        let (result, _) = session.relay(SERVER_HELLO, |message| {
            if message[6..38] != HELLO_RETRY_REQUEST {
                return message.to_vec();
            }
            retries += 1;
            let hello = ServerHello::parse(message).unwrap();
            let selected = wire::find(&hello.extensions, KEY_SHARE).unwrap();
            assert_eq!(selected, P256.to_be_bytes());
            let group = if rewrite { UNKNOWN_GROUP } else { P256 };
            with_server_hello_extension(message, KEY_SHARE, &group.to_be_bytes())
        });
        assert_eq!(retries, 1);
        let hellos = session.client_hellos();
        let first = wire::ClientHello::parse(&hellos[0]).unwrap();
        let groups = wire::u16_list(first.extension(SUPPORTED_GROUPS).unwrap(), 2).unwrap();
        assert_eq!(groups, [UNKNOWN_GROUP, X25519, P256]);
        if rewrite {
            session.assert_rejected(result, "WRONG_CURVE", ILLEGAL_PARAMETER);
            assert_eq!(hellos.len(), 1);
        } else {
            result.unwrap();
            assert_eq!(hellos.len(), 2);
            let second = wire::ClientHello::parse(&hellos[1]).unwrap();
            let shares = wire::key_share_groups(second.extension(KEY_SHARE).unwrap());
            assert_eq!(shares.unwrap(), [P256]);
        }
    }
}

/// The server answers, in EncryptedExtensions, an extension the client sent
/// only as a preserved unknown body, or one it never sent: GREASE, or a known
/// extension it did not request. BoringSSL parses no answer to an extension it
/// did not build, so each is unsolicited. Relayed unchanged, the re-encoded
/// EncryptedExtensions complete the handshake.
#[test]
fn encrypted_extensions_answering_unbuilt_or_unsent_extensions_are_rejected() {
    for injected in [
        Some(UNKNOWN_EXTENSION),
        Some(GREASE_EXTENSION),
        Some(SIGNED_CERTIFICATE_TIMESTAMP),
        None,
    ] {
        let mut session = preserving(|ssl| ssl.set_extension_order(&[UNKNOWN_EXTENSION]).unwrap());
        let (result, seen) = session.relay(ENCRYPTED_EXTENSIONS, |message| {
            with_extra_encrypted_extension(message, injected.map(|id| (id, &[1, 2, 3][..])))
        });
        assert_eq!(seen, 1);
        assert_eq!(session.offered(UNKNOWN_EXTENSION).unwrap(), [1, 2, 3]);
        assert!(session.offered(GREASE_EXTENSION).is_none());
        assert!(session.offered(SIGNED_CERTIFICATE_TIMESTAMP).is_none());
        if let Some(id) = injected {
            let raised =
                session.assert_rejected(result, "UNEXPECTED_EXTENSION", UNSUPPORTED_EXTENSION);
            assert_eq!(raised[0].1.as_deref(), Some(&*format!("extension {id}")));
        } else {
            result.unwrap();
        }
    }
}

/// The same answer to the preserved unknown extension, in the ServerHello.
#[test]
fn server_hello_answering_a_preserved_unknown_extension_is_rejected() {
    for injected in [Some(UNKNOWN_EXTENSION), None] {
        let mut session = preserving(|ssl| ssl.set_extension_order(&[UNKNOWN_EXTENSION]).unwrap());
        let (result, seen) = session.relay(SERVER_HELLO, |message| {
            with_extra_server_hello_extension(message, injected.map(|id| (id, &[1, 2, 3][..])))
        });
        assert_eq!(seen, 1);
        assert_eq!(session.offered(UNKNOWN_EXTENSION).unwrap(), [1, 2, 3]);
        if let Some(id) = injected {
            let raised =
                session.assert_rejected(result, "UNEXPECTED_EXTENSION", UNSUPPORTED_EXTENSION);
            assert_eq!(raised[0].1.as_deref(), Some(&*format!("extension {id}")));
        } else {
            result.unwrap();
        }
    }
}

/// The server repeats an extension it answered in its ServerHello.
#[test]
fn server_hello_with_a_duplicate_extension_is_rejected() {
    for duplicated in [Some(SUPPORTED_VERSIONS), Some(KEY_SHARE), None] {
        let mut session = preserving(|_| {});
        let (result, seen) = session.relay(SERVER_HELLO, |message| {
            let hello = ServerHello::parse(message).unwrap();
            let copy = duplicated.map(|id| (id, wire::find(&hello.extensions, id).unwrap()));
            with_extra_server_hello_extension(message, copy)
        });
        assert_eq!(seen, 1);
        match duplicated {
            Some(_) => {
                session.assert_rejected(result, "DUPLICATE_EXTENSION", ILLEGAL_PARAMETER);
            }
            None => result.unwrap(),
        }
    }
}

/// The server repeats an extension it answered in its EncryptedExtensions.
/// BoringSSL's duplicate check there raises no reason of its own: the only
/// error is the generic extension parse failure, with a decode_error alert.
/// Each extension parses correctly alone, as the control shows, so only the
/// duplicate check can fail it.
#[test]
fn encrypted_extensions_with_a_duplicate_extension_are_rejected() {
    for duplicated in [Some(ALPN), Some(QUIC_TRANSPORT_PARAMETERS), None] {
        let mut session = preserving(|_| {});
        let (result, seen) = session.relay(ENCRYPTED_EXTENSIONS, |message| {
            let extensions = wire::encrypted_extensions(message).unwrap();
            let copy = duplicated.map(|id| (id, wire::find(&extensions, id).unwrap()));
            with_extra_encrypted_extension(message, copy)
        });
        assert_eq!(seen, 1);
        match duplicated {
            Some(_) => {
                let raised = session.assert_rejected(result, "PARSE_TLSEXT", DECODE_ERROR);
                assert_eq!(raised.len(), 1);
            }
            None => result.unwrap(),
        }
    }
}
