//! Decode emitted messages independently of BoringSSL's ECH implementation.
use super::{memory, wire};
use crate::ssl::{
    ClientHelloShape, EchGreaseCipherSuite, EchGreaseShape, GreaseValues, Ssl, SslContentType,
    SslCurve, SslVersion,
};
use foreign_types::ForeignTypeRef;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Outer {
    pub(crate) kdf: u16,
    pub(crate) aead: u16,
    config_id: u8,
    pub(crate) enc: Vec<u8>,
    pub(crate) payload: Vec<u8>,
}

impl Outer {
    pub(crate) fn parse(message: &[u8]) -> Option<Self> {
        let hello = wire::ClientHello::parse(message).expect("valid ClientHello");
        let (_, body) = hello.extensions.iter().find(|(id, _)| *id == 0xfe0d)?;
        let mut reader = wire::Reader::new(body);
        assert_eq!(reader.u8(), Some(0));
        let outer = Self {
            kdf: reader.u16().unwrap(),
            aead: reader.u16().unwrap(),
            config_id: reader.u8().unwrap(),
            enc: reader.prefixed_u16().unwrap().rest().to_vec(),
            payload: reader.prefixed_u16().unwrap().rest().to_vec(),
        };
        reader.finish().unwrap();
        Some(outer)
    }
}

pub(crate) fn observe(ssl: &mut crate::ssl::SslRef) -> Arc<Mutex<Vec<Option<Outer>>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    ssl.set_msg_callback(move |_, msg| {
        if msg.is_written()
            && msg.content_type() == SslContentType::HANDSHAKE
            && msg.handshake_type() == Some(1)
        {
            sink.lock().unwrap().push(Outer::parse(msg.bytes()));
        }
    });
    seen
}

fn client() -> Ssl {
    let mut ssl = Ssl::new(&memory::client_context().build()).unwrap();
    ssl.set_curves(&[SslCurve::X25519, SslCurve::SECP256R1])
        .unwrap();
    ssl
}

fn apply(ssl: &mut crate::ssl::SslRef, suite: EchGreaseCipherSuite, length: usize) {
    ssl.set_client_hello_shape(
        &ClientHelloShape::new()
            .with_grease_values(GreaseValues::Seeded(7))
            .with_ech_grease(Some(EchGreaseShape::new(suite, length).unwrap())),
    )
    .unwrap();
}

fn complete(mut ssl: Ssl) -> Vec<Option<Outer>> {
    let seen = observe(&mut ssl);
    let (client, server) =
        memory::handshake(ssl, Ssl::new(&memory::server_context().build()).unwrap());
    assert!(!client.done().ssl().ech_accepted());
    server.done();
    let result = seen.lock().unwrap().clone();
    result
}

#[test]
fn ech_grease_shapes_are_exact_and_fresh() {
    for suite in [
        EchGreaseCipherSuite::HkdfSha256Aes128Gcm,
        EchGreaseCipherSuite::HkdfSha256Aes256Gcm,
        EchGreaseCipherSuite::HkdfSha256ChaCha20Poly1305,
    ] {
        for length in [16, 17, 144, 208, 240] {
            let mut samples = Vec::new();
            for _ in 0..16 {
                let mut ssl = client();
                ssl.set_enable_ech_grease(true);
                apply(&mut ssl, suite, length);
                let mut seen = complete(ssl);
                assert_eq!(seen.len(), 1);
                let outer = seen.pop().unwrap().unwrap();
                assert_eq!((outer.kdf, outer.aead), suite.ids());
                assert_eq!(outer.enc.len(), 32);
                assert_eq!(outer.payload.len(), length);
                for previous in &samples {
                    let previous: &Outer = previous;
                    assert_ne!(outer.enc, previous.enc);
                    assert_ne!(outer.payload, previous.payload);
                }
                samples.push(outer);
            }
            assert!(samples.iter().any(|s| s.config_id != samples[0].config_id));
        }
    }
}

#[test]
fn ech_grease_defaults_clear_and_enablement() {
    for clear in [false, true] {
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..32 {
            let mut ssl = client();
            ssl.set_enable_ech_grease(true);
            if clear {
                apply(&mut ssl, EchGreaseCipherSuite::HkdfSha256Aes256Gcm, 17);
                ssl.set_client_hello_shape(&ClientHelloShape::new())
                    .unwrap();
            }
            let seen = complete(ssl);
            let outer = seen[0].as_ref().unwrap();
            assert_eq!(outer.kdf, 1);
            assert!([1, 3].contains(&outer.aead));
            assert_eq!(outer.enc.len(), 32);
            assert!([144, 176, 208, 240].contains(&outer.payload.len()));
            lengths.insert(outer.payload.len());
        }
        assert!(lengths.len() > 1, "default still randomizes payload size");
    }
    for disabled in [false, true] {
        let mut ssl = client();
        apply(&mut ssl, EchGreaseCipherSuite::HkdfSha256Aes128Gcm, 144);
        if disabled {
            ssl.set_enable_ech_grease(true);
            ssl.set_enable_ech_grease(false);
        }
        assert_eq!(complete(ssl), [None]);
    }
    let mut ssl = client();
    apply(&mut ssl, EchGreaseCipherSuite::HkdfSha256Aes128Gcm, 144);
    ssl.set_enable_ech_grease(true);
    ssl.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    assert_eq!(complete(ssl), [None]);
}

#[test]
fn ech_grease_invalid_shapes_and_lifecycle() {
    for (kdf, aead, enc, payload) in [
        (0, 1, 32, 144),
        (2, 1, 32, 144),
        (1, 0, 32, 144),
        (1, 4, 32, 144),
        (1, 1, 0, 144),
        (1, 1, 31, 144),
        (1, 1, 33, 144),
        (1, 1, 32, 0),
        (1, 1, 32, 15),
        (1, 1, 32, 65490),
        (1, 1, 32, usize::MAX),
    ] {
        assert!(EchGreaseShape::from_wire(kdf, aead, enc, payload).is_err());
    }
    for length in [16, 65489] {
        let shape = EchGreaseShape::from_wire(1, 2, 32, length).unwrap();
        assert_eq!(shape.payload_len(), length);
        assert_eq!(shape.cipher_suite().ids(), (1, 2));
    }
    let shape = ClientHelloShape::new()
        .with_ech_grease(Some(EchGreaseShape::from_wire(1, 1, 32, 144).unwrap()));
    let mut ssl = client();
    unsafe {
        crate::ffi::SSL_set_accept_state(ssl.as_ptr());
    }
    assert!(ssl.set_client_hello_shape(&shape).is_err());
    let mut ssl = client();
    ssl.set_enable_ech_grease(true);
    ssl.set_client_hello_shape(&shape).unwrap();
    let (a, _b) = memory::ends();
    let Err(crate::ssl::HandshakeError::WouldBlock(mut mid)) = ssl.connect(a) else {
        panic!("expected pending handshake");
    };
    assert!(mid.ssl_mut().set_client_hello_shape(&shape).is_err());
}

#[test]
fn ech_grease_large_payload_is_encoded_exactly() {
    let mut ssl = client();
    ssl.set_enable_ech_grease(true);
    apply(&mut ssl, EchGreaseCipherSuite::HkdfSha256Aes128Gcm, 65_000);
    let seen = observe(&mut ssl);
    let (a, _b) = memory::ends();
    // Inspect the first flight only: ordinary servers may impose a smaller
    // handshake message limit (BoringSSL defaults to 16 KiB).
    assert!(matches!(
        ssl.connect(a),
        Err(crate::ssl::HandshakeError::WouldBlock(_))
    ));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].as_ref().unwrap().payload.len(), 65_000);
}

#[test]
fn ech_grease_oversized_hello_fails_before_output() {
    use std::io::Read;
    let mut ssl = client();
    ssl.set_enable_ech_grease(true);
    apply(
        &mut ssl,
        EchGreaseCipherSuite::HkdfSha256Aes128Gcm,
        EchGreaseShape::MAX_PAYLOAD_LEN,
    );
    let seen = observe(&mut ssl);
    let (a, mut b) = memory::ends();
    assert!(matches!(
        ssl.connect(a),
        Err(crate::ssl::HandshakeError::Failure(_))
    ));
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(
        b.read(&mut [0u8; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn ech_grease_hrr_reuses_extension_and_freezes_shape() {
    let mut ssl = client();
    ssl.set_enable_ech_grease(true);
    apply(&mut ssl, EchGreaseCipherSuite::HkdfSha256Aes256Gcm, 208);
    ssl.set_raw_key_shares(&[]).unwrap();
    let seen = observe(&mut ssl);
    let (client, server) =
        memory::handshake(ssl, Ssl::new(&memory::server_context().build()).unwrap());
    let mut client = client.done();
    server.done();
    assert!(client.ssl().used_hello_retry_request());
    assert!(client
        .ssl_mut()
        .set_client_hello_shape(&ClientHelloShape::new())
        .is_err());
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], seen[1]);
    let outer = seen[0].as_ref().unwrap();
    assert_eq!(
        (outer.kdf, outer.aead, outer.enc.len(), outer.payload.len()),
        (1, 2, 32, 208)
    );
}

#[test]
fn ech_grease_unusable_real_config_falls_back() {
    let mut ssl = client();
    ssl.set_enable_ech_grease(true);
    // A syntactically valid list containing an unknown ECH version.
    ssl.set_ech_config_list(&[0, 4, 0xba, 0xdc, 0, 0]).unwrap();
    apply(&mut ssl, EchGreaseCipherSuite::HkdfSha256Aes256Gcm, 17);
    let seen = complete(ssl);
    let outer = seen[0].as_ref().unwrap();
    assert_eq!((outer.kdf, outer.aead, outer.payload.len()), (1, 2, 17));
}

#[test]
fn ech_grease_shape_preserves_unusable_config_rejection_policy() {
    use std::io::Read;
    let mut ssl = client();
    ssl.set_enable_ech_grease(true);
    ssl.set_ech_config_list(&[0, 4, 0xba, 0xdc, 0, 0]).unwrap();
    unsafe {
        crate::ffi::SSL_set_reject_unusable_ech_config(ssl.as_ptr(), 1);
    }
    apply(&mut ssl, EchGreaseCipherSuite::HkdfSha256Aes128Gcm, 144);
    let seen = observe(&mut ssl);
    let (a, mut b) = memory::ends();
    assert!(matches!(
        ssl.connect(a),
        Err(crate::ssl::HandshakeError::Failure(_))
    ));
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(
        b.read(&mut [0u8; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
