use super::server::Server;
use crate::asn1::Asn1Time;
use crate::bn::BigNum;
use crate::ec::{EcGroup, EcKey};
use crate::ecdsa::EcdsaSig;
use crate::hash::MessageDigest;
use crate::nid::Nid;
use crate::pkey::PKey;
use crate::ssl::{
    ExtensionType, SslContextBuilder, SslInfoCallbackMode, SslSignatureAlgorithm as Sig, SslVersion,
};
use crate::x509::{X509Name, X509};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

fn pin_version(ctx: &mut SslContextBuilder, version: SslVersion) {
    ctx.set_min_proto_version(Some(version)).unwrap();
    ctx.set_max_proto_version(Some(version)).unwrap();
}

fn capture_signature(ctx: &mut SslContextBuilder) -> Arc<Mutex<Option<Sig>>> {
    let captured = Arc::new(Mutex::new(None));
    let callback_captured = Arc::clone(&captured);
    ctx.set_info_callback(move |ssl, mode, _| {
        if mode == SslInfoCallbackMode::HANDSHAKE_DONE {
            *callback_captured.lock().unwrap() = ssl.signature_algorithm_used();
        }
    });
    captured
}

#[test]
fn legacy_rsa_ciphers_and_versions_exchange_records() {
    for version in [SslVersion::TLS1, SslVersion::TLS1_1, SslVersion::TLS1_2] {
        for cipher in [
            "DES-CBC3-SHA",
            "AES128-SHA",
            "AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
        ] {
            let mut server = Server::builder();
            pin_version(server.ctx(), version);
            server.ctx().set_strict_cipher_list(cipher).unwrap();
            let signature = capture_signature(server.ctx());
            server.io_cb(|mut stream| {
                let mut reply = [0; 4];
                stream.read_exact(&mut reply).unwrap();
                assert_eq!(&reply, b"rama");
            });
            let server = server.build();
            let mut client = server.client();
            pin_version(client.ctx(), version);
            client.ctx().set_strict_cipher_list(cipher).unwrap();
            let mut stream = client.connect();
            assert_eq!(stream.ssl().version(), Some(version));
            assert_eq!(stream.ssl().current_cipher().unwrap().name(), cipher);
            if cipher.starts_with("ECDHE") && version != SslVersion::TLS1_2 {
                assert_eq!(*signature.lock().unwrap(), Some(Sig::RSA_PKCS1_MD5_SHA1));
            }
            stream.write_all(b"rama").unwrap();
        }
    }
}

#[test]
fn legacy_tls12_signatures_are_negotiated() {
    for scheme in [
        Sig::RSA_PKCS1_SHA1,
        Sig::RSA_PKCS1_SHA256,
        Sig::RSA_PKCS1_SHA384,
        Sig::RSA_PKCS1_SHA512,
        Sig::ECDSA_SHA1,
        Sig::ECDSA_SECP256R1_SHA256,
        Sig::ECDSA_SECP384R1_SHA384,
        Sig::ECDSA_SECP521R1_SHA512,
    ] {
        let mut server = Server::builder();
        pin_version(server.ctx(), SslVersion::TLS1_2);
        let is_ecdsa = matches!(
            scheme,
            Sig::ECDSA_SHA1
                | Sig::ECDSA_SECP256R1_SHA256
                | Sig::ECDSA_SECP384R1_SHA384
                | Sig::ECDSA_SECP521R1_SHA512
        );
        let cipher = if is_ecdsa {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
            let mut name = X509Name::builder().unwrap();
            name.append_entry_by_text("CN", "localhost").unwrap();
            let name = name.build();
            let mut cert = X509::builder().unwrap();
            cert.set_version(2).unwrap();
            cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
                .unwrap();
            cert.set_subject_name(&name).unwrap();
            cert.set_issuer_name(&name).unwrap();
            cert.set_pubkey(&key).unwrap();
            cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
                .unwrap();
            cert.sign(&key, MessageDigest::sha256()).unwrap();
            server.ctx().set_certificate(&cert.build()).unwrap();
            server.ctx().set_private_key(&key).unwrap();
            "ECDHE-ECDSA-AES128-SHA"
        } else {
            "ECDHE-RSA-AES128-SHA"
        };
        server.ctx().set_strict_cipher_list(cipher).unwrap();
        let signature = capture_signature(server.ctx());
        let server = server.build();
        let mut client = server.client();
        pin_version(client.ctx(), SslVersion::TLS1_2);
        client.ctx().set_strict_cipher_list(cipher).unwrap();
        client.ctx().set_verify_algorithm_prefs(&[scheme]).unwrap();
        let stream = client.connect();
        assert_eq!(stream.ssl().peer_signature_algorithm(), Some(scheme));
        assert_eq!(*signature.lock().unwrap(), Some(scheme));
    }
}

#[test]
fn explicit_signature_order_survives_general_grease() {
    let schemes = [
        Sig::ECDSA_SHA1,
        Sig::RSA_PKCS1_SHA512,
        Sig::RSA_PKCS1_SHA1,
        Sig::RSA_PKCS1_SHA256,
    ];
    for grease in [false, true] {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let callback_captured = Arc::clone(&captured);
        let mut server = Server::builder();
        server.ctx().set_select_certificate_callback(move |hello| {
            *callback_captured.lock().unwrap() = hello
                .get_extension(ExtensionType::SIGNATURE_ALGORITHMS)
                .unwrap()
                .to_vec();
            Ok(())
        });
        let server = server.build();
        let mut client = server.client();
        pin_version(client.ctx(), SslVersion::TLS1_2);
        client.ctx().set_grease_enabled(grease);
        client.ctx().set_verify_algorithm_prefs(&schemes).unwrap();
        client.connect();
        assert_eq!(*captured.lock().unwrap(), [0, 8, 2, 3, 6, 1, 2, 1, 4, 1]);
    }
}

#[test]
fn legacy_p224_signatures_remain_available() {
    let group = EcGroup::from_curve_name(Nid::SECP224R1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let digest = crate::hash::hash(MessageDigest::sha1(), b"rama legacy signature").unwrap();
    let signature = EcdsaSig::sign(&digest, &key).unwrap();
    assert!(signature.verify(&digest, &key).unwrap());
    let wrong_digest = crate::hash::hash(MessageDigest::sha1(), b"different message").unwrap();
    assert!(!signature.verify(&wrong_digest, &key).unwrap());
}
