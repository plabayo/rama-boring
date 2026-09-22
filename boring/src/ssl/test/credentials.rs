use super::{private_key_method::Method, server::Server};
use crate::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer},
    ssl::{
        SslContext, SslCredential, SslCredentialBuilder, SslMethod, SslSignatureAlgorithm,
        SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub(super) fn credential(id: &[u8], must_match: bool) -> SslCredentialBuilder {
    let cert = X509::from_pem(include_bytes!("../../../test/cert.pem")).unwrap();
    let key = PKey::private_key_from_pem(include_bytes!("../../../test/key.pem")).unwrap();
    let mut builder = SslCredential::builder().unwrap();
    builder.set_certificate_chain([cert]).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.set_trust_anchor_id(id).unwrap();
    builder.set_must_match_issuer(must_match);
    builder
}

#[test]
fn credential_construction_validates_required_material_and_key_matching() {
    let mut builder = SslCredential::builder().unwrap();
    assert!(!builder.is_complete());
    assert!(builder.set_certificate_chain(Vec::<X509>::new()).is_err());
    let cert = X509::from_pem(include_bytes!("../../../test/cert.pem")).unwrap();
    builder.set_certificate_chain([&cert]).unwrap();
    assert!(!builder.is_complete());
    let wrong_key =
        PKey::private_key_from_pem(include_bytes!("../../../test/root-ca.key")).unwrap();
    assert!(builder.set_private_key(&wrong_key).is_err());
    let key = PKey::private_key_from_pem(include_bytes!("../../../test/key.pem")).unwrap();
    builder.set_private_key(&key).unwrap();
    assert!(builder.is_complete());
    let built = builder.build();
    assert!(built.is_complete());
    let cloned = built.clone();
    drop(built);
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.add_credential(&cloned).unwrap();
    let incomplete = SslCredential::builder().unwrap().build();
    assert!(ctx.add_credential(&incomplete).is_err());

    let mut key_first = SslCredential::builder().unwrap();
    key_first.set_private_key(&wrong_key).unwrap();
    assert!(key_first.set_certificate_chain([&cert]).is_err());
}

#[test]
fn certificate_properties_and_signing_preferences_preserve_native_errors() {
    for malformed in [
        &[][..],
        &[0][..],
        &[0, 5, 0, 0][..],
        &[0, 4, 0, 0, 0, 0][..],
        &[0, 10, 0, 0, 0, 1, 42, 0, 0, 0, 1, 17][..],
    ] {
        assert!(credential(&[], false)
            .set_certificate_properties(malformed)
            .is_err());
    }
    let mut builder = credential(&[], false);
    builder.set_certificate_properties(&[0, 0]).unwrap();
    builder
        .set_certificate_properties(&[0, 5, 0, 0, 0, 1, 42])
        .unwrap();
    builder
        .set_signing_algorithm_prefs(&[SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256])
        .unwrap();
    assert!(builder
        .set_signing_algorithm_prefs(&[SslSignatureAlgorithm::RSA_PKCS1_MD5_SHA1])
        .is_err());
}

#[test]
fn credential_owned_private_key_method_and_metadata_survive_the_builder() {
    let selected = Arc::new(AtomicUsize::new(0));
    let observed = selected.clone();
    let index = SslCredential::new_ex_index::<usize>().unwrap();
    let mut builder = credential(&[], false);
    builder.replace_ex_data(index, 17);
    assert_eq!(builder.replace_ex_data(index, 42), Some(17));
    builder
        .set_signing_algorithm_prefs(&[SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256])
        .unwrap();
    builder
        .set_ocsp_response(b"credential-specific OCSP")
        .unwrap();
    builder
        .set_signed_cert_timestamp_list(&[0, 3, 0, 1, 42])
        .unwrap();
    builder
        .set_private_key_method(Method::new().sign(move |ssl, input, algorithm, output| {
            assert_eq!(algorithm, SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256);
            let marker = *ssl.selected_credential().unwrap().ex_data(index).unwrap();
            observed.store(marker, Ordering::SeqCst);
            let key = PKey::private_key_from_pem(include_bytes!("../../../test/key.pem")).unwrap();
            let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
            signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .unwrap();
            signer.update(input).unwrap();
            Ok(signer.sign(output).unwrap())
        }))
        .unwrap();
    let cred = builder.build();
    let mut server = Server::builder();
    // The same server that exposed its selected credential during signing must
    // stop exposing it after the handshake finishes.
    server.io_cb(|stream| assert!(stream.ssl().selected_credential().is_none()));
    // Same Rust callback type on the context must not override credential state.
    server.ctx().set_private_key_method(Method::new());
    server.ctx().add_credential(&cred).unwrap();
    drop(cred);
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_verify(SslVerifyMode::PEER);
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client.ctx().enable_ocsp_stapling();
    client.ctx().enable_signed_cert_timestamps();
    let stream = client.connect();
    assert_eq!(selected.load(Ordering::SeqCst), 42);
    assert_eq!(
        stream.ssl().ocsp_status(),
        Some(&b"credential-specific OCSP"[..])
    );
    assert_eq!(
        stream.ssl().signed_cert_timestamp_list(),
        Some(&[0, 3, 0, 1, 42][..])
    );
}

#[test]
fn credential_owned_private_key_method_survives_async_completion() {
    use crate::ssl::{HandshakeError, PrivateKeyMethodError};
    use std::{io::Write, sync::OnceLock};

    let input = Arc::new(OnceLock::new());
    let input_for_sign = input.clone();
    let completed = Arc::new(AtomicUsize::new(0));
    let observed = completed.clone();
    let index = SslCredential::new_ex_index::<usize>().unwrap();
    let mut builder = credential(&[], false);
    builder.replace_ex_data(index, 42);
    builder
        .set_signing_algorithm_prefs(&[SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256])
        .unwrap();
    builder
        .set_private_key_method(
            Method::new()
                .sign(move |ssl, bytes, algorithm, _| {
                    assert_eq!(algorithm, SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256);
                    assert_eq!(ssl.selected_credential().unwrap().ex_data(index), Some(&42));
                    input_for_sign.set(bytes.to_vec()).unwrap();
                    Err(PrivateKeyMethodError::RETRY)
                })
                .complete(move |ssl, output| {
                    assert_eq!(ssl.selected_credential().unwrap().ex_data(index), Some(&42));
                    let key = PKey::private_key_from_pem(include_bytes!("../../../test/key.pem"))
                        .unwrap();
                    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
                    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                    signer
                        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                        .unwrap();
                    signer.update(input.get().unwrap()).unwrap();
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(signer.sign(output).unwrap())
                }),
        )
        .unwrap();
    let cred = builder.build();
    let mut server = Server::builder();
    server.ctx().set_private_key_method(Method::new());
    server.ctx().add_credential(&cred).unwrap();
    drop(cred);
    server.err_cb(|error| {
        let HandshakeError::WouldBlock(handshake) = error else {
            panic!("expected pending private key operation");
        };
        let mut stream = handshake.handshake().unwrap();
        stream.write_all(&[0]).unwrap();
    });
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_verify(SslVerifyMode::PEER);
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client.connect();
    assert_eq!(completed.load(Ordering::SeqCst), 1);
}

#[test]
fn multi_certificate_chains_are_retained_and_replacement_removes_old_entries() {
    for replace_with_leaf in [false, true] {
        let chain = X509::stack_from_pem(include_bytes!("../../../test/certs.pem")).unwrap();
        assert!(chain.len() > 1);
        let mut builder = credential(&[], false);
        builder.set_certificate_chain(&chain).unwrap();
        let expected_chain = if replace_with_leaf {
            builder.set_certificate_chain(&chain[..1]).unwrap();
            &chain[..1]
        } else {
            &chain[..]
        };
        let expected: Vec<_> = expected_chain
            .iter()
            .map(|cert| cert.to_der().unwrap())
            .collect();
        drop(chain);
        let cred = builder.build();
        let mut server = Server::builder();
        server.ctx().add_credential(&cred).unwrap();
        drop(cred);
        let server = server.build();
        let mut client = server.client_with_root_ca();
        client.ctx().set_verify(SslVerifyMode::PEER);
        let stream = client.connect();
        let actual: Vec<_> = stream
            .ssl()
            .peer_cert_chain()
            .unwrap()
            .iter()
            .map(|cert| cert.to_der().unwrap())
            .collect();
        assert_eq!(actual, expected);
    }
}
