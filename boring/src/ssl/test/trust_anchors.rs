use std::sync::{Arc, Mutex};

use super::parse_client_hello_extension_order;
use super::server::Server;
use crate::ssl::{SslContext, SslMethod, SslVerifyMode, SslVersion};

#[test]
fn malformed_requested_trust_anchor_identifiers_are_rejected() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    for ids in [&[0][..], &[2, 1][..], &[1, 42, 0][..]] {
        assert!(ctx.set_requested_trust_anchors(ids).is_err());
    }
}

#[test]
fn requested_trust_anchors_are_emitted_with_their_length_and_order() {
    for (ids, expected) in [
        (None, None),
        (Some(&[][..]), Some(&[0, 0][..])),
        (
            Some(&[1, 42, 2, 17, 34][..]),
            Some(&[0, 5, 1, 42, 2, 17, 34][..]),
        ),
    ] {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let callback_captured = Arc::clone(&captured);
        let mut server = Server::builder();
        server.ctx().set_select_certificate_callback(move |hello| {
            callback_captured.lock().unwrap().push((
                hello.get_extension(51_764.into()).map(<[u8]>::to_vec),
                parse_client_hello_extension_order(hello.extensions()),
            ));
            Ok(())
        });
        let server = server.build();
        let mut client = server.client_with_root_ca();
        client.ctx().set_verify(SslVerifyMode::PEER);
        client
            .ctx()
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        client.ctx().set_extension_order(&[43, 51_764, 13]).unwrap();
        if let Some(ids) = ids {
            client.ctx().set_requested_trust_anchors(ids).unwrap();
        }
        let _ = client.connect();

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0.as_deref(), expected);
        let prefix: &[u16] = if ids.is_some() {
            &[43, 51_764, 13]
        } else {
            &[43, 13]
        };
        assert!(captured[0].1.starts_with(prefix));
    }
}

#[test]
fn connection_requested_ids_override_context_and_failed_updates_retain_them() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let observed = captured.clone();
    let mut server = Server::builder();
    server.expected_connections_count(3);
    server.ctx().set_select_certificate_callback(move |hello| {
        observed.lock().unwrap().push(
            hello
                .get_extension(crate::ssl::ExtensionType::TRUST_ANCHORS)
                .unwrap()
                .to_vec(),
        );
        Ok(())
    });
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_requested_trust_anchors(&[1, 42]).unwrap();
    client.ctx().set_verify(SslVerifyMode::PEER);
    let client = client.build();
    let mut first = client.builder();
    let mut input = vec![1, 17];
    first.ssl().set_requested_trust_anchors(&input).unwrap();
    input.fill(0);
    assert!(first.ssl().set_requested_trust_anchors(&[0]).is_err());
    first.connect();
    let mut empty = client.builder();
    empty.ssl().set_requested_trust_anchors(&[]).unwrap();
    empty.connect();
    client.builder().connect();
    assert_eq!(
        *captured.lock().unwrap(),
        vec![vec![0, 2, 1, 17], vec![0, 0], vec![0, 2, 1, 42]]
    );
}

#[test]
fn available_ids_reject_empty_and_malformed_lists_on_context_and_connection() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    for ids in [&[][..], &[0][..], &[2, 42][..]] {
        assert!(ctx.set_available_trust_anchors(ids).is_err());
    }
    ctx.set_available_trust_anchors(&[1, 42]).unwrap();
    let mut ssl = crate::ssl::Ssl::new(&ctx.build()).unwrap();
    for ids in [&[][..], &[0][..], &[2, 42][..]] {
        assert!(ssl.set_available_trust_anchors(ids).is_err());
    }
    ssl.set_available_trust_anchors(&[1, 17]).unwrap();
    assert!(ssl.peer_available_trust_anchors().is_empty());
    assert!(!ssl.peer_matched_trust_anchor());
}

#[test]
fn credential_selection_and_available_ids_are_visible_during_verification() {
    use super::credentials::credential;
    use crate::x509::X509StoreContext;
    for (requested, matched) in [(vec![1, 42], true), (vec![], false), (vec![1, 99], false)] {
        for available_source in [0, 1, 2] {
            let mut server = Server::builder();
            let cred = credential(&[42], true).build();
            server.ctx().add_credential(&cred).unwrap();
            drop(cred);
            if available_source != 0 {
                server.ctx().set_available_trust_anchors(&[1, 17]).unwrap();
                assert!(server.ctx().set_available_trust_anchors(&[]).is_err());
            }
            if available_source == 2 {
                server.ssl_cb(|ssl| {
                    ssl.set_available_trust_anchors(&[1, 42, 1, 99]).unwrap();
                    assert!(ssl.set_available_trust_anchors(&[]).is_err());
                });
            }
            let server = server.build();
            let mut client = server.client_with_root_ca();
            client
                .ctx()
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            client
                .ctx()
                .set_requested_trust_anchors(&requested)
                .unwrap();
            let capture = Arc::new(Mutex::new(None));
            let output = capture.clone();
            client
                .ctx()
                .set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                    *output.lock().unwrap() = Some((
                        ssl.peer_available_trust_anchors().to_vec(),
                        ssl.peer_matched_trust_anchor(),
                    ));
                    let cert = ssl.peer_certificate().unwrap();
                    X509StoreContext::new()
                        .unwrap()
                        .init(
                            ssl.ssl_context().cert_store(),
                            &cert,
                            ssl.peer_cert_chain().unwrap(),
                            |ctx| {
                                assert!(ctx.verify_cert()?);
                                Ok(())
                            },
                        )
                        .unwrap();
                    Ok(())
                });
            let stream = client.connect();
            let expected = match available_source {
                0 => vec![1, 42],
                1 => vec![1, 17],
                _ => vec![1, 42, 1, 99],
            };
            assert_eq!(*capture.lock().unwrap(), Some((expected, matched)));
            assert!(stream.ssl().peer_available_trust_anchors().is_empty());
            assert!(!stream.ssl().peer_matched_trust_anchor());
        }
    }
}

#[test]
fn certificate_properties_and_group_inclusions_drive_selection() {
    use super::credentials::credential;
    for use_properties in [false, true] {
        let mut server = Server::builder();
        let mut cred = credential(&[], true);
        if use_properties {
            cred.set_certificate_properties(&[0, 5, 0, 0, 0, 1, 42])
                .unwrap();
        } else {
            cred.set_trust_anchor_id(&[17]).unwrap();
            cred.set_trust_anchor_id(&[]).unwrap();
            cred.add_trust_anchor_group_inclusion(&[42], 1, 3).unwrap();
        }
        let cred = cred.build();
        server.ssl_cb(move |ssl| {
            ssl.add_credential(&cred).unwrap();
        });
        let server = server.build();
        let matched = Arc::new(Mutex::new(None));
        let capture = matched.clone();
        let mut client = server.client_with_root_ca();
        client
            .ctx()
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        client
            .ctx()
            .set_requested_trust_anchors(if use_properties {
                &[1, 42]
            } else {
                &[2, 42, 2]
            })
            .unwrap();
        // Preserve normal chain verification while observing the handshake.
        client
            .ctx()
            .set_verify_callback(SslVerifyMode::PEER, move |valid, ctx| {
                let ssl = ctx
                    .ex_data(crate::x509::X509StoreContext::ssl_idx().unwrap())
                    .unwrap();
                *capture.lock().unwrap() = Some(ssl.peer_matched_trust_anchor());
                valid
            });
        client.connect();
        assert_eq!(*matched.lock().unwrap(), Some(true));
    }
}

#[test]
fn verification_failure_can_capture_alternatives_and_retry_on_the_same_endpoint() {
    use super::credentials::credential;
    use crate::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        ssl::{Ssl, SslAlert, SslVerifyError},
        x509::{X509StoreContext, X509},
    };
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    // Prefer the trusted chain only if explicitly requested. The fallback is
    // signed by a different root that the client has not configured as trusted.
    let trusted = credential(&[42], true).build();
    let key = PKey::private_key_from_pem(include_bytes!("../../../test/key.pem")).unwrap();
    let original = X509::from_pem(include_bytes!("../../../test/cert.pem")).unwrap();
    let other_root = X509::from_pem(include_bytes!("../../../test/root-ca-2.pem")).unwrap();
    let other_key =
        PKey::private_key_from_pem(include_bytes!("../../../test/root-ca-2.key")).unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(original.serial_number()).unwrap();
    cert.set_subject_name(original.subject_name()).unwrap();
    cert.set_issuer_name(other_root.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    cert.sign(&other_key, MessageDigest::sha256()).unwrap();
    let mut fallback = credential(&[17], false);
    fallback.set_certificate_chain([cert.build()]).unwrap();
    let mut server = SslContext::builder(SslMethod::tls_server()).unwrap();
    server
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.add_credential(&trusted).unwrap();
    server.add_credential(&fallback.build()).unwrap();
    let server = server.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let first = listener.accept().unwrap().0;
        assert!(Ssl::new(&server).unwrap().accept(first).is_err());
        let second = listener.accept().unwrap().0;
        let mut stream = Ssl::new(&server).unwrap().accept(second).unwrap();
        stream.write_all(&[42]).unwrap();
    });
    let captured = Arc::new(Mutex::new(Vec::new()));
    let output = captured.clone();
    let mut client = SslContext::builder(SslMethod::tls_client()).unwrap();
    client.set_ca_file("test/root-ca.pem").unwrap();
    client.set_requested_trust_anchors(&[]).unwrap();
    client.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        output.lock().unwrap().push((
            ssl.peer_available_trust_anchors().to_vec(),
            ssl.peer_matched_trust_anchor(),
        ));
        let cert = ssl.peer_certificate().unwrap();
        let valid = X509StoreContext::new()
            .unwrap()
            .init(
                ssl.ssl_context().cert_store(),
                &cert,
                ssl.peer_cert_chain().unwrap(),
                |ctx| ctx.verify_cert(),
            )
            .unwrap();
        if valid {
            Ok(())
        } else {
            Err(SslVerifyError::Invalid(SslAlert::UNKNOWN_CA))
        }
    });
    let client = client.build();
    assert!(Ssl::new(&client)
        .unwrap()
        .connect(TcpStream::connect(address).unwrap())
        .is_err());
    assert_eq!(captured.lock().unwrap()[0], (vec![1, 42, 1, 17], false));
    // ID 42 is known locally to correspond to our configured root. The server's
    // advertisement alone must not cause ID 17 or its root to become trusted.
    let mut retry = Ssl::new(&client).unwrap();
    retry.set_requested_trust_anchors(&[1, 42]).unwrap();
    let mut stream = retry.connect(TcpStream::connect(address).unwrap()).unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [42]);
    assert_eq!(captured.lock().unwrap()[1], (vec![1, 42, 1, 17], true));
    worker.join().unwrap();
}

#[test]
fn clearing_a_trust_anchor_id_stops_matching_requests_for_that_id() {
    use super::credentials::credential;
    for clear in [false, true] {
        let mut builder = credential(&[17], true);
        if clear {
            builder.set_trust_anchor_id(&[]).unwrap();
        }
        let mut server = Server::builder();
        server.ctx().add_credential(&builder.build()).unwrap();
        let server = server.build();
        let observed = Arc::new(Mutex::new(None));
        let output = observed.clone();
        let mut client = server.client_with_root_ca();
        client
            .ctx()
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        client.ctx().set_requested_trust_anchors(&[1, 17]).unwrap();
        client
            .ctx()
            .set_verify_callback(SslVerifyMode::PEER, move |valid, ctx| {
                let ssl = ctx
                    .ex_data(crate::x509::X509StoreContext::ssl_idx().unwrap())
                    .unwrap();
                *output.lock().unwrap() = Some(ssl.peer_matched_trust_anchor());
                valid
            });
        // After clearing the ID, the matching-only credential is skipped and
        // the harness's legacy certificate provides the verified fallback.
        client.connect();
        assert_eq!(*observed.lock().unwrap(), Some(!clear));
    }
}
