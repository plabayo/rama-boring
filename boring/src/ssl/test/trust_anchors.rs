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
