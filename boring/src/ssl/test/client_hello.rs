use std::sync::{Arc, Mutex};

use super::server::{Builder, Server};
use crate::ssl::{ExtensionType, Ssl, SslContext, SslCurve, SslMethod, SslVerifyMode, SslVersion};

const CONFIGURED: [SslCurve; 3] = [
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
];

/// Capture one extension body of the initial ClientHello of each connection.
fn capture_extension(server: &mut Builder, extension: ExtensionType) -> Arc<Mutex<Vec<Vec<u8>>>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let callback_captured = Arc::clone(&captured);
    server.ctx().set_select_certificate_callback(move |hello| {
        callback_captured
            .lock()
            .unwrap()
            .push(hello.get_extension(extension).unwrap().to_vec());
        Ok(())
    });
    captured
}

fn key_share_groups(body: &[u8]) -> Vec<u16> {
    let (length, mut entries) = body.split_at(2);
    assert_eq!(
        usize::from(u16::from_be_bytes([length[0], length[1]])),
        entries.len()
    );
    let mut groups = Vec::new();
    while let [a, b, l1, l2, rest @ ..] = entries {
        groups.push(u16::from_be_bytes([*a, *b]));
        entries = &rest[usize::from(u16::from_be_bytes([*l1, *l2]))..];
    }
    groups
}

fn signature_algorithms(body: &[u8]) -> Vec<u16> {
    let (length, list) = body.split_at(2);
    assert_eq!(
        usize::from(u16::from_be_bytes([length[0], length[1]])),
        list.len()
    );
    list.chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn group_id(curve: SslCurve) -> u16 {
    curve.0 as u16
}

#[test]
fn explicit_key_shares_are_sent_in_the_given_order() {
    let cases: [(Option<&[SslCurve]>, &[SslCurve]); 4] = [
        // The default offers the post-quantum group and one classical group.
        (None, &CONFIGURED[..2]),
        (Some(&CONFIGURED), &CONFIGURED),
        (Some(&CONFIGURED[1..]), &CONFIGURED[1..]),
        (Some(&CONFIGURED[2..]), &CONFIGURED[2..]),
    ];
    let mut server = Server::builder();
    server.expected_connections_count(cases.len());
    let captured = capture_extension(&mut server, ExtensionType::KEY_SHARE);
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_verify(SslVerifyMode::PEER);
    client.ctx().set_grease_enabled(false);
    client.ctx().set_curves(&CONFIGURED).unwrap();
    let client = client.build();
    for (shares, _) in cases {
        let mut connection = client.builder();
        if let Some(shares) = shares {
            connection.ssl().set_client_key_shares(shares).unwrap();
        }
        connection.connect();
    }

    let captured = captured.lock().unwrap();
    assert_eq!(captured.len(), cases.len());
    for ((shares, expected), body) in cases.iter().zip(captured.iter()) {
        let expected: Vec<u16> = expected.iter().copied().map(group_id).collect();
        assert_eq!(key_share_groups(body), expected, "requested: {shares:?}");
    }
}

#[test]
fn key_shares_must_be_an_ordered_subset_of_the_configured_groups() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_curves(&CONFIGURED[1..]).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    for invalid in [
        &[SslCurve::X25519_MLKEM768][..],
        &[SslCurve::SECP256R1, SslCurve::X25519][..],
        &[SslCurve::X25519, SslCurve::X25519][..],
    ] {
        assert!(ssl.set_client_key_shares(invalid).is_err(), "{invalid:?}");
    }
    ssl.set_client_key_shares(&[]).unwrap();
    ssl.set_client_key_shares(&CONFIGURED[1..]).unwrap();
}

#[test]
fn an_empty_key_share_list_still_completes_through_hello_retry() {
    let mut server = Server::builder();
    let captured = capture_extension(&mut server, ExtensionType::KEY_SHARE);
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_verify(SslVerifyMode::PEER);
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client.ctx().set_curves(&CONFIGURED).unwrap();
    let client = client.build();
    let mut connection = client.builder();
    connection.ssl().set_client_key_shares(&[]).unwrap();
    let stream = connection.connect();
    assert!(stream.ssl().used_hello_retry_request());

    let first = captured.lock().unwrap()[0].clone();
    assert_eq!(first, [0, 0]);
}

#[test]
fn signature_algorithms_grease_is_independent_of_grease() {
    let cases = [(false, false), (false, true), (true, false), (true, true)];
    let mut server = Server::builder();
    server.expected_connections_count(cases.len());
    let captured = capture_extension(&mut server, ExtensionType::SIGNATURE_ALGORITHMS);
    let server = server.build();
    for (grease, grease_sigalgs) in cases {
        let mut client = server.client_with_root_ca();
        client.ctx().set_verify(SslVerifyMode::PEER);
        client.ctx().set_grease_enabled(grease);
        client.ctx().set_grease_sigalgs_enabled(grease_sigalgs);
        client.connect();
    }

    let captured = captured.lock().unwrap();
    let lists: Vec<Vec<u16>> = captured
        .iter()
        .map(|body| signature_algorithms(body))
        .collect();
    for ((_, grease_sigalgs), list) in cases.iter().zip(&lists) {
        assert_eq!(is_grease(list[0]), *grease_sigalgs, "{list:x?}");
        assert!(!list[1..].iter().copied().any(is_grease), "{list:x?}");
        let real = &list[usize::from(*grease_sigalgs)..];
        assert_eq!(real, &lists[0][..], "only the GREASE value is added");
    }
}
