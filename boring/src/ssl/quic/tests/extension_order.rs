//! Per-connection ClientHello extension order on QUIC handshakes.

use super::support::{settle, Peer};
use super::{connection, contexts, pump, Record};
use crate::{
    ffi,
    ssl::{
        quic::{EncryptionLevel, HandshakeStatus},
        Ssl, SslContext,
    },
};
use proptest::prelude::*;
use std::sync::{Arc, LazyLock};

const ALPN: u16 = 16;
const PRE_SHARED_KEY: u16 = 41;
const SUPPORTED_VERSIONS: u16 = 43;
const QUIC_TRANSPORT_PARAMETERS: u16 = 57;
const QUIC_TRANSPORT_PARAMETERS_LEGACY: u16 = 0xffa5;

/// The extension IDs of the ClientHello a client wrote at the Initial level.
fn client_hello_order(record: &Record) -> Vec<u16> {
    let bytes: Vec<_> = record
        .output
        .lock()
        .unwrap()
        .iter()
        .filter(|(level, _)| *level == EncryptionLevel::Initial)
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    assert_eq!(bytes[0], 1, "ClientHello handshake type");
    // Handshake header, legacy version and random precede the variable fields.
    let mut fields = &bytes[4 + 2 + 32..];
    fields = &fields[1 + usize::from(fields[0])..];
    let cipher_bytes = usize::from(u16::from_be_bytes([fields[0], fields[1]]));
    fields = &fields[2 + cipher_bytes..];
    fields = &fields[1 + usize::from(fields[0])..];
    let extension_bytes = usize::from(u16::from_be_bytes([fields[0], fields[1]]));
    fields = &fields[2..];
    assert_eq!(fields.len(), extension_bytes);
    let mut order = Vec::new();
    while !fields.is_empty() {
        let id = u16::from_be_bytes([fields[0], fields[1]]);
        let length = usize::from(u16::from_be_bytes([fields[2], fields[3]]));
        // GREASE values are fresh per connection; compare their positions.
        order.push(if is_grease(id) { GREASE } else { id });
        fields = &fields[4 + length..];
    }
    order
}

/// Marks a GREASE position in a parsed or expected extension order.
const GREASE: u16 = 0x0a0a;

fn is_grease(id: u16) -> bool {
    id & 0x0f0f == 0x0a0a && id >> 8 == id & 0xff
}

fn use_legacy_codepoint(peer: &mut Peer, legacy: bool) {
    peer.conn.ssl_mut().set_quic_use_legacy_codepoint(legacy);
}

/// Emits the first flight of a fresh client and returns its extension order.
fn emitted(ctx: &SslContext, legacy: bool, order: Option<&[u16]>) -> (Peer, Vec<u16>) {
    emitted_with(ctx, legacy, false, order)
}

fn emitted_with(
    ctx: &SslContext,
    legacy: bool,
    permute: bool,
    order: Option<&[u16]>,
) -> (Peer, Vec<u16>) {
    let mut client = Peer::quic(ctx, false);
    use_legacy_codepoint(&mut client, legacy);
    // The connection inherits this setting from its context; per-SSL order must win.
    client.conn.ssl_mut().set_permute_extensions(permute);
    if let Some(order) = order {
        client.conn.ssl_mut().set_extension_order(order).unwrap();
    }
    client.poll();
    let order = client_hello_order(&client.record);
    (client, order)
}

fn server_for(legacy: bool) -> Peer {
    let (_, server) = &*CONTEXTS;
    let mut server = Peer::quic(server, true);
    use_legacy_codepoint(&mut server, legacy);
    server
}

static CONTEXTS: LazyLock<(SslContext, SslContext)> = LazyLock::new(|| {
    let (client, server, _) = contexts();
    (client, server)
});

/// What a per-SSL order must emit: requested IDs first, deduplicated and
/// restricted to emitted extensions, with every GREASE codepoint a GREASE slot
/// at its position, then everything else in canonical order.
fn expected(requested: &[u16], canonical: &[u16]) -> Vec<u16> {
    let mut order = Vec::new();
    for id in requested {
        if is_grease(*id) {
            order.push(GREASE);
        } else if canonical.contains(id) && !order.contains(id) {
            order.push(*id);
        }
    }
    for id in canonical {
        if *id != GREASE && !order.contains(id) {
            order.push(*id);
        }
    }
    order
}

#[test]
fn per_session_order_preserves_resumption_and_transport_parameters() {
    let context_order = [SUPPORTED_VERSIONS, ALPN, QUIC_TRANSPORT_PARAMETERS];
    let (client_ctx, server_ctx, tickets) = super::contexts_with_order(Some(&context_order));

    for (index, order) in [
        Some([ALPN, QUIC_TRANSPORT_PARAMETERS, SUPPORTED_VERSIONS]),
        Some([QUIC_TRANSPORT_PARAMETERS, SUPPORTED_VERSIONS, ALPN]),
        None,
    ]
    .into_iter()
    .enumerate()
    {
        let resumed = index == 1;
        let c = Arc::new(Record::default());
        let s = Arc::new(Record::default());
        let mut client = connection(&client_ctx, false, c.clone());
        let mut server = connection(&server_ctx, true, s.clone());
        if let Some(order) = &order {
            client.ssl_mut().set_extension_order(order).unwrap();
        }
        if resumed {
            let ticket = tickets.lock().unwrap().take().expect("QUIC TLS ticket");
            // Same retained context and peer as the connection issuing this ticket.
            unsafe {
                client.ssl_mut().set_session(&ticket).unwrap();
            }
        }
        assert_eq!(
            client.handshake().unwrap(),
            if resumed {
                HandshakeStatus::EarlyData
            } else {
                HandshakeStatus::WantRead
            }
        );
        let emitted = client_hello_order(&c);
        assert_eq!(emitted[..3], order.unwrap_or(context_order));
        if resumed {
            // The PSK binder covers everything before it, so it stays last.
            assert_eq!(emitted.last(), Some(&PRE_SHARED_KEY));
        }
        assert!(client
            .ssl_mut()
            .set_extension_order(&context_order)
            .is_err());
        pump(&mut client, &mut server, &c, &s).unwrap();
        assert_eq!(client.ssl().session_reused(), resumed);
        assert_eq!(server.ssl().session_reused(), resumed);
        assert_eq!(client.early_data_accepted(), resumed);
        assert_eq!(client.peer_transport_parameters(), b"server parameters");
        assert_eq!(server.peer_transport_parameters(), b"client parameters");
        assert_eq!(client.ssl().selected_alpn_protocol(), Some(&b"h3"[..]));
        assert!(c.alerts.lock().unwrap().is_empty());
        assert!(s.alerts.lock().unwrap().is_empty());
    }
}

#[test]
fn both_transport_parameter_codepoints_can_be_ordered() {
    let (client_ctx, _) = &*CONTEXTS;
    for (legacy, id, other) in [
        (
            false,
            QUIC_TRANSPORT_PARAMETERS,
            QUIC_TRANSPORT_PARAMETERS_LEGACY,
        ),
        (
            true,
            QUIC_TRANSPORT_PARAMETERS_LEGACY,
            QUIC_TRANSPORT_PARAMETERS,
        ),
    ] {
        // Listing both codepoints is how a relay mirrors an unknown peer version.
        let (mut client, order) = emitted(client_ctx, legacy, Some(&[other, id, ALPN]));
        assert_eq!(order[..2], [id, ALPN]);
        assert!(!order.contains(&other));
        let mut server = server_for(legacy);
        settle(&mut client, &mut server, 13);
        assert!(
            client.is_complete() && server.is_complete(),
            "legacy={legacy}"
        );
        assert_eq!(
            client.conn.peer_transport_parameters(),
            b"server parameters"
        );
        assert_eq!(
            server.conn.peer_transport_parameters(),
            b"client parameters"
        );
    }
}

#[test]
fn empty_order_is_canonical_even_when_the_context_permutes() {
    let (client_ctx, _) = &*CONTEXTS;
    let (_, canonical) = emitted(client_ctx, false, None);
    let permuted: Vec<_> = (0..8)
        .map(|_| emitted_with(client_ctx, false, true, None).1)
        .collect();
    assert!(
        permuted.iter().any(|order| *order != canonical),
        "context permutation is inactive"
    );
    for _ in 0..8 {
        assert_eq!(
            emitted_with(client_ctx, false, true, Some(&[])).1,
            canonical
        );
    }
}

#[test]
fn a_later_order_replaces_the_earlier_one() {
    let (client_ctx, _) = &*CONTEXTS;
    let mut client = Peer::quic(client_ctx, false);
    let ssl = client.conn.ssl_mut();
    ssl.set_extension_order(&[ALPN, SUPPORTED_VERSIONS])
        .unwrap();
    ssl.set_extension_order(&[SUPPORTED_VERSIONS]).unwrap();
    client.poll();
    let (_, canonical) = emitted(client_ctx, false, None);
    assert_eq!(
        client_hello_order(&client.record),
        expected(&[SUPPORTED_VERSIONS], &canonical)
    );
}

#[test]
fn order_is_rejected_for_servers_started_handshakes_and_oversized_lists() {
    let (client_ctx, server_ctx) = &*CONTEXTS;
    let reason = |error: crate::error::ErrorStack| {
        let errors = error.errors();
        assert_eq!(errors.len(), 1, "{error}");
        errors[0].reason_code()
    };

    let mut client = Ssl::new(client_ctx).unwrap();
    client
        .set_extension_order(&[SUPPORTED_VERSIONS; 256])
        .unwrap();
    let overflow = reason(
        client
            .set_extension_order(&[SUPPORTED_VERSIONS; 257])
            .unwrap_err(),
    );
    assert_eq!(overflow, ffi::ERR_R_OVERFLOW & 0xfff);
    assert_eq!(
        ffi::RAMA_SSL_MAX_EXTENSION_ORDER,
        256,
        "documented bound changed"
    );

    let mut server = server_for(false);
    let state = reason(
        server
            .conn
            .ssl_mut()
            .set_extension_order(&[ALPN])
            .unwrap_err(),
    );
    assert_eq!(state, ffi::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED & 0xfff);

    let mut started = Peer::quic(client_ctx, false);
    started.poll();
    let before = client_hello_order(&started.record);
    assert!(started.conn.ssl_mut().set_extension_order(&[]).is_err());
    let mut server = Peer::quic(server_ctx, true);
    settle(&mut started, &mut server, 1200);
    assert!(started.is_complete());
    assert!(started.conn.ssl_mut().set_extension_order(&[]).is_err());
    assert_eq!(before, emitted(client_ctx, false, None).1);
}

#[test]
fn per_session_order_never_changes_the_shared_context() {
    let (client_ctx, _) = &*CONTEXTS;
    let (_, canonical) = emitted(client_ctx, false, None);
    let reversed: Vec<_> = canonical.iter().rev().copied().collect();
    let (_, ordered) = emitted(client_ctx, false, Some(&reversed));
    assert_eq!(ordered, reversed);
    assert_eq!(emitted(client_ctx, false, None).1, canonical);
}

/// IDs a captured ClientHello may carry: emitted, GREASE, known-but-absent and unknown.
fn requested_ids(canonical: Vec<u16>) -> impl Strategy<Value = Vec<u16>> {
    let id = prop_oneof![
        4 => proptest::sample::select(canonical),
        1 => (0u16..16).prop_map(|n| 0x0a0a + n * 0x1010),
        1 => Just(QUIC_TRANSPORT_PARAMETERS_LEGACY),
        1 => Just(PRE_SHARED_KEY),
        1 => any::<u16>(),
    ];
    proptest::collection::vec(id, 0..48)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn requested_order_then_canonical_is_emitted_and_completes(
        (requested, permuting, legacy, chunk) in {
            let (client_ctx, _) = &*CONTEXTS;
            let canonical = emitted(client_ctx, false, None).1;
            (requested_ids(canonical), any::<bool>(), any::<bool>(), 1usize..1400)
        }
    ) {
        let (client_ctx, _) = &*CONTEXTS;
        let canonical = emitted(client_ctx, legacy, None).1;
        let (mut client, order) = emitted_with(client_ctx, legacy, permuting, Some(&requested));
        prop_assert_eq!(&order, &expected(&requested, &canonical));
        let mut server = server_for(legacy);
        settle(&mut client, &mut server, chunk);
        prop_assert!(client.is_complete() && server.is_complete());
        prop_assert_eq!(client.conn.peer_transport_parameters(), b"server parameters");
        prop_assert_eq!(client.conn.ssl().selected_alpn_protocol(), Some(&b"h3"[..]));
    }
}

#[test]
fn structured_orders_cover_every_position_and_noise_placement() {
    // Systematic counterpart of the property test: every extension at the front
    // and at the back, every adjacent swap, duplicates and noise at every position,
    // on both transport parameter codepoints, with and without permutation.
    const NOISE: [u16; 4] = [0x0a0a, 0xfafa, 0xfeed, PRE_SHARED_KEY];
    let (client_ctx, _) = &*CONTEXTS;
    let mut cases = 0;
    for legacy in [false, true] {
        let canonical = emitted(client_ctx, legacy, None).1;
        let n = canonical.len();
        let mut requests: Vec<Vec<u16>> = vec![
            Vec::new(),
            canonical.clone(),
            canonical.iter().rev().copied().collect(),
        ];
        for i in 0..n {
            requests.push(vec![canonical[i]]);
            let mut last: Vec<_> = canonical.clone();
            let id = last.remove(i);
            last.push(id);
            requests.push(last);
            requests.push(vec![canonical[i], canonical[i], canonical[(i + 1) % n]]);
        }
        for i in 0..n - 1 {
            let mut swapped = canonical.clone();
            swapped.swap(i, i + 1);
            requests.push(swapped);
        }
        for noise in NOISE {
            for at in 0..=n {
                let mut noisy = canonical.iter().rev().copied().collect::<Vec<_>>();
                noisy.insert(at, noise);
                requests.push(noisy);
            }
        }
        for requested in &requests {
            for permute in [false, true] {
                let (_, order) = emitted_with(client_ctx, legacy, permute, Some(requested));
                assert_eq!(
                    order,
                    expected(requested, &canonical),
                    "legacy={legacy} permute={permute} requested={requested:?}"
                );
                cases += 1;
            }
        }
    }
    assert!(cases > 200, "{cases}");
}
