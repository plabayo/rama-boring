//! RFC 7919 finite field groups in a TLS 1.3 key_share: off by default, and
//! negotiable once a caller lists them.

use super::memory::{
    client_context, ends, handshake, replace_extension, rewrite_server_hello, server_context,
    Buffer, End, Side,
};
use super::wire;
use crate::bn::{BigNum, BigNumContext};
use crate::ssl::{Ssl, SslContentType, SslContext, SslCurve, SslOptions, SslStream, SslVersion};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

const X25519: u16 = 0x001d;
const KEY_SHARE: u16 = 51;
const ILLEGAL_PARAMETER_ALERT: [u8; 2] = [2, 47];
const INTERNAL_ERROR_ALERT: [u8; 2] = [2, 80];

// The primes of RFC 7919, appendix A.1 and A.2, as printed there.
const FFDHE2048_P: &str = concat!(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695",
    "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A",
    "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935",
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A",
    "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4",
    "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61",
    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005",
    "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF",
);

const FFDHE3072_P: &str = concat!(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695",
    "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A",
    "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935",
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A",
    "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4",
    "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61",
    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005",
    "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B",
    "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C",
    "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF",
    "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E",
    "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF",
);

struct Group {
    id: u16,
    curve: SslCurve,
    name: &'static str,
    p: &'static str,
}

const GROUPS: &[Group] = &[
    Group {
        id: 0x0100,
        curve: SslCurve::FFDHE2048,
        name: "ffdhe2048",
        p: FFDHE2048_P,
    },
    Group {
        id: 0x0101,
        curve: SslCurve::FFDHE3072,
        name: "ffdhe3072",
        p: FFDHE3072_P,
    },
];

impl Group {
    fn p(&self) -> BigNum {
        BigNum::from_hex_str(self.p).unwrap()
    }

    fn len(&self) -> usize {
        self.p.len() / 2
    }
}

fn client(version: SslVersion, groups: &[u16], key_shares: &[u16]) -> Ssl {
    let mut ctx = client_context();
    ctx.set_max_proto_version(Some(version)).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_raw_supported_groups(groups).unwrap();
    if version == SslVersion::TLS1_3 {
        ssl.set_raw_key_shares(key_shares).unwrap();
    }
    ssl
}

fn server(curves: &[SslCurve]) -> SslContext {
    let mut ctx = server_context();
    ctx.set_curves(curves).unwrap();
    ctx.build()
}

/// Every alert a side wrote.
type Alerts = Arc<Mutex<Vec<Vec<u8>>>>;

fn alerts(ssl: &mut Ssl) -> Alerts {
    let alerts = Alerts::default();
    let sink = alerts.clone();
    ssl.set_msg_callback(move |_, message| {
        if message.is_written() && message.content_type() == SslContentType::ALERT {
            sink.lock().unwrap().push(message.bytes().to_vec());
        }
    });
    alerts
}

fn send(from: &mut SslStream<End>, to: &mut SslStream<End>, len: usize) {
    let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
    from.write_all(&data).unwrap();
    let mut read = vec![0; len];
    to.read_exact(&mut read).unwrap();
    assert_eq!(read, data);
}

#[test]
fn each_group_negotiates_tls13_and_exchanges_data() {
    for group in GROUPS {
        let server = server(&[group.curve]);
        // A key share up front, and one after a HelloRetryRequest.
        for (key_shares, retry) in [(&[group.id][..], false), (&[X25519][..], true)] {
            let client = client(SslVersion::TLS1_3, &[X25519, group.id], key_shares);
            let (client, server) = handshake(client, Ssl::new(&server).unwrap());
            let (mut client, mut server) = (client.done(), server.done());
            for side in [client.ssl(), server.ssl()] {
                assert_eq!(side.version(), Some(SslVersion::TLS1_3));
                assert_eq!(side.curve(), Some(group.curve));
            }
            assert_eq!(client.ssl().used_hello_retry_request(), retry);
            for len in [1, 100, 5000] {
                send(&mut client, &mut server, len);
                send(&mut server, &mut client, len);
            }
        }
        assert_eq!(group.curve.name(), Some(group.name));
    }
}

/// The entries of a ClientHello key_share body.
fn client_key_shares(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut reader = wire::Reader::new(body);
    let mut entries = reader.prefixed_u16().unwrap();
    reader.finish().unwrap();
    let mut out = Vec::new();
    while !entries.is_empty() {
        let id = entries.u16().unwrap();
        out.push((id, entries.prefixed_u16().unwrap().rest().to_vec()));
    }
    out
}

fn encode_client_key_shares(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut list = Vec::new();
    for (id, key) in entries {
        list.extend(id.to_be_bytes());
        list.extend(u16::try_from(key.len()).unwrap().to_be_bytes());
        list.extend(key);
    }
    [&u16::try_from(list.len()).unwrap().to_be_bytes()[..], &list].concat()
}

/// A public value of the RFC group: p bytes long, 1 < Y < p-1 and in the
/// order-q subgroup, which a value computed modulo any other prime fails.
#[track_caller]
fn check_public_value(group: &Group, y: &[u8]) {
    assert_eq!(y.len(), group.len());
    let p = group.p();
    let y = BigNum::from_slice(y).unwrap();
    let mut p_minus_1 = p.to_owned().unwrap();
    p_minus_1.sub_word(1).unwrap();
    assert!(y > BigNum::from_u32(1).unwrap());
    assert!(y < p_minus_1);
    let mut q = BigNum::new().unwrap();
    q.rshift1(&p).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut r = BigNum::new().unwrap();
    r.mod_exp(&y, &q, &p, &mut ctx).unwrap();
    assert_eq!(r, BigNum::from_u32(1).unwrap());
}

#[test]
fn rfc_primes_are_safe_primes() {
    let mut ctx = BigNumContext::new().unwrap();
    for group in GROUPS {
        let p = group.p();
        assert_eq!(usize::try_from(p.num_bytes()).unwrap(), group.len());
        let mut q = BigNum::new().unwrap();
        q.rshift1(&p).unwrap();
        assert!(p.is_prime(20, &mut ctx).unwrap(), "{}", group.name);
        assert!(q.is_prime(20, &mut ctx).unwrap(), "{}", group.name);
    }
}

/// Both public values belong to the group printed in the RFC.
#[test]
fn key_shares_lie_in_the_rfc_groups() {
    for group in GROUPS {
        let mut ssl = client(SslVersion::TLS1_3, &[group.id], &[group.id]);
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sink = messages.clone();
        ssl.set_msg_callback(move |_, message| {
            if message.handshake_type().is_some() {
                sink.lock()
                    .unwrap()
                    .push((message.is_written(), message.bytes().to_vec()));
            }
        });
        let server = server(&[group.curve]);
        handshake(ssl, Ssl::new(&server).unwrap()).0.done();
        let messages = messages.lock().unwrap();
        let hello = &messages
            .iter()
            .find(|(out, m)| *out && m[0] == 1)
            .unwrap()
            .1;
        let hello = wire::ClientHello::parse(hello).unwrap();
        let shares = client_key_shares(hello.extension(KEY_SHARE).unwrap());
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].0, group.id);
        check_public_value(group, &shares[0].1);
        let reply = &messages
            .iter()
            .find(|(out, m)| !*out && m[0] == 2)
            .unwrap()
            .1;
        let reply = wire::ServerHello::parse(reply).unwrap();
        let (id, y) =
            wire::server_key_share(wire::find(&reply.extensions, KEY_SHARE).unwrap()).unwrap();
        assert_eq!(id, group.id);
        check_public_value(group, y);
    }
}

/// Malformed public values: wrong lengths, and values outside 1 < Y < p-1.
fn malformed(group: &Group) -> Vec<(&'static str, Vec<u8>)> {
    let len = group.len();
    let p = group.p();
    let mut p_minus_1 = p.to_owned().unwrap();
    p_minus_1.sub_word(1).unwrap();
    let value = |n: &BigNum| n.to_vec_padded(len).unwrap();
    let mut one = vec![0; len];
    one[len - 1] = 1;
    vec![
        ("DH_PUBLIC_VALUE_LENGTH_IS_WRONG", vec![1]),
        ("DH_PUBLIC_VALUE_LENGTH_IS_WRONG", vec![2; len - 1]),
        ("DH_PUBLIC_VALUE_LENGTH_IS_WRONG", vec![2; len + 1]),
        ("INVALID_PUBKEY", vec![0; len]),
        ("INVALID_PUBKEY", one),
        ("INVALID_PUBKEY", value(&p_minus_1)),
        ("INVALID_PUBKEY", value(&p)),
        ("INVALID_PUBKEY", vec![0xff; len]),
    ]
}

/// Replaces the key_share body of the ClientHello at the front of a server's
/// pending input.
fn rewrite_client_key_share(rx: &Buffer, body: &[u8]) {
    let mut rx = rx.lock().unwrap();
    let bytes: Vec<u8> = rx.drain(..).collect();
    let message = wire::first_record_message(&bytes).unwrap();
    let mut hello = wire::ClientHello::parse(message).unwrap();
    for (id, ext) in hello.extensions.iter_mut() {
        if *id == KEY_SHARE {
            *ext = body;
        }
    }
    let rewritten = hello.encode();
    let end = 5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    assert_eq!(end, 5 + message.len(), "one ClientHello per record");
    let len = u16::try_from(rewritten.len()).unwrap().to_be_bytes();
    rx.extend(&bytes[..3]);
    rx.extend(len);
    rx.extend(rewritten);
    rx.extend(&bytes[end..]);
}

#[track_caller]
fn failed_with(side: &Side<End>, reason: &str) {
    side.panicked_or_failed_with(reason);
}

#[test]
fn malformed_client_shares_are_rejected() {
    for group in GROUPS {
        let server_ctx = server(&[group.curve]);
        for (reason, bad) in malformed(group) {
            let (a, b) = ends();
            let server_rx = b.rx.clone();
            let _client =
                Side::from(client(SslVersion::TLS1_3, &[group.id], &[group.id]).connect(a));
            let body = encode_client_key_shares(&[(group.id, bad.clone())]);
            rewrite_client_key_share(&server_rx, &body);
            let mut server = Ssl::new(&server_ctx).unwrap();
            let alerts = alerts(&mut server);
            let server = Side::from(server.accept(b));
            failed_with(&server, reason);
            assert_eq!(
                *alerts.lock().unwrap(),
                [ILLEGAL_PARAMETER_ALERT],
                "{reason}"
            );
        }
    }
}

#[test]
fn malformed_server_shares_are_rejected() {
    for group in GROUPS {
        let server_ctx = server(&[group.curve]);
        for (reason, bad) in malformed(group) {
            let (a, b) = ends();
            let client_rx = a.rx.clone();
            let mut ssl = client(SslVersion::TLS1_3, &[group.id], &[group.id]);
            let alerts = alerts(&mut ssl);
            let client = Side::from(ssl.connect(a));
            let _server = Side::from(Ssl::new(&server_ctx).unwrap().accept(b));
            let body = wire::encode_server_key_share(group.id, &bad);
            rewrite_server_hello(&client_rx, |_, extensions| {
                replace_extension(extensions, KEY_SHARE, &body);
            });
            failed_with(&client.step(), reason);
            // A client reports any failed key share as an internal error, for
            // every group, as upstream does.
            assert_eq!(*alerts.lock().unwrap(), [INTERNAL_ERROR_ALERT], "{reason}");
        }
    }
}

/// A server answering with a group the client did not offer fails.
#[test]
fn unlisted_groups_from_the_server_are_rejected() {
    for group in GROUPS {
        let (a, b) = ends();
        let client_rx = a.rx.clone();
        let client = Side::from(client(SslVersion::TLS1_3, &[X25519], &[X25519]).connect(a));
        let _server = Side::from(Ssl::new(&server(&[SslCurve::X25519])).unwrap().accept(b));
        let mut y = vec![0; group.len()];
        y[group.len() - 1] = 2;
        let body = wire::encode_server_key_share(group.id, &y);
        rewrite_server_hello(&client_rx, |_, extensions| {
            replace_extension(extensions, KEY_SHARE, &body);
        });
        failed_with(&client.step(), "WRONG_CURVE");
    }
}

/// A TLS 1.2 server never picks an FFDHE group for ECDHE, preferring its own
/// list or the client's.
#[test]
fn tls12_servers_skip_ffdhe() {
    for group in GROUPS {
        for server_preference in [false, true] {
            let mut ctx = server_context();
            ctx.set_curves(&[group.curve, SslCurve::X25519]).unwrap();
            ctx.set_strict_cipher_list("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
                .unwrap();
            if server_preference {
                ctx.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
            }
            let ctx = ctx.build();
            let (client, _) = handshake(
                client(SslVersion::TLS1_2, &[group.id, X25519], &[]),
                Ssl::new(&ctx).unwrap(),
            );
            let client = client.done();
            assert_eq!(client.ssl().version(), Some(SslVersion::TLS1_2));
            assert_eq!(client.ssl().curve(), Some(SslCurve::X25519));
            // With no other group in common, ECDHE is impossible.
            let (client, server) = handshake(client_only(group.id), Ssl::new(&ctx).unwrap());
            client.failed();
            server.failed();
        }
    }
}

fn client_only(id: u16) -> Ssl {
    client(SslVersion::TLS1_2, &[id], &[])
}

/// Sets the named group of the ServerKeyExchange in a TLS 1.2 server flight.
fn rewrite_server_key_exchange_group(rx: &Buffer, group: u16) {
    let mut rx = rx.lock().unwrap();
    let mut bytes: Vec<u8> = rx.drain(..).collect();
    let mut record = 0;
    let mut found = false;
    while record + 5 <= bytes.len() {
        let len = usize::from(u16::from_be_bytes([bytes[record + 3], bytes[record + 4]]));
        if bytes[record] == 22 {
            let mut message = record + 5;
            while message + 4 <= record + 5 + len {
                let body = u32::from_be_bytes([
                    0,
                    bytes[message + 1],
                    bytes[message + 2],
                    bytes[message + 3],
                ]);
                if bytes[message] == 12 {
                    // curve_type named_curve, then the group.
                    assert_eq!(bytes[message + 4], 3);
                    bytes[message + 5..message + 7].copy_from_slice(&group.to_be_bytes());
                    found = true;
                }
                message += 4 + usize::try_from(body).unwrap();
            }
        }
        record += 5 + len;
    }
    assert!(found, "a ServerKeyExchange");
    rx.extend(bytes);
}

/// A TLS 1.2 client rejects a ServerKeyExchange naming an FFDHE group, even
/// one it listed.
#[test]
fn tls12_clients_reject_ffdhe_server_key_exchange() {
    for group in GROUPS {
        let (a, b) = ends();
        let client_rx = a.rx.clone();
        let client = Side::from(client(SslVersion::TLS1_2, &[X25519, group.id], &[]).connect(a));
        let _server = Side::from(Ssl::new(&server(&[SslCurve::X25519])).unwrap().accept(b));
        rewrite_server_key_exchange_group(&client_rx, group.id);
        failed_with(&client.step(), "WRONG_CURVE");
    }
}

/// Default endpoints never offer or pick the groups.
#[test]
fn defaults_never_negotiate_ffdhe() {
    let default_server = server_context().build();
    for group in GROUPS {
        // A client listing only the group finds no common one.
        let (client_side, _) = handshake(
            client(SslVersion::TLS1_3, &[group.id], &[group.id]),
            Ssl::new(&default_server).unwrap(),
        );
        client_side.failed();
        // Listed first, it is skipped for a group the server enables.
        let (client_side, _) = handshake(
            client(SslVersion::TLS1_3, &[group.id, X25519], &[group.id, X25519]),
            Ssl::new(&default_server).unwrap(),
        );
        let client_side = client_side.done();
        assert_eq!(client_side.ssl().curve(), Some(SslCurve::X25519));
        // A named list enables it.
        let mut ctx = server_context();
        ctx.set_curves_list(group.name).unwrap();
        let (client_side, _) = handshake(
            client(SslVersion::TLS1_3, &[group.id], &[group.id]),
            Ssl::new(&ctx.build()).unwrap(),
        );
        assert_eq!(client_side.done().ssl().curve(), Some(group.curve));
    }
}
