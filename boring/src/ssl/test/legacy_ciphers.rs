//! Deprecated CBC cipher suites browsers still offer: off by default, and
//! negotiable once a caller names them.

use super::memory::{
    client_context, ends, handshake, rewrite_server_hello, server_context, End, Side,
};
use super::wire;
use crate::asn1::Asn1Time;
use crate::bn::BigNum;
use crate::ec::{EcGroup, EcKey};
use crate::ffi;
use crate::hash::{self, MessageDigest};
use crate::nid::Nid;
use crate::pkey::PKey;
use crate::ssl::{
    Error, Ssl, SslCipher, SslContentType, SslContext, SslContextBuilder, SslMethod, SslStream,
    SslVersion,
};
use crate::symm::{Cipher, Crypter, Mode};
use crate::x509::{X509Name, X509};
use foreign_types::ForeignTypeRef;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

const APPLICATION_DATA: u8 = 23;
const BAD_RECORD_MAC_ALERT: [u8; 2] = [2, 20];
const TLS12_AND_BELOW: &[SslVersion] = &[SslVersion::TLS1, SslVersion::TLS1_1, SslVersion::TLS1_2];
const TLS12: &[SslVersion] = &[SslVersion::TLS1_2];

/// One deprecated suite and its record protection.
struct Suite {
    id: u16,
    name: &'static str,
    ecdsa: bool,
    cipher: fn() -> Cipher,
    mac: fn() -> MessageDigest,
    versions: &'static [SslVersion],
}

const SUITES: &[Suite] = &[
    Suite {
        id: 0xc008,
        name: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        ecdsa: true,
        cipher: Cipher::des_ede3_cbc,
        mac: MessageDigest::sha1,
        versions: TLS12_AND_BELOW,
    },
    Suite {
        id: 0xc012,
        name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        ecdsa: false,
        cipher: Cipher::des_ede3_cbc,
        mac: MessageDigest::sha1,
        versions: TLS12_AND_BELOW,
    },
    Suite {
        id: 0x003c,
        name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        ecdsa: false,
        cipher: Cipher::aes_128_cbc,
        mac: MessageDigest::sha256,
        versions: TLS12,
    },
    Suite {
        id: 0x003d,
        name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        ecdsa: false,
        cipher: Cipher::aes_256_cbc,
        mac: MessageDigest::sha256,
        versions: TLS12,
    },
    Suite {
        id: 0xc024,
        name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        ecdsa: true,
        cipher: Cipher::aes_256_cbc,
        mac: MessageDigest::sha384,
        versions: TLS12,
    },
    Suite {
        id: 0xc028,
        name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        ecdsa: false,
        cipher: Cipher::aes_256_cbc,
        mac: MessageDigest::sha384,
        versions: TLS12,
    },
];

fn ecdsa_identity(ctx: &mut SslContextBuilder) {
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
    ctx.set_certificate(&cert.build()).unwrap();
    ctx.set_private_key(&key).unwrap();
}

/// A server that enables only `suite`, by name.
fn server(suite: &Suite) -> SslContext {
    server_with(suite, suite.name, SslVersion::TLS1_3)
}

/// A server with `suite`'s identity, the cipher `rule` and maximum version.
fn server_with(suite: &Suite, rule: &str, max: SslVersion) -> SslContext {
    let mut ctx = if suite.ecdsa {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ecdsa_identity(&mut ctx);
        ctx
    } else {
        server_context()
    };
    ctx.set_min_proto_version(Some(SslVersion::TLS1)).unwrap();
    ctx.set_max_proto_version(Some(max)).unwrap();
    ctx.set_strict_cipher_list(rule).unwrap();
    ctx.build()
}

/// A client pinned to `version` that lists `ciphers` raw.
fn client(version: SslVersion, ciphers: &[u16]) -> Ssl {
    let mut ctx = client_context();
    ctx.set_min_proto_version(Some(version)).unwrap();
    ctx.set_max_proto_version(Some(version)).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_raw_cipher_list(ciphers).unwrap();
    ssl
}

/// Every alert the server wrote.
type Alerts = Arc<Mutex<Vec<Vec<u8>>>>;

struct Connection {
    client: SslStream<End>,
    server: SslStream<End>,
    alerts: Alerts,
    /// Records the test sealed and the server opened.
    opened: u64,
}

fn connect(suite: &Suite, version: SslVersion) -> Connection {
    let mut server = Ssl::new(&server(suite)).unwrap();
    let alerts = Alerts::default();
    let sink = alerts.clone();
    server.set_msg_callback(move |_, message| {
        if message.is_written() && message.content_type() == SslContentType::ALERT {
            sink.lock().unwrap().push(message.bytes().to_vec());
        }
    });
    let (client, server) = handshake(client(version, &[suite.id]), server);
    let (client, server) = (client.done(), server.done());
    assert_eq!(client.ssl().version(), Some(version));
    assert_eq!(
        client.ssl().current_cipher().unwrap().protocol_id(),
        suite.id
    );
    assert_eq!(
        server.ssl().current_cipher().unwrap().standard_name(),
        Some(suite.name)
    );
    Connection {
        client,
        server,
        alerts,
        opened: 0,
    }
}

fn send(from: &mut SslStream<End>, to: &mut SslStream<End>, len: usize) {
    let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
    from.write_all(&data).unwrap();
    let mut read = vec![0; len];
    to.read_exact(&mut read).unwrap();
    assert_eq!(read, data);
}

/// Each length gives another padding length, up to records of several blocks.
#[test]
fn each_suite_exchanges_every_record_length() {
    for suite in SUITES {
        for &version in suite.versions {
            let mut conn = connect(suite, version);
            for len in (1..=320).chain([4096, 16384]) {
                send(&mut conn.client, &mut conn.server, len);
                send(&mut conn.server, &mut conn.client, len);
            }
        }
    }
}

/// The client's next record, as the server will read it.
fn queued_record(conn: &mut Connection, len: usize) -> Vec<u8> {
    conn.client.write_all(&vec![7; len]).unwrap();
    let rx = conn.server.get_ref().rx.clone();
    let bytes: Vec<u8> = rx.lock().unwrap().drain(..).collect();
    bytes
}

fn deliver(conn: &mut Connection, record: &[u8]) {
    conn.server.get_ref().rx.lock().unwrap().extend(record);
}

fn reasons(error: &Error) -> Vec<String> {
    error
        .ssl_error()
        .map(|stack| {
            stack
                .errors()
                .iter()
                .filter_map(|e| e.reason().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The server rejected the record with `bad_record_mac`.
#[track_caller]
fn rejected(conn: &mut Connection) -> Vec<String> {
    let error = conn.server.ssl_read(&mut [0; 64]).unwrap_err();
    let reasons = reasons(&error);
    assert!(
        reasons
            .iter()
            .any(|r| r == "DECRYPTION_FAILED_OR_BAD_RECORD_MAC"),
        "{reasons:?}"
    );
    assert_eq!(*conn.alerts.lock().unwrap(), [BAD_RECORD_MAC_ALERT]);
    reasons
}

#[test]
fn every_tampered_record_byte_fails_the_mac() {
    for suite in SUITES {
        let version = SslVersion::TLS1_2;
        let len = queued_record(&mut connect(suite, version), 40).len();
        // The header is checked before decryption; every other byte is the
        // explicit IV or the ciphertext.
        for pos in 5..len {
            let mut conn = connect(suite, version);
            let mut record = queued_record(&mut conn, 40);
            assert_eq!(record.len(), len);
            record[pos] ^= 0x01;
            deliver(&mut conn, &record);
            rejected(&mut conn);
        }
    }
}

/// The record protection keys of a TLS 1.2 connection, client side.
struct ClientKeys {
    mac: Vec<u8>,
    key: Vec<u8>,
    seq: u64,
}

fn client_keys(conn: &Connection, suite: &Suite) -> ClientKeys {
    let mac_len = (suite.mac)().size();
    let key_len = (suite.cipher)().key_len();
    let ptr = conn.client.ssl().as_ptr();
    let mut block = vec![0; 2 * (mac_len + key_len)];
    // SAFETY: `ptr` is the live client SSL; the getters only read it, and
    // `block` is exactly the asserted key block length.
    let seq = unsafe {
        assert_eq!(ffi::SSL_get_key_block_len(ptr), block.len());
        assert_eq!(
            ffi::SSL_generate_key_block(ptr, block.as_mut_ptr(), block.len()),
            1
        );
        ffi::SSL_get_write_sequence(ptr)
    };
    ClientKeys {
        mac: block[..mac_len].to_vec(),
        key: block[2 * mac_len..2 * mac_len + key_len].to_vec(),
        seq,
    }
}

fn hmac(digest: MessageDigest, key: &[u8], data: &[u8]) -> Vec<u8> {
    match digest.size() {
        20 => hash::hmac::<20>(digest, key, data).unwrap().to_vec(),
        32 => hash::hmac::<32>(digest, key, data).unwrap().to_vec(),
        48 => hash::hmac::<48>(digest, key, data).unwrap().to_vec(),
        size => unreachable!("no HMAC of {size} bytes"),
    }
}

/// How a crafted record is damaged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Damage {
    None,
    Padding,
    Mac,
}

/// A TLS 1.2 CBC record sealed with the client's keys at sequence number
/// `seq`, with `pad` padding bytes besides the length byte, damaged as asked.
fn seal(
    suite: &Suite,
    keys: &ClientKeys,
    seq: u64,
    plaintext: &[u8],
    pad: usize,
    damage: Damage,
) -> Vec<u8> {
    let cipher = (suite.cipher)();
    let block = cipher.block_size();
    let len = u16::try_from(plaintext.len()).unwrap().to_be_bytes();
    let header = [APPLICATION_DATA, 3, 3, len[0], len[1]];
    let mut mac = hmac(
        (suite.mac)(),
        &keys.mac,
        &[&seq.to_be_bytes()[..], &header, plaintext].concat(),
    );
    if damage == Damage::Mac {
        mac[0] ^= 0x01;
    }
    let mut padding = vec![u8::try_from(pad).unwrap(); pad + 1];
    if damage == Damage::Padding {
        padding[0] ^= 0x01;
    }
    let body = [plaintext, &mac, &padding].concat();
    assert_eq!(body.len() % block, 0);
    let iv = vec![0x5a; block];
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &keys.key, Some(&iv)).unwrap();
    crypter.pad(false);
    let mut sealed = vec![0; body.len() + block];
    let mut n = crypter.update(&body, &mut sealed).unwrap();
    n += crypter.finalize(&mut sealed[n..]).unwrap();
    sealed.truncate(n);
    let fragment = [iv, sealed].concat();
    let fragment_len = u16::try_from(fragment.len()).unwrap().to_be_bytes();
    [
        &[APPLICATION_DATA, 3, 3, fragment_len[0], fragment_len[1]][..],
        &fragment,
    ]
    .concat()
}

/// The shortest padding of more than one block for `len` plaintext bytes, so a
/// damaged first padding byte keeps every public length check satisfied.
fn long_padding(suite: &Suite, len: usize) -> usize {
    let block = (suite.cipher)().block_size();
    let unpadded = len + (suite.mac)().size() + 1;
    (block - unpadded % block) % block + block
}

/// Bad padding and a bad MAC must be indistinguishable to the peer: the same
/// error and the same alert, so the record layer does not act as an oracle.
#[test]
fn bad_padding_and_bad_mac_fail_alike() {
    for suite in SUITES {
        let plaintext = b"rama legacy record";
        let mut outcomes = Vec::new();
        for damage in [Damage::None, Damage::Padding, Damage::Mac] {
            let mut conn = connect(suite, SslVersion::TLS1_2);
            let keys = client_keys(&conn, suite);
            let pad = long_padding(suite, plaintext.len());
            let record = seal(suite, &keys, keys.seq, plaintext, pad, damage);
            deliver(&mut conn, &record);
            if damage == Damage::None {
                // The crafted record is right when undamaged.
                let mut read = [0; 18];
                conn.server.read_exact(&mut read).unwrap();
                assert_eq!(&read, plaintext);
            } else {
                outcomes.push(rejected(&mut conn));
            }
        }
        assert_eq!(outcomes[0], outcomes[1], "{}", suite.name);
    }
}

/// A ServerHello naming a suite the client did not list fails, even when the
/// library implements it.
#[test]
fn unlisted_suites_from_the_server_are_rejected() {
    for suite in SUITES {
        // Offer the suite's sibling, and answer with the suite itself.
        let (a, b) = ends();
        let rx = a.rx.clone();
        let client = Side::from(client(SslVersion::TLS1_2, &[0xc02f, 0xc014]).connect(a));
        let mut server_ctx = server_context();
        server_ctx
            .set_strict_cipher_list("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
            .unwrap();
        let _server = Side::from(Ssl::new(&server_ctx.build()).unwrap().accept(b));
        rewrite_server_hello(&rx, |cipher, _| *cipher = suite.id);
        client
            .step()
            .panicked_or_failed_with("WRONG_CIPHER_RETURNED");
    }
}

/// The suites are known to the library, by value and by name, and deprecated:
/// no rule but their own name enables them.
#[test]
fn suites_are_known_and_only_enabled_by_name() {
    for suite in SUITES {
        let cipher = SslCipher::from_value(suite.id).unwrap();
        assert_eq!(cipher.standard_name(), Some(suite.name));
        assert_eq!(cipher.protocol_id(), suite.id);
        for rule in ["ALL", "DEFAULT", "HIGH", "kRSA", "ECDHE", "AES", "SHA1"] {
            let mut ctx = client_context();
            ctx.set_cipher_list(rule).unwrap();
            let ctx = ctx.build();
            let listed = ctx.ciphers().unwrap();
            assert!(
                listed.iter().all(|c| c.protocol_id() != suite.id),
                "{rule} enables {}",
                suite.name
            );
        }
        let mut ctx = client_context();
        ctx.set_strict_cipher_list(suite.name).unwrap();
        let ids: Vec<u16> = ctx
            .build()
            .ciphers()
            .unwrap()
            .iter()
            .map(|c| c.protocol_id())
            .collect();
        assert_eq!(ids, [suite.id]);
    }
}

/// What a default client's ClientHello offers: ciphers, then supported groups,
/// key share groups and extension IDs.
fn default_hello() -> [Vec<u16>; 4] {
    let mut ssl = Ssl::new(&client_context().build()).unwrap();
    let hellos = Arc::new(Mutex::new(Vec::new()));
    let sink = hellos.clone();
    ssl.set_msg_callback(move |_, message| {
        if message.is_written() && message.handshake_type() == Some(1) {
            sink.lock().unwrap().push(message.bytes().to_vec());
        }
    });
    handshake(ssl, Ssl::new(&server_context().build()).unwrap())
        .0
        .done();
    let hellos = hellos.lock().unwrap();
    let hello = wire::ClientHello::parse(&hellos[0]).unwrap();
    [
        hello.ciphers.clone(),
        wire::u16_list(hello.extension(10).unwrap(), 2).unwrap(),
        wire::key_share_groups(hello.extension(51).unwrap()).unwrap(),
        hello.ids(),
    ]
}

fn default_hello_ciphers() -> Vec<u16> {
    let [ciphers, ..] = default_hello();
    ciphers
}

fn expansion(rule: &str) -> Vec<u16> {
    let mut ctx = client_context();
    ctx.set_cipher_list(rule).unwrap();
    let ctx = ctx.build();
    let ids = ctx
        .ciphers()
        .unwrap()
        .iter()
        .map(|c| c.protocol_id())
        .collect();
    ids
}

// The default cipher orders of the library before these suites existed. With
// AES hardware, AES-GCM comes before ChaCha20-Poly1305; without it, after. The
// rest of each list is the same either way.
const HELLO_WITH_AES_HW: [u16; 17] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const HELLO_WITHOUT_AES_HW: [u16; 17] = [
    0x1303, 0x1301, 0x1302, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const ALL_WITH_AES_HW: [u16; 19] = [
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xccac, 0xc009, 0xc013, 0xc035, 0xc00a, 0xc014,
    0xc036, 0x009c, 0x009d, 0x002f, 0x008c, 0x0035, 0x008d,
];
const ALL_WITHOUT_AES_HW: [u16; 19] = [
    0xcca9, 0xcca8, 0xccac, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc035, 0xc00a, 0xc014,
    0xc036, 0x009c, 0x009d, 0x002f, 0x008c, 0x0035, 0x008d,
];

/// Pinned to the lists of the library before these suites existed, in the
/// order for this machine's AES hardware, the same for every list.
#[test]
fn default_offers_and_rules_are_unchanged() {
    let [ciphers, groups, key_shares, extensions] = default_hello();
    let aes_hw = ciphers == HELLO_WITH_AES_HW;
    if !aes_hw {
        assert_eq!(ciphers, HELLO_WITHOUT_AES_HW);
    }
    let all = if aes_hw {
        ALL_WITH_AES_HW
    } else {
        ALL_WITHOUT_AES_HW
    };
    assert_eq!(expansion("ALL"), all);
    assert_eq!(expansion("DEFAULT"), all);
    // Groups, key shares and the extension order have no hardware branch.
    assert_eq!(
        groups,
        [0x11ec, 0x001d, 0x0202, 0x0017, 0x0018, 0x0019, 0x6399, 0xfe30]
    );
    assert_eq!(key_shares, [0x11ec, 0x001d]);
    assert_eq!(
        extensions,
        [0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x000d, 0x0033, 0x002d, 0x002b]
    );
}

/// The two pinned orders differ only by where the AES-GCM block sits.
#[test]
fn pinned_orders_hold_the_same_suites() {
    let sorted = |list: &[u16]| {
        let mut list = list.to_vec();
        list.sort_unstable();
        list
    };
    assert_eq!(sorted(&HELLO_WITH_AES_HW), sorted(&HELLO_WITHOUT_AES_HW));
    assert_eq!(sorted(&ALL_WITH_AES_HW), sorted(&ALL_WITHOUT_AES_HW));
    assert_eq!(HELLO_WITH_AES_HW[9..], HELLO_WITHOUT_AES_HW[9..]);
    assert_eq!(ALL_WITH_AES_HW[7..], ALL_WITHOUT_AES_HW[7..]);
}

/// A default server never picks the suites: it skips them for a later shared
/// cipher, and finds none when a client lists only them.
#[test]
fn default_servers_do_not_negotiate_the_suites() {
    let default_server = server_context().build();
    let offered = default_hello_ciphers();
    let listed: Vec<u16> = SUITES.iter().map(|suite| suite.id).collect();
    let (client_side, _) = handshake(
        client(SslVersion::TLS1_2, &[&listed[..], &[0xc02f]].concat()),
        Ssl::new(&default_server).unwrap(),
    );
    let client_side = client_side.done();
    assert_eq!(
        client_side.ssl().current_cipher().unwrap().protocol_id(),
        0xc02f
    );
    for suite in SUITES {
        assert!(!offered.contains(&suite.id));
        let (client_side, server_side) = handshake(
            client(SslVersion::TLS1_2, &[suite.id]),
            Ssl::new(&default_server).unwrap(),
        );
        server_side.panicked_or_failed_with("NO_SHARED_CIPHER");
        client_side.failed();
    }
}

/// Records sealed in the test, with every padding length the format allows,
/// open to their plaintext: a known-answer check of the constant-time MAC and
/// padding removal against an HMAC computed independently.
#[test]
fn crafted_records_with_every_padding_length_open() {
    for suite in SUITES {
        let mut conn = connect(suite, SslVersion::TLS1_2);
        let keys = client_keys(&conn, suite);
        let block = (suite.cipher)().block_size();
        for (i, pad) in (0..=255).enumerate() {
            let unpadded = (suite.mac)().size() + pad + 1;
            let len = (block - unpadded % block) % block + block;
            let plaintext: Vec<u8> = (0..len).map(|b| (b + i) as u8).collect();
            let seq = keys.seq + conn.opened;
            deliver(
                &mut conn,
                &seal(suite, &keys, seq, &plaintext, pad, Damage::None),
            );
            conn.opened += 1;
            let mut read = vec![0; len];
            conn.server.read_exact(&mut read).unwrap();
            assert_eq!(read, plaintext, "{} padding {pad}", suite.name);
        }
    }
}

/// Records the library seals decrypt, in the test, to the plaintext, an HMAC
/// over the TLS pseudo-header computed independently, and minimal padding.
#[test]
fn sealed_records_match_an_independent_computation() {
    for suite in SUITES {
        let mut conn = connect(suite, SslVersion::TLS1_2);
        let keys = client_keys(&conn, suite);
        let cipher = (suite.cipher)();
        let block = cipher.block_size();
        let mac_len = (suite.mac)().size();
        for (i, len) in (1..=80).chain([255, 256, 1000]).enumerate() {
            let plaintext: Vec<u8> = (0..len).map(|b| (b * 7 + i) as u8).collect();
            conn.client.write_all(&plaintext).unwrap();
            let record: Vec<u8> = conn.server.get_ref().rx.lock().unwrap().drain(..).collect();
            assert_eq!(&record[..3], [APPLICATION_DATA, 3, 3]);
            let fragment = &record[5..];
            assert_eq!(
                fragment.len(),
                usize::from(u16::from_be_bytes([record[3], record[4]]))
            );
            let (iv, sealed) = fragment.split_at(block);
            let mut crypter = Crypter::new(cipher, Mode::Decrypt, &keys.key, Some(iv)).unwrap();
            crypter.pad(false);
            let mut body = vec![0; sealed.len() + block];
            let mut n = crypter.update(sealed, &mut body).unwrap();
            n += crypter.finalize(&mut body[n..]).unwrap();
            body.truncate(n);
            let pad = usize::from(*body.last().unwrap());
            assert!(pad < block, "minimal padding");
            assert!(body[body.len() - pad - 1..]
                .iter()
                .all(|b| usize::from(*b) == pad));
            let (data, mac) = body[..body.len() - pad - 1].split_at(len);
            assert_eq!(data, plaintext);
            let seq = keys.seq + u64::try_from(i).unwrap();
            let header = [APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8];
            let expected = hmac(
                (suite.mac)(),
                &keys.mac,
                &[&seq.to_be_bytes()[..], &header, &plaintext].concat(),
            );
            assert_eq!(mac.len(), mac_len);
            assert_eq!(mac, expected, "{} length {len}", suite.name);
        }
    }
}

/// The SHA-256 and SHA-384 CBC suites exist only in TLS 1.2: below it, a server
/// never selects them and a client rejects a server that does.
#[test]
fn sha2_cbc_suites_are_not_negotiated_below_tls12() {
    for suite in SUITES.iter().filter(|suite| suite.versions == TLS12) {
        // A TLS 1.0 or 1.1 suite with the same identity, offered alongside.
        let (fallback, fallback_name) = if suite.ecdsa {
            (0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
        } else {
            (0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
        };
        let both = format!("{}:{fallback_name}", suite.name);
        for version in [SslVersion::TLS1, SslVersion::TLS1_1] {
            // Only the suite listed: no shared cipher at this version.
            let (client_side, server_side) = handshake(
                client(version, &[suite.id]),
                Ssl::new(&server(suite)).unwrap(),
            );
            server_side.panicked_or_failed_with("NO_SHARED_CIPHER");
            client_side.failed();

            // A server capped at this version skips it for the other suite.
            let mut ctx = client_context();
            ctx.set_min_proto_version(Some(SslVersion::TLS1)).unwrap();
            let mut ssl = Ssl::new(&ctx.build()).unwrap();
            ssl.set_raw_cipher_list(&[suite.id, fallback]).unwrap();
            let capped = server_with(suite, &both, version);
            let (client_side, _) = handshake(ssl, Ssl::new(&capped).unwrap());
            let client_side = client_side.done();
            assert_eq!(client_side.ssl().version(), Some(version));
            assert_eq!(
                client_side.ssl().current_cipher().unwrap().protocol_id(),
                fallback
            );

            // A server selecting it at this version anyway is rejected.
            let (a, b) = ends();
            let rx = a.rx.clone();
            let client_side = Side::from(client(version, &[suite.id, fallback]).connect(a));
            let _server = Side::from(Ssl::new(&capped).unwrap().accept(b));
            rewrite_server_hello(&rx, |cipher, _| *cipher = suite.id);
            client_side
                .step()
                .panicked_or_failed_with("WRONG_CIPHER_RETURNED");
        }
    }
}
