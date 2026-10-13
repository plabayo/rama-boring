//! Per-connection ClientHello shape: GREASE slots and values, raw lists,
//! unknown values and padding, checked on the wire.

use super::memory::{client_context, handshake, server_context, Side};
use super::wire::{self, is_grease};
use crate::ssl::{
    ClientHelloShape, ExtensionType, GreaseLists, GreaseValues, Padding, Ssl, SslContext,
    SslContextBuilder, SslVersion, UnknownValues,
};
use std::sync::{Arc, Mutex};

const SUPPORTED_GROUPS: u16 = 10;
const SIGNATURE_ALGORITHMS: u16 = 13;
const PADDING: u16 = 21;
const ENCRYPT_THEN_MAC: u16 = 22;
const PRE_SHARED_KEY: u16 = 41;
const SUPPORTED_VERSIONS: u16 = 43;
const KEY_SHARE: u16 = 51;
const X25519: u16 = 0x001d;
const P256: u16 = 0x0017;
const P384: u16 = 0x0018;
const FFDHE2048: u16 = 0x0100;

/// A ClientHello as sent.
#[derive(Debug, Clone)]
struct Hello {
    len: usize,
    ciphers: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    fn parse(message: &[u8]) -> Self {
        let hello = wire::ClientHello::parse(message)
            .unwrap_or_else(|| panic!("a well-formed ClientHello: {message:02x?}"));
        Self {
            len: message.len(),
            ciphers: hello.ciphers,
            extensions: hello
                .extensions
                .into_iter()
                .map(|(id, body)| (id, body.to_vec()))
                .collect(),
        }
    }

    /// A two-byte list behind a length prefix of `prefix` bytes.
    fn list(&self, id: u16, prefix: usize) -> Vec<u16> {
        let body = self.body(id).unwrap_or_else(|| panic!("extension {id}"));
        wire::u16_list(body, prefix).unwrap_or_else(|| panic!("malformed extension {id}"))
    }

    fn ids(&self) -> Vec<u16> {
        self.extensions.iter().map(|(id, _)| *id).collect()
    }

    fn body(&self, id: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(ext, _)| *ext == id)
            .map(|(_, body)| body.as_slice())
    }

    fn groups(&self) -> Vec<u16> {
        self.list(SUPPORTED_GROUPS, 2)
    }

    fn versions(&self) -> Vec<u16> {
        self.list(SUPPORTED_VERSIONS, 1)
    }

    fn sigalgs(&self) -> Vec<u16> {
        self.list(SIGNATURE_ALGORITHMS, 2)
    }

    fn key_shares(&self) -> Vec<u16> {
        wire::key_share_groups(self.body(KEY_SHARE).expect("key_share"))
            .expect("a well-formed key_share")
    }

    /// Every GREASE value, list by list, in order.
    fn grease(&self) -> Vec<u16> {
        [
            self.ciphers.clone(),
            self.groups(),
            self.versions(),
            self.sigalgs(),
            self.key_shares(),
            self.ids(),
        ]
        .concat()
        .into_iter()
        .filter(|value| is_grease(*value))
        .collect()
    }
}

/// Positions of GREASE values, with everything else exact.
fn shape(values: &[u16]) -> Vec<Option<u16>> {
    values
        .iter()
        .map(|value| (!is_grease(*value)).then_some(*value))
        .collect()
}

/// Runs a handshake and returns every ClientHello the client wrote.
fn hellos_of(client: Ssl, server: Ssl) -> (Vec<Hello>, Side<super::memory::End>) {
    let written = Arc::new(Mutex::new(Vec::new()));
    let sink = written.clone();
    let mut client = client;
    client.set_msg_callback(move |_, message| {
        if message.is_written() && message.handshake_type() == Some(1) {
            sink.lock().unwrap().push(Hello::parse(message.bytes()));
        }
    });
    let (client, _) = handshake(client, server);
    let hellos = written.lock().unwrap().clone();
    (hellos, client)
}

fn server() -> SslContext {
    server_context().build()
}

fn client(configure: impl FnOnce(&mut SslContextBuilder)) -> Ssl {
    let mut ctx = client_context();
    configure(&mut ctx);
    Ssl::new(&ctx.build()).unwrap()
}

/// A client with GREASE slots in the middle of every list.
fn slotted(grease: [u16; 6]) -> Ssl {
    slotted_on(client(|_| {}), grease)
}

fn slotted_on(mut ssl: Ssl, grease: [u16; 6]) -> Ssl {
    ssl.set_raw_cipher_list(&[0x1301, grease[0], 0x1302, 0xc02b])
        .unwrap();
    ssl.set_raw_supported_groups(&[X25519, grease[1], P256])
        .unwrap();
    ssl.set_raw_key_shares(&[X25519, grease[1]]).unwrap();
    ssl.set_raw_supported_versions(&[0x0304, grease[2], 0x0303])
        .unwrap();
    ssl.set_raw_signature_algorithms(&[0x0403, grease[3], 0x0804, 0x0401])
        .unwrap();
    ssl.set_extension_order(&[
        KEY_SHARE,
        grease[4],
        SUPPORTED_VERSIONS,
        SUPPORTED_GROUPS,
        SIGNATURE_ALGORITHMS,
        grease[5],
    ])
    .unwrap();
    ssl
}

#[test]
fn grease_codepoints_are_slots_at_their_positions() {
    let ssl = slotted([0x0a0a; 6]);
    let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
    client.done();
    let hello = &hellos[0];
    assert_eq!(
        shape(&hello.ciphers),
        [Some(0x1301), None, Some(0x1302), Some(0xc02b)]
    );
    assert_eq!(shape(&hello.groups()), [Some(X25519), None, Some(P256)]);
    assert_eq!(shape(&hello.key_shares()), [Some(X25519), None]);
    assert_eq!(shape(&hello.versions()), [Some(0x0304), None, Some(0x0303)]);
    assert_eq!(
        shape(&hello.sigalgs()),
        [Some(0x0403), None, Some(0x0804), Some(0x0401)]
    );
    assert_eq!(
        shape(&hello.ids()[..6]),
        [
            Some(KEY_SHARE),
            None,
            Some(SUPPORTED_VERSIONS),
            Some(SUPPORTED_GROUPS),
            Some(SIGNATURE_ALGORITHMS),
            None
        ]
    );
    // Two GREASE extensions never share a value, and keep the native bodies.
    let ids = hello.ids();
    assert_ne!(ids[1], ids[5]);
    assert_eq!(hello.body(ids[1]), Some(&[][..]));
    assert_eq!(hello.body(ids[5]), Some(&[0][..]));
    // No native GREASE is added on top of the listed slots.
    assert_eq!(hello.grease().len(), 7);
}

#[test]
fn pinned_values_mirror_the_listed_codepoints() {
    let grease = [0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a];
    let mut ssl = slotted(grease);
    ssl.set_client_hello_shape(
        &ClientHelloShape::new()
            .with_grease_values(GreaseValues::Pinned)
            .with_extension_body(ExtensionType::from(0x8a8a), [1, 2, 3]),
    )
    .unwrap();
    let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
    client.done();
    let hello = &hellos[0];
    assert_eq!(hello.ciphers[1], 0x3a3a);
    assert_eq!(hello.groups()[1], 0x4a4a);
    assert_eq!(hello.key_shares()[1], 0x4a4a);
    assert_eq!(hello.versions()[1], 0x5a5a);
    assert_eq!(hello.sigalgs()[1], 0x6a6a);
    assert_eq!(hello.ids()[1], 0x7a7a);
    assert_eq!(hello.ids()[5], 0x8a8a);
    assert_eq!(hello.body(0x7a7a), Some(&[][..]));
    assert_eq!(hello.body(0x8a8a), Some(&[1, 2, 3][..]));
}

#[test]
fn pinned_duplicate_grease_extensions_fail_closed() {
    let mut ssl = slotted([0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x7a7a]);
    ssl.set_client_hello_shape(&ClientHelloShape::new().with_grease_values(GreaseValues::Pinned))
        .unwrap();
    let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
    assert!(hellos.is_empty());
    client.panicked_or_failed_with("listed twice");

    // Fresh values for repeated GREASE slots are made distinct.
    let ssl = slotted([0x0a0a; 6]);
    let (hellos, _) = hellos_of(ssl, Ssl::new(&server()).unwrap());
    let ids = hellos[0].ids();
    assert_ne!(ids[1], ids[5]);
}

#[test]
fn seeded_values_are_reproducible() {
    let values = |seed: Option<u64>| {
        let mut ssl = slotted([0x0a0a; 6]);
        if let Some(seed) = seed {
            ssl.set_client_hello_shape(
                &ClientHelloShape::new().with_grease_values(GreaseValues::Seeded(seed)),
            )
            .unwrap();
        }
        let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
        client.done();
        hellos[0].grease()
    };
    assert_eq!(values(Some(7)), values(Some(7)));
    let seeds: std::collections::HashSet<_> = (0..8).map(|seed| values(Some(seed))).collect();
    assert!(seeds.len() > 1, "seeds must change the values");
    let fresh: std::collections::HashSet<_> = (0..8).map(|_| values(None)).collect();
    assert!(fresh.len() > 1, "fresh values must vary per connection");
}

#[test]
fn grease_lists_are_chosen_per_connection() {
    let lists = |ctx_grease: bool, lists: Option<GreaseLists>| {
        let mut ssl = client(|ctx| ctx.set_grease_enabled(ctx_grease));
        if let Some(lists) = lists {
            ssl.set_client_hello_shape(&ClientHelloShape::new().with_grease_lists(lists))
                .unwrap();
        }
        let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
        client.done();
        let hello = &hellos[0];
        [
            is_grease(hello.ciphers[0]),
            is_grease(hello.groups()[0]),
            is_grease(hello.key_shares()[0]),
            is_grease(hello.versions()[0]),
            is_grease(hello.sigalgs()[0]),
            is_grease(hello.ids()[0]) && is_grease(*hello.ids().last().unwrap()),
        ]
    };
    assert_eq!(lists(false, None), [false; 6]);
    assert_eq!(lists(true, None), [true, true, true, true, false, true]);
    assert_eq!(lists(true, Some(GreaseLists::empty())), [false; 6]);
    assert_eq!(lists(false, Some(GreaseLists::all())), [true; 6]);
    assert_eq!(
        lists(false, Some(GreaseLists::CIPHERS | GreaseLists::EXTENSIONS)),
        [true, false, false, false, false, true]
    );
}

fn unknown_client(policy: Option<UnknownValues>) -> Ssl {
    let mut ssl = client(|ctx| {
        ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    });
    ssl.set_raw_supported_groups(&[X25519, FFDHE2048, P256])
        .unwrap();
    ssl.set_raw_supported_versions(&[0x0304, 0x0303, 0x0302])
        .unwrap();
    ssl.set_raw_signature_algorithms(&[0x0403, 0x0808, 0x0804])
        .unwrap();
    // Padding and pre_shared_key are written natively, never from the order.
    ssl.set_extension_order(&[
        SUPPORTED_GROUPS,
        ENCRYPT_THEN_MAC,
        PADDING,
        SUPPORTED_VERSIONS,
        PRE_SHARED_KEY,
    ])
    .unwrap();
    if let Some(policy) = policy {
        ssl.set_client_hello_shape(&ClientHelloShape::new().with_unknown_values(policy))
            .unwrap();
    }
    ssl
}

#[test]
fn unknown_values_are_dropped_by_default() {
    for policy in [None, Some(UnknownValues::Drop)] {
        let (hellos, client) = hellos_of(unknown_client(policy), Ssl::new(&server()).unwrap());
        client.done();
        let hello = &hellos[0];
        assert_eq!(hello.groups(), [X25519, P256]);
        assert_eq!(hello.versions(), [0x0304, 0x0303]);
        assert_eq!(hello.sigalgs(), [0x0403, 0x0804]);
        assert!(hello.body(ENCRYPT_THEN_MAC).is_none());
    }
}

#[test]
fn unknown_values_can_be_forbidden() {
    let (hellos, client) = hellos_of(
        unknown_client(Some(UnknownValues::Forbid)),
        Ssl::new(&server()).unwrap(),
    );
    assert!(hellos.is_empty(), "nothing is sent");
    client.panicked_or_failed_with("cannot be negotiated");
}

#[test]
fn unknown_values_can_be_preserved() {
    let mut ssl = unknown_client(Some(UnknownValues::Preserve));
    ssl.set_client_hello_shape(
        &ClientHelloShape::new()
            .with_unknown_values(UnknownValues::Preserve)
            .with_extension_body(ExtensionType::from(ENCRYPT_THEN_MAC), [9]),
    )
    .unwrap();
    let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
    // The server ignores what it does not know; the handshake completes.
    client.done();
    let hello = &hellos[0];
    assert_eq!(hello.groups(), [X25519, FFDHE2048, P256]);
    assert_eq!(hello.versions(), [0x0304, 0x0303, 0x0302]);
    assert_eq!(hello.sigalgs(), [0x0403, 0x0808, 0x0804]);
    assert_eq!(
        hello.ids()[..3],
        [SUPPORTED_GROUPS, ENCRYPT_THEN_MAC, SUPPORTED_VERSIONS]
    );
    assert_eq!(hello.body(ENCRYPT_THEN_MAC), Some(&[9][..]));
    assert!(hello.body(PRE_SHARED_KEY).is_none(), "no session, no PSK");
    assert!(hello.ids().iter().filter(|id| **id == PADDING).count() <= 1);
}

#[test]
fn bodies_of_native_extensions_cannot_be_replaced() {
    let mut ssl = client(|_| {});
    // Small key shares keep the ClientHello within the natively padded range.
    ssl.set_raw_key_shares(&[X25519, P256]).unwrap();
    // A rejected body leaves the connection's other choices untouched.
    let shape = ClientHelloShape::new()
        .with_extension_body(ExtensionType::SERVER_NAME, [0])
        .with_padding(Padding::Off);
    assert!(ssl.set_client_hello_shape(&shape).is_err());
    let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
    client.done();
    assert_eq!(hellos[0].len, 512, "padding stayed native");
    let mut ssl = self::client(|_| {});
    let shape = ClientHelloShape::new()
        .with_extension_body(ExtensionType::from(ENCRYPT_THEN_MAC), vec![0; 70_000]);
    assert!(ssl.set_client_hello_shape(&shape).is_err());
}

#[test]
fn padding_is_chosen_per_connection() {
    let hello = |padding: Option<Padding>| {
        let mut ssl = client(|_| {});
        // Small key shares keep the ClientHello within the padded range.
        ssl.set_raw_key_shares(&[X25519, P256]).unwrap();
        if let Some(padding) = padding {
            ssl.set_client_hello_shape(&ClientHelloShape::new().with_padding(padding))
                .unwrap();
        }
        let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
        client.done();
        hellos[0].clone()
    };
    let native = hello(None);
    assert_eq!(native.len, 512, "native padding reaches 512 bytes");
    assert!(native.body(PADDING).is_some());
    assert_eq!(hello(Some(Padding::Native)).len, 512);
    let off = hello(Some(Padding::Off));
    assert!(off.body(PADDING).is_none());
    assert!(off.len < 512);
    let padded = hello(Some(Padding::ToLength(700)));
    assert_eq!(padded.len, 700);
    assert_eq!(*padded.ids().last().unwrap(), PADDING);
    // A target the ClientHello already exceeds adds nothing.
    assert!(hello(Some(Padding::ToLength(100))).body(PADDING).is_none());
}

#[test]
fn hello_retry_keeps_the_shape_and_grease_values() {
    let mut server = server_context();
    server.set_curves_list("P-384").unwrap();
    let mut ssl = slotted([0x0a0a; 6]);
    ssl.set_raw_supported_groups(&[X25519, 0x0a0a, P256, P384])
        .unwrap();
    let (hellos, client) = hellos_of(ssl, Ssl::new(&server.build()).unwrap());
    let client = client.done();
    assert!(client.ssl().used_hello_retry_request());
    assert_eq!(hellos.len(), 2);
    let (first, second) = (&hellos[0], &hellos[1]);
    assert_eq!(first.ciphers, second.ciphers);
    assert_eq!(first.groups(), second.groups());
    assert_eq!(first.versions(), second.versions());
    assert_eq!(first.sigalgs(), second.sigalgs());
    // The retry sends one key share for the server's group.
    assert_eq!(second.key_shares(), [P384]);
}

#[test]
fn shape_setters_reject_servers_and_started_handshakes() {
    let mut server = Ssl::new(&server())
        .unwrap()
        .setup_accept(std::io::Cursor::new(Vec::<u8>::new()));
    let server = server.ssl_mut();
    assert!(server.set_raw_supported_groups(&[X25519]).is_err());
    assert!(server
        .set_client_hello_shape(&ClientHelloShape::new())
        .is_err());

    let (connected, _) = handshake(client(|_| {}), Ssl::new(&self::server()).unwrap());
    let mut connected = connected.done();
    assert!(connected
        .ssl_mut()
        .set_raw_supported_groups(&[X25519])
        .is_err());

    let mut ssl = client(|_| {});
    assert!(
        ssl.set_raw_supported_groups(&[FFDHE2048]).is_err(),
        "none supported"
    );
    assert!(ssl.set_raw_signature_algorithms(&[0x0403; 257]).is_err());
}

mod model {
    use super::*;
    use proptest::prelude::*;

    const KNOWN_GROUPS: [u16; 4] = [X25519, P256, P384, 0x0019];
    // FFDHE 2048/3072 and X448: real groups BoringSSL does not implement.
    const UNKNOWN_GROUPS: [u16; 3] = [FFDHE2048, 0x0101, 0x001e];
    const KNOWN_VERSIONS: [u16; 2] = [0x0304, 0x0303];
    const UNKNOWN_VERSIONS: [u16; 3] = [0x0302, 0x0301, 0x7f1c];
    const KNOWN_SIGALGS: [u16; 4] = [0x0403, 0x0804, 0x0401, 0x0503];
    const UNKNOWN_SIGALGS: [u16; 3] = [0x0808, 0x0809, 0x0303];

    fn list(known: &'static [u16], unknown: &'static [u16]) -> impl Strategy<Value = Vec<u16>> {
        let value = prop_oneof![
            4 => proptest::sample::select(known),
            1 => proptest::sample::select(unknown),
            1 => (0u16..16).prop_map(|n| 0x0a0a + n * 0x1010),
        ];
        proptest::collection::vec(value, 0..8)
    }

    fn policy() -> impl Strategy<Value = UnknownValues> {
        prop_oneof![
            Just(UnknownValues::Drop),
            Just(UnknownValues::Forbid),
            Just(UnknownValues::Preserve)
        ]
    }

    fn values() -> impl Strategy<Value = GreaseValues> {
        prop_oneof![
            Just(GreaseValues::Fresh),
            any::<u64>().prop_map(GreaseValues::Seeded),
            Just(GreaseValues::Pinned)
        ]
    }

    /// What a raw list becomes on the wire, or None when the policy forbids it.
    fn expected(
        raw: &[u16],
        known: &[u16],
        policy: UnknownValues,
        values: GreaseValues,
    ) -> Option<Vec<Option<u16>>> {
        // Repeats are kept as listed.
        let mut out = Vec::new();
        for &value in raw {
            if is_grease(value) {
                out.push(
                    (values == GreaseValues::Pinned)
                        .then_some(value)
                        .map(|_| value),
                );
                continue;
            }
            if known.contains(&value) {
                out.push(Some(value));
            } else {
                match policy {
                    UnknownValues::Drop => {}
                    UnknownValues::Forbid => return None,
                    UnknownValues::Preserve => out.push(Some(value)),
                }
            }
        }
        Some(out)
    }

    /// Compares GREASE slots by position (and value when pinned).
    fn wire(values: &[u16], pinned: bool) -> Vec<Option<u16>> {
        values
            .iter()
            .map(|value| {
                if is_grease(*value) {
                    pinned.then_some(*value)
                } else {
                    Some(*value)
                }
            })
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn shaped_lists_match_the_model(
            groups in list(&KNOWN_GROUPS, &UNKNOWN_GROUPS),
            versions in list(&KNOWN_VERSIONS, &UNKNOWN_VERSIONS),
            sigalgs in list(&KNOWN_SIGALGS, &UNKNOWN_SIGALGS),
            policy in policy(),
            values in values(),
        ) {
            // A connection needs one negotiable group and version.
            let groups = [&[X25519][..], &groups].concat();
            let versions = [&[0x0304][..], &versions].concat();
            let sigalgs = [&[0x0804][..], &sigalgs].concat();
            let mut ssl = client(|ctx| {
                ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
            });
            ssl.set_raw_supported_groups(&groups).unwrap();
            ssl.set_raw_supported_versions(&versions).unwrap();
            ssl.set_raw_signature_algorithms(&sigalgs).unwrap();
            ssl.set_client_hello_shape(
                &ClientHelloShape::new()
                    .with_unknown_values(policy)
                    .with_grease_values(values),
            )
            .unwrap();
            let expected_groups = expected(&groups, &KNOWN_GROUPS, policy, values);
            let expected_versions = expected(&versions, &KNOWN_VERSIONS, policy, values);
            let expected_sigalgs = expected(&sigalgs, &KNOWN_SIGALGS, policy, values);
            let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
            match (expected_groups, expected_versions, expected_sigalgs) {
                (Some(groups), Some(versions), Some(sigalgs)) => {
                    let pinned = values == GreaseValues::Pinned;
                    let hello = &hellos[0];
                    prop_assert_eq!(wire(&hello.groups(), pinned), groups);
                    prop_assert_eq!(wire(&hello.versions(), pinned), versions);
                    prop_assert_eq!(wire(&hello.sigalgs(), pinned), sigalgs);
                    // Advertised but unsupported values are never selected.
                    client.done();
                }
                _ => {
                    prop_assert!(hellos.is_empty());
                    client.panicked_or_failed_with("cannot be negotiated");
                }
            }
        }
    }
}

#[test]
fn slot_values_are_the_native_grease_values() {
    // Under one seed, a listed slot and BoringSSL's native GREASE position of the
    // same list carry the same value: slots are real GREASE, not echoed codepoints.
    let mut differing_seeds = 0;
    for seed in 0..8 {
        let shape = ClientHelloShape::new().with_grease_values(GreaseValues::Seeded(seed));
        let mut slotted = slotted([0x0a0a; 6]);
        slotted.set_client_hello_shape(&shape).unwrap();
        let mut native = client(|_| {});
        native
            .set_client_hello_shape(&shape.clone().with_grease_lists(GreaseLists::all()))
            .unwrap();
        native.set_raw_key_shares(&[0x0a0a, X25519]).unwrap();
        let (slotted, _) = hellos_of(slotted, Ssl::new(&server()).unwrap());
        let (native, _) = hellos_of(native, Ssl::new(&server()).unwrap());
        let (slotted, native) = (&slotted[0], &native[0]);
        assert_eq!(slotted.ciphers[1], native.ciphers[0], "seed {seed}");
        assert_eq!(slotted.groups()[1], native.groups()[0], "seed {seed}");
        assert_eq!(
            slotted.key_shares()[1],
            native.key_shares()[0],
            "seed {seed}"
        );
        assert_eq!(slotted.versions()[1], native.versions()[0], "seed {seed}");
        assert_eq!(slotted.sigalgs()[1], native.sigalgs()[0], "seed {seed}");
        assert_eq!(slotted.ids()[1], native.ids()[0], "seed {seed}");
        let native_last_grease = native.ids().into_iter().rev().find(|id| is_grease(*id));
        assert_eq!(Some(slotted.ids()[5]), native_last_grease, "seed {seed}");
        differing_seeds += usize::from(slotted.ciphers[1] != 0x0a0a);
    }
    assert!(
        differing_seeds > 0,
        "slot values must not echo the listed codepoint"
    );
}

#[test]
fn listed_slots_replace_native_grease() {
    // With every native GREASE switched on, lists that carry their own GREASE
    // codepoints get exactly those slots and nothing more.
    for (context, lists) in [(true, None), (false, Some(GreaseLists::all()))] {
        let base = client(|ctx| {
            ctx.set_grease_enabled(context);
            ctx.set_grease_sigalgs_enabled(context);
        });
        let mut ssl = slotted_on(base, [0x0a0a; 6]);
        if let Some(lists) = lists {
            ssl.set_client_hello_shape(&ClientHelloShape::new().with_grease_lists(lists))
                .unwrap();
        }
        let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
        client.done();
        let hello = &hellos[0];
        let count = |values: &[u16]| values.iter().filter(|v| is_grease(**v)).count();
        assert_eq!(count(&hello.ciphers), 1, "{context}");
        assert_eq!(count(&hello.groups()), 1, "{context}");
        assert_eq!(count(&hello.key_shares()), 1, "{context}");
        assert_eq!(count(&hello.versions()), 1, "{context}");
        assert_eq!(count(&hello.sigalgs()), 1, "{context}");
        assert_eq!(count(&hello.ids()), 2, "{context}");
        assert!(
            !is_grease(hello.ciphers[0]),
            "{context}: no native first GREASE"
        );
    }
}

#[test]
fn emulated_jdk11_client_triggers_the_server_workaround() {
    // A JDK 11 ClientHello shape, built only with the shaping API. BoringSSL's
    // server recognises it and, with the workaround on, avoids TLS 1.3.
    const SIGNATURE_ALGORITHMS_CERT: u16 = 50;
    const EC_POINT_FORMATS: u16 = 11;
    const EXTENDED_MASTER_SECRET: u16 = 23;
    const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    const RENEGOTIATE: u16 = 0xff01;
    let sigalgs = [0x0403u16, 0x0804, 0x0401];
    let jdk11 = || {
        let mut ssl = client(|ctx| {
            ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
            ctx.set_options(crate::ssl::SslOptions::NO_TICKET);
        });
        ssl.set_raw_cipher_list(&[0x1301, 0x1302, 0xc02b, 0xc02f])
            .unwrap();
        ssl.set_raw_supported_groups(&[P256, P384]).unwrap();
        ssl.set_raw_key_shares(&[P256]).unwrap();
        ssl.set_raw_signature_algorithms(&sigalgs).unwrap();
        ssl.set_extension_order(&[
            SUPPORTED_GROUPS,
            EC_POINT_FORMATS,
            SIGNATURE_ALGORITHMS,
            SIGNATURE_ALGORITHMS_CERT,
            EXTENDED_MASTER_SECRET,
            SUPPORTED_VERSIONS,
            PSK_KEY_EXCHANGE_MODES,
            KEY_SHARE,
            RENEGOTIATE,
        ])
        .unwrap();
        // signature_algorithms_cert is not built natively: preserve it with
        // exactly the signature_algorithms body.
        let mut body = vec![0, 6];
        body.extend(sigalgs.iter().flat_map(|alg| alg.to_be_bytes()));
        ssl.set_client_hello_shape(
            &ClientHelloShape::new()
                .with_unknown_values(UnknownValues::Preserve)
                .with_extension_body(ExtensionType::from(SIGNATURE_ALGORITHMS_CERT), body)
                .with_padding(Padding::Off),
        )
        .unwrap();
        ssl
    };
    // Without the workaround the emulated client gets TLS 1.3. With it, the
    // server picks TLS 1.2 for what it takes to be JDK 11, and this client, which
    // does support TLS 1.3, detects the server's downgrade sentinel and stops.
    let negotiate = |workaround: bool, ssl: Ssl| {
        let mut server = Ssl::new(&server()).unwrap();
        server.set_jdk11_workaround(workaround);
        handshake(ssl, server).0
    };
    let version = |client: Side<super::memory::End>| client.done().ssl().version().unwrap();
    assert_eq!(version(negotiate(false, jdk11())), SslVersion::TLS1_3);
    negotiate(true, jdk11()).panicked_or_failed_with("TLS13_DOWNGRADE");
    // Offering X25519, as JDK 11 never does, is not mistaken for it.
    let mut not_jdk = jdk11();
    not_jdk.set_raw_supported_groups(&[X25519, P256]).unwrap();
    assert_eq!(version(negotiate(true, not_jdk)), SslVersion::TLS1_3);
}

#[test]
fn shape_bodies_replace_and_are_bounded() {
    let body_sent = |shape: ClientHelloShape| {
        let mut ssl = client(|_| {});
        ssl.set_extension_order(&[0x0a0a, SUPPORTED_GROUPS])
            .unwrap();
        ssl.set_client_hello_shape(&shape.with_grease_values(GreaseValues::Pinned))
            .unwrap();
        let (hellos, _) = hellos_of(ssl, Ssl::new(&server()).unwrap());
        hellos[0].body(0x0a0a).unwrap().to_vec()
    };
    let id = ExtensionType::from(0x0a0a);
    let shape = ClientHelloShape::new()
        .with_extension_body(id, [1])
        .with_extension_body(id, [2, 2]);
    assert_eq!(
        body_sent(shape.clone()),
        [2, 2],
        "a later body replaces the earlier one"
    );
    assert_eq!(
        shape,
        ClientHelloShape::new().with_extension_body(id, [2, 2])
    );
    // Bodies of different extensions are kept apart.
    let other = ExtensionType::from(ENCRYPT_THEN_MAC);
    assert_ne!(
        ClientHelloShape::new()
            .with_extension_body(id, [1])
            .with_extension_body(other, [2]),
        ClientHelloShape::new().with_extension_body(other, [2])
    );

    let mut ssl = client(|_| {});
    let largest = ClientHelloShape::new().with_extension_body(id, vec![0; 0xffff]);
    assert!(ssl.set_client_hello_shape(&largest).is_ok());
    let too_large = ClientHelloShape::new().with_extension_body(id, vec![0; 0x1_0000]);
    assert!(ssl.set_client_hello_shape(&too_large).is_err());
}

#[test]
fn a_rejected_shape_changes_nothing() {
    let grease = ExtensionType::from(0x0a0a);
    let mut ssl = client(|_| {});
    ssl.set_raw_key_shares(&[X25519, P256]).unwrap();
    ssl.set_extension_order(&[0x0a0a, SUPPORTED_GROUPS])
        .unwrap();
    let applied = ClientHelloShape::new()
        .with_grease_values(GreaseValues::Pinned)
        .with_padding(Padding::Off)
        .with_extension_body(grease, [1]);
    ssl.set_client_hello_shape(&applied).unwrap();
    // A valid body before an invalid one: neither, nor anything else, applies.
    let rejected = ClientHelloShape::new()
        .with_padding(Padding::ToLength(700))
        .with_extension_body(grease, [2, 3])
        .with_extension_body(ExtensionType::SERVER_NAME, [0]);
    assert!(ssl.set_client_hello_shape(&rejected).is_err());
    let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
    client.done();
    let hello = &hellos[0];
    assert_eq!(hello.ids()[0], 0x0a0a, "values stay pinned");
    assert_eq!(hello.body(0x0a0a), Some(&[1][..]));
    assert!(hello.body(PADDING).is_none(), "padding stays off");
}

#[test]
fn a_later_shape_replaces_the_earlier_one_as_a_whole() {
    let hello = |shapes: &[ClientHelloShape]| {
        let mut ssl = client(|ctx| ctx.set_grease_enabled(true));
        ssl.set_raw_key_shares(&[X25519, P256]).unwrap();
        ssl.set_extension_order(&[0x0a0a, SUPPORTED_GROUPS])
            .unwrap();
        for shape in shapes {
            ssl.set_client_hello_shape(shape).unwrap();
        }
        let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
        client.done();
        hellos[0].clone()
    };
    let first = ClientHelloShape::new()
        .with_grease_lists(GreaseLists::empty())
        .with_padding(Padding::Off)
        .with_extension_body(ExtensionType::from(0x0a0a), [1, 2]);
    let shaped = hello(std::slice::from_ref(&first));
    assert_eq!(shaped.body(shaped.ids()[0]), Some(&[1, 2][..]));
    assert!(!is_grease(shaped.groups()[0]), "no native GREASE");
    // A default shape restores every default, including the context's GREASE.
    let reset = hello(&[first, ClientHelloShape::new()]);
    assert_eq!(reset.body(reset.ids()[0]), Some(&[][..]));
    assert!(is_grease(reset.groups()[0]), "context GREASE is back");
    assert_eq!(reset.len, 512, "padding is native again");
}

#[test]
fn key_shares_without_a_supported_group_request_a_retry() {
    const UNKNOWN: u16 = 0xfefe;
    for policy in [
        UnknownValues::Drop,
        UnknownValues::Forbid,
        UnknownValues::Preserve,
    ] {
        for shares in [
            &[][..],
            &[UNKNOWN],
            &[FFDHE2048],
            &[0x0a0a],
            &[UNKNOWN, 0x0a0a],
        ] {
            let mut ssl = client(|_| {});
            ssl.set_client_hello_shape(&ClientHelloShape::new().with_unknown_values(policy))
                .unwrap();
            ssl.set_raw_supported_groups(&[X25519, P256]).unwrap();
            ssl.set_raw_key_shares(shares).unwrap();
            let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
            let client = client.done();
            let what = format!("{policy:?} {shares:x?}");
            // Unknown key shares are dropped whatever the policy: what is left
            // is GREASE at most, so the server asks for a real one.
            assert!(client.ssl().used_hello_retry_request(), "{what}");
            let sent = hellos[0].key_shares();
            assert!(
                sent.iter().all(|group| is_grease(*group)),
                "{what}: {sent:x?}"
            );
            assert_eq!(sent.len(), shares.iter().filter(|g| is_grease(**g)).count());
            assert_eq!(hellos[1].key_shares().len(), 1, "{what}");
        }
        // A supported share next to an unknown one: no retry needed.
        let mut ssl = client(|_| {});
        ssl.set_client_hello_shape(&ClientHelloShape::new().with_unknown_values(policy))
            .unwrap();
        ssl.set_raw_supported_groups(&[X25519, P256]).unwrap();
        ssl.set_raw_key_shares(&[UNKNOWN, X25519]).unwrap();
        let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
        assert!(!client.done().ssl().used_hello_retry_request());
        assert_eq!(hellos[0].key_shares(), [X25519], "{policy:?}");
    }
}

#[test]
fn extension_orders_have_at_most_sixteen_grease_slots() {
    let all: Vec<u16> = (0..16)
        .map(|n| (n << 12) | 0x0a00 | (n << 4) | 0x0a)
        .collect();
    for values in [
        GreaseValues::Fresh,
        GreaseValues::Pinned,
        GreaseValues::Seeded(9),
    ] {
        for listed in [all.clone(), vec![0x0a0a; 16]] {
            let mut ssl = client(|_| {});
            ssl.set_raw_key_shares(&[X25519]).unwrap();
            ssl.set_extension_order(&listed).unwrap();
            ssl.set_client_hello_shape(&ClientHelloShape::new().with_grease_values(values))
                .unwrap();
            let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
            let what = format!("{values:?} {:x?}", &listed[..2]);
            if matches!(values, GreaseValues::Pinned) && listed[0] == listed[1] {
                // Pinned repeats cannot be made distinct.
                client.panicked_or_failed_with("listed twice");
                continue;
            }
            client.done();
            let mut grease: Vec<u16> = hellos[0]
                .ids()
                .into_iter()
                .filter(|id| is_grease(*id))
                .collect();
            assert_eq!(grease.len(), 16, "{what}");
            if matches!(values, GreaseValues::Pinned) {
                assert_eq!(grease, all, "{what}");
            }
            grease.sort_unstable();
            grease.dedup();
            assert_eq!(grease.len(), 16, "{what}: distinct values");
        }
    }
    // A 17th slot cannot have a distinct value: rejected up front.
    let mut seventeen = all.clone();
    seventeen.push(0x0a0a);
    let mut ssl = client(|_| {});
    assert!(ssl.set_extension_order(&seventeen).is_err());
    let mut ctx = client_context();
    assert!(ctx.set_extension_order(&seventeen).is_err());
    assert!(ctx.set_extension_order(&all).is_ok());
}

/// Every list set explicitly, without GREASE codepoints of its own.
fn exact_lists(ssl: &mut Ssl) {
    ssl.set_raw_cipher_list(&[0x1301, 0x1302, 0xc02b]).unwrap();
    ssl.set_raw_supported_groups(&[X25519, P256]).unwrap();
    ssl.set_raw_key_shares(&[X25519]).unwrap();
    ssl.set_raw_supported_versions(&[0x0304, 0x0303]).unwrap();
    ssl.set_raw_signature_algorithms(&[0x0403, 0x0804]).unwrap();
    ssl.set_extension_order(&[KEY_SHARE, SUPPORTED_VERSIONS, SUPPORTED_GROUPS])
        .unwrap();
}

#[test]
fn set_lists_are_exact_whatever_grease_is_enabled() {
    for (context, lists) in [
        (true, None),
        (false, Some(GreaseLists::all())),
        (true, Some(GreaseLists::all())),
    ] {
        let enable = |ctx: &mut SslContextBuilder| {
            ctx.set_grease_enabled(context);
            ctx.set_grease_sigalgs_enabled(context);
        };
        let shaped = |ssl: &mut Ssl| {
            if let Some(lists) = lists {
                ssl.set_client_hello_shape(&ClientHelloShape::new().with_grease_lists(lists))
                    .unwrap();
            }
        };
        let mut exact = client(enable);
        exact_lists(&mut exact);
        shaped(&mut exact);
        let (hellos, client_side) = hellos_of(exact, Ssl::new(&server()).unwrap());
        client_side.done();
        let what = format!("{context} {lists:?}");
        assert_eq!(hellos[0].grease(), [], "{what}: set lists get no GREASE");
        assert_eq!(hellos[0].ciphers, [0x1301, 0x1302, 0xc02b], "{what}");

        // The same switches still GREASE every native list.
        let mut native = client(enable);
        shaped(&mut native);
        let (hellos, client_side) = hellos_of(native, Ssl::new(&server()).unwrap());
        client_side.done();
        let hello = &hellos[0];
        assert!(is_grease(hello.ciphers[0]), "{what}");
        assert!(is_grease(hello.groups()[0]), "{what}");
        assert!(is_grease(hello.key_shares()[0]), "{what}");
        assert!(is_grease(hello.versions()[0]), "{what}");
        assert!(is_grease(hello.sigalgs()[0]), "{what}");
        assert_eq!(
            hello.ids().iter().filter(|id| is_grease(**id)).count(),
            2,
            "{what}"
        );
    }
}

#[test]
fn context_extension_orders_are_exact() {
    let hello = |order: &[u16]| {
        let ssl = client(|ctx| {
            ctx.set_grease_enabled(true);
            ctx.set_extension_order(order).unwrap();
        });
        let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
        client.done();
        hellos[0].ids()
    };
    // GREASE extensions appear at the order's slots only.
    let ids = hello(&[0x0a0a, SUPPORTED_GROUPS, KEY_SHARE, 0x0a0a]);
    assert!(is_grease(ids[0]) && is_grease(ids[3]), "{ids:x?}");
    assert_eq!(ids[1..3], [SUPPORTED_GROUPS, KEY_SHARE]);
    assert_eq!(ids.iter().filter(|id| is_grease(**id)).count(), 2);
    // An order without slots has no GREASE extensions; unknown IDs are dropped.
    let ids = hello(&[SUPPORTED_GROUPS, ENCRYPT_THEN_MAC, KEY_SHARE]);
    assert_eq!(ids[..2], [SUPPORTED_GROUPS, KEY_SHARE]);
    assert!(
        !ids.iter()
            .any(|id| is_grease(*id) || *id == ENCRYPT_THEN_MAC),
        "{ids:x?}"
    );
    // A connection order replaces the context's; an empty one is canonical
    // and, being set, exact: no GREASE extensions.
    let mut ssl = client(|ctx| {
        ctx.set_grease_enabled(true);
        ctx.set_extension_order(&[SUPPORTED_GROUPS, KEY_SHARE])
            .unwrap();
    });
    ssl.set_extension_order(&[]).unwrap();
    let (hellos, client) = hellos_of(ssl, Ssl::new(&server()).unwrap());
    client.done();
    let ids = hellos[0].ids();
    assert!(!ids.iter().any(|id| is_grease(*id)), "{ids:x?}");
    assert_ne!(ids[..2], [SUPPORTED_GROUPS, KEY_SHARE], "{ids:x?}");
}

/// "Compresses" by copying.
struct Copying;

impl crate::ssl::CertificateCompressor for Copying {
    const ALGORITHM: crate::ssl::CertificateCompressionAlgorithm =
        crate::ssl::CertificateCompressionAlgorithm(0xff01);
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        output.write_all(input)
    }
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        output.write_all(input)
    }
}

#[test]
fn wire_settings_are_fixed_once_the_client_hello_is_written() {
    let algorithms = [<Copying as crate::ssl::CertificateCompressor>::ALGORITHM];
    let mut ctx = client_context();
    ctx.add_certificate_compression_algorithm(Copying).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    assert!(ssl.set_raw_cipher_list(&[0x1301]).is_ok());
    assert!(ssl
        .set_certificate_compression_algorithms(&algorithms)
        .is_ok());
    let (a, _b) = super::memory::ends();
    let Err(crate::ssl::HandshakeError::WouldBlock(mut mid)) = ssl.connect(a) else {
        panic!("the client waits for the server");
    };
    let ssl = mid.ssl_mut();
    assert!(ssl.set_raw_cipher_list(&[0x1302]).is_err());
    assert!(ssl.set_certificate_compression_algorithms(&[]).is_err());
    assert!(ssl.set_raw_supported_groups(&[X25519]).is_err());
    assert!(ssl.set_extension_order(&[]).is_err());
    assert!(ssl
        .set_client_hello_shape(&ClientHelloShape::new())
        .is_err());
}

#[test]
fn every_list_takes_at_most_sixteen_grease_slots() {
    let sixteen: Vec<u16> = (0..16)
        .map(|n| (n << 12) | 0x0a00 | (n << 4) | 0x0a)
        .collect();
    let mut seventeen = sixteen.clone();
    seventeen.push(0x0a0a);
    let with = |values: &[u16], known: u16| [values, &[known]].concat();
    let mut ssl = client(|_| {});
    assert!(ssl.set_raw_cipher_list(&with(&sixteen, 0x1301)).is_ok());
    assert!(ssl.set_raw_cipher_list(&with(&seventeen, 0x1301)).is_err());
    assert!(ssl
        .set_raw_supported_groups(&with(&sixteen, X25519))
        .is_ok());
    assert!(ssl
        .set_raw_supported_groups(&with(&seventeen, X25519))
        .is_err());
    assert!(ssl.set_raw_key_shares(&with(&sixteen, X25519)).is_ok());
    assert!(ssl.set_raw_key_shares(&with(&seventeen, X25519)).is_err());
    assert!(ssl
        .set_raw_supported_versions(&with(&sixteen, 0x0304))
        .is_ok());
    assert!(ssl
        .set_raw_supported_versions(&with(&seventeen, 0x0304))
        .is_err());
    assert!(ssl
        .set_raw_signature_algorithms(&with(&sixteen, 0x0804))
        .is_ok());
    assert!(ssl
        .set_raw_signature_algorithms(&with(&seventeen, 0x0804))
        .is_err());
    let mut ctx = client_context();
    assert!(ctx.set_raw_cipher_list(&with(&sixteen, 0x1301)).is_ok());
    assert!(ctx.set_raw_cipher_list(&with(&seventeen, 0x1301)).is_err());
}
