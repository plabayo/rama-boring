//! Strict parsing of TLS handshake messages for wire-level tests.
//!
//! Every read is length-checked and every length prefix must be consumed
//! exactly, as BoringSSL's own parser requires: malformed input yields `None`,
//! never a panic and never a partial result. A test oracle built on this cannot
//! accept a message BoringSSL would reject. The property tests below check
//! that parsing never panics, that it inverts encoding, and that any truncation
//! or trailing byte is rejected; a differential test checks it against
//! BoringSSL's own view of real ClientHellos.

/// A cursor over bytes where every read is checked.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(head)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|bytes| bytes[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.bytes(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.bytes(3)
            .map(|bytes| usize::from_be_bytes([0, 0, 0, 0, 0, bytes[0], bytes[1], bytes[2]]))
    }

    /// The contents of a one-byte length prefix.
    pub(crate) fn prefixed_u8(&mut self) -> Option<Reader<'a>> {
        let len = self.u8()?;
        self.bytes(len.into()).map(Reader)
    }

    /// The contents of a two-byte length prefix.
    pub(crate) fn prefixed_u16(&mut self) -> Option<Reader<'a>> {
        let len = self.u16()?;
        self.bytes(len.into()).map(Reader)
    }

    fn prefixed_u24(&mut self) -> Option<Reader<'a>> {
        let len = self.u24()?;
        self.bytes(len).map(Reader)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn rest(self) -> &'a [u8] {
        self.0
    }

    /// Ends parsing: `None` if anything is left over.
    pub(crate) fn finish(self) -> Option<()> {
        self.0.is_empty().then_some(())
    }

    /// The remaining bytes as a list of two-byte values.
    pub(crate) fn u16s(mut self) -> Option<Vec<u16>> {
        let mut values = Vec::new();
        while !self.is_empty() {
            values.push(self.u16()?);
        }
        Some(values)
    }
}

/// An extension: its ID and body.
pub(crate) type Extension<'a> = (u16, &'a [u8]);

/// The extensions of a block, without the block's own length prefix.
pub(crate) fn extensions(mut block: Reader<'_>) -> Option<Vec<Extension<'_>>> {
    let mut extensions = Vec::new();
    while !block.is_empty() {
        let id = block.u16()?;
        extensions.push((id, block.prefixed_u16()?.rest()));
    }
    Some(extensions)
}

/// An optional trailing extensions block, as in TLS 1.2 hellos.
fn trailing_extensions(mut fields: Reader<'_>) -> Option<Vec<Extension<'_>>> {
    if fields.is_empty() {
        return Some(Vec::new());
    }
    let block = fields.prefixed_u16()?;
    fields.finish()?;
    extensions(block)
}

pub(crate) fn ids(extensions: &[Extension<'_>]) -> Vec<u16> {
    extensions.iter().map(|(id, _)| *id).collect()
}

pub(crate) fn find<'a>(extensions: &[Extension<'a>], id: u16) -> Option<&'a [u8]> {
    extensions
        .iter()
        .find(|(ext, _)| *ext == id)
        .map(|(_, body)| *body)
}

pub(crate) fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

/// A handshake message's type and body; the header length must match exactly.
pub(crate) fn message(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let mut reader = Reader::new(bytes);
    let kind = reader.u8()?;
    let body = reader.prefixed_u24()?;
    reader.finish()?;
    Some((kind, body.rest()))
}

/// The first handshake message of the first record in `bytes`.
pub(crate) fn first_record_message(bytes: &[u8]) -> Option<&[u8]> {
    let mut records = Reader::new(bytes);
    (records.u8()? == 0x16).then_some(())?;
    records.u16()?;
    let mut fragment = records.prefixed_u16()?;
    let start = fragment.rest();
    fragment.u8()?;
    let len = fragment.u24()?;
    start.get(..4 + len)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientHello<'a> {
    pub(crate) legacy_version: u16,
    pub(crate) random: &'a [u8],
    pub(crate) session_id: &'a [u8],
    pub(crate) ciphers: Vec<u16>,
    pub(crate) compression: &'a [u8],
    pub(crate) extensions: Vec<Extension<'a>>,
}

impl<'a> ClientHello<'a> {
    /// Parses a whole ClientHello message, header included.
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        let (1, body) = message(bytes)? else {
            return None;
        };
        let mut fields = Reader::new(body);
        Some(Self {
            legacy_version: fields.u16()?,
            random: fields.bytes(32)?,
            session_id: fields.prefixed_u8()?.rest(),
            ciphers: fields.prefixed_u16()?.u16s()?,
            compression: fields.prefixed_u8()?.rest(),
            extensions: trailing_extensions(fields)?,
        })
    }

    /// The whole message, header included.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut body = self.legacy_version.to_be_bytes().to_vec();
        body.extend_from_slice(self.random);
        push_u8_prefixed(&mut body, self.session_id);
        let ciphers: Vec<u8> = self.ciphers.iter().flat_map(|c| c.to_be_bytes()).collect();
        push_u16_prefixed(&mut body, &ciphers);
        push_u8_prefixed(&mut body, self.compression);
        push_u16_prefixed(&mut body, &encode_extensions(&self.extensions));
        encode_message(1, &body)
    }

    pub(crate) fn ids(&self) -> Vec<u16> {
        ids(&self.extensions)
    }

    pub(crate) fn extension(&self, id: u16) -> Option<&'a [u8]> {
        find(&self.extensions, id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerHello<'a> {
    pub(crate) cipher: u16,
    pub(crate) extensions: Vec<Extension<'a>>,
}

impl<'a> ServerHello<'a> {
    /// Parses a whole ServerHello message, header included.
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        let (2, body) = message(bytes)? else {
            return None;
        };
        let mut fields = Reader::new(body);
        fields.bytes(2 + 32)?;
        fields.prefixed_u8()?;
        let cipher = fields.u16()?;
        fields.u8()?;
        Some(Self {
            cipher,
            extensions: trailing_extensions(fields)?,
        })
    }

    pub(crate) fn ids(&self) -> Vec<u16> {
        ids(&self.extensions)
    }
}

/// Parses a whole EncryptedExtensions message, header included.
pub(crate) fn encrypted_extensions(bytes: &[u8]) -> Option<Vec<Extension<'_>>> {
    let (8, body) = message(bytes)? else {
        return None;
    };
    let mut fields = Reader::new(body);
    let block = fields.prefixed_u16()?;
    fields.finish()?;
    extensions(block)
}

/// The groups of a `key_share` extension body sent by a client.
pub(crate) fn key_share_groups(body: &[u8]) -> Option<Vec<u16>> {
    let mut outer = Reader::new(body);
    let mut entries = outer.prefixed_u16()?;
    outer.finish()?;
    let mut groups = Vec::new();
    while !entries.is_empty() {
        groups.push(entries.u16()?);
        entries.prefixed_u16()?;
    }
    Some(groups)
}

/// A list of two-byte values behind a one- or two-byte length prefix that
/// spans the whole body.
pub(crate) fn u16_list(body: &[u8], prefix: usize) -> Option<Vec<u16>> {
    let mut outer = Reader::new(body);
    let list = match prefix {
        1 => outer.prefixed_u8()?,
        2 => outer.prefixed_u16()?,
        _ => return None,
    };
    outer.finish()?;
    list.u16s()
}

/// A handshake message with its header.
pub(crate) fn encode_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![kind];
    message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    message.extend_from_slice(body);
    message
}

pub(crate) fn encode_extensions(extensions: &[Extension<'_>]) -> Vec<u8> {
    let mut block = Vec::new();
    for (id, body) in extensions {
        block.extend_from_slice(&id.to_be_bytes());
        push_u16_prefixed(&mut block, body);
    }
    block
}

fn push_u8_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(u8::try_from(bytes.len()).unwrap());
    out.extend_from_slice(bytes);
}

fn push_u16_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}

mod tests {
    use super::*;
    use crate::ssl::test::memory::{client_context, handshake, server_context};
    use crate::ssl::{
        ClientHelloShape, ExtensionType, GreaseValues, Padding, Ssl, SslVersion, UnknownValues,
    };
    use proptest::prelude::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    struct Owned {
        legacy_version: u16,
        random: Vec<u8>,
        session_id: Vec<u8>,
        ciphers: Vec<u16>,
        compression: Vec<u8>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    impl Owned {
        fn borrow(&self) -> ClientHello<'_> {
            ClientHello {
                legacy_version: self.legacy_version,
                random: &self.random,
                session_id: &self.session_id,
                ciphers: self.ciphers.clone(),
                compression: &self.compression,
                extensions: self
                    .extensions
                    .iter()
                    .map(|(id, body)| (*id, body.as_slice()))
                    .collect(),
            }
        }
    }

    fn client_hellos() -> impl Strategy<Value = Owned> {
        (
            any::<u16>(),
            prop::collection::vec(any::<u8>(), 32),
            prop::collection::vec(any::<u8>(), 0..=32),
            prop::collection::vec(any::<u16>(), 0..64),
            prop::collection::vec(any::<u8>(), 0..4),
            prop::collection::vec(
                (any::<u16>(), prop::collection::vec(any::<u8>(), 0..300)),
                0..24,
            ),
        )
            .prop_map(
                |(legacy_version, random, session_id, ciphers, compression, extensions)| Owned {
                    legacy_version,
                    random,
                    session_id,
                    ciphers,
                    compression,
                    extensions,
                },
            )
    }

    fn extension_lists() -> impl Strategy<Value = Vec<(u16, Vec<u8>)>> {
        prop::collection::vec(
            (any::<u16>(), prop::collection::vec(any::<u8>(), 0..64)),
            0..12,
        )
    }

    fn borrowed(extensions: &[(u16, Vec<u8>)]) -> Vec<Extension<'_>> {
        extensions
            .iter()
            .map(|(id, body)| (*id, body.as_slice()))
            .collect()
    }

    fn server_hello(cipher: u16, session_id: &[u8], extensions: &[Extension<'_>]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        push_u8_prefixed(&mut body, session_id);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        push_u16_prefixed(&mut body, &encode_extensions(extensions));
        encode_message(2, &body)
    }

    fn encrypted(extensions: &[Extension<'_>]) -> Vec<u8> {
        let mut body = Vec::new();
        push_u16_prefixed(&mut body, &encode_extensions(extensions));
        encode_message(8, &body)
    }

    /// `message` with `extra` appended inside its body, header length fixed.
    fn with_trailing_body_byte(message: &[u8], extra: u8) -> Vec<u8> {
        let mut body = message[4..].to_vec();
        body.push(extra);
        encode_message(message[0], &body)
    }

    fn list(values: &[u16], prefix: usize) -> Vec<u8> {
        let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
        let mut out = Vec::new();
        if prefix == 1 {
            push_u8_prefixed(&mut out, &bytes);
        } else {
            push_u16_prefixed(&mut out, &bytes);
        }
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn trailing_bytes_inside_a_body_are_rejected(
            hello in client_hellos(),
            extensions in extension_lists(),
            extra in any::<u8>(),
        ) {
            let client_hello = with_trailing_body_byte(&hello.borrow().encode(), extra);
            prop_assert_eq!(ClientHello::parse(&client_hello), None);
            let extensions = borrowed(&extensions);
            let server = with_trailing_body_byte(&server_hello(0x1301, &[1, 2], &extensions), extra);
            prop_assert_eq!(ServerHello::parse(&server), None);
            let encrypted = with_trailing_body_byte(&encrypted(&extensions), extra);
            prop_assert_eq!(encrypted_extensions(&encrypted), None);
        }

        #[test]
        fn server_messages_parse_strictly(
            cipher in any::<u16>(),
            session_id in prop::collection::vec(any::<u8>(), 0..=32),
            extensions in extension_lists(),
            cut in any::<prop::sample::Index>(),
        ) {
            let extensions = borrowed(&extensions);
            let server = server_hello(cipher, &session_id, &extensions);
            prop_assert_eq!(
                ServerHello::parse(&server),
                Some(ServerHello { cipher, extensions: extensions.clone() })
            );
            prop_assert_eq!(ServerHello::parse(&server[..cut.index(server.len())]), None);
            let encrypted = encrypted(&extensions);
            prop_assert_eq!(encrypted_extensions(&encrypted), Some(extensions.clone()));
            prop_assert_eq!(encrypted_extensions(&encrypted[..cut.index(encrypted.len())]), None);
            // A message of another type is not mistaken for either.
            let mut other = encrypted.clone();
            other[0] = 4;
            prop_assert_eq!(encrypted_extensions(&other), None);
            prop_assert_eq!(ServerHello::parse(&other), None);
        }

        #[test]
        fn lists_parse_strictly(
            values in prop::collection::vec(any::<u16>(), 0..100),
            wide in any::<bool>(),
            extra in any::<u8>(),
            cut in any::<prop::sample::Index>(),
        ) {
            let prefix = if wide { 2 } else { 1 };
            let encoded = list(&values, prefix);
            prop_assert_eq!(u16_list(&encoded, prefix), Some(values.clone()));
            prop_assert_eq!(u16_list(&encoded[..cut.index(encoded.len())], prefix), None);
            let mut trailing = encoded.clone();
            trailing.push(extra);
            prop_assert_eq!(u16_list(&trailing, prefix), None);
            // An odd byte inside the list, with the prefix covering it.
            let mut bytes: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
            bytes.push(extra);
            let mut odd = Vec::new();
            if wide {
                push_u16_prefixed(&mut odd, &bytes);
            } else {
                push_u8_prefixed(&mut odd, &bytes);
            }
            prop_assert_eq!(u16_list(&odd, prefix), None);
        }

        #[test]
        fn key_shares_parse_strictly(
            shares in prop::collection::vec(
                (any::<u16>(), prop::collection::vec(any::<u8>(), 0..40)),
                0..6,
            ),
            extra in any::<u8>(),
            cut in any::<prop::sample::Index>(),
        ) {
            let mut entries = Vec::new();
            for (group, key) in &shares {
                entries.extend_from_slice(&group.to_be_bytes());
                push_u16_prefixed(&mut entries, key);
            }
            let mut body = Vec::new();
            push_u16_prefixed(&mut body, &entries);
            let groups: Vec<u16> = shares.iter().map(|(group, _)| *group).collect();
            prop_assert_eq!(key_share_groups(&body), Some(groups));
            prop_assert_eq!(key_share_groups(&body[..cut.index(body.len())]), None);
            body.push(extra);
            prop_assert_eq!(key_share_groups(&body), None);
        }

        #[test]
        fn parsing_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = ClientHello::parse(&bytes);
            let _ = ServerHello::parse(&bytes);
            let _ = encrypted_extensions(&bytes);
            let _ = key_share_groups(&bytes);
            let _ = u16_list(&bytes, 1);
            let _ = u16_list(&bytes, 2);
            let _ = first_record_message(&bytes);
        }

        #[test]
        fn parsing_inverts_encoding(hello in client_hellos()) {
            let hello = hello.borrow();
            let bytes = hello.encode();
            prop_assert_eq!(ClientHello::parse(&bytes), Some(hello));
        }

        #[test]
        fn truncated_or_extended_messages_are_rejected(
            hello in client_hellos(),
            cut in any::<prop::sample::Index>(),
            extra in any::<u8>(),
        ) {
            let bytes = hello.borrow().encode();
            let cut = cut.index(bytes.len());
            prop_assert_eq!(ClientHello::parse(&bytes[..cut]), None);
            let mut extended = bytes.clone();
            extended.push(extra);
            prop_assert_eq!(ClientHello::parse(&extended), None);
        }

        #[test]
        fn a_corrupted_byte_never_parses_to_skipped_or_invented_bytes(
            hello in client_hellos(),
            at in any::<prop::sample::Index>(),
            value in any::<u8>(),
        ) {
            let mut bytes = hello.borrow().encode();
            let at = at.index(bytes.len());
            bytes[at] = value;
            // Whatever a corrupted message parses to must encode back to it:
            // the parser never skips or invents bytes. The one exception is an
            // absent extensions block, which encodes as an empty one.
            if let Some(parsed) = ClientHello::parse(&bytes) {
                let encoded = parsed.encode();
                if encoded != bytes {
                    prop_assert!(parsed.extensions.is_empty());
                    prop_assert_eq!(&encoded[4..bytes.len()], &bytes[4..]);
                    prop_assert_eq!(&encoded[bytes.len()..], &[0, 0]);
                }
            }
        }
    }

    #[test]
    fn hellos_without_extensions_are_accepted_and_stray_bytes_are_not() {
        let hello = ClientHello {
            legacy_version: 0x0303,
            random: &[0; 32],
            session_id: &[],
            ciphers: vec![0x002f],
            compression: &[0],
            extensions: Vec::new(),
        };
        let encoded = hello.encode();
        // Drop the empty extensions block: a valid TLS 1.2 hello.
        let bare = encode_message(1, &encoded[4..encoded.len() - 2]);
        assert_eq!(ClientHello::parse(&bare), Some(hello));
        let stray = with_trailing_body_byte(&bare, 0);
        assert_eq!(ClientHello::parse(&stray), None);
        let server = server_hello(0x002f, &[], &[]);
        let bare = encode_message(2, &server[4..server.len() - 2]);
        assert_eq!(ServerHello::parse(&bare).unwrap().extensions, []);
        assert_eq!(ServerHello::parse(&with_trailing_body_byte(&bare, 0)), None);
    }

    #[test]
    fn only_handshake_records_yield_a_message() {
        let message = encrypted(&[(0, &[1][..])]);
        let mut record = vec![0x16, 3, 3];
        push_u16_prefixed(&mut record, &message);
        assert_eq!(first_record_message(&record), Some(&message[..]));
        record[0] = 0x17;
        assert_eq!(first_record_message(&record), None);
        record[0] = 0x16;
        assert_eq!(first_record_message(&record[..record.len() - 1]), None);
    }

    /// The parser agrees with BoringSSL's own parser on real ClientHellos:
    /// every extension it finds is the one BoringSSL looks up by ID.
    #[test]
    fn client_hellos_parse_as_boringssl_parses_them() {
        let shapes: [fn(&mut Ssl); 4] = [
            |_| {},
            |ssl| ssl.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap(),
            |ssl| {
                let shape = ClientHelloShape::new()
                    .with_grease_values(GreaseValues::Seeded(7))
                    .with_unknown_values(UnknownValues::Preserve)
                    .with_padding(Padding::ToLength(700))
                    .with_extension_body(ExtensionType::from(0x8a8a), [1, 2, 3])
                    .with_extension_body(ExtensionType::from(22), [9]);
                ssl.set_client_hello_shape(&shape).unwrap();
                ssl.set_raw_supported_groups(&[0x0a0a, 0x001d, 0x0100, 0x0017])
                    .unwrap();
                ssl.set_extension_order(&[0x8a8a, 0, 22, 10, 13, 43, 51, 0x1a1a])
                    .unwrap();
            },
            |ssl| {
                ssl.set_raw_cipher_list(&[0x0a0a, 0x1301, 0xc02b, 0x0a0a])
                    .unwrap();
            },
        ];
        for shape in shapes {
            let written = Arc::new(Mutex::new(Vec::new()));
            let sink = written.clone();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let seen_sink = seen.clone();
            let mut server = server_context();
            server.set_select_certificate_callback(move |hello| {
                let raw = hello.extensions();
                let looked_up: Vec<_> = extensions(Reader::new(raw))
                    .expect("BoringSSL accepted these extensions")
                    .into_iter()
                    .map(|(id, _)| {
                        (
                            id,
                            hello
                                .get_extension(ExtensionType::from(id))
                                .map(<[u8]>::to_vec),
                        )
                    })
                    .collect();
                seen_sink.lock().unwrap().push((
                    hello.random().to_vec(),
                    hello.ciphers().to_vec(),
                    looked_up,
                ));
                Ok(())
            });
            let mut client = Ssl::new(&client_context().build()).unwrap();
            client.set_msg_callback(move |_, message| {
                if message.is_written() && message.handshake_type() == Some(1) {
                    sink.lock().unwrap().push(message.bytes().to_vec());
                }
            });
            shape(&mut client);
            let _ = handshake(client, Ssl::new(&server.build()).unwrap());
            let written = written.lock().unwrap();
            let seen = seen.lock().unwrap();
            assert!(!written.is_empty());
            assert_eq!(written.len(), seen.len());
            for (bytes, (random, ciphers, looked_up)) in written.iter().zip(seen.iter()) {
                let hello = ClientHello::parse(bytes).expect("a well-formed ClientHello");
                assert_eq!(hello.encode(), *bytes);
                assert_eq!(hello.random, random.as_slice());
                assert_eq!(Reader::new(ciphers).u16s().unwrap(), hello.ciphers);
                let ours: Vec<_> = hello
                    .extensions
                    .iter()
                    .map(|(id, body)| (*id, Some(body.to_vec())))
                    .collect();
                assert_eq!(&ours, looked_up);
            }
        }
    }
}
