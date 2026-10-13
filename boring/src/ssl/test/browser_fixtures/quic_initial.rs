//! Decryption of client QUIC v1 Initial packets (RFC 9001 §5), to recover the
//! ClientHello a browser sent from its raw datagrams.

use crate::hash::MessageDigest;
use crate::hkdf;
use crate::ssl::test::wire::Reader;
use crate::symm::{self, Cipher, Crypter, Mode};

/// RFC 9001 §5.2.
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const VERSION_1: u32 = 1;

/// HKDF-Expand-Label of TLS 1.3 (RFC 8446 §7.1), with an empty context.
fn expand_label(secret: &[u8], label: &str, len: usize) -> Vec<u8> {
    let label = format!("tls13 {label}");
    let mut info = u16::try_from(len).unwrap().to_be_bytes().to_vec();
    info.push(u8::try_from(label.len()).unwrap());
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    let mut out = vec![0; len];
    hkdf::expand(MessageDigest::sha256(), secret, &info, &mut out).unwrap();
    out
}

/// The client's Initial packet protection keys for a destination connection ID.
struct Keys {
    key: Vec<u8>,
    iv: Vec<u8>,
    hp: Vec<u8>,
}

impl Keys {
    fn client(dcid: &[u8]) -> Self {
        let mut initial = [0; 32];
        hkdf::extract(MessageDigest::sha256(), &INITIAL_SALT, dcid, &mut initial).unwrap();
        let client = expand_label(&initial, "client in", 32);
        Self {
            key: expand_label(&client, "quic key", 16),
            iv: expand_label(&client, "quic iv", 12),
            hp: expand_label(&client, "quic hp", 16),
        }
    }

    /// The header protection mask for a ciphertext sample.
    fn mask(&self, sample: &[u8]) -> [u8; 16] {
        let mut ecb = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &self.hp, None).unwrap();
        ecb.pad(false);
        let mut out = [0; 32];
        assert_eq!(ecb.update(sample, &mut out).unwrap(), 16);
        out[..16].try_into().unwrap()
    }
}

fn varint(reader: &mut Reader<'_>) -> Option<u64> {
    let first = reader.u8()?;
    let mut value = u64::from(first & 0x3f);
    for _ in 1..1 << (first >> 6) {
        value = value << 8 | u64::from(reader.u8()?);
    }
    Some(value)
}

fn len(value: u64) -> usize {
    usize::try_from(value).unwrap()
}

/// The decrypted payloads of the client Initial packets in `datagram`, which
/// may also carry other packets or trailing padding; `None` if any Initial
/// packet is malformed or fails authentication. The first Initial packet of the
/// flight sets the connection ID the keys derive from.
fn initial_payloads(datagram: &[u8], dcid: &mut Option<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let mut payloads = Vec::new();
    let mut rest = datagram;
    // Datagram padding after the last packet is zeros (RFC 9000 §14.1).
    while rest.first().is_some_and(|&byte| byte != 0) {
        let packet = rest;
        let mut header = Reader::new(packet);
        let first = header.u8()?;
        // Long header, fixed bit set, Initial type.
        if first & 0xc0 != 0xc0 {
            return None;
        }
        let version = u32::from_be_bytes(header.bytes(4)?.try_into().unwrap());
        let id = header.prefixed_u8()?.rest();
        header.prefixed_u8()?;
        let initial = first & 0x30 == 0 && version == VERSION_1;
        if initial {
            let token = varint(&mut header)?;
            header.bytes(len(token))?;
        }
        let length = len(varint(&mut header)?);
        let pn_offset = packet.len() - header.rest().len();
        let end = pn_offset.checked_add(length)?;
        rest = packet.get(end..)?;
        if !initial {
            continue;
        }
        let keys = Keys::client(dcid.get_or_insert_with(|| id.to_vec()));
        let mut packet = packet.get(..end)?.to_vec();
        let mask = keys.mask(packet.get(pn_offset + 4..pn_offset + 20)?);
        packet[0] ^= mask[0] & 0x0f;
        let pn_len = usize::from(packet[0] & 0x03) + 1;
        let mut nonce = keys.iv.clone();
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
            // The packet number, right-aligned, XORed into the IV.
            nonce[12 - pn_len + i] ^= packet[pn_offset + i];
        }
        let (aad, sealed) = packet.split_at(pn_offset + pn_len);
        let (ciphertext, tag) = sealed.split_at_checked(sealed.len().checked_sub(16)?)?;
        payloads.push(
            symm::decrypt_aead(
                Cipher::aes_128_gcm(),
                &keys.key,
                Some(&nonce),
                aad,
                ciphertext,
                tag,
            )
            .ok()?,
        );
    }
    rest.iter().all(|&byte| byte == 0).then_some(payloads)
}

/// The CRYPTO stream of a flight of client Initial datagrams, reassembled by
/// offset: the ClientHello. `None` if a datagram is malformed, a frame is not
/// one a client Initial carries, data overlaps inconsistently, or the stream
/// has a gap.
pub(super) fn client_hello(datagrams: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut dcid = None;
    let mut stream: Vec<Option<u8>> = Vec::new();
    for datagram in datagrams {
        for payload in initial_payloads(datagram, &mut dcid)? {
            let mut frames = Reader::new(&payload);
            while !frames.is_empty() {
                match varint(&mut frames)? {
                    // PADDING and PING.
                    0x00 | 0x01 => {}
                    // CRYPTO.
                    0x06 => {
                        let offset = len(varint(&mut frames)?);
                        let data_len = len(varint(&mut frames)?);
                        let data = frames.bytes(data_len)?;
                        if stream.len() < offset + data.len() {
                            stream.resize(offset + data.len(), None);
                        }
                        for (slot, &byte) in stream[offset..].iter_mut().zip(data) {
                            if slot.is_some_and(|known| known != byte) {
                                return None;
                            }
                            *slot = Some(byte);
                        }
                    }
                    _ => return None,
                }
            }
        }
    }
    stream.into_iter().collect()
}

/// The hex fixture `text` as bytes, ignoring whitespace.
pub(super) fn unhex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    hex::decode(text).expect("a hex fixture")
}

#[test]
fn rfc9001_client_initial_keys() {
    // RFC 9001 Appendix A.1.
    let keys = Keys::client(&unhex("8394c8f03e515708"));
    assert_eq!(keys.key, unhex("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(keys.iv, unhex("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(keys.hp, unhex("9f50449e04a0e810283a1e9933adedd2"));
    // RFC 9001 Appendix A.2.
    assert_eq!(
        keys.mask(&unhex("d1b1c98dd7689fb8ec11d242b123dc9b"))[..5],
        unhex("437b9aec36")
    );
}
