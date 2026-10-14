//! Random client wire configurations, run through real handshakes over TCP
//! and QUIC and checked against a reference model of what the ClientHello
//! must carry.
//!
//! The generator deliberately favours edge cases: empty lists, lists of only
//! unknown values or only GREASE codepoints, duplicates, GREASE slots at the
//! edges, extension orders at and beyond their limits, large extension bodies
//! and every shape mode. A native assert aborts the test binary, so every case
//! that runs to the end also shows the native code tolerates it.

use super::memory::{client_context, ends, server_context, End};
use super::wire::{self, is_grease};
use crate::error::ErrorStack;
use crate::ssl::quic::{tests as quic, QuicError};
use crate::ssl::{
    ClientHelloShape, ExtensionType, GreaseLists, GreaseValues, HandshakeError, Padding, Ssl,
    SslRef, SslSession, SslSessionCacheMode, SslStream, SslVersion, UnknownValues,
};
use proptest::prelude::*;
use proptest::sample::{select, Index};
use std::fmt;
use std::sync::{Arc, Mutex};

const SUPPORTED_GROUPS: u16 = 10;
const SIGNATURE_ALGORITHMS: u16 = 13;
const PADDING: u16 = 21;
const PRE_SHARED_KEY: u16 = 41;
const SUPPORTED_VERSIONS: u16 = 43;
const KEY_SHARE: u16 = 51;
const X25519: u16 = 0x001d;
const P256: u16 = 0x0017;
const X25519_MLKEM768: u16 = 0x11ec;

static GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];
static KNOWN_CIPHERS: [u16; 11] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c, 0x002f,
];
// Renegotiation SCSV, fallback SCSV, TLS_AES_128_CCM_SHA256 and unassigned.
static UNKNOWN_CIPHERS: [u16; 6] = [0x0000, 0x00ff, 0x5600, 0x1304, 0xc0ff, 0xffff];
static KNOWN_GROUPS: [u16; 5] = [X25519, P256, 0x0018, 0x0019, X25519_MLKEM768];
// FFDHE 2048/3072, X448 and unassigned.
static UNKNOWN_GROUPS: [u16; 5] = [0x0100, 0x0101, 0x001e, 0x0000, 0xffff];
static KNOWN_VERSIONS: [u16; 2] = [0x0304, 0x0303];
// TLS 1.1, TLS 1.0, a TLS 1.3 draft and DTLS 1.2.
static UNKNOWN_VERSIONS: [u16; 4] = [0x0302, 0x0301, 0x7f1c, 0xfefd];
static KNOWN_SIGALGS: [u16; 10] = [
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807,
];
// Ed448, RSA-PSS-PSS, ECDSA-SHA224 and unassigned.
static UNKNOWN_SIGALGS: [u16; 6] = [0x0808, 0x0809, 0x080a, 0x0303, 0x0000, 0xfe00];
/// Every extension BoringSSL builds itself, padding and pre_shared_key aside.
static KNOWN_EXTENSIONS: [u16; 32] = [
    0, 5, 10, 11, 13, 14, 16, 18, 19, 20, 23, 27, 28, 34, 35, 42, 43, 44, 45, 47, 51, 57, 4832,
    13172, 17513, 17613, 30032, 0x8a3b, 0xca34, 0xfe0d, 0xff01, 0xffa5,
];
// encrypt_then_mac, signature_algorithms_cert, tls_flags and unassigned.
static UNKNOWN_EXTENSIONS: [u16; 8] = [22, 50, 62, 0x1234, 0xff02, 0xdead, 0x00fe, 0x7777];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Versions {
    Tls12,
    Tls13,
    Both,
}

/// A [`ClientHelloShape`], with bodies as `(id, length)`: see [`body`].
#[derive(Debug, Clone)]
struct Shape {
    grease_lists: Option<GreaseLists>,
    values: GreaseValues,
    unknown: UnknownValues,
    padding: Padding,
    bodies: Vec<(u16, usize)>,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            grease_lists: None,
            values: GreaseValues::Fresh,
            unknown: UnknownValues::Drop,
            padding: Padding::Native,
            bodies: Vec::new(),
        }
    }
}

impl Shape {
    fn build(&self) -> ClientHelloShape {
        let mut shape = ClientHelloShape::new()
            .with_grease_values(self.values)
            .with_unknown_values(self.unknown)
            .with_padding(self.padding);
        if let Some(lists) = self.grease_lists {
            shape.set_grease_lists(lists);
        }
        for &(id, len) in &self.bodies {
            shape.set_extension_body(ExtensionType::from(id), body(id, len));
        }
        shape
    }

    /// Whether the native setter accepts it: no body for an extension
    /// BoringSSL builds, and none over 65535 bytes. A later body replaces an
    /// earlier one before the setter sees them.
    fn valid(&self) -> bool {
        self.bodies.iter().all(|&(id, _)| {
            (is_grease(id) || !(is_known_extension(id) || id == PADDING || id == PRE_SHARED_KEY))
                && self.body(id).is_some_and(|body| body.len() <= 0xffff)
        })
    }

    /// The body set for `id`: a later one replaces an earlier one.
    fn body(&self, id: u16) -> Option<Vec<u8>> {
        self.bodies
            .iter()
            .rev()
            .find(|(known, _)| *known == id)
            .map(|&(id, len)| body(id, len))
    }
}

/// Extension body bytes, distinct per extension.
fn body(id: u16, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8) ^ (id as u8)).collect()
}

fn is_known_extension(id: u16) -> bool {
    KNOWN_EXTENSIONS.contains(&id)
}

/// One client wire configuration. Each setter runs only for a `Some` list;
/// orders and shapes are applied in turn.
#[derive(Clone)]
struct Case {
    versions: Versions,
    context_grease: bool,
    context_grease_sigalgs: bool,
    ciphers: Option<Vec<u16>>,
    groups: Option<Vec<u16>>,
    key_shares: Option<Vec<u16>>,
    supported_versions: Option<Vec<u16>>,
    sigalgs: Option<Vec<u16>>,
    orders: Vec<Vec<u16>>,
    shapes: Vec<Shape>,
    shape_first: bool,
    resume: bool,
}

impl Case {
    fn new(versions: Versions) -> Self {
        Self {
            versions,
            context_grease: false,
            context_grease_sigalgs: false,
            ciphers: None,
            groups: None,
            key_shares: None,
            supported_versions: None,
            sigalgs: None,
            orders: Vec::new(),
            shapes: Vec::new(),
            shape_first: false,
            resume: false,
        }
    }

    fn shape(mut self, shape: Shape) -> Self {
        self.shapes.push(shape);
        self
    }

    fn order(mut self, order: &[u16]) -> Self {
        self.orders.push(order.to_vec());
        self
    }

    /// Runs every setter and checks it succeeds exactly when `model` (built
    /// from this case) says it must.
    fn apply(&self, ssl: &mut SslRef, model: &Model) -> Result<(), TestCaseError> {
        fn check(
            name: &str,
            raw: &dyn fmt::Debug,
            ok: bool,
            accepted: bool,
        ) -> Result<(), TestCaseError> {
            prop_assert_eq!(ok, accepted, "{}({:04x?})", name, raw);
            Ok(())
        }
        if self.shape_first {
            self.apply_shapes(ssl)?;
        }
        if let Some(raw) = &self.ciphers {
            let ok = ssl.set_raw_cipher_list(raw).is_ok();
            check("set_raw_cipher_list", raw, ok, model.ciphers.is_some())?;
        }
        if let Some(raw) = &self.groups {
            let ok = ssl.set_raw_supported_groups(raw).is_ok();
            check("set_raw_supported_groups", raw, ok, model.groups.is_some())?;
        }
        if let Some(raw) = &self.key_shares {
            let ok = ssl.set_raw_key_shares(raw).is_ok();
            check("set_raw_key_shares", raw, ok, model.key_shares.is_some())?;
        }
        if let Some(raw) = &self.supported_versions {
            let ok = ssl.set_raw_supported_versions(raw).is_ok();
            check(
                "set_raw_supported_versions",
                raw,
                ok,
                model.versions.is_some(),
            )?;
        }
        if let Some(raw) = &self.sigalgs {
            let ok = ssl.set_raw_signature_algorithms(raw).is_ok();
            check(
                "set_raw_signature_algorithms",
                raw,
                ok,
                model.sigalgs.is_some(),
            )?;
        }
        for order in &self.orders {
            let ok = ssl.set_extension_order(order).is_ok();
            check("set_extension_order", order, ok, order_accepted(order))?;
        }
        if !self.shape_first {
            self.apply_shapes(ssl)?;
        }
        Ok(())
    }

    fn apply_shapes(&self, ssl: &mut SslRef) -> Result<(), TestCaseError> {
        for shape in &self.shapes {
            let ok = ssl.set_client_hello_shape(&shape.build()).is_ok();
            prop_assert_eq!(ok, shape.valid(), "set_client_hello_shape({:?})", shape);
        }
        Ok(())
    }
}

/// Whether the extension order setter accepts `order`: at most 256 IDs, and
/// at most 16 GREASE slots as GREASE extensions must be distinct.
fn order_accepted(order: &[u16]) -> bool {
    order.len() <= 256 && order.iter().filter(|id| is_grease(**id)).count() <= 16
}

/// Lists in hex, as on the wire.
struct Hex<'a>(Option<&'a [u16]>);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(list) => write!(f, "{list:04x?}"),
            None => f.write_str("None"),
        }
    }
}

impl fmt::Debug for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let orders: Vec<Hex<'_>> = self.orders.iter().map(|o| Hex(Some(o))).collect();
        f.debug_struct("Case")
            .field("versions", &self.versions)
            .field("context_grease", &self.context_grease)
            .field("context_grease_sigalgs", &self.context_grease_sigalgs)
            .field("ciphers", &Hex(self.ciphers.as_deref()))
            .field("groups", &Hex(self.groups.as_deref()))
            .field("key_shares", &Hex(self.key_shares.as_deref()))
            .field(
                "supported_versions",
                &Hex(self.supported_versions.as_deref()),
            )
            .field("sigalgs", &Hex(self.sigalgs.as_deref()))
            .field("orders", &orders)
            .field("shapes", &self.shapes)
            .field("shape_first", &self.shape_first)
            .field("resume", &self.resume)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Known,
    /// Left out whatever the policy.
    Skipped,
    Unknown,
}

/// What one connection is configured with, and what its ClientHellos must
/// therefore carry. Built from the documented semantics, not the code.
#[derive(Debug)]
struct Model {
    min13: bool,
    max13: bool,
    quic: bool,
    context_grease: GreaseLists,
    ciphers: Option<Vec<u16>>,
    groups: Option<Vec<u16>>,
    key_shares: Option<Vec<u16>>,
    versions: Option<Vec<u16>>,
    sigalgs: Option<Vec<u16>>,
    order: Option<Vec<u16>>,
    shape: Shape,
}

impl Model {
    /// The model of `case`: a list or order the setter rejects is not set,
    /// and a later accepted order or shape replaces an earlier one.
    fn new(case: &Case, quic: bool) -> Self {
        let mut context_grease = GreaseLists::empty();
        if case.context_grease {
            context_grease = GreaseLists::all() - GreaseLists::SIGNATURE_ALGORITHMS;
        }
        if case.context_grease_sigalgs {
            context_grease |= GreaseLists::SIGNATURE_ALGORITHMS;
        }
        // At most 256 values, and 16 GREASE slots so slots never repeat a value.
        let within_limit = |raw: &Vec<u16>| {
            raw.len() <= 256 && raw.iter().filter(|v| is_grease(**v)).count() <= 16
        };
        Self {
            min13: case.versions == Versions::Tls13,
            max13: case.versions != Versions::Tls12,
            quic,
            context_grease,
            ciphers: case
                .ciphers
                .clone()
                .filter(|raw| !raw.is_empty() && within_limit(raw)),
            // The groups also become the negotiated ones: one must be supported.
            groups: case
                .groups
                .clone()
                .filter(|raw| within_limit(raw) && raw.iter().any(|g| KNOWN_GROUPS.contains(g))),
            key_shares: case.key_shares.clone().filter(within_limit),
            versions: case.supported_versions.clone().filter(within_limit),
            sigalgs: case.sigalgs.clone().filter(within_limit),
            order: case
                .orders
                .iter()
                .rev()
                .find(|order| order_accepted(order))
                .cloned(),
            shape: case
                .shapes
                .iter()
                .rev()
                .find(|shape| shape.valid())
                .cloned()
                .unwrap_or_default(),
        }
    }

    fn pinned(&self) -> bool {
        self.shape.values == GreaseValues::Pinned
    }

    /// Lists that get native GREASE when not set explicitly.
    fn native_grease(&self) -> GreaseLists {
        self.shape.grease_lists.unwrap_or(self.context_grease)
    }

    fn group_class(&self, group: u16) -> Class {
        if !KNOWN_GROUPS.contains(&group) {
            Class::Unknown
        } else if group == X25519_MLKEM768 && !self.max13 {
            // Post-quantum groups need TLS 1.3.
            Class::Skipped
        } else {
            Class::Known
        }
    }

    fn version_class(&self, version: u16) -> Class {
        let supported = match version {
            0x0304 => self.max13,
            0x0303 => !self.min13,
            _ => false,
        };
        if supported {
            Class::Known
        } else {
            Class::Unknown
        }
    }

    fn sigalg_class(sigalg: u16) -> Class {
        if KNOWN_SIGALGS.contains(&sigalg) {
            Class::Known
        } else {
            Class::Unknown
        }
    }

    /// A set list as it must appear on the wire: GREASE slots exactly where
    /// listed (their value too when pinned), later duplicates of other values
    /// dropped when `dedupe` (key shares only: RFC 8446 forbids repeats), and
    /// the unknown-value policy applied. `None`
    /// when the policy forbids it.
    fn expected(
        &self,
        raw: &[u16],
        dedupe: bool,
        class: impl Fn(u16) -> Class,
    ) -> Option<Vec<Option<u16>>> {
        let mut out = Vec::new();
        let mut seen = Vec::new();
        for &value in raw {
            if is_grease(value) {
                // Pinned slots keep their codepoint, so a repeated one is a
                // repeated value; fresh and seeded slots are always distinct.
                if dedupe && self.pinned() {
                    if seen.contains(&value) {
                        continue;
                    }
                    seen.push(value);
                }
                out.push(self.pinned().then_some(value));
                continue;
            }
            if dedupe {
                if seen.contains(&value) {
                    continue;
                }
                seen.push(value);
            }
            match class(value) {
                Class::Known => out.push(Some(value)),
                Class::Skipped => {}
                Class::Unknown => match self.shape.unknown {
                    UnknownValues::Drop => {}
                    UnknownValues::Forbid => return None,
                    UnknownValues::Preserve => out.push(Some(value)),
                },
            }
        }
        Some(out)
    }

    /// Wire values with GREASE slots blanked, unless pinned.
    fn wire(&self, values: &[u16]) -> Vec<Option<u16>> {
        values
            .iter()
            .map(|&value| (!is_grease(value) || self.pinned()).then_some(value))
            .collect()
    }

    fn planned_order(&self) -> &[u16] {
        self.order.as_deref().unwrap_or_default()
    }

    /// Whether the policy fails the handshake before a ClientHello is written.
    fn forbidden(&self) -> bool {
        let forbids = |raw: &Option<Vec<u16>>, class: &dyn Fn(u16) -> Class| {
            raw.as_ref()
                .is_some_and(|raw| self.expected(raw, true, class).is_none())
        };
        forbids(&self.groups, &|g| self.group_class(g))
            || (self.max13 && forbids(&self.versions, &|v| self.version_class(v)))
            || forbids(&self.sigalgs, &Self::sigalg_class)
            || (self.shape.unknown == UnknownValues::Forbid
                && self.planned_order().iter().any(|&id| {
                    !is_grease(id)
                        && !is_known_extension(id)
                        && id != PADDING
                        && id != PRE_SHARED_KEY
                }))
    }

    /// Whether pinned GREASE extensions repeat a value, which fails closed.
    fn pinned_duplicate(&self) -> bool {
        let grease: Vec<u16> = self
            .planned_order()
            .iter()
            .copied()
            .filter(|id| is_grease(*id))
            .collect();
        self.pinned() && (1..grease.len()).any(|i| grease[..i].contains(&grease[i]))
    }

    /// Whether the extensions the order adds may overflow the ClientHello.
    fn oversized(&self) -> bool {
        let preserve = self.shape.unknown == UnknownValues::Preserve;
        let mut seen = Vec::new();
        let mut bytes = 0;
        for &id in self.planned_order() {
            let grease = is_grease(id);
            if !grease && (seen.contains(&id) || is_known_extension(id)) {
                continue;
            }
            seen.push(id);
            if grease || (preserve && id != PADDING && id != PRE_SHARED_KEY) {
                bytes += 4 + self.shape.body(id).map_or(1, |body| body.len());
            }
        }
        bytes > 50_000
    }

    /// Checks a whole connection: what it wrote and how it ended.
    fn check(&self, hellos: &[Vec<u8>], outcome: &Result<(), String>) -> Result<(), TestCaseError> {
        if self.forbidden() || self.pinned_duplicate() {
            prop_assert!(hellos.is_empty(), "a ClientHello was written");
            let Err(error) = outcome else {
                return Err(TestCaseError::fail("the handshake completed"));
            };
            if !self.oversized() {
                let expected = if self.forbidden() {
                    "cannot be negotiated"
                } else {
                    "listed twice"
                };
                prop_assert!(
                    error.contains(expected) || (self.forbidden() && self.pinned_duplicate()),
                    "{}",
                    error
                );
            }
        } else if hellos.is_empty() {
            prop_assert!(
                self.oversized(),
                "no ClientHello was written: {:?}",
                outcome
            );
            prop_assert!(outcome.is_err());
        }
        prop_assert!(hellos.len() <= 2, "{} ClientHellos", hellos.len());
        for (index, hello) in hellos.iter().enumerate() {
            self.check_hello(hello, index == 1)
                .map_err(|error| TestCaseError::fail(format!("ClientHello {index}: {error}")))?;
        }
        Ok(())
    }

    /// Fresh and seeded GREASE slots of one list never repeat a value (a key
    /// share must not repeat a group), and the n-th GREASE values of
    /// supported_groups and key_share match.
    fn check_grease_values(
        &self,
        hello: &wire::ClientHello<'_>,
        retry: bool,
    ) -> Result<(), TestCaseError> {
        if self.pinned() {
            return Ok(());
        }
        let only_grease = |values: Vec<u16>| -> Vec<u16> {
            values.into_iter().filter(|v| is_grease(*v)).collect()
        };
        let groups = only_grease(list(hello, SUPPORTED_GROUPS, 2)?);
        let mut lists = vec![
            ("ciphers", only_grease(hello.ciphers.clone())),
            ("supported_groups", groups.clone()),
            (
                "signature_algorithms",
                only_grease(list(hello, SIGNATURE_ALGORITHMS, 2)?),
            ),
        ];
        if self.max13 {
            lists.push((
                "supported_versions",
                only_grease(list(hello, SUPPORTED_VERSIONS, 1)?),
            ));
            if !retry {
                let body = hello
                    .extension(KEY_SHARE)
                    .ok_or_else(|| TestCaseError::fail("no key_share"))?;
                let shares = only_grease(
                    wire::key_share_groups(body)
                        .ok_or_else(|| TestCaseError::fail("malformed key_share"))?,
                );
                let common = shares.len().min(groups.len());
                prop_assert_eq!(
                    &shares[..common],
                    &groups[..common],
                    "GREASE groups and shares"
                );
                lists.push(("key_share", shares));
            }
        }
        for (name, values) in lists {
            for (i, value) in values.iter().enumerate() {
                prop_assert!(
                    !values[..i].contains(value),
                    "{} repeats GREASE {:#06x}: {:04x?}",
                    name,
                    value,
                    values
                );
            }
        }
        Ok(())
    }

    fn check_hello(&self, bytes: &[u8], retry: bool) -> Result<(), TestCaseError> {
        let Some(hello) = wire::ClientHello::parse(bytes) else {
            return Err(TestCaseError::fail(format!("malformed: {bytes:02x?}")));
        };
        let ids = hello.ids();
        for (i, id) in ids.iter().enumerate() {
            prop_assert!(
                !ids[..i].contains(id),
                "extension {:#06x} twice: {:04x?}",
                id,
                ids
            );
        }
        if let Some(psk) = ids.iter().position(|id| *id == PRE_SHARED_KEY) {
            prop_assert_eq!(
                psk,
                ids.len() - 1,
                "pre_shared_key is not last: {:04x?}",
                ids
            );
        }
        // Padding, if any, is the last extension or comes right before
        // pre_shared_key: never earlier.
        if let Some(padding) = ids.iter().position(|id| *id == PADDING) {
            let expected = ids.len() - 1 - usize::from(ids.last() == Some(&PRE_SHARED_KEY));
            prop_assert_eq!(padding, expected, "padding misplaced: {:04x?}", ids);
        }
        let native = ids
            .iter()
            .rposition(|id| *id != PADDING && *id != PRE_SHARED_KEY)
            .map_or(0, |last| last + 1);
        prop_assert!(
            ids[native..]
                .iter()
                .all(|id| *id == PADDING || *id == PRE_SHARED_KEY),
            "padding is not last before pre_shared_key: {:04x?}",
            ids
        );
        let grease = self.native_grease();
        self.check_grease_values(&hello, retry)?;

        match &self.ciphers {
            Some(raw) => prop_assert_eq!(
                self.wire(&hello.ciphers),
                self.expected(raw, false, |_| Class::Known).unwrap(),
                "ciphers"
            ),
            None => native_list(
                "ciphers",
                &hello.ciphers,
                grease.contains(GreaseLists::CIPHERS),
            )?,
        }

        let groups = list(&hello, SUPPORTED_GROUPS, 2)?;
        match &self.groups {
            Some(raw) => prop_assert_eq!(
                self.wire(&groups),
                self.expected(raw, false, |g| self.group_class(g)).unwrap(),
                "supported_groups"
            ),
            None => native_list("groups", &groups, grease.contains(GreaseLists::GROUPS))?,
        }

        if self.max13 {
            let versions = list(&hello, SUPPORTED_VERSIONS, 1)?;
            match &self.versions {
                Some(raw) => prop_assert_eq!(
                    self.wire(&versions),
                    self.expected(raw, false, |v| self.version_class(v))
                        .unwrap(),
                    "supported_versions"
                ),
                None => native_list(
                    "versions",
                    &versions,
                    grease.contains(GreaseLists::VERSIONS),
                )?,
            }
        } else {
            prop_assert!(hello.extension(SUPPORTED_VERSIONS).is_none());
        }

        let sigalgs = list(&hello, SIGNATURE_ALGORITHMS, 2)?;
        match &self.sigalgs {
            Some(raw) => prop_assert_eq!(
                self.wire(&sigalgs),
                self.expected(raw, false, Self::sigalg_class).unwrap(),
                "signature_algorithms"
            ),
            None => native_list(
                "signature algorithms",
                &sigalgs,
                grease.contains(GreaseLists::SIGNATURE_ALGORITHMS),
            )?,
        }

        if self.max13 {
            let body = hello
                .extension(KEY_SHARE)
                .ok_or_else(|| TestCaseError::fail("no key_share"))?;
            let shares = wire::key_share_groups(body)
                .ok_or_else(|| TestCaseError::fail("malformed key_share"))?;
            if retry {
                // The retry sends one key share, for the group the server chose.
                prop_assert_eq!(shares.len(), 1, "retried key shares {:04x?}", shares);
                prop_assert!(!is_grease(shares[0]));
            } else if let Some(raw) = &self.key_shares {
                // A key share needs a supported group: others are always left out.
                let supported: Vec<u16> = match &self.groups {
                    Some(groups) => groups
                        .iter()
                        .copied()
                        .filter(|g| KNOWN_GROUPS.contains(g))
                        .collect(),
                    None => groups.iter().copied().filter(|g| !is_grease(*g)).collect(),
                };
                let class = |g| {
                    if supported.contains(&g) {
                        Class::Known
                    } else {
                        Class::Skipped
                    }
                };
                prop_assert_eq!(
                    self.wire(&shares),
                    self.expected(raw, true, class).unwrap(),
                    "key shares"
                );
            } else {
                native_list(
                    "key shares",
                    &shares,
                    grease.contains(GreaseLists::KEY_SHARES),
                )?;
            }
        } else {
            prop_assert!(hello.extension(KEY_SHARE).is_none());
        }

        self.check_extensions(&hello.extensions[..native], grease)?;

        let padded = ids.contains(&PADDING);
        let len = bytes.len();
        if retry {
            prop_assert!(!padded, "a retried ClientHello is never padded");
        } else {
            match self.shape.padding {
                Padding::Off => prop_assert!(!padded, "padding is off"),
                Padding::Native if self.quic => prop_assert!(!padded, "QUIC is not padded"),
                Padding::Native => {
                    prop_assert!(!(256..512).contains(&len), "{} bytes, natively padded", len)
                }
                Padding::ToLength(target) => {
                    let target = usize::from(target);
                    if padded {
                        prop_assert_eq!(len, target, "padded length");
                    } else {
                        prop_assert!(len + 4 > target, "{} bytes, not padded to {}", len, target);
                    }
                }
            }
        }
        Ok(())
    }

    /// Extensions before padding and pre_shared_key: a set order comes first,
    /// exactly, and nothing after it is GREASE.
    fn check_extensions(
        &self,
        extensions: &[wire::Extension<'_>],
        grease: GreaseLists,
    ) -> Result<(), TestCaseError> {
        let ids = wire::ids(extensions);
        let Some(order) = &self.order else {
            let count = ids.iter().filter(|id| is_grease(**id)).count();
            if grease.contains(GreaseLists::EXTENSIONS) {
                prop_assert_eq!(count, 2, "native GREASE extensions: {:04x?}", ids);
                prop_assert!(is_grease(ids[0]) && extensions[0].1.is_empty());
                let last = extensions.last().unwrap();
                prop_assert!(is_grease(last.0) && last.1 == [0], "{:04x?}", ids);
            } else {
                prop_assert_eq!(count, 0, "native GREASE extensions: {:04x?}", ids);
            }
            return Ok(());
        };
        let mut at = 0;
        let mut slots = 0;
        let mut seen = Vec::new();
        for &id in order {
            if is_grease(id) {
                let (value, body) = *extensions.get(at).ok_or_else(|| {
                    TestCaseError::fail(format!("GREASE slot {slots} missing: {ids:04x?}"))
                })?;
                prop_assert!(
                    is_grease(value),
                    "slot {}: {:#06x} in {:04x?}",
                    slots,
                    value,
                    ids
                );
                if self.pinned() {
                    prop_assert_eq!(value, id, "pinned slot {}", slots);
                }
                let expected =
                    self.shape
                        .body(id)
                        .unwrap_or(if slots == 0 { vec![] } else { vec![0] });
                prop_assert_eq!(body, &expected[..], "body of GREASE slot {}", slots);
                at += 1;
                slots += 1;
                continue;
            }
            if seen.contains(&id) || id == PADDING || id == PRE_SHARED_KEY {
                continue;
            }
            seen.push(id);
            if is_known_extension(id) {
                // Written where listed, if this connection sends it at all.
                if extensions.get(at).is_some_and(|(next, _)| *next == id) {
                    at += 1;
                } else {
                    prop_assert!(!ids.contains(&id), "{:#06x} out of order: {:04x?}", id, ids);
                }
            } else if self.shape.unknown == UnknownValues::Preserve {
                let expected = self.shape.body(id).unwrap_or_default();
                prop_assert_eq!(
                    extensions.get(at).copied(),
                    Some((id, &expected[..])),
                    "preserved {:#06x} in {:04x?}",
                    id,
                    ids
                );
                at += 1;
            } else {
                prop_assert!(!ids.contains(&id), "dropped {:#06x} was sent", id);
            }
        }
        prop_assert!(
            !ids[at..].iter().any(|id| is_grease(*id)),
            "GREASE after the order: {:04x?}",
            ids
        );
        Ok(())
    }
}

/// A two-byte list extension with a `prefix`-byte length.
fn list(hello: &wire::ClientHello<'_>, id: u16, prefix: usize) -> Result<Vec<u16>, TestCaseError> {
    let body = hello
        .extension(id)
        .ok_or_else(|| TestCaseError::fail(format!("extension {id} missing")))?;
    wire::u16_list(body, prefix)
        .ok_or_else(|| TestCaseError::fail(format!("extension {id} malformed")))
}

/// A native list: one GREASE value, first, when enabled, and none otherwise.
fn native_list(name: &str, values: &[u16], enabled: bool) -> Result<(), TestCaseError> {
    let count = values.iter().filter(|v| is_grease(**v)).count();
    prop_assert_eq!(
        count,
        usize::from(enabled),
        "native {} {:04x?}",
        name,
        values
    );
    prop_assert!(
        !enabled || is_grease(values[0]),
        "native {} {:04x?}",
        name,
        values
    );
    Ok(())
}

/// Records every ClientHello the client writes.
fn capture(ssl: &mut SslRef) -> Arc<Mutex<Vec<Vec<u8>>>> {
    let written = Arc::new(Mutex::new(Vec::new()));
    let sink = written.clone();
    ssl.set_msg_callback(move |_, message| {
        if message.is_written() && message.handshake_type() == Some(1) {
            sink.lock().unwrap().push(message.bytes().to_vec());
        }
    });
    written
}

/// An error with each queued error's detail.
fn describe(stack: &ErrorStack) -> String {
    let mut text = stack.to_string();
    for error in stack.errors() {
        if let Some(data) = error.data() {
            text.push_str(" | ");
            text.push_str(data);
        }
    }
    text
}

/// How one connection went.
#[derive(Debug)]
struct Report {
    hellos: Vec<Vec<u8>>,
    outcome: Result<(), String>,
    retried: bool,
    resumed: bool,
}

enum Side {
    Mid(crate::ssl::MidHandshakeSslStream<End>),
    Done(SslStream<End>),
    Failed(String),
}

impl Side {
    fn from(result: Result<SslStream<End>, HandshakeError<End>>) -> Result<Self, TestCaseError> {
        Ok(match result {
            Ok(stream) => Self::Done(stream),
            Err(HandshakeError::WouldBlock(mid)) => Self::Mid(mid),
            Err(HandshakeError::Failure(mid)) => {
                let stack = mid.error().ssl_error().ok_or_else(|| {
                    TestCaseError::fail(format!("failed without an error stack: {}", mid.error()))
                })?;
                Self::Failed(describe(stack))
            }
            Err(HandshakeError::SetupFailure(stack)) => Self::Failed(describe(&stack)),
        })
    }

    fn step(self) -> Result<Self, TestCaseError> {
        match self {
            Self::Mid(mid) => Self::from(mid.handshake()),
            other => Ok(other),
        }
    }
}

/// Runs a TCP handshake in memory. It must complete or fail within a bounded
/// number of steps.
fn drive(
    client: Ssl,
    server: Ssl,
) -> Result<(Result<SslStream<End>, String>, Side), TestCaseError> {
    let (a, b) = ends();
    let mut client = Side::from(client.connect(a))?;
    let mut server = Side::from(server.accept(b))?;
    for _ in 0..64 {
        client = client.step()?;
        server = server.step()?;
        if !matches!(client, Side::Mid(_)) && !matches!(server, Side::Mid(_)) {
            break;
        }
    }
    let client = match (client, &server) {
        (Side::Done(stream), Side::Done(_) | Side::Failed(_)) => Ok(stream),
        (Side::Failed(error), _) => Err(error),
        // A peer that gave up leaves the other waiting.
        (Side::Mid(_), Side::Failed(error)) => Err(format!("server: {error}")),
        _ => return Err(TestCaseError::fail("the handshake stalled")),
    };
    Ok((client, server))
}

/// Runs `case` over TCP, resuming on a second connection when asked.
fn run_tcp(case: &Case) -> Result<Vec<Report>, TestCaseError> {
    let mut ctx = client_context();
    let (min, max) = match case.versions {
        Versions::Tls12 => (SslVersion::TLS1_2, SslVersion::TLS1_2),
        Versions::Tls13 => (SslVersion::TLS1_3, SslVersion::TLS1_3),
        Versions::Both => (SslVersion::TLS1_2, SslVersion::TLS1_3),
    };
    ctx.set_min_proto_version(Some(min)).unwrap();
    ctx.set_max_proto_version(Some(max)).unwrap();
    ctx.set_grease_enabled(case.context_grease);
    ctx.set_grease_sigalgs_enabled(case.context_grease_sigalgs);
    ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    let session = Arc::new(Mutex::new(None::<SslSession>));
    let sink = session.clone();
    ctx.set_new_session_callback(move |_, new| *sink.lock().unwrap() = Some(new));
    let ctx = ctx.build();
    let server = server_context().build();

    let mut reports = Vec::new();
    for resuming in [false, true] {
        let offered = session.lock().unwrap().take();
        if resuming && (!case.resume || offered.is_none()) {
            break;
        }
        let mut ssl = Ssl::new(&ctx).unwrap();
        let model = Model::new(case, false);
        case.apply(&mut ssl, &model)?;
        let hellos = capture(&mut ssl);
        if let Some(offered) = offered.filter(|_| resuming) {
            unsafe { ssl.set_session(&offered) }.unwrap();
        }
        let (client, server) = drive(ssl, Ssl::new(&server).unwrap())?;
        let report = match client {
            Ok(mut stream) => {
                // Reading application data processes TLS 1.3 session tickets.
                if let Side::Done(mut server) = server {
                    server.ssl_write(b"x").unwrap();
                    let mut byte = [0];
                    prop_assert_eq!(stream.ssl_read(&mut byte).ok(), Some(1));
                }
                Report {
                    hellos: hellos.lock().unwrap().clone(),
                    outcome: Ok(()),
                    retried: stream.ssl().used_hello_retry_request(),
                    resumed: stream.ssl().session_reused(),
                }
            }
            Err(error) => Report {
                hellos: hellos.lock().unwrap().clone(),
                outcome: Err(error),
                retried: false,
                resumed: false,
            },
        };
        model.check(&report.hellos, &report.outcome)?;
        let failed = report.outcome.is_err();
        reports.push(report);
        if failed {
            break;
        }
    }
    Ok(reports)
}

/// `case` as QUIC runs it: TLS 1.3 only, and the QUIC client context has no
/// GREASE of its own.
fn over_quic(case: &Case) -> Case {
    let mut case = case.clone();
    case.versions = Versions::Tls13;
    case.context_grease = false;
    case.context_grease_sigalgs = false;
    case
}

/// Runs `case` over QUIC, resuming when asked.
fn run_quic(case: &Case) -> Result<Vec<Report>, TestCaseError> {
    let case = over_quic(case);
    let (client_ctx, server_ctx, tickets) = quic::contexts();
    let mut reports = Vec::new();
    for resuming in [false, true] {
        let ticket = tickets.lock().unwrap().take();
        if resuming && (!case.resume || ticket.is_none()) {
            break;
        }
        let c = Arc::new(quic::Record::default());
        let s = Arc::new(quic::Record::default());
        let mut client = quic::connection(&client_ctx, false, c.clone());
        let mut server = quic::connection(&server_ctx, true, s.clone());
        let model = Model::new(&case, true);
        case.apply(client.ssl_mut(), &model)?;
        let hellos = capture(client.ssl_mut());
        if let Some(ticket) = ticket.filter(|_| resuming) {
            unsafe { client.ssl_mut().set_session(&ticket) }.unwrap();
        }
        let outcome = match quic::pump(&mut client, &mut server, &c, &s) {
            Ok(()) => Ok(()),
            Err(QuicError::Tls(error)) => Err(describe(error.ssl_error().ok_or_else(|| {
                TestCaseError::fail(format!("failed without an error stack: {error}"))
            })?)),
            Err(QuicError::Callback(stack)) => Err(describe(&stack)),
            Err(other) => return Err(TestCaseError::fail(format!("QUIC failed: {other}"))),
        };
        let report = Report {
            hellos: hellos.lock().unwrap().clone(),
            retried: outcome.is_ok() && client.ssl().used_hello_retry_request(),
            resumed: outcome.is_ok() && client.ssl().session_reused(),
            outcome,
        };
        model.check(&report.hellos, &report.outcome)?;
        let failed = report.outcome.is_err();
        reports.push(report);
        if failed {
            break;
        }
    }
    Ok(reports)
}

fn grease() -> impl Strategy<Value = u16> {
    select(&GREASE[..])
}

fn value(known: &'static [u16], unknown: &'static [u16]) -> impl Strategy<Value = u16> {
    prop_oneof![
        4 => select(known),
        1 => select(unknown),
        1 => grease(),
    ]
}

/// A raw list biased towards edge cases.
fn raw_list(known: &'static [u16], unknown: &'static [u16]) -> impl Strategy<Value = Vec<u16>> {
    let mixed = (
        prop::collection::vec(value(known, unknown), 0..10),
        grease(),
        0..4u8,
        any::<Index>(),
        any::<Option<Index>>(),
    )
        .prop_map(|(mut list, slot, edge, at, duplicate)| {
            // A GREASE slot first, last or in the middle.
            match edge {
                0 => list.insert(0, slot),
                1 => list.push(slot),
                2 => list.insert(at.index(list.len() + 1), slot),
                _ => {}
            }
            if let Some(duplicate) = duplicate.filter(|_| !list.is_empty()) {
                list.push(list[duplicate.index(list.len())]);
            }
            list
        });
    prop_oneof![
        1 => Just(Vec::new()),
        1 => prop::collection::vec(select(unknown), 1..5),
        1 => prop::collection::vec(grease(), 1..5),
        1 => prop::collection::vec(select(known), 1..8),
        8 => mixed,
        1 => prop::collection::vec(value(known, unknown), 250..300),
    ]
}

fn extension_id() -> impl Strategy<Value = u16> {
    prop_oneof![
        4 => select(&KNOWN_EXTENSIONS[..]),
        2 => select(&UNKNOWN_EXTENSIONS[..]),
        1 => Just(PADDING),
        1 => Just(PRE_SHARED_KEY),
    ]
}

/// An extension order with 0 to 20 GREASE slots, distinct or repeated, among
/// known, unknown, padding, pre_shared_key and repeated IDs; sometimes empty
/// or over the 256-ID limit.
fn extension_order() -> impl Strategy<Value = Vec<u16>> {
    let slots = prop_oneof![
        3 => Just(0usize),
        3 => Just(1),
        1 => Just(2),
        1 => Just(15),
        2 => Just(16),
        1 => Just(17),
        1 => Just(20),
    ];
    let mixed = (
        prop::collection::vec(extension_id(), 0..12),
        slots,
        any::<bool>(),
        prop::collection::vec(grease(), 20),
        prop::collection::vec(any::<Index>(), 20),
        any::<Option<Index>>(),
    )
        .prop_map(|(mut ids, slots, distinct, random, positions, duplicate)| {
            let offset = GREASE.iter().position(|g| *g == random[0]).unwrap();
            for slot in 0..slots {
                let value = if distinct {
                    GREASE[(offset + slot) % GREASE.len()]
                } else {
                    random[slot]
                };
                ids.insert(positions[slot].index(ids.len() + 1), value);
            }
            if let Some(duplicate) = duplicate.filter(|_| !ids.is_empty()) {
                ids.push(ids[duplicate.index(ids.len())]);
            }
            ids
        });
    prop_oneof![
        1 => Just(Vec::new()),
        10 => mixed,
        1 => prop::collection::vec(extension_id(), 250..=256),
        1 => prop::collection::vec(extension_id(), 257..300),
    ]
}

fn shape() -> impl Strategy<Value = Shape> {
    let id = prop_oneof![
        3 => grease(),
        3 => select(&UNKNOWN_EXTENSIONS[..]),
        // Bodies BoringSSL builds itself are rejected.
        1 => select(vec![0u16, SUPPORTED_GROUPS, PADDING, PRE_SHARED_KEY]),
    ];
    let len = prop_oneof![
        3 => Just(0usize),
        3 => Just(1),
        2 => 2..64usize,
        2 => Just(4000),
        1 => Just(0xffff),
        1 => Just(0x1_0000),
    ];
    (
        prop::option::of((0..64u32).prop_map(GreaseLists::from_bits_truncate)),
        prop_oneof![
            Just(GreaseValues::Fresh),
            any::<u64>().prop_map(GreaseValues::Seeded),
            Just(GreaseValues::Pinned),
        ],
        prop_oneof![
            Just(UnknownValues::Drop),
            Just(UnknownValues::Forbid),
            Just(UnknownValues::Preserve),
        ],
        prop_oneof![
            Just(Padding::Native),
            Just(Padding::Off),
            select(vec![0u16, 1, 256, 511, 512, 700, 0xffff]).prop_map(Padding::ToLength),
            any::<u16>().prop_map(Padding::ToLength),
        ],
        prop::collection::vec((id, len), 0..4),
    )
        .prop_map(|(grease_lists, values, unknown, padding, bodies)| Shape {
            grease_lists,
            values,
            unknown,
            padding,
            bodies,
        })
}

fn case() -> impl Strategy<Value = Case> {
    let lists = (
        prop::option::weighted(0.6, raw_list(&KNOWN_CIPHERS, &UNKNOWN_CIPHERS)),
        prop::option::weighted(0.6, raw_list(&KNOWN_GROUPS, &UNKNOWN_GROUPS)),
        prop::option::weighted(0.6, raw_list(&KNOWN_GROUPS, &UNKNOWN_GROUPS)),
        prop::option::weighted(0.6, raw_list(&KNOWN_VERSIONS, &UNKNOWN_VERSIONS)),
        prop::option::weighted(0.6, raw_list(&KNOWN_SIGALGS, &UNKNOWN_SIGALGS)),
    );
    let settings = (
        prop_oneof![
            Just(Versions::Tls12),
            Just(Versions::Tls13),
            Just(Versions::Both)
        ],
        any::<bool>(),
        any::<bool>(),
        prop::collection::vec(extension_order(), 0..=2),
        prop::collection::vec(shape(), 0..=2),
        any::<bool>(),
        any::<bool>(),
    );
    (lists, settings).prop_map(
        |(
            (ciphers, groups, key_shares, supported_versions, sigalgs),
            (versions, context_grease, context_grease_sigalgs, orders, shapes, shape_first, resume),
        )| Case {
            versions,
            context_grease,
            context_grease_sigalgs,
            ciphers,
            groups,
            key_shares,
            supported_versions,
            sigalgs,
            orders,
            shapes,
            shape_first,
            resume,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_wire_configurations_over_tcp(case in case()) {
        run_tcp(&case)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_wire_configurations_over_quic(case in case()) {
        run_quic(&case)?;
    }
}

fn completes(reports: &[Report]) -> &Report {
    let report = reports.last().expect("a connection");
    assert_eq!(report.outcome, Ok(()), "{report:?}");
    report
}

fn fails(reports: &[Report]) -> &Report {
    let report = reports.last().expect("a connection");
    assert!(report.outcome.is_err(), "{report:?}");
    report
}

fn shape_with(configure: impl FnOnce(&mut Shape)) -> Shape {
    let mut shape = Shape::default();
    configure(&mut shape);
    shape
}

#[test]
fn empty_key_shares_ask_for_a_retry() {
    for versions in [Versions::Tls13, Versions::Both] {
        let mut case = Case::new(versions);
        case.key_shares = Some(vec![]);
        assert!(completes(&run_tcp(&case).unwrap()).retried);
        assert!(completes(&run_quic(&case).unwrap()).retried);
    }
}

#[test]
fn unsupported_key_shares_are_dropped_under_every_policy() {
    for unknown in [
        UnknownValues::Drop,
        UnknownValues::Forbid,
        UnknownValues::Preserve,
    ] {
        let mut case = Case::new(Versions::Tls13).shape(shape_with(|s| s.unknown = unknown));
        case.key_shares = Some(vec![0x0100, 0x001e, 0xffff]);
        assert!(completes(&run_tcp(&case).unwrap()).retried);
        // Known groups the connection does not list are dropped too.
        case.groups = Some(vec![X25519]);
        case.key_shares = Some(vec![P256, 0x0100]);
        assert!(completes(&run_tcp(&case).unwrap()).retried);
    }
}

#[test]
fn grease_only_key_shares_ask_for_a_retry() {
    let mut case = Case::new(Versions::Tls13);
    case.key_shares = Some(vec![0x0a0a, 0x0a0a, 0x3a3a]);
    assert!(completes(&run_tcp(&case).unwrap()).retried);
    let case = case.shape(shape_with(|s| s.values = GreaseValues::Pinned));
    assert!(completes(&run_tcp(&case).unwrap()).retried);
}

#[test]
fn empty_and_degenerate_lists_never_abort() {
    let lists: [&[u16]; 4] = [&[], &[0xffff, 0x0000], &[0x0a0a, 0x1a1a], &[0x0a0a; 3]];
    for versions in [Versions::Tls12, Versions::Tls13, Versions::Both] {
        for raw in lists {
            for set in 0..5 {
                let mut case = Case::new(versions);
                let raw = Some(raw.to_vec());
                match set {
                    0 => case.ciphers = raw,
                    1 => case.groups = raw,
                    2 => case.key_shares = raw,
                    3 => case.supported_versions = raw,
                    _ => case.sigalgs = raw,
                }
                run_tcp(&case).unwrap();
                run_quic(&case).unwrap();
            }
        }
    }
}

#[test]
fn grease_slots_first_middle_and_last() {
    let mut case = Case::new(Versions::Both).order(&[0x0a0a, 10, 0x1a1a, 13, 43, 51, 0x2a2a]);
    case.ciphers = Some(vec![0x0a0a, 0x1301, 0x1a1a, 0xc02f, 0x2a2a]);
    case.groups = Some(vec![0x0a0a, X25519, 0x1a1a, P256, 0x2a2a]);
    case.key_shares = Some(vec![0x0a0a, X25519, 0x1a1a]);
    case.supported_versions = Some(vec![0x0a0a, 0x0304, 0x1a1a, 0x0303, 0x2a2a]);
    case.sigalgs = Some(vec![0x0a0a, 0x0804, 0x1a1a, 0x0403, 0x2a2a]);
    for values in [
        GreaseValues::Fresh,
        GreaseValues::Seeded(3),
        GreaseValues::Pinned,
    ] {
        let case = case.clone().shape(shape_with(|s| {
            s.values = values;
            s.grease_lists = Some(GreaseLists::all());
        }));
        completes(&run_tcp(&case).unwrap());
        completes(&run_quic(&case).unwrap());
    }
}

/// Lists keep repeats as listed (Safari repeats a signature algorithm); key
/// shares drop later repeats, and an order lists each extension once.
#[test]
fn duplicates_are_kept_except_in_key_shares_and_orders() {
    let mut case = Case::new(Versions::Both).order(&[51, 10, 51, 0x0a0a, 10, 0x0a0a]);
    case.ciphers = Some(vec![0x1301, 0x1301, 0xc02f, 0x1301]);
    case.groups = Some(vec![X25519, P256, X25519, 0x0a0a, 0x0a0a]);
    case.key_shares = Some(vec![X25519, X25519, 0x0a0a, 0x0a0a]);
    case.supported_versions = Some(vec![0x0304, 0x0304, 0x0303]);
    case.sigalgs = Some(vec![0x0804, 0x0804, 0x0403]);
    completes(&run_tcp(&case).unwrap());
    completes(&run_quic(&case).unwrap());
}

#[test]
fn extension_orders_take_at_most_16_grease_slots() {
    for slots in [0, 1, 15, 16, 17, 20] {
        for values in [GreaseValues::Fresh, GreaseValues::Pinned] {
            let mut order: Vec<u16> = GREASE.iter().copied().cycle().take(slots).collect();
            order.insert(order.len() / 2, SUPPORTED_GROUPS);
            let case = Case::new(Versions::Both)
                .order(&order)
                .shape(shape_with(|s| s.values = values));
            // Over the limit the setter fails, the order is not used, and the
            // native extensions are sent without GREASE.
            let reports = run_tcp(&case).unwrap();
            completes(&reports);
            let hello = wire::ClientHello::parse(&reports[0].hellos[0]).unwrap();
            let grease = hello.ids().into_iter().filter(|id| is_grease(*id)).count();
            assert_eq!(grease, if slots <= 16 { slots } else { 0 }, "{slots}");
            completes(&run_quic(&case).unwrap());
        }
    }
}

#[test]
fn extension_orders_take_at_most_256_ids() {
    let long: Vec<u16> = KNOWN_EXTENSIONS.iter().copied().cycle().take(256).collect();
    completes(&run_tcp(&Case::new(Versions::Both).order(&long)).unwrap());
    // A rejected order leaves the previous one in place.
    let mut longer = long.clone();
    longer.push(0x0a0a);
    let case = Case::new(Versions::Both)
        .order(&[0x0a0a, SUPPORTED_GROUPS])
        .order(&longer);
    let reports = run_tcp(&case).unwrap();
    let hello = wire::ClientHello::parse(&completes(&reports).hellos[0]).unwrap();
    assert!(is_grease(hello.ids()[0]));
    assert_eq!(hello.ids()[1], SUPPORTED_GROUPS);
}

#[test]
fn unknown_extensions_with_and_without_bodies() {
    for unknown in [
        UnknownValues::Drop,
        UnknownValues::Forbid,
        UnknownValues::Preserve,
    ] {
        for len in [0, 1, 4000] {
            let case = Case::new(Versions::Both)
                .order(&[22, 0x0a0a, 50, 0x1a1a, 0x1234, 10])
                .shape(shape_with(|s| {
                    s.unknown = unknown;
                    s.bodies = vec![(22, len), (0x1a1a, len)];
                }));
            let reports = run_tcp(&case).unwrap();
            if unknown == UnknownValues::Forbid {
                assert!(fails(&reports).hellos.is_empty());
            } else {
                completes(&reports);
            }
            run_quic(&case).unwrap();
        }
    }
}

#[test]
fn bodies_too_large_or_of_native_extensions_are_rejected() {
    for (id, len) in [
        (0x0a0a, 0x1_0000),
        (0, 0),
        (PADDING, 1),
        (PRE_SHARED_KEY, 1),
    ] {
        let case = Case::new(Versions::Both)
            .order(&[0x0a0a, 22])
            .shape(shape_with(|s| s.unknown = UnknownValues::Preserve))
            .shape(shape_with(|s| s.bodies = vec![(id, len)]));
        // The rejected shape leaves the earlier one in place.
        completes(&run_tcp(&case).unwrap());
    }
    // The largest body is accepted, though the ClientHello cannot carry it.
    let case = Case::new(Versions::Both)
        .order(&[0x0a0a])
        .shape(shape_with(|s| s.bodies = vec![(0x0a0a, 0xffff)]));
    fails(&run_tcp(&case).unwrap());
}

#[test]
fn padding_and_pre_shared_key_keep_their_places() {
    for padding in [
        Padding::Native,
        Padding::Off,
        Padding::ToLength(0),
        Padding::ToLength(1),
        Padding::ToLength(512),
        Padding::ToLength(700),
        Padding::ToLength(0xffff),
    ] {
        let mut case = Case::new(Versions::Tls13)
            .order(&[PRE_SHARED_KEY, PADDING, 0x0a0a, 51, 43, PADDING, 10, 0x1a1a])
            .shape(shape_with(|s| s.padding = padding));
        case.resume = true;
        // Small key shares keep the ClientHello within the natively padded
        // range, and a group the server takes avoids a retry.
        case.groups = Some(vec![X25519, P256]);
        case.key_shares = Some(vec![X25519]);
        let reports = run_tcp(&case).unwrap();
        if padding == Padding::ToLength(0xffff) {
            // The server refuses a ClientHello this large.
            fails(&reports);
            continue;
        }
        assert_eq!(reports.len(), 2, "{padding:?}: {reports:?}");
        assert!(completes(&reports).resumed, "{padding:?}");
        let hello = wire::ClientHello::parse(&reports[1].hellos[0]).unwrap();
        assert_eq!(hello.ids().last(), Some(&PRE_SHARED_KEY));
        let quic = run_quic(&case).unwrap();
        assert!(completes(&quic).resumed, "{padding:?}");
    }
}

#[test]
fn every_policy_and_value_mode_with_every_version_range() {
    for versions in [Versions::Tls12, Versions::Tls13, Versions::Both] {
        for unknown in [
            UnknownValues::Drop,
            UnknownValues::Forbid,
            UnknownValues::Preserve,
        ] {
            for values in [
                GreaseValues::Fresh,
                GreaseValues::Seeded(9),
                GreaseValues::Pinned,
            ] {
                let mut case = Case::new(versions)
                    .order(&[0x0a0a, 22, 43, 10, 0x1a1a])
                    .shape(shape_with(|s| {
                        s.unknown = unknown;
                        s.values = values;
                    }));
                case.groups = Some(vec![0x0a0a, X25519, 0x0100, P256]);
                case.supported_versions = Some(vec![0x1a1a, 0x0304, 0x0303, 0x0302]);
                case.sigalgs = Some(vec![0x0804, 0x0808, 0x0403, 0x0a0a]);
                case.resume = true;
                let reports = run_tcp(&case).unwrap();
                if unknown == UnknownValues::Forbid {
                    assert!(fails(&reports).hellos.is_empty());
                } else {
                    completes(&reports);
                }
            }
        }
    }
}

#[test]
fn set_lists_get_no_native_grease() {
    for (context, lists) in [(true, None), (false, Some(GreaseLists::all()))] {
        let mut case = Case::new(Versions::Both).order(&[SUPPORTED_GROUPS]);
        case.context_grease = context;
        case.context_grease_sigalgs = context;
        case.ciphers = Some(vec![0x1301, 0xc02f]);
        case.groups = Some(vec![X25519, P256]);
        case.key_shares = Some(vec![X25519]);
        case.supported_versions = Some(vec![0x0304, 0x0303]);
        case.sigalgs = Some(vec![0x0804, 0x0403]);
        case.shapes = vec![Shape {
            grease_lists: lists,
            ..Shape::default()
        }];
        let reports = run_tcp(&case).unwrap();
        let hello = wire::ClientHello::parse(&completes(&reports).hellos[0]).unwrap();
        assert!(!hello.ciphers.iter().any(|c| is_grease(*c)));
        assert!(!hello.ids().iter().any(|id| is_grease(*id)));
    }
}

#[test]
fn empty_extension_order_is_exact() {
    // A set order is exact, with no GREASE beyond its own slots, as a set
    // empty list is for every other list.
    let mut case = Case::new(Versions::Both).order(&[]);
    case.context_grease = true;
    run_tcp(&case).unwrap();
    let case = Case::new(Versions::Tls13).order(&[]).shape(shape_with(|s| {
        s.grease_lists = Some(GreaseLists::EXTENSIONS);
    }));
    run_quic(&case).unwrap();
}

#[test]
fn grease_key_shares_offer_distinct_groups() {
    // RFC 8446, section 4.2.8: clients MUST NOT offer multiple KeyShareEntry
    // values for the same group, and strict servers reject such a ClientHello.
    for values in [GreaseValues::Fresh, GreaseValues::Seeded(1)] {
        let mut case = Case::new(Versions::Tls13).shape(shape_with(|s| s.values = values));
        case.key_shares = Some(vec![0x0a0a, X25519, 0x1a1a]);
        let reports = run_tcp(&case).unwrap();
        let hello = wire::ClientHello::parse(&reports[0].hellos[0]).unwrap();
        let shares = wire::key_share_groups(hello.extension(KEY_SHARE).unwrap()).unwrap();
        assert_ne!(shares[0], shares[2], "{values:?}: {shares:04x?}");
    }
}
