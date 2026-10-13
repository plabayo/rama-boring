//! Provider-level model of QUIC MITM client-auth interleaving.
//!
//! Four in-memory endpoints: the real client talks to the relay's ingress
//! server, and the relay's egress client talks to the origin. A coordinator does
//! what the relay does between polls: it dials egress with the client's
//! extension order, issues the ingress certificate once the origin is
//! authenticated, pauses egress at the origin's CertificateRequest, authenticates
//! ingress through a policy, answers egress with the mapped credential, binds
//! ingress completion to egress success, and cancels both legs on failure or
//! deadline.

use super::support::{credential, deliver, quic_context, Authority, Gate, Peer};
use crate::ssl::test::wire;
use crate::{
    pkey::{PKey, Private},
    ssl::{
        AsyncSelectCertError, BoxCertificateFinish, BoxCustomVerifyFinish, CertificateSelection,
        SslAlert, SslContext, SslCredential, SslRef, SslVerifyMode,
    },
    x509::X509,
};
use proptest::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering::SeqCst},
    Arc, LazyLock, Mutex,
};

const ORIGIN: &str = "origin.test";

struct Pki {
    /// The relay's interception CA, trusted by the client.
    mitm: Authority,
    /// Authenticates the origin to the relay.
    origin_ca: Authority,
    /// Authenticates real clients to the relay's ingress policy.
    client_ca: Authority,
    /// Authenticates the relay's mapped credential to the origin.
    upstream_ca: Authority,
    origin: (X509, PKey<Private>),
    client: (X509, PKey<Private>),
    untrusted_client: (X509, PKey<Private>),
    mapped: (X509, PKey<Private>),
    /// A mapped credential the origin does not trust.
    unknown_mapped: (X509, PKey<Private>),
}

static PKI: LazyLock<Pki> = LazyLock::new(|| {
    let mitm = Authority::new("relay interception CA");
    let origin_ca = Authority::new("origin CA");
    let client_ca = Authority::new("client CA");
    let upstream_ca = Authority::new("upstream client CA");
    let rogue = Authority::new("rogue CA");
    Pki {
        origin: origin_ca.issue(ORIGIN),
        client: client_ca.issue("client.test"),
        untrusted_client: rogue.issue("client.test"),
        mapped: upstream_ca.issue("relay.test"),
        unknown_mapped: rogue.issue("relay.test"),
        mitm,
        origin_ca,
        client_ca,
        upstream_ca,
    }
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OriginAuth {
    None,
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientCert {
    None,
    Trusted,
    Untrusted,
}

/// A policy wait at which the relay may be cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    Issuer,
    IssuedSigning,
    Upstream,
    MappedSigning,
    Policy,
}

const POINTS: [Point; 5] = [
    Point::Issuer,
    Point::IssuedSigning,
    Point::Upstream,
    Point::MappedSigning,
    Point::Policy,
];

#[derive(Clone, Copy, Debug)]
struct Scenario {
    origin: OriginAuth,
    client: ClientCert,
    /// The relay authenticates ingress even when the origin does not ask.
    ingress_auth: bool,
    /// The mapped credential is unknown to the origin.
    mapped_untrusted: bool,
    async_signers: bool,
    /// Legacy QUIC transport parameter codepoint, per hop.
    legacy: (bool, bool),
    chunk: usize,
    cancel_at: Option<Point>,
}

impl Scenario {
    fn new(origin: OriginAuth, client: ClientCert, ingress_auth: bool) -> Self {
        Self {
            origin,
            client,
            ingress_auth,
            mapped_untrusted: false,
            async_signers: false,
            legacy: (false, false),
            chunk: 1200,
            cancel_at: None,
        }
    }
}

#[derive(Default)]
struct Shared {
    client_hello: Mutex<Option<Vec<u16>>>,
    origin_hello: Mutex<Option<Vec<u16>>>,
    origin_cert: Mutex<Option<X509>>,
    origin_requested: AtomicBool,
    presented: Mutex<Option<X509>>,
    upstream_credential: Mutex<Option<SslCredential>>,
    events: Mutex<Vec<&'static str>>,
}

impl Shared {
    fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }

    fn position(&self, event: &str) -> Option<usize> {
        self.events.lock().unwrap().iter().position(|e| *e == event)
    }
}

struct Gates {
    issuer: Arc<Gate>,
    issued_signing: Arc<Gate>,
    upstream: Arc<Gate>,
    mapped_signing: Arc<Gate>,
    policy: Arc<Gate>,
}

impl Gates {
    fn new() -> Self {
        Self {
            issuer: Gate::new(),
            issued_signing: Gate::new(),
            upstream: Gate::new(),
            mapped_signing: Gate::new(),
            policy: Gate::new(),
        }
    }

    fn at(&self, point: Point) -> &Arc<Gate> {
        match point {
            Point::Issuer => &self.issuer,
            Point::IssuedSigning => &self.issued_signing,
            Point::Upstream => &self.upstream,
            Point::MappedSigning => &self.mapped_signing,
            Point::Policy => &self.policy,
        }
    }

    fn all(&self) -> [&Arc<Gate>; 5] {
        POINTS.map(|point| self.at(point))
    }
}

/// Collects a ClientHello's extension IDs as a relay's peek or an origin sees them.
fn capture_hello(
    slot: &'static str,
    shared: &Arc<Shared>,
) -> impl Fn(crate::ssl::ClientHello<'_>) -> Result<(), crate::ssl::SelectCertError>
       + Send
       + Sync
       + 'static {
    let shared = shared.clone();
    move |hello| {
        let ids = wire::ids(
            &wire::extensions(wire::Reader::new(hello.extensions())).expect("extensions"),
        );
        let target = if slot == "client" {
            &shared.client_hello
        } else {
            &shared.origin_hello
        };
        *target.lock().unwrap() = Some(ids);
        Ok(())
    }
}

fn set_legacy(peer: &mut Peer, legacy: bool) {
    peer.conn.ssl_mut().set_quic_use_legacy_codepoint(legacy);
}

struct Relay {
    scenario: Scenario,
    shared: Arc<Shared>,
    gates: Gates,
    client: Peer,
    ingress: Peer,
    egress: Option<Peer>,
    egress_ctx: SslContext,
    origin: Peer,
    policy_decided: bool,
    policy_bound: bool,
    cancelled: bool,
}

impl Relay {
    fn new(scenario: Scenario) -> Self {
        let pki = &*PKI;
        let shared = Arc::new(Shared::default());
        let gates = Gates::new();

        let mut client = quic_context();
        client.set_verify(SslVerifyMode::PEER);
        client.set_verify_cert_store(pki.mitm.store()).unwrap();
        match scenario.client {
            ClientCert::None => {}
            ClientCert::Trusted => client
                .add_credential(&credential(&pki.client.0, &pki.client.1, None))
                .unwrap(),
            ClientCert::Untrusted => client
                .add_credential(&credential(
                    &pki.untrusted_client.0,
                    &pki.untrusted_client.1,
                    None,
                ))
                .unwrap(),
        }

        let mut origin = quic_context();
        origin
            .add_credential(&credential(&pki.origin.0, &pki.origin.1, None))
            .unwrap();
        origin
            .set_verify_cert_store(pki.upstream_ca.store())
            .unwrap();
        origin.set_verify(match scenario.origin {
            OriginAuth::None => SslVerifyMode::NONE,
            OriginAuth::Optional => SslVerifyMode::PEER,
            OriginAuth::Required => SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        });
        origin.set_select_certificate_callback(capture_hello("origin", &shared));

        let ingress = Self::ingress_context(scenario, &shared, &gates);
        let egress_ctx = Self::egress_context(&shared, &gates);

        let mut client = Peer::quic(&client.build(), false);
        set_legacy(&mut client, scenario.legacy.0);
        let ssl = client.conn.ssl_mut();
        ssl.set_hostname(ORIGIN).unwrap();
        ssl.param_mut().set_host(ORIGIN).unwrap();
        // A distinctive, non-canonical order for the relay to mirror.
        ssl.set_extension_order(&[43, 16, 0xffa5, 57, 51, 13, 10, 0])
            .unwrap();
        let mut ingress = Peer::quic(&ingress, true);
        set_legacy(&mut ingress, scenario.legacy.0);
        let mut origin = Peer::quic(&origin.build(), true);
        set_legacy(&mut origin, scenario.legacy.1);

        Self {
            scenario,
            shared,
            gates,
            client,
            ingress,
            egress: None,
            egress_ctx,
            origin,
            policy_decided: false,
            policy_bound: false,
            cancelled: false,
        }
    }

    fn ingress_context(scenario: Scenario, shared: &Arc<Shared>, gates: &Gates) -> SslContext {
        let mut ingress = quic_context();
        // The relay peeks the ClientHello before issuing anything.
        ingress.set_select_certificate_callback(capture_hello("client", shared));
        let (shared, issuer) = (shared.clone(), gates.issuer.clone());
        let issued_signer = scenario.async_signers.then(|| gates.issued_signing.clone());
        let policy = gates.policy.clone();
        ingress.set_async_certificate_callback(move |_| {
            let (shared, finish_gate) = (shared.clone(), issuer.clone());
            let (issued_signer, policy) = (issued_signer.clone(), policy.clone());
            Ok(issuer.future(
                move || {
                    Box::new(move |mut selection: CertificateSelection<'_>| {
                        finish_gate.record_finish();
                        let origin = shared.origin_cert.lock().unwrap().clone();
                        // Issued only once egress authenticated the origin.
                        let origin = origin.ok_or(AsyncSelectCertError)?;
                        assert!(PKI.origin_ca.issued(&origin));
                        let (cert, key) = PKI.mitm.issue(ORIGIN);
                        let issued = credential(&cert, &key, issued_signer.as_ref());
                        let ssl = selection.ssl_mut();
                        ssl.add_credential(&issued)
                            .map_err(|_| AsyncSelectCertError)?;
                        if scenario.ingress_auth || shared.origin_requested.load(SeqCst) {
                            let mut mode = SslVerifyMode::PEER;
                            if scenario.ingress_auth {
                                mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
                            }
                            install_policy(ssl, mode, &shared, &policy);
                        }
                        shared.event("issued");
                        Ok(())
                    }) as BoxCertificateFinish
                },
                AsyncSelectCertError,
            ))
        });
        ingress.build()
    }

    fn egress_context(shared: &Arc<Shared>, gates: &Gates) -> SslContext {
        let pki = &*PKI;
        let mut egress = quic_context();
        egress.set_verify(SslVerifyMode::PEER);
        egress.set_verify_cert_store(pki.origin_ca.store()).unwrap();
        let (shared, upstream) = (shared.clone(), gates.upstream.clone());
        egress.set_async_certificate_callback(move |selection| {
            // The origin is authenticated before it can ask for a client credential.
            let origin = selection.ssl().peer_certificate().expect("verified origin");
            *shared.origin_cert.lock().unwrap() = Some(origin);
            shared.origin_requested.store(true, SeqCst);
            shared.event("origin requested");
            let (shared, finish_gate) = (shared.clone(), upstream.clone());
            Ok(upstream.future(
                move || {
                    Box::new(move |mut selection: CertificateSelection<'_>| {
                        finish_gate.record_finish();
                        let ssl = selection.ssl_mut();
                        ssl.clear_certificates();
                        if let Some(credential) = shared.upstream_credential.lock().unwrap().take()
                        {
                            ssl.add_credential(&credential)
                                .map_err(|_| AsyncSelectCertError)?;
                        }
                        shared.event("upstream answered");
                        Ok(())
                    }) as BoxCertificateFinish
                },
                AsyncSelectCertError,
            ))
        });
        egress.build()
    }

    fn dial_egress(&mut self) {
        let Some(order) = self.shared.client_hello.lock().unwrap().clone() else {
            return;
        };
        let mut egress = Peer::quic(&self.egress_ctx, false);
        set_legacy(&mut egress, self.scenario.legacy.1);
        let ssl = egress.conn.ssl_mut();
        ssl.set_hostname(ORIGIN).unwrap();
        ssl.param_mut().set_host(ORIGIN).unwrap();
        ssl.set_extension_order(&order).unwrap();
        self.egress = Some(egress);
    }

    fn peers(&mut self) -> [&mut Peer; 4] {
        let egress = self.egress.as_mut().expect("egress dialed");
        [
            &mut self.client,
            &mut self.ingress,
            egress,
            &mut self.origin,
        ]
    }

    fn cancel(&mut self) {
        self.cancelled = true;
        self.ingress.abort();
        if let Some(egress) = &mut self.egress {
            egress.abort();
        }
        self.propagate_closes();
    }

    /// One coordinator step; returns whether anything changed.
    fn step(&mut self) -> bool {
        let before = self.fingerprint();
        let chunk = self.scenario.chunk;
        if self.egress.is_none() {
            self.client.poll();
            deliver(&self.client, &mut self.ingress, chunk);
            self.dial_egress();
        }
        if self.egress.is_none() {
            return self.fingerprint() != before;
        }
        for peer in self.peers() {
            peer.poll();
        }
        let [client, ingress, egress, origin] = self.peers();
        deliver(client, ingress, chunk);
        deliver(ingress, client, chunk);
        deliver(egress, origin, chunk);
        deliver(origin, egress, chunk);

        if let Some(point) = self.scenario.cancel_at {
            if !self.cancelled && self.gates.at(point).is_waiting() {
                self.cancel();
                return true;
            }
        }
        if self.cancelled {
            self.propagate_closes();
            return self.fingerprint() != before;
        }
        self.coordinate();
        self.fingerprint() != before
    }

    /// A TLS failure closes the QUIC connection: its peer receives CONNECTION_CLOSE.
    /// A relay-side abort likewise closes the leg towards its peer.
    fn propagate_closes(&mut self) {
        let egress = self.egress.as_mut().unwrap();
        for (a, b) in [
            (&mut self.client, &mut self.ingress),
            (egress, &mut self.origin),
        ] {
            if a.is_closed() && !b.is_closed() {
                b.abort();
            } else if b.is_closed() && !a.is_closed() {
                a.abort();
            }
        }
    }

    fn coordinate(&mut self) {
        self.propagate_closes();
        let egress = self.egress.as_mut().unwrap();
        // A client completes before its server authenticated it; only the
        // origin's HANDSHAKE_DONE confirms that it accepted the credential.
        let confirmed = egress.is_complete() && self.origin.is_complete();
        if confirmed && self.shared.position("egress confirmed").is_none() {
            self.shared.event("egress confirmed");
        }
        if egress.is_complete() && self.shared.origin_cert.lock().unwrap().is_none() {
            *self.shared.origin_cert.lock().unwrap() = egress.conn.ssl().peer_certificate();
            self.shared.event("origin authenticated");
        }
        if self.shared.origin_cert.lock().unwrap().is_some() && self.gates.issuer.is_waiting() {
            self.gates.issuer.open();
        }
        for (point, gate) in [
            (Point::IssuedSigning, &self.gates.issued_signing),
            (Point::MappedSigning, &self.gates.mapped_signing),
        ] {
            if gate.is_waiting() && self.scenario.cancel_at != Some(point) {
                gate.open();
            }
        }

        if self.gates.policy.is_waiting() && !self.policy_decided {
            self.policy_decided = true;
            let presented = self.shared.presented.lock().unwrap().clone().unwrap();
            if !PKI.client_ca.issued(&presented) {
                self.shared.event("policy rejected");
                self.gates.policy.fail();
            } else if self.gates.upstream.is_waiting() {
                let (cert, key) = if self.scenario.mapped_untrusted {
                    &PKI.unknown_mapped
                } else {
                    &PKI.mapped
                };
                let signer = self
                    .scenario
                    .async_signers
                    .then_some(&self.gates.mapped_signing);
                *self.shared.upstream_credential.lock().unwrap() =
                    Some(credential(cert, key, signer));
                self.shared.event("policy mapped");
                self.policy_bound = true;
                self.gates.upstream.open();
            } else {
                self.shared.event("policy accepted");
                self.gates.policy.open();
            }
        }
        let egress = self.egress.as_mut().unwrap();
        if self.policy_bound && self.gates.policy.is_waiting() {
            // Ingress completes only once the origin accepted the mapped credential.
            if confirmed {
                self.gates.policy.open();
            } else if egress.is_closed() {
                self.gates.policy.fail();
            }
        }
        // A client without a certificate never reaches the policy; once ingress
        // completes, egress answers the origin without a credential.
        if self.gates.upstream.is_waiting() && !self.policy_bound && self.ingress.is_complete() {
            self.shared.event("forward none");
            self.gates.upstream.open();
        }

        // Neither leg outlives the other before handoff.
        if egress.is_closed() && !self.ingress.is_closed() && !self.policy_bound {
            self.ingress.abort();
        }
        if self.ingress.is_closed() && !egress.is_closed() {
            egress.abort();
        }
        if self.ingress.is_complete() && self.shared.position("ingress complete").is_none() {
            self.shared.event("ingress complete");
        }
    }

    fn fingerprint(&self) -> Vec<usize> {
        let mut state = vec![
            self.shared.events.lock().unwrap().len(),
            self.cancelled as usize,
        ];
        for peer in [
            Some(&self.client),
            Some(&self.ingress),
            self.egress.as_ref(),
            Some(&self.origin),
        ]
        .into_iter()
        .flatten()
        {
            state.extend([
                peer.conn.ssl().is_init_finished() as usize,
                peer.is_closed() as usize,
                peer.pending as usize,
                peer.has_output() as usize,
            ]);
        }
        for gate in self.gates.all() {
            state.extend([gate.created(), gate.dropped(), gate.finished()]);
        }
        state
    }

    fn run(mut self) -> Outcome {
        let mut idle = 0;
        for _ in 0..256 {
            if self.step() {
                idle = 0;
            } else {
                idle += 1;
                if idle == 3 {
                    return self.finish();
                }
            }
        }
        panic!("relay did not settle: {:?}", self.scenario);
    }

    fn finish(self) -> Outcome {
        let egress = self.egress.as_ref();
        let outcome = Outcome {
            client: self.client.is_complete(),
            ingress: self.ingress.is_complete(),
            egress: egress.is_some_and(Peer::is_complete),
            origin: self.origin.is_complete(),
            ingress_peer: self.ingress.conn.ssl().peer_certificate(),
            origin_peer: self.origin.conn.ssl().peer_certificate(),
            client_peer: self.client.conn.ssl().peer_certificate(),
            client_alerted: !self.client.record.alerts.lock().unwrap().is_empty(),
            ingress_alerted: !self.ingress.record.alerts.lock().unwrap().is_empty(),
            client_hello: self.shared.client_hello.lock().unwrap().clone(),
            origin_hello: self.shared.origin_hello.lock().unwrap().clone(),
            events: self.shared.events.lock().unwrap().clone(),
            cancelled: self.cancelled,
            alpn: [
                Some(&self.client),
                Some(&self.ingress),
                egress,
                Some(&self.origin),
            ]
            .into_iter()
            .flatten()
            .filter(|peer| peer.is_complete())
            .all(|peer| peer.conn.ssl().selected_alpn_protocol() == Some(&b"h3"[..])),
            transport_parameters: [
                (&self.client, b"server parameters"),
                (&self.ingress, b"client parameters"),
            ]
            .into_iter()
            .chain(egress.map(|egress| (egress, b"server parameters")))
            .chain([(&self.origin, b"client parameters")])
            .filter(|(peer, _)| peer.is_complete())
            .all(|(peer, expected)| peer.conn.peer_transport_parameters() == expected),
            output_after_close: [Some(&self.ingress), egress]
                .into_iter()
                .flatten()
                .any(|peer| peer.aborted && peer.has_output()),
            created: self.gates.all().map(|gate| gate.created()),
            finished: self.gates.all().map(|gate| gate.finished()),
            gates: self.gates,
        };
        // Dropping every leg must release every pending callback.
        drop((self.client, self.ingress, self.egress, self.origin));
        for gate in outcome.gates.all() {
            gate.assert_released();
        }
        outcome
    }
}

fn install_policy(ssl: &mut SslRef, mode: SslVerifyMode, shared: &Arc<Shared>, policy: &Arc<Gate>) {
    let (shared, policy) = (shared.clone(), policy.clone());
    ssl.set_async_custom_verify_callback(mode, move |ssl| {
        // Futures own their inputs: copy the presented leaf for the policy.
        let presented = ssl.peer_certificate().expect("client certificate");
        *shared.presented.lock().unwrap() = Some(presented);
        shared.event("policy started");
        let finish_gate = policy.clone();
        Ok(policy.future(
            move || {
                Box::new(move |_: &mut SslRef| {
                    finish_gate.record_finish();
                    Ok(())
                }) as BoxCustomVerifyFinish
            },
            SslAlert::BAD_CERTIFICATE,
        ))
    });
}

struct Outcome {
    client: bool,
    ingress: bool,
    egress: bool,
    origin: bool,
    ingress_peer: Option<X509>,
    origin_peer: Option<X509>,
    client_peer: Option<X509>,
    client_alerted: bool,
    ingress_alerted: bool,
    client_hello: Option<Vec<u16>>,
    origin_hello: Option<Vec<u16>>,
    events: Vec<&'static str>,
    cancelled: bool,
    alpn: bool,
    transport_parameters: bool,
    output_after_close: bool,
    created: [usize; 5],
    finished: [usize; 5],
    gates: Gates,
}

impl Outcome {
    fn before(&self, a: &str, b: &str) -> bool {
        let position = |event| self.events.iter().position(|e| *e == event);
        matches!((position(a), position(b)), (Some(a), Some(b)) if a < b)
    }

    fn created(&self, point: Point) -> usize {
        self.created[POINTS.iter().position(|p| *p == point).unwrap()]
    }

    /// Invariants that hold for every scenario, cancelled or not.
    #[track_caller]
    fn assert_safe(&self, scenario: &Scenario) {
        let context = format!("{scenario:?} events={:?}", self.events);
        assert!(self.alpn, "{context}");
        assert!(self.transport_parameters, "{context}");
        assert!(!self.output_after_close, "aborted leg emitted: {context}");
        for (index, (created, finished)) in self.created.iter().zip(self.finished).enumerate() {
            assert!(
                *created <= 1,
                "{:?} factory reran: {context}",
                POINTS[index]
            );
            assert!(finished <= *created, "{context}");
        }
        if let Some(point) = scenario.cancel_at.filter(|_| self.cancelled) {
            assert_eq!(
                self.finished[POINTS.iter().position(|p| *p == point).unwrap()],
                0
            );
        }
        // The client only trusts certificates the relay issued for the origin.
        if let Some(peer) = &self.client_peer {
            assert!(PKI.mitm.issued(peer), "{context}");
        }
        // The origin never sees the real client's certificate.
        if let Some(peer) = &self.origin_peer {
            assert!(!PKI.client_ca.issued(peer), "{context}");
        }
        // Ingress never completes authentication the origin rejected.
        if self.ingress
            && self.created(Point::Policy) == 1
            && self.events.contains(&"policy mapped")
        {
            assert!(self.origin && self.egress, "{context}");
        }
        // The origin sees the client's extension order.
        if let (Some(client), Some(origin)) = (&self.client_hello, &self.origin_hello) {
            let common = |a: &[u16], b: &[u16]| -> Vec<u16> {
                a.iter().filter(|id| b.contains(id)).copied().collect()
            };
            assert_eq!(common(client, origin), common(origin, client), "{context}");
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Expected {
    complete: bool,
    origin_sees: Option<&'static str>,
    ingress_sees_client: bool,
    upstream: bool,
    policy: bool,
}

/// The relay contract for a scenario without cancellation.
fn expected(scenario: &Scenario) -> Expected {
    let origin_asks = scenario.origin != OriginAuth::None;
    let ingress_asks = origin_asks || scenario.ingress_auth;
    let presents = ingress_asks && scenario.client != ClientCert::None;
    let policy = presents;
    let accepted = scenario.client == ClientCert::Trusted;
    let mapped = origin_asks && presents && accepted;
    let mapped_accepted = mapped && !scenario.mapped_untrusted;
    let complete = match (scenario.client, ingress_asks) {
        (_, false) => true,
        (ClientCert::Untrusted, true) => false,
        (ClientCert::None, true) => {
            !scenario.ingress_auth && scenario.origin != OriginAuth::Required
        }
        (ClientCert::Trusted, true) => !mapped || mapped_accepted,
    };
    Expected {
        complete,
        origin_sees: (complete && mapped_accepted).then_some("mapped"),
        ingress_sees_client: presents && accepted,
        upstream: origin_asks,
        policy,
    }
}

/// Whether the relay ever waits at `point` in `scenario`.
fn reachable(point: Point, scenario: &Scenario) -> bool {
    let origin_asks = scenario.origin != OriginAuth::None;
    let presents = (origin_asks || scenario.ingress_auth) && scenario.client != ClientCert::None;
    match point {
        Point::Issuer => true,
        Point::IssuedSigning => scenario.async_signers,
        Point::Upstream => origin_asks,
        Point::MappedSigning => {
            scenario.async_signers
                && origin_asks
                && presents
                && scenario.client == ClientCert::Trusted
        }
        Point::Policy => presents,
    }
}

#[track_caller]
fn check(scenario: Scenario) -> Outcome {
    let outcome = Relay::new(scenario).run();
    outcome.assert_safe(&scenario);
    let context = format!("{scenario:?} events={:?}", outcome.events);
    if let Some(point) = scenario.cancel_at {
        assert_eq!(outcome.cancelled, reachable(point, &scenario), "{context}");
    }
    if outcome.cancelled {
        // Cancellation closes every leg and nothing resumes afterwards.
        assert!(
            !outcome.client && !outcome.ingress && !outcome.egress && !outcome.origin,
            "{context}"
        );
        return outcome;
    }
    let expected = expected(&scenario);
    assert_eq!(
        outcome.client && outcome.ingress && outcome.egress && outcome.origin,
        expected.complete,
        "{context}"
    );
    assert_eq!(
        outcome.created(Point::Upstream) == 1,
        expected.upstream,
        "{context}"
    );
    assert_eq!(
        outcome.created(Point::Policy) == 1,
        expected.policy,
        "{context}"
    );
    assert_eq!(
        outcome
            .origin_peer
            .as_ref()
            .is_some_and(|peer| PKI.upstream_ca.issued(peer)),
        expected.origin_sees == Some("mapped"),
        "{context}"
    );
    assert_eq!(
        outcome
            .ingress_peer
            .as_ref()
            .is_some_and(|peer| PKI.client_ca.issued(peer)),
        expected.ingress_sees_client,
        "{context}"
    );
    if expected.complete {
        assert!(outcome.client_hello.is_some() && outcome.origin_hello.is_some());
        assert!(
            !outcome.client_alerted && !outcome.ingress_alerted,
            "{context}"
        );
    } else {
        // Every leg closes: no half-established relay survives a failure.
        assert!(
            !outcome.client && !outcome.ingress && !outcome.egress && !outcome.origin,
            "{context}"
        );
    }
    outcome
}

#[test]
fn server_only_issues_after_egress_and_never_requests_a_client_certificate() {
    for client in [ClientCert::None, ClientCert::Trusted] {
        let outcome = check(Scenario::new(OriginAuth::None, client, false));
        assert!(outcome.ingress_peer.is_none());
        assert!(outcome.origin_peer.is_none());
        assert!(outcome.before("origin authenticated", "issued"));
        assert_eq!(outcome.finished, [1, 0, 0, 0, 0]);
    }
}

#[test]
fn ingress_only_authentication_never_reaches_the_origin() {
    let outcome = check(Scenario::new(OriginAuth::None, ClientCert::Trusted, true));
    assert_eq!(outcome.created(Point::Upstream), 0);
    assert!(outcome.before("issued", "policy accepted"));
    assert!(outcome.before("egress confirmed", "ingress complete"));

    for client in [ClientCert::None, ClientCert::Untrusted] {
        let outcome = check(Scenario::new(OriginAuth::None, client, true));
        assert!(!outcome.client && !outcome.ingress);
        assert!(outcome.ingress_alerted);
    }
}

#[test]
fn mapped_credential_answers_the_origin_after_ingress_authentication() {
    for async_signers in [false, true] {
        let outcome = check(Scenario {
            async_signers,
            ..Scenario::new(OriginAuth::Required, ClientCert::Trusted, false)
        });
        // Egress pauses at the CertificateRequest; ingress issues, authenticates,
        // and only then does egress answer and ingress complete.
        for (a, b) in [
            ("origin requested", "issued"),
            ("issued", "policy started"),
            ("policy started", "policy mapped"),
            ("policy mapped", "upstream answered"),
            ("upstream answered", "egress confirmed"),
            ("egress confirmed", "ingress complete"),
        ] {
            assert!(outcome.before(a, b), "{a} before {b}: {:?}", outcome.events);
        }
        let signing = usize::from(async_signers);
        assert_eq!(outcome.finished, [1, signing, 1, signing, 1]);
    }
}

#[test]
fn optional_origin_auth_without_client_certificate_forwards_none() {
    let outcome = check(Scenario::new(OriginAuth::Optional, ClientCert::None, false));
    assert!(outcome.events.contains(&"forward none"));
    assert!(outcome.origin_peer.is_none());
}

#[test]
fn origin_rejection_closes_the_already_complete_ingress() {
    let outcome = check(Scenario::new(OriginAuth::Required, ClientCert::None, false));
    assert!(outcome.events.contains(&"forward none"));
    assert!(!outcome.egress && !outcome.origin);
}

#[test]
fn policy_rejection_never_answers_the_origin() {
    let outcome = check(Scenario::new(
        OriginAuth::Required,
        ClientCert::Untrusted,
        false,
    ));
    assert!(outcome.events.contains(&"policy rejected"));
    assert_eq!(outcome.finished[2], 0, "egress answered after rejection");
    assert!(!outcome.egress && !outcome.origin && !outcome.ingress);
    assert!(outcome.ingress_alerted);
}

#[test]
fn origin_refusing_the_mapped_credential_fails_ingress_too() {
    // Optional origin auth still rejects a presented credential it cannot verify.
    for (origin, chunk) in [(OriginAuth::Required, 1200), (OriginAuth::Optional, 1)] {
        let outcome = check(Scenario {
            mapped_untrusted: true,
            chunk,
            ..Scenario::new(origin, ClientCert::Trusted, false)
        });
        assert!(outcome.events.contains(&"policy mapped"));
        assert!(!outcome.ingress && !outcome.egress && !outcome.origin);
        assert!(outcome.ingress_alerted, "ingress must not complete unbound");
    }
}

#[test]
fn per_hop_transport_parameter_codepoints_are_independent() {
    for legacy in [(true, false), (false, true), (true, true)] {
        check(Scenario {
            legacy,
            chunk: 97,
            async_signers: true,
            ..Scenario::new(OriginAuth::Required, ClientCert::Trusted, false)
        });
    }
}

#[test]
fn cancellation_at_every_policy_wait_releases_both_legs() {
    let reachable = Scenario {
        async_signers: true,
        ..Scenario::new(OriginAuth::Required, ClientCert::Trusted, false)
    };
    for point in POINTS {
        let outcome = check(Scenario {
            cancel_at: Some(point),
            ..reachable
        });
        assert!(outcome.cancelled, "{point:?} never reached");
        assert!(!outcome.ingress && !outcome.egress, "{point:?}");
        assert!(!outcome.client && !outcome.origin, "{point:?}");
        assert_eq!(outcome.gates.at(point).finished(), 0, "{point:?}");
    }
}

fn scenarios() -> impl Strategy<Value = Scenario> {
    (
        prop_oneof![
            Just(OriginAuth::None),
            Just(OriginAuth::Optional),
            Just(OriginAuth::Required)
        ],
        prop_oneof![
            Just(ClientCert::None),
            Just(ClientCert::Trusted),
            Just(ClientCert::Untrusted)
        ],
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        (any::<bool>(), any::<bool>()),
        prop_oneof![1usize..64, 64usize..1500],
        proptest::option::weighted(0.4, proptest::sample::select(POINTS.to_vec())),
    )
        .prop_map(
            |(
                origin,
                client,
                ingress_auth,
                mapped_untrusted,
                async_signers,
                legacy,
                chunk,
                cancel_at,
            )| {
                Scenario {
                    origin,
                    client,
                    ingress_auth,
                    mapped_untrusted,
                    async_signers,
                    legacy,
                    chunk,
                    cancel_at,
                }
            },
        )
}

#[test]
fn relay_contract_holds_for_every_discrete_scenario() {
    // Every combination of the discrete dimensions, with fragmentation varied
    // deterministically; the property test below samples fragmentation freely.
    const CHUNKS: [usize; 5] = [1, 7, 97, 211, 1200];
    let mut count = 0;
    for origin in [OriginAuth::None, OriginAuth::Optional, OriginAuth::Required] {
        for client in [ClientCert::None, ClientCert::Trusted, ClientCert::Untrusted] {
            for ingress_auth in [false, true] {
                for mapped_untrusted in [false, true] {
                    for async_signers in [false, true] {
                        for legacy in [(false, false), (false, true), (true, false), (true, true)] {
                            for cancel_at in std::iter::once(None).chain(POINTS.map(Some)) {
                                check(Scenario {
                                    origin,
                                    client,
                                    ingress_auth,
                                    mapped_untrusted,
                                    async_signers,
                                    legacy,
                                    chunk: CHUNKS[count % CHUNKS.len()],
                                    cancel_at,
                                });
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(count, 3 * 3 * 2 * 2 * 2 * 4 * 6);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn relay_contract_holds_for_every_scenario(scenario in scenarios()) {
        let outcome = check(scenario);
        if outcome.cancelled {
            prop_assert!(!outcome.ingress || !outcome.egress);
        }
    }
}
