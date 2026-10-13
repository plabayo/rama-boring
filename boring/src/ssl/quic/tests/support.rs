//! Shared doubles for asynchronous QUIC handshake tests: controllable callback
//! futures, counting wakers, a polling peer driver and a runtime PKI.

use super::{connection, Record};
use crate::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
    ssl::{
        quic::{EncryptionLevel, HandshakeStatus, QuicConnection, QuicError},
        AsyncPrivateKeyMethod, AsyncPrivateKeyMethodError, BoxPrivateKeyMethodFinish,
        BoxPrivateKeyMethodFuture, ExDataFuture, SslContext, SslContextBuilder, SslCredential,
        SslMethod, SslRef, SslSignatureAlgorithm, SslVersion,
    },
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        store::{X509Store, X509StoreBuilder},
        X509Name, X509,
    },
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc, Mutex,
    },
    task::{Context, Poll, RawWaker, RawWakerVTable, Wake, Waker},
};

/// Counts wake-ups delivered to one simulated transport task.
#[derive(Default)]
pub(super) struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, SeqCst);
    }
}

impl WakeCount {
    pub(super) fn new() -> (Arc<Self>, Waker) {
        let count = Arc::new(Self::default());
        let waker = Waker::from(count.clone());
        (count, waker)
    }

    pub(super) fn get(&self) -> usize {
        self.0.load(SeqCst)
    }
}

/// A waker whose clones and drops are counted, proving waker reuse and release.
pub(super) struct CloneCount {
    pub(super) clones: AtomicUsize,
    pub(super) drops: AtomicUsize,
    pub(super) wakes: AtomicUsize,
}

impl CloneCount {
    pub(super) fn new() -> &'static Self {
        Box::leak(Box::new(Self {
            clones: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
        }))
    }

    /// A new handle; counted like a clone so `live` includes the caller's own.
    pub(super) fn waker(&'static self) -> Waker {
        self.clones.fetch_add(1, SeqCst);
        // SAFETY: the vtable only ever reads a leaked, immortal `CloneCount`.
        unsafe {
            Waker::from_raw(RawWaker::new(
                (self as *const Self).cast(),
                &CLONE_COUNT_VTABLE,
            ))
        }
    }

    /// Handles still alive, including any the test itself holds.
    pub(super) fn live(&self) -> usize {
        self.clones.load(SeqCst) - self.drops.load(SeqCst)
    }
}

static CLONE_COUNT_VTABLE: RawWakerVTable = RawWakerVTable::new(
    |data| {
        unsafe { &*data.cast::<CloneCount>() }
            .clones
            .fetch_add(1, SeqCst);
        RawWaker::new(data, &CLONE_COUNT_VTABLE)
    },
    |data| {
        let count = unsafe { &*data.cast::<CloneCount>() };
        count.wakes.fetch_add(1, SeqCst);
        count.drops.fetch_add(1, SeqCst);
    },
    |data| {
        unsafe { &*data.cast::<CloneCount>() }
            .wakes
            .fetch_add(1, SeqCst);
    },
    |data| {
        unsafe { &*data.cast::<CloneCount>() }
            .drops
            .fetch_add(1, SeqCst);
    },
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Wait,
    Pass,
    Fail,
}

/// Stands in for one asynchronous policy, issuer, verifier or signer.
///
/// Each future it creates counts its polls and drop; finish closures count their
/// calls. A test opens or fails the gate, which wakes the last registered task.
pub(super) struct Gate {
    outcome: Mutex<Outcome>,
    waker: Mutex<Option<Waker>>,
    pub(super) created: AtomicUsize,
    pub(super) polls: AtomicUsize,
    pub(super) dropped: AtomicUsize,
    pub(super) finished: AtomicUsize,
}

impl Gate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            outcome: Mutex::new(Outcome::Wait),
            waker: Mutex::new(None),
            created: AtomicUsize::new(0),
            polls: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
        })
    }

    pub(super) fn open(&self) {
        self.resolve(Outcome::Pass);
    }

    pub(super) fn fail(&self) {
        self.resolve(Outcome::Fail);
    }

    fn resolve(&self, outcome: Outcome) {
        *self.outcome.lock().unwrap() = outcome;
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    pub(super) fn created(&self) -> usize {
        self.created.load(SeqCst)
    }

    pub(super) fn finished(&self) -> usize {
        self.finished.load(SeqCst)
    }

    pub(super) fn dropped(&self) -> usize {
        self.dropped.load(SeqCst)
    }

    /// A created future is still owned by the TLS stack.
    pub(super) fn is_waiting(&self) -> bool {
        self.created() > self.dropped()
    }

    /// Every future was released and none outlived its connection.
    #[track_caller]
    pub(super) fn assert_released(&self) {
        assert_eq!(self.created(), self.dropped(), "leaked callback future");
        assert!(self.finished() <= self.created());
    }

    /// Creates a future resolving to `ok()` or `err` once the gate opens or fails.
    pub(super) fn future<T: 'static, E: Send + 'static>(
        self: &Arc<Self>,
        ok: impl FnOnce() -> T + Send + 'static,
        err: E,
    ) -> ExDataFuture<Result<T, E>> {
        self.created.fetch_add(1, SeqCst);
        Box::pin(GateFuture {
            gate: self.clone(),
            ok: Some(Box::new(ok)),
            err: Some(err),
        })
    }

    pub(super) fn record_finish(&self) {
        self.finished.fetch_add(1, SeqCst);
    }
}

type Produce<T> = Box<dyn FnOnce() -> T + Send>;

struct GateFuture<T, E> {
    gate: Arc<Gate>,
    ok: Option<Produce<T>>,
    err: Option<E>,
}

impl<T, E> Unpin for GateFuture<T, E> {}

impl<T, E> Future for GateFuture<T, E> {
    type Output = Result<T, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.gate.polls.fetch_add(1, SeqCst);
        let outcome = *self.gate.outcome.lock().unwrap();
        match outcome {
            Outcome::Wait => {
                *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
            Outcome::Pass => Poll::Ready(Ok((self.ok.take().expect("polled after completion"))())),
            Outcome::Fail => Poll::Ready(Err(self.err.take().expect("polled after completion"))),
        }
    }
}

impl<T, E> Drop for GateFuture<T, E> {
    fn drop(&mut self) {
        self.gate.dropped.fetch_add(1, SeqCst);
    }
}

/// Remote ECDSA P-256 signing behind a gate, like an HSM or signing service.
pub(super) struct GatedSigner {
    pub(super) key: PKey<Private>,
    pub(super) gate: Arc<Gate>,
}

impl AsyncPrivateKeyMethod for GatedSigner {
    fn sign(
        &self,
        _: &mut SslRef,
        input: &[u8],
        algorithm: SslSignatureAlgorithm,
        _: &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError> {
        assert_eq!(algorithm, SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256);
        let (key, input, gate) = (self.key.clone(), input.to_vec(), self.gate.clone());
        Ok(self.gate.future(
            move || {
                Box::new(move |_: &mut SslRef, output: &mut [u8]| {
                    gate.record_finish();
                    let mut signer = Signer::new(MessageDigest::sha256(), &key)
                        .map_err(|_| AsyncPrivateKeyMethodError)?;
                    signer
                        .sign_oneshot(output, &input)
                        .map_err(|_| AsyncPrivateKeyMethodError)
                }) as BoxPrivateKeyMethodFinish
            },
            AsyncPrivateKeyMethodError,
        ))
    }

    fn decrypt(
        &self,
        _: &mut SslRef,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError> {
        unreachable!("TLS 1.3 never decrypts with the certificate key")
    }
}

/// Polls one QUIC endpoint the way a transport driver would.
pub(super) struct Peer {
    pub(super) conn: QuicConnection,
    pub(super) record: Arc<Record>,
    pub(super) wake: Arc<WakeCount>,
    waker: Waker,
    pub(super) pending: bool,
    pub(super) error: Option<QuicError>,
    pub(super) aborted: bool,
}

impl Peer {
    pub(super) fn new(conn: QuicConnection, record: Arc<Record>) -> Self {
        let (wake, waker) = WakeCount::new();
        Self {
            conn,
            record,
            wake,
            waker,
            pending: false,
            error: None,
            aborted: false,
        }
    }

    /// A QUIC endpoint without early data, as an intercepting relay uses.
    pub(super) fn quic(ctx: &SslContext, server: bool) -> Self {
        let record = Arc::new(Record::default());
        let mut conn = connection(ctx, server, record.clone());
        conn.set_early_data_enabled(false);
        Self::new(conn, record)
    }

    pub(super) fn is_closed(&self) -> bool {
        self.error.is_some() || self.aborted
    }

    pub(super) fn is_complete(&self) -> bool {
        !self.is_closed() && self.conn.ssl().is_init_finished()
    }

    /// Advances the handshake; terminal failures are retained, not returned.
    pub(super) fn poll(&mut self) {
        if self.is_closed() {
            return;
        }
        let mut cx = Context::from_waker(&self.waker);
        loop {
            if self.conn.ssl().is_init_finished() {
                self.pending = false;
                if let Err(error) = self.conn.process_post_handshake() {
                    self.error = Some(error);
                }
                return;
            }
            match self.conn.poll_handshake(&mut cx) {
                Poll::Pending => {
                    self.pending = true;
                    return;
                }
                Poll::Ready(Ok(HandshakeStatus::EarlyDataRejected)) => {
                    self.conn.reset_early_data_rejection().unwrap();
                }
                Poll::Ready(Ok(HandshakeStatus::EarlyData)) => continue,
                Poll::Ready(Ok(_)) => {
                    self.pending = false;
                    return;
                }
                Poll::Ready(Err(error)) => {
                    self.pending = false;
                    self.error = Some(error);
                    return;
                }
            }
        }
    }

    /// Cancels as a relay does on peer close, policy failure or deadline.
    pub(super) fn abort(&mut self) {
        // A closed transport discards whatever TLS had not yet sent.
        self.take_output();
        self.conn.abort_handshake();
        self.aborted = true;
        self.pending = false;
    }

    pub(super) fn take_output(&self) -> Vec<(EncryptionLevel, Vec<u8>)> {
        std::mem::take(&mut *self.record.output.lock().unwrap())
    }

    pub(super) fn has_output(&self) -> bool {
        !self.record.output.lock().unwrap().is_empty()
    }
}

/// Moves `from`'s CRYPTO output into `to` in `chunk`-byte pieces, advancing `to`
/// after each piece. A closed receiver discards data like a closed transport.
pub(super) fn deliver(from: &Peer, to: &mut Peer, chunk: usize) -> bool {
    let output = from.take_output();
    let moved = !output.is_empty();
    for (level, bytes) in output {
        for piece in bytes.chunks(chunk.max(1)) {
            if to.is_closed() {
                break;
            }
            match to.conn.provide_data(level, piece) {
                Ok(()) => to.poll(),
                Err(error) => to.error = Some(error),
            }
        }
    }
    moved
}

/// Runs a two-party handshake until neither side can progress without outside work.
pub(super) fn settle(client: &mut Peer, server: &mut Peer, chunk: usize) {
    client.poll();
    server.poll();
    for _ in 0..64 {
        let a = deliver(client, server, chunk);
        let b = deliver(server, client, chunk);
        if !a && !b {
            return;
        }
    }
    panic!("handshake failed to settle");
}

pub(super) fn ec_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

/// A certificate authority minted at runtime.
pub(super) struct Authority {
    pub(super) cert: X509,
    key: PKey<Private>,
}

impl Authority {
    pub(super) fn new(name: &str) -> Self {
        let key = ec_key();
        let name = Self::name(name);
        let mut builder = Self::builder(&name, &key);
        builder.set_issuer_name(&name).unwrap();
        builder
            .append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(&KeyUsage::new().critical().key_cert_sign().build().unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        Self {
            cert: builder.build(),
            key,
        }
    }

    fn name(common_name: &str) -> X509Name {
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        name.build()
    }

    fn builder(subject: &X509Name, key: &PKey<Private>) -> crate::x509::X509Builder {
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(subject).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        builder.set_pubkey(key).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder
    }

    /// Issues a leaf for `dns_name`, usable for server or client authentication.
    pub(super) fn issue(&self, dns_name: &str) -> (X509, PKey<Private>) {
        let key = ec_key();
        let mut builder = Self::builder(&Self::name(dns_name), &key);
        builder.set_issuer_name(self.cert.subject_name()).unwrap();
        builder
            .append_extension(
                &KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder
            .append_extension(
                &ExtendedKeyUsage::new()
                    .server_auth()
                    .client_auth()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns(dns_name)
            .build(&builder.x509v3_context(Some(&self.cert), None))
            .unwrap();
        builder.append_extension(&san).unwrap();
        builder.sign(&self.key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    pub(super) fn store(&self) -> X509Store {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(self.cert.clone()).unwrap();
        store.build()
    }

    /// The leaf signature verifies with this authority's key.
    pub(super) fn issued(&self, leaf: &X509) -> bool {
        leaf.verify(&self.cert.public_key().unwrap())
            .unwrap_or(false)
            && leaf.issuer_name().to_der().unwrap() == self.cert.subject_name().to_der().unwrap()
    }
}

/// A credential for `cert`, signing locally or through `signer`.
pub(super) fn credential(
    cert: &X509,
    key: &PKey<Private>,
    signer: Option<&Arc<Gate>>,
) -> SslCredential {
    let mut credential = SslCredential::builder().unwrap();
    credential.set_certificate_chain([cert.clone()]).unwrap();
    credential
        .set_signing_algorithm_prefs(&[SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256])
        .unwrap();
    match signer {
        Some(gate) => credential
            .set_async_private_key_method(GatedSigner {
                key: key.clone(),
                gate: gate.clone(),
            })
            .unwrap(),
        None => credential.set_private_key(key).unwrap(),
    }
    credential.build()
}

/// A TLS 1.3-only context negotiating `h3`, as QUIC requires.
pub(super) fn quic_context() -> SslContextBuilder {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_alpn_protos(b"\x02h3").unwrap();
    ctx.set_alpn_select_callback(|_, offers| {
        crate::ssl::select_next_proto(b"\x02h3", offers).ok_or(crate::ssl::AlpnError::ALERT_FATAL)
    });
    ctx
}
