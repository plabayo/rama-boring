//! `poll_handshake` and `abort_handshake` for every asynchronous callback kind.

use super::support::{
    credential, deliver, quic_context, settle, Authority, CloneCount, Gate, Peer,
};
use super::Record;
use crate::{
    pkey::{PKey, Private},
    ssl::{
        async_callbacks::SELECT_GET_SESSION_FUTURE_INDEX,
        mut_only::MutOnly,
        quic::{HandshakeStatus, QuicConnection, QuicError},
        AsyncSelectCertError, BoxCertificateFinish, BoxCustomVerifyFinish, BoxGetSessionFinish,
        BoxSelectCertFinish, CertificateSelection, ClientHello, ErrorCode, SelectCertError, Ssl,
        SslAlert, SslContext, SslContextBuilder, SslRef, SslVerifyError, SslVerifyMode,
    },
    x509::X509,
};
use std::{
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};

struct Pki {
    server: (X509, PKey<Private>),
    client: (X509, PKey<Private>),
}

static PKI: LazyLock<Pki> = LazyLock::new(|| {
    let ca = Authority::new("async handshake CA");
    let server = ca.issue("server.test");
    let client = ca.issue("client.test");
    Pki { server, client }
});

/// Every place a QUIC handshake can wait on application work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    ServerEarlySelection,
    ServerCertificate,
    ServerSigning,
    ServerVerify,
    ClientCertificate,
    ClientVerify,
    ClientSigning,
}

const WAITS: [Wait; 7] = [
    Wait::ServerEarlySelection,
    Wait::ServerCertificate,
    Wait::ServerSigning,
    Wait::ServerVerify,
    Wait::ClientCertificate,
    Wait::ClientVerify,
    Wait::ClientSigning,
];

impl Wait {
    fn on_server(self) -> bool {
        matches!(
            self,
            Self::ServerEarlySelection
                | Self::ServerCertificate
                | Self::ServerSigning
                | Self::ServerVerify
        )
    }

    fn client_authenticates(self) -> bool {
        matches!(
            self,
            Self::ServerVerify | Self::ClientCertificate | Self::ClientSigning
        )
    }
}

fn certificate_finish(gate: &Arc<Gate>, cert: &X509, key: &PKey<Private>) -> BoxCertificateFinish {
    let (gate, credential) = (gate.clone(), credential(cert, key, None));
    Box::new(move |mut selection: CertificateSelection<'_>| {
        gate.record_finish();
        let ssl = selection.ssl_mut();
        ssl.clear_certificates();
        ssl.add_credential(&credential)
            .map_err(|_| AsyncSelectCertError)
    })
}

fn verify_finish(gate: &Arc<Gate>) -> BoxCustomVerifyFinish {
    let gate = gate.clone();
    Box::new(move |ssl: &mut SslRef| {
        gate.record_finish();
        // The finish runs with the verified peer chain still available.
        assert!(ssl.peer_certificate().is_some());
        Ok(())
    })
}

fn accept_any_certificate(ssl: &mut SslRef) -> Result<(), SslVerifyError> {
    assert!(ssl.peer_certificate().is_some());
    Ok(())
}

fn async_verify(ctx: &mut SslContextBuilder, gate: &Arc<Gate>) {
    let gate = gate.clone();
    ctx.set_async_custom_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        move |ssl| {
            assert!(ssl.peer_certificate().is_some());
            let finish_gate = gate.clone();
            Ok(gate.future(
                move || verify_finish(&finish_gate),
                SslAlert::BAD_CERTIFICATE,
            ))
        },
    );
}

/// Builds a client and server configured to wait at `wait` on `gate`, and runs
/// their handshake as far as it goes.
fn handshake_at(wait: Wait, gate: &Arc<Gate>) -> (Peer, Peer) {
    let pki = &*PKI;
    let mut server = quic_context();
    let mut client = quic_context();
    client.set_verify(SslVerifyMode::NONE);

    let server_signer = (wait == Wait::ServerSigning).then_some(gate);
    if wait != Wait::ServerCertificate {
        server
            .add_credential(&credential(&pki.server.0, &pki.server.1, server_signer))
            .unwrap();
    }
    if wait.client_authenticates() {
        let client_signer = (wait == Wait::ClientSigning).then_some(gate);
        if wait != Wait::ClientCertificate {
            client
                .add_credential(&credential(&pki.client.0, &pki.client.1, client_signer))
                .unwrap();
        }
        if wait != Wait::ServerVerify {
            server.set_custom_verify_callback(
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                accept_any_certificate,
            );
        }
    }
    match wait {
        Wait::ServerEarlySelection => {
            let gate = gate.clone();
            server.set_async_select_certificate_callback(move |hello: &mut ClientHello<'_>| {
                assert_eq!(
                    hello.servername(crate::ssl::NameType::HOST_NAME),
                    Some("server.test")
                );
                let finish_gate = gate.clone();
                Ok(gate.future(
                    move || {
                        Box::new(move |_: ClientHello<'_>| {
                            finish_gate.record_finish();
                            Ok(())
                        }) as BoxSelectCertFinish
                    },
                    AsyncSelectCertError,
                ))
            });
        }
        Wait::ServerCertificate => {
            let gate = gate.clone();
            server.set_async_certificate_callback(move |_| {
                let finish_gate = gate.clone();
                Ok(gate.future(
                    move || certificate_finish(&finish_gate, &PKI.server.0, &PKI.server.1),
                    AsyncSelectCertError,
                ))
            });
        }
        Wait::ServerVerify => async_verify(&mut server, gate),
        Wait::ClientCertificate => {
            let gate = gate.clone();
            client.set_async_certificate_callback(move |selection| {
                // The relay sees the authenticated origin before answering.
                assert!(selection.ssl().peer_certificate().is_some());
                assert!(!selection.peer_verify_algorithms().is_empty());
                let finish_gate = gate.clone();
                Ok(gate.future(
                    move || certificate_finish(&finish_gate, &PKI.client.0, &PKI.client.1),
                    AsyncSelectCertError,
                ))
            });
        }
        Wait::ClientVerify => async_verify(&mut client, gate),
        Wait::ServerSigning | Wait::ClientSigning => {}
    }

    let mut client = Peer::quic(&client.build(), false);
    client.conn.ssl_mut().set_hostname("server.test").unwrap();
    let mut server = Peer::quic(&server.build(), true);
    settle(&mut client, &mut server, 7);
    (client, server)
}

/// Builds a client and server whose handshake waits at `wait` on `gate`.
fn handshake_waiting_at(wait: Wait, gate: &Arc<Gate>) -> (Peer, Peer) {
    let (client, server) = handshake_at(wait, gate);
    assert!(gate.is_waiting(), "{wait:?} did not wait");
    assert_eq!(gate.created(), 1, "{wait:?}");
    assert!(client.error.is_none() && server.error.is_none(), "{wait:?}");
    let (waiting, other) = if wait.on_server() {
        (&server, &client)
    } else {
        (&client, &server)
    };
    assert!(waiting.pending, "{wait:?}");
    assert!(!waiting.conn.ssl().is_init_finished(), "{wait:?}");
    assert!(!waiting.has_output() && !other.has_output(), "{wait:?}");
    (client, server)
}

/// The waiting peer and its counterpart.
fn waiting_side<'a>(
    wait: Wait,
    client: &'a mut Peer,
    server: &'a mut Peer,
) -> (&'a mut Peer, &'a mut Peer) {
    if wait.on_server() {
        (server, client)
    } else {
        (client, server)
    }
}

#[track_caller]
fn assert_poisoned(peer: &mut Peer) {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(matches!(
        peer.conn.poll_handshake(&mut cx),
        Poll::Ready(Err(QuicError::InvalidState))
    ));
    assert!(matches!(
        peer.conn.handshake(),
        Err(QuicError::InvalidState)
    ));
    assert!(matches!(
        peer.conn
            .provide_data(crate::ssl::quic::EncryptionLevel::Handshake, b"late"),
        Err(QuicError::InvalidState)
    ));
    assert!(matches!(
        peer.conn.process_post_handshake(),
        Err(QuicError::InvalidState)
    ));
    assert!(!peer.has_output());
}

#[test]
fn every_wait_resumes_from_its_wake_without_peer_input() {
    for wait in WAITS {
        let gate = Gate::new();
        let (mut client, mut server) = handshake_waiting_at(wait, &gate);
        let (waiting, _) = waiting_side(wait, &mut client, &mut server);

        // Spurious polls neither recreate nor finish the pending work.
        for _ in 0..3 {
            waiting.poll();
            assert!(waiting.pending && !waiting.has_output(), "{wait:?}");
        }
        assert_eq!((gate.created(), gate.finished()), (1, 0), "{wait:?}");
        assert_eq!(waiting.wake.get(), 0, "{wait:?}");

        gate.open();
        assert_eq!(waiting.wake.get(), 1, "{wait:?} must wake the transport");
        waiting.poll();
        assert!(!waiting.pending, "{wait:?}");
        assert_eq!(gate.finished(), 1, "{wait:?}");
        assert!(waiting.has_output(), "{wait:?} resumed without emitting");

        settle(&mut client, &mut server, 5);
        assert!(client.is_complete() && server.is_complete(), "{wait:?}");
        assert_eq!(client.conn.ssl().selected_alpn_protocol(), Some(&b"h3"[..]));
        assert_eq!(
            client.conn.peer_transport_parameters(),
            b"server parameters"
        );
        assert_eq!(
            server.conn.peer_transport_parameters(),
            b"client parameters"
        );
        assert_eq!(
            server.conn.ssl().peer_certificate().is_some(),
            wait.client_authenticates(),
            "{wait:?}"
        );
        assert!(client.record.alerts.lock().unwrap().is_empty());
        assert!(server.record.alerts.lock().unwrap().is_empty());
        assert_eq!(gate.created(), 1, "{wait:?} reran its factory");
        gate.assert_released();
    }
}

#[test]
fn abort_at_every_wait_drops_work_and_poisons_the_connection() {
    for wait in WAITS {
        let gate = Gate::new();
        let (mut client, mut server) = handshake_waiting_at(wait, &gate);
        let (waiting, other) = waiting_side(wait, &mut client, &mut server);
        let record = Arc::downgrade(&waiting.record);

        waiting.abort();
        assert_eq!(gate.dropped(), 1, "{wait:?} kept its future after abort");
        assert_eq!(gate.finished(), 0, "{wait:?}");
        assert_poisoned(waiting);
        waiting.abort();
        assert_eq!(gate.dropped(), 1, "{wait:?}");

        // A late result can only wake the task; nothing resumes or finishes.
        gate.open();
        waiting.poll();
        assert_poisoned(waiting);
        assert_eq!((gate.created(), gate.finished()), (1, 0), "{wait:?}");
        // A client completes before the server authenticates it.
        assert_eq!(other.is_complete(), wait == Wait::ServerVerify, "{wait:?}");
        gate.assert_released();

        drop(client);
        drop(server);
        assert!(
            record.upgrade().is_none(),
            "{wait:?} leaked its QUIC method"
        );
    }
}

#[test]
fn late_result_before_repoll_is_discarded_by_abort() {
    for wait in WAITS {
        let gate = Gate::new();
        let (mut client, mut server) = handshake_waiting_at(wait, &gate);
        let (waiting, _) = waiting_side(wait, &mut client, &mut server);
        gate.open();
        assert_eq!(waiting.wake.get(), 1);
        waiting.abort();
        waiting.poll();
        assert_eq!(gate.finished(), 0, "{wait:?} finished after cancellation");
        gate.assert_released();
        assert_poisoned(waiting);
    }
}

#[test]
fn failed_work_at_every_wait_is_terminal() {
    for wait in WAITS {
        let gate = Gate::new();
        let (mut client, mut server) = handshake_waiting_at(wait, &gate);
        let (waiting, other) = waiting_side(wait, &mut client, &mut server);
        gate.fail();
        waiting.poll();
        assert!(
            matches!(waiting.error, Some(QuicError::Tls(_))),
            "{wait:?}: {:?}",
            waiting.error
        );
        assert_eq!(gate.finished(), 0, "{wait:?}");
        gate.assert_released();
        // BoringSSL fails a signing error without an alert; the QUIC transport
        // must close with its own error code instead.
        let signing = matches!(wait, Wait::ServerSigning | Wait::ClientSigning);
        assert_eq!(
            waiting.record.alerts.lock().unwrap().is_empty(),
            signing,
            "{wait:?}"
        );
        assert_poisoned(waiting);
        assert_eq!(other.is_complete(), wait == Wait::ServerVerify, "{wait:?}");
    }
}

#[test]
fn dropping_a_waiting_connection_releases_work_and_waker() {
    for wait in WAITS {
        let gate = Gate::new();
        let (client, server) = handshake_waiting_at(wait, &gate);
        let record = Arc::downgrade(if wait.on_server() {
            &server.record
        } else {
            &client.record
        });
        drop((client, server));
        gate.assert_released();
        assert_eq!(gate.finished(), 0);
        assert!(record.upgrade().is_none());
    }
}

#[test]
fn waiting_connection_moves_to_another_thread() {
    let gate = Gate::new();
    let (mut client, server) = handshake_waiting_at(Wait::ServerCertificate, &gate);
    let opener = gate.clone();
    let mut server = std::thread::spawn(move || {
        let mut server = server;
        opener.open();
        server.poll();
        server
    })
    .join()
    .unwrap();
    assert_eq!(gate.finished(), 1);
    settle(&mut client, &mut server, 64);
    assert!(client.is_complete() && server.is_complete());
}

fn certificate_pending_server(gate: &Arc<Gate>) -> (Peer, Peer) {
    handshake_waiting_at(Wait::ServerCertificate, gate)
}

#[test]
fn pending_poll_keeps_one_waker_and_releases_it_when_ready() {
    let gate = Gate::new();
    let (mut client, mut server) = certificate_pending_server(&gate);
    // Restart the wait on a counted waker: abort is not needed, the future
    // re-registers whatever waker polls it next.
    let count = CloneCount::new();
    let waker = count.waker();
    let mut cx = Context::from_waker(&waker);
    assert!(server.conn.poll_handshake(&mut cx).is_pending());
    // Installed on the connection and registered by the pending future, besides
    // the test's own handle.
    assert_eq!(count.live(), 3);
    let clones = count.clones.load(std::sync::atomic::Ordering::SeqCst);
    assert!(server.conn.poll_handshake(&mut cx).is_pending());
    // The installed waker is reused: only the callback's transient clone and the
    // future's re-registration clone it again.
    assert_eq!(
        count.clones.load(std::sync::atomic::Ordering::SeqCst) - clones,
        2
    );
    assert_eq!(count.live(), 3);

    let other = CloneCount::new();
    let other_waker = other.waker();
    assert!(server
        .conn
        .poll_handshake(&mut Context::from_waker(&other_waker))
        .is_pending());
    assert_eq!(count.live(), 1, "a replaced waker must be released");
    assert_eq!(other.live(), 3);

    gate.open();
    assert_eq!(other.wakes.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(matches!(
        server
            .conn
            .poll_handshake(&mut Context::from_waker(&other_waker)),
        Poll::Ready(Ok(HandshakeStatus::WantRead))
    ));
    assert_eq!(other.live(), 1, "a finished step must release its waker");
    settle(&mut client, &mut server, 9);
    assert!(client.is_complete() && server.is_complete());
    assert_eq!(other.live(), 1);
}

#[test]
fn abort_releases_the_installed_waker() {
    let gate = Gate::new();
    let (_client, mut server) = certificate_pending_server(&gate);
    let count = CloneCount::new();
    let waker = count.waker();
    assert!(server
        .conn
        .poll_handshake(&mut Context::from_waker(&waker))
        .is_pending());
    server.abort();
    // Only the gate's own registration remains; it holds no TLS state.
    assert_eq!(count.live(), 2);
    gate.open();
    assert_eq!(count.live(), 1);
}

#[test]
fn intermediate_synchronous_step_resumes_instead_of_abandoning() {
    let gate = Gate::new();
    let (mut client, mut server) = certificate_pending_server(&gate);
    // A transport may advance synchronously after new peer input.
    match server.conn.handshake() {
        Err(QuicError::Tls(error)) => {
            assert!(error.would_block());
            assert_eq!(error.code(), ErrorCode::WANT_X509_LOOKUP);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!((gate.created(), gate.dropped()), (1, 0));
    gate.open();
    assert_eq!(server.wake.get(), 1);
    assert_eq!(server.conn.handshake().unwrap(), HandshakeStatus::WantRead);
    assert_eq!(gate.finished(), 1);
    settle(&mut client, &mut server, 3);
    assert!(client.is_complete() && server.is_complete());
    gate.assert_released();
}

#[test]
fn asynchronous_callback_without_waker_fails_closed() {
    let gate = Gate::new();
    let mut server = quic_context();
    let factory = gate.clone();
    server.set_async_certificate_callback(move |_| {
        let finish_gate = factory.clone();
        Ok(factory.future(
            move || certificate_finish(&finish_gate, &PKI.server.0, &PKI.server.1),
            AsyncSelectCertError,
        ))
    });
    let mut client = Peer::quic(&quic_context().build(), false);
    let record = Arc::new(Record::default());
    let mut server_conn = super::connection(&server.build(), true, record.clone());
    client.poll();
    for (level, bytes) in client.take_output() {
        server_conn.provide_data(level, &bytes).unwrap();
    }
    assert!(matches!(server_conn.handshake(), Err(QuicError::Tls(ref e)) if !e.would_block()));
    assert_eq!(gate.created(), 0, "no factory may run without a waker");
    assert!(matches!(
        server_conn.handshake(),
        Err(QuicError::InvalidState)
    ));
    assert!(!record.alerts.lock().unwrap().is_empty());
}

#[test]
fn factory_error_is_terminal() {
    let mut server = quic_context();
    server.set_async_certificate_callback(|_| Err(AsyncSelectCertError));
    let mut client = Peer::quic(&quic_context().build(), false);
    let mut server = Peer::quic(&server.build(), true);
    client.poll();
    deliver(&client, &mut server, 1200);
    assert!(matches!(server.error, Some(QuicError::Tls(_))));
    assert_poisoned(&mut server);
}

#[test]
fn synchronous_retry_is_not_terminal() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = calls.clone();
    let mut server = quic_context();
    server.set_certificate_callback(move |mut selection| {
        if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
            return Err(SelectCertError::RETRY);
        }
        let ssl = selection.ssl_mut();
        ssl.add_credential(&credential(&PKI.server.0, &PKI.server.1, None))
            .map_err(|_| SelectCertError::ERROR)
    });
    let mut client = Peer::quic(&quic_context().build(), false);
    let mut server = Peer::quic(&server.build(), true);
    client.poll();
    deliver(&client, &mut server, 1200);
    // The driver polled once on delivery; a retry is pending, not fatal.
    assert!(server.pending && server.error.is_none());
    match server.conn.handshake() {
        Err(QuicError::Tls(error)) => assert_eq!(error.code(), ErrorCode::WANT_X509_LOOKUP),
        other => panic!("{other:?}"),
    }
    server.poll();
    assert!(!server.pending);
    settle(&mut client, &mut server, 1200);
    assert!(client.is_complete() && server.is_complete());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
}

#[test]
fn abort_before_start_and_after_completion() {
    let mut fresh = Peer::quic(&quic_context().build(), false);
    fresh.abort();
    assert_poisoned(&mut fresh);

    let mut server = quic_context();
    server
        .add_credential(&credential(&PKI.server.0, &PKI.server.1, None))
        .unwrap();
    let mut client = Peer::quic(&quic_context().build(), false);
    let mut server = Peer::quic(&server.build(), true);
    settle(&mut client, &mut server, 1200);
    assert!(client.is_complete() && server.is_complete());
    server.abort();
    client.abort();
    assert!(server.conn.ssl().is_init_finished());
    assert_poisoned(&mut server);
    assert_poisoned(&mut client);
}

#[test]
fn sequential_waits_happen_one_at_a_time_in_handshake_order() {
    let pki = &*PKI;
    let gates: [Arc<Gate>; 4] = std::array::from_fn(|_| Gate::new());
    let [early, select, sign, verify] = gates.clone();
    let mut server = quic_context();
    server.set_async_select_certificate_callback(move |_| {
        let finish = early.clone();
        Ok(early.future(
            move || {
                Box::new(move |_: ClientHello<'_>| {
                    finish.record_finish();
                    Ok(())
                }) as BoxSelectCertFinish
            },
            AsyncSelectCertError,
        ))
    });
    let signer = sign.clone();
    server.set_async_certificate_callback(move |_| {
        let (finish, signer) = (select.clone(), signer.clone());
        Ok(select.future(
            move || {
                let credential = credential(&PKI.server.0, &PKI.server.1, Some(&signer));
                Box::new(move |mut selection: CertificateSelection<'_>| {
                    finish.record_finish();
                    selection
                        .ssl_mut()
                        .add_credential(&credential)
                        .map_err(|_| AsyncSelectCertError)
                }) as BoxCertificateFinish
            },
            AsyncSelectCertError,
        ))
    });
    async_verify(&mut server, &verify);
    let mut client = quic_context();
    client
        .add_credential(&credential(&pki.client.0, &pki.client.1, None))
        .unwrap();
    let mut client = Peer::quic(&client.build(), false);
    let mut server = Peer::quic(&server.build(), true);

    for (index, gate) in gates.iter().enumerate() {
        settle(&mut client, &mut server, 11);
        let waiting: Vec<_> = gates.iter().map(|gate| gate.is_waiting()).collect();
        let mut expected = [false; 4];
        expected[index] = true;
        assert_eq!(waiting, expected, "wait {index}");
        assert!(server.pending);
        gate.open();
        server.poll();
    }
    settle(&mut client, &mut server, 11);
    assert!(client.is_complete() && server.is_complete());
    for gate in &gates {
        assert_eq!((gate.created(), gate.finished()), (1, 1));
        gate.assert_released();
    }
}

#[test]
fn abort_drops_a_pending_session_lookup() {
    // TLS 1.3 resumes only from tickets, so QUIC never reaches this lookup.
    // Its cancellation still belongs to the abort contract.
    let ctx = SslContext::builder(crate::ssl::SslMethod::tls())
        .unwrap()
        .build();
    let mut ssl = Ssl::new(&ctx).unwrap();
    let gate = Gate::new();
    let future = gate.future(
        || Box::new(|_: &mut SslRef, _: &[u8]| None) as BoxGetSessionFinish,
        (),
    );
    let lookup: crate::ssl::BoxGetSessionFuture = Box::pin(async move { future.await.ok() });
    ssl.set_ex_data(*SELECT_GET_SESSION_FUTURE_INDEX, MutOnly::new(Some(lookup)));
    let mut conn = QuicConnection::new(ssl, Arc::new(Record::default())).unwrap();
    assert_eq!(gate.dropped(), 0);
    conn.abort_handshake();
    gate.assert_released();
    assert_eq!(gate.created(), 1);
}

#[test]
fn early_selection_finish_can_route_to_another_context() {
    // A relay picks a per-host context from the ClientHello; routing must not be
    // mistaken for replacing the callback mid-flight.
    let gate = Gate::new();
    let mut routed = quic_context();
    routed
        .add_credential(&credential(&PKI.server.0, &PKI.server.1, None))
        .unwrap();
    let routed = routed.build();
    let mut server = quic_context();
    let factory = gate.clone();
    server.set_async_select_certificate_callback(move |_| {
        let (finish, routed) = (factory.clone(), routed.clone());
        Ok(factory.future(
            move || {
                Box::new(move |mut hello: ClientHello<'_>| {
                    finish.record_finish();
                    hello
                        .ssl_mut()
                        .set_ssl_context(&routed)
                        .map_err(|_| AsyncSelectCertError)
                }) as BoxSelectCertFinish
            },
            AsyncSelectCertError,
        ))
    });
    let mut client = Peer::quic(&quic_context().build(), false);
    let mut server = Peer::quic(&server.build(), true);
    settle(&mut client, &mut server, 1200);
    assert!(gate.is_waiting());
    gate.open();
    server.poll();
    settle(&mut client, &mut server, 1200);
    assert!(client.is_complete() && server.is_complete());
    assert_eq!(gate.finished(), 1);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resolution {
    Open,
    Fail,
    AbortBefore,
    AbortAfterResult,
}

#[test]
fn every_schedule_at_every_wait_keeps_the_contract() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut schedules = 0;
    for wait in WAITS {
        for spurious in 0..3 {
            for sync_step in [false, true] {
                for swap_waker in [false, true] {
                    for resolution in [
                        Resolution::Open,
                        Resolution::Fail,
                        Resolution::AbortBefore,
                        Resolution::AbortAfterResult,
                    ] {
                        for resume_with_poll in [false, true] {
                            let case = format!(
                                "{wait:?} spurious={spurious} sync={sync_step} swap={swap_waker} \
                                 {resolution:?} poll={resume_with_poll}"
                            );
                            let gate = Gate::new();
                            let (mut client, mut server) = handshake_waiting_at(wait, &gate);
                            let (waiting, _) = waiting_side(wait, &mut client, &mut server);
                            for _ in 0..spurious {
                                waiting.poll();
                            }
                            if sync_step {
                                match waiting.conn.handshake() {
                                    Err(QuicError::Tls(error)) => {
                                        assert!(error.would_block(), "{case}")
                                    }
                                    other => panic!("{case}: {other:?}"),
                                }
                            }
                            let swapped = CloneCount::new();
                            if swap_waker {
                                let waker = swapped.waker();
                                assert!(
                                    waiting
                                        .conn
                                        .poll_handshake(&mut Context::from_waker(&waker))
                                        .is_pending(),
                                    "{case}"
                                );
                            }
                            assert_eq!((gate.created(), gate.dropped()), (1, 0), "{case}");
                            let own_wakes = waiting.wake.get();

                            match resolution {
                                Resolution::Open | Resolution::AbortAfterResult => gate.open(),
                                Resolution::Fail => gate.fail(),
                                Resolution::AbortBefore => {}
                            }
                            if resolution != Resolution::AbortBefore {
                                // The most recent waker, and only it, is woken.
                                if swap_waker {
                                    assert_eq!(swapped.wakes.load(SeqCst), 1, "{case}");
                                    assert_eq!(waiting.wake.get(), own_wakes, "{case}");
                                } else {
                                    assert_eq!(waiting.wake.get(), own_wakes + 1, "{case}");
                                }
                            }
                            if matches!(
                                resolution,
                                Resolution::AbortBefore | Resolution::AbortAfterResult
                            ) {
                                waiting.abort();
                                assert_poisoned(waiting);
                                assert_eq!(gate.finished(), 0, "{case}");
                                assert_eq!(gate.dropped(), 1, "{case}");
                                drop((client, server));
                                gate.assert_released();
                                // The policy itself may still hold its registration;
                                // TLS holds none once it resolves.
                                gate.open();
                                assert_eq!(swapped.live(), 0, "{case}");
                                schedules += 1;
                                continue;
                            }

                            if resume_with_poll {
                                waiting.poll();
                            } else {
                                match waiting.conn.handshake() {
                                    Ok(_) => waiting.pending = false,
                                    Err(error) => waiting.error = Some(error),
                                }
                            }
                            if resolution == Resolution::Fail {
                                assert!(
                                    matches!(waiting.error, Some(QuicError::Tls(ref e)) if !e.would_block()),
                                    "{case}: {:?}",
                                    waiting.error
                                );
                                assert_eq!(gate.finished(), 0, "{case}");
                                assert_poisoned(waiting);
                            } else {
                                assert_eq!(gate.finished(), 1, "{case}");
                                assert!(waiting.has_output(), "{case}");
                                settle(&mut client, &mut server, 5);
                                assert!(client.is_complete() && server.is_complete(), "{case}");
                            }
                            drop((client, server));
                            gate.assert_released();
                            assert_eq!(gate.created(), 1, "{case}");
                            assert_eq!(swapped.live(), 0, "{case}: waker leaked");
                            schedules += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(schedules, 7 * 3 * 2 * 2 * 4 * 2);
}

#[track_caller]
fn assert_panic_failed(peer: &mut Peer, stage: &str, context: &str) {
    match &peer.error {
        Some(QuicError::Tls(error)) => assert!(
            error
                .to_string()
                .contains(&format!("callback panicked: {stage}")),
            "{context}: {error}"
        ),
        other => panic!("{context}: {other:?}"),
    }
    assert_poisoned(peer);
}

isolated_test! {
    fn panics_at_every_wait_fail_the_handshake_closed() {
        for wait in WAITS {
            for stage in ["poll", "finish"] {
                let context = format!("{wait:?} {stage}");
                let gate = Gate::new();
                let (mut client, mut server) = handshake_waiting_at(wait, &gate);
                let (waiting, _) = waiting_side(wait, &mut client, &mut server);
                if stage == "poll" {
                    gate.panic();
                } else {
                    gate.panic_in_finish();
                }
                waiting.poll();
                assert_panic_failed(waiting, stage, &context);
                drop((client, server));
                gate.assert_released();
                assert_eq!(gate.created(), 1, "{context}: retried after a panic");
            }

            let gate = Gate::new();
            gate.panic_in_factory();
            let (mut client, mut server) = handshake_at(wait, &gate);
            let (waiting, _) = waiting_side(wait, &mut client, &mut server);
            assert_panic_failed(waiting, "factory", &format!("{wait:?} factory"));
            assert_eq!(gate.created(), 0);
        }
    }
}
