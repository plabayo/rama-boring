//! Resumed certificates use the same connection policy as a full handshake.

use super::memory::{client_context, handshake_results, server_context};
use crate::{
    ssl::{
        quic::{
            tests::{pump, Record},
            QuicConnection,
        },
        HandshakeError, Ssl, SslContext, SslRef, SslSession, SslSessionCacheMode, SslVerifyMode,
        SslVersion,
    },
    x509::{store::X509StoreBuilder, X509VerifyError, X509VerifyResult, X509},
};
use std::sync::{
    atomic::{AtomicUsize, Ordering::SeqCst},
    Arc, Mutex,
};

type Tickets = Arc<Mutex<Option<SslSession>>>;
const VALID_TIME: libc::time_t = 1_800_000_000;
const EXPIRED_TIME: libc::time_t = 2_500_000_000;

fn contexts(version: SslVersion, reverify: bool) -> (SslContext, SslContext, Tickets) {
    let mut server = server_context();
    server.set_min_proto_version(Some(version)).unwrap();
    server.set_max_proto_version(Some(version)).unwrap();
    server.set_session_id_context(b"default-reverify").unwrap();
    server.set_alpn_select_callback(|_, offers| {
        crate::ssl::select_next_proto(b"\x02h3", offers).ok_or(crate::ssl::AlpnError::ALERT_FATAL)
    });
    let mut client = client_context();
    client.set_min_proto_version(Some(version)).unwrap();
    client.set_max_proto_version(Some(version)).unwrap();
    client.set_alpn_protos(b"\x02h3").unwrap();
    client.set_verify(SslVerifyMode::PEER);
    client
        .cert_store_mut()
        .add_cert(X509::from_pem(super::ROOT_CERT).unwrap())
        .unwrap();
    client.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.set_reverify_on_resume(reverify);
    let tickets = Tickets::default();
    let sink = tickets.clone();
    client.set_new_session_callback(move |_, ticket| *sink.lock().unwrap() = Some(ticket));
    (client.build(), server.build(), tickets)
}

fn client(ctx: &SslContext) -> Ssl {
    let mut ssl = Ssl::new(ctx).unwrap();
    ssl.verify_param_mut().set_time(VALID_TIME);
    ssl.verify_param_mut().set_host("foobar.com").unwrap();
    ssl
}

fn outcome(ssl: &SslRef, success: bool) -> (bool, bool, X509VerifyResult) {
    if success && ssl.version() == Some(SslVersion::TLS1_2) {
        use foreign_types::ForeignTypeRef;
        assert_eq!(
            unsafe { crate::ffi::SSL_SESSION_is_resumable(ssl.session().unwrap().as_ptr()) },
            1
        );
    }
    (success, ssl.session_reused(), ssl.verify_result())
}

fn drive(client: Ssl, server: Ssl, quic: bool, early: bool) -> (bool, bool, X509VerifyResult) {
    if quic {
        let c = Arc::new(Record::default());
        let s = Arc::new(Record::default());
        let mut client = QuicConnection::new(client, c.clone()).unwrap();
        let mut server = QuicConnection::new(server, s.clone()).unwrap();
        client.set_connect_state();
        server.set_accept_state();
        for conn in [&mut client, &mut server] {
            conn.set_transport_parameters(b"parameters").unwrap();
            conn.set_early_data_enabled(early);
        }
        server.set_early_data_context(b"reverify").unwrap();
        let success = pump(&mut client, &mut server, &c, &s).is_ok();
        if success {
            assert!(client.ssl().is_init_finished());
            assert!(server.ssl().is_init_finished());
        }
        return outcome(client.ssl(), success);
    }
    let (client, server) = handshake_results(client, server);
    match client {
        Ok(mut client) => {
            let mut server = server.unwrap_or_else(|error| panic!("server handshake: {error}"));
            server.ssl_write(b"x").unwrap();
            assert_eq!(client.ssl_read(&mut [0; 1]).unwrap(), 1);
            outcome(client.ssl(), true)
        }
        Err(HandshakeError::Failure(mid)) => outcome(mid.ssl(), false),
        Err(error) => panic!("client handshake: {error}"),
    }
}

#[derive(Clone, Copy, Debug)]
enum Policy {
    Valid,
    Expired,
    Reject,
    Hostname,
    Store,
    ConnectionStore,
    VerifyNone,
}

pub(crate) fn check(quic: bool, version: SslVersion) {
    for reverify in [false, true] {
        for early in [false, true] {
            if early && !quic {
                continue;
            }
            for policy in [
                Policy::Valid,
                Policy::Expired,
                Policy::Reject,
                Policy::Hostname,
                Policy::Store,
                Policy::ConnectionStore,
                Policy::VerifyNone,
            ] {
                let (ctx, server, tickets) = contexts(version, reverify);
                let first = drive(client(&ctx), Ssl::new(&server).unwrap(), quic, early);
                assert_eq!(first, (true, false, Ok(())), "initial: {policy:?}");
                let ticket = tickets.lock().unwrap().take().unwrap();
                let original = ticket.to_der().unwrap();
                let mut resumed = client(&ctx);
                // Same context and server as the session's origin.
                unsafe {
                    resumed.set_session(&ticket).unwrap();
                }
                let calls = Arc::new(AtomicUsize::new(0));
                match policy {
                    Policy::Valid => {}
                    Policy::Expired => resumed.verify_param_mut().set_time(EXPIRED_TIME),
                    Policy::Reject => {
                        let calls = calls.clone();
                        resumed.set_verify_callback(SslVerifyMode::PEER, move |ok, store| {
                            if store.error_depth() == 0 {
                                calls.fetch_add(1, SeqCst);
                                store.set_error(Err(X509VerifyError::APPLICATION_VERIFICATION));
                                false
                            } else {
                                ok
                            }
                        });
                    }
                    Policy::Hostname => resumed
                        .verify_param_mut()
                        .set_host("wrong.example")
                        .unwrap(),
                    Policy::Store => resumed
                        .set_verify_cert_store(X509StoreBuilder::new().unwrap().build())
                        .unwrap(),
                    Policy::ConnectionStore => {
                        let mut store = X509StoreBuilder::new().unwrap();
                        store
                            .add_cert(X509::from_pem(super::ROOT_CERT).unwrap())
                            .unwrap();
                        resumed.set_verify_cert_store(store.build()).unwrap();
                        let calls = calls.clone();
                        resumed.set_verify_callback(SslVerifyMode::PEER, move |ok, store| {
                            if store.error_depth() == 0 {
                                calls.fetch_add(1, SeqCst);
                            }
                            ok
                        });
                    }
                    Policy::VerifyNone => {
                        resumed.set_verify(SslVerifyMode::NONE);
                        resumed.verify_param_mut().set_time(EXPIRED_TIME);
                    }
                }
                let result = drive(resumed, Ssl::new(&server).unwrap(), quic, early);
                let accepted = !reverify
                    || matches!(
                        policy,
                        Policy::Valid | Policy::ConnectionStore | Policy::VerifyNone
                    );
                assert_eq!(
                    result.0, accepted,
                    "{version:?} quic={quic} early={early} reverify={reverify} {policy:?}"
                );
                if accepted {
                    assert!(result.1, "must resume, not fall back to a full handshake");
                }
                let expected = if !reverify {
                    Ok(())
                } else {
                    match policy {
                        Policy::Expired | Policy::VerifyNone => {
                            Err(X509VerifyError::CERT_HAS_EXPIRED)
                        }
                        Policy::Reject => Err(X509VerifyError::APPLICATION_VERIFICATION),
                        Policy::Hostname => Err(X509VerifyError::HOSTNAME_MISMATCH),
                        Policy::Store => result.2,
                        _ => Ok(()),
                    }
                };
                assert_eq!(result.2, expected, "{policy:?}");
                if reverify && matches!(policy, Policy::Store) {
                    assert!(result.2.is_err());
                }
                if matches!(policy, Policy::Reject | Policy::ConnectionStore) {
                    assert_eq!(calls.load(SeqCst), usize::from(reverify));
                }
                assert_eq!(
                    ticket.to_der().unwrap(),
                    original,
                    "shared session must remain immutable"
                );
                let mut again = client(&ctx);
                unsafe {
                    again.set_session(&ticket).unwrap();
                }
                assert_eq!(
                    drive(again, Ssl::new(&server).unwrap(), quic, early),
                    (true, true, Ok(()))
                );
            }
        }
    }
}

#[test]
fn reverify_x509_over_tls12() {
    check(false, SslVersion::TLS1_2);
}

#[test]
fn reverify_x509_over_tls13() {
    check(false, SslVersion::TLS1_3);
}

#[test]
fn reverify_custom_callback_behavior_is_unchanged() {
    use crate::ssl::{SslAlert, SslVerifyError};
    use std::sync::atomic::AtomicBool;
    for (quic, version) in [
        (false, SslVersion::TLS1_2),
        (false, SslVersion::TLS1_3),
        (true, SslVersion::TLS1_3),
    ] {
        for reverify in [false, true] {
            for reject in [false, true] {
                let (ctx, server, tickets) = contexts(version, reverify);
                let rejecting = Arc::new(AtomicBool::new(false));
                let calls = Arc::new(AtomicUsize::new(0));
                let configure = |ssl: &mut Ssl| {
                    let rejecting = rejecting.clone();
                    let calls = calls.clone();
                    // An empty store and bad hostname prove the custom callback
                    // remains authoritative; default verification must not run.
                    ssl.set_verify_cert_store(X509StoreBuilder::new().unwrap().build())
                        .unwrap();
                    ssl.verify_param_mut().set_host("wrong.example").unwrap();
                    ssl.set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
                        calls.fetch_add(1, SeqCst);
                        if rejecting.load(SeqCst) {
                            Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_REVOKED))
                        } else {
                            Ok(())
                        }
                    });
                };
                let mut first = client(&ctx);
                configure(&mut first);
                assert!(drive(first, Ssl::new(&server).unwrap(), quic, false).0);
                rejecting.store(reject, SeqCst);
                let mut resumed = client(&ctx);
                configure(&mut resumed);
                unsafe {
                    resumed
                        .set_session(&tickets.lock().unwrap().take().unwrap())
                        .unwrap();
                }
                let result = drive(resumed, Ssl::new(&server).unwrap(), quic, false);
                assert_eq!(result.0, !(reverify && reject));
                assert_eq!(calls.load(SeqCst), if reverify { 2 } else { 1 });
                // The existing custom path keeps the original verification result.
                assert_eq!(result.2, Ok(()));
            }
        }
    }
}

#[test]
#[ignore = "release-mode timing of a full TLS 1.3 handshake plus a resumption"]
fn measure_reverify_handshake_pairs() {
    use std::time::Instant;
    const N: usize = 1000;
    for reverify in [false, true, false, true] {
        if reverify && std::env::var_os("RAMA_BENCH_OFF_ONLY").is_some() {
            continue;
        }
        let (ctx, server, tickets) = contexts(SslVersion::TLS1_3, reverify);
        let verified = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        for _ in 0..N {
            for resume in [false, true] {
                let mut ssl = client(&ctx);
                let verified = verified.clone();
                ssl.set_verify_callback(SslVerifyMode::PEER, move |ok, store| {
                    if store.error_depth() == 0 {
                        verified.fetch_add(1, SeqCst);
                    }
                    ok
                });
                if resume {
                    unsafe {
                        ssl.set_session(&tickets.lock().unwrap().take().unwrap())
                            .unwrap();
                    }
                }
                assert_eq!(
                    drive(ssl, Ssl::new(&server).unwrap(), false, false),
                    (true, resume, Ok(()))
                );
            }
        }
        let ns = start.elapsed().as_nanos() / N as u128;
        assert_eq!(verified.load(SeqCst), N * if reverify { 2 } else { 1 });
        eprintln!("TLS13 full+resumed handshake pair; baseline=reverify off; reverify={reverify}; ns/pair={ns}; leaf_verifications={}", verified.load(SeqCst));
    }
}

#[test]
#[ignore = "release-mode resumption overhead against one standalone verification"]
fn measure_reverify_resumption_cost() {
    use crate::{ffi, stack::Stack, x509::X509StoreContext};
    use foreign_types::{ForeignType, ForeignTypeRef};
    use std::time::Instant;
    const N: usize = 3000;
    for round in 0..3 {
        let (ctx, _, _) = contexts(SslVersion::TLS1_3, false);
        let mut ssl = client(&ctx);
        let leaf = X509::from_pem(super::CERT).unwrap();
        let mut chain = Stack::new().unwrap();
        chain.push(leaf.clone()).unwrap();
        let mut verify = || {
            X509StoreContext::new()
                .unwrap()
                .init(ctx.cert_store(), &leaf, &chain, |store| {
                    // Match session_verify_cert_chain: server purpose, SSL ex_data,
                    // and the connection's hostname/time parameters.
                    unsafe {
                        assert_eq!(
                            ffi::X509_STORE_CTX_set_default(store.as_ptr(), c"ssl_server".as_ptr()),
                            1
                        );
                        assert_eq!(
                            ffi::X509_STORE_CTX_set_ex_data(
                                store.as_ptr(),
                                ffi::SSL_get_ex_data_X509_STORE_CTX_idx(),
                                ssl.as_ptr().cast()
                            ),
                            1
                        );
                    }
                    store
                        .verify_param_mut()
                        .copy_from(ssl.verify_param_mut())
                        .unwrap();
                    assert!(store.verify_cert().unwrap());
                    Ok(())
                })
                .unwrap();
        };
        for _ in 0..64 {
            verify();
        }
        let start = Instant::now();
        for _ in 0..N {
            verify();
        }
        eprintln!("round={round}; baseline=standalone X509 verification of same cached leaf/root, hostname and time; ns/verify={}", start.elapsed().as_nanos() / N as u128);
        for reverify in [false, true] {
            if reverify && std::env::var_os("RAMA_BENCH_OFF_ONLY").is_some() {
                continue;
            }
            let (ctx, server, tickets) = contexts(SslVersion::TLS1_3, reverify);
            assert!(drive(client(&ctx), Ssl::new(&server).unwrap(), false, false).0);
            let ticket = tickets.lock().unwrap().take().unwrap();
            let resume = || {
                let mut ssl = client(&ctx);
                unsafe {
                    ssl.set_session(&ticket).unwrap();
                }
                assert_eq!(
                    drive(ssl, Ssl::new(&server).unwrap(), false, false),
                    (true, true, Ok(()))
                );
            };
            for _ in 0..64 {
                resume();
            }
            let start = Instant::now();
            for _ in 0..N {
                resume();
            }
            eprintln!("round={round}; baseline=reverify off; TLS13 resumed client/server handshake; reverify={reverify}; ns/resumption={}", start.elapsed().as_nanos() / N as u128);
        }
    }
}

#[test]
fn reverify_custom_callback_can_retry() {
    use crate::ssl::SslVerifyError;
    for (quic, version) in [
        (false, SslVersion::TLS1_2),
        (false, SslVersion::TLS1_3),
        (true, SslVersion::TLS1_3),
    ] {
        let (ctx, server, tickets) = contexts(version, true);
        for resume in [false, true] {
            let mut ssl = client(&ctx);
            if resume {
                unsafe {
                    ssl.set_session(&tickets.lock().unwrap().take().unwrap())
                        .unwrap();
                }
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let counter = calls.clone();
            ssl.set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
                if counter.fetch_add(1, SeqCst) == 0 {
                    Err(SslVerifyError::Retry)
                } else {
                    Ok(())
                }
            });
            assert_eq!(
                drive(ssl, Ssl::new(&server).unwrap(), quic, false),
                (true, resume, Ok(()))
            );
            assert_eq!(calls.load(SeqCst), 2);
        }
    }
}
