use super::*;
use crate::{
    pkey::PKey,
    ssl::{SslContext, SslMethod, SslSession, SslSessionCacheMode, SslVerifyMode, SslVersion},
    x509::X509,
};

type RecordedSecret = (bool, EncryptionLevel, u16, Vec<u8>);

#[derive(Default)]
struct Record {
    output: Mutex<Vec<(EncryptionLevel, Vec<u8>)>>,
    secrets: Mutex<Vec<RecordedSecret>>,
    alerts: Mutex<Vec<u8>>,
    panic: bool,
    panic_payload: bool,
    fail: bool,
}
impl QuicMethod for Record {
    fn set_read_secret(
        &self,
        level: EncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), ErrorStack> {
        self.secrets
            .lock()
            .unwrap()
            .push((false, level, cipher.protocol_id(), secret.to_vec()));
        Ok(())
    }
    fn set_write_secret(
        &self,
        level: EncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), ErrorStack> {
        self.secrets
            .lock()
            .unwrap()
            .push((true, level, cipher.protocol_id(), secret.to_vec()));
        Ok(())
    }
    fn add_handshake_data(&self, level: EncryptionLevel, data: &[u8]) -> Result<(), ErrorStack> {
        if self.panic_payload {
            struct Payload;
            impl Drop for Payload {
                fn drop(&mut self) {
                    panic!("panic payload destructor");
                }
            }
            std::panic::panic_any(Payload);
        }
        assert!(!self.panic, "callback fault");
        if self.fail {
            return Err(ErrorStack::get());
        }
        self.output.lock().unwrap().push((level, data.to_vec()));
        Ok(())
    }
    fn flush_flight(&self) -> Result<(), ErrorStack> {
        Ok(())
    }
    fn send_alert(&self, _: EncryptionLevel, alert: u8) -> Result<(), ErrorStack> {
        self.alerts.lock().unwrap().push(alert);
        Ok(())
    }
}

fn contexts() -> (SslContext, SslContext, Arc<Mutex<Option<SslSession>>>) {
    let mut server = SslContext::builder(SslMethod::tls()).unwrap();
    server
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .set_certificate(&X509::from_pem(include_bytes!("../../../test/cert.pem")).unwrap())
        .unwrap();
    server
        .set_private_key(
            &PKey::private_key_from_pem(include_bytes!("../../../test/key.pem")).unwrap(),
        )
        .unwrap();
    server.set_session_id_context(b"quic-test").unwrap();
    server.set_alpn_select_callback(|_, offers| {
        crate::ssl::select_next_proto(b"\x02h3", offers).ok_or(crate::ssl::AlpnError::ALERT_FATAL)
    });
    let mut client = SslContext::builder(SslMethod::tls()).unwrap();
    client
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client.set_verify(SslVerifyMode::NONE);
    client.set_alpn_protos(b"\x02h3").unwrap();
    client.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    let tickets = Arc::new(Mutex::new(None));
    let captured = tickets.clone();
    client.set_new_session_callback(move |_, ticket| *captured.lock().unwrap() = Some(ticket));
    (client.build(), server.build(), tickets)
}

fn connection(ctx: &SslContext, server: bool, record: Arc<Record>) -> QuicConnection {
    let ssl = Ssl::new(ctx).unwrap();
    let mut conn = QuicConnection::new(ssl, record).unwrap();
    if server {
        conn.set_accept_state();
    } else {
        conn.set_connect_state();
    }
    conn.set_transport_parameters(if server {
        b"server parameters"
    } else {
        b"client parameters"
    })
    .unwrap();
    conn.set_early_data_enabled(true);
    if server {
        conn.set_early_data_context(b"transport-context").unwrap();
    }
    conn
}

fn step(conn: &mut QuicConnection) -> Result<(), QuicError> {
    if conn.ssl().is_init_finished() {
        return conn.process_post_handshake();
    }
    if conn.handshake()? == HandshakeStatus::EarlyDataRejected {
        conn.reset_early_data_rejection()?;
        conn.handshake()?;
    }
    Ok(())
}

fn pump(
    client: &mut QuicConnection,
    server: &mut QuicConnection,
    c: &Record,
    s: &Record,
) -> Result<(), QuicError> {
    for _ in 0..32 {
        step(client)?;
        step(server)?;
        for (record, receiver) in [(c, &mut *server), (s, &mut *client)] {
            for (level, bytes) in std::mem::take(&mut *record.output.lock().unwrap()) {
                for chunk in bytes.chunks(7) {
                    receiver.provide_data(level, chunk)?;
                    step(receiver)?;
                }
            }
        }
        if client.ssl().is_init_finished()
            && server.ssl().is_init_finished()
            && c.output.lock().unwrap().is_empty()
            && s.output.lock().unwrap().is_empty()
        {
            return Ok(());
        }
    }
    panic!("handshake failed to make progress");
}

#[test]
fn fragmented_handshake_and_resumption_deliver_directional_secrets() {
    let (client_ctx, server_ctx, tickets) = contexts();
    for resumed in [false, true] {
        let c = Arc::new(Record::default());
        let s = Arc::new(Record::default());
        let mut client = connection(&client_ctx, false, c.clone());
        let mut server = connection(&server_ctx, true, s.clone());
        if resumed {
            let ticket = tickets
                .lock()
                .unwrap()
                .take()
                .expect("post-handshake ticket");
            // Both connections use the same client context.
            unsafe {
                client.ssl_mut().set_session(&ticket).unwrap();
            }
        }
        pump(&mut client, &mut server, &c, &s).unwrap();
        assert_eq!(client.ssl().session_reused(), resumed);
        assert_eq!(server.ssl().session_reused(), resumed);
        assert_eq!(client.early_data_accepted(), resumed);
        assert_eq!(server.early_data_accepted(), resumed);
        assert_eq!(client.peer_transport_parameters(), b"server parameters");
        assert_eq!(server.peer_transport_parameters(), b"client parameters");
        let cs = c.secrets.lock().unwrap();
        let ss = s.secrets.lock().unwrap();
        for (write, level, cipher, secret) in cs.iter() {
            assert!(ss
                .iter()
                .any(|(w, l, a, k)| *w != *write && l == level && a == cipher && k == secret));
        }
        for level in [EncryptionLevel::Handshake, EncryptionLevel::Application] {
            assert_eq!(cs.iter().filter(|(_, l, _, _)| *l == level).count(), 2);
        }
        assert_eq!(
            cs.iter()
                .filter(|(_, l, _, _)| *l == EncryptionLevel::EarlyData)
                .count(),
            usize::from(resumed)
        );
        let mut a = [0; 32];
        let mut b = [0; 32];
        client
            .ssl()
            .export_keying_material(&mut a, "test", Some(b"context"))
            .unwrap();
        server
            .ssl()
            .export_keying_material(&mut b, "test", Some(b"context"))
            .unwrap();
        assert_eq!(a, b);
    }
}

#[test]
fn callback_faults_return_to_rust_and_release_ownership() {
    let (ctx, _, _) = contexts();
    for panic in [false, true] {
        let record = Arc::new(Record {
            panic,
            fail: !panic,
            ..Default::default()
        });
        let weak = Arc::downgrade(&record);
        let mut conn = connection(&ctx, false, record);
        let error = conn.handshake().unwrap_err();
        assert!(matches!(
            (panic, error),
            (true, QuicError::CallbackPanicked) | (false, QuicError::Callback(_))
        ));
        assert!(matches!(conn.handshake(), Err(QuicError::InvalidState)));
        drop(conn);
        assert!(weak.upgrade().is_none());
    }
}

#[test]
fn wrong_encryption_level_is_rejected() {
    let (_, ctx, _) = contexts();
    let mut server = connection(&ctx, true, Arc::new(Record::default()));
    assert!(server
        .provide_data(EncryptionLevel::Application, b"invalid")
        .is_err());
}

#[test]
fn panicking_payload_destructor_cannot_unwind_through_c() {
    let (ctx, _, _) = contexts();
    let record = Arc::new(Record {
        panic_payload: true,
        ..Default::default()
    });
    let mut client = connection(&ctx, false, record);
    assert!(matches!(
        client.handshake(),
        Err(QuicError::CallbackPanicked)
    ));
}

#[test]
fn certificate_verification_failure_emits_an_alert() {
    let (client_ctx, server_ctx, _) = contexts();
    let c = Arc::new(Record::default());
    let s = Arc::new(Record::default());
    let mut client = connection(&client_ctx, false, c.clone());
    let mut server = connection(&server_ctx, true, s.clone());
    client.ssl_mut().set_verify(SslVerifyMode::PEER);
    let error = pump(&mut client, &mut server, &c, &s).unwrap_err();
    assert!(matches!(error, QuicError::Tls(_)));
    assert!(
        error.to_string().contains("CERTIFICATE_VERIFY_FAILED"),
        "{error}"
    );
    assert!(!c.alerts.lock().unwrap().is_empty());
}

#[test]
fn native_quic_handshake_requires_an_alpn_offer() {
    let (ctx, _, _) = contexts();
    let record = Arc::new(Record::default());
    let mut client = connection(&ctx, false, record.clone());
    client.ssl_mut().set_alpn_protos(&[]).unwrap();
    let error = client.handshake().unwrap_err();
    assert!(matches!(error, QuicError::Tls(_)));
    assert!(
        error.to_string().contains("NO_APPLICATION_PROTOCOL"),
        "{error}"
    );
    assert!(record.output.lock().unwrap().is_empty());
}

#[test]
fn rejection_reset_requires_a_rejected_handshake() {
    let (ctx, _, _) = contexts();
    let mut client = connection(&ctx, false, Arc::new(Record::default()));
    assert!(matches!(
        client.reset_early_data_rejection(),
        Err(QuicError::InvalidState)
    ));
    assert!(matches!(
        client.process_post_handshake(),
        Err(QuicError::InvalidState)
    ));
    assert_eq!(client.handshake().unwrap(), HandshakeStatus::WantRead);
}

#[test]
fn changed_early_data_context_rejects_early_data_but_resumes_tls() {
    let (client_ctx, server_ctx, tickets) = contexts();
    let c = Arc::new(Record::default());
    let s = Arc::new(Record::default());
    let mut client = connection(&client_ctx, false, c.clone());
    let mut server = connection(&server_ctx, true, s.clone());
    pump(&mut client, &mut server, &c, &s).unwrap();
    let ticket = tickets.lock().unwrap().take().unwrap();

    let c = Arc::new(Record::default());
    let s = Arc::new(Record::default());
    let mut client = connection(&client_ctx, false, c.clone());
    let mut server = connection(&server_ctx, true, s.clone());
    // The ticket belongs to the same client context.
    unsafe {
        client.ssl_mut().set_session(&ticket).unwrap();
    }
    server
        .set_early_data_context(b"changed-transport-context")
        .unwrap();
    pump(&mut client, &mut server, &c, &s).unwrap();
    assert!(client.ssl().session_reused());
    assert!(server.ssl().session_reused());
    assert!(!client.early_data_accepted());
    assert!(!server.early_data_accepted());
    assert!(c
        .secrets
        .lock()
        .unwrap()
        .iter()
        .any(|(_, level, _, _)| *level == EncryptionLevel::EarlyData));
    assert!(!s
        .secrets
        .lock()
        .unwrap()
        .iter()
        .any(|(_, level, _, _)| *level == EncryptionLevel::EarlyData));
}
