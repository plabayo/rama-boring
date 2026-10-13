//! How a client answers a TLS 1.2 server's HelloRequest, per renegotiation mode.
//!
//! BoringSSL servers cannot initiate renegotiation, so these tests seal the
//! server's records themselves, with the server write key from the key block.

use super::memory::{client_context, handshake, server_context, End};
use crate::ffi;
use crate::ssl::{
    Error, ErrorCode, Ssl, SslContentType, SslContext, SslContextBuilder, SslRenegotiateMode,
    SslStream, SslVersion,
};
use crate::symm::{encrypt_aead, Cipher};
use foreign_types::ForeignTypeRef;
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

const HELLO_REQUEST: [u8; 4] = [0, 0, 0, 0];
const APPLICATION_DATA: u8 = 23;
const NO_RENEGOTIATION_ALERT: [u8; 2] = [2, 100];

/// Every message one side wrote: content type and bytes.
type Written = Arc<Mutex<Vec<(i32, Vec<u8>)>>>;

fn tls12(mut ctx: SslContextBuilder) -> SslContext {
    ctx.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.set_cipher_list("ECDHE-RSA-AES128-GCM-SHA256").unwrap();
    ctx.build()
}

/// A finished TLS 1.2 connection whose server records the test seals itself.
struct Connection {
    client: SslStream<End>,
    server: SslStream<End>,
    written: Written,
    key: Vec<u8>,
    iv: Vec<u8>,
    seq: u64,
}

impl Connection {
    fn new(client: &SslContext, mode: Option<SslRenegotiateMode>) -> Self {
        let mut ssl = Ssl::new(client).unwrap();
        if let Some(mode) = mode {
            ssl.set_renegotiate_mode(mode);
        }
        let written = Written::default();
        let sink = written.clone();
        ssl.set_msg_callback(move |_, message| {
            if message.is_written() {
                sink.lock()
                    .unwrap()
                    .push((message.content_type().as_raw(), message.bytes().to_vec()));
            }
        });
        let server = Ssl::new(&tls12(server_context())).unwrap();
        let (client, server) = handshake(ssl, server);
        let (client, server) = (client.done(), server.done());
        assert_eq!(client.ssl().current_cipher().unwrap().protocol_id(), 0xc02f);

        // AES-GCM has no MAC keys: client key, server key, client IV, server IV.
        let ptr = server.ssl().as_ptr();
        let mut block = [0; 40];
        let seq = unsafe {
            assert_eq!(ffi::SSL_get_key_block_len(ptr), block.len());
            assert_eq!(
                ffi::SSL_generate_key_block(ptr, block.as_mut_ptr(), block.len()),
                1
            );
            ffi::SSL_get_write_sequence(ptr)
        };
        // Only the server's Finished was encrypted so far.
        assert_eq!(seq, 1);
        Self {
            client,
            server,
            written,
            key: block[16..32].to_vec(),
            iv: block[36..40].to_vec(),
            seq,
        }
    }

    /// Seals a record as the server and queues it for the client.
    fn send_as_server(&mut self, content_type: u8, plaintext: &[u8]) {
        let seq = self.seq.to_be_bytes();
        let nonce = [self.iv.as_slice(), &seq].concat();
        let len = u16::try_from(plaintext.len()).unwrap().to_be_bytes();
        let aad = [&seq[..], &[content_type, 3, 3], &len].concat();
        let mut tag = [0; 16];
        let sealed = encrypt_aead(
            Cipher::aes_128_gcm(),
            &self.key,
            Some(&nonce),
            &aad,
            plaintext,
            &mut tag,
        )
        .unwrap();
        let body = [&seq[..], &sealed, &tag].concat();
        let header = [content_type, 3, 3];
        let body_len = u16::try_from(body.len()).unwrap().to_be_bytes();
        self.client
            .get_mut()
            .rx
            .lock()
            .unwrap()
            .extend([&header[..], &body_len, &body].concat());
        self.seq += 1;
    }

    fn hello_request(&mut self) {
        self.send_as_server(SslContentType::HANDSHAKE.as_raw() as u8, &HELLO_REQUEST);
    }

    fn read(&mut self) -> Result<usize, Error> {
        self.client.ssl_read(&mut [0; 16])
    }

    /// How many ClientHellos the client wrote.
    fn client_hellos(&self) -> usize {
        self.written_messages(SslContentType::HANDSHAKE)
            .filter(|bytes| bytes.first() == Some(&1))
            .count()
    }

    fn written_messages(&self, content_type: SslContentType) -> impl Iterator<Item = Vec<u8>> {
        let written = self.written.lock().unwrap().clone();
        written
            .into_iter()
            .filter(move |(ty, _)| *ty == content_type.as_raw())
            .map(|(_, bytes)| bytes)
    }

    fn total_renegotiations(&self) -> i32 {
        unsafe { ffi::SSL_total_renegotiations(self.client.ssl().as_ptr()) }
    }

    fn renegotiate_pending(&self) -> bool {
        unsafe { ffi::SSL_renegotiate_pending(self.client.ssl().as_ptr()) == 1 }
    }

    /// The client's next message to the server still arrives.
    #[track_caller]
    fn client_can_write(&mut self) {
        self.client.write_all(b"ping").unwrap();
        let mut buf = [0; 4];
        self.server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// The client refused the HelloRequest with a `no_renegotiation` alert.
    #[track_caller]
    fn refused(&mut self) {
        no_renegotiation(&self.read().unwrap_err());
        assert!(self
            .written_messages(SslContentType::ALERT)
            .any(|alert| alert == NO_RENEGOTIATION_ALERT));
        assert_eq!(self.client_hellos(), 1);
        assert_eq!(self.total_renegotiations(), 0);
    }

    /// The client answered the HelloRequest with a new ClientHello.
    #[track_caller]
    fn renegotiating(&mut self) {
        assert_eq!(self.read().unwrap_err().code(), ErrorCode::WANT_READ);
        assert_eq!(self.client_hellos(), 2);
        assert_eq!(self.total_renegotiations(), 1);
        assert!(self.renegotiate_pending());
    }
}

/// A read failed because renegotiation is not allowed.
#[track_caller]
fn no_renegotiation(error: &Error) {
    assert_eq!(error.code(), ErrorCode::SSL);
    let reasons: Vec<_> = error
        .ssl_error()
        .unwrap()
        .errors()
        .iter()
        .filter_map(|e| e.reason())
        .collect();
    assert!(reasons.contains(&"NO_RENEGOTIATION"), "{reasons:?}");
}

fn client() -> SslContext {
    tls12(client_context())
}

/// Clients refuse renegotiation by default, with a `no_renegotiation` alert.
#[test]
fn renegotiation_refused_by_default() {
    let mut conn = Connection::new(&client(), None);
    conn.hello_request();
    conn.refused();

    let mut conn = Connection::new(&client(), Some(SslRenegotiateMode::NEVER));
    conn.hello_request();
    conn.refused();
}

/// `FREELY` answers a HelloRequest with a new ClientHello, which a BoringSSL
/// server then rejects: it never accepts renegotiation.
#[test]
fn renegotiation_freely_starts_a_handshake() {
    let mut conn = Connection::new(&client(), Some(SslRenegotiateMode::FREELY));
    conn.hello_request();
    conn.renegotiating();

    no_renegotiation(&conn.server.ssl_read(&mut [0; 16]).unwrap_err());
}

/// `ONCE` starts one renegotiation. Refusing a second needs the first to
/// finish, which needs a server that renegotiates: BoringSSL has none.
#[test]
fn renegotiation_once_starts_a_handshake() {
    let mut conn = Connection::new(&client(), Some(SslRenegotiateMode::ONCE));
    conn.hello_request();
    conn.renegotiating();
}

/// `IGNORE` drops the HelloRequest and keeps the connection usable both ways.
#[test]
fn renegotiation_ignored() {
    let mut conn = Connection::new(&client(), Some(SslRenegotiateMode::IGNORE));
    conn.hello_request();
    assert_eq!(conn.read().unwrap_err().code(), ErrorCode::WANT_READ);
    assert_eq!(conn.client_hellos(), 1);
    assert_eq!(conn.total_renegotiations(), 0);
    assert!(conn
        .written_messages(SslContentType::ALERT)
        .next()
        .is_none());

    conn.send_as_server(APPLICATION_DATA, b"after");
    let mut buf = [0; 5];
    conn.client.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"after");
    conn.client_can_write();
}

/// `EXPLICIT` pauses reads with `WANT_RENEGOTIATE` until `SSL_renegotiate`;
/// writes keep working meanwhile.
#[test]
fn renegotiation_explicit_waits_for_the_caller() {
    let want_renegotiate = ErrorCode::from_raw(ffi::SSL_ERROR_WANT_RENEGOTIATE);
    let mut conn = Connection::new(&client(), Some(SslRenegotiateMode::EXPLICIT));
    conn.hello_request();
    assert_eq!(conn.read().unwrap_err().code(), want_renegotiate);
    assert_eq!(conn.read().unwrap_err().code(), want_renegotiate);
    assert_eq!(conn.client_hellos(), 1);
    assert_eq!(conn.total_renegotiations(), 0);
    // Pending means a renegotiation handshake is running, not merely requested.
    assert!(!conn.renegotiate_pending());
    conn.client_can_write();

    assert_eq!(
        unsafe { ffi::SSL_renegotiate(conn.client.ssl().as_ptr()) },
        1
    );
    conn.renegotiating();
}

/// The mode belongs to one connection, not to the context it came from.
#[test]
fn renegotiation_mode_is_per_connection() {
    let client = client();
    let mut freely = Connection::new(&client, Some(SslRenegotiateMode::FREELY));
    let mut never = Connection::new(&client, None);
    freely.hello_request();
    never.hello_request();
    freely.renegotiating();
    never.refused();
}
