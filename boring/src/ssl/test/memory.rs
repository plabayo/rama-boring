//! An in-memory, nonblocking TLS transport and a driver that runs both ends of
//! a handshake in one thread.

use crate::ssl::{
    HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslContextBuilder, SslFiletype,
    SslMethod, SslStream,
};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    sync::{Arc, Mutex},
};

pub(super) type Buffer = Arc<Mutex<VecDeque<u8>>>;

/// One end of an in-memory, nonblocking transport.
pub(super) struct End {
    pub(super) rx: Buffer,
    pub(super) tx: Buffer,
}

impl Read for End {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.rx.lock().unwrap();
        if rx.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = rx.len().min(buf.len());
        for (slot, byte) in buf.iter_mut().zip(rx.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

impl Write for End {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx.lock().unwrap().extend(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn ends() -> (End, End) {
    let (a, b) = (Buffer::default(), Buffer::default());
    (
        End {
            rx: a.clone(),
            tx: b.clone(),
        },
        End { rx: b, tx: a },
    )
}

pub(super) enum Side<S> {
    Mid(MidHandshakeSslStream<S>),
    Done(SslStream<S>),
    Failed(String),
}

impl<S: Read + Write> Side<S> {
    pub(super) fn from(result: Result<SslStream<S>, HandshakeError<S>>) -> Self {
        match result {
            Ok(stream) => Self::Done(stream),
            Err(HandshakeError::WouldBlock(mid)) => Self::Mid(mid),
            Err(HandshakeError::Failure(mid)) => Self::Failed(describe(mid.error())),
            Err(HandshakeError::SetupFailure(error)) => Self::Failed(error.to_string()),
        }
    }

    pub(super) fn step(self) -> Self {
        match self {
            Self::Mid(mid) => Self::from(mid.handshake()),
            other => other,
        }
    }

    #[track_caller]
    pub(super) fn done(self) -> SslStream<S> {
        match self {
            Self::Done(stream) => stream,
            Self::Mid(_) => panic!("handshake stalled"),
            Self::Failed(error) => panic!("handshake failed: {error}"),
        }
    }

    /// The handshake failed because the named callback panicked.
    #[track_caller]
    pub(super) fn panicked(&self, what: &str) {
        match self {
            Self::Failed(error) => assert!(
                error.contains(&format!("callback panicked: {what}")),
                "{error}"
            ),
            Self::Done(_) => panic!("handshake succeeded"),
            Self::Mid(_) => panic!("handshake stalled"),
        }
    }

    /// The handshake failed with an error mentioning `text`.
    #[track_caller]
    pub(super) fn panicked_or_failed_with(&self, text: &str) {
        match self {
            Self::Failed(error) => assert!(error.contains(text), "{error}"),
            Self::Done(_) => panic!("handshake succeeded"),
            Self::Mid(_) => panic!("handshake stalled"),
        }
    }

    #[track_caller]
    pub(super) fn failed(&self) {
        assert!(matches!(self, Self::Failed(_)), "handshake did not fail");
    }
}

/// Runs both handshakes over an in-memory transport until neither can progress.
pub(super) fn handshake(client: Ssl, server: Ssl) -> (Side<End>, Side<End>) {
    let (client, server) = handshake_results(client, server);
    (Side::from(client), Side::from(server))
}

type HandshakeResult = Result<SslStream<End>, HandshakeError<End>>;

/// Keeps failed connections available for inspecting their verification result.
pub(super) fn handshake_results(client: Ssl, server: Ssl) -> (HandshakeResult, HandshakeResult) {
    fn step(result: HandshakeResult) -> HandshakeResult {
        match result {
            Err(HandshakeError::WouldBlock(mid)) => mid.handshake(),
            other => other,
        }
    }
    let (a, b) = ends();
    let mut client = client.connect(a);
    let mut server = server.accept(b);
    for _ in 0..32 {
        client = step(client);
        server = step(server);
        if !matches!(client, Err(HandshakeError::WouldBlock(_)))
            && !matches!(server, Err(HandshakeError::WouldBlock(_)))
        {
            break;
        }
    }
    (client, server)
}

pub(super) fn server_context() -> SslContextBuilder {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_certificate_chain_file("test/cert.pem").unwrap();
    ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    ctx
}

pub(super) fn client_context() -> SslContextBuilder {
    SslContext::builder(SslMethod::tls()).unwrap()
}

pub(super) fn connect(
    client: SslContextBuilder,
    server: SslContextBuilder,
) -> (Side<End>, Side<End>) {
    handshake(
        Ssl::new(&client.build()).unwrap(),
        Ssl::new(&server.build()).unwrap(),
    )
}

/// An error with each queued error's detail, which `Display` leaves out.
fn describe(error: &crate::ssl::Error) -> String {
    let mut text = error.to_string();
    for queued in error
        .ssl_error()
        .map(|stack| stack.errors())
        .unwrap_or_default()
    {
        if let Some(data) = queued.data() {
            text.push_str(" | ");
            text.push_str(data);
        }
    }
    text
}
