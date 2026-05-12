use futures::future;
use rama_boring::ssl::{NameType, SslConnector, SslMethod};
use std::net::ToSocketAddrs;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

mod common;

use self::common::{
    connect, connect_without_sni, create_server, with_trivial_client_server_exchange,
};

#[tokio::test]
async fn google() {
    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let config = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap();
    let mut stream = rama_boring_tokio::connect(config, Some("google.com"), stream)
        .await
        .unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
}

#[tokio::test]
async fn no_sni_local() {
    let (stream, addr) = create_server(|_| ());

    let server = async {
        let mut stream = stream.await.unwrap();

        // The client must NOT have sent SNI.
        assert!(stream.ssl().servername(NameType::HOST_NAME).is_none());

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"asdf");

        stream.write_all(b"jkl;").await.unwrap();

        future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
            .await
            .unwrap();
    };

    let client = async {
        let mut stream = connect_without_sni(addr, |builder| builder.set_ca_file("tests/cert.pem"))
            .await
            .unwrap();

        stream.write_all(b"asdf").await.unwrap();

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"jkl;");
    };

    future::join(server, client).await;
}

#[tokio::test]
async fn server() {
    with_trivial_client_server_exchange(|_| ()).await;
}

#[tokio::test]
async fn handshake_error() {
    let (stream, addr) = create_server(|_| ());

    let server = async {
        let err = stream.await.unwrap_err();

        assert!(err.into_source_stream().is_some());
    };

    let client = async {
        let err = connect(addr, |_| Ok(())).await.unwrap_err();

        assert!(err.into_source_stream().is_some());
    };

    future::join(server, client).await;
}
