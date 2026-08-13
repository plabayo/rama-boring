use futures::future;
use rama_boring::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{NameType, SslAcceptor, SslConnector, SslMethod},
    x509::{extension::SubjectAlternativeName, store::X509StoreBuilder, X509Name, X509},
};
use std::net::ToSocketAddrs;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

mod common;

use self::common::{
    connect, connect_without_sni, create_listener, create_server,
    with_trivial_client_server_exchange,
};

fn ip_certificate() -> (X509, PKey<Private>) {
    let private_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "ip.test")
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&private_key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let subject_alt_name = SubjectAlternativeName::new()
        .ip("127.0.0.1")
        .ip("::1")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&subject_alt_name).unwrap();
    builder.sign(&private_key, MessageDigest::sha256()).unwrap();

    (builder.build(), private_key)
}

fn ip_acceptor(certificate: &X509, private_key: &PKey<Private>) -> SslAcceptor {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key(private_key).unwrap();
    builder.set_certificate(certificate).unwrap();
    builder.check_private_key().unwrap();
    builder.build()
}

async fn assert_ip_identity(peer_identity: &'static str, accepted: bool) {
    let (listener, addr) = create_listener();
    let (certificate, private_key) = ip_certificate();
    let acceptor = ip_acceptor(&certificate, &private_key);
    let server = async move {
        let stream = listener.accept().await.unwrap().0;
        rama_boring_tokio::accept(&acceptor, stream).await
    };
    let client = async move {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(certificate).unwrap();
        let mut builder = SslConnector::no_default_verify_builder(SslMethod::tls()).unwrap();
        builder.set_cert_store_builder(store);
        let config = builder.build().configure().unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        rama_boring_tokio::connect(config, Some(peer_identity), stream).await
    };

    let (client, server) = future::join(client, server).await;
    if accepted {
        assert!(
            client.is_ok(),
            "failed to verify {peer_identity}: client={client:?}, server={server:?}"
        );
        let server = server.unwrap();
        assert!(server.ssl().servername(NameType::HOST_NAME).is_none());
    } else {
        assert!(client.is_err(), "accepted wrong identity {peer_identity}");
    }
}

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
async fn dns_identity_is_sent_as_sni() {
    let (server, addr) = create_server(|_| ());

    let server = async {
        let stream = server.await.unwrap();
        assert_eq!(
            stream.ssl().servername(NameType::HOST_NAME),
            Some("localhost")
        );
    };

    let client = async {
        connect(addr, |builder| builder.set_ca_file("tests/cert.pem"))
            .await
            .unwrap();
    };

    future::join(server, client).await;
}

#[tokio::test]
async fn ip_identities_are_verified_without_sni() {
    for peer_identity in ["127.0.0.1", "::1"] {
        assert_ip_identity(peer_identity, true).await;
    }
}

#[tokio::test]
async fn wrong_ip_identity_is_rejected() {
    assert_ip_identity("127.0.0.2", false).await;
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
