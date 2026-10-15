//! Local diagnostic only. The TLS client intentionally accepts the test
//! certificate; all sockets are restricted to IPv4 loopback.
use rama_boring as boring;
use rama_boring_sys as ffi;
use std::{
    error::Error,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

use boring::{
    pkey::PKey,
    ssl::{SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion},
    x509::X509,
};

const RECORD: usize = 16 * 1024;
const CIPHER: &str = "ECDHE-RSA-AES128-GCM-SHA256";
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn capability() -> bool {
    ffi::init();
    // This symbol is resolved from the very same rama-boring-sys dependency
    // as the TLS and AEAD calls below, including its versioned symbol prefix.
    let aes = unsafe { ffi::EVP_has_aes_hardware() != 0 };
    eprintln!(
        "pid={} arch={} aes_hardware={aes}",
        std::process::id(),
        std::env::consts::ARCH
    );
    aes
}

fn crypto(seconds: u64) {
    for (name, algorithm, key_len) in unsafe {
        [
            ("AES-128-GCM", ffi::EVP_aead_aes_128_gcm(), 16),
            ("AES-256-GCM", ffi::EVP_aead_aes_256_gcm(), 32),
            ("ChaCha20-Poly1305", ffi::EVP_aead_chacha20_poly1305(), 32),
        ]
    } {
        let key = [42_u8; 32];
        let ctx = unsafe { ffi::EVP_AEAD_CTX_new(algorithm, key.as_ptr(), key_len, 16) };
        assert!(!ctx.is_null());
        let plaintext = [7_u8; RECORD];
        let aad = [0_u8; 13];
        let mut ciphertext = [0_u8; RECORD + 16];
        let mut decrypted = [0_u8; RECORD];
        for operation in ["seal", "open"] {
            let start = Instant::now();
            let mut count = 0_u64;
            let mut nonce = [0_u8; 12];
            let mut len = 0;
            // Prepare one authenticated record for the decryption benchmark.
            if operation == "open" {
                nonce[0] = 1; // distinct from all seal nonces
                assert_eq!(
                    unsafe {
                        ffi::EVP_AEAD_CTX_seal(
                            ctx,
                            ciphertext.as_mut_ptr(),
                            &mut len,
                            ciphertext.len(),
                            nonce.as_ptr(),
                            nonce.len(),
                            plaintext.as_ptr(),
                            plaintext.len(),
                            aad.as_ptr(),
                            aad.len(),
                        )
                    },
                    1
                );
            }
            while start.elapsed() < Duration::from_secs(seconds) {
                if operation == "seal" {
                    nonce[4..].copy_from_slice(&count.to_le_bytes());
                    assert_eq!(
                        unsafe {
                            ffi::EVP_AEAD_CTX_seal(
                                ctx,
                                ciphertext.as_mut_ptr(),
                                &mut len,
                                ciphertext.len(),
                                nonce.as_ptr(),
                                nonce.len(),
                                plaintext.as_ptr(),
                                plaintext.len(),
                                aad.as_ptr(),
                                aad.len(),
                            )
                        },
                        1
                    );
                } else {
                    assert_eq!(
                        unsafe {
                            ffi::EVP_AEAD_CTX_open(
                                ctx,
                                decrypted.as_mut_ptr(),
                                &mut len,
                                decrypted.len(),
                                nonce.as_ptr(),
                                nonce.len(),
                                ciphertext.as_ptr(),
                                ciphertext.len(),
                                aad.as_ptr(),
                                aad.len(),
                            )
                        },
                        1
                    );
                }
                count += 1;
            }
            let elapsed = start.elapsed().as_secs_f64();
            if operation == "open" {
                assert_eq!(decrypted, plaintext);
            }
            println!(
                "crypto,{name},{operation},{RECORD},{count},{elapsed:.6},{:.3}",
                count as f64 * RECORD as f64 / elapsed / 1e6
            );
        }
        unsafe { ffi::EVP_AEAD_CTX_free(ctx) };
    }
}

fn acceptor() -> Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    let certificate = X509::from_pem(include_bytes!("../../../boring/test/cert.pem"))?;
    let key = PKey::private_key_from_pem(include_bytes!("../../../boring/test/key.pem"))?;
    builder.set_certificate(&certificate)?;
    builder.set_private_key(&key)?;
    builder.check_private_key()?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_cipher_list(CIPHER)?;
    Ok(builder.build())
}

fn connect(port: u16) -> Result<SslStream<TcpStream>> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_cipher_list(CIPHER)?;
    let socket = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))?;
    socket.set_nodelay(true)?;
    Ok(builder.build().connect(Some("localhost"), socket)?)
}

fn describe(leg: &str, stream: &SslStream<TcpStream>) {
    eprintln!(
        "{leg}: version={} cipher={}",
        stream.ssl().version_str(),
        stream.ssl().current_cipher().unwrap().name()
    );
}

fn header(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        data.push(byte[0]);
        if data.len() > 8192 {
            return Err("HTTP header too large".into());
        }
    }
    Ok(data)
}

fn origin(port: u16, mib: u64) -> Result<()> {
    let acceptor = acceptor()?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    eprintln!("ready origin {port}");
    for socket in listener.incoming() {
        let socket = socket?;
        socket.set_nodelay(true)?;
        let mut tls = acceptor.accept(socket)?;
        describe("origin", &tls);
        header(&mut tls)?;
        let bytes = mib * 1024 * 1024;
        write!(
            tls,
            "HTTP/1.1 200 OK\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n"
        )?;
        for _ in 0..bytes / RECORD as u64 {
            tls.write_all(&[7_u8; RECORD])?;
        }
        let _ = tls.shutdown();
    }
    Ok(())
}

fn relay(port: u16, upstream: u16) -> Result<()> {
    let acceptor = acceptor()?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    eprintln!("ready relay {port}; per-record logging disabled");
    for socket in listener.incoming() {
        let mut socket = socket?;
        socket.set_nodelay(true)?;
        let request = header(&mut socket)?;
        if !request.starts_with(b"CONNECT localhost:") {
            return Err("expected local CONNECT".into());
        }
        socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        let mut downstream = acceptor.accept(socket)?;
        let mut upstream = connect(upstream)?;
        describe("downstream", &downstream);
        describe("upstream", &upstream);
        upstream.write_all(&header(&mut downstream)?)?;
        let mut buffer = [0; RECORD];
        loop {
            let n = upstream.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            downstream.write_all(&buffer[..n])?;
        }
        let _ = downstream.shutdown();
    }
    Ok(())
}

fn download(port: u16, proxy: bool) -> Result<()> {
    let start = Instant::now();
    let mut tls = if proxy {
        let mut socket = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))?;
        socket.set_nodelay(true)?;
        socket.write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        assert!(header(&mut socket)?.starts_with(b"HTTP/1.1 200"));
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_cipher_list(CIPHER)?;
        builder.build().connect(Some("localhost"), socket)?
    } else {
        connect(port)?
    };
    describe("client", &tls);
    tls.write_all(b"GET /payload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let response = String::from_utf8(header(&mut tls)?)?;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    let expected: u64 = response
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .ok_or("missing Content-Length")?
        .parse()?;
    let mut bytes = 0_u64;
    let mut buffer = [0; RECORD];
    loop {
        let n = tls.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        assert!(buffer[..n].iter().all(|&b| b == 7), "corrupted payload");
        bytes += n as u64;
    }
    assert_eq!(bytes, expected);
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "download,{bytes},{elapsed:.6},{:.3}",
        bytes as f64 * 8.0 / elapsed / 1e6
    );
    Ok(())
}

fn main() -> Result<()> {
    let aes = capability();
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("probe") => {
            if let Some(expected) = args.get(2) {
                assert_eq!(aes, expected.parse::<u8>()? != 0, "AES hardware regression");
            }
        }
        Some("crypto") => crypto(args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(3)),
        Some("origin") => origin(args[2].parse()?, args[3].parse()?)?,
        Some("relay") => relay(args[2].parse()?, args[3].parse()?)?,
        Some("download") => download(args[2].parse()?, args.get(3).map(String::as_str) == Some("proxy"))?,
        _ => return Err("usage: probe [0|1] | crypto [seconds per case] | origin PORT MiB | relay PORT ORIGIN_PORT | download PORT [proxy]".into()),
    }
    Ok(())
}
