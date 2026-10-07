use std::io::Write as _;
use std::sync::{Arc, Mutex};

use super::server::Server;
use crate::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};

struct BrotliCompressor {
    q: u32,
    lgwin: u32,
}

impl Default for BrotliCompressor {
    fn default() -> Self {
        Self { q: 11, lgwin: 32 }
    }
}

impl CertificateCompressor for BrotliCompressor {
    const ALGORITHM: crate::ssl::CertificateCompressionAlgorithm =
        crate::ssl::CertificateCompressionAlgorithm(1234);

    const CAN_COMPRESS: bool = true;

    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut writer = brotli::CompressorWriter::new(output, 1024, self.q, self.lgwin);
        writer.write_all(input)?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)?;
        Ok(())
    }
}

/// Connect with compression configured per side; return what each side observed.
fn observed(
    client_compresses: bool,
    server_compresses: bool,
) -> [(
    Option<CertificateCompressionAlgorithm>,
    Option<CertificateCompressionAlgorithm>,
); 2] {
    let server_observed = Arc::new(Mutex::new(None));
    let mut server = Server::builder();
    if server_compresses {
        server
            .ctx()
            .add_certificate_compression_algorithm(BrotliCompressor::default())
            .unwrap();
    }
    let slot = server_observed.clone();
    server.io_cb(move |stream| {
        let ssl = stream.ssl();
        *slot.lock().unwrap() = Some((
            ssl.certificate_compression_algorithm(),
            ssl.peer_certificate_compression_algorithm(),
        ));
    });
    let server = server.build();

    let mut client = server.client();
    if client_compresses {
        client
            .ctx()
            .add_certificate_compression_algorithm(BrotliCompressor::default())
            .unwrap();
    }
    let stream = client.connect();
    let client_observed = (
        stream.ssl().certificate_compression_algorithm(),
        stream.ssl().peer_certificate_compression_algorithm(),
    );
    drop(stream);
    drop(server);
    let server_observed = server_observed.lock().unwrap().take().unwrap();
    [client_observed, server_observed]
}

#[test]
fn server_only_cert_compression() {
    assert_eq!(observed(false, true), [(None, None), (None, None)]);
}

#[test]
fn client_only_cert_compression() {
    assert_eq!(observed(true, false), [(None, None), (None, None)]);
}

#[test]
fn client_and_server_cert_compression() {
    let algorithm = Some(BrotliCompressor::ALGORITHM);
    assert_eq!(
        observed(true, true),
        [(None, algorithm), (algorithm, None)],
        "the server compresses its certificate and the client decompresses it"
    );
}
