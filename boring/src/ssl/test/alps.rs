use std::sync::{Arc, Mutex};

use super::server::Server;
use crate::ssl::{select_next_proto, AlpnError};

const H2: &[u8] = b"h2";

/// Negotiate h2 with the given ALPS values; return the settings each side received.
fn exchange(
    new_codepoint: bool,
    client_value: &'static [u8],
    server_value: Option<&'static [u8]>,
) -> [Option<Vec<u8>>; 2] {
    let server_received = Arc::new(Mutex::new(None));
    let mut server = Server::builder();
    server.ctx().set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h2", offered).ok_or(AlpnError::NOACK)
    });
    server.ssl_cb(move |ssl| {
        ssl.set_alps_use_new_codepoint(new_codepoint);
        if let Some(value) = server_value {
            ssl.add_application_settings_value(H2, value).unwrap();
        }
    });
    let slot = server_received.clone();
    server.io_cb(move |stream| {
        *slot.lock().unwrap() = Some(stream.ssl().peer_application_settings().map(<[u8]>::to_vec));
    });
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x02h2").unwrap();
    let client = client.build();
    let mut connection = client.builder();
    connection.ssl().set_alps_use_new_codepoint(new_codepoint);
    connection
        .ssl()
        .add_application_settings_value(H2, client_value)
        .unwrap();
    let stream = connection.connect();
    assert_eq!(stream.ssl().selected_alpn_protocol(), Some(H2));
    let client_received = stream.ssl().peer_application_settings().map(<[u8]>::to_vec);
    drop(stream);
    drop(server);
    let server_received = server_received.lock().unwrap().take().unwrap();
    [client_received, server_received]
}

#[test]
fn application_settings_values_are_exchanged_on_both_codepoints() {
    for new_codepoint in [false, true] {
        assert_eq!(
            exchange(new_codepoint, b"client settings", Some(b"server settings")),
            [
                Some(b"server settings".to_vec()),
                Some(b"client settings".to_vec())
            ],
            "new codepoint: {new_codepoint}"
        );
    }
}

#[test]
fn an_empty_value_still_negotiates_application_settings() {
    assert_eq!(
        exchange(true, b"", Some(b"")),
        [Some(Vec::new()), Some(Vec::new())]
    );
}

#[test]
fn application_settings_need_both_sides() {
    assert_eq!(exchange(true, b"client settings", None), [None, None]);
}
