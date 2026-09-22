use super::server::Server;
use crate::{
    ssl::{ExtensionType, SslVerifyMode},
    stack::Stack,
    x509::{X509Name, X509},
};
use std::sync::{Arc, Mutex};

#[test]
fn ca_names_are_copied_replaced_and_cleared_independently_of_client_ca_list() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let output = captured.clone();
    let mut server = Server::builder();
    server.expected_connections_count(3);
    server.ctx().set_select_certificate_callback(move |hello| {
        output.lock().unwrap().push(
            hello
                .get_extension(ExtensionType::CERTIFICATE_AUTHORITIES)
                .map(<[u8]>::to_vec),
        );
        Ok(())
    });
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_verify(SslVerifyMode::PEER);
    let client = client.build();
    let ca = X509::from_pem(include_bytes!("../../../test/root-ca.pem")).unwrap();
    let ca2 = X509::from_pem(include_bytes!("../../../test/root-ca-2.pem")).unwrap();
    let mut names = Stack::<X509Name>::new().unwrap();
    names
        .push(X509Name::from_der(&ca.subject_name().to_der().unwrap()).unwrap())
        .unwrap();
    names
        .push(X509Name::from_der(&ca2.subject_name().to_der().unwrap()).unwrap())
        .unwrap();
    let mut expected = Vec::new();
    for name in &names {
        let der = name.to_der().unwrap();
        expected.extend_from_slice(&(der.len() as u16).to_be_bytes());
        expected.extend_from_slice(&der);
    }
    let mut body = (expected.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&expected);
    let mut connection = client.builder();
    connection.ssl().set_ca_names(&names).unwrap();
    // Dropping the source and independently setting the mTLS CA list must not
    // change the ClientHello CA-name list.
    connection.ssl().set_client_ca_list(Stack::new().unwrap());
    drop(names);
    connection.connect();
    let mut cleared = client.builder();
    let mut names = Stack::new().unwrap();
    names
        .push(X509Name::from_der(&ca.subject_name().to_der().unwrap()).unwrap())
        .unwrap();
    cleared.ssl().set_ca_names(&names).unwrap();
    cleared.ssl().set_ca_names(&Stack::new().unwrap()).unwrap();
    cleared.connect();
    client.builder().connect();
    assert_eq!(*captured.lock().unwrap(), vec![Some(body), None, None]);
}
