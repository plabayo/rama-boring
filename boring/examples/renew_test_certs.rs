use std::error::Error;
use std::fs;
use std::path::Path;

use rama_boring::asn1::{Asn1Time, Asn1TimeRef};
use rama_boring::bn::BigNum;
use rama_boring::error::ErrorStack;
use rama_boring::hash::MessageDigest;
use rama_boring::pkcs12::Pkcs12;
use rama_boring::pkey::{PKey, PKeyRef, Private};
use rama_boring::stack::Stack;
use rama_boring::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use rama_boring::x509::{X509Builder, X509Name, X509NameRef, X509Ref, X509};

const VALID_DAYS: u32 = 20 * 365;

fn name(entries: &[(&str, &str)]) -> Result<X509Name, ErrorStack> {
    let mut builder = X509Name::builder()?;
    for (field, value) in entries {
        builder.append_entry_by_text(field, value)?;
    }
    Ok(builder.build())
}

fn certificate_builder(
    subject: &X509NameRef,
    issuer: &X509NameRef,
    key: &PKeyRef<Private>,
    serial: &str,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
    version: i32,
) -> Result<X509Builder, ErrorStack> {
    let mut builder = X509::builder()?;
    builder.set_version(version)?;
    let serial = BigNum::from_hex_str(serial)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(subject)?;
    builder.set_issuer_name(issuer)?;
    builder.set_pubkey(key)?;
    builder.set_not_before(not_before)?;
    builder.set_not_after(not_after)?;
    Ok(builder)
}

#[allow(clippy::too_many_arguments)]
fn ca_certificate(
    subject: &X509NameRef,
    issuer: &X509NameRef,
    issuer_cert: Option<&X509Ref>,
    key: &PKeyRef<Private>,
    issuer_key: &PKeyRef<Private>,
    serial: &str,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
) -> Result<X509, ErrorStack> {
    let mut builder = certificate_builder(subject, issuer, key, serial, not_before, not_after, 2)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?.as_ref())?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?
            .as_ref(),
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(issuer_cert, None))?;
    builder.append_extension(&subject_key_identifier)?;

    if issuer_cert.is_some() {
        let authority_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(issuer_cert, None))?;
        builder.append_extension(&authority_key_identifier)?;
    }

    builder.sign(issuer_key, MessageDigest::sha256())?;
    Ok(builder.build())
}

#[allow(clippy::too_many_arguments)]
fn leaf_certificate(
    subject: &X509NameRef,
    issuer: &X509Ref,
    key: &PKeyRef<Private>,
    issuer_key: &PKeyRef<Private>,
    serial: &str,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
) -> Result<X509, ErrorStack> {
    let mut builder = certificate_builder(
        subject,
        issuer.subject_name(),
        key,
        serial,
        not_before,
        not_after,
        0,
    )?;
    builder.sign(issuer_key, MessageDigest::sha256())?;
    Ok(builder.build())
}

fn write_certificate(path: &Path, certificate: &X509Ref) -> Result<(), Box<dyn Error>> {
    fs::write(path, certificate.to_pem()?)?;
    Ok(())
}

fn private_key(path: &Path) -> Result<PKey<Private>, Box<dyn Error>> {
    Ok(PKey::private_key_from_pem(&fs::read(path)?)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let boring = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = boring.join("test");
    let tokio_fixtures = boring.join("../tokio-boring/tests");
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(VALID_DAYS)?;

    let root_key = private_key(&fixtures.join("root-ca.key"))?;
    let leaf_key = private_key(&fixtures.join("key.pem"))?;
    let intermediate_key = private_key(&fixtures.join("intermediate-ca.key"))?;
    let root2_key = private_key(&fixtures.join("root-ca-2.key"))?;
    let root2 = X509::from_pem(&fs::read(fixtures.join("root-ca-2.pem"))?)?;

    let root_name = name(&[
        ("C", "AU"),
        ("ST", "Some-State"),
        ("O", "Internet Widgits Pty Ltd"),
    ])?;
    let root = ca_certificate(
        &root_name,
        &root_name,
        None,
        &root_key,
        &root_key,
        "E22F0E255BD7C795",
        &not_before,
        &not_after,
    )?;

    let leaf_name = name(&[
        ("C", "AU"),
        ("ST", "Some-State"),
        ("O", "Internet Widgits Pty Ltd"),
        ("CN", "foobar.com"),
    ])?;
    let leaf = leaf_certificate(
        &leaf_name,
        &root,
        &leaf_key,
        &root_key,
        "8771F7BDEE982FA5",
        &not_before,
        &not_after,
    )?;

    let wildcard_name = name(&[
        ("C", "AU"),
        ("ST", "Some-State"),
        ("L", "Internet Widgits Pty Ltd"),
        ("CN", "*.foobar.com"),
    ])?;
    let wildcard = leaf_certificate(
        &wildcard_name,
        &root,
        &leaf_key,
        &root_key,
        "6C30BA29573878C18D0E7CE050FD76BA7D521FCB",
        &not_before,
        &not_after,
    )?;

    let intermediate_name = name(&[
        ("C", "AU"),
        ("ST", "Some-State"),
        ("O", "Internet Widgits Pty Ltd Intermediate"),
    ])?;
    let intermediate = ca_certificate(
        &intermediate_name,
        root.subject_name(),
        Some(&root),
        &intermediate_key,
        &root_key,
        "13EA5C1075397B8C24329A76AA8C87CBEC07F1A3",
        &not_before,
        &not_after,
    )?;
    let intermediate_leaf = leaf_certificate(
        &leaf_name,
        &intermediate,
        &leaf_key,
        &intermediate_key,
        "1122371A6E92768EECFC35622F3C516E1A886A34",
        &not_before,
        &not_after,
    )?;

    let cross_signed_root = ca_certificate(
        &root_name,
        root2.subject_name(),
        Some(&root2),
        &root_key,
        &root2_key,
        "49820D49075BAFCCB3575F3AB3FCD08FEDB3A25F",
        &not_before,
        &not_after,
    )?;

    let alt_name = name(&[
        ("C", "US"),
        ("ST", "NY"),
        ("L", "New York"),
        ("O", "Example, LLC"),
        ("CN", "Example Company"),
        ("emailAddress", "test@example.com"),
    ])?;
    let mut alt_name_builder = certificate_builder(
        &alt_name,
        root.subject_name(),
        &leaf_key,
        "01",
        &not_before,
        &not_after,
        2,
    )?;
    alt_name_builder.append_extension(BasicConstraints::new().build()?.as_ref())?;
    alt_name_builder.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()?
            .as_ref(),
    )?;
    let subject_alt_name = SubjectAlternativeName::new()
        .dns("example.com")
        .ip("127.0.0.1")
        .ip("::1")
        .email("test@example.com")
        .uri("http://www.example.com")
        .build(&alt_name_builder.x509v3_context(Some(&root), None))?;
    alt_name_builder.append_extension(&subject_alt_name)?;
    alt_name_builder.sign(&root_key, MessageDigest::sha256())?;
    let alt_name_certificate = alt_name_builder.build();

    let tokio_key = private_key(&tokio_fixtures.join("key.pem"))?;
    let tokio_name = name(&[
        ("C", "AU"),
        ("ST", "Some-State"),
        ("O", "Internet Widgits Pty Ltd"),
        ("CN", "localhost"),
    ])?;
    let mut tokio_certificate_builder = certificate_builder(
        &tokio_name,
        &tokio_name,
        &tokio_key,
        "B0A5252F9CABECA4",
        &not_before,
        &not_after,
        2,
    )?;
    tokio_certificate_builder.append_extension(BasicConstraints::new().ca().build()?.as_ref())?;
    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&tokio_certificate_builder.x509v3_context(None, None))?;
    tokio_certificate_builder.append_extension(&subject_key_identifier)?;
    tokio_certificate_builder.sign(&tokio_key, MessageDigest::sha256())?;
    let tokio_certificate = tokio_certificate_builder.build();

    write_certificate(&fixtures.join("root-ca.pem"), &root)?;
    write_certificate(&fixtures.join("cert.pem"), &leaf)?;
    write_certificate(&fixtures.join("cert-wildcard.pem"), &wildcard)?;
    write_certificate(&fixtures.join("intermediate-ca.pem"), &intermediate)?;
    write_certificate(
        &fixtures.join("cert-with-intermediate.pem"),
        &intermediate_leaf,
    )?;
    write_certificate(&fixtures.join("root-ca-cross.pem"), &cross_signed_root)?;
    write_certificate(&fixtures.join("alt_name_cert.pem"), &alt_name_certificate)?;
    write_certificate(&tokio_fixtures.join("cert.pem"), &tokio_certificate)?;

    let mut identity_chain = Stack::new()?;
    identity_chain.push(root.clone())?;
    let mut identity_builder = Pkcs12::builder();
    identity_builder.ca(identity_chain);
    let identity = identity_builder.build("mypass", "foobar.com", &leaf_key, &leaf)?;
    fs::write(fixtures.join("identity.p12"), identity.to_der()?)?;

    let mut chain = leaf.to_pem()?;
    chain.extend(root.to_pem()?);
    fs::write(fixtures.join("certs.pem"), chain)?;

    Ok(())
}
