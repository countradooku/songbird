//! The CA's output completes a real mutual-TLS handshake with rustls (aws-lc-rs), the stack every
//! Songbird service uses, and a certificate from another CA is refused.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::as_conversions,
    reason = "integration test: failures should panic"
)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

fn admin(args: &[&str]) {
    let st = Command::new(env!("CARGO_BIN_EXE_songbird-admin"))
        .args(args)
        .status()
        .unwrap();
    assert!(st.success(), "songbird-admin {args:?} failed");
}

fn pki(dir: &Path) {
    let p = |s: &str| dir.join(s).to_str().unwrap().to_owned();
    admin(&["ca", "init-root", "--out", &p("root"), "--env", "test"]);
    admin(&[
        "ca",
        "init-intermediate",
        "--root",
        &p("root"),
        "--out",
        &p("ca"),
        "--env",
        "test",
    ]);
    for n in ["server.songbird.internal", "client.songbird.internal"] {
        admin(&[
            "ca",
            "issue",
            "--ca",
            &p("ca"),
            "--name",
            n,
            "--san",
            n,
            "--out",
            &p("leaf"),
        ]);
    }
}

fn certs(path: &Path) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(path)
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn roots(path: &Path) -> Arc<RootCertStore> {
    let mut r = RootCertStore::empty();
    for c in certs(path) {
        r.add(c).unwrap();
    }
    Arc::new(r)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn handshake(server_dir: &Path, client_dir: &Path) -> Result<(), rustls::Error> {
    let leaf = server_dir.join("leaf");
    let verifier =
        WebPkiClientVerifier::builder_with_provider(roots(&leaf.join("ca.crt")), provider())
            .build()
            .unwrap();
    let server_cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            certs(&leaf.join("server.songbird.internal.crt")),
            PrivateKeyDer::from_pem_file(leaf.join("server.songbird.internal.key")).unwrap(),
        )
        .unwrap();
    let cleaf = client_dir.join("leaf");
    let client_cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots(&cleaf.join("ca.crt")))
        .with_client_auth_cert(
            certs(&cleaf.join("client.songbird.internal.crt")),
            PrivateKeyDer::from_pem_file(cleaf.join("client.songbird.internal.key")).unwrap(),
        )
        .unwrap();

    let mut client = ClientConnection::new(
        Arc::new(client_cfg),
        ServerName::try_from("server.songbird.internal").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    for _ in 0..10 {
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut &buf[..]).unwrap();
        server.process_new_packets()?;
        let mut buf = Vec::new();
        server.write_tls(&mut buf).unwrap();
        client.read_tls(&mut &buf[..]).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            assert!(
                server.peer_certificates().is_some(),
                "client must present a certificate"
            );
            return Ok(());
        }
    }
    panic!("handshake did not finish");
}

#[test]
fn mutual_tls_with_issued_certificates() {
    let dir = tempfile::tempdir().unwrap();
    pki(dir.path());
    handshake(dir.path(), dir.path()).unwrap();
}

#[test]
fn certificates_from_another_ca_are_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    pki(a.path());
    pki(b.path());
    assert!(handshake(a.path(), b.path()).is_err());
}

#[test]
fn check_reports_renewal_window() {
    let dir = tempfile::tempdir().unwrap();
    pki(dir.path());
    let cert = dir.path().join("leaf/server.songbird.internal.crt");
    let out = Command::new(env!("CARGO_BIN_EXE_songbird-admin"))
        .args([
            "ca",
            "check",
            "--cert",
            cert.to_str().unwrap(),
            "--renew-within",
            "10",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let st = Command::new(env!("CARGO_BIN_EXE_songbird-admin"))
        .args([
            "ca",
            "check",
            "--cert",
            cert.to_str().unwrap(),
            "--renew-within",
            "40",
        ])
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(1), "inside the renewal window");
}
