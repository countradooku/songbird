//! End to end: client -> outer TLS (proxy cert) -> inner TLS (upstream cert) -> upstream echo.
//! Proves the proxy relays an opaque TLS session it cannot read, and refuses unknown SNI.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::as_conversions,
    reason = "integration test: failures should panic"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use songbird_proxy::config::{Limits, ProxyConfig, TlsConfig, Upstream};
use songbird_proxy::relay::{Relay, tls_acceptor};
use songbird_types::SecretRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn cert(name: &str) -> (CertificateDer<'static>, String, String) {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    (
        ck.cert.der().clone(),
        ck.cert.pem(),
        ck.signing_key.serialize_pem(),
    )
}

fn client(root: CertificateDer<'static>) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

/// TLS echo server standing in for a Songbird edge.
async fn upstream(name: &str) -> (SocketAddr, CertificateDer<'static>) {
    let (der, _, key_pem) = cert(name);
    let key = rustls::pki_types::pem::PemObject::from_pem_slice(key_pem.as_bytes()).unwrap();
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], PrivateKeyDer::Pkcs8(key))
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = tls.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    tls.write_all(&buf[..n]).await.unwrap();
                    tls.flush().await.unwrap();
                }
            });
        }
    });
    (addr, der)
}

async fn proxy(
    up: SocketAddr,
    limits: Limits,
) -> (SocketAddr, CertificateDer<'static>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let (der, cert_pem, key_pem) = cert("proxy.test");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: TlsConfig {
            cert: cert_path,
            key: SecretRef::File(key_path),
        },
        upstream: vec![Upstream {
            sni: "edge.songbird.test".into(),
            address: up.to_string(),
        }],
        limits,
    };
    let acceptor = tls_acceptor(&config.tls).unwrap();
    let listener = TcpListener::bind(config.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = Relay::new(config, acceptor);
    tokio::spawn(relay.serve(listener, std::future::pending(), Duration::from_secs(1)));
    (addr, der, dir)
}

#[tokio::test]
async fn relays_nested_tls_end_to_end() {
    let (up, up_root) = upstream("edge.songbird.test").await;
    let (px, px_root, _dir) = proxy(up, Limits::default()).await;

    let tcp = TcpStream::connect(px).await.unwrap();
    let outer = client(px_root)
        .connect(ServerName::try_from("proxy.test").unwrap(), tcp)
        .await
        .unwrap();
    let mut inner = client(up_root)
        .connect(ServerName::try_from("edge.songbird.test").unwrap(), outer)
        .await
        .unwrap();

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(&mut inner);
    let send = async {
        w.write_all(&payload).await.unwrap();
        w.flush().await.unwrap();
    };
    let mut got = vec![0u8; payload.len()];
    let recv = r.read_exact(&mut got);
    let ((), res) = tokio::join!(send, recv);
    res.unwrap();
    assert_eq!(got, payload);
}

#[tokio::test]
async fn refuses_unknown_sni() {
    let (up, _) = upstream("edge.songbird.test").await;
    let (px, px_root, _dir) = proxy(up, Limits::default()).await;
    let (other_root, _, _) = cert("elsewhere.test");

    let tcp = TcpStream::connect(px).await.unwrap();
    let outer = client(px_root)
        .connect(ServerName::try_from("proxy.test").unwrap(), tcp)
        .await
        .unwrap();
    let r = client(other_root)
        .connect(ServerName::try_from("elsewhere.test").unwrap(), outer)
        .await;
    assert!(r.is_err(), "an open relay would have connected");
}

#[tokio::test]
async fn closes_silent_clients_after_handshake_timeout() {
    let (up, _) = upstream("edge.songbird.test").await;
    let limits = Limits {
        handshake_timeout_secs: 1,
        ..Limits::default()
    };
    let (px, _, _dir) = proxy(up, limits).await;
    let mut tcp = TcpStream::connect(px).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
        .await
        .unwrap();
    assert!(matches!(n, Ok(0) | Err(_)), "connection should be closed");
}

#[tokio::test]
async fn non_tls_probes_get_nothing() {
    let (up, _) = upstream("edge.songbird.test").await;
    let (px, _, _dir) = proxy(up, Limits::default()).await;
    let mut tcp = TcpStream::connect(px).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf))
        .await
        .unwrap();
    // rustls answers garbage with at most a TLS alert; never HTTP or upstream data.
    assert!(
        !buf.starts_with(b"HTTP"),
        "proxy answered a non-TLS probe with HTTP ({} bytes)",
        buf.len()
    );
}
