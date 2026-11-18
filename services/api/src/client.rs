//! A minimal signed `api` client over HTTP/1.1 (tests, the load generator, tools). Plain TCP:
//! for loopback test servers; real clients speak TLS.

use std::net::SocketAddr;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use songbird_proto::registration::{self, RegisterRequest};
use songbird_types::DeviceId;

use crate::auth;

/// One device talking to `api`.
#[derive(Debug)]
pub struct ApiClient {
    addr: SocketAddr,
    server_name: String,
    device: DeviceId,
    key: Ed25519KeyPair,
}

/// A response: status and body.
pub type Reply = (u16, Bytes);

impl ApiClient {
    /// A client for `device`, signing with its authentication key.
    #[must_use]
    pub fn new(addr: SocketAddr, server_name: &str, device: DeviceId, key: Ed25519KeyPair) -> Self {
        Self {
            addr,
            server_name: server_name.to_owned(),
            device,
            key,
        }
    }

    /// Sends a request with a signed body (`None`: no body).
    ///
    /// # Errors
    /// Connection or protocol failure.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<Reply, hyper::Error> {
        let (authz, hash) = auth::sign(
            &self.key,
            &self.device,
            &self.server_name,
            method,
            path,
            body,
        );
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header("host", &self.server_name)
            .header(auth::AUTHORIZATION, authz);
        if let Some(h) = hash {
            b = b.header(auth::CONTENT_SHA256, h);
        }
        let body = Bytes::copy_from_slice(body.unwrap_or_default());
        self.exchange(b, body).await
    }

    /// `PUT /v1/messages` with a `Send` frame (signed): the HTTP status and, on a 200, the
    /// `SendResult` it carries (request ID and status).
    ///
    /// # Errors
    /// Connection or protocol failure.
    pub async fn put_message(
        &self,
        frame: &songbird_proto::frame::SendFrame,
    ) -> Result<(u16, Option<(u32, songbird_proto::frame::SendStatus)>), hyper::Error> {
        let body = songbird_proto::ClientFrame::Send(frame.clone()).to_bytes();
        let (status, reply) = self.send("PUT", "/v1/messages", Some(&body)).await?;
        let result =
            match songbird_proto::ServerFrame::decode(&reply, &songbird_proto::Limits::DEFAULT) {
                Ok(songbird_proto::ServerFrame::SendResult { req_id, status }) => {
                    Some((req_id, status))
                }
                _ => None,
            };
        Ok((status, result))
    }

    /// Uploads an attachment body (unsigned content, exact length).
    ///
    /// # Errors
    /// Connection or protocol failure.
    pub async fn upload(&self, path: &str, body: Bytes) -> Result<Reply, hyper::Error> {
        let (authz, _) = auth::sign(
            &self.key,
            &self.device,
            &self.server_name,
            "PUT",
            path,
            None,
        );
        let b = Request::builder()
            .method("PUT")
            .uri(path)
            .header("host", &self.server_name)
            .header(auth::AUTHORIZATION, authz);
        self.exchange(b, body).await
    }

    /// A request whose body is not signed (uploads, parts, tus), with extra headers; returns the
    /// status, the response headers and the body. A `GET` or `HEAD` sends no body.
    ///
    /// # Errors
    /// Connection or protocol failure.
    pub async fn upload_with(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Bytes,
    ) -> Result<(u16, hyper::HeaderMap, Bytes), hyper::Error> {
        let (authz, _) = auth::sign(
            &self.key,
            &self.device,
            &self.server_name,
            method,
            path,
            None,
        );
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header("host", &self.server_name)
            .header(auth::AUTHORIZATION, authz);
        for (n, v) in headers {
            b = b.header(*n, v.as_str());
        }
        exchange_full(self.addr, b, body).await
    }

    /// Sends a prepared request as it is (tests replay or tamper with headers).
    ///
    /// # Errors
    /// Connection or protocol failure.
    pub async fn raw(
        &self,
        req: hyper::http::request::Builder,
        body: Bytes,
    ) -> Result<Reply, hyper::Error> {
        self.exchange(req, body).await
    }

    /// Signs a request without sending it (tests).
    #[must_use]
    pub fn sign(&self, method: &str, path: &str, body: Option<&[u8]>) -> (String, Option<String>) {
        auth::sign(
            &self.key,
            &self.device,
            &self.server_name,
            method,
            path,
            body,
        )
    }

    async fn exchange(
        &self,
        b: hyper::http::request::Builder,
        body: Bytes,
    ) -> Result<Reply, hyper::Error> {
        exchange(self.addr, b, body).await
    }
}

/// An unsigned request (opening and reading a provisioning channel, linking a device), with a
/// `Content-Length` header when there is a body.
///
/// # Errors
/// Connection or protocol failure.
pub async fn unsigned(
    addr: SocketAddr,
    server_name: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<Reply, hyper::Error> {
    let body = body.map(Bytes::copy_from_slice).unwrap_or_default();
    let b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", server_name)
        .header("content-length", body.len());
    exchange(addr, b, body).await
}

/// As [`exchange`], with the response headers.
async fn exchange_full(
    addr: SocketAddr,
    b: hyper::http::request::Builder,
    body: Bytes,
) -> Result<(u16, hyper::HeaderMap, Bytes), hyper::Error> {
    let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
        return Ok((0, hyper::HeaderMap::new(), Bytes::new()));
    };
    let _ = tcp.set_nodelay(true);
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    let Ok(req) = b.body(Full::new(body)) else {
        return Ok((0, hyper::HeaderMap::new(), Bytes::new()));
    };
    let resp = send.send_request(req).await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, headers, bytes))
}

async fn exchange(
    addr: SocketAddr,
    b: hyper::http::request::Builder,
    body: Bytes,
) -> Result<Reply, hyper::Error> {
    // Status 0: could not connect.
    let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
        return Ok((0, Bytes::new()));
    };
    let _ = tcp.set_nodelay(true);
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    let Ok(req) = b.body(Full::new(body)) else {
        return Ok((0, Bytes::new()));
    };
    let resp = send.send_request(req).await?;
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, bytes))
}

/// Registration for a client that has no device yet (`POST /v1/registration`, PROTOCOL.md §4.1).
#[derive(Debug, Clone)]
pub struct Registrar {
    addr: SocketAddr,
    server_name: String,
}

/// A registration's result.
#[derive(Debug)]
pub enum Registered {
    /// The new account and its first device.
    Ok {
        /// Account ID.
        account: songbird_types::AccountId,
        /// Device ID.
        device: DeviceId,
    },
    /// Refused or failed: the HTTP status and body.
    Refused(Reply),
}

impl Registrar {
    /// A registrar for the server at `addr` with this name.
    #[must_use]
    pub fn new(addr: SocketAddr, server_name: &str) -> Self {
        Self {
            addr,
            server_name: server_name.to_owned(),
        }
    }

    fn post(&self, path: &str, len: usize) -> hyper::http::request::Builder {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("host", &self.server_name)
            .header("content-length", len)
    }

    /// `POST /v1/registration/challenge`.
    ///
    /// # Errors
    /// Connection or protocol failure.
    pub async fn challenge(&self) -> Result<Reply, hyper::Error> {
        exchange(
            self.addr,
            self.post("/v1/registration/challenge", 0),
            Bytes::new(),
        )
        .await
    }

    /// Builds and signs a request (tests tamper with it before sending).
    #[must_use]
    pub fn request(
        &self,
        challenge: &[u8; registration::CHALLENGE_LEN],
        solutions: Vec<u32>,
        invite: Option<[u8; registration::INVITE_LEN]>,
        identity: &Ed25519KeyPair,
        auth: &Ed25519KeyPair,
    ) -> RegisterRequest {
        let key = |k: &Ed25519KeyPair| {
            let mut out = [0u8; 32];
            out.copy_from_slice(k.public_key().as_ref());
            out
        };
        let (identity_key, auth_key) = (key(identity), key(auth));
        let sign = |context: &[u8], k: &Ed25519KeyPair| {
            let t = registration::transcript(
                context,
                &self.server_name,
                challenge,
                &identity_key,
                &auth_key,
            )
            .unwrap_or_default();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(k.sign(&t).as_ref());
            sig
        };
        RegisterRequest {
            challenge: *challenge,
            solutions,
            invite,
            identity_key,
            auth_key,
            identity_sig: sign(registration::IDENTITY_CONTEXT, identity),
            auth_sig: sign(registration::DEVICE_CONTEXT, auth),
        }
    }

    /// `POST /v1/registration` with an encoded body.
    ///
    /// # Errors
    /// Connection or protocol failure.
    pub async fn submit(&self, body: Vec<u8>) -> Result<Reply, hyper::Error> {
        exchange(
            self.addr,
            self.post("/v1/registration", body.len()),
            Bytes::from(body),
        )
        .await
    }

    /// The whole flow: a challenge, its solutions (on a blocking thread), the signed request.
    ///
    /// # Errors
    /// Connection or protocol failure.
    pub async fn register(
        &self,
        identity: &Ed25519KeyPair,
        auth: &Ed25519KeyPair,
        invite: Option<[u8; registration::INVITE_LEN]>,
    ) -> Result<Registered, hyper::Error> {
        let (status, body) = self.challenge().await?;
        if status != 200 {
            return Ok(Registered::Refused((status, body)));
        }
        let Ok(challenge) = songbird_pow::decode(&body) else {
            return Ok(Registered::Refused((status, body)));
        };
        let solved = tokio::task::spawn_blocking(move || songbird_pow::solve(&challenge))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        let Some(solutions) = solved else {
            return Ok(Registered::Refused((0, Bytes::new())));
        };
        let req = self.request(&challenge.bytes, solutions, invite, identity, auth);
        let (status, body) = self.submit(req.encode()).await?;
        if status != 201 {
            return Ok(Registered::Refused((status, body)));
        }
        let ids = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                let id = |name: &str| {
                    v.get(name)
                        .and_then(serde_json::Value::as_str)
                        .and_then(|h| hex::decode(h).ok())
                };
                Some((
                    songbird_types::AccountId::from_slice(&id("account")?).ok()?,
                    DeviceId::from_slice(&id("device")?).ok()?,
                ))
            });
        Ok(match ids {
            Some((account, device)) => Registered::Ok { account, device },
            None => Registered::Refused((status, body)),
        })
    }
}

/// An unsigned request with extra headers, returning the status, the response headers and the
/// body (downloads by capability and signed media URLs, Prompt 6).
///
/// # Errors
/// Connection or protocol failure.
pub async fn unsigned_full(
    addr: SocketAddr,
    server_name: &str,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
) -> Result<(u16, hyper::HeaderMap, Bytes), hyper::Error> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", server_name);
    for (n, v) in headers {
        b = b.header(*n, v.as_str());
    }
    exchange_full(addr, b, Bytes::new()).await
}

/// An unsigned request with a body and extra headers (sealed sends and sealed presence, which
/// carry no device signature): the status and the body.
///
/// # Errors
/// Connection or protocol failure.
pub async fn unsigned_body(
    addr: SocketAddr,
    server_name: &str,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Bytes,
) -> Result<Reply, hyper::Error> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", server_name);
    for (n, v) in headers {
        b = b.header(*n, v.as_str());
    }
    let (status, _, body) = exchange_full(addr, b, body).await?;
    Ok((status, body))
}

/// As [`unsigned_full`], from a chosen local address (tests: two recipients on 127.0.0.1 and
/// 127.0.0.2 are two sources).
///
/// # Errors
/// Connection or protocol failure.
pub async fn unsigned_from(
    addr: SocketAddr,
    local: std::net::IpAddr,
    server_name: &str,
    method: &str,
    path: &str,
) -> Result<(u16, hyper::HeaderMap, Bytes), hyper::Error> {
    let socket = match local {
        std::net::IpAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
        std::net::IpAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
    };
    let Ok(socket) = socket else {
        return Ok((0, hyper::HeaderMap::new(), Bytes::new()));
    };
    if socket.bind(SocketAddr::new(local, 0)).is_err() {
        return Ok((0, hyper::HeaderMap::new(), Bytes::new()));
    }
    let Ok(tcp) = socket.connect(addr).await else {
        return Ok((0, hyper::HeaderMap::new(), Bytes::new()));
    };
    let _ = tcp.set_nodelay(true);
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    let Ok(req) = Request::builder()
        .method(method)
        .uri(path)
        .header("host", server_name)
        .body(Full::new(Bytes::new()))
    else {
        return Ok((0, hyper::HeaderMap::new(), Bytes::new()));
    };
    let resp = send.send_request(req).await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, headers, bytes))
}
