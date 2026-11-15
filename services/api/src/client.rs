//! A minimal signed `api` client over HTTP/1.1 (tests, the load generator, tools). Plain TCP:
//! for loopback test servers; real clients speak TLS.

use std::net::SocketAddr;

use aws_lc_rs::signature::Ed25519KeyPair;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
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
        // Status 0: could not connect.
        let Ok(tcp) = tokio::net::TcpStream::connect(self.addr).await else {
            return Ok((0, Bytes::new()));
        };
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
}
