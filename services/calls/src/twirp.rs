//! LiveKit's room service over Twirp (D-0085 §5): `POST <api_url>/twirp/livekit.RoomService/<Method>`
//! with a protobuf body (`livekit-protocol`'s messages) and a short bearer token, as LiveKit's
//! own SDK sends it. Built on hyper and rustls with aws-lc-rs, so `livekit-api`'s `reqwest` and
//! `ring` stay out of the tree.
//!
//! One HTTP/1.1 connection per request: rooms are created once per call, not per frame.

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use livekit_protocol as proto;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::Deserialize;

use crate::config::TwirpTls;
use crate::ids::RoomId;
use crate::token::Minter;

/// Largest answer read (a participant list of a 1,000-person room is far below it).
const MAX_ANSWER: usize = 4 << 20;

/// Why a room-service call failed. Carries no room name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TwirpError {
    /// Connecting, TLS, a timeout, or an answer we could not read.
    #[error("livekit unavailable")]
    Unavailable,
    /// LiveKit says the room or participant does not exist.
    #[error("not found")]
    NotFound,
    /// Another Twirp error code.
    #[error("livekit error {0}")]
    Code(String),
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
}

/// A room-service client.
pub struct RoomClient {
    authority: String,
    prefix: String,
    host: String,
    port: u16,
    tls: Option<(tokio_rustls::TlsConnector, ServerName<'static>)>,
    minter: Arc<Minter>,
    timeout: Duration,
}

impl std::fmt::Debug for RoomClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomClient")
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Builds the mutual-TLS client for the tunnel in front of LiveKit's API.
///
/// # Errors
/// What could not be read (no secret material in it).
pub fn tls_connector(t: &TwirpTls) -> Result<tokio_rustls::TlsConnector, String> {
    let read = |p: &std::path::Path| std::fs::File::open(p).map(BufReader::new);
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_reader_iter(read(&t.ca).map_err(|_| "calls tls ca")?) {
        roots
            .add(c.map_err(|_| "calls tls ca")?)
            .map_err(|_| "calls tls ca")?;
    }
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(read(&t.cert_chain).map_err(|_| "calls tls chain")?)
            .collect::<Result<_, _>>()
            .map_err(|_| "calls tls chain")?;
    let secret = t.key.resolve().map_err(|_| "calls tls key")?;
    let key =
        PrivateKeyDer::from_pem_slice(secret.expose().as_bytes()).map_err(|_| "calls tls key")?;
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "calls tls protocol")?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|_| "calls tls client certificate")?;
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

impl RoomClient {
    /// A client for `api_url` (`http://host:port[/prefix]` or `https://…` with `tls`).
    ///
    /// # Errors
    /// A malformed URL, or `https` without TLS settings.
    pub fn new(
        api_url: &str,
        tls: Option<(tokio_rustls::TlsConnector, String)>,
        minter: Arc<Minter>,
        timeout: Duration,
    ) -> Result<Self, &'static str> {
        let uri: Uri = api_url.parse().map_err(|_| "calls.api_url")?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err("calls.api_url"),
        };
        let host = uri.host().ok_or("calls.api_url")?.to_owned();
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let tls = match (https, tls) {
            (true, Some((c, name))) => Some((
                c,
                ServerName::try_from(name).map_err(|_| "calls.tls.server_name")?,
            )),
            (true, None) => return Err("calls.tls"),
            (false, _) => None,
        };
        Ok(Self {
            authority: uri.authority().ok_or("calls.api_url")?.as_str().to_owned(),
            prefix: uri.path().trim_end_matches('/').to_owned(),
            host,
            port,
            tls,
            minter,
            timeout,
        })
    }

    async fn call<Q: prost::Message, A: prost::Message + Default>(
        &self,
        method: &str,
        room: Option<&RoomId>,
        req: &Q,
    ) -> Result<A, TwirpError> {
        let token = self
            .minter
            .admin(room)
            .map_err(|_| TwirpError::Unavailable)?;
        let path = format!("{}/twirp/livekit.RoomService/{method}", self.prefix);
        let request = Request::post(path)
            .header(hyper::header::HOST, &self.authority)
            .header(hyper::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(hyper::header::CONTENT_TYPE, "application/protobuf")
            .header(hyper::header::USER_AGENT, "songbird")
            .body(Full::new(Bytes::from(req.encode_to_vec())))
            .map_err(|_| TwirpError::Unavailable)?;
        let fut = async {
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|_| TwirpError::Unavailable)?;
            let _ = tcp.set_nodelay(true);
            let resp = if let Some((connector, name)) = &self.tls {
                let stream = connector
                    .connect(name.clone(), tcp)
                    .await
                    .map_err(|_| TwirpError::Unavailable)?;
                let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|_| TwirpError::Unavailable)?;
                tokio::spawn(conn);
                send.send_request(request)
                    .await
                    .map_err(|_| TwirpError::Unavailable)?
            } else {
                let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                    .await
                    .map_err(|_| TwirpError::Unavailable)?;
                tokio::spawn(conn);
                send.send_request(request)
                    .await
                    .map_err(|_| TwirpError::Unavailable)?
            };
            let status = resp.status();
            let body = Limited::new(resp.into_body(), MAX_ANSWER)
                .collect()
                .await
                .map_err(|_| TwirpError::Unavailable)?
                .to_bytes();
            if status == StatusCode::OK {
                return A::decode(body).map_err(|_| TwirpError::Unavailable);
            }
            let code = serde_json::from_slice::<ErrorBody>(&body)
                .map(|e| e.code)
                .unwrap_or_default();
            Err(match code.as_str() {
                "not_found" => TwirpError::NotFound,
                "" => TwirpError::Unavailable,
                _ => TwirpError::Code(code),
            })
        };
        tokio::time::timeout(self.timeout, fut)
            .await
            .unwrap_or(Err(TwirpError::Unavailable))
    }

    /// Creates `room` (idempotent: an existing room is returned as it is).
    ///
    /// # Errors
    /// [`TwirpError`].
    pub async fn create_room(
        &self,
        room: &RoomId,
        empty_timeout: u32,
        departure_timeout: u32,
        max_participants: u32,
    ) -> Result<(), TwirpError> {
        let req = proto::CreateRoomRequest {
            name: room.name(),
            empty_timeout,
            departure_timeout,
            max_participants,
            ..proto::CreateRoomRequest::default()
        };
        self.call::<_, proto::Room>("CreateRoom", None, &req)
            .await
            .map(|_| ())
    }

    /// Ends `room` for everyone in it.
    ///
    /// # Errors
    /// [`TwirpError`].
    pub async fn delete_room(&self, room: &RoomId) -> Result<(), TwirpError> {
        let req = proto::DeleteRoomRequest { room: room.name() };
        self.call::<_, proto::DeleteRoomResponse>("DeleteRoom", None, &req)
            .await
            .map(|_| ())
    }

    /// Whether LiveKit has `room` (`ListRooms` by name: `ListParticipants` answers an empty list
    /// for a room that does not exist).
    ///
    /// # Errors
    /// [`TwirpError`].
    pub async fn exists(&self, room: &RoomId) -> Result<bool, TwirpError> {
        let req = proto::ListRoomsRequest {
            names: vec![room.name()],
        };
        let a: proto::ListRoomsResponse = self.call("ListRooms", None, &req).await?;
        Ok(a.rooms.iter().any(|r| r.name == room.name()))
    }

    /// The identities in `room`.
    ///
    /// # Errors
    /// [`TwirpError`] ([`TwirpError::NotFound`] for no such room).
    pub async fn participants(&self, room: &RoomId) -> Result<Vec<String>, TwirpError> {
        let req = proto::ListParticipantsRequest { room: room.name() };
        let a: proto::ListParticipantsResponse =
            self.call("ListParticipants", Some(room), &req).await?;
        Ok(a.participants.into_iter().map(|p| p.identity).collect())
    }

    /// Disconnects `identity` from `room`; gone already is success.
    ///
    /// # Errors
    /// [`TwirpError`].
    pub async fn remove(&self, room: &RoomId, identity: &str) -> Result<(), TwirpError> {
        let req = proto::RoomParticipantIdentity {
            room: room.name(),
            identity: identity.to_owned(),
            ..proto::RoomParticipantIdentity::default()
        };
        match self
            .call::<_, proto::RemoveParticipantResponse>("RemoveParticipant", Some(room), &req)
            .await
        {
            Ok(_) | Err(TwirpError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
