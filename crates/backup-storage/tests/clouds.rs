//! Prompt 10, M3 (D-0122): Google Drive, OneDrive and Dropbox through emulators that follow
//! each provider's documented API: bearer tokens and refresh, pagination (small pages, so
//! paging is exercised), Dropbox's `add` and `update(rev)` conflicts, Graph's `If-Match`,
//! `conflictBehavior=fail`, upload sessions above 4 MiB and redirects to pre-authenticated
//! download URLs (which must not receive the token), and Drive's IDs, repeated names and
//! multipart uploads with no conditional write. Each adapter then runs the conformance suite.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::type_complexity,
    reason = "tests and their emulators"
)]

use std::collections::{BTreeMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use songbird_backup_format::{OsRng, RecoveryKey};
use songbird_backup_storage::conformance::{self, Plan};
use songbird_backup_storage::http::HyperHttp;
use songbird_backup_storage::oauth::{self, Refreshing, TokenSource, Tokens};
use songbird_backup_storage::{BackupStore, StoreError};
use zeroize::Zeroizing;

type Resp = Response<Full<Bytes>>;

fn reply(status: u16, body: impl Into<Bytes>) -> Resp {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = StatusCode::from_u16(status).unwrap();
    r
}

fn json_reply(status: u16, v: &Value) -> Resp {
    let mut r = reply(status, v.to_string());
    r.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    r
}

/// Tokens the emulators accept; the token endpoint swaps in a new one.
#[derive(Default)]
struct Auth {
    valid: Mutex<HashSet<String>>,
    refreshes: Mutex<u32>,
}

impl Auth {
    fn ok(&self, req: &Request<hyper::body::Incoming>) -> bool {
        let h = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        h.strip_prefix("Bearer ")
            .is_some_and(|t| self.valid.lock().unwrap().contains(t))
    }
    fn expire_all(&self) {
        self.valid.lock().unwrap().clear();
    }
    fn issue(&self) -> String {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let t = format!("tok-{}", hex::encode(r));
        self.valid.lock().unwrap().insert(t.clone());
        t
    }
}

async fn serve<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<hyper::body::Incoming>, SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let h = Arc::clone(&h);
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let h = Arc::clone(&h);
                    async move { Ok::<_, Infallible>(h(req, addr).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    addr
}

async fn body(req: Request<hyper::body::Incoming>) -> Vec<u8> {
    req.into_body().collect().await.unwrap().to_bytes().to_vec()
}

fn query(req: &Request<hyper::body::Incoming>) -> BTreeMap<String, String> {
    req.uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap(), 16).unwrap(),
            );
            i += 3;
        } else if b[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// A token endpoint (RFC 6749 refresh grant) issuing tokens `auth` accepts.
fn token_endpoint(auth: &Auth) -> Resp {
    *auth.refreshes.lock().unwrap() += 1;
    json_reply(
        200,
        &json!({"access_token": auth.issue(), "expires_in": 3600, "token_type": "Bearer"}),
    )
}

// ------------------------------------------------------------------------------------- Dropbox

#[derive(Default)]
struct Dropbox {
    auth: Auth,
    files: Mutex<BTreeMap<String, (Vec<u8>, u64)>>,
    rev: Mutex<u64>,
}

fn dbx_err(summary: &str) -> Resp {
    json_reply(409, &json!({"error_summary": summary, "error": {}}))
}

impl Dropbox {
    fn next_rev(&self) -> u64 {
        let mut r = self.rev.lock().unwrap();
        *r += 1;
        *r
    }

    async fn handle(self: Arc<Self>, req: Request<hyper::body::Incoming>) -> Resp {
        let path = req.uri().path().to_owned();
        if path == "/oauth2/token" {
            return token_endpoint(&self.auth);
        }
        if !self.auth.ok(&req) {
            return json_reply(401, &json!({"error_summary": "expired_access_token/"}));
        }
        let arg: Value = req
            .headers()
            .get("dropbox-api-arg")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or(Value::Null);
        match path.as_str() {
            "/2/files/upload" => {
                let p = arg["path"].as_str().unwrap().to_lowercase();
                let data = body(req).await;
                let rev = self.next_rev();
                let mut f = self.files.lock().unwrap();
                let exists = f.get(&p).map(|(_, r)| *r);
                match &arg["mode"] {
                    Value::String(m) if m == "add" && exists.is_some() => {
                        return dbx_err("path/conflict/file/..");
                    }
                    Value::Object(o) if o.get(".tag") == Some(&json!("update")) => {
                        if exists.map(|r| format!("{r:09x}"))
                            != o.get("update").and_then(Value::as_str).map(str::to_owned)
                        {
                            return dbx_err("path/conflict/file/..");
                        }
                    }
                    _ => {}
                }
                f.insert(p.clone(), (data, rev));
                json_reply(
                    200,
                    &json!({"name": p.rsplit('/').next(), "rev": format!("{rev:09x}")}),
                )
            }
            "/2/files/download" => {
                let p = arg["path"].as_str().unwrap().to_lowercase();
                match self.files.lock().unwrap().get(&p) {
                    Some((d, rev)) => {
                        let mut r = reply(200, d.clone());
                        r.headers_mut().insert(
                            "dropbox-api-result",
                            json!({"rev": format!("{rev:09x}")})
                                .to_string()
                                .parse()
                                .unwrap(),
                        );
                        r
                    }
                    None => dbx_err("path/not_found/.."),
                }
            }
            "/2/files/list_folder" | "/2/files/list_folder/continue" => {
                let b: Value = serde_json::from_slice(&body(req).await).unwrap();
                let (dir, offset) = match b.get("cursor").and_then(Value::as_str) {
                    Some(c) => {
                        let (d, o) = c.rsplit_once('|').unwrap();
                        (d.to_owned(), o.parse::<usize>().unwrap())
                    }
                    None => (b["path"].as_str().unwrap().to_lowercase(), 0),
                };
                let f = self.files.lock().unwrap();
                let prefix = format!("{dir}/");
                let names: Vec<String> = f
                    .keys()
                    .filter_map(|k| {
                        k.strip_prefix(&prefix)
                            .filter(|r| !r.contains('/'))
                            .map(str::to_owned)
                    })
                    .collect();
                if !dir.is_empty() && !f.keys().any(|k| k.starts_with(&prefix)) {
                    return dbx_err("path/not_found/..");
                }
                // Pages of 300, whatever the limit asked.
                let page: Vec<Value> = names
                    .iter()
                    .skip(offset)
                    .take(300)
                    .map(|n| json!({".tag": "file", "name": n}))
                    .collect();
                let more = offset + page.len() < names.len();
                json_reply(
                    200,
                    &json!({"entries": page, "cursor": format!("{dir}|{}", offset + 300), "has_more": more}),
                )
            }
            "/2/files/delete_v2" => {
                let b: Value = serde_json::from_slice(&body(req).await).unwrap();
                let p = b["path"].as_str().unwrap().to_lowercase();
                let mut f = self.files.lock().unwrap();
                let before = f.len();
                f.retain(|k, _| *k != p && !k.starts_with(&format!("{p}/")));
                if f.len() == before {
                    return dbx_err("path_lookup/not_found/..");
                }
                json_reply(200, &json!({"metadata": {}}))
            }
            _ => reply(404, ""),
        }
    }
}

// ------------------------------------------------------------------------------------ OneDrive

#[derive(Default)]
struct OneDrive {
    auth: Auth,
    files: Mutex<BTreeMap<String, (Vec<u8>, u64)>>,
    version: Mutex<u64>,
    sessions: Mutex<BTreeMap<String, (String, Option<String>, bool)>>,
    downloads: Mutex<BTreeMap<String, String>>,
}

const SIMPLE_LIMIT: usize = 4 << 20;

impl OneDrive {
    fn etag(path: &str, v: u64) -> String {
        format!("\"{{{path}}},{v}\"")
    }

    /// Writes with Graph's checks, atomically: `fail` refuses an existing item, `If-Match` a
    /// changed one.
    fn write(&self, path: &str, data: Vec<u8>, if_match: Option<&str>, fail: bool) -> Resp {
        let mut f = self.files.lock().unwrap();
        let cur = f.get(path).map(|(_, v)| Self::etag(path, *v));
        if fail && cur.is_some() {
            return json_reply(409, &json!({"error": {"code": "nameAlreadyExists"}}));
        }
        if let Some(m) = if_match
            && cur.as_deref() != Some(m)
        {
            return json_reply(412, &json!({"error": {"code": "preconditionFailed"}}));
        }
        let v = {
            let mut g = self.version.lock().unwrap();
            *g += 1;
            *g
        };
        f.insert(path.to_owned(), (data, v));
        json_reply(
            201,
            &json!({"name": path.rsplit('/').next(), "eTag": Self::etag(path, v)}),
        )
    }

    async fn handle(self: Arc<Self>, req: Request<hyper::body::Incoming>, me: SocketAddr) -> Resp {
        let raw = req.uri().path().to_owned();
        if raw == "/token" {
            return token_endpoint(&self.auth);
        }
        // Pre-authenticated URLs: never with a bearer token.
        if let Some(t) = raw.strip_prefix("/download/") {
            if req.headers().contains_key("authorization") {
                return reply(400, "a bearer token was sent to a pre-authenticated URL");
            }
            let Some(p) = self.downloads.lock().unwrap().get(t).cloned() else {
                return reply(404, "");
            };
            return match self.files.lock().unwrap().get(&p) {
                Some((d, _)) => reply(200, d.clone()),
                None => reply(404, ""),
            };
        }
        if let Some(id) = raw.strip_prefix("/upload/") {
            if req.headers().contains_key("authorization") {
                return reply(400, "a bearer token was sent to an upload URL");
            }
            let Some((path, if_match, fail)) = self.sessions.lock().unwrap().remove(id) else {
                return reply(404, "");
            };
            let data = body(req).await;
            return self.write(&path, data, if_match.as_deref(), fail);
        }
        if !self.auth.ok(&req) {
            return json_reply(
                401,
                &json!({"error": {"code": "InvalidAuthenticationToken"}}),
            );
        }
        let rest = raw
            .strip_prefix("/v1.0/me/drive/special/approot")
            .unwrap_or("");
        let (item, op) = match rest.strip_prefix(":/") {
            Some(r) => {
                let (p, after) = r.split_once(':').unwrap_or((r, ""));
                (decode(p), after.trim_start_matches('/').to_owned())
            }
            None => (String::new(), rest.trim_start_matches('/').to_owned()),
        };
        let q = query(&req);
        let method = req.method().clone();
        let if_match = req
            .headers()
            .get("if-match")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match (method.as_str(), op.as_str()) {
            ("GET", "") if item.is_empty() => {
                json_reply(200, &json!({"id": "approot", "folder": {}}))
            }
            ("GET", "") => {
                let f = self.files.lock().unwrap();
                if let Some((d, v)) = f.get(&item) {
                    json_reply(
                        200,
                        &json!({"name": item, "size": d.len(), "eTag": Self::etag(&item, *v)}),
                    )
                } else if f.keys().any(|k| k.starts_with(&format!("{item}/"))) {
                    json_reply(200, &json!({"name": item, "folder": {}}))
                } else {
                    json_reply(404, &json!({"error": {"code": "itemNotFound"}}))
                }
            }
            ("GET", "content") => {
                if !self.files.lock().unwrap().contains_key(&item) {
                    return json_reply(404, &json!({"error": {"code": "itemNotFound"}}));
                }
                let mut t = [0u8; 8];
                getrandom::fill(&mut t).unwrap();
                let t = hex::encode(t);
                self.downloads.lock().unwrap().insert(t.clone(), item);
                let mut r = reply(302, "");
                r.headers_mut().insert(
                    "location",
                    format!("http://{me}/download/{t}").parse().unwrap(),
                );
                r
            }
            ("PUT", "content") => {
                let data = body(req).await;
                if data.len() > SIMPLE_LIMIT {
                    return json_reply(413, &json!({"error": {"code": "requestTooLarge"}}));
                }
                let fail = q
                    .get("@microsoft.graph.conflictBehavior")
                    .map(String::as_str)
                    == Some("fail");
                self.write(&item, data, if_match.as_deref(), fail)
            }
            ("POST", "createUploadSession") => {
                let b: Value = serde_json::from_slice(&body(req).await).unwrap_or(Value::Null);
                let fail = b
                    .pointer("/item/@microsoft.graph.conflictBehavior")
                    .and_then(Value::as_str)
                    == Some("fail");
                let mut id = [0u8; 8];
                getrandom::fill(&mut id).unwrap();
                let id = hex::encode(id);
                self.sessions
                    .lock()
                    .unwrap()
                    .insert(id.clone(), (item, if_match, fail));
                json_reply(
                    200,
                    &json!({"uploadUrl": format!("http://{me}/upload/{id}")}),
                )
            }
            ("GET", "children") => {
                let f = self.files.lock().unwrap();
                let prefix = format!("{item}/");
                if !f.keys().any(|k| k.starts_with(&prefix)) {
                    return json_reply(404, &json!({"error": {"code": "itemNotFound"}}));
                }
                let names: Vec<&str> = f
                    .keys()
                    .filter_map(|k| k.strip_prefix(&prefix))
                    .filter(|r| !r.contains('/'))
                    .collect();
                let skip: usize = q
                    .get("$skiptoken")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                // Pages of 200, whatever `$top` asked.
                let page: Vec<Value> = names
                    .iter()
                    .skip(skip)
                    .take(200)
                    .map(|n| json!({"name": n}))
                    .collect();
                let mut v = json!({"value": page});
                if skip + 200 < names.len() {
                    v["@odata.nextLink"] = json!(format!(
                        "http://{me}/v1.0/me/drive/special/approot:/{item}:/children?$select=name&$top=1000&$skiptoken={}",
                        skip + 200
                    ));
                }
                json_reply(200, &v)
            }
            ("DELETE", "") => {
                let mut f = self.files.lock().unwrap();
                let before = f.len();
                f.retain(|k, _| {
                    *k != item && !k.starts_with(&format!("{item}/")) && !item.is_empty()
                });
                if f.len() == before {
                    return json_reply(404, &json!({"error": {"code": "itemNotFound"}}));
                }
                reply(204, "")
            }
            _ => reply(400, "unsupported"),
        }
    }
}

// -------------------------------------------------------------------------------- Google Drive

#[derive(Default)]
struct Drive {
    auth: Auth,
    /// id → (name, content)
    files: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
}

fn multipart_parts(content_type: &str, body: &[u8]) -> (Value, Vec<u8>) {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .unwrap()
        .trim_matches('"');
    let sep = format!("--{boundary}");
    let text = body;
    let mut parts = vec![];
    let mut at = 0;
    let find = |hay: &[u8], needle: &[u8], from: usize| {
        hay[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    };
    while let Some(s) = find(text, sep.as_bytes(), at) {
        let start = s + sep.len();
        if text[start..].starts_with(b"--") {
            break;
        }
        let head_end = find(text, b"\r\n\r\n", start).unwrap() + 4;
        let next = find(text, sep.as_bytes(), head_end).unwrap();
        parts.push(text[head_end..next - 2].to_vec());
        at = next;
    }
    (serde_json::from_slice(&parts[0]).unwrap(), parts[1].clone())
}

impl Drive {
    async fn handle(self: Arc<Self>, req: Request<hyper::body::Incoming>) -> Resp {
        let path = req.uri().path().to_owned();
        if path == "/token" {
            return token_endpoint(&self.auth);
        }
        if !self.auth.ok(&req) {
            return json_reply(
                401,
                &json!({"error": {"code": 401, "errors": [{"reason": "authError"}]}}),
            );
        }
        let q = query(&req);
        match (req.method().as_str(), path.as_str()) {
            ("GET", "/drive/v3/files") => {
                assert_eq!(q.get("spaces").map(String::as_str), Some("appDataFolder"));
                let filter = q.get("q").cloned().unwrap_or_default();
                let prefix = filter
                    .split("name contains '")
                    .nth(1)
                    .map(|r| r.split('\'').next().unwrap().to_owned())
                    .unwrap_or_default();
                let f = self.files.lock().unwrap();
                let all: Vec<(&String, &String)> = f
                    .iter()
                    .filter(|(_, (n, _))| n.starts_with(&prefix))
                    .map(|(id, (n, _))| (id, n))
                    .collect();
                let skip: usize = q.get("pageToken").and_then(|s| s.parse().ok()).unwrap_or(0);
                // At most 100 a page.
                let page: Vec<Value> = all
                    .iter()
                    .skip(skip)
                    .take(100)
                    .map(|(id, n)| json!({"id": id, "name": n}))
                    .collect();
                let mut v = json!({"files": page});
                if skip + 100 < all.len() {
                    v["nextPageToken"] = json!((skip + 100).to_string());
                }
                json_reply(200, &v)
            }
            ("POST", "/upload/drive/v3/files") => {
                assert_eq!(q.get("uploadType").map(String::as_str), Some("multipart"));
                let ct = req
                    .headers()
                    .get("content-type")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();
                let b = body(req).await;
                let (meta, content) = multipart_parts(&ct, &b);
                assert_eq!(meta["parents"], json!(["appDataFolder"]));
                let mut id = [0u8; 10];
                getrandom::fill(&mut id).unwrap();
                let id = hex::encode(id);
                self.files.lock().unwrap().insert(
                    id.clone(),
                    (meta["name"].as_str().unwrap().to_owned(), content),
                );
                json_reply(200, &json!({"id": id}))
            }
            ("GET", p) if p.starts_with("/drive/v3/files/") => {
                assert_eq!(q.get("alt").map(String::as_str), Some("media"));
                let id = p.trim_start_matches("/drive/v3/files/");
                match self.files.lock().unwrap().get(id) {
                    Some((_, d)) => reply(200, d.clone()),
                    None => json_reply(
                        404,
                        &json!({"error": {"code": 404, "errors": [{"reason": "notFound"}]}}),
                    ),
                }
            }
            ("DELETE", p) if p.starts_with("/drive/v3/files/") => {
                let id = p.trim_start_matches("/drive/v3/files/");
                match self.files.lock().unwrap().remove(id) {
                    Some(_) => reply(204, ""),
                    None => json_reply(
                        404,
                        &json!({"error": {"code": 404, "errors": [{"reason": "notFound"}]}}),
                    ),
                }
            }
            _ => reply(400, "unsupported"),
        }
    }
}

// ----------------------------------------------------------------------------------- the tests

fn keys() -> Arc<songbird_backup_format::BackupKeys> {
    Arc::new(RecoveryKey::generate(&mut OsRng).unwrap().derive().unwrap())
}

fn http() -> Arc<HyperHttp> {
    Arc::new(HyperHttp::new(&[]).unwrap())
}

/// Tokens that refresh through the emulator's token endpoint, starting from `first`.
fn refreshing(token_url: String, first: String) -> Arc<dyn TokenSource> {
    let client = oauth::Client {
        provider: oauth::Provider {
            authorize: "http://unused/".into(),
            token: token_url,
            scope: "x".into(),
            extra: vec![],
        },
        client_id: "test-client".into(),
        redirect_uri: "http://127.0.0.1:1/".into(),
    };
    Arc::new(Refreshing::new(
        client,
        http(),
        Tokens {
            access: Zeroizing::new(first),
            refresh: Some(Zeroizing::new("refresh-token".into())),
            expires_at: u64::MAX,
        },
        Box::new(|_| {}),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn dropbox_conforms() {
    let d = Arc::new(Dropbox::default());
    let first = d.auth.issue();
    let dd = Arc::clone(&d);
    let addr = serve(move |r, _| Arc::clone(&dd).handle(r)).await;
    let base = format!("http://{addr}");
    let tokens = refreshing(format!("{base}/oauth2/token"), first);
    let k = keys();
    let store = Arc::new(songbird_backup_storage::dropbox::DropboxStore::new(
        http(),
        tokens,
        songbird_backup_storage::dropbox::DropboxHosts {
            api: base.clone(),
            content: base,
        },
        &format!("/{}", &hex::encode(k.vault_id)[..16]),
    ));
    // An expired token mid-way is refreshed once and the call repeated.
    let s2: Arc<dyn BackupStore> = store.clone();
    s2.open().await.unwrap();
    d.auth.expire_all();
    let r = conformance::run(store, k, Plan::default()).await;
    assert!(r.is_ok(), "{r:?}");
    assert!(*d.auth.refreshes.lock().unwrap() >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn onedrive_conforms() {
    let o = Arc::new(OneDrive::default());
    let first = o.auth.issue();
    let oo = Arc::clone(&o);
    let addr = serve(move |r, me| Arc::clone(&oo).handle(r, me)).await;
    let tokens = refreshing(format!("http://{addr}/token"), first);
    let k = keys();
    let store = Arc::new(songbird_backup_storage::onedrive::OneDriveStore::new(
        http(),
        tokens,
        &format!("http://{addr}/v1.0"),
        &hex::encode(k.vault_id)[..16],
    ));
    o.auth.expire_all();
    let r = conformance::run(store, k, Plan::default()).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn google_drive_conforms() {
    let g = Arc::new(Drive::default());
    let first = g.auth.issue();
    let gg = Arc::clone(&g);
    let addr = serve(move |r, _| Arc::clone(&gg).handle(r)).await;
    let tokens = refreshing(format!("http://{addr}/token"), first);
    let k = keys();
    let store = Arc::new(songbird_backup_storage::gdrive::GoogleDriveStore::new(
        http(),
        tokens,
        &format!("http://{addr}"),
        &format!("{}.", &hex::encode(k.vault_id)[..16]),
    ));
    g.auth.expire_all();
    let r = conformance::run(store, k, Plan::default()).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_icloud_interface_conforms_with_the_reference_bridge() {
    let store = Arc::new(songbird_backup_storage::icloud::ICloudStore::new(Arc::new(
        songbird_backup_storage::icloud::MemoryBridge::default(),
    )));
    let r = conformance::run(store, keys(), Plan::default()).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_token_is_reported_not_retried_forever() {
    let d = Arc::new(Dropbox::default());
    let dd = Arc::clone(&d);
    let addr = serve(move |r, _| Arc::clone(&dd).handle(r)).await;
    let base = format!("http://{addr}");
    let store = songbird_backup_storage::dropbox::DropboxStore::new(
        http(),
        Arc::new(oauth::StaticToken(Zeroizing::new("not-a-token".into()))),
        songbird_backup_storage::dropbox::DropboxHosts {
            api: base.clone(),
            content: base,
        },
        "/x",
    );
    assert!(matches!(store.open().await, Err(StoreError::Unauthorized)));
}
