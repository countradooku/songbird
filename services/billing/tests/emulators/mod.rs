//! Emulators of the App Store Server API, Google's OAuth, Play Developer API and signing keys,
//! and Mollie's API, written from the providers' documentation, in one small hyper server; and
//! a test Apple PKI (root, intermediate and leaf with Apple's marker extensions).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code,
    reason = "test support"
)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
    RSA_PKCS1_SHA256, RsaKeyPair, UnparsedPublicKey,
};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use songbird_billing::jose::{b64_encode, b64url_decode, b64url_encode};

// ----- a test Apple PKI -----

/// Root, intermediate and leaf certificates (DER) and the leaf's signing key.
pub(crate) struct ApplePki {
    pub(crate) root: Vec<u8>,
    pub(crate) intermediate: Vec<u8>,
    pub(crate) leaf: Vec<u8>,
    pub(crate) leaf_key: EcdsaKeyPair,
}

fn ca_params(cn: &str, ext: Option<&[u64]>) -> rcgen::CertificateParams {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    if let Some(oid) = ext {
        p.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            oid,
            vec![0x05, 0x00],
        )];
    }
    p
}

impl ApplePki {
    /// A chain; `leaf_marker` and `intermediate_marker` choose whether Apple's extensions are
    /// present.
    pub(crate) fn new(intermediate_marker: bool, leaf_marker: bool) -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let root_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let root_params = ca_params("Test Apple Root", None);
        let root = root_params.self_signed(&root_key).unwrap();
        let root_issuer = rcgen::Issuer::new(root_params, root_key);
        let inter_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let inter_params = ca_params(
            "Test Apple WWDR",
            intermediate_marker.then_some(&[1, 2, 840, 113_635, 100, 6, 2, 1][..]),
        );
        let inter = inter_params.signed_by(&inter_key, &root_issuer).unwrap();
        let inter_issuer = rcgen::Issuer::new(inter_params, inter_key);
        let leaf_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test App Store Receipt Signing");
        leaf_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        if leaf_marker {
            leaf_params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
                &[1, 2, 840, 113_635, 100, 6, 11, 1],
                vec![0x05, 0x00],
            )];
        }
        let leaf = leaf_params.signed_by(&leaf_key, &inter_issuer).unwrap();
        let signing =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &leaf_key.serialize_der())
                .unwrap();
        Self {
            root: root.der().to_vec(),
            intermediate: inter.der().to_vec(),
            leaf: leaf.der().to_vec(),
            leaf_key: signing,
        }
    }

    /// A compact JWS of `payload` signed by the leaf, with `x5c` = `[leaf, intermediate, root]`.
    pub(crate) fn sign(&self, payload: &Value) -> String {
        let header = json!({
            "alg": "ES256",
            "x5c": [b64_encode(&self.leaf), b64_encode(&self.intermediate), b64_encode(&self.root)],
        });
        let mut out = b64url_encode(header.to_string().as_bytes());
        out.push('.');
        out.push_str(&b64url_encode(payload.to_string().as_bytes()));
        let sig = self
            .leaf_key
            .sign(&SystemRandom::new(), out.as_bytes())
            .unwrap();
        out.push('.');
        out.push_str(&b64url_encode(sig.as_ref()));
        out
    }
}

/// A key pair and its PKCS#8 DER.
pub(crate) fn p256() -> (EcdsaKeyPair, Vec<u8>) {
    let doc = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
        .unwrap()
        .to_pkcs8v1()
        .unwrap();
    let der = doc.as_ref().to_vec();
    (
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der).unwrap(),
        der,
    )
}

/// An RSA 2048 key pair, its PKCS#8 DER, and its public `(n, e)`.
pub(crate) fn rsa() -> (RsaKeyPair, Vec<u8>, Vec<u8>, Vec<u8>) {
    let kp = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let der = kp.as_der().unwrap().as_ref().to_vec();
    // PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }.
    let pk = kp.public_key().as_ref().to_vec();
    let read = |b: &[u8]| -> (u8, usize, usize) {
        let tag = b[0];
        let (len, hdr) = if b[1] < 0x80 {
            (usize::from(b[1]), 2)
        } else {
            let n = usize::from(b[1] & 0x7f);
            (
                b[2..2 + n]
                    .iter()
                    .fold(0, |a, x| (a << 8) | usize::from(*x)),
                2 + n,
            )
        };
        (tag, hdr, len)
    };
    let (_, h, _) = read(&pk);
    let body = &pk[h..];
    let (_, nh, nl) = read(body);
    let n = body[nh..nh + nl].to_vec();
    let rest = &body[nh + nl..];
    let (_, eh, el) = read(rest);
    let e = rest[eh..eh + el].to_vec();
    let strip = |v: Vec<u8>| v.into_iter().skip_while(|b| *b == 0).collect::<Vec<u8>>();
    let kp = RsaKeyPair::from_pkcs8(&der).unwrap();
    (kp, der, strip(n), strip(e))
}

/// An RS256 compact JWS.
pub(crate) fn rs256(key: &RsaKeyPair, header: &Value, claims: &Value) -> String {
    let mut out = b64url_encode(header.to_string().as_bytes());
    out.push('.');
    out.push_str(&b64url_encode(claims.to_string().as_bytes()));
    let mut sig = vec![0u8; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        out.as_bytes(),
        &mut sig,
    )
    .unwrap();
    out.push('.');
    out.push_str(&b64url_encode(&sig));
    out
}

pub(crate) fn pem(label: &str, der: &[u8]) -> String {
    let b = b64_encode(der);
    let lines: Vec<&str> = b
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

// ----- the emulated world -----

/// What the providers hold, set by the tests.
#[derive(Default)]
pub(crate) struct World {
    /// Apple: original transaction ID → (status, signed transaction, signed renewal).
    pub(crate) apple: HashMap<String, (u64, String, String)>,
    /// Apple: the In-App Purchase key's public half (to check the API's bearer token).
    pub(crate) apple_key: Vec<u8>,
    /// Apple: API calls answered.
    pub(crate) apple_calls: usize,
    /// Google: purchase token → subscriptionsv2 resource.
    pub(crate) google: HashMap<String, Value>,
    /// Google: the service account's public `(n, e)`.
    pub(crate) google_sa: (Vec<u8>, Vec<u8>),
    /// Google: the OIDC signing keys `(kid, n, e)`.
    pub(crate) google_jwks: Vec<(String, Vec<u8>, Vec<u8>)>,
    /// Google: subscriptionsv2 calls and acknowledgements.
    pub(crate) google_gets: usize,
    pub(crate) google_acks: Vec<String>,
    /// Mollie: payments by ID.
    pub(crate) payments: HashMap<String, Value>,
    pub(crate) customers: usize,
    /// Mollie: subscriptions created (customer, interval, start) and cancelled.
    pub(crate) subscriptions: Vec<(String, String, String)>,
    pub(crate) cancelled: Vec<String>,
}

pub(crate) type Shared = Arc<Mutex<World>>;

fn reply(status: u16, v: &Value) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(v.to_string())));
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    r
}

fn bearer(req: &hyper::http::request::Parts) -> String {
    req.headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_owned()
}

fn handle(w: &Shared, parts: &hyper::http::request::Parts, body: &[u8]) -> Response<Full<Bytes>> {
    let path = parts.uri.path().to_owned();
    let method = parts.method.as_str().to_owned();
    let mut w = w.lock().unwrap();
    // Apple: GET /inApps/v1/subscriptions/{id}, ES256 bearer of the configured key.
    if let Some(id) = path.strip_prefix("/inApps/v1/subscriptions/") {
        let jwt = bearer(parts);
        let mut it = jwt.split('.');
        let (h, c, s) = (
            it.next().unwrap_or(""),
            it.next().unwrap_or(""),
            it.next().unwrap_or(""),
        );
        let ok = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &w.apple_key)
            .verify(
                format!("{h}.{c}").as_bytes(),
                &b64url_decode(s).unwrap_or_default(),
            )
            .is_ok();
        let claims: Value =
            serde_json::from_slice(&b64url_decode(c).unwrap_or_default()).unwrap_or_default();
        if !ok || claims["aud"] != "appstoreconnect-v1" || claims["bid"] != "chat.songbird.app" {
            return reply(401, &json!({}));
        }
        w.apple_calls += 1;
        return match w.apple.get(id) {
            Some((status, t, r)) => reply(
                200,
                &json!({
                    "environment": "Sandbox",
                    "bundleId": "chat.songbird.app",
                    "data": [{
                        "subscriptionGroupIdentifier": "1",
                        "lastTransactions": [{
                            "status": status,
                            "originalTransactionId": id,
                            "signedTransactionInfo": t,
                            "signedRenewalInfo": r,
                        }],
                    }],
                }),
            ),
            None => reply(404, &json!({ "errorCode": 4_040_010 })),
        };
    }
    // Google: OAuth for the service account.
    if path == "/token" && method == "POST" {
        let form = String::from_utf8_lossy(body).into_owned();
        let assertion = form
            .split('&')
            .find_map(|kv| kv.strip_prefix("assertion="))
            .unwrap_or_default()
            .to_owned();
        let mut it = assertion.split('.');
        let (h, c, s) = (
            it.next().unwrap_or(""),
            it.next().unwrap_or(""),
            it.next().unwrap_or(""),
        );
        let (n, e) = &w.google_sa;
        let ok = aws_lc_rs::signature::RsaPublicKeyComponents {
            n: n.as_slice(),
            e: e.as_slice(),
        }
        .verify(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            format!("{h}.{c}").as_bytes(),
            &b64url_decode(s).unwrap_or_default(),
        )
        .is_ok();
        return if ok
            && form.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")
        {
            reply(200, &json!({ "access_token": "at-1", "expires_in": 3_600 }))
        } else {
            reply(400, &json!({ "error": "invalid_grant" }))
        };
    }
    if path == "/certs" {
        let keys: Vec<Value> = w
            .google_jwks
            .iter()
            .map(|(kid, n, e)| json!({ "kty": "RSA", "kid": kid, "alg": "RS256", "n": b64url_encode(n), "e": b64url_encode(e) }))
            .collect();
        return reply(200, &json!({ "keys": keys }));
    }
    if let Some(rest) =
        path.strip_prefix("/androidpublisher/v3/applications/chat.songbird.app/purchases/")
    {
        if bearer(parts) != "at-1" {
            return reply(401, &json!({}));
        }
        if let Some(t) = rest.strip_prefix("subscriptionsv2/tokens/") {
            w.google_gets += 1;
            return match w.google.get(t) {
                Some(v) => reply(200, v),
                None => reply(404, &json!({})),
            };
        }
        if let Some(r) = rest.strip_prefix("subscriptions/")
            && let Some(t) = r
                .split("/tokens/")
                .nth(1)
                .and_then(|x| x.strip_suffix(":acknowledge"))
        {
            let t = t.to_owned();
            if let Some(v) = w.google.get_mut(&t) {
                v["acknowledgementState"] = json!("ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED");
            }
            w.google_acks.push(t);
            return reply(200, &json!({}));
        }
    }
    // Mollie.
    if path == "/v2/customers" && method == "POST" {
        w.customers += 1;
        return reply(201, &json!({ "id": format!("cst_{}", w.customers) }));
    }
    if path == "/v2/payments" && method == "POST" {
        let v: Value = serde_json::from_slice(body).unwrap();
        assert!(v.get("billingEmail").is_none() && v.get("consumerName").is_none());
        let id = format!("tr_{}", w.payments.len() + 1);
        w.payments.insert(
            id.clone(),
            json!({
                "id": id,
                "status": "open",
                "sequenceType": v["sequenceType"],
                "customerId": v["customerId"],
                "metadata": v["metadata"],
                "amount": v["amount"],
            }),
        );
        return reply(
            201,
            &json!({ "id": id, "_links": { "checkout": { "href": format!("https://mollie.test/checkout/{id}") } } }),
        );
    }
    if let Some(id) = path.strip_prefix("/v2/payments/") {
        return match w.payments.get(id) {
            Some(p) => reply(200, p),
            None => reply(404, &json!({})),
        };
    }
    if let Some(rest) = path.strip_prefix("/v2/customers/") {
        let (customer, tail) = rest.split_once('/').unwrap_or((rest, ""));
        if tail == "subscriptions" && method == "POST" {
            let v: Value = serde_json::from_slice(body).unwrap();
            w.subscriptions.push((
                customer.to_owned(),
                v["interval"].as_str().unwrap_or_default().to_owned(),
                v["startDate"].as_str().unwrap_or_default().to_owned(),
            ));
            return reply(
                201,
                &json!({ "id": format!("sub_{}", w.subscriptions.len()) }),
            );
        }
        if let Some(s) = tail.strip_prefix("subscriptions/")
            && method == "DELETE"
        {
            w.cancelled.push(s.to_owned());
            return reply(200, &json!({ "id": s, "status": "canceled" }));
        }
    }
    reply(404, &json!({}))
}

/// Starts the emulators; returns their base URL.
pub(crate) async fn serve(w: Shared) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let w = Arc::clone(&w);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let w = Arc::clone(&w);
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        Ok::<_, Infallible>(handle(&w, &parts, &body))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}
