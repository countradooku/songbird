//! S3 multipart uploads (Prompt 6, M2, D-0081): resumable attachment uploads go to the store in
//! fixed-size parts, each streamed straight through with its exact length, so `api` never buffers
//! an upload.
//!
//! The operations: create, upload a part, list the parts received, complete, abort, and list
//! the uploads in progress (for the sweep of abandoned ones). Upload IDs and `ETag`s come from the
//! store; both are checked to be short and printable before they are reused in a URL or a
//! document, and neither appears in an error.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use bytes::Bytes;
use futures_core::Stream;
use hyper::header::CONTENT_LENGTH;
use hyper::{Method, StatusCode};

use crate::body::{BODY_MISMATCH, BODY_OK, BODY_SOURCE, ExactBody, ReqBody};
use crate::{Client, Error, MAX_ERROR_BYTES, check_key, sigv4, xml};

/// The most parts an upload may have (the S3 limit).
pub const MAX_PARTS: u16 = 10_000;
/// The smallest part but the last (the S3 limit).
pub const MIN_PART_BYTES: u64 = 5 << 20;
/// The largest part (the S3 limit).
pub const MAX_PART_BYTES: u64 = 5 << 30;
/// Longest upload ID or `ETag` accepted.
pub const MAX_TOKEN_LEN: usize = 1024;
/// Most pages [`Client::list_multipart_uploads`] reads (100,000 uploads).
pub const MAX_UPLOAD_PAGES: usize = 100;
/// Largest `ListParts` or `ListMultipartUploads` document read.
const MAX_LIST_BYTES: usize = 1 << 20;

/// A part the store holds. `Debug` hides the `ETag`.
#[derive(Clone, PartialEq, Eq)]
pub struct Part {
    /// 1-based.
    pub number: u16,
    /// Bytes.
    pub size: u64,
    /// The store's `ETag`, quotes included, for completing.
    pub etag: String,
}

impl std::fmt::Debug for Part {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Part")
            .field("number", &self.number)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// An upload in progress ([`Client::list_multipart_uploads`]). `Debug` hides the key and ID.
#[derive(Clone, PartialEq, Eq)]
pub struct Upload {
    /// Object key (never log it).
    pub key: String,
    /// Upload ID.
    pub upload_id: String,
    /// `Initiated` as sent (ISO 8601).
    pub initiated: String,
}

impl std::fmt::Debug for Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upload")
            .field("initiated", &self.initiated)
            .finish_non_exhaustive()
    }
}

/// One page of uploads in progress, and the next page's markers (key, upload ID) when there is more.
pub type UploadPage = (Vec<Upload>, Option<(String, String)>);

/// A token the store issued (upload ID, `ETag`): non-empty, short, printable ASCII.
pub(crate) fn valid_token(t: &str) -> bool {
    !t.is_empty() && t.len() <= MAX_TOKEN_LEN && t.bytes().all(|b| b.is_ascii_graphic())
}

fn check_upload(upload_id: &str) -> Result<(), Error> {
    if valid_token(upload_id) {
        Ok(())
    } else {
        Err(Error::InvalidInput("upload id"))
    }
}

impl Client {
    /// Starts a multipart upload of `key`; returns its upload ID.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn create_multipart_upload(&self, key: &str) -> Result<String, Error> {
        check_key(key)?;
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let req = i.request(
                &Method::POST,
                Some(key),
                &[("uploads", "")],
                &[(CONTENT_LENGTH.as_str(), "0".to_owned())],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(i.error_for(resp, conn).await);
            }
            let (_, body) = i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
            xml::upload_id(&body)
        })
        .await
    }

    /// Uploads part `number` (1-based) of `length` bytes from `body`, held to exactly that
    /// length like [`Client::put_object`]; returns its `ETag`.
    ///
    /// # Errors
    /// [`Error::LengthMismatch`], [`Error::BodySource`], [`Error::NotFound`] (no such upload),
    /// [`Error::InvalidInput`], the others.
    pub async fn upload_part<S, E>(
        &self,
        key: &str,
        upload_id: &str,
        number: u16,
        length: u64,
        body: S,
    ) -> Result<String, Error>
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: 'static,
    {
        check_key(key)?;
        check_upload(upload_id)?;
        if number == 0 || number > MAX_PARTS {
            return Err(Error::InvalidInput("part number"));
        }
        if length == 0 || length > MAX_PART_BYTES {
            return Err(Error::InvalidInput("part length"));
        }
        let i = &self.inner;
        let state = Arc::new(AtomicU8::new(BODY_OK));
        let exact = ExactBody::new(body, length, Arc::clone(&state));
        let body_error = |state: &AtomicU8| match state.load(Ordering::Relaxed) {
            BODY_MISMATCH => Some(Error::LengthMismatch),
            BODY_SOURCE => Some(Error::BodySource),
            _ => None,
        };
        let n = number.to_string();
        let result = self
            .timed(i.upload_timeout, async {
                let req = i.request(
                    &Method::PUT,
                    Some(key),
                    &[("partNumber", &n), ("uploadId", upload_id)],
                    &[(CONTENT_LENGTH.as_str(), length.to_string())],
                    sigv4::UNSIGNED_PAYLOAD,
                    ReqBody::Exact(exact),
                )?;
                let (resp, conn) = i.send(req).await?;
                if !resp.status().is_success() {
                    return Err(i.error_for(resp, conn).await);
                }
                let etag = resp
                    .headers()
                    .get(hyper::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .filter(|t| valid_token(t))
                    .map(str::to_owned)
                    .ok_or(Error::Protocol("part without ETag"))?;
                i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
                Ok(etag)
            })
            .await;
        match result {
            Err(e) => Err(body_error(&state).unwrap_or(e)),
            Ok(etag) => body_error(&state).map_or(Ok(etag), Err),
        }
    }

    /// The parts received so far, in part order (at most 1,000: Songbird's uploads have far
    /// fewer parts).
    ///
    /// # Errors
    /// [`Error::NotFound`] (no such upload), [`Error::Protocol`] for more than 1,000 parts or a
    /// malformed document, the others.
    pub async fn list_parts(&self, key: &str, upload_id: &str) -> Result<Vec<Part>, Error> {
        check_key(key)?;
        check_upload(upload_id)?;
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let req = i.request(
                &Method::GET,
                Some(key),
                &[("max-parts", "1000"), ("uploadId", upload_id)],
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(i.error_for(resp, conn).await);
            }
            let (_, body) = i.read_body(resp, conn, MAX_LIST_BYTES).await?;
            xml::list_parts(&body, 1000)
        })
        .await
    }

    /// Completes the upload from `parts` (in order, as [`Client::list_parts`] returned them).
    ///
    /// # Errors
    /// [`Error::NotFound`] (no such upload), `Status` for a part the store rejects (S3 answers
    /// some failures with 200 and an error document: those are errors here too), the others.
    pub async fn complete_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[Part],
    ) -> Result<(), Error> {
        check_key(key)?;
        check_upload(upload_id)?;
        if parts.is_empty() || parts.len() > usize::from(MAX_PARTS) {
            return Err(Error::InvalidInput("parts"));
        }
        let mut doc = String::with_capacity(64 + parts.len() * 96);
        doc.push_str("<CompleteMultipartUpload>");
        let mut last = 0;
        for p in parts {
            if p.number <= last || !valid_token(&p.etag) {
                return Err(Error::InvalidInput("parts"));
            }
            last = p.number;
            doc.push_str("<Part><PartNumber>");
            doc.push_str(&p.number.to_string());
            doc.push_str("</PartNumber><ETag>");
            xml::escape_into(&p.etag, &mut doc);
            doc.push_str("</ETag></Part>");
        }
        doc.push_str("</CompleteMultipartUpload>");
        let body = Bytes::from(doc);
        let hash = sigv4::sha256_hex(&body);
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let req = i.request(
                &Method::POST,
                Some(key),
                &[("uploadId", upload_id)],
                &[(CONTENT_LENGTH.as_str(), body.len().to_string())],
                &hash,
                ReqBody::Full(Some(body.clone())),
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(i.error_for(resp, conn).await);
            }
            let (_, doc) = i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
            xml::complete_result(&doc)
        })
        .await
    }

    /// Aborts the upload and frees its parts. Aborting one that is gone succeeds.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn abort_multipart_upload(&self, key: &str, upload_id: &str) -> Result<(), Error> {
        check_key(key)?;
        check_upload(upload_id)?;
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let req = i.request(
                &Method::DELETE,
                Some(key),
                &[("uploadId", upload_id)],
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status().is_success() {
                i.read_body(resp, conn, MAX_ERROR_BYTES).await?;
                return Ok(());
            }
            match i.error_for(resp, conn).await {
                Error::NotFound => Ok(()),
                e => Err(e),
            }
        })
        .await
    }

    /// Every upload in progress whose key starts with `prefix`, page after page (at most
    /// [`MAX_UPLOAD_PAGES`] pages of 1,000).
    ///
    /// # Errors
    /// [`Error`]; [`Error::Protocol`] past the page limit.
    pub async fn list_multipart_uploads(&self, prefix: &str) -> Result<Vec<Upload>, Error> {
        let mut all = Vec::new();
        let mut marker: Option<(String, String)> = None;
        for _ in 0..MAX_UPLOAD_PAGES {
            let (page, next) = self
                .list_multipart_uploads_page(
                    prefix,
                    marker.as_ref().map(|(k, u)| (k.as_str(), u.as_str())),
                )
                .await?;
            all.extend(page);
            match next {
                Some(n) if marker.as_ref() != Some(&n) => marker = Some(n),
                Some(_) => return Err(Error::Protocol("upload listing does not advance")),
                None => return Ok(all),
            }
        }
        Err(Error::Protocol("too many uploads in progress"))
    }

    /// One page of up to 1,000 uploads in progress after `marker` (key, upload ID); the next
    /// page's marker when there is more.
    ///
    /// # Errors
    /// [`Error`].
    pub async fn list_multipart_uploads_page(
        &self,
        prefix: &str,
        marker: Option<(&str, &str)>,
    ) -> Result<UploadPage, Error> {
        if let Some((k, u)) = marker
            && (k.is_empty()
                || k.len() > crate::MAX_KEY_BYTES
                || k.chars().any(char::is_control)
                || !valid_token(u))
        {
            return Err(Error::InvalidInput("marker"));
        }
        if prefix.len() > crate::MAX_KEY_BYTES || prefix.chars().any(char::is_control) {
            return Err(Error::InvalidInput("prefix"));
        }
        let i = &self.inner;
        self.timed(i.request_timeout, async {
            let mut query: Vec<(&str, &str)> = vec![("max-uploads", "1000"), ("uploads", "")];
            if !prefix.is_empty() {
                query.push(("prefix", prefix));
            }
            if let Some((k, u)) = marker {
                query.push(("key-marker", k));
                query.push(("upload-id-marker", u));
            }
            let req = i.request(
                &Method::GET,
                None,
                &query,
                &[],
                sigv4::EMPTY_SHA256,
                ReqBody::Empty,
            )?;
            let (resp, conn) = i.send(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(i.error_for(resp, conn).await);
            }
            let (_, body) = i.read_body(resp, conn, MAX_LIST_BYTES).await?;
            xml::list_uploads(&body, 1000)
        })
        .await
    }
}

/// The multipart document parsers, for the fuzz target (`fuzz/fuzz_targets/s3_multipart_xml.rs`).
#[doc(hidden)]
pub mod parse {
    /// `CreateMultipartUpload`'s result.
    ///
    /// # Errors
    /// Malformed.
    pub fn upload_id(body: &[u8]) -> Result<String, crate::Error> {
        crate::xml::upload_id(body)
    }
    /// `ListParts`.
    ///
    /// # Errors
    /// Malformed.
    pub fn list_parts(body: &[u8]) -> Result<Vec<super::Part>, crate::Error> {
        crate::xml::list_parts(body, 1000)
    }
    /// `ListMultipartUploads`.
    ///
    /// # Errors
    /// Malformed.
    pub fn list_uploads(body: &[u8]) -> Result<super::UploadPage, crate::Error> {
        crate::xml::list_uploads(body, 1000)
    }
    /// `CompleteMultipartUpload`'s result.
    ///
    /// # Errors
    /// An error document, or malformed.
    pub fn complete_result(body: &[u8]) -> Result<(), crate::Error> {
        crate::xml::complete_result(body)
    }
}
