//! The link `worker` uses to delete devices (D-0036): its own listener, mutual TLS from the
//! internal CA, only `worker.` certificates, only the requests of
//! [`songbird_link::devices`]. Every operation acts on the devices named and nothing else.

use std::sync::Arc;

use bytes::Bytes;
use songbird_link::devices::{DeviceRequest, encode_response};
use songbird_mailbox::Mailbox;
use songbird_router::Router;

use crate::Shared;

/// The link handler.
pub fn handler<M: Mailbox, R: Router>(shared: Arc<Shared<M, R>>) -> songbird_link::Handler {
    Arc::new(move |req: Bytes| {
        let shared = Arc::clone(&shared);
        Box::pin(async move {
            let r = match DeviceRequest::decode(&req) {
                None => Err(()),
                Some(DeviceRequest::Forget(ds)) => {
                    // Sessions first: a device must not keep reading while its mailbox goes.
                    for d in &ds {
                        shared.router.close_everywhere(d).await;
                    }
                    match shared.mailbox.forget(&ds).await {
                        Ok(()) => Ok(Vec::new()),
                        Err(_) => Err(()),
                    }
                }
                Some(DeviceRequest::Known(ds)) => {
                    let mut out = Ok(Vec::with_capacity(ds.len()));
                    for d in &ds {
                        let Ok(k) = shared.mailbox.knows(d).await else {
                            out = Err(());
                            break;
                        };
                        if let Ok(v) = &mut out {
                            v.push(k);
                        }
                    }
                    out
                }
            };
            Bytes::from(encode_response(&r))
        })
    })
}
