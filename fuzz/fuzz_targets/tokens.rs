//! Anonymous token decoders and checks (Prompt 11, D-0128): issuance requests reach billing and
//! redemptions reach `api` from anyone. Never panics; elements and scalars decode only when
//! canonical (and never the identity); nothing the fuzzer makes redeems; an answer the fuzzer
//! makes never finishes a real request.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use songbird_tokens::oprf;
use songbird_tokens::token::{self, Info, IssueRequest, IssueResponse, Keys, Kind, Redemption};

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| Keys::derive(&[0x5A; 32], &[1]).expect("keys"))
}

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = oprf::element(data) {
        assert_eq!(&oprf::element_bytes(&p)[..], data);
    }
    if let Ok(s) = oprf::scalar(data) {
        assert_eq!(&s.to_bytes()[..], data);
    }
    if let Ok(r) = serde_json::from_slice::<Redemption>(data) {
        assert!(keys().redeem(&r).is_err(), "a made-up token redeemed");
    }
    if let Ok(req) = serde_json::from_slice::<IssueRequest>(data) {
        if let Ok(resp) = keys().issue(&req) {
            assert_eq!(resp.evaluated.len(), req.blinded.len());
        }
    }
    if let Ok(resp) = serde_json::from_slice::<IssueResponse>(data) {
        let info = Info {
            kind: Kind::Plan,
            level: 1,
            period: 683,
        };
        let (pending, _) = token::request(1, info, 1).expect("request");
        let pinned = keys().public()[0].1;
        assert!(pending.finish(&pinned, &resp).is_err());
    }
});
