use proptest::prelude::*;

use super::*;

const SECRET: [u8; 32] = [0x42; 32];

fn plan(level: u8, period: u32) -> Info {
    Info {
        kind: Kind::Plan,
        level,
        period,
    }
}

fn pinned(keys: &Keys) -> [u8; NE] {
    keys.public().last().unwrap().1
}

#[test]
fn issued_tokens_redeem_once_under_their_metadata() {
    let keys = Keys::derive(&SECRET, &[1, 2]).unwrap();
    assert_eq!(keys.current(), 2);
    let info = plan(1, 683);
    let (pending, req) = request(2, info, 3).unwrap();
    // The issuer sees the metadata and three blinded elements: no nonce.
    let wire = serde_json::to_string(&req).unwrap();
    let resp = keys.issue(&req).unwrap();
    let tokens = pending.finish(&pinned(&keys), &resp).unwrap();
    assert_eq!(tokens.len(), 3);
    let mut nullifiers = std::collections::HashSet::new();
    for t in &tokens {
        assert!(
            !wire.contains(&t.nonce),
            "the nonce never went to the issuer"
        );
        let (i, n) = keys.redeem(t).unwrap();
        assert_eq!(i, info);
        assert!(nullifiers.insert(n), "each token has its own nullifier");
        // Any change to the metadata or the output is refused.
        let other = if t.nonce == tokens[1].nonce {
            &tokens[0]
        } else {
            &tokens[1]
        };
        for bad in [
            Redemption {
                level: 0,
                ..t.clone()
            },
            Redemption {
                period: 684,
                ..t.clone()
            },
            Redemption {
                kind: Kind::VaultDay.as_u8(),
                ..t.clone()
            },
            Redemption {
                key: 1,
                ..t.clone()
            },
            Redemption {
                nonce: other.nonce.clone(),
                ..t.clone()
            },
        ] {
            assert_eq!(keys.redeem(&bad), Err(TokenError::Invalid));
        }
    }
    // An unknown key ID or kind, and bad hex, are malformed.
    let t = &tokens[0];
    assert_eq!(
        keys.redeem(&Redemption {
            key: 9,
            ..t.clone()
        }),
        Err(TokenError::Malformed)
    );
    assert_eq!(
        keys.redeem(&Redemption {
            kind: 7,
            ..t.clone()
        }),
        Err(TokenError::Malformed)
    );
    assert_eq!(
        keys.redeem(&Redemption {
            nonce: "zz".into(),
            ..t.clone()
        }),
        Err(TokenError::Malformed)
    );
}

#[test]
fn a_server_tagging_a_user_with_another_key_is_caught() {
    let keys = Keys::derive(&SECRET, &[1]).unwrap();
    let tagging = Keys::derive(&[0x43; 32], &[1]).unwrap();
    let (pending, req) = request(1, plan(1, 683), 2).unwrap();
    let resp = tagging.issue(&req).unwrap();
    assert_eq!(
        pending.finish(&pinned(&keys), &resp).unwrap_err(),
        TokenError::Proof
    );
}

#[test]
fn a_server_evaluating_under_other_metadata_is_caught() {
    let keys = Keys::derive(&SECRET, &[1]).unwrap();
    let (pending, req) = request(1, plan(1, 683), 1).unwrap();
    // The issuer answers as if the request were for another month.
    let resp = keys.issue(&IssueRequest { period: 690, ..req }).unwrap();
    assert_eq!(
        pending.finish(&pinned(&keys), &resp).unwrap_err(),
        TokenError::Proof
    );
}

#[test]
fn requests_and_answers_are_bounded() {
    let keys = Keys::derive(&SECRET, &[1]).unwrap();
    assert!(request(1, plan(1, 1), 0).is_err());
    assert!(request(1, plan(1, 1), MAX_ISSUE + 1).is_err());
    let (_, req) = request(1, plan(1, 1), 2).unwrap();
    let mut big = req.clone();
    big.blinded = vec![req.blinded[0].clone(); MAX_ISSUE + 1];
    assert_eq!(keys.issue(&big), Err(TokenError::Malformed));
    // A blinded "element" that is the identity or not canonical is refused.
    let mut bad = req.clone();
    bad.blinded[0] = hex::encode([0u8; 32]);
    assert_eq!(keys.issue(&bad), Err(TokenError::Malformed));
    bad.blinded[0] = hex::encode([0xff; 32]);
    assert_eq!(keys.issue(&bad), Err(TokenError::Malformed));
    // Only the current key issues.
    let two = Keys::derive(&SECRET, &[1, 2]).unwrap();
    assert_eq!(two.issue(&req), Err(TokenError::Malformed));
    // Keys: at least one, none twice.
    assert!(Keys::derive(&SECRET, &[]).is_err());
    assert!(Keys::derive(&SECRET, &[1, 1]).is_err());
    // A short answer is refused.
    let (pending, req) = request(1, plan(1, 1), 2).unwrap();
    let mut resp = keys.issue(&req).unwrap();
    resp.evaluated.pop();
    assert_eq!(
        pending.finish(&pinned(&keys), &resp).unwrap_err(),
        TokenError::Malformed
    );
}

#[test]
fn key_ids_have_their_own_keys_and_debug_shows_no_secret() {
    let keys = Keys::derive(&SECRET, &[1, 2]).unwrap();
    let p = keys.public();
    assert_ne!(p[0].1, p[1].1);
    let shown = format!("{keys:?}");
    assert!(!shown.contains(&hex::encode(SECRET)));
    let (pending, _) = request(1, plan(1, 1), 1).unwrap();
    assert!(!format!("{pending:?}").contains("nonce"));
}

#[test]
fn months_and_days() {
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(days_from_civil(2026, 11, 19), 20_776);
    assert_eq!(month_of(20_776), (2026 - 1970) * 12 + 10);
    let m = month_of(20_776);
    assert_eq!(civil_from_days(i64::from(first_day(m))), (2026, 11, 1));
    assert_eq!(civil_from_days(i64::from(last_day(m))), (2026, 11, 30));
    // February in a leap year and in a century year that is not one.
    let feb24 = month_of(u32::try_from(days_from_civil(2024, 2, 10)).unwrap());
    assert_eq!(civil_from_days(i64::from(last_day(feb24))), (2024, 2, 29));
    let feb00 = month_of(u32::try_from(days_from_civil(2100, 2, 10)).unwrap());
    assert_eq!(civil_from_days(i64::from(last_day(feb00))), (2100, 2, 28));
    let dec = month_of(u32::try_from(days_from_civil(2026, 12, 31)).unwrap());
    assert_eq!(civil_from_days(i64::from(last_day(dec))), (2026, 12, 31));
    assert_eq!(
        first_day(dec + 1),
        u32::try_from(days_from_civil(2027, 1, 1)).unwrap()
    );
}

proptest! {
    #[test]
    fn civil_dates_round_trip(z in 0i64..2_000_000) {
        let (y, m, d) = civil_from_days(z);
        prop_assert_eq!(days_from_civil(y, m, d), z);
        let day = u32::try_from(z).unwrap();
        let month = month_of(day);
        prop_assert!(first_day(month) <= day && day <= last_day(month));
        prop_assert_eq!(last_day(month) + 1, first_day(month + 1));
    }

    #[test]
    fn info_encodes_injectively(k in 1u8..=3, l: u8, p: u32, k2 in 1u8..=3, l2: u8, p2: u32) {
        let a = Info { kind: Kind::from_u8(k).unwrap(), level: l, period: p };
        let b = Info { kind: Kind::from_u8(k2).unwrap(), level: l2, period: p2 };
        prop_assert_eq!(a.encode() == b.encode(), a == b);
    }
}

/// Songbird's token vector (PROTOCOL §14.4): a fixed secret, key ID, metadata, nonce, blind and
/// proof scalar give fixed bytes for every step. `vectors/check.py` re-derives them with the
/// Python standard library (ristretto255 written from RFC 9496). `SONGBIRD_WRITE_VECTORS=1`
/// rewrites the file; otherwise it must match.
#[test]
fn the_published_vector_holds() {
    use curve25519_dalek::scalar::Scalar;
    let secret = [0x07u8; 32];
    let keys = Keys::derive(&secret, &[1]).unwrap();
    let info = plan(1, 683);
    let nonce = [0x11u8; NONCE_LEN];
    let blind = Scalar::from_bytes_mod_order_wide(&[0x22; 64]);
    let r = Scalar::from_bytes_mod_order_wide(&[0x33; 64]);
    let (pending, req) = request_with(1, info, vec![nonce], vec![blind]).unwrap();
    let kp = keys.pair(1).unwrap();
    let blinded = oprf::element(&hex::decode(&req.blinded[0]).unwrap()).unwrap();
    let (ev, proof) = kp
        .blind_evaluate(&suite(), &[blinded], &info.encode(), &r)
        .unwrap();
    let resp = IssueResponse {
        evaluated: vec![hex::encode(oprf::element_bytes(&ev[0]))],
        proof: hex::encode(proof.unwrap().to_bytes()),
    };
    let t = pending.finish(&kp.public(), &resp).unwrap().remove(0);
    let (_, n) = keys.redeem(&t).unwrap();
    let v = serde_json::json!({
        "suite": "ristretto255-SHA512 POPRF (RFC 9497)",
        "secret": hex::encode(secret),
        "key_id": 1,
        "public_key": hex::encode(kp.public()),
        "info": hex::encode(info.encode()),
        "nonce": hex::encode(nonce),
        "blind": hex::encode(blind.to_bytes()),
        "proof_random": hex::encode(r.to_bytes()),
        "blinded": req.blinded[0],
        "evaluated": resp.evaluated[0],
        "proof": resp.proof,
        "output": t.output,
        "nullifier": hex::encode(n),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1.json");
    let text = format!("{}\n", serde_json::to_string_pretty(&v).unwrap());
    if std::env::var("SONGBIRD_WRITE_VECTORS").is_ok() {
        std::fs::write(&path, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
}
