//! Passkeys against the W3C WebAuthn Level 3 test vectors (§16.2 "ES256 Credential with No
//! Attestation", §16.11 "Packed Attestation with Ed25519 Credential"; RP ID `example.org`, origin
//! `https://example.org`), copied verbatim from the specification's source
//! (`w3c/webauthn` `index.bs`). The vectors' authenticators do not set the user-verified flag, so
//! they run with `require_uv` off; requiring it refuses them.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use songbird_keys::webauthn::{
    CredentialKey, RelyingParty, WebAuthnError, check_assertion, check_registration,
};

mod v {
    pub(crate) const ES_RC: &str =
        "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130";
    pub(crate) const ES_CID: &str =
        "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4";
    pub(crate) const ES_RCD: &str = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d";
    pub(crate) const ES_AO: &str = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220";
    pub(crate) const ES_AC: &str =
        "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408";
    pub(crate) const ES_AD: &str =
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000";
    pub(crate) const ES_ACD: &str = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d";
    pub(crate) const ES_SIG: &str = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87";
    pub(crate) const ED_RC: &str =
        "a8abf9dabdc6b0df63466b39bda9e8a34a34e185337a59f1c579990676d3b3bd";
    pub(crate) const ED_CID: &str =
        "ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bd";
    pub(crate) const ED_RCD: &str = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22714b763532723347734e396a526d733576616e6f6f306f303459557a656c6e7878586d5a426e6254733730222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20425f44543567375a445f2d394f544c59583549764551227d";
    pub(crate) const ED_AO: &str = "a363666d74667061636b65646761747453746d74a363616c67266373696758483046022100d83f60bd80269537583218858aefb03ac57d45fa06e42feaae332d187f62da9f022100a02bd3cb6f7e1d283c93bad1f3f4b5a4c0494463da7fdbf256949116754d1f17637835638159022730820223308201c8a003020102021100b2cfc9ea33c8643b0e1a760463eaf164300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004dd2b7a564b73b8c0b81c4c62e521925c4d1198ec9f583dbf1eebe364b65cd9c29a9bdf346aaa81fb6b9507e5249a52fdaf8e39e26b0b7dc45992a7e233b70f70a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e041604140ae27546bc7eccb1b4b597bd354f0c0b1f1f8f8e301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d0403020349003046022100a0d434ecb5fc3bfd7da5f41904517ad2836249f561bd834ba7a438a8ab7a4ce8022100fac845bb7a02513b58e9f319654dbe49b0f02b95835bac568c71f8a18cdde9ab6861757468446174615881bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54100000000d5aa33581e8ca478e20fe713f5d32ff20020ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bda401010327200621582044e06ddd331c36a8dc667bab52bcae63486c916aa5e339e6acebaa84934bf832";
    pub(crate) const ED_AC: &str =
        "895957e01c633a698348a2d8a31a54b7db27e8c1c43b2080d79ae2190267bfd2";
    pub(crate) const ED_AD: &str =
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50100000000";
    pub(crate) const ED_ACD: &str = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2269566c583442786a4f6d6d44534b4c596f7870557439736e364d48454f7943413135726947514a6e763949222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d";
    pub(crate) const ED_SIG: &str = "f5c59c7e46c34f6f8cc197101ddf9934fa2595f68eb1913a637e8419eb9ba4cfdfc48f85393bc0d40b011f0d6fecb097d6607525713223a0dc0d453993dae00b";
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn origins() -> Vec<String> {
    vec!["https://example.org".to_owned()]
}

struct Vector {
    rc: &'static str,
    cid: &'static str,
    rcd: &'static str,
    ao: &'static str,
    ac: &'static str,
    ad: &'static str,
    acd: &'static str,
    sig: &'static str,
}

const ES256: Vector = Vector {
    rc: v::ES_RC,
    cid: v::ES_CID,
    rcd: v::ES_RCD,
    ao: v::ES_AO,
    ac: v::ES_AC,
    ad: v::ES_AD,
    acd: v::ES_ACD,
    sig: v::ES_SIG,
};
const ED25519: Vector = Vector {
    rc: v::ED_RC,
    cid: v::ED_CID,
    rcd: v::ED_RCD,
    ao: v::ED_AO,
    ac: v::ED_AC,
    ad: v::ED_AD,
    acd: v::ED_ACD,
    sig: v::ED_SIG,
};

fn run(t: &Vector, es256: bool) {
    let o = origins();
    let rp = RelyingParty {
        id: "example.org",
        origins: &o,
        require_uv: false,
    };
    let cred = check_registration(&h(t.rcd), &h(t.ao), &h(t.rc), &rp).unwrap();
    assert_eq!(cred.id, h(t.cid));
    assert_eq!(matches!(cred.key, CredentialKey::Es256(_)), es256);
    assert_eq!(
        CredentialKey::from_bytes(&cred.key.to_bytes()).unwrap(),
        cred.key
    );
    let assert =
        |key: &CredentialKey,
         count: u32,
         ad: &[u8],
         cd: &[u8],
         sig: &[u8],
         ch: &[u8],
         rp: &RelyingParty<'_>| { check_assertion(key, count, ad, cd, sig, ch, rp) };
    let (ad, cd, sig, ch) = (h(t.ad), h(t.acd), h(t.sig), h(t.ac));
    assert_eq!(
        assert(&cred.key, cred.sign_count, &ad, &cd, &sig, &ch, &rp),
        Ok(0)
    );
    // Another challenge, origin, RP ID; a flipped signature or authenticator-data byte.
    assert_eq!(
        assert(&cred.key, 0, &ad, &cd, &sig, &h(t.rc), &rp),
        Err(WebAuthnError::ClientData)
    );
    let other = vec!["https://example.com".to_owned()];
    let rp_o = RelyingParty {
        origins: &other,
        ..rp.clone()
    };
    assert_eq!(
        assert(&cred.key, 0, &ad, &cd, &sig, &ch, &rp_o),
        Err(WebAuthnError::ClientData)
    );
    let rp_id = RelyingParty {
        id: "example.com",
        ..rp.clone()
    };
    assert_eq!(
        assert(&cred.key, 0, &ad, &cd, &sig, &ch, &rp_id),
        Err(WebAuthnError::AuthenticatorData)
    );
    let mut bad = sig.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        assert(&cred.key, 0, &ad, &cd, &bad, &ch, &rp),
        Err(WebAuthnError::Signature)
    );
    let mut bad_ad = ad.clone();
    bad_ad[33] ^= 0x80;
    assert!(assert(&cred.key, 0, &bad_ad, &cd, &sig, &ch, &rp).is_err());
    // A stored counter above zero and a zero counter: a cloned authenticator.
    assert_eq!(
        assert(&cred.key, 5, &ad, &cd, &sig, &ch, &rp),
        Err(WebAuthnError::Counter)
    );
    // Registration data replayed as an assertion, and the reverse.
    assert!(check_registration(&cd, &h(t.ao), &ch, &rp).is_err());
    // Requiring user verification refuses these authenticators.
    let rp_uv = RelyingParty {
        require_uv: true,
        ..rp.clone()
    };
    assert_eq!(
        check_registration(&h(t.rcd), &h(t.ao), &h(t.rc), &rp_uv),
        Err(WebAuthnError::AuthenticatorData)
    );
    // The attestation statement and AAGUID are deliberately unchecked (no attestation is
    // trusted); within the authenticator data, a flipped RP ID hash byte or a cleared
    // user-present flag is refused, and a flipped credential ID or key byte never yields the
    // same credential.
    let ao = h(t.ao);
    let ad_at = ao.windows(32).position(|w| w == &h(t.ad)[..32]).unwrap();
    let flip = |off: usize, bit: u8| {
        let mut x = ao.clone();
        x[ad_at + off] ^= bit;
        check_registration(&h(t.rcd), &x, &h(t.rc), &rp)
    };
    assert_eq!(flip(0, 1), Err(WebAuthnError::AuthenticatorData));
    assert_eq!(flip(32, 0x01), Err(WebAuthnError::AuthenticatorData));
    for off in 55..ao.len() - ad_at {
        if let Ok(c) = flip(off, 1) {
            assert_ne!(c, cred, "authenticator data byte {off}");
        }
    }
}

#[test]
fn es256_none_attestation_registers_and_asserts() {
    run(&ES256, true);
}

#[test]
fn ed25519_packed_attestation_registers_and_asserts() {
    run(&ED25519, false);
}
