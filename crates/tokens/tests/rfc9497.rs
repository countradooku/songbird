//! RFC 9497 Appendix A.1 (`ristretto255-SHA512`): every published vector of the three modes,
//! byte for byte: key derivation, blinding, evaluation, the batched DLEQ proof with its given
//! random scalar, and the output, from the client's and the server's side.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use songbird_tokens::oprf::{self, KeyPair, Mode, Suite, element, element_bytes, scalar};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

const SEED: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
const KEY_INFO: &str = "74657374206b6579";
const BLIND_1: &str = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706";
const BLIND_2: &str = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e";

struct Vector {
    inputs: &'static [&'static str],
    blinds: &'static [&'static str],
    blinded: &'static [&'static str],
    evaluated: &'static [&'static str],
    proof: Option<&'static str>,
    proof_r: Option<&'static str>,
    outputs: &'static [&'static str],
}

fn key(mode: Mode) -> (Suite, KeyPair) {
    let suite = Suite::new(mode);
    let seed: [u8; 32] = h(SEED).try_into().unwrap();
    let kp = suite.derive_key_pair(&seed, &h(KEY_INFO)).unwrap();
    (suite, kp)
}

fn check(mode: Mode, kp_expect: (&str, Option<&str>), info: &[u8], v: &Vector) {
    let (suite, kp) = key(mode);
    assert_eq!(hex::encode(kp.secret_bytes()), kp_expect.0, "skSm");
    if let Some(pk) = kp_expect.1 {
        assert_eq!(hex::encode(kp.public()), pk, "pkSm");
    }
    let inputs: Vec<Vec<u8>> = v.inputs.iter().map(|i| h(i)).collect();
    let blinds: Vec<_> = v.blinds.iter().map(|b| scalar(&h(b)).unwrap()).collect();
    // Client: blinding.
    let blinded: Vec<_> = inputs
        .iter()
        .zip(&blinds)
        .map(|(i, b)| suite.blind(i, b).unwrap())
        .collect();
    for (b, e) in blinded.iter().zip(v.blinded) {
        assert_eq!(hex::encode(element_bytes(b)), *e, "BlindedElement");
    }
    // Server: evaluation with the vector's proof scalar.
    let r = v
        .proof_r
        .map_or(curve25519_dalek::scalar::Scalar::ONE, |r| {
            scalar(&h(r)).unwrap()
        });
    let (evaluated, proof) = kp.blind_evaluate(&suite, &blinded, info, &r).unwrap();
    for (e, x) in evaluated.iter().zip(v.evaluated) {
        assert_eq!(hex::encode(element_bytes(e)), *x, "EvaluationElement");
    }
    assert_eq!(
        proof.map(|p| hex::encode(p.to_bytes())).as_deref(),
        v.proof,
        "Proof"
    );
    // Client: the received bytes deserialize, the proof verifies, the outputs match.
    let received: Vec<_> = v
        .evaluated
        .iter()
        .map(|e| element(&h(e)).unwrap())
        .collect();
    let proof = v
        .proof
        .map(|p| oprf::Proof::from_bytes(&h(p).try_into().unwrap()).unwrap());
    let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let out = suite
        .finalize(
            &refs,
            &blinds,
            &blinded,
            &received,
            Some(kp.public_point()),
            info,
            proof.as_ref(),
        )
        .unwrap();
    for (o, x) in out.iter().zip(v.outputs) {
        assert_eq!(hex::encode(o), *x, "Output");
    }
    // The server alone reaches the same output.
    for (i, x) in inputs.iter().zip(v.outputs) {
        assert_eq!(
            hex::encode(kp.evaluate(&suite, i, info).unwrap()),
            *x,
            "Evaluate"
        );
    }
    // A flipped proof never verifies.
    if let Some(mut p) = proof {
        p.c += curve25519_dalek::scalar::Scalar::ONE;
        assert_eq!(
            suite.finalize(
                &refs,
                &blinds,
                &blinded,
                &received,
                Some(kp.public_point()),
                info,
                Some(&p)
            ),
            Err(oprf::Error::Verify)
        );
    }
}

const OUT_0_V: &str = "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c";
const OUT_5A_V: &str = "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6";
const OUT_0_P: &str = "ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221";
const OUT_5A_P: &str = "7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507";
const IN_5A: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

#[test]
fn oprf_mode() {
    let sk = (
        "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e",
        None,
    );
    check(
        Mode::Oprf,
        sk,
        b"",
        &Vector {
            inputs: &["00"],
            blinds: &[BLIND_1],
            blinded: &["609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"],
            evaluated: &["7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e"],
            proof: None,
            proof_r: None,
            outputs: &[
                "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
            ],
        },
    );
    check(
        Mode::Oprf,
        sk,
        b"",
        &Vector {
            inputs: &[IN_5A],
            blinds: &[BLIND_1],
            blinded: &["da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418"],
            evaluated: &["b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25"],
            proof: None,
            proof_r: None,
            outputs: &[
                "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73",
            ],
        },
    );
}

#[test]
fn voprf_mode() {
    let k = (
        "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909",
        Some("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e"),
    );
    check(
        Mode::Voprf,
        k,
        b"",
        &Vector {
            inputs: &["00"],
            blinds: &[BLIND_1],
            blinded: &["863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"],
            evaluated: &["aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"],
            proof: Some(
                "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d",
            ),
            proof_r: Some(BLIND_2),
            outputs: &[OUT_0_V],
        },
    );
    check(
        Mode::Voprf,
        k,
        b"",
        &Vector {
            inputs: &[IN_5A],
            blinds: &[BLIND_1],
            blinded: &["cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c"],
            evaluated: &["60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468"],
            proof: Some(
                "401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02",
            ),
            proof_r: Some(BLIND_2),
            outputs: &[OUT_5A_V],
        },
    );
    check(
        Mode::Voprf,
        k,
        b"",
        &Vector {
            inputs: &["00", IN_5A],
            blinds: &[BLIND_1, BLIND_2],
            blinded: &[
                "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",
                "90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654",
            ],
            evaluated: &[
                "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",
                "cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a",
            ],
            proof: Some(
                "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08",
            ),
            proof_r: Some("419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c"),
            outputs: &[OUT_0_V, OUT_5A_V],
        },
    );
}

#[test]
fn poprf_mode() {
    let k = (
        "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07",
        Some("c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"),
    );
    let info = h("7465737420696e666f");
    check(
        Mode::Poprf,
        k,
        &info,
        &Vector {
            inputs: &["00"],
            blinds: &[BLIND_1],
            blinded: &["c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"],
            evaluated: &["1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874"],
            proof: Some(
                "41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100de32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206",
            ),
            proof_r: Some(BLIND_2),
            outputs: &[OUT_0_P],
        },
    );
    check(
        Mode::Poprf,
        k,
        &info,
        &Vector {
            inputs: &[IN_5A],
            blinds: &[BLIND_1],
            blinded: &["f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d"],
            evaluated: &["8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540"],
            proof: Some(
                "4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de77018bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908",
            ),
            proof_r: Some(BLIND_2),
            outputs: &[OUT_5A_P],
        },
    );
    check(
        Mode::Poprf,
        k,
        &info,
        &Vector {
            inputs: &["00", IN_5A],
            blinds: &[BLIND_1, BLIND_2],
            blinded: &[
                "c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715",
                "423a01c072e06eb1cce96d23acce06e1ea64a609d7ec9e9023f3049f2d64e50c",
            ],
            evaluated: &[
                "1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874",
                "aa1f16e903841036e38075da8a46655c94fc92341887eb5819f46312adfc0504",
            ],
            proof: Some(
                "43fdb53be399cbd3561186ae480320caa2b9f36cca0e5b160c4a677b8bbf4301b28f12c36aa8e11e5a7ef551da0781e863a6dc8c0b2bf5a149c9e00621f02006",
            ),
            proof_r: Some("419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c"),
            outputs: &[OUT_0_P, OUT_5A_P],
        },
    );
}
