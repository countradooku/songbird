//! For every vector in `crates/content/vectors/v*/vectors.json`:
//!
//! 1. compile `content.proto` with protox (not prost, not protoc: an independent compiler);
//! 2. parse the hand-written protobuf JSON into a dynamic message of the vector's type;
//! 3. encode it and require exactly the vector's hex (which the Rust types produced);
//! 4. decode the hex back and require the same message, with no unknown fields anywhere.
//!
//! `"@name"` in a bytes field stands for another vector's bytes. A `PaddedPlaintext` is unpadded
//! (`0x80 0x00*`) and checked as a `Plaintext`.
use std::path::Path;

use base64::Engine as _;
use prost::Message as _;
use prost_reflect::{DynamicMessage, MessageDescriptor, ReflectMessage as _, Value};

fn main() {
    // The repository this tool lives in (`tools/content-vectors`), fixed at build time.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let content = root.join("crates/content");
    let pool = protox::compile([content.join("proto/content.proto")], [content.join("proto")])
        .expect("content.proto compiles");
    let pool = prost_reflect::DescriptorPool::from_file_descriptor_set(pool).expect("pool");
    let mut total = 0;
    let mut dirs: Vec<_> = std::fs::read_dir(content.join("vectors"))
        .expect("vectors")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        total += check_dir(&pool, &dir);
    }
    println!("all {total} vectors match content.proto");
}

fn check_dir(pool: &prost_reflect::DescriptorPool, dir: &Path) -> usize {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("vectors.json")).expect("read"))
            .expect("json");
    let vectors = doc["vectors"].as_array().expect("vectors");
    let hex_of = |name: &str| -> String {
        vectors
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("no vector {name}"))["hex"]
            .as_str()
            .expect("hex")
            .to_owned()
    };
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let (ty, mut want) = match v["type"].as_str().expect("type") {
            "Content" => ("Content", hex::decode(v["hex"].as_str().expect("hex")).expect("hex")),
            "PaddedPlaintext" => {
                let padded = hex::decode(v["hex"].as_str().expect("hex")).expect("hex");
                assert!(padded.len() % 160 == 0, "{name}: padded length");
                let end = padded.iter().rposition(|b| *b != 0).expect("marker");
                assert_eq!(padded[end], 0x80, "{name}: padding marker");
                ("Plaintext", padded[..end].to_vec())
            }
            other => panic!("unknown type {other}"),
        };
        let desc: MessageDescriptor = pool
            .get_message_by_name(&format!("songbird.content.v1.{ty}"))
            .expect("message type");
        let mut json = v["message"].clone();
        resolve(&mut json, &hex_of);
        let expected = DynamicMessage::deserialize(desc.clone(), json)
            .unwrap_or_else(|e| panic!("{name}: JSON does not fit content.proto: {e}"));
        let encoded = expected.encode_to_vec();
        assert_eq!(
            hex::encode(&encoded),
            hex::encode(&want),
            "{name}: content.proto encodes the JSON differently from the Rust types"
        );
        let decoded = DynamicMessage::decode(desc, want.as_slice()).expect("decode");
        no_unknown_fields(&decoded, name);
        // Same fields and values: compare the canonical JSON of both (DynamicMessage's own
        // equality also compares how fields were set).
        assert_eq!(
            serde_json::to_value(&decoded).expect("json"),
            serde_json::to_value(&expected).expect("json"),
            "{name}: decoded message differs"
        );
        assert_eq!(decoded.encode_to_vec(), want, "{name}: re-encoding differs");
        want.clear();
        println!("ok {}/{name}", dir.file_name().unwrap().to_string_lossy());
    }
    vectors.len()
}

/// Replaces `"@name"` strings with the base64 of that vector's bytes.
fn resolve(v: &mut serde_json::Value, hex_of: &dyn Fn(&str) -> String) {
    match v {
        serde_json::Value::String(s) if s.starts_with('@') => {
            let bytes = hex::decode(hex_of(&s[1..])).expect("hex");
            *s = base64::engine::general_purpose::STANDARD.encode(bytes);
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| resolve(x, hex_of)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| resolve(x, hex_of)),
        _ => {}
    }
}

fn no_unknown_fields(m: &DynamicMessage, name: &str) {
    assert_eq!(m.unknown_fields().count(), 0, "{name}: unknown fields in {}", m.descriptor().full_name());
    for (_, value) in m.fields() {
        match value {
            Value::Message(inner) => no_unknown_fields(inner, name),
            Value::List(items) => {
                for i in items {
                    if let Value::Message(inner) = i {
                        no_unknown_fields(inner, name);
                    }
                }
            }
            _ => {}
        }
    }
}
