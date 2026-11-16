//! Encrypted content (Prompt 4, M1): what apps decode after decryption. The padded-plaintext and
//! content decoders never panic, and whatever opens seals again to the same content.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(o) = songbird_content::open(data) {
        let (padded, commit) = songbird_content::seal(&o.content, o.franking_key).expect("valid");
        let again = songbird_content::open(&padded).expect("reopens");
        assert_eq!(again.content, o.content);
        if let Some(c) = commit {
            assert!(again.franking_matches(&c));
        }
    }
    let _ = songbird_content::decode_content(data);
});
