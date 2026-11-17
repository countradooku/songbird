//! Call signalling and link cards (Prompt 7, M1, D-0086): the call message decoder and validator
//! and the card opener never panic; a card that decodes and validates seals and opens back to
//! itself, and nothing opens under the wrong key.
#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message as _;
use songbird_content::call::{open_card, seal_card_with_nonce, validate, validate_card};
use songbird_content::schema::{CallLinkCard, CallMessage};

const KEY: [u8; 32] = [7; 32];

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = CallMessage::decode(data) {
        let _ = validate(&m);
    }
    let _ = open_card(&KEY, data);
    if let Ok(c) = CallLinkCard::decode(data)
        && validate_card(&c).is_ok()
        && let Ok(sealed) = seal_card_with_nonce(&KEY, &c, [1; 12])
    {
        assert_eq!(open_card(&KEY, &sealed).unwrap(), c);
        assert!(open_card(&[8; 32], &sealed).is_err());
    }
});
