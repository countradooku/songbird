//! The GIF proxy (Prompt 6, M4, D-0083): the app's request decoder, the provider answer parser
//! and the media token decoder never panic; a token never unwraps to a host outside the
//! provider's.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_api::config::GifSettings;
use songbird_api::gifs::{GifRequest, Gifs, Giphy, Provider as _};

fuzz_target!(|data: &[u8]| {
    let _ = GifRequest::decode(data, true);
    let _ = GifRequest::decode(data, false);
    let giphy = Giphy::new("k".into(), "g".into());
    let _ = giphy.parse(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let g = Gifs::new(GifSettings::default(), Box::new(giphy), &[1; 32]).unwrap();
        if let Some(uri) = g.unwrap_token(s, 1_000) {
            assert!(GifSettings::default().cdn_hosts.iter().any(|h| Some(h.as_str()) == uri.host()));
        }
    }
});
