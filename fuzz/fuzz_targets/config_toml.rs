//! Configuration loader on arbitrary TOML and overrides: errors, never panics.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_types::config::{CommonConfig, Validate, Validator, load_from_parts};

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct C {
    common: CommonConfig,
}
impl Validate for C {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    // First line is an environment override value, the rest is the file.
    let (env_val, text) = s.split_once('\n').unwrap_or(("", s));
    let env = vec![("SB__COMMON__LOG__FILTER".to_owned(), env_val.to_owned())];
    let _ = load_from_parts::<C, _>(text, env, "SB");
});
