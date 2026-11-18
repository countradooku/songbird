//! Push credentials can be configured in the push service only (Prompt 8, D-0097): every other
//! service's configuration refuses a provider section, at the top level and inside its own
//! section, so a provider key cannot be handed to it even by mistake. (`worker` and `calls`
//! check the same in their own crates; their configuration types are private.)
#![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

use songbird_api::config::ApiConfig;
use songbird_delivery::config::DeliveryConfig;
use songbird_types::ConfigError;
use songbird_types::config::load_from_parts;

const PROVIDERS: [(&str, &str); 4] = [
    (
        "apns",
        r#"{ key = { file = "/run/songbird/secrets/apns_key.p8" } }"#,
    ),
    (
        "fcm",
        r#"{ service_account = { file = "/run/songbird/secrets/fcm.json" } }"#,
    ),
    (
        "webpush",
        r#"{ vapid_key = { file = "/run/songbird/secrets/vapid_key.pem" } }"#,
    ),
    ("push_key", r#"{ file = "/run/songbird/secrets/push_key" }"#),
];

/// The configuration texts that try to hand a provider credential to `section`'s service.
fn attempts(section: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for (name, value) in PROVIDERS {
        out.push((
            name,
            format!(
                "{name} = {value}\n[common]\nenvironment = \"dev\"\nadmin_listen = \"127.0.0.1:9100\"\n"
            ),
        ));
        out.push((
            name,
            format!(
                "[common]\nenvironment = \"dev\"\nadmin_listen = \"127.0.0.1:9100\"\n[{section}]\n{name} = {value}\n"
            ),
        ));
    }
    out
}

fn assert_refused<T: std::fmt::Debug>(section: &str, name: &str, r: Result<T, ConfigError>) {
    match r {
        Err(ConfigError::Parse(e)) => {
            assert!(
                e.contains(name),
                "{section}: `{name}` refused for another reason: {e}"
            );
        }
        other => panic!("{section} accepted `{name}`: {other:?}"),
    }
}

#[test]
fn api_refuses_push_credentials() {
    for (name, text) in attempts("api") {
        let r = load_from_parts::<ApiConfig, _>(&text, Vec::<(String, String)>::new(), "SONGBIRD");
        assert_refused("api", name, r);
    }
}

#[test]
fn delivery_refuses_push_credentials() {
    for (name, text) in attempts("delivery") {
        let r =
            load_from_parts::<DeliveryConfig, _>(&text, Vec::<(String, String)>::new(), "SONGBIRD");
        assert_refused("delivery", name, r);
    }
}
