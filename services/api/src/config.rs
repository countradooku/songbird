//! `api` configuration (`[api]`), validated at start-up.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use songbird_service::HasCommon;
use songbird_types::SecretRef;
use songbird_types::config::{CommonConfig, Validate, Validator};

/// The configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Shared settings.
    pub common: CommonConfig,
    /// `api` settings; absent in development, the service idles (smoke test without stores).
    #[serde(default)]
    pub api: Option<ApiSettings>,
}

impl HasCommon for ApiConfig {
    fn common(&self) -> &CommonConfig {
        &self.common
    }
}

impl Validate for ApiConfig {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
        let deployed = self.common.environment.is_deployed();
        let Some(api) = &self.api else {
            v.check(!deployed, "api", "is required in staging and production");
            return;
        };
        v.section("api", api);
        if deployed {
            v.check(
                api.tls.is_some(),
                "api.tls",
                "is required in staging and production",
            );
            v.check(
                api.s3.tls_ca.is_some(),
                "api.s3.tls_ca",
                "is required in staging and production",
            );
            v.check(
                api.surrealdb.tls_ca.is_some(),
                "api.surrealdb.tls_ca",
                "is required in staging and production",
            );
            v.check(
                api.valkey_hot.tls() && api.jobs.valkey.tls(),
                "api.valkey_hot.tls_ca",
                "and api.jobs.valkey.tls_ca are required in staging and production",
            );
            v.check(
                api.requests.is_some(),
                "api.requests",
                "is required in staging and production (blocks, message requests)",
            );
            v.check(
                api.reports.is_some(),
                "api.reports",
                "is required in staging and production (reporting)",
            );
            v.check(
                api.media.is_some(),
                "api.media",
                "is required in staging and production (upload budgets, downloads, D-0084)",
            );
            v.check(
                api.calls.is_some(),
                "api.calls",
                "is required in staging and production (calls, D-0085)",
            );
            if let Some(s) = &api.send {
                v.check(
                    s.franking_key.is_some(),
                    "api.send.franking_key",
                    "is required in staging and production (franked sends, reports)",
                );
                v.check(
                    s.valkey.tls(),
                    "api.send.valkey.tls_ca",
                    "is required in staging and production",
                );
            }
        }
    }
}

/// `[api]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSettings {
    /// Public HTTPS listener.
    pub listen: SocketAddr,
    /// The host name devices sign (`api.<domain>`).
    pub server_name: String,
    /// TLS (required outside development).
    #[serde(default)]
    pub tls: Option<TlsSettings>,
    /// The account registry.
    pub surrealdb: songbird_accounts::SurrealSettings,
    /// `valkey-hot`: single-use nonces.
    pub valkey_hot: songbird_valkey::ValkeySettings,
    /// The job queue.
    pub jobs: JobsSettings,
    /// Attachment storage.
    pub s3: S3Settings,
    /// The push service's X25519 public key (64 hex characters; public, not a secret): push
    /// registrations are sealed to it.
    pub push_public_key: String,
    /// 64 hex characters keying push-token rows (shared with `push` and `worker`).
    pub push_index_secret: SecretRef,
    /// Attachment limits.
    #[serde(default)]
    pub attachments: AttachmentLimits,
    /// `[api.media]` (Prompt 6): upload budgets. Absent only in development: uploads then have
    /// no per-account budget.
    #[serde(default)]
    pub media: Option<MediaSettings>,
    /// Account creation for operators and tests (Prompt 3 replaces it with registration).
    #[serde(default)]
    pub admin: Option<AdminSettings>,
    /// Concurrent connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// `PUT /v1/messages` (D-0037, D-0044); absent: the endpoint answers 503.
    #[serde(default)]
    pub send: Option<SendSettings>,
    /// `[api.registration]`: public sign-up, proof of work, invites (Prompt 3, D-0048). Absent:
    /// the registration and invite endpoints answer 503 (accounts only through the admin link).
    #[serde(default)]
    pub registration: Option<RegistrationSettings>,
    /// `[api.usernames]`: usernames, the username key, links (Prompt 3, M2, D-0049). Absent:
    /// those endpoints answer 503.
    #[serde(default)]
    pub usernames: Option<UsernameSettings>,
    /// `[api.keys]`: the key directory (Prompt 3, M3, D-0050). Absent: those endpoints answer
    /// 503.
    #[serde(default)]
    pub keys: Option<KeySettings>,
    /// `[api.profiles]`: encrypted profiles and sealed sender (Prompt 3, M5, D-0054). Absent:
    /// those endpoints answer 503.
    #[serde(default)]
    pub profiles: Option<ProfileSettings>,
    /// `[api.kt]`: key transparency (Prompt 3, M6, D-0055). Absent: those endpoints answer 503.
    #[serde(default)]
    pub kt: Option<KtSettings>,
    /// `[api.requests]` (Prompt 4, D-0062): blocks, the request policy, and the gate of message
    /// requests and broadcasts on `PUT /v1/messages`. Absent: those endpoints answer 503, and
    /// requests and broadcasts over HTTP are refused as unavailable.
    #[serde(default)]
    pub requests: Option<RequestsSettings>,
    /// `[api.reports]` (Prompt 4, D-0063): reporting with message franking. Needs
    /// `[api.requests]` and `[api.send]` (the franking keys). Absent: `POST /v1/reports` answers
    /// 503.
    #[serde(default)]
    pub reports: Option<ReportSettings>,
    /// `[api.calls]` (Prompt 7, D-0085): LiveKit rooms and tokens. Absent: `/v1/calls…` answers
    /// 503.
    #[serde(default)]
    pub calls: Option<songbird_calls::CallSettings>,
}

/// `[api.reports]` (Prompt 4, D-0063).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSettings {
    /// The moderation public key (X25519, 64 hex characters) reports are sealed to. Its private
    /// half stays offline with the moderators (`songbird-admin reports keygen`).
    pub moderation_key: String,
    /// Days a queued report is kept (1 to 90).
    #[serde(default = "default_report_days")]
    pub retention_days: u32,
    /// How old a stamp may be to be reported, in days (1 to 30: undelivered envelopes are kept 30
    /// days at most).
    #[serde(default = "default_report_days")]
    pub window_days: u32,
    /// Reports per hour per reporting account.
    #[serde(default = "default_reports_per_hour")]
    pub per_hour: u32,
    /// Burst of the above.
    #[serde(default = "default_report_burst")]
    pub burst: u32,
}

const fn default_report_days() -> u32 {
    30
}
const fn default_reports_per_hour() -> u32 {
    20
}
const fn default_report_burst() -> u32 {
    10
}

impl Validate for ReportSettings {
    fn validate(&self, v: &mut Validator) {
        let mut k = [0u8; 32];
        v.check(
            hex::decode_to_slice(&self.moderation_key, &mut k).is_ok()
                && songbird_keys::xeddsa::x25519_public_key_ok(&k),
            "moderation_key",
            "must be an X25519 public key (64 hex characters)",
        );
        v.check(
            (1..=90).contains(&self.retention_days),
            "retention_days",
            "must be in 1..=90",
        );
        v.check(
            (1..=30).contains(&self.window_days),
            "window_days",
            "must be in 1..=30",
        );
        v.check(
            (1..=10_000).contains(&self.per_hour) && (1..=10_000).contains(&self.burst),
            "per_hour",
            "and burst must be in 1..=10000",
        );
    }
}

/// `[api.requests]` and `[delivery.requests]` (Prompt 4, D-0062).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestsSettings {
    /// 64 hex characters, the same on every `api` and delivery node: the keys of block rows and
    /// request budgets derive from it.
    pub secret: SecretRef,
    /// The budgets.
    #[serde(default)]
    pub limits: songbird_send::RequestLimits,
}

/// `[api.kt]` (Prompt 3, M6, D-0055).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KtSettings {
    /// 32 bytes (64 hex characters), the same on every `api` node: keys the throttle records.
    pub secret: SecretRef,
    /// The log key's Ed25519 seed (64 hex characters): signs epoch heads; apps pin it.
    pub log_key: SecretRef,
    /// The akd VRF key's seed (64 hex characters), the worker's `kt_vrf_key`: readers need it
    /// to open the directory; apps pin its public key.
    pub vrf_key: SecretRef,
    /// Account and consistency answers per hour per requesting account.
    #[serde(default = "default_profile_fetches")]
    pub fetches_per_hour: u32,
    /// Its burst.
    #[serde(default = "default_profile_fetch_burst")]
    pub fetch_burst: u32,
}

impl Validate for KtSettings {
    fn validate(&self, v: &mut Validator) {
        for (name, n) in [
            ("fetches_per_hour", self.fetches_per_hour),
            ("fetch_burst", self.fetch_burst),
        ] {
            v.check((1..=3_600_000).contains(&n), name, "must be in 1..=3600000");
        }
    }
}

/// `[api.profiles]` (Prompt 3, M5, D-0054).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSettings {
    /// 32 bytes (64 hex characters), the same on every `api` node: keys the throttle records.
    pub secret: SecretRef,
    /// The sender-certificate key's Ed25519 seed (64 hex characters); with `sealed_sender`.
    #[serde(default)]
    pub certificate_key: Option<SecretRef>,
    /// Sealed sender on (the flag Prompt 12 verifies). Off: certificates and sealed sends 404.
    #[serde(default)]
    pub sealed_sender: bool,
    /// Sender certificate lifetime (hours).
    #[serde(default = "default_certificate_hours")]
    pub certificate_hours: u64,
    /// Profile and avatar fetches per hour per requesting account.
    #[serde(default = "default_profile_fetches")]
    pub fetches_per_hour: u32,
    /// Its burst.
    #[serde(default = "default_profile_fetch_burst")]
    pub fetch_burst: u32,
    /// Sealed sends per hour per IP range.
    #[serde(default = "default_sealed")]
    pub sealed_per_hour: u32,
    /// Sealed sends per hour per recipient account.
    #[serde(default = "default_sealed")]
    pub sealed_per_account_hour: u32,
    /// Burst of both.
    #[serde(default = "default_sealed_burst")]
    pub sealed_burst: u32,
    /// IPv4 prefix length of a range.
    #[serde(default = "default_v4")]
    pub ipv4_prefix: u8,
    /// IPv6 prefix length of a range.
    #[serde(default = "default_v6")]
    pub ipv6_prefix: u8,
}

const fn default_certificate_hours() -> u64 {
    24
}
const fn default_profile_fetches() -> u32 {
    600
}
const fn default_profile_fetch_burst() -> u32 {
    120
}
const fn default_sealed() -> u32 {
    3_600
}
const fn default_sealed_burst() -> u32 {
    200
}
const fn default_v4() -> u8 {
    24
}
const fn default_v6() -> u8 {
    48
}

impl Validate for ProfileSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            !self.sealed_sender || self.certificate_key.is_some(),
            "certificate_key",
            "must be set when sealed_sender is on",
        );
        v.check(
            (1..=168).contains(&self.certificate_hours),
            "certificate_hours",
            "must be in 1..=168",
        );
        for (name, n) in [
            ("fetches_per_hour", self.fetches_per_hour),
            ("fetch_burst", self.fetch_burst),
            ("sealed_per_hour", self.sealed_per_hour),
            ("sealed_per_account_hour", self.sealed_per_account_hour),
            ("sealed_burst", self.sealed_burst),
        ] {
            v.check((1..=3_600_000).contains(&n), name, "must be in 1..=3600000");
        }
        v.check(
            (8..=32).contains(&self.ipv4_prefix),
            "ipv4_prefix",
            "must be in 8..=32",
        );
        v.check(
            (16..=128).contains(&self.ipv6_prefix),
            "ipv6_prefix",
            "must be in 16..=128",
        );
    }
}

const fn default_max_connections() -> usize {
    4096
}

impl Validate for ApiSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            songbird_types::dns::is_valid_host(self.server_name.as_bytes()),
            "server_name",
            "must be a DNS host name",
        );
        v.section("surrealdb", &self.surrealdb);
        v.section("valkey_hot", &self.valkey_hot);
        v.section("jobs", &self.jobs);
        v.section("s3", &self.s3);
        v.section("attachments", &self.attachments);
        if let Some(m) = &self.media {
            v.section("media", m);
        }
        if let Some(r) = &self.requests {
            v.section("requests.limits", &r.limits);
        }
        if let Some(r) = &self.reports {
            v.section("reports", r);
            v.check(
                self.requests.is_some()
                    && self.send.as_ref().is_some_and(|s| s.franking_key.is_some()),
                "reports",
                "needs [api.requests] and [api.send] franking_key",
            );
        }
        if let Some(c) = &self.calls {
            v.section("calls", c);
        }
        let mut k = [0u8; 32];
        v.check(
            hex::decode_to_slice(&self.push_public_key, &mut k).is_ok(),
            "push_public_key",
            "must be 64 hex characters",
        );
        if let Some(a) = &self.admin {
            v.section("admin", a);
        }
        v.check(
            (1..=1_000_000).contains(&self.max_connections),
            "max_connections",
            "must be in 1..=1000000",
        );
        if let Some(s) = &self.send {
            v.section("send", s);
        }
        if let Some(r) = &self.registration {
            v.section("registration", r);
        }
        if let Some(u) = &self.usernames {
            v.section("usernames", u);
        }
        if let Some(p) = &self.profiles {
            v.section("profiles", p);
        }
        if let Some(k) = &self.kt {
            v.section("kt", k);
        }
        if let Some(k) = &self.keys {
            v.section("keys", k);
        }
    }
}

/// `[api.tls]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    /// PEM chain, leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
}

/// `[api.jobs]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobsSettings {
    /// `valkey-jobs`.
    pub valkey: songbird_valkey::ValkeySettings,
    /// 64 hex characters sealing jobs.
    pub secret: SecretRef,
}

impl Validate for JobsSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("valkey", &self.valkey);
    }
}

/// `[api.s3]`: `api`'s own least-privilege `RustFS` credential (D-0035).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Settings {
    /// `host:port` (the mutual-TLS tunnel in deployments).
    pub addr: String,
    /// TLS server name (with `tls_ca`).
    #[serde(default)]
    pub tls_domain: Option<String>,
    /// PEM root of the internal CA; TLS is on when set.
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,
    /// Bucket of attachments.
    pub bucket: String,
    /// Access key ID.
    pub access_key: SecretRef,
    /// Secret access key.
    pub secret_key: SecretRef,
}

impl Validate for S3Settings {
    fn validate(&self, v: &mut Validator) {
        v.check(self.addr.contains(':'), "addr", "must be host:port");
        v.check(
            self.tls_ca.is_none() || self.tls_domain.is_some(),
            "tls_domain",
            "is required with tls_ca",
        );
        v.check(
            (3..=63).contains(&self.bucket.len()),
            "bucket",
            "must be 3 to 63 characters",
        );
    }
}

/// `[api.attachments]`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AttachmentLimits {
    /// Largest attachment (padded size), bytes.
    pub max_bytes: u64,
    /// Most recipient fetches one attachment may be granted.
    pub max_fetches: u32,
    /// How long an upload grant stays valid without activity, seconds (each part of a resumable
    /// upload renews it, at most 24 hours after it was issued).
    pub grant_ttl_secs: u64,
    /// Resumable uploads go in parts of this many bytes (the last part is shorter).
    pub part_size: u64,
}

impl Default for AttachmentLimits {
    fn default() -> Self {
        Self {
            // D-0079: 2 GiB, for WhatsApp parity, until Prompt 11's plans set it.
            max_bytes: 2 << 30,
            max_fetches: 1024,
            grant_ttl_secs: 3600,
            // D-0081: 16 MiB, measured against 5 and 64.
            part_size: 16 << 20,
        }
    }
}

impl Validate for AttachmentLimits {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (1..=(5 << 30)).contains(&self.max_bytes),
            "max_bytes",
            "must be in 1..=5 GiB",
        );
        v.check(
            (1..=100_000).contains(&self.max_fetches),
            "max_fetches",
            "must be in 1..=100000",
        );
        v.check(
            (60..=86_400).contains(&self.grant_ttl_secs),
            "grant_ttl_secs",
            "must be in 60..=86400",
        );
        // S3: every part but the last at least 5 MiB, at most 10,000 parts.
        v.check(
            ((5 << 20)..=(512 << 20)).contains(&self.part_size)
                && self.max_bytes.div_ceil(self.part_size) <= 1_000,
            "part_size",
            "must be in 5 MiB..=512 MiB, with max_bytes in at most 1,000 parts (the parts list the server reads)",
        );
    }
}

/// `[api.media]` (Prompt 6, D-0079): the budgets of uploads, and the key of their records.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaSettings {
    /// 32 bytes (64 hex characters), the same on every `api` node: keys the budget records
    /// (and, in later milestones, signed download URLs and GIF tokens).
    pub secret: SecretRef,
    /// Per-account budgets.
    #[serde(default)]
    pub budgets: MediaBudgets,
    /// Downloads.
    #[serde(default)]
    pub downloads: MediaDownloads,
    /// The GIF search proxy (Prompt 6, M4). Absent: the GIF endpoints answer 503.
    #[serde(default)]
    pub gifs: Option<GifSettings>,
}

impl Validate for MediaSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("budgets", &self.budgets);
        v.section("downloads", &self.downloads);
        if let Some(g) = &self.gifs {
            v.section("gifs", g);
        }
    }
}

/// `[api.media.gifs]` (Prompt 6, M4, D-0083): the GIF provider (GIPHY, D-0079 §4) behind the proxy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GifSettings {
    /// The provider's API key (its file or variable).
    pub api_key: Option<SecretRef>,
    /// The API's origin.
    pub base_url: String,
    /// The only hosts media is fetched from (`host` or `host:port`).
    pub cdn_hosts: Vec<String>,
    /// The content rating asked for (`g`, `pg`, `pg-13`, `r`).
    pub rating: String,
    /// Searches per hour per account, and their burst.
    pub searches_per_hour: u32,
    /// Their burst.
    pub search_burst: u32,
    /// Provider requests per second, across the cluster.
    pub provider_per_sec: u32,
    /// Cached answers and files (each).
    pub cache_entries: usize,
    /// How long an answer stays cached, seconds.
    pub cache_ttl_secs: u64,
    /// Bytes of cached files.
    pub media_cache_bytes: u64,
    /// The largest file proxied.
    pub max_media_bytes: u64,
    /// Provider request timeout, seconds.
    pub timeout_secs: u64,
}

impl Default for GifSettings {
    fn default() -> Self {
        Self {
            api_key: None,
            base_url: "https://api.giphy.com".into(),
            cdn_hosts: [
                "media.giphy.com",
                "media0.giphy.com",
                "media1.giphy.com",
                "media2.giphy.com",
                "media3.giphy.com",
                "media4.giphy.com",
                "i.giphy.com",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            rating: "pg-13".into(),
            searches_per_hour: 300,
            search_burst: 60,
            provider_per_sec: 50,
            cache_entries: 4_096,
            cache_ttl_secs: 600,
            media_cache_bytes: 256 << 20,
            max_media_bytes: 8 << 20,
            timeout_secs: 5,
        }
    }
}

impl Validate for GifSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.base_url.parse::<hyper::Uri>().is_ok_and(|u| {
                u.scheme_str() == Some("https")
                    || (u.scheme_str() == Some("http") && u.host() == Some("127.0.0.1"))
            }),
            "base_url",
            "must be https (plain http only to 127.0.0.1, for tests)",
        );
        v.check(
            !self.cdn_hosts.is_empty() && self.cdn_hosts.len() <= 32,
            "cdn_hosts",
            "must name 1 to 32 hosts",
        );
        v.check(
            matches!(self.rating.as_str(), "g" | "pg" | "pg-13" | "r"),
            "rating",
            "must be g, pg, pg-13 or r",
        );
        v.check(
            self.searches_per_hour >= 1 && self.search_burst >= 1 && self.provider_per_sec >= 1,
            "searches_per_hour",
            "budgets must be at least 1",
        );
        v.check(
            (1..=1_000_000).contains(&self.cache_entries)
                && (1..=86_400).contains(&self.cache_ttl_secs)
                && self.media_cache_bytes <= 16 << 30
                && (1..=(64 << 20)).contains(&self.max_media_bytes)
                && (1..=60).contains(&self.timeout_secs),
            "cache_entries",
            "cache and timeout bounds",
        );
    }
}

/// `[api.media.downloads]` (Prompt 6, M3, D-0082): downloads need no account (the object ID is the
/// capability); they are throttled per IP range, in keyed records.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MediaDownloads {
    /// How long a signed media URL works, seconds.
    pub url_ttl_secs: u64,
    /// Download redirects and fetch confirmations per hour per IP range.
    pub per_hour: u32,
    /// Their burst.
    pub burst: u32,
    /// IPv4 prefix length of a range.
    pub ipv4_prefix: u8,
    /// IPv6 prefix length of a range.
    pub ipv6_prefix: u8,
    /// Signed-URL requests (each range a player asks for) per hour per IP range (D-0084).
    pub serve_per_hour: u32,
    /// Their burst.
    pub serve_burst: u32,
}

impl Default for MediaDownloads {
    fn default() -> Self {
        Self {
            url_ttl_secs: 600,
            per_hour: 6_000,
            burst: 600,
            ipv4_prefix: 24,
            ipv6_prefix: 48,
            serve_per_hour: 36_000,
            serve_burst: 3_600,
        }
    }
}

impl Validate for MediaDownloads {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (60..=3_600).contains(&self.url_ttl_secs),
            "url_ttl_secs",
            "must be in 60..=3600",
        );
        v.check(
            (1..=1_000_000).contains(&self.per_hour)
                && (1..=100_000).contains(&self.burst)
                && (1..=10_000_000).contains(&self.serve_per_hour)
                && (1..=1_000_000).contains(&self.serve_burst),
            "per_hour",
            "per_hour must be in 1..=1000000 and burst in 1..=100000",
        );
        v.check(
            (8..=32).contains(&self.ipv4_prefix) && (16..=128).contains(&self.ipv6_prefix),
            "ipv4_prefix",
            "prefixes must be 8..=32 (IPv4) and 16..=128 (IPv6)",
        );
    }
}

/// `[api.media.budgets]`: per account, in keyed `valkey-hot` records (no object is ever linked
/// to an account). Prompt 11's plans will set them per plan.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MediaBudgets {
    /// Upload grants per hour.
    pub grants_per_hour: u32,
    /// Their burst.
    pub grant_burst: u32,
    /// Bytes granted per 24 hours (all may be spent at once).
    pub bytes_per_day: u64,
}

impl Default for MediaBudgets {
    fn default() -> Self {
        // D-0079.
        Self {
            grants_per_hour: 300,
            grant_burst: 60,
            bytes_per_day: 10 << 30,
        }
    }
}

impl Validate for MediaBudgets {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (1..=100_000).contains(&self.grants_per_hour),
            "grants_per_hour",
            "must be in 1..=100000",
        );
        v.check(
            (1..=10_000).contains(&self.grant_burst),
            "grant_burst",
            "must be in 1..=10000",
        );
        v.check(
            ((1 << 20)..=(1 << 40)).contains(&self.bytes_per_day),
            "bytes_per_day",
            "must be in 1 MiB..=1 TiB",
        );
    }
}

/// `[api.admin]`: a node link accepting only `admin.` certificates (internal CA).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSettings {
    /// Listener (private address).
    pub listen: SocketAddr,
    /// This service's name (`api.<host>.songbird.internal`).
    pub node_name: String,
    /// PEM chain, leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
    /// PEM root of the internal CA.
    pub ca: PathBuf,
}

impl Validate for AdminSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.node_name.starts_with("api.") && self.node_name.ends_with(".songbird.internal"),
            "node_name",
            "must be api.<host>.songbird.internal",
        );
        v.check(
            songbird_types::config::is_internal_ip(self.listen.ip()),
            "listen",
            "must be a private or loopback address",
        );
    }
}

/// `[api.send]`: `PUT /v1/messages` through the shared send path (D-0037). `api` owns no mailbox
/// partition: it stores on each partition's owner over node links, admitted there for the store
/// of a send only (D-0044). Everything that must match the delivery nodes is named so.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendSettings {
    /// Frame limits: the delivery nodes' `[delivery.limits]`.
    #[serde(default)]
    pub limits: songbird_send::LimitsConfig,
    /// Sustained sends per second per device: the delivery nodes' `session.sends_per_sec`.
    #[serde(default = "default_sends_per_sec")]
    pub sends_per_sec: u32,
    /// Send burst: the delivery nodes' `session.send_burst`.
    #[serde(default = "default_send_burst")]
    pub send_burst: u32,
    /// Group sends (shared bodies) per second per device: the delivery nodes'
    /// `session.group_sends_per_sec`.
    #[serde(default = "default_group_sends_per_sec")]
    pub group_sends_per_sec: u32,
    /// Group send burst: the delivery nodes' `session.group_send_burst`.
    #[serde(default = "default_group_send_burst")]
    pub group_send_burst: u32,
    /// Iggy stream of the mailbox: the delivery nodes' `mailbox.iggy.stream`.
    pub stream: String,
    /// Iggy topic: the delivery nodes' `mailbox.iggy.topic`.
    pub topic: String,
    /// Partitions: the delivery nodes' `mailbox.iggy.partitions`.
    pub partitions: u32,
    /// The delivery nodes' `mailbox.iggy.idempotency_secret` (64 hex characters), so a retry
    /// over the WebSocket after an HTTP attempt is recognised.
    pub idempotency_secret: SecretRef,
    /// Longest wait for a partition owner's answer, milliseconds.
    #[serde(default = "default_send_timeout_ms")]
    pub timeout_ms: u64,
    /// The delivery nodes' `cluster.lease_ttl_ms`: partition owners are read every third of it.
    #[serde(default = "default_lease_ttl_ms")]
    pub lease_ttl_ms: u64,
    /// This service's node-link identity (`api.<host>.songbird.internal`, internal CA).
    pub node_name: String,
    /// PEM chain, leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
    /// PEM root of the internal CA.
    pub ca: PathBuf,
    /// The router's Valkey (`[delivery.router.valkey]`): routing and the partition leases.
    pub valkey: songbird_valkey::ValkeySettings,
    /// The router's cluster secret (64 hex characters).
    pub cluster_secret: SecretRef,
    /// How often the device directory is checked for changes, milliseconds.
    #[serde(default = "default_directory_poll_ms")]
    pub directory_poll_ms: u64,
    /// At most one push job per device per this window, milliseconds.
    #[serde(default = "default_push_debounce_ms")]
    pub push_debounce_ms: u64,
    /// The delivery nodes' `franking_key` (64 hex characters; Prompt 4, D-0061): franked sends
    /// over HTTP are stamped with it, and reports are verified against it.
    #[serde(default)]
    pub franking_key: Option<SecretRef>,
    /// Earlier franking keys, still accepted when verifying reports (rotation).
    #[serde(default)]
    pub previous_franking_keys: Vec<SecretRef>,
}

const fn default_sends_per_sec() -> u32 {
    50
}
const fn default_group_sends_per_sec() -> u32 {
    10
}
const fn default_group_send_burst() -> u32 {
    40
}
const fn default_send_burst() -> u32 {
    200
}
const fn default_send_timeout_ms() -> u64 {
    5_000
}
const fn default_lease_ttl_ms() -> u64 {
    3_000
}
const fn default_directory_poll_ms() -> u64 {
    1_000
}
const fn default_push_debounce_ms() -> u64 {
    5_000
}

impl Validate for SendSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("limits", &self.limits);
        v.check(
            (1..=1_000).contains(&self.sends_per_sec),
            "sends_per_sec",
            "must be in 1..=1000",
        );
        v.check(
            (1..=100_000).contains(&self.send_burst),
            "send_burst",
            "must be in 1..=100000",
        );
        v.check(
            !self.stream.is_empty() && !self.topic.is_empty(),
            "stream",
            "and topic must be set",
        );
        v.check(
            (1..=4096).contains(&self.partitions),
            "partitions",
            "must be in 1..=4096",
        );
        v.check(
            (100..=60_000).contains(&self.timeout_ms),
            "timeout_ms",
            "must be in 100..=60000",
        );
        v.check(
            (1_000..=60_000).contains(&self.lease_ttl_ms),
            "lease_ttl_ms",
            "must be in 1000..=60000",
        );
        v.check(
            self.node_name.starts_with("api.") && self.node_name.ends_with(".songbird.internal"),
            "node_name",
            "must be api.<host>.songbird.internal",
        );
        v.section("valkey", &self.valkey);
        v.check(
            (100..=60_000).contains(&self.directory_poll_ms),
            "directory_poll_ms",
            "must be in 100..=60000",
        );
        v.check(
            (100..=3_600_000).contains(&self.push_debounce_ms),
            "push_debounce_ms",
            "must be in 100..=3600000",
        );
    }
}

/// `[api.registration]`: public sign-up (`POST /v1/registration`), its proof of work, per-range
/// throttles and invites (Prompt 3, M1, D-0048).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationSettings {
    /// 32 bytes (64 hex characters), the same on every `api` node: authenticates proof-of-work
    /// challenges and keys the IP-range throttle records.
    pub secret: SecretRef,
    /// Invite-only mode (the launch default, D-0038): registration needs a valid invite code.
    /// Switching it off needs no migration.
    #[serde(default = "default_true")]
    pub invite_only: bool,
    /// Invites each new account may create.
    #[serde(default = "default_allowance")]
    pub allowance: u32,
    /// Lifetime of an invite a user creates, days (at most 30).
    #[serde(default = "default_invite_ttl_days")]
    pub invite_ttl_days: u32,
    /// How long a proof-of-work challenge stays valid, seconds.
    #[serde(default = "default_challenge_ttl_secs")]
    pub challenge_ttl_secs: u64,
    /// Proof-of-work verifications running at once (each holds `pow.memory_kib`); 0: half the
    /// cores, at least one.
    #[serde(default)]
    pub max_concurrent_verifications: usize,
    /// The work asked of each registration.
    #[serde(default)]
    pub pow: PowSettings,
    /// Throttles per IP range and across the deployment.
    #[serde(default)]
    pub throttle: ThrottleSettings,
}

const fn default_true() -> bool {
    true
}
const fn default_allowance() -> u32 {
    5
}
const fn default_invite_ttl_days() -> u32 {
    7
}
const fn default_challenge_ttl_secs() -> u64 {
    600
}

impl Validate for RegistrationSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(self.allowance <= 1_000, "allowance", "must be at most 1000");
        v.check(
            (1..=30).contains(&self.invite_ttl_days),
            "invite_ttl_days",
            "must be in 1..=30",
        );
        v.check(
            (60..=3_600).contains(&self.challenge_ttl_secs),
            "challenge_ttl_secs",
            "must be in 60..=3600",
        );
        v.check(
            self.max_concurrent_verifications <= 1_024,
            "max_concurrent_verifications",
            "must be at most 1024",
        );
        v.section("pow", &self.pow);
        v.section("throttle", &self.throttle);
    }
}

/// Argon2id parameters of the registration proof of work. Defaults: 16 MiB, one pass, 8
/// solutions of 4 zero bits (128 evaluations on average): 0.48 s median on an Apple M5 Pro core,
/// a few seconds on a phone (D-0048). Challenges carry their parameters, so retuning needs no
/// client release.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PowSettings {
    /// Memory per evaluation, KiB.
    pub memory_kib: u32,
    /// Passes over memory.
    pub iterations: u32,
    /// Leading zero bits per solution.
    pub bits: u8,
    /// Solutions per challenge.
    pub solutions: u8,
}

impl Default for PowSettings {
    fn default() -> Self {
        Self {
            memory_kib: 16_384,
            iterations: 1,
            bits: 4,
            solutions: 8,
        }
    }
}

impl PowSettings {
    /// As the proof-of-work crate's parameters.
    #[must_use]
    pub fn params(&self) -> songbird_pow::Params {
        songbird_pow::Params {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            bits: self.bits,
            solutions: self.solutions,
        }
    }
}

impl Validate for PowSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.params().in_bounds(),
            "pow",
            "memory_kib 8..=262144, iterations 1..=16, bits 0..=24, solutions 1..=64",
        );
    }
}

/// Generic cell rate limits in `valkey-hot`, on Valkey's clock, per IP range (IPv4 `/24` and
/// IPv6 `/48` by default; carrier-grade NAT puts many people behind one range, so the
/// per-range numbers are generous and the deployment-wide caps are the backstop).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ThrottleSettings {
    /// Challenges per hour per range.
    pub challenges_per_hour: u32,
    /// Challenge burst per range.
    pub challenge_burst: u32,
    /// Registration attempts per hour per range.
    pub registrations_per_hour: u32,
    /// Registration burst per range.
    pub registration_burst: u32,
    /// Refused invite codes per hour per range (after a valid proof of work).
    pub invite_failures_per_hour: u32,
    /// Refused-invite burst per range.
    pub invite_failure_burst: u32,
    /// Registration attempts per hour across the deployment.
    pub global_registrations_per_hour: u32,
    /// Refused invite codes per hour across the deployment.
    pub global_invite_failures_per_hour: u32,
    /// IPv4 prefix length of a range.
    pub ipv4_prefix: u8,
    /// IPv6 prefix length of a range.
    pub ipv6_prefix: u8,
}

impl Default for ThrottleSettings {
    fn default() -> Self {
        Self {
            challenges_per_hour: 120,
            challenge_burst: 30,
            registrations_per_hour: 60,
            registration_burst: 20,
            invite_failures_per_hour: 10,
            invite_failure_burst: 5,
            global_registrations_per_hour: 20_000,
            global_invite_failures_per_hour: 600,
            ipv4_prefix: 24,
            ipv6_prefix: 48,
        }
    }
}

impl Validate for ThrottleSettings {
    fn validate(&self, v: &mut Validator) {
        for (name, rate) in [
            ("challenges_per_hour", self.challenges_per_hour),
            ("registrations_per_hour", self.registrations_per_hour),
            ("invite_failures_per_hour", self.invite_failures_per_hour),
            (
                "global_registrations_per_hour",
                self.global_registrations_per_hour,
            ),
            (
                "global_invite_failures_per_hour",
                self.global_invite_failures_per_hour,
            ),
        ] {
            v.check(
                (1..=3_600_000).contains(&rate),
                name,
                "must be in 1..=3600000",
            );
        }
        for (name, burst) in [
            ("challenge_burst", self.challenge_burst),
            ("registration_burst", self.registration_burst),
            ("invite_failure_burst", self.invite_failure_burst),
        ] {
            v.check(
                (1..=100_000).contains(&burst),
                name,
                "must be in 1..=100000",
            );
        }
        v.check(
            (8..=32).contains(&self.ipv4_prefix),
            "ipv4_prefix",
            "must be in 8..=32",
        );
        v.check(
            (16..=128).contains(&self.ipv6_prefix),
            "ipv6_prefix",
            "must be in 16..=128",
        );
    }
}

/// `[api.usernames]` (Prompt 3, M2, D-0049).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameSettings {
    /// 32 bytes (64 hex characters), the same on every `api` node: the username key's pepper and
    /// the throttle records' key. Never in the database or its backups.
    pub secret: SecretRef,
    /// Usernames nobody may claim, beyond the built-in list (`usernames::RESERVED`).
    #[serde(default)]
    pub reserved: Vec<String>,
    /// Username key verifications at once (each holds `key.memory_kib`); 0: half the cores.
    #[serde(default)]
    pub max_concurrent_key_checks: usize,
    /// Argon2id cost of the username key.
    #[serde(default)]
    pub key: KeyCost,
    /// Throttles.
    #[serde(default)]
    pub throttle: UsernameThrottle,
}

impl Validate for UsernameSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.reserved
                .iter()
                .all(|r| songbird_keys::username::Username::parse(r).is_ok()),
            "reserved",
            "every entry must be a valid username",
        );
        v.check(
            self.max_concurrent_key_checks <= 1_024,
            "max_concurrent_key_checks",
            "must be at most 1024",
        );
        v.section("key", &self.key);
        v.section("throttle", &self.throttle);
    }
}

/// Argon2id cost of a username key verifier. Default 19 MiB, two passes (the OWASP baseline for
/// Argon2id).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KeyCost {
    /// Memory, KiB.
    pub memory_kib: u32,
    /// Passes.
    pub iterations: u32,
}

impl Default for KeyCost {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
        }
    }
}

impl Validate for KeyCost {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (8..=262_144).contains(&self.memory_kib),
            "memory_kib",
            "must be in 8..=262144",
        );
        v.check(
            (1..=16).contains(&self.iterations),
            "iterations",
            "must be in 1..=16",
        );
    }
}

/// Username throttles (GCRA in `valkey-hot` under keyed hashes; fail closed).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UsernameThrottle {
    /// Lookups (and link reads) per hour per account.
    pub lookups_per_hour: u32,
    /// Their burst.
    pub lookup_burst: u32,
    /// Lookups per hour per IP range.
    pub range_lookups_per_hour: u32,
    /// Their burst.
    pub range_lookup_burst: u32,
    /// Username claims per hour per account (attempts, taken or not).
    pub changes_per_hour: u32,
    /// Their burst.
    pub change_burst: u32,
    /// Lookups with a key that find nothing, per hour per username, across every requester.
    pub key_failures_per_hour: u32,
    /// Their burst.
    pub key_failure_burst: u32,
    /// IPv4 prefix length of a range.
    pub ipv4_prefix: u8,
    /// IPv6 prefix length of a range.
    pub ipv6_prefix: u8,
}

impl Default for UsernameThrottle {
    fn default() -> Self {
        Self {
            lookups_per_hour: 120,
            lookup_burst: 30,
            range_lookups_per_hour: 600,
            range_lookup_burst: 100,
            changes_per_hour: 2,
            change_burst: 5,
            key_failures_per_hour: 1,
            key_failure_burst: 10,
            ipv4_prefix: 24,
            ipv6_prefix: 48,
        }
    }
}

impl Validate for UsernameThrottle {
    fn validate(&self, v: &mut Validator) {
        for (name, n) in [
            ("lookups_per_hour", self.lookups_per_hour),
            ("lookup_burst", self.lookup_burst),
            ("range_lookups_per_hour", self.range_lookups_per_hour),
            ("range_lookup_burst", self.range_lookup_burst),
            ("changes_per_hour", self.changes_per_hour),
            ("change_burst", self.change_burst),
            ("key_failures_per_hour", self.key_failures_per_hour),
            ("key_failure_burst", self.key_failure_burst),
        ] {
            v.check((1..=3_600_000).contains(&n), name, "must be in 1..=3600000");
        }
        v.check(
            (8..=32).contains(&self.ipv4_prefix),
            "ipv4_prefix",
            "must be in 8..=32",
        );
        v.check(
            (16..=128).contains(&self.ipv6_prefix),
            "ipv6_prefix",
            "must be in 16..=128",
        );
    }
}

/// `[api.keys]` (Prompt 3, M3, D-0050).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySettings {
    /// 32 bytes (64 hex characters), the same on every `api` node: keys the throttle records.
    pub secret: SecretRef,
    /// The system key's Ed25519 seed (64 hex characters) for "prekeys low" notices (D-0044);
    /// with `[api.send]`. Absent: no notices (clients still see their counts).
    #[serde(default)]
    pub system_key: Option<SecretRef>,
    /// Most one-time prekeys of each kind a device may hold.
    #[serde(default = "default_max_stored")]
    pub max_stored: usize,
    /// A device below this many one-time prekeys of either kind is told to upload more.
    #[serde(default = "default_refill_below")]
    pub refill_below: u32,
    /// Throttles.
    #[serde(default)]
    pub throttle: KeyThrottle,
    /// `[api.keys.devices]`: device linking and the signed device list (Prompt 3, M4, D-0052);
    /// same secret and system key.
    #[serde(default)]
    pub devices: DeviceSettings,
}

/// `[api.keys.devices]` (Prompt 3, M4, D-0052; second factors M4b, D-0053).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeviceSettings {
    /// Most enabled devices per account, primary included (owner, D-0047: primary + 5, until
    /// Prompt 11's plans).
    pub max_devices: u32,
    /// How long a link token stays valid (seconds).
    pub link_token_ttl_secs: u64,
    /// How long a provisioning channel lives (seconds).
    pub channel_ttl_secs: u64,
    /// Longest a provisioning read waits for its message (seconds).
    pub long_poll_secs: u64,
    /// Provisioning channels opened per hour per IP range, and their burst.
    pub channels_per_hour: u32,
    /// Its burst.
    pub channel_burst: u32,
    /// Provisioning reads per hour per IP range (each waits up to `long_poll_secs`).
    pub reads_per_hour: u32,
    /// Its burst.
    pub read_burst: u32,
    /// Link attempts per hour per IP range.
    pub links_per_hour: u32,
    /// Its burst.
    pub link_burst: u32,
    /// Link tokens and provisioning messages per hour per account.
    pub tokens_per_hour: u32,
    /// Its burst.
    pub token_burst: u32,
    /// Device-list fetches per hour per requesting account.
    pub list_fetches_per_hour: u32,
    /// Its burst.
    pub list_fetch_burst: u32,
    /// Argon2id cost of the two-step PIN (with the pepper from the key directory's secret).
    pub pin_cost: KeyCost,
    /// PIN attempts before the lock starts.
    pub pin_free_attempts: u32,
    /// The first lock (seconds); each further wrong attempt doubles it, at most a week.
    pub pin_lock_base_secs: u64,
    /// Attempts after which the PIN is unusable until the primary sets a new one.
    pub pin_max_attempts: u32,
    /// Passkeys per account.
    pub max_passkeys: u32,
    /// The WebAuthn relying party ID (a domain); absent: passkeys answer 503.
    pub rp_id: Option<String>,
    /// Origins passkey ceremonies may come from (`https://…` and the apps' origins).
    pub origins: Vec<String>,
    /// Require the authenticator's user-verified flag.
    pub require_uv: bool,
}

impl Default for DeviceSettings {
    fn default() -> Self {
        Self {
            max_devices: 6,
            link_token_ttl_secs: 600,
            channel_ttl_secs: 600,
            long_poll_secs: 25,
            channels_per_hour: 60,
            channel_burst: 10,
            reads_per_hour: 1_200,
            read_burst: 120,
            links_per_hour: 30,
            link_burst: 10,
            tokens_per_hour: 20,
            token_burst: 10,
            list_fetches_per_hour: 240,
            list_fetch_burst: 60,
            pin_cost: KeyCost::default(),
            pin_free_attempts: 5,
            pin_lock_base_secs: 60,
            pin_max_attempts: 20,
            max_passkeys: 10,
            rp_id: None,
            origins: Vec::new(),
            require_uv: true,
        }
    }
}

impl Validate for DeviceSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            usize::try_from(self.max_devices)
                .is_ok_and(|n| (1..=songbird_proto::devices::MAX_LIST_DEVICES).contains(&n)),
            "max_devices",
            "must be in 1..=16",
        );
        for (name, n) in [
            ("link_token_ttl_secs", self.link_token_ttl_secs),
            ("channel_ttl_secs", self.channel_ttl_secs),
        ] {
            v.check((60..=3_600).contains(&n), name, "must be in 60..=3600");
        }
        v.section("pin_cost", &self.pin_cost);
        v.check(
            (1..=20).contains(&self.pin_free_attempts)
                && self.pin_free_attempts <= self.pin_max_attempts,
            "pin_free_attempts",
            "must be in 1..=20 and at most pin_max_attempts",
        );
        v.check(
            (1..=100).contains(&self.pin_max_attempts),
            "pin_max_attempts",
            "must be in 1..=100",
        );
        v.check(
            (1..=86_400).contains(&self.pin_lock_base_secs),
            "pin_lock_base_secs",
            "must be in 1..=86400",
        );
        v.check(
            (1..=100).contains(&self.max_passkeys),
            "max_passkeys",
            "must be in 1..=100",
        );
        v.check(
            self.rp_id.is_none() || !self.origins.is_empty(),
            "origins",
            "must list at least one origin when rp_id is set",
        );
        v.check(
            (1..=55).contains(&self.long_poll_secs),
            "long_poll_secs",
            "must be in 1..=55",
        );
        for (name, n) in [
            ("channels_per_hour", self.channels_per_hour),
            ("channel_burst", self.channel_burst),
            ("reads_per_hour", self.reads_per_hour),
            ("read_burst", self.read_burst),
            ("links_per_hour", self.links_per_hour),
            ("link_burst", self.link_burst),
            ("tokens_per_hour", self.tokens_per_hour),
            ("token_burst", self.token_burst),
            ("list_fetches_per_hour", self.list_fetches_per_hour),
            ("list_fetch_burst", self.list_fetch_burst),
        ] {
            v.check((1..=3_600_000).contains(&n), name, "must be in 1..=3600000");
        }
    }
}

const fn default_max_stored() -> usize {
    200
}
const fn default_refill_below() -> u32 {
    10
}

impl Validate for KeySettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (1..=1_000).contains(&self.max_stored),
            "max_stored",
            "must be in 1..=1000",
        );
        v.check(
            self.refill_below <= 1_000,
            "refill_below",
            "must be at most 1000",
        );
        v.section("throttle", &self.throttle);
        v.section("devices", &self.devices);
    }
}

/// Key directory throttles (GCRA in `valkey-hot` under keyed hashes; fail closed).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KeyThrottle {
    /// Fetches per hour per requesting account.
    pub fetches_per_hour: u32,
    /// Their burst.
    pub fetch_burst: u32,
    /// Fetches per hour per IP range.
    pub range_fetches_per_hour: u32,
    /// Their burst.
    pub range_fetch_burst: u32,
    /// Fetches per hour per target account that may claim one-time prekeys, across all
    /// requesters; beyond it a fetch gets last-resort keys only.
    pub target_one_time_per_hour: u32,
    /// Its burst.
    pub target_one_time_burst: u32,
    /// IPv4 prefix length of a range.
    pub ipv4_prefix: u8,
    /// IPv6 prefix length of a range.
    pub ipv6_prefix: u8,
}

impl Default for KeyThrottle {
    fn default() -> Self {
        Self {
            fetches_per_hour: 240,
            fetch_burst: 60,
            range_fetches_per_hour: 1_200,
            range_fetch_burst: 200,
            target_one_time_per_hour: 60,
            target_one_time_burst: 30,
            ipv4_prefix: 24,
            ipv6_prefix: 48,
        }
    }
}

impl Validate for KeyThrottle {
    fn validate(&self, v: &mut Validator) {
        for (name, n) in [
            ("fetches_per_hour", self.fetches_per_hour),
            ("fetch_burst", self.fetch_burst),
            ("range_fetches_per_hour", self.range_fetches_per_hour),
            ("range_fetch_burst", self.range_fetch_burst),
            ("target_one_time_per_hour", self.target_one_time_per_hour),
            ("target_one_time_burst", self.target_one_time_burst),
        ] {
            v.check((1..=3_600_000).contains(&n), name, "must be in 1..=3600000");
        }
        v.check(
            (8..=32).contains(&self.ipv4_prefix),
            "ipv4_prefix",
            "must be in 8..=32",
        );
        v.check(
            (16..=128).contains(&self.ipv6_prefix),
            "ipv6_prefix",
            "must be in 16..=128",
        );
    }
}
