//! A SurrealDB handle that reconnects (the RPC client closes on any connection failure and
//! leaves reconnecting to its owner, D-0025), and the shared `[*.surrealdb]` settings.

use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use serde::Deserialize;
use songbird_surreal::{Client, Config, RpcError, Value};
use songbird_types::config::{Validate, Validator};
use songbird_types::secret::SecretRef;

/// `[*.surrealdb]`: where the registry lives.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurrealSettings {
    /// `host:port` of the RPC endpoint.
    pub addr: String,
    /// Host name for TLS and the `Host` header.
    pub host: String,
    /// PEM CA certificate for the server's TLS (required outside development).
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,
    /// User.
    pub user: String,
    /// Password.
    pub pass: SecretRef,
    /// Namespace.
    #[serde(default = "default_ns")]
    pub namespace: String,
    /// Database.
    #[serde(default = "default_ns")]
    pub database: String,
    /// Connect and per-request timeout.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_ns() -> String {
    "songbird".into()
}

const fn default_timeout_ms() -> u64 {
    5_000
}

impl Validate for SurrealSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            songbird_types::dns::is_valid_host(self.host.as_bytes()),
            "host",
            "must be a DNS host name",
        );
        v.check(!self.addr.is_empty(), "addr", "must be host:port");
        v.check(
            (100..=60_000).contains(&self.timeout_ms),
            "timeout_ms",
            "must be in 100..=60000",
        );
    }
}

impl SurrealSettings {
    /// Reads the CA and password and builds the client configuration.
    ///
    /// # Errors
    /// A file or secret could not be read.
    pub fn config(&self) -> Result<Config, DbError> {
        let tls = match &self.tls_ca {
            None => None,
            Some(path) => {
                let file = std::fs::File::open(path).map_err(|_| DbError::Settings("tls_ca"))?;
                let mut roots = rustls::RootCertStore::empty();
                for cert in CertificateDer::pem_reader_iter(BufReader::new(file)) {
                    roots
                        .add(cert.map_err(|_| DbError::Settings("tls_ca"))?)
                        .map_err(|_| DbError::Settings("tls_ca"))?;
                }
                let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
                let cfg = rustls::ClientConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|_| DbError::Settings("tls"))?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                Some(Arc::new(cfg))
            }
        };
        Ok(Config {
            addr: self.addr.clone(),
            host: self.host.clone(),
            tls,
            user: self.user.clone(),
            pass: self
                .pass
                .resolve()
                .map_err(|_| DbError::Settings("pass"))?
                .expose()
                .to_owned(),
            namespace: self.namespace.clone(),
            database: self.database.clone(),
            timeout: Duration::from_millis(self.timeout_ms),
            max_message_bytes: 16 << 20,
        })
    }
}

/// Database failures. Server messages can quote data: only kinds are shown.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Settings could not be read.
    #[error("surrealdb settings: cannot read {0}")]
    Settings(&'static str),
    /// Connection or request failure.
    #[error("surrealdb: {0}")]
    Rpc(#[from] RpcError),
    /// A statement failed (its kind; the message is never shown).
    #[error("surrealdb statement failed ({0})")]
    Statement(String),
}

/// Connects, retrying a few times when SurrealDB reports a transaction conflict: signing in
/// and selecting a namespace and database that several clients create at the same moment
/// conflict, and the server says to retry (found by the parallel CI run).
async fn connect_retrying(cfg: &Config) -> Result<Client, RpcError> {
    let mut delay = Duration::from_millis(20);
    for _ in 0..5 {
        match Client::connect(cfg).await {
            Err(RpcError::Server { code, .. })
                if code == songbird_surreal::CODE_TRANSACTION_CONFLICT =>
            {
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            r => return r,
        }
    }
    Client::connect(cfg).await
}

/// A reconnecting SurrealDB handle.
pub struct Db {
    cfg: Config,
    current: tokio::sync::Mutex<Option<Client>>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl Db {
    /// Connects now (a bad address or password fails at start-up).
    ///
    /// # Errors
    /// [`DbError`].
    pub async fn connect(cfg: Config) -> Result<Self, DbError> {
        let c = connect_retrying(&cfg).await?;
        Ok(Self {
            cfg,
            current: tokio::sync::Mutex::new(Some(c)),
        })
    }

    async fn client(&self) -> Result<Client, DbError> {
        let mut cur = self.current.lock().await;
        if let Some(c) = cur.as_ref()
            && !c.is_closed()
        {
            return Ok(c.clone());
        }
        let c = connect_retrying(&self.cfg).await?;
        *cur = Some(c.clone());
        Ok(c)
    }

    /// Runs `SurrealQL`; returns every statement's result. Any failed statement fails the call
    /// (with the first failure's kind, skipping the "not executed" ones a failed transaction
    /// adds). A dropped connection is replaced on the next call.
    ///
    /// # Errors
    /// [`DbError`].
    pub async fn query(
        &self,
        sql: &str,
        vars: Vec<(String, Value)>,
    ) -> Result<Vec<Value>, DbError> {
        let c = self.client().await?;
        let results = c.query(sql, vars).await?;
        let mut out = Vec::with_capacity(results.len());
        // The real cause wins over the "not executed" cancellations a failed transaction adds.
        let mut cause: Option<String> = None;
        let mut cancelled: Option<String> = None;
        for r in results {
            match r {
                Ok(v) => out.push(v),
                Err(e) => {
                    // The message itself is never shown; an existing record is told apart by kind.
                    let kind = if e.message.contains("already exists") {
                        "AlreadyExists".to_owned()
                    } else {
                        e.kind.clone()
                    };
                    if e.message.contains("not executed")
                        || e.message.contains("failed transaction")
                    {
                        cancelled.get_or_insert(kind);
                    } else {
                        cause.get_or_insert(kind);
                    }
                    out.push(Value::Null);
                }
            }
        }
        let failure = cause.or(cancelled);
        match failure {
            Some(kind) => Err(DbError::Statement(kind)),
            None => Ok(out),
        }
    }

    /// Runs `SurrealQL` and returns the first statement's result.
    ///
    /// # Errors
    /// [`DbError`].
    pub async fn query1(&self, sql: &str, vars: Vec<(String, Value)>) -> Result<Value, DbError> {
        Ok(self
            .query(sql, vars)
            .await?
            .into_iter()
            .next()
            .unwrap_or(Value::Null))
    }

    /// Runs `SurrealQL`, ignoring results.
    ///
    /// # Errors
    /// [`DbError`].
    pub async fn exec(&self, sql: &str, vars: Vec<(String, Value)>) -> Result<(), DbError> {
        self.query(sql, vars).await.map(|_| ())
    }
}
