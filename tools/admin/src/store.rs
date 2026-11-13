//! Connecting to the account registry (SurrealDB) from the operator tool, and the store
//! generation commands of the restore runbook (D-0040).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Args;
use songbird_accounts::{Db, Registry};

/// Where the registry is. The password comes from an environment variable, never a flag (it
/// would land in shell history and the process list).
#[derive(Debug, Clone, Args)]
pub(crate) struct StoreArgs {
    /// SurrealDB RPC `host:port`.
    #[arg(long, default_value = "127.0.0.1:8000")]
    pub(crate) addr: String,
    /// Host name for TLS and the `Host` header.
    #[arg(long, default_value = "localhost")]
    pub(crate) host: String,
    /// PEM CA of the server's TLS certificate (TLS is off without it: loopback only).
    #[arg(long)]
    pub(crate) tls_ca: Option<std::path::PathBuf>,
    /// User.
    #[arg(long, default_value = "root")]
    pub(crate) user: String,
    /// Name of the environment variable that holds the password.
    #[arg(long, default_value = "SURREAL_PASS")]
    pub(crate) pass_env: String,
    /// Namespace.
    #[arg(long, default_value = "songbird")]
    pub(crate) namespace: String,
    /// Database.
    #[arg(long, default_value = "songbird")]
    pub(crate) database: String,
}

impl StoreArgs {
    /// The RPC client configuration.
    pub(crate) fn config(&self) -> Result<songbird_surreal::Config> {
        let pass = std::env::var(&self.pass_env)
            .with_context(|| format!("environment variable {} is not set", self.pass_env))?;
        let tls = match &self.tls_ca {
            None => None,
            Some(path) => {
                use rustls_pki_types::pem::PemObject as _;
                let mut roots = rustls::RootCertStore::empty();
                for c in rustls_pki_types::CertificateDer::pem_file_iter(path)
                    .context("reading the CA")?
                {
                    roots.add(c.context("reading the CA")?)?;
                }
                let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
                Some(Arc::new(
                    rustls::ClientConfig::builder_with_provider(provider)
                        .with_protocol_versions(&[&rustls::version::TLS13])?
                        .with_root_certificates(roots)
                        .with_no_client_auth(),
                ))
            }
        };
        Ok(songbird_surreal::Config {
            addr: self.addr.clone(),
            host: self.host.clone(),
            tls,
            user: self.user.clone(),
            pass,
            namespace: self.namespace.clone(),
            database: self.database.clone(),
            timeout: Duration::from_secs(10),
            max_message_bytes: 16 << 20,
        })
    }

    /// Connects to the registry.
    pub(crate) async fn registry(&self) -> Result<Registry> {
        let db = Db::connect(self.config()?)
            .await
            .context("connecting to SurrealDB")?;
        Registry::connect(db).await.context("opening the registry")
    }
}

/// Prints the store generation.
pub(crate) async fn show(store: &StoreArgs) -> Result<u64> {
    Ok(store.registry().await?.store_generation().await?)
}

/// Bumps the store generation; returns the new value.
pub(crate) async fn bump(store: &StoreArgs) -> Result<u64> {
    Ok(store.registry().await?.bump_store_generation().await?)
}
