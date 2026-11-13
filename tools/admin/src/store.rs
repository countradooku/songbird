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
    /// The user is defined on the database (`DEFINE USER … ON DATABASE`), not at the root: the
    /// backup timer's read-only `VIEWER` user. Only `backup run` accepts one.
    #[arg(long)]
    pub(crate) database_user: bool,
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
        anyhow::ensure!(
            !self.database_user,
            "--database-user works with `backup run` only (an export needs no more)"
        );
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

/// Registers every device of a static directory file (`[[devices]] id, auth_key`, as
/// `songbird-loadgen keys` writes it) as an account of its own: development and drills only,
/// until Prompt 3's registration. Returns how many were created (existing ones are skipped).
pub(crate) async fn import_directory(store: &StoreArgs, file: &std::path::Path) -> Result<usize> {
    #[derive(serde::Deserialize)]
    struct Dir {
        devices: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        id: String,
        auth_key: String,
    }
    let text = std::fs::read_to_string(file).context("reading the directory")?;
    let dir: Dir = toml::from_str(&text).context("parsing the directory")?;
    let registry = store.registry().await?;
    let mut created = 0;
    for e in dir.devices {
        let device = songbird_types::DeviceId::parse_hex(&e.id).context("device id")?;
        let mut key = [0u8; 32];
        hex::decode_to_slice(&e.auth_key, &mut key).context("auth key")?;
        // The device forms an account of its own (as the static directory does).
        let account = songbird_types::AccountId::from_bytes(*device.as_bytes());
        match registry.create_account(&account, &[(device, key)]).await {
            Ok(()) => created += 1,
            Err(songbird_accounts::RegistryError::Exists) => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(created)
}
