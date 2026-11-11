//! The internal mutual-TLS certificate authority.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256,
};
use songbird_types::config::is_internal_ip;
use songbird_types::dns::is_valid_host;
use time::{Duration, OffsetDateTime};

/// DNS suffix every internal name must end with.
pub(crate) const INTERNAL_DOMAIN: &str = "songbird.internal";
/// Private ranges an internal certificate may name.
const INTERNAL_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "fc00::/7",
    "::1/128",
];
const BACKDATE: Duration = Duration::minutes(5);
const MAX_LEAF_DAYS: u32 = 90;

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::OrganizationName, "Songbird");
    d.push(DnType::CommonName, cn);
    d
}

fn validity(p: &mut CertificateParams, days: u32) {
    let now = OffsetDateTime::now_utc();
    p.not_before = now - BACKDATE;
    p.not_after = now + Duration::days(i64::from(days));
}

fn write_new(path: &Path, contents: &str, private: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut f = opts
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn read(path: &Path) -> Result<String> {
    let meta = fs::metadata(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(meta.len() <= 1024 * 1024, "{} is too large", path.display());
    fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

fn load_issuer(dir: &Path, stem: &str) -> Result<Issuer<'static, KeyPair>> {
    let cert = read(&dir.join(format!("{stem}.crt")))?;
    let key = KeyPair::from_pem(&read(&dir.join(format!("{stem}.key")))?)
        .with_context(|| format!("parse {stem}.key"))?;
    Issuer::from_ca_cert_pem(&cert, key).with_context(|| format!("parse {stem}.crt"))
}

pub(crate) fn init_root(out: &Path, env: &str, days: u32) -> Result<()> {
    ensure!(
        !out.join("root.key").exists(),
        "{} already holds a root CA",
        out.display()
    );
    fs::create_dir_all(out)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(&format!("Songbird internal root CA ({env})"));
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut p, days);
    let cert = p.self_signed(&key)?;
    write_new(&out.join("root.crt"), &cert.pem(), false)?;
    write_new(&out.join("root.key"), &key.serialize_pem(), true)?;
    Ok(())
}

pub(crate) fn init_intermediate(root: &Path, out: &Path, env: &str, days: u32) -> Result<()> {
    let issuer = load_issuer(root, "root")?;
    fs::create_dir_all(out)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(&format!("Songbird internal intermediate CA ({env})"));
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut permitted = vec![GeneralSubtree::DnsName(INTERNAL_DOMAIN.to_owned())];
    for cidr in INTERNAL_CIDRS {
        permitted.push(GeneralSubtree::IpAddress(
            cidr.parse::<CidrSubnet>()
                .map_err(|()| anyhow::anyhow!("bad CIDR {cidr}"))?,
        ));
    }
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: permitted,
        excluded_subtrees: vec![],
    });
    p.use_authority_key_identifier_extension = true;
    validity(&mut p, days);
    let cert = p.signed_by(&key, &issuer)?;
    write_new(&out.join("intermediate.crt"), &cert.pem(), false)?;
    write_new(&out.join("intermediate.key"), &key.serialize_pem(), true)?;
    fs::copy(root.join("root.crt"), out.join("root.crt"))?;
    Ok(())
}

/// Rejects names the intermediate's name constraints would reject anyway, with a clear error.
pub(crate) fn check_san(san: &str) -> Result<()> {
    if let Ok(ip) = san.parse::<IpAddr>() {
        ensure!(
            is_internal_ip(ip),
            "SAN {san} is not a private or loopback address"
        );
        return Ok(());
    }
    let lower = san.to_ascii_lowercase();
    ensure!(
        lower == INTERNAL_DOMAIN || lower.ends_with(&format!(".{INTERNAL_DOMAIN}")),
        "SAN {san} must be under {INTERNAL_DOMAIN}"
    );
    ensure!(
        is_valid_host(lower.as_bytes()),
        "SAN {san} is not a DNS name"
    );
    Ok(())
}

pub(crate) fn issue(ca: &Path, name: &str, sans: &[String], out: &Path, days: u32) -> Result<()> {
    ensure!(
        (1..=MAX_LEAF_DAYS).contains(&days),
        "leaf validity must be 1..={MAX_LEAF_DAYS} days"
    );
    check_san(name)?;
    for s in sans {
        check_san(s)?;
    }
    let issuer = load_issuer(ca, "intermediate")?;
    let intermediate_pem = read(&ca.join("intermediate.crt"))?;
    fs::create_dir_all(out)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut p = CertificateParams::new(sans.to_vec())?;
    p.distinguished_name = dn(name);
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    p.use_authority_key_identifier_extension = true;
    validity(&mut p, days);
    let cert = p.signed_by(&key, &issuer)?;
    // Each file is replaced atomically (write to a temporary name, then rename), so a reader never
    // sees a partial file. Services pick the pair up on the reload that follows `issue`
    // (deploy/ansible/rotate-certs.yml), never between the two renames.
    let leaf_cert = out.join(format!("{name}.crt"));
    let leaf_key = out.join(format!("{name}.key"));
    let tmp_cert = out.join(format!(".{name}.crt.new"));
    let tmp_key = out.join(format!(".{name}.key.new"));
    write_new(&tmp_key, &key.serialize_pem(), true)?;
    write_new(
        &tmp_cert,
        &format!("{}{intermediate_pem}", cert.pem()),
        false,
    )?;
    fs::rename(&tmp_key, &leaf_key)?;
    fs::rename(&tmp_cert, &leaf_cert)?;
    fs::copy(ca.join("root.crt"), out.join("ca.crt"))?;
    Ok(())
}

pub(crate) fn days_left(cert: &Path) -> Result<i64> {
    let pem_text = read(cert)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
        .map_err(|e| anyhow::anyhow!("parse PEM: {e}"))?;
    let x509 = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("parse certificate: {e}"))?;
    let not_after = x509.validity().not_after.timestamp();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if now > not_after {
        bail!("certificate expired");
    }
    Ok((not_after - now) / 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_chain_issues_and_checks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let inter = dir.path().join("inter");
        let leaf = dir.path().join("leaf");
        init_root(&root, "test", 3650).unwrap();
        assert!(
            init_root(&root, "test", 3650).is_err(),
            "must not overwrite a root"
        );
        init_intermediate(&root, &inter, "test", 365).unwrap();
        let name = "delivery.core-1.songbird.internal";
        issue(&inter, name, &[name.into(), "10.0.1.5".into()], &leaf, 30).unwrap();

        let d = days_left(&leaf.join(format!("{name}.crt"))).unwrap();
        assert!((29..=30).contains(&d), "{d}");
        assert!(days_left(&inter.join("intermediate.crt")).unwrap() >= 364);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for k in [
                root.join("root.key"),
                inter.join("intermediate.key"),
                leaf.join(format!("{name}.key")),
            ] {
                assert_eq!(
                    fs::metadata(&k).unwrap().permissions().mode() & 0o777,
                    0o600,
                    "{}",
                    k.display()
                );
            }
        }
        // Chain file holds leaf then intermediate.
        let chain = fs::read_to_string(leaf.join(format!("{name}.crt"))).unwrap();
        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
        // Rotation: issuing again replaces the pair atomically.
        issue(&inter, name, &[name.into()], &leaf, 30).unwrap();
    }

    #[test]
    fn rejects_public_names() {
        assert!(check_san("api.songbird.internal").is_ok());
        assert!(check_san("10.1.2.3").is_ok());
        assert!(check_san("fd00::1").is_ok());
        assert!(check_san("songbird.example").is_err());
        assert!(check_san("evilsongbird.internal").is_err());
        assert!(check_san("203.0.113.5").is_err());
        assert!(check_san("a..songbird.internal").is_err());
    }
}
