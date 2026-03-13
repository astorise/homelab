use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};
use x509_parser::pem::parse_x509_pem;

const ROOT_CA_COMMON_NAME: &str = "Home Lab Root CA";
const ROOT_CA_CERT_FILE: &str = "home-lab-root-ca.pem";
const ROOT_CA_KEY_FILE: &str = "home-lab-root-ca-key.pem";

#[derive(Debug, Clone)]
pub struct RootCaMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ServerCertificateRequest {
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub existing_key_pair_pem: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IssuedServerCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_cert_pem: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStoreLocation {
    LocalMachine,
    CurrentUser,
    AlreadyPresent,
}

#[derive(Debug, Clone)]
pub struct TrustStoreInstallResult {
    pub location: TrustStoreLocation,
    pub detail: String,
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("create temp {}", tmp_path.display()))?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn home_lab_pki_dir() -> PathBuf {
    if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
        return PathBuf::from(program_data).join("home-lab").join("pki");
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data).join("home-lab").join("pki");
    }
    if let Some(temp) = std::env::var_os("TEMP").or_else(|| std::env::var_os("TMP")) {
        return PathBuf::from(temp).join("home-lab").join("pki");
    }
    PathBuf::from(".").join("home-lab").join("pki")
}

pub fn ensure_home_lab_pki_dir() -> Result<PathBuf> {
    let dir = home_lab_pki_dir();
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

pub fn root_ca_cert_path() -> PathBuf {
    home_lab_pki_dir().join(ROOT_CA_CERT_FILE)
}

pub fn root_ca_key_path() -> PathBuf {
    home_lab_pki_dir().join(ROOT_CA_KEY_FILE)
}

pub fn ensure_root_ca() -> Result<RootCaMaterial> {
    let dir = ensure_home_lab_pki_dir()?;
    let cert_path = dir.join(ROOT_CA_CERT_FILE);
    let key_path = dir.join(ROOT_CA_KEY_FILE);

    if cert_path.exists() && key_path.exists() {
        let cert_pem = fs::read_to_string(&cert_path)
            .with_context(|| format!("read {}", cert_path.display()))?;
        let key_pem = fs::read_to_string(&key_path)
            .with_context(|| format!("read {}", key_path.display()))?;
        KeyPair::from_pem(&key_pem).context("load root CA key")?;
        Issuer::from_ca_cert_pem(&cert_pem, KeyPair::from_pem(&key_pem)?)
            .context("load root CA certificate")?;
        return Ok(RootCaMaterial {
            cert_pem,
            key_pem,
            cert_path,
            key_path,
        });
    }

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, ROOT_CA_COMMON_NAME);
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = now_utc() - Duration::days(1);
    params.not_after = now_utc() + Duration::days(3650);

    let key_pair = KeyPair::generate().context("generate root CA key")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign root CA certificate")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    write_atomic(&cert_path, cert_pem.as_bytes())?;
    write_atomic(&key_path, key_pem.as_bytes())?;

    Ok(RootCaMaterial {
        cert_pem,
        key_pem,
        cert_path,
        key_path,
    })
}

pub fn issue_server_certificate(
    request: &ServerCertificateRequest,
) -> Result<IssuedServerCertificate> {
    let root = ensure_root_ca()?;
    let signer = Issuer::from_ca_cert_pem(&root.cert_pem, KeyPair::from_pem(&root.key_pem)?)
        .context("load root CA issuer")?;

    let mut dns_names = BTreeSet::new();
    for dns_name in &request.dns_names {
        let trimmed = dns_name.trim();
        if !trimmed.is_empty() {
            dns_names.insert(trimmed.to_string());
        }
    }

    let mut ip_addresses = BTreeSet::new();
    for ip in &request.ip_addresses {
        ip_addresses.insert(*ip);
    }

    let common_name = request.common_name.trim();
    if common_name.is_empty() {
        return Err(anyhow!("certificate common name is required"));
    }

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_string());
    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.not_before = now_utc() - Duration::days(1);
    params.not_after = now_utc() + Duration::days(825);

    for dns_name in dns_names {
        params
            .subject_alt_names
            .push(SanType::DnsName(dns_name.try_into()?));
    }
    for ip_address in ip_addresses {
        params
            .subject_alt_names
            .push(SanType::IpAddress(ip_address));
    }

    let (key_pair, key_pem) = match request.existing_key_pair_pem.as_ref() {
        Some(existing_key_pair_pem) => (
            KeyPair::from_pem(existing_key_pair_pem).context("load existing key pair")?,
            existing_key_pair_pem.clone(),
        ),
        None => {
            let generated = KeyPair::generate().context("generate server key pair")?;
            let pem = generated.serialize_pem();
            (generated, pem)
        }
    };

    let cert = params
        .signed_by(&key_pair, &signer)
        .context("sign server certificate with root CA")?;

    Ok(IssuedServerCertificate {
        cert_pem: cert.pem(),
        key_pem,
        ca_cert_pem: root.cert_pem,
    })
}

pub fn is_certificate_signed_by_current_root(cert_pem: &str) -> Result<bool> {
    let root = ensure_root_ca()?;
    let (_, leaf_pem) =
        parse_x509_pem(cert_pem.as_bytes()).map_err(|_| anyhow!("parse leaf PEM certificate"))?;
    let leaf_cert = leaf_pem
        .parse_x509()
        .context("parse leaf DER certificate")?;

    let (_, root_pem) = parse_x509_pem(root.cert_pem.as_bytes())
        .map_err(|_| anyhow!("parse root PEM certificate"))?;
    let root_cert = root_pem
        .parse_x509()
        .context("parse root DER certificate")?;

    if leaf_cert.issuer() != root_cert.subject() {
        return Ok(false);
    }

    Ok(leaf_cert
        .verify_signature(Some(root_cert.public_key()))
        .is_ok())
}

#[cfg(windows)]
pub fn ensure_root_ca_installed() -> Result<TrustStoreInstallResult> {
    let root = ensure_root_ca()?;
    let cert_path = root.cert_path.display().to_string().replace('\'', "''");
    let script = format!(
        r#"
$path = '{cert_path}'
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($path)
$thumb = $cert.Thumbprint
if (Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $thumb | Select-Object -First 1) {{
  Write-Output "already-installed:$thumb"
  exit 0
}}
if (Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $thumb | Select-Object -First 1) {{
  Write-Output "already-installed:$thumb"
  exit 0
}}
try {{
  Import-Certificate -FilePath $path -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop | Out-Null
  Write-Output "installed:local-machine:$thumb"
  exit 0
}} catch {{
  Import-Certificate -FilePath $path -CertStoreLocation Cert:\CurrentUser\Root -ErrorAction Stop | Out-Null
  Write-Output "installed:current-user:$thumb"
  exit 0
}}
"#
    );
    let output = std::process::Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(script)
        .output()
        .context("run PowerShell certificate import")?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(anyhow!(
            "root CA import failed with status {}: {}",
            output.status,
            detail
        ));
    }

    let location = if stdout.starts_with("installed:local-machine:") {
        TrustStoreLocation::LocalMachine
    } else if stdout.starts_with("installed:current-user:") {
        TrustStoreLocation::CurrentUser
    } else {
        TrustStoreLocation::AlreadyPresent
    };

    Ok(TrustStoreInstallResult {
        location,
        detail: stdout,
    })
}

#[cfg(not(windows))]
pub fn ensure_root_ca_installed() -> Result<TrustStoreInstallResult> {
    let root = ensure_root_ca()?;
    Ok(TrustStoreInstallResult {
        location: TrustStoreLocation::AlreadyPresent,
        detail: format!("root CA available at {}", root.cert_path.display()),
    })
}
