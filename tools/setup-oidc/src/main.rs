use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const APP_NAME: &str = "home-lab";
const SERVICE_NAME: &str = "oidc-service";
const SERVICE_DISPLAY_NAME: &str = "OIDC Identity Provider (Local)";
const SERVICE_DESCRIPTION: &str = "Local OIDC provider for CI/CD and K3S auth";
const FIREWALL_RULE_NAME: &str = "OIDC Local 8443";

fn main() {
    if let Err(err) = run() {
        eprintln!("setup-oidc failed: {err:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let paths = Paths::discover()?;
    println!("[setup-oidc] base dir: {}", paths.base_dir.display());
    fs::create_dir_all(&paths.base_dir)
        .with_context(|| format!("unable to create {}", paths.base_dir.display()))?;

    let key_material = ensure_key_material(&paths)?;
    let config = ensure_config(&paths)?;
    let kid = write_jwks(&paths, &key_material.public_key)?;
    restrict_acl(&paths.private_key_path)?;
    restrict_acl(&paths.certificate_path)?;

    import_certificate(&paths.certificate_path)?;
    ensure_firewall_rule(config.port)?;
    ensure_service()?;

    println!("[setup-oidc] JWKS kid={kid}");
    Ok(())
}

#[derive(Clone)]
struct KeyMaterial {
    public_key: RsaPublicKey,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OidcClient {
    client_id: String,
    client_secret: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OidcConfig {
    issuer: String,
    port: u16,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    clients: Vec<OidcClient>,
}

struct Paths {
    base_dir: PathBuf,
    config_path: PathBuf,
    private_key_path: PathBuf,
    certificate_path: PathBuf,
    jwks_path: PathBuf,
}

impl Paths {
    fn discover() -> Result<Self> {
        let program_data =
            env::var("PROGRAMDATA").unwrap_or_else(|_| String::from(r"C:\\ProgramData"));
        let base_dir = Path::new(&program_data).join(APP_NAME).join("oidc");
        Ok(Self {
            base_dir: base_dir.clone(),
            config_path: base_dir.join("oidc-config.json"),
            private_key_path: base_dir.join("oidc-private-key.pem"),
            certificate_path: base_dir.join("oidc-cert.pem"),
            jwks_path: base_dir.join("oidc-jwks.json"),
        })
    }
}

fn ensure_key_material(paths: &Paths) -> Result<KeyMaterial> {
    if paths.private_key_path.exists() && paths.certificate_path.exists() {
        let private_key = load_private_key(&paths.private_key_path)?;
        Ok(KeyMaterial {
            public_key: private_key.to_public_key(),
        })
    } else {
        let (private_key, cert_pem, key_pem) = generate_certificate()?;
        write_file_atomic(&paths.private_key_path, key_pem.as_bytes())?;
        write_file_atomic(&paths.certificate_path, cert_pem.as_bytes())?;
        println!("[setup-oidc] generated new RSA key pair and certificate");
        Ok(KeyMaterial {
            public_key: private_key.to_public_key(),
        })
    }
}

fn ensure_config(paths: &Paths) -> Result<OidcConfig> {
    if paths.config_path.exists() {
        let raw = fs::read_to_string(&paths.config_path)
            .with_context(|| format!("unable to read {}", paths.config_path.display()))?;
        let config: OidcConfig = serde_json::from_str(&raw)
            .with_context(|| format!("invalid JSON in {}", paths.config_path.display()))?;
        Ok(config)
    } else {
        let secret = random_secret();
        let config = OidcConfig {
            issuer: "https://127.0.0.1:8443".to_string(),
            port: 8443,
            audiences: vec!["kubernetes".to_string(), "local-ci".to_string()],
            clients: vec![OidcClient {
                client_id: "ci-client".to_string(),
                client_secret: secret,
                scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
            }],
        };
        let json = serde_json::to_string_pretty(&config)?;
        write_file_atomic(&paths.config_path, json.as_bytes())?;
        println!(
            "[setup-oidc] wrote default configuration to {}",
            paths.config_path.display()
        );
        Ok(config)
    }
}

fn write_jwks(paths: &Paths, public_key: &RsaPublicKey) -> Result<String> {
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
    let kid = compute_kid(&n, &e);
    let jwks = json!({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": e,
            }
        ]
    });
    let serialized = serde_json::to_string_pretty(&jwks)?;
    write_file_atomic(&paths.jwks_path, serialized.as_bytes())?;
    Ok(jwks["keys"][0]["kid"].as_str().unwrap().to_string())
}

fn restrict_acl(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let status = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("SYSTEM:(R)")
        .arg("Administrators:(R)")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to set ACLs on {}", path.display()))?;
    if !status.success() {
        println!(
            "[setup-oidc] warning: icacls returned status {:?} for {}",
            status.code(),
            path.display()
        );
    }
    Ok(())
}

fn import_certificate(cert_path: &Path) -> Result<()> {
    println!("[setup-oidc] importing certificate {}", cert_path.display());
    let path_str = cert_path.display().to_string();
    let local_machine = format!(
        "Import-Certificate -FilePath \"{}\" -CertStoreLocation \"Cert:\\LocalMachine\\Root\"",
        path_str
    );
    let status = run_powershell(&local_machine)?;
    if status.success() {
        println!("[setup-oidc] certificate added to LocalMachine\\Root");
        return Ok(());
    }
    let current_user = format!(
        "Import-Certificate -FilePath \"{}\" -CertStoreLocation \"Cert:\\CurrentUser\\Root\"",
        path_str
    );
    let status = run_powershell(&current_user)?;
    if status.success() {
        println!("[setup-oidc] certificate added to CurrentUser\\Root");
        return Ok(());
    }
    Err(anyhow!("failed to import certificate"))
}

fn ensure_firewall_rule(port: u16) -> Result<()> {
    let script = format!(
        "$rule = Get-NetFirewallRule -DisplayName \"{name}\" -ErrorAction SilentlyContinue; \
if ($null -eq $rule) {{ New-NetFirewallRule -DisplayName \"{name}\" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow -Profile Any }} else {{ Set-NetFirewallRule -DisplayName \"{name}\" -Enabled True -Action Allow -Profile Any }}",
        name = FIREWALL_RULE_NAME,
        port = port
    );
    let status = run_powershell(&script)?;
    if !status.success() {
        println!(
            "[setup-oidc] warning: unable to configure firewall rule (status {:?})",
            status.code()
        );
    } else {
        println!("[setup-oidc] firewall rule ensured for port {port}");
    }
    Ok(())
}

fn ensure_service() -> Result<()> {
    let service_path = locate_service_binary()?;
    println!("[setup-oidc] service binary: {}", service_path.display());
    if !service_path.exists() {
        return Err(anyhow!(
            "service binary not found at {}",
            service_path.display()
        ));
    }

    let query_status = Command::new("sc.exe")
        .args(["query", SERVICE_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if matches!(query_status, Ok(status) if status.success()) {
        let _ = Command::new("sc.exe")
            .args([
                "config",
                SERVICE_NAME,
                &format!("binPath= \"{}\"", service_path.display()),
                "start= auto",
                &format!("DisplayName= \"{}\"", SERVICE_DISPLAY_NAME),
            ])
            .status();
    } else {
        let status = Command::new("sc.exe")
            .args([
                "create",
                SERVICE_NAME,
                &format!("binPath= \"{}\"", service_path.display()),
                "start= auto",
                &format!("DisplayName= \"{}\"", SERVICE_DISPLAY_NAME),
            ])
            .status()
            .context("failed to create service")?;
        if !status.success() {
            println!(
                "[setup-oidc] warning: sc.exe create returned {:?}",
                status.code()
            );
        }
    }

    let _ = Command::new("sc.exe")
        .args(["description", SERVICE_NAME, SERVICE_DESCRIPTION])
        .status();

    let status = Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .status()
        .context("failed to start service")?;
    if !status.success() {
        println!(
            "[setup-oidc] warning: service start returned {:?}",
            status.code()
        );
    } else {
        println!("[setup-oidc] service started");
    }
    Ok(())
}

fn locate_service_binary() -> Result<PathBuf> {
    let exe_path = env::current_exe().context("unable to determine executable path")?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| anyhow!("setup executable has no parent directory"))?;
    let candidates = [
        exe_dir.join("oidc-service.exe"),
        exe_dir.join("..\\oidc-service.exe"),
        exe_dir.join("..\\bin\\oidc-service.exe"),
        exe_dir.join("..\\..\\bin\\oidc-service.exe"),
    ];
    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(anyhow!(
        "unable to locate oidc-service.exe relative to {}",
        exe_dir.display()
    ))
}

fn run_powershell(script: &str) -> Result<std::process::ExitStatus> {
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .status()
        .with_context(|| "failed to invoke powershell")
}

fn write_file_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    let mut file = fs::File::create(&tmp_path)
        .with_context(|| format!("unable to create temporary file {}", tmp_path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("unable to write {}", tmp_path.display()))?;
    file.sync_all()?;
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "unable to move {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn generate_certificate() -> Result<(RsaPrivateKey, String, String)> {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]);
    params.alg = &rcgen::PKCS_RSA_SHA256;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "127.0.0.1");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * 5);
    params.key_pair = Some(KeyPair::generate(&rcgen::PKCS_RSA_SHA256)?);

    let cert = Certificate::from_params(params)?;
    let key_pem = cert.serialize_private_key_pem();
    let cert_pem = cert.serialize_pem()?;
    let key_der = cert.serialize_private_key_der();
    let private_key = RsaPrivateKey::from_pkcs8_der(&key_der)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(&key_der))
        .context("unable to parse generated private key")?;
    Ok((private_key, cert_pem, key_pem))
}

fn load_private_key(path: &Path) -> Result<RsaPrivateKey> {
    let pem = fs::read_to_string(path)
        .with_context(|| format!("unable to read private key {}", path.display()))?;
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(&pem) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(&pem) {
        return Ok(key);
    }
    Err(anyhow!(
        "unsupported private key format in {}",
        path.display()
    ))
}

fn random_secret() -> String {
    let mut bytes = [0u8; 48];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn compute_kid(n: &str, e: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(n.as_bytes());
    hasher.update(b".");
    hasher.update(e.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&digest[..16])
}
