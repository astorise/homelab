use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

use crate::dns;
use crate::http;
use crate::oidc::{
    oidc_get_status, oidc_list_clients, register_client_config, ClientOut, RegisterClientIn,
    StatusOut,
};
use anyhow::{anyhow, Context, Result};
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::RsaPrivateKey;
use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, Manager};
use tracing::{error, info, warn};

#[derive(Serialize)]
pub struct ProvisionResult {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
pub struct WslOperationResult {
    ok: bool,
    message: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct WslInstance {
    name: String,
    state: String,
    version: Option<String>,
    is_default: bool,
    cluster: Option<WslClusterStatus>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ClusterOidcInfo {
    present: bool,
    client_id: Option<String>,
    scopes: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ClusterRouteBinding {
    host: String,
    port: u16,
}

#[derive(Serialize, Clone, Debug)]
pub struct ClusterProxyInfo {
    inbound_http: u16,
    inbound_https: u16,
    routes: Vec<ClusterRouteBinding>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ClusterDnsEntry {
    name: String,
    a: Vec<String>,
    ttl: Option<u32>,
}

#[derive(Serialize, Clone, Debug)]
pub struct WslClusterStatus {
    domains: Vec<String>,
    proxy: ClusterProxyInfo,
    api_port: u16,
    dns_records: Vec<ClusterDnsEntry>,
    oidc: ClusterOidcInfo,
}

const DEFAULT_DOMAIN_TEMPLATE: &str = "{name}.wsl";
const ENV_DOMAIN_TEMPLATES: &str = "HOME_LAB_WSL_DOMAIN_TEMPLATES";
const DEFAULT_DNS_TARGET: &str = "127.0.0.1";
const ENV_DNS_TARGET: &str = "HOME_LAB_WSL_DNS_TARGET";
const DEFAULT_DNS_TTL: u32 = 60;
const ENV_DNS_TTL: &str = "HOME_LAB_WSL_DNS_TTL";
const DEFAULT_HTTP_PORT_BASE: u16 = 8080;
const DEFAULT_HTTP_PORT_STEP: u16 = 1000;
const DEFAULT_HTTP_PORT_MAX: u16 = 60000;
const ENV_HTTP_PORT_BASE: &str = "HOME_LAB_WSL_HTTP_PORT_BASE";
const ENV_HTTP_PORT_STEP: &str = "HOME_LAB_WSL_HTTP_PORT_STEP";
const ENV_HTTP_PORT_MAX: &str = "HOME_LAB_WSL_HTTP_PORT_MAX";
const DEFAULT_HTTP_INBOUND: u16 = 80;
const DEFAULT_HTTPS_INBOUND: u16 = 443;
const ENV_HTTP_INBOUND: &str = "HOME_LAB_WSL_HTTP_INBOUND";
const ENV_HTTPS_INBOUND: &str = "HOME_LAB_WSL_HTTPS_INBOUND";
const DEFAULT_API_PORT: u16 = 6443;
const ENV_API_PORT: &str = "HOME_LAB_WSL_K3S_API_PORT";
const SERVICE_RPC_RETRIES: usize = 8;
const SERVICE_RPC_BASE_DELAY_MS: u64 = 750;
const HTTP_SERVICE_NAME: &str = "HomeHttpService";
const DNS_SERVICE_NAME: &str = "HomeDnsService";

fn env_or_default_u16(var: &str, default: u16) -> u16 {
    match std::env::var(var) {
        Ok(value) => value
            .trim()
            .parse::<u16>()
            .map_err(|_| {
                warn!(
                    target: "wsl",
                    variable = var,
                    value = %value,
                    "Valeur u16 invalide, utilisation de la valeur par defaut"
                )
            })
            .unwrap_or(default),
        Err(_) => default,
    }
}

fn env_or_default_u32(var: &str, default: u32) -> u32 {
    match std::env::var(var) {
        Ok(value) => value
            .trim()
            .parse::<u32>()
            .map_err(|_| {
                warn!(
                    target: "wsl",
                    variable = var,
                    value = %value,
                    "Valeur u32 invalide, utilisation de la valeur par defaut"
                )
            })
            .unwrap_or(default),
        Err(_) => default,
    }
}

fn cluster_domain_templates() -> Vec<String> {
    if let Ok(raw) = std::env::var(ENV_DOMAIN_TEMPLATES) {
        let templates: Vec<String> = raw
            .split(|c| c == ',' || c == ';')
            .map(|chunk| chunk.trim())
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| chunk.to_string())
            .collect();
        if !templates.is_empty() {
            return templates;
        }
    }
    vec![DEFAULT_DOMAIN_TEMPLATE.to_string()]
}

fn cluster_domain_slug(source: &str) -> String {
    let mut slug = String::new();
    let trimmed = source.trim();
    let lower = trimmed.to_ascii_lowercase();
    let mut last_dash = false;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_dash = false;
        } else if matches!(ch, '-' | '_' | '.' | ' ') {
            if !slug.is_empty() && !last_dash {
                slug.push('-');
                last_dash = true;
            }
        }
    }
    let mut slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        slug = "cluster".into();
    }
    if slug.len() > 63 {
        slug.truncate(63);
    }
    slug
}

fn normalize_domain(candidate: &str) -> Option<String> {
    let mut labels = Vec::new();
    for raw_label in candidate.split('.') {
        let mut label = String::new();
        for ch in raw_label.chars() {
            let lower = ch.to_ascii_lowercase();
            if lower.is_ascii_alphanumeric() {
                label.push(lower);
            } else if matches!(lower, '-' | '_' | ' ') {
                if !label.ends_with('-') {
                    label.push('-');
                }
            }
        }
        let label = label.trim_matches('-').to_string();
        if !label.is_empty() {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn cluster_domains(instance: &str) -> Vec<String> {
    let slug = cluster_domain_slug(instance);
    let templates = cluster_domain_templates();
    let mut result = Vec::new();
    for tpl in templates {
        let rendered = if tpl.contains("{name}") {
            tpl.replace("{name}", &slug)
        } else {
            format!("{slug}{tpl}")
        };
        if let Some(domain) = normalize_domain(&rendered) {
            if !result
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(domain.as_str()))
            {
                result.push(domain);
            }
        }
    }
    result
}

fn dns_target_ipv4() -> String {
    std::env::var(ENV_DNS_TARGET)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_DNS_TARGET.to_string())
}

fn dns_record_ttl() -> u32 {
    let ttl = env_or_default_u32(ENV_DNS_TTL, DEFAULT_DNS_TTL);
    ttl.max(1)
}

fn http_port_base() -> u16 {
    env_or_default_u16(ENV_HTTP_PORT_BASE, DEFAULT_HTTP_PORT_BASE)
}

fn http_port_step() -> u16 {
    let step = env_or_default_u16(ENV_HTTP_PORT_STEP, DEFAULT_HTTP_PORT_STEP);
    if step == 0 {
        DEFAULT_HTTP_PORT_STEP
    } else {
        step
    }
}

fn http_port_max() -> u16 {
    env_or_default_u16(ENV_HTTP_PORT_MAX, DEFAULT_HTTP_PORT_MAX)
}

fn inbound_http_port() -> u16 {
    env_or_default_u16(ENV_HTTP_INBOUND, DEFAULT_HTTP_INBOUND)
}

fn inbound_https_port() -> u16 {
    env_or_default_u16(ENV_HTTPS_INBOUND, DEFAULT_HTTPS_INBOUND)
}

fn k3s_api_port() -> u16 {
    env_or_default_u16(ENV_API_PORT, DEFAULT_API_PORT)
}

fn pick_http_port(used_ports: &HashSet<u16>) -> Result<u16> {
    let base = http_port_base();
    let step = http_port_step();
    let max = http_port_max();
    let mut candidate = base;
    while candidate <= max {
        if !used_ports.contains(&candidate) {
            return Ok(candidate);
        }
        match candidate.checked_add(step) {
            Some(next) if next > candidate => {
                candidate = next;
            }
            _ => break,
        }
    }
    Err(anyhow!(
        "Aucun port HTTP disponible dans la plage configuree ({base}-{max})."
    ))
}

async fn configure_cluster_networking(instance: &str) -> Result<String> {
    let hosts = cluster_domains(instance);
    if hosts.is_empty() {
        anyhow::bail!("Aucun nom de domaine valide pour l'instance {instance}");
    }

    let routes = retry_http_rpc("list_routes", || http::http_list_routes())
        .await?
        .routes;

    let mut used_ports: HashSet<u16> = HashSet::new();
    for route in &routes {
        if let Ok(port) = u16::try_from(route.port) {
            used_ports.insert(port);
        } else {
            warn!(
                target: "wsl",
                host = %route.host,
                port = route.port,
                "Port HTTP invalide (hors plage u16) ignore pour la selection"
            );
        }
    }

    let mut selected_port = None;
    for route in &routes {
        if hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(&route.host))
        {
            if let Ok(existing) = u16::try_from(route.port) {
                selected_port = Some(existing);
                break;
            }
        }
    }

    let http_port = match selected_port {
        Some(port) => port,
        None => pick_http_port(&used_ports)?,
    };

    let mut applied_hosts = Vec::new();
    for host in &hosts {
        retry_http_rpc("add_route", || {
            http::http_add_route(host.clone(), http_port as u32)
        })
        .await
        .map_err(|e| anyhow!("http_add_route({host}): {e}"))?;
        applied_hosts.push(host.clone());
    }

    let dns_ip = dns_target_ipv4();
    let ttl = dns_record_ttl();
    for host in &hosts {
        retry_dns_rpc("add_record", || {
            dns::dns_add_record(host.clone(), "A".into(), dns_ip.clone(), ttl)
        })
        .await
        .map_err(|e| anyhow!("dns_add_record({host}): {e}"))?;
    }

    info!(
        target: "wsl",
        instance = %instance,
        hosts = %applied_hosts.join(","),
        http_port,
        dns_ip = %dns_ip,
        ttl,
        "Configuration DNS/HTTP appliquee pour l'instance WSL"
    );
    log_wsl_event(format!(
        "Configuration DNS/HTTP pour {}: hosts={} port={} ip={} ttl={}",
        escape_for_log(instance),
        escape_for_log(&applied_hosts.join(",")),
        http_port,
        escape_for_log(&dns_ip),
        ttl
    ));

    Ok(format!(
        "DNS/HTTP configures pour {} (port {}).",
        applied_hosts.join(", "),
        http_port
    ))
}

async fn start_service_if_needed(service_name: &str) {
    let name = service_name.to_string();
    let name_log = escape_for_log(&name);
    let result = tauri::async_runtime::spawn_blocking(move || {
        Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(format!(
                "Try {{ $svc = Get-Service -Name '{name}' -ErrorAction Stop; if ($svc.Status -ne 'Running') {{ Start-Service -Name '{name}' -ErrorAction Stop; Write-Output 'started' }} else {{ Write-Output 'already-running' }} }} Catch {{ Write-Output ('error: ' + $_.Exception.Message) }}",
            ))
            .output()
    })
    .await;

    match result {
        Ok(Ok(output)) => {
            let stdout = decode_cli_output(&output.stdout);
            let stderr = decode_cli_output(&output.stderr);
            let stdout_trim = stdout.trim();
            let stderr_trim = stderr.trim();
            if !output.status.success() || stdout_trim.starts_with("error:") {
                warn!(
                    target: "wsl",
                    service = %name_log,
                    status = %output.status,
                    stdout = %escape_for_log(stdout_trim),
                    stderr = %escape_for_log(stderr_trim),
                    "Start-Service attempt failed"
                );
                log_wsl_event(format!(
                    "Start-Service {name_log} failed: status={} stdout={} stderr={}",
                    output.status,
                    escape_for_log(stdout_trim),
                    escape_for_log(stderr_trim)
                ));
            } else {
                info!(
                    target: "wsl",
                    service = %name_log,
                    status = %output.status,
                    stdout = %escape_for_log(stdout_trim),
                    "Start-Service invoked"
                );
                log_wsl_event(format!(
                    "Start-Service {name_log}: status={} stdout={}",
                    output.status,
                    escape_for_log(stdout_trim)
                ));
            }
        }
        Ok(Err(err)) => {
            warn!(
                target: "wsl",
                service = %name_log,
                error = %err,
                "Start-Service command failed to run"
            );
            log_wsl_event(format!(
                "Start-Service {name_log} failed to run: {}",
                escape_for_log(&err.to_string())
            ));
        }
        Err(err) => {
            warn!(
                target: "wsl",
                service = %name_log,
                error = %err,
                "Start-Service JoinHandle failed"
            );
            log_wsl_event(format!(
                "Start-Service {name_log} JoinHandle failed: {}",
                escape_for_log(&err.to_string())
            ));
        }
    }
}

async fn retry_http_rpc<T, Fut>(op_name: &str, mut op: impl FnMut() -> Fut) -> Result<T>
where
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut last_error = String::new();
    for attempt in 1..=SERVICE_RPC_RETRIES {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_error = err.clone();
                warn!(
                    target: "wsl",
                    attempt,
                    op = op_name,
                    error = %err,
                    "HTTP RPC attempt failed"
                );
                if attempt == 1 {
                    start_service_if_needed(HTTP_SERVICE_NAME).await;
                }
                if attempt < SERVICE_RPC_RETRIES {
                    let delay = SERVICE_RPC_BASE_DELAY_MS * attempt as u64;
                    sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }
    Err(anyhow!(
        "HTTP service unreachable after {} attempts (op={}): {}",
        SERVICE_RPC_RETRIES,
        op_name,
        last_error
    ))
}

async fn retry_dns_rpc<T, Fut>(op_name: &str, mut op: impl FnMut() -> Fut) -> Result<T>
where
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut last_error = String::new();
    for attempt in 1..=SERVICE_RPC_RETRIES {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_error = err.clone();
                warn!(
                    target: "wsl",
                    attempt,
                    op = op_name,
                    error = %err,
                    "DNS RPC attempt failed"
                );
                if attempt == 1 {
                    start_service_if_needed(DNS_SERVICE_NAME).await;
                }
                if attempt < SERVICE_RPC_RETRIES {
                    let delay = SERVICE_RPC_BASE_DELAY_MS * attempt as u64;
                    sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }
    Err(anyhow!(
        "DNS service unreachable after {} attempts (op={}): {}",
        SERVICE_RPC_RETRIES,
        op_name,
        last_error
    ))
}

async fn attach_cluster_details(instances: &mut [WslInstance]) {
    if instances.is_empty() {
        return;
    }

    let inbound_http = inbound_http_port();
    let inbound_https = inbound_https_port();
    let api_port = k3s_api_port();

    let http_routes = match http::http_list_routes().await {
        Ok(list) => Some(list.routes),
        Err(err) => {
            warn!(
                target: "wsl",
                error = %err,
                "Impossible de recuperer la liste des routes HTTP"
            );
            None
        }
    };

    let dns_records = match dns::dns_list_records().await {
        Ok(list) => Some(list.records),
        Err(err) => {
            warn!(
                target: "wsl",
                error = %err,
                "Impossible de recuperer les enregistrements DNS"
            );
            None
        }
    };

    let oidc_clients: Option<Vec<ClientOut>> = match oidc_list_clients().await {
        Ok(list) => Some(list.clients),
        Err(err) => {
            warn!(
                target: "wsl",
                error = %err,
                "Impossible de recuperer les clients OIDC"
            );
            None
        }
    };

    for instance in instances.iter_mut() {
        let domains = cluster_domains(&instance.name);
        if domains.is_empty() {
            instance.cluster = None;
            continue;
        }

        let mut routes = Vec::new();
        if let Some(all_routes) = http_routes.as_ref() {
            for route in all_routes {
                if domains
                    .iter()
                    .any(|domain| domain.eq_ignore_ascii_case(&route.host))
                {
                    if let Ok(port) = u16::try_from(route.port) {
                        if !routes.iter().any(|binding: &ClusterRouteBinding| {
                            binding.host.eq_ignore_ascii_case(&route.host)
                        }) {
                            routes.push(ClusterRouteBinding {
                                host: route.host.clone(),
                                port,
                            });
                        }
                    }
                }
            }
        }

        let dns_entries = if let Some(all_records) = dns_records.as_ref() {
            let mut entries = Vec::new();
            for record in all_records {
                if domains
                    .iter()
                    .any(|domain| domain.eq_ignore_ascii_case(&record.name))
                {
                    entries.push(ClusterDnsEntry {
                        name: record.name.clone(),
                        a: record.a.clone(),
                        ttl: if record.ttl == 0 {
                            None
                        } else {
                            Some(record.ttl)
                        },
                    });
                }
            }
            entries
        } else {
            Vec::new()
        };

        let oidc_info = if let Some(clients) = oidc_clients.as_ref() {
            if let Some(client) = clients
                .iter()
                .find(|client| client.subject.eq_ignore_ascii_case(&instance.name))
            {
                ClusterOidcInfo {
                    present: true,
                    client_id: Some(client.client_id.clone()),
                    scopes: client.allowed_scopes.clone(),
                }
            } else {
                ClusterOidcInfo::default()
            }
        } else {
            ClusterOidcInfo::default()
        };

        instance.cluster = Some(WslClusterStatus {
            domains,
            proxy: ClusterProxyInfo {
                inbound_http,
                inbound_https,
                routes,
            },
            api_port,
            dns_records: dns_entries,
            oidc: oidc_info,
        });
    }
}

fn decode_cli_output(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    if let Ok(utf8) = std::str::from_utf8(data) {
        if !utf8.contains('\0') {
            return utf8.to_string();
        }
    }

    if data.len() % 2 == 0 {
        let utf16: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        if let Ok(text) = String::from_utf16(&utf16) {
            return text;
        }
        return String::from_utf16_lossy(&utf16);
    }

    String::from_utf8_lossy(data).into_owned()
}

fn escape_for_log(input: &str) -> String {
    input.escape_debug().to_string()
}

fn format_cli_command(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return program.to_string();
    }

    let rendered_args: Vec<String> = args
        .iter()
        .map(|arg| {
            if arg
                .chars()
                .any(|c| c.is_whitespace() || c == '"' || c == '\'')
            {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg.to_string()
            }
        })
        .collect();

    format!("{} {}", program, rendered_args.join(" "))
}

static WSL_LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn wsl_log_lock() -> &'static Mutex<()> {
    WSL_LOG_LOCK.get_or_init(|| Mutex::new(()))
}

fn wsl_log_file_path() -> PathBuf {
    let base = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
    base.join("home-lab").join("logs").join("wsl-actions.log")
}

fn epoch_timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            let millis = duration.subsec_millis();
            format!("{secs}.{millis:03}")
        }
        Err(_) => "0".to_string(),
    }
}

fn append_wsl_log(message: &str) -> std::io::Result<()> {
    let path = wsl_log_file_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "[{}] {}", epoch_timestamp(), message)?;
    Ok(())
}

fn log_wsl_event(message: impl AsRef<str>) {
    let sanitized = message.as_ref().replace('\r', "\\r").replace('\n', "\\n");

    let lock = wsl_log_lock().lock();
    if let Ok(_guard) = lock {
        if let Err(err) = append_wsl_log(&sanitized) {
            warn!(target: "wsl", "Echec ecriture log WSL: {err}");
        }
    } else {
        warn!(target: "wsl", "Impossible d'obtenir le verrou du journal WSL");
    }
}

fn append_provision_message(target: &mut String, extra: &str) {
    if extra.trim().is_empty() {
        return;
    }
    if !target.trim().is_empty() {
        target.push('\n');
    }
    target.push_str(extra);
}

fn sanitize_cli_field(value: &str) -> String {
    fn is_disallowed(c: char) -> bool {
        matches!(
            c,
            '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{feff}'
                | '\u{fffd}'
        ) || c.is_control()
    }

    let filtered: String = value.chars().filter(|c| !is_disallowed(*c)).collect();
    filtered.trim().to_string()
}

fn sanitize_wsl_instance_name(raw: &str) -> Result<String> {
    let sanitized = sanitize_cli_field(raw);
    if sanitized.is_empty() {
        return Err(anyhow!("Le nom de l'instance WSL est requis."));
    }

    if sanitized.len() > 60 {
        return Err(anyhow!(
            "Le nom de l'instance WSL est trop long (60 caractères maximum)."
        ));
    }

    let valid = sanitized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '));
    if !valid {
        return Err(anyhow!(
            "Le nom de l'instance WSL ne peut contenir que des lettres, chiffres, espaces, points, tirets ou underscores."
        ));
    }

    Ok(sanitized)
}

fn resolve_install_dir(app: &AppHandle) -> Result<PathBuf> {
    if let Some(pd) = std::env::var_os("PROGRAMDATA") {
        return Ok(PathBuf::from(pd).join("home-lab").join("wsl"));
    }

    app.path()
        .app_data_dir()
        .map(|p| p.join("wsl"))
        .context("Impossible de déterminer le dossier d'installation WSL")
}

fn cluster_config_root() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir())
        .join("home-oidc")
        .join("clusters")
}

fn persist_cluster_credentials(
    instance: &str,
    client_id: &str,
    private_key: &str,
    public_key: &str,
    status: &StatusOut,
    scopes: &[String],
) -> Result<PathBuf> {
    let dir = cluster_config_root().join(instance);
    fs::create_dir_all(&dir).with_context(|| format!("Création de {}", dir.display()))?;
    fs::write(dir.join("oidc-client.key"), private_key)
        .with_context(|| "Écriture de la clé privée OIDC")?;
    fs::write(dir.join("oidc-client.pub"), public_key)
        .with_context(|| "Écriture de la clé publique OIDC")?;
    let metadata = json!({
        "client_id": client_id,
        "issuer": status.issuer,
        "token_endpoint": status.token_endpoint,
        "allowed_scopes": scopes,
    });
    fs::write(
        dir.join("oidc-client.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )
    .with_context(|| "Écriture du fichier de configuration OIDC")?;
    Ok(dir)
}

async fn configure_k3s_oidc_client(instance: &str) -> Result<String> {
    let mut rng = OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 4096).context("Génération de la clé privée OIDC")?;
    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("Sérialisation de la clé privée")?
        .to_string();
    let public_key = private_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .context("Sérialisation de la clé publique")?;
    let suffix = rng.next_u32();
    let normalized = instance.to_lowercase();
    let client_id = format!("k3s-{normalized}-{suffix:08x}");
    let scopes = vec!["k3s.admin".to_string()];
    let ack = register_client_config(RegisterClientIn {
        client_id: client_id.clone(),
        subject: Some(instance.to_string()),
        allowed_scopes: scopes.clone(),
        audiences: Vec::new(),
        public_key_pem: public_key.clone(),
        auth_method: Some("private_key_jwt".into()),
    })
    .await
    .map_err(|e| anyhow!(e))?;
    if !ack.ok {
        anyhow::bail!(ack.message);
    }
    let status = oidc_get_status().await.map_err(|e| anyhow!(e))?;
    let dir = persist_cluster_credentials(
        instance,
        &client_id,
        &private_pem,
        &public_key,
        &status,
        &scopes,
    )?;
    Ok(format!(
        "OIDC client '{client_id}' enregistré. Clés stockées dans {}.",
        dir.display()
    ))
}

#[tauri::command]
pub async fn wsl_import_instance(
    app: AppHandle,
    force: Option<bool>,
    name: Option<String>,
) -> Result<ProvisionResult, String> {
    let force_import = force.unwrap_or(false);
    let provided_name = name.unwrap_or_else(|| "home-lab-k3s".to_string());
    let sanitized_name = sanitize_wsl_instance_name(&provided_name).map_err(|e| {
        error!(target: "wsl", error = %e, "Nom d'instance WSL invalide");
        e.to_string()
    })?;
    let sanitized_debug = escape_for_log(&sanitized_name);
    let handle = app.clone();
    let instance_name = sanitized_name.clone();

    log_wsl_event(format!(
        "Demande d'import WSL (force={}, instance={})",
        force_import, sanitized_debug
    ));
    info!(
        target: "wsl",
        force = force_import,
        instance = %sanitized_name,
        instance_debug = %sanitized_debug,
        "Demande d'import WSL recue"
    );

    let setup_result = tauri::async_runtime::spawn_blocking(move || {
        run_wsl_setup(&handle, force_import, &instance_name)
    })
    .await
    .map_err(|e| {
        error!(target: "wsl", "Erreur JoinHandle: {e}");
        log_wsl_event(format!(
            "Erreur JoinHandle pendant l'import WSL (instance={}): {e}",
            sanitized_debug
        ));
        format!("Erreur interne: {e}")
    })?;

    let mut provision = match setup_result {
        Ok(prov) => prov,
        Err(err) => {
            error!(target: "wsl", "Echec import WSL: {err}");
            log_wsl_event(format!(
                "Echec import WSL pour l'instance {}: {err}",
                sanitized_debug
            ));
            ProvisionResult {
                ok: false,
                message: err.to_string(),
            }
        }
    };

    let mut allow_post_config = provision.ok;
    if !allow_post_config {
        match is_wsl_instance_present(&sanitized_name).await {
            Ok(true) => {
                allow_post_config = true;
                info!(
                    target: "wsl",
                    instance = %sanitized_name,
                    "Instance presente malgre une erreur setup, tentative de configuration reseau/OIDC"
                );
                log_wsl_event(format!(
                    "Instance {} presente malgre erreur setup, configuration reseau/OIDC en cours",
                    sanitized_debug
                ));
            }
            Ok(false) => {
                info!(
                    target: "wsl",
                    instance = %sanitized_name,
                    "Instance absente apres echec setup, configuration reseau/OIDC ignoree"
                );
            }
            Err(err) => {
                warn!(
                    target: "wsl",
                    instance = %sanitized_name,
                    error = %err,
                    "Impossible de verifier la presence de l'instance WSL apres echec setup"
                );
                append_provision_message(
                    &mut provision.message,
                    &format!("Verification de l'instance WSL impossible: {err}"),
                );
            }
        }
    }

    if allow_post_config {
        match configure_k3s_oidc_client(&sanitized_name).await {
            Ok(extra) => {
                append_provision_message(&mut provision.message, &extra);
                log_wsl_event(format!(
                    "Client OIDC k3s cree pour {}: {}",
                    sanitized_debug,
                    escape_for_log(&extra)
                ));
            }
            Err(err) => {
                warn!(
                    target: "wsl",
                    instance = %sanitized_name,
                    error = %err,
                    "Configuration OIDC pour k3s impossible"
                );
                append_provision_message(
                    &mut provision.message,
                    &format!("Configuration OIDC impossible: {err}"),
                );
                log_wsl_event(format!(
                    "Configuration OIDC pour {} impossible: {}",
                    sanitized_debug,
                    escape_for_log(&err.to_string())
                ));
            }
        }

        match configure_cluster_networking(&sanitized_name).await {
            Ok(extra) => {
                append_provision_message(&mut provision.message, &extra);
                log_wsl_event(format!(
                    "Reseau WSL configure pour {}: {}",
                    sanitized_debug,
                    escape_for_log(&extra)
                ));
            }
            Err(err) => {
                warn!(
                    target: "wsl",
                    instance = %sanitized_name,
                    error = %err,
                    "Configuration DNS/HTTP pour WSL impossible"
                );
                append_provision_message(
                    &mut provision.message,
                    &format!("Configuration DNS/HTTP impossible: {err}"),
                );
                log_wsl_event(format!(
                    "Configuration DNS/HTTP pour {} impossible: {}",
                    sanitized_debug,
                    escape_for_log(&err.to_string())
                ));
            }
        }
    }

    Ok(provision)
}

fn run_wsl_setup(
    app: &AppHandle,
    force_import: bool,
    instance_name: &str,
) -> Result<ProvisionResult> {
    let resource_dir = app
        .path()
        .resource_dir()
        .context("Impossible de recuperer le dossier des ressources")?;
    let wsl_dir = resource_dir.join("wsl");
    let script_path = wsl_dir.join("setup-wsl.ps1");
    if !script_path.exists() {
        return Err(anyhow!(
            "Script setup-wsl.ps1 introuvable dans {:?}",
            script_path
        ));
    }

    let rootfs_path = wsl_dir.join("wsl-rootfs.tar");
    if !rootfs_path.exists() {
        return Err(anyhow!("Archive rootfs introuvable dans {:?}", rootfs_path));
    }

    let install_dir = (resolve_install_dir(app)?).join(instance_name);
    let instance_debug = escape_for_log(instance_name);

    info!(
        target: "wsl",
        script = %script_path.display(),
        rootfs = %rootfs_path.display(),
        install = %install_dir.display(),
        force = force_import,
        instance = %instance_name,
        instance_debug = %instance_debug,
        "Lancement de setup-wsl.ps1"
    );
    log_wsl_event(format!(
        "Lancement de setup-wsl.ps1 (force={}, instance={}, script={}, rootfs={}, install={})",
        force_import,
        instance_debug,
        script_path.display(),
        rootfs_path.display(),
        install_dir.display()
    ));

    let mut command = Command::new("powershell.exe");
    command
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&script_path)
        .arg("-InstallDir")
        .arg(&install_dir)
        .arg("-Rootfs")
        .arg(&rootfs_path)
        .arg("-DistroName")
        .arg(instance_name);

    if force_import {
        command.arg("-ForceImport");
    }

    let mut command_preview = format!(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\" -InstallDir \"{}\" -Rootfs \"{}\" -DistroName \"{}\"",
        script_path.display(),
        install_dir.display(),
        rootfs_path.display(),
        instance_name
    );
    if force_import {
        command_preview.push_str(" -ForceImport");
    }

    info!(
        target: "wsl",
        command = %command_preview,
        "Execution d'une commande WSL (setup)"
    );
    log_wsl_event(format!(
        "Execution commande WSL (setup): {}",
        command_preview
    ));

    let output = command
        .output()
        .with_context(|| "Impossible d'executer setup-wsl.ps1".to_string())?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    info!(
        target: "wsl",
        command = %command_preview,
        status = %output.status,
        stdout = %stdout_log,
        stderr = %stderr_log,
        "Commande WSL terminee (setup)"
    );
    log_wsl_event(format!(
        "Commande terminee (setup) status={} stdout={} stderr={}",
        output.status, stdout_log, stderr_log
    ));

    if output.status.success() {
        if !stdout_trim.is_empty() {
            info!(target: "wsl", "setup-wsl.ps1 stdout:\n{stdout_trim}");
        }
        if !stderr_trim.is_empty() {
            warn!(target: "wsl", "setup-wsl.ps1 stderr: {stderr_trim}");
        }
        let mut message = if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            format!("Instance WSL '{instance_name}' importee avec succes.")
        };
        if !stderr_trim.is_empty() {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(stderr_trim);
        }
        info!(
            target: "wsl",
            instance = %instance_name,
            instance_debug = %instance_debug,
            "Import WSL termine"
        );
        log_wsl_event(format!(
            "Import WSL termine pour {}: {}",
            instance_debug,
            escape_for_log(&message)
        ));
        Ok(ProvisionResult { ok: true, message })
    } else {
        error!(
            target: "wsl",
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "setup-wsl.ps1 a echoue"
        );
        log_wsl_event(format!(
            "setup-wsl.ps1 a echoue pour {}: status={} stdout={} stderr={}",
            instance_debug, output.status, stdout_log, stderr_log
        ));
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "(code inconnu)".into());
        let mut combined = stderr;
        if combined.is_empty() {
            combined = stdout;
        }
        if combined.is_empty() {
            combined = format!("setup-wsl.ps1 a echoue (code {code})");
        }
        Err(anyhow!(combined))
    }
}

fn parse_wsl_list_output(output: &str) -> Result<Vec<WslInstance>> {
    let entry_re = Regex::new(r"^(?P<name>.+?)\s{2,}(?P<state>\S.*?)(?:\s{2,}(?P<version>\S+))?$")?;
    let mut instances = Vec::new();
    let mut header_skipped = false;

    for raw_line in output.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !header_skipped {
            header_skipped = true;
            // Première ligne = en-tête (NAME/STATE/VERSION ou équivalent localisé).
            continue;
        }

        let working = raw_line.trim_start();
        let (is_default, without_marker) = if working.starts_with('*') {
            (true, working.trim_start_matches('*').trim_start())
        } else {
            (false, working)
        };

        if without_marker.is_empty() {
            warn!(
                target: "wsl",
                line = %escape_for_log(raw_line),
                "Ligne WSL vide apres retrait du marqueur par defaut; ignoree"
            );
            continue;
        }

        let Some(caps) = entry_re.captures(without_marker) else {
            warn!(
                target: "wsl",
                line = %escape_for_log(without_marker),
                "Impossible d'analyser la ligne WSL; ligne ignoree"
            );
            continue;
        };

        let name_raw = caps.name("name").map(|m| m.as_str()).unwrap_or_default();
        let state_raw = caps.name("state").map(|m| m.as_str()).unwrap_or_default();
        let version_raw = caps.name("version").map(|m| m.as_str());

        let name = sanitize_cli_field(name_raw);
        if name.is_empty() {
            warn!(
                target: "wsl",
                line = %escape_for_log(raw_line),
                "Nom d'instance WSL vide apres nettoyage; ligne ignoree"
            );
            continue;
        }

        let state = sanitize_cli_field(state_raw);
        let version =
            version_raw
                .map(sanitize_cli_field)
                .and_then(|v| if v.is_empty() { None } else { Some(v) });

        instances.push(WslInstance {
            name,
            state,
            version,
            is_default,
            cluster: None,
        });
    }

    Ok(instances)
}

fn collect_wsl_instances() -> Result<Vec<WslInstance>> {
    let args = ["--list", "--verbose", "--all"];
    let command_line = format_cli_command("wsl.exe", &args);

    log_wsl_event(format!("Execution commande WSL (list): {command_line}"));
    let output = Command::new("wsl.exe")
        .args(args)
        .output()
        .context("Impossible d'executer wsl.exe --list --verbose --all")?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    info!(
        target: "wsl",
        command = %command_line,
        status = %output.status,
        stdout = %stdout_log,
        stderr = %stderr_log,
        "Commande WSL terminee"
    );
    log_wsl_event(format!(
        "Commande terminee (list) status={} stdout={} stderr={}",
        output.status, stdout_log, stderr_log
    ));

    if !output.status.success() {
        let lower_stdout = stdout_trim.to_lowercase();
        let lower_stderr = stderr_trim.to_lowercase();
        let no_distro = lower_stdout.contains("no installed distributions")
            || lower_stdout.contains("aucune distribution install")
            || lower_stderr.contains("no installed distributions")
            || lower_stderr.contains("aucune distribution install");

        if no_distro {
            info!(target: "wsl", "wsl.exe indique qu'aucune distribution n'est installee");
            log_wsl_event("wsl.exe indique qu'aucune distribution n'est installee");
            return Ok(Vec::new());
        }

        let message = if !stderr_trim.is_empty() {
            stderr_trim.to_string()
        } else if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            "wsl.exe --list a echoue".to_string()
        };
        log_wsl_event(format!("Echec wsl.exe --list --verbose --all: {message}"));
        return Err(anyhow!(message));
    }

    let instances = parse_wsl_list_output(stdout.as_str())?;

    for inst in &instances {
        let version_ref = inst.version.as_deref().unwrap_or("");
        info!(
            target: "wsl",
            instance = %inst.name,
            instance_debug = %escape_for_log(&inst.name),
            state = %inst.state,
            state_debug = %escape_for_log(&inst.state),
            version = %version_ref,
            version_debug = %escape_for_log(version_ref),
            "Instance WSL detectee"
        );
        log_wsl_event(format!(
            "Instance detectee: name={} state={} version={} default={}",
            escape_for_log(&inst.name),
            escape_for_log(&inst.state),
            escape_for_log(version_ref),
            inst.is_default
        ));
    }

    Ok(instances)
}

async fn is_wsl_instance_present(name: &str) -> Result<bool> {
    let target = name.to_ascii_lowercase();
    tauri::async_runtime::spawn_blocking(move || {
        collect_wsl_instances().map(|instances| {
            instances
                .iter()
                .any(|instance| instance.name.to_ascii_lowercase() == target)
        })
    })
    .await
    .map_err(|e| anyhow!("Erreur JoinHandle pour verifier l'instance WSL: {e}"))?
}

fn run_wsl_unregister(name: &str) -> Result<WslOperationResult> {
    if name.trim().is_empty() {
        return Err(anyhow!("Le nom de l'instance WSL est requis"));
    }

    let command_line = format_cli_command("wsl.exe", &["--unregister", name]);
    let instance_debug = escape_for_log(name);

    info!(
        target: "wsl",
        instance = name,
        instance_debug = %instance_debug,
        command = %command_line,
        "Execution d'une commande WSL"
    );
    log_wsl_event(format!(
        "Suppression WSL demandee pour {} via {}",
        instance_debug, command_line
    ));

    let output = Command::new("wsl.exe")
        .args(["--unregister", name])
        .output()
        .with_context(|| format!("Impossible de supprimer l'instance WSL {name}"))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    if output.status.success() {
        let mut message = if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            format!("Instance WSL '{name}' supprimee.")
        };
        if !stderr_trim.is_empty() && stderr_trim != message {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(stderr_trim);
        }
        info!(
            target: "wsl",
            instance = name,
            instance_debug = %instance_debug,
            command = %command_line,
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "Instance WSL supprimee"
        );
        log_wsl_event(format!(
            "Instance WSL supprimee: {} message={} stdout={} stderr={}",
            instance_debug,
            escape_for_log(&message),
            stdout_log,
            stderr_log
        ));
        Ok(WslOperationResult { ok: true, message })
    } else {
        let lower_stdout = stdout_trim.to_lowercase();
        let lower_stderr = stderr_trim.to_lowercase();
        let not_found = lower_stdout.contains("wsl_e_distro_not_found")
            || lower_stderr.contains("wsl_e_distro_not_found")
            || lower_stdout.contains("no distribution")
            || lower_stderr.contains("no distribution")
            || lower_stdout.contains("aucune distribution")
            || lower_stderr.contains("aucune distribution");

        if not_found {
            info!(
                target: "wsl",
                instance = name,
                instance_debug = %instance_debug,
                command = %command_line,
                stdout = %stdout_log,
                stderr = %stderr_log,
                "Suppression WSL consideree comme deja effectuee (distribution absente)"
            );
            log_wsl_event(format!(
                "Suppression WSL consideree comme deja effectuee (absente): {}",
                instance_debug
            ));
            return Ok(WslOperationResult {
                ok: true,
                message: format!("Instance WSL '{name}' introuvable ou deja supprimee."),
            });
        }

        let mut combined = stderr_trim.to_string();
        if combined.is_empty() {
            combined = stdout_trim.to_string();
        }
        if combined.is_empty() {
            let code = output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "(code inconnu)".into());
            combined = format!("Suppression de l'instance '{name}' a echoue (code {code})");
        }
        error!(
            target: "wsl",
            instance = name,
            instance_debug = %instance_debug,
            command = %command_line,
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "Suppression WSL a echoue"
        );
        log_wsl_event(format!(
            "Suppression WSL a echoue: {} message={} stdout={} stderr={}",
            instance_debug,
            escape_for_log(&combined),
            stdout_log,
            stderr_log
        ));
        Err(anyhow!(combined))
    }
}

#[tauri::command]
pub async fn wsl_list_instances() -> Result<Vec<WslInstance>, String> {
    info!(target: "wsl", "Listing des instances WSL");
    log_wsl_event("Listing des instances WSL");
    let mut instances = tauri::async_runtime::spawn_blocking(collect_wsl_instances)
        .await
        .map_err(|e| {
            error!(target: "wsl", "Erreur JoinHandle (list): {e}");
            log_wsl_event(format!("Erreur JoinHandle lors du listing WSL: {e}"));
            format!("Erreur interne: {e}")
        })?
        .map_err(|e| e.to_string())?;

    attach_cluster_details(&mut instances).await;

    Ok(instances)
}

#[tauri::command]
pub async fn wsl_remove_instance(name: String) -> Result<WslOperationResult, String> {
    let raw_trimmed = name.trim();
    if raw_trimmed.is_empty() {
        return Err("Le nom de l'instance est requis.".into());
    }

    let sanitized = sanitize_wsl_instance_name(raw_trimmed).map_err(|e| e.to_string())?;

    if sanitized != raw_trimmed {
        info!(
            target: "wsl",
            instance_raw = %escape_for_log(raw_trimmed),
            instance_sanitized = %escape_for_log(&sanitized),
            "Nom d'instance WSL nettoyé avant suppression"
        );
        log_wsl_event(format!(
            "Nom d'instance WSL nettoye avant suppression: brut={} nettoye={}",
            escape_for_log(raw_trimmed),
            escape_for_log(&sanitized)
        ));
    }

    let instance_name = sanitized;
    let instance_debug = escape_for_log(&instance_name);
    info!(
        target: "wsl",
        instance = %instance_name,
        instance_debug = %instance_debug,
        "Suppression d'une instance WSL demandée"
    );
    log_wsl_event(format!(
        "Suppression d'une instance WSL demandee: {}",
        instance_debug
    ));

    tauri::async_runtime::spawn_blocking({
        let instance_name = instance_name.clone();
        move || run_wsl_unregister(&instance_name)
    })
    .await
    .map_err(|e| {
        error!(target: "wsl", "Erreur JoinHandle (remove): {e}");
        log_wsl_event(format!("Erreur JoinHandle (remove): {e}"));
        format!("Erreur interne: {e}")
    })
    .and_then(|result| {
        result.map_err(|e| {
            error!(target: "wsl", "Échec suppression WSL: {e}");
            log_wsl_event(format!(
                "Échec suppression WSL pour {}: {e}",
                instance_debug
            ));
            e.to_string()
        })
    })
}
