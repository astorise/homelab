use anyhow::{Context, Result};
use chrono::Utc;
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
use log::{debug, error, info, warn, LevelFilter};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::*;

const SERVICE_NAME: &str = "HomeDnsService";
const SERVICE_DISPLAY_NAME: &str = "Home DNS Service";
const SERVICE_DESCRIPTION: &str = "Applique la configuration DNS à toutes les interfaces et sauvegarde par adresse MAC dans dns.yaml. Restaure à l'arrêt/crash. Log vers fichier.";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsConfig {
    /// Serveurs DNS à appliquer à TOUTES les interfaces (IPv4/IPv6).
    servers_v4: Vec<String>,
    #[serde(default)]
    servers_v6: Vec<String>,

    /// Sauvegardes par MAC normalisée (AA-BB-CC-DD-EE-FF)
    #[serde(default)]
    backups: HashMap<String, DnsBackup>,

    /// Niveau de log: "debug" ou "info" (défaut: info)
    #[serde(default)]
    log_level: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsBackup {
    alias: String,         // alias au moment du snapshot (peut changer)
    is_dhcp_v4: bool,
    is_dhcp_v6: bool,
    servers_v4: Vec<String>,
    servers_v6: Vec<String>,
    dirty: bool,
    timestamp_unix: i64,
}

#[derive(Deserialize, Debug)]
struct PsAdapter {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "MacAddress")]
    mac_address: Option<String>,
    #[serde(rename = "Status")]
    status: Option<String>,
}

fn program_data_dir() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\home-dns")
}

fn logs_dir() -> PathBuf {
    program_data_dir().join("logs")
}

fn config_path() -> PathBuf {
    program_data_dir().join("dns.yaml")
}

fn init_logger(level: LevelFilter) -> Result<()> {
    fs::create_dir_all(logs_dir()).ok();
    Logger::try_with_str(match level {
        LevelFilter::Debug => "debug",
        _ => "info",
    })?
    .log_to_file(
        FileSpec::default()
            .directory(logs_dir())
            .basename("home-dns")
            .suffix("log"),
    )
    .format(flexi_logger::detailed_format)
    .duplicate_to_stderr(Duplicate::Info)
    .rotate(
        Criterion::AgeOrSize(Age::Day, 5_000_000),
        Naming::Timestamps,
        Cleanup::KeepLogFiles(7),
    )
    .start()?;
    Ok(())
}

fn level_from_cfg(cfg: &DnsConfig) -> LevelFilter {
    match cfg.log_level.as_deref().unwrap_or("info").to_ascii_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        _ => LevelFilter::Info,
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).ok();
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).with_context(|| format!("create tmp {}", tmp.display()))?;
        f.write_all(bytes)?;
        let _ = f.sync_all();
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn load_config_or_init() -> Result<DnsConfig> {
    let p = config_path();
    if !p.exists() {
        let cfg = DnsConfig {
            servers_v4: vec!["1.1.1.1".into(), "1.0.0.1".into()],
            servers_v6: vec![],
            backups: HashMap::new(),
            log_level: Some("info".into()),
        };
        let yaml = serde_yaml::to_string(&cfg)?;
        write_atomic(&p, yaml.as_bytes())?;
        return Ok(cfg);
    }
    let s = fs::read_to_string(&p)
        .with_context(|| format!("lecture config: {}", p.display()))?;
    let cfg: DnsConfig = serde_yaml::from_str(&s).context("YAML invalide")?;
    if cfg.servers_v4.is_empty() && cfg.servers_v6.is_empty() {
        anyhow::bail!("dns.yaml invalide: servers_v4 et servers_v6 sont vides");
    }
    Ok(cfg)
}

fn save_config(cfg: &DnsConfig) -> Result<()> {
    let yaml = serde_yaml::to_string(cfg)?;
    write_atomic(&config_path(), yaml.as_bytes())
}

fn normalize_mac(mac: &str) -> String {
    mac.trim().to_uppercase().replace(":", "-")
}

fn get_all_adapters() -> Result<Vec<PsAdapter>> {
    let ps = r#"Get-NetAdapter | Select-Object -Property Name,MacAddress,Status | ConvertTo-Json -Compress"#;
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Get-NetAdapter")?;
    if !out.status.success() {
        anyhow::bail!("Get-NetAdapter a échoué: {}", String::from_utf8_lossy(&out.stderr));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let adapters: Vec<PsAdapter> = if stdout.trim_start().starts_with('[') {
        serde_json::from_str(stdout.trim()).context("parse JSON adapters")?
    } else {
        let single: PsAdapter = serde_json::from_str(stdout.trim()).context("parse JSON adapter")?;
        vec![single]
    };
    Ok(adapters)
}

fn read_current_dns(alias: &str, family: &str) -> Result<(bool, Vec<String>)> {
    let ps = format!(
        r#"$x = Get-DnsClientServerAddress -InterfaceAlias "{}" -AddressFamily {}
if ($x -eq $null -or $x.ServerAddresses -eq $null -or $x.ServerAddresses.Count -eq 0) {{"DHCP";""}} else {{"STATIC"; [string]::Join(",", $x.ServerAddresses)}}"#,
        alias, family
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Get-DnsClientServerAddress")?;
    if !out.status.success() {
        anyhow::bail!(
            "Get-DnsClientServerAddress a échoué: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines().map(|s| s.trim()).filter(|s| !s.is_empty());
    let mode = lines.next().unwrap_or("STATIC");
    let servers_line = lines.next().unwrap_or("");
    let is_dhcp = mode.eq_ignore_ascii_case("DHCP");
    let servers: Vec<String> = if servers_line.is_empty() {
        vec![]
    } else {
        servers_line
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    Ok((is_dhcp, servers))
}

fn set_dns_with_powershell(alias: &str, family: &str, servers: &[String]) -> Result<()> {
    let joined = servers
        .iter()
        .map(|s| format!(r#""{}""#, s))
        .collect::<Vec<_>>()
        .join(",");
    let cmd = format!(
        r#"Set-DnsClientServerAddress -InterfaceAlias "{}" -AddressFamily {} -ServerAddresses {}"#,
        alias, family, joined
    );
    debug!("Apply DNS [{}] {} => {}", alias, family, joined);
    let status = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd])
        .status()?;
    if !status.success() {
        anyhow::bail!("Set-DnsClientServerAddress({family}) a échoué");
    }
    Ok(())
}

fn reset_dns_to_dhcp(alias: &str, family: &str) -> Result<()> {
    let cmd = format!(
        r#"Set-DnsClientServerAddress -InterfaceAlias "{}" -AddressFamily {} -ResetServerAddresses"#,
        alias, family
    );
    debug!("Reset DNS [{}] {} to DHCP", alias, family);
    let status = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd])
        .status()?;
    if !status.success() {
        anyhow::bail!("ResetServerAddresses({family}) a échoué");
    }
    Ok(())
}

fn snapshot_and_apply_all(mut cfg: DnsConfig) -> Result<DnsConfig> {
    let adapters = get_all_adapters()?;
    info!("Applying DNS to {} adapters", adapters.len());
    for ad in adapters {
        let mac = match ad.mac_address {
            Some(ref m) if !m.trim().is_empty() => normalize_mac(m),
            _ => {
                debug!("Skip adapter without MAC: {}", ad.name);
                continue;
            }
        };
        let alias = ad.name;
        let status = ad.status.unwrap_or_default();
        debug!("Processing adapter [{}] MAC={} Status={}", alias, mac, status);

        let (is_dhcp_v4, servers_v4) = read_current_dns(&alias, "IPv4").unwrap_or((true, vec![]));
        let (is_dhcp_v6, servers_v6) = read_current_dns(&alias, "IPv6").unwrap_or((true, vec![]));

        cfg.backups.insert(
            mac.clone(),
            DnsBackup {
                alias: alias.clone(),
                is_dhcp_v4,
                is_dhcp_v6,
                servers_v4: servers_v4.clone(),
                servers_v6: servers_v6.clone(),
                dirty: true,
                timestamp_unix: Utc::now().timestamp(),
            },
        );

        if !cfg.servers_v4.is_empty() {
            if let Err(e) = set_dns_with_powershell(&alias, "IPv4", &cfg.servers_v4) {
                warn!("Failed to set IPv4 DNS on {}: {}", alias, e);
            }
        }
        if !cfg.servers_v6.is_empty() {
            if let Err(e) = set_dns_with_powershell(&alias, "IPv6", &cfg.servers_v6) {
                warn!("Failed to set IPv6 DNS on {}: {}", alias, e);
            }
        }
    }
    save_config(&cfg)?;
    Ok(cfg)
}

fn restore_all() -> Result<()> {
    let mut cfg = load_config_or_init()?;
    let adapters = get_all_adapters().unwrap_or_default();
    let mut mac_to_alias: HashMap<String, String> = HashMap::new();
    for ad in adapters {
        if let Some(mac) = ad.mac_address {
            let key = normalize_mac(&mac);
            mac_to_alias.insert(key, ad.name);
        }
    }

    let mut restored = 0usize;
    let keys: Vec<String> = cfg.backups.keys().cloned().collect();
    for mac in keys {
        if let Some(entry) = cfg.backups.get_mut(&mac) {
            if !entry.dirty {
                continue;
            }
            let alias = mac_to_alias.get(&mac).cloned().unwrap_or_else(|| entry.alias.clone());

            info!("Restoring adapter [{}] MAC={}", alias, mac);

            if entry.is_dhcp_v4 {
                let _ = reset_dns_to_dhcp(&alias, "IPv4");
            } else if !entry.servers_v4.is_empty() {
                let _ = set_dns_with_powershell(&alias, "IPv4", &entry.servers_v4);
            }
            if entry.is_dhcp_v6 {
                let _ = reset_dns_to_dhcp(&alias, "IPv6");
            } else if !entry.servers_v6.is_empty() {
                let _ = set_dns_with_powershell(&alias, "IPv6", &entry.servers_v6);
            }
            entry.dirty = false;
            restored += 1;
        }
    }
    if restored > 0 {
        info!("Restored {} adapter(s)", restored);
    }
    save_config(&cfg)?;
    Ok(())
}

/// --- Hooks pour journaliser les requêtes DNS (à appeler depuis ton résolveur) ---
#[allow(dead_code)]
fn log_dns_request(query_name: &str, client: &str, qtype: &str) {
    // Niveau: DEBUG pour toutes les requêtes
    debug!("DNS request: name={} type={} from={}", query_name, qtype, client);
}

#[allow(dead_code)]
fn log_local_resolution(query_name: &str, resolved_to: &str) {
    // Niveau: INFO pour les résolutions locales
    info!("Locally resolved: {} -> {}", query_name, resolved_to);
}

define_windows_service!(ffi_service_main, service_main);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn service_main(_args: Vec<OsString>) {
    let _ = init_logger(LevelFilter::Info); // démarrage minimal
    if let Err(e) = run_service() {
        error!("[home-dns] FATAL: {e:?}");
        let _ = restore_all();
    }
}

fn run_service() -> Result<()> {
    let status_handle = service_control_handler::register(SERVICE_NAME, |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            STOP_REQUESTED.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .context("register service control handler")?;

    let set_status = |state: ServiceState| {
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_millis(3000),
            process_id: None,
        };
        let _ = status_handle.set_service_status(status);
    };

    set_status(ServiceState::StartPending);

    let cfg = load_config_or_init()?;
    let desired = level_from_cfg(&cfg);
    let _ = init_logger(desired);
    info!("Service starting (level={:?})", desired);

    let _ = restore_all(); // si crash précédent, restaure
    let _cfg_after_apply = snapshot_and_apply_all(cfg)?;

    set_status(ServiceState::Running);
    info!("Service running");

    while !STOP_REQUESTED.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    info!("Service stopping");
    let _ = restore_all();
    set_status(ServiceState::Stopped);
    info!("Service stopped");
    Ok(())
}

fn install_service() -> Result<()> {
    let cfg = load_config_or_init()?;
    let _ = init_logger(level_from_cfg(&cfg));

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let exe_path = std::env::current_exe()?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.clone(),
        launch_arguments: vec!["run".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    let _ = service.set_description(SERVICE_DESCRIPTION);

    configure_recovery_action_run_restore(&exe_path)?;
    info!("Service installed");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let _ = init_logger(LevelFilter::Info);
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE)?;
    let _ = service.stop();
    service.delete()?;
    info!("Service uninstalled");
    Ok(())
}

fn configure_recovery_action_run_restore(exe: &Path) -> Result<()> {
    let exe_str = exe.display().to_string();
    let cmd = format!(
        r#"sc.exe failure "{}" actions= run/0 reset= 0 command= "\"{}\" restore""#,
        SERVICE_NAME, exe_str
    );
    debug!("Configuring SCM recovery: {}", cmd);
    let status = Command::new("cmd").args(["/C", &cmd]).status()?;
    if !status.success() {
        anyhow::bail!("sc.exe failure a échoué");
    }
    Ok(())
}

fn main() -> Result<()> {
    let _ = init_logger(LevelFilter::Info);

    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "install" => {
            install_service()?;
            println!("Service installé. Éditez {} si besoin puis démarrez le service.", config_path().display());
        }
        "uninstall" => {
            uninstall_service()?;
            println!("Service désinstallé.");
        }
        "run" => {
            if let Err(e) = windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                error!("Erreur démarrage service: {e:?}");
                let _ = restore_all();
            }
        }
        "apply-once" => {
            let cfg = load_config_or_init()?;
            let _ = init_logger(level_from_cfg(&cfg));
            let _ = snapshot_and_apply_all(cfg)?;
            println!("DNS appliqué sur toutes les interfaces.");
        }
        "restore" => {
            let cfg = load_config_or_init()?;
            let _ = init_logger(level_from_cfg(&cfg));
            restore_all()?;
            println!("DNS restaurés (toutes interfaces connues via dns.yaml).");
        }
        _ => {
            eprintln!("Usage: home-dns [install|uninstall|run|apply-once|restore]");
        }
    }
    Ok(())
}