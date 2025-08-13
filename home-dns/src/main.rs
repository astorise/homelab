use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
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
const SERVICE_DESCRIPTION: &str = "Applique et restaure la configuration DNS (IPv4/IPv6) depuis dns.yaml avec rollback sûr.";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsConfig {
    interface_alias: String,
    servers_v4: Vec<String>,
    #[serde(default)]
    servers_v6: Vec<String>,
    #[serde(default)]
    fallback_servers_v4: Vec<String>,
    #[serde(default)]
    fallback_servers_v6: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsBackup {
    interface_alias: String,
    is_dhcp_v4: bool,
    is_dhcp_v6: bool,
    servers_v4: Vec<String>,
    servers_v6: Vec<String>,
    dirty: bool,
    timestamp_unix: i64,
}

fn program_data_dir() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\home-dns")
}

fn config_path() -> PathBuf {
    program_data_dir().join("dns.yaml")
}

fn backup_path() -> PathBuf {
    program_data_dir().join("backup.json")
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

fn load_config() -> Result<DnsConfig> {
    let p = config_path();
    let s = fs::read_to_string(&p)
        .with_context(|| format!("lecture config: {}", p.display()))?;
    let cfg: DnsConfig = serde_yaml::from_str(&s).context("YAML invalide")?;
    if cfg.servers_v4.is_empty() && cfg.servers_v6.is_empty() {
        anyhow::bail!("Liste de serveurs vide: servers_v4 et servers_v6 sont vides");
    }
    Ok(cfg)
}

fn read_current_dns(alias: &str, family: &str) -> Result<(bool, Vec<String>)> {
    // family: "IPv4" | "IPv6"
    // Retourne (is_dhcp, servers)
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
        .context("PowerShell Get-DnsClientServerAddress")?;
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

fn snapshot_before_change(alias: &str) -> Result<()> {
    let (is_dhcp_v4, servers_v4) = read_current_dns(alias, "IPv4").unwrap_or((true, vec![]));
    let (is_dhcp_v6, servers_v6) = read_current_dns(alias, "IPv6").unwrap_or((true, vec![]));
    let b = DnsBackup {
        interface_alias: alias.to_string(),
        is_dhcp_v4,
        is_dhcp_v6,
        servers_v4,
        servers_v6,
        dirty: true,
        timestamp_unix: Utc::now().timestamp(),
    };
    let payload = serde_json::to_vec_pretty(&b)?;
    write_atomic(&backup_path(), &payload)?;
    Ok(())
}

fn read_backup() -> Result<DnsBackup> {
    let s = fs::read_to_string(backup_path())?;
    Ok(serde_json::from_str(&s)?)
}

fn mark_clean_and_remove() {
    if let Ok(mut b) = read_backup() {
        b.dirty = false;
        if let Ok(bytes) = serde_json::to_vec_pretty(&b) {
            let _ = write_atomic(&backup_path(), &bytes);
        }
    }
    let _ = fs::remove_file(backup_path());
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
    let status = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd])
        .status()?;
    if !status.success() {
        anyhow::bail!("ResetServerAddresses({family}) a échoué");
    }
    Ok(())
}

fn restore_previous_dns() -> Result<()> {
    let b = read_backup()?;
    if b.dirty {
        if b.is_dhcp_v4 {
            let _ = reset_dns_to_dhcp(&b.interface_alias, "IPv4");
        } else if !b.servers_v4.is_empty() {
            let _ = set_dns_with_powershell(&b.interface_alias, "IPv4", &b.servers_v4);
        }
        if b.is_dhcp_v6 {
            let _ = reset_dns_to_dhcp(&b.interface_alias, "IPv6");
        } else if !b.servers_v6.is_empty() {
            let _ = set_dns_with_powershell(&b.interface_alias, "IPv6", &b.servers_v6);
        }
        mark_clean_and_remove();
    }
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("[home-dns] FATAL: {e:?}");
        // Tentative de restauration si crash
        let _ = restore_previous_dns();
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
            wait_hint: Duration::from_millis(3000),
            process_id: None,
        };
        let _ = status_handle.set_service_status(status);
    };

    set_status(ServiceState::StartPending);

    // Sécurité: si un backup "dirty" traîne (crash précédent), on restaure d'abord
    let _ = restore_previous_dns();

    // Charge la config et applique
    let cfg = load_config()?;

    // Snapshot avant toute modif
    snapshot_before_change(&cfg.interface_alias)?;

    // Appliquer IPv4/IPv6
    if !cfg.servers_v4.is_empty() {
        set_dns_with_powershell(&cfg.interface_alias, "IPv4", &cfg.servers_v4)?;
    }
    if !cfg.servers_v6.is_empty() {
        set_dns_with_powershell(&cfg.interface_alias, "IPv6", &cfg.servers_v6)?;
    }

    set_status(ServiceState::Running);

    // Boucle simple: on tourne et on attend STOP
    while !STOP_REQUESTED.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    // À l'arrêt: on restaure
    let _ = restore_previous_dns();
    set_status(ServiceState::Stopped);
    Ok(())
}

fn install_service() -> Result<()> {
    // Préparer ProgramData + exemple de config
    if !config_path().exists() {
        let example = DnsConfig {
            interface_alias: "Ethernet".into(),
            servers_v4: vec!["1.1.1.1".into(), "1.0.0.1".into()],
            servers_v6: vec![],
            fallback_servers_v4: vec!["8.8.8.8".into(), "8.8.4.4".into()],
            fallback_servers_v6: vec![],
        };
        let yaml = serde_yaml::to_string(&example)?;
        write_atomic(&config_path(), yaml.as_bytes())?;
    }

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
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    let _ = service.set_description(SERVICE_DESCRIPTION);

    // Configure recovery: 1er échec => run "<exe> restore"
    configure_recovery_action_run_restore(&exe_path)?;

    Ok(())
}

fn uninstall_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE)?;
    let _ = service.stop();
    service.delete()?;
    Ok(())
}

fn configure_recovery_action_run_restore(exe: &Path) -> Result<()> {
    // sc.exe failure HomeDnsService actions= run/0 reset= 0 command= "\"C:\path\home-dns.exe\" restore"
    let exe_str = exe.display().to_string();
    let cmd = format!(
        r#"sc.exe failure "{}" actions= run/0 reset= 0 command= "\"{}\" restore""#,
        SERVICE_NAME, exe_str
    );
    let status = Command::new("cmd").args(["/C", &cmd]).status()?;
    if !status.success() {
        anyhow::bail!("sc.exe failure a échoué");
    }
    Ok(())
}

fn main() -> Result<()> {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "install" => {
            install_service()?;
            println!("Service installé. Modifiez {} puis démarrez le service.", config_path().display());
        }
        "uninstall" => {
            uninstall_service()?;
            println!("Service désinstallé.");
        }
        "run" => {
            if let Err(e) = windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                eprintln!("Erreur démarrage service: {e:?}");
                // En cas d'échec, on tente une restauration
                let _ = restore_previous_dns();
            }
        }
        "apply-once" => {
            let cfg = load_config()?;
            snapshot_before_change(&cfg.interface_alias)?;
            if !cfg.servers_v4.is_empty() {
                set_dns_with_powershell(&cfg.interface_alias, "IPv4", &cfg.servers_v4)?;
            }
            if !cfg.servers_v6.is_empty() {
                set_dns_with_powershell(&cfg.interface_alias, "IPv6", &cfg.servers_v6)?;
            }
            println!("DNS appliqué une fois.");
        }
        "restore" => {
            restore_previous_dns()?;
            println!("DNS restauré depuis le backup.");
        }
        _ => {
            eprintln!("Usage: home-dns [install|uninstall|run|apply-once|restore]");
        }
    }
    Ok(())
}