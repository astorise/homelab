#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
use log::{debug, error, info, warn, LevelFilter};
use parking_lot::Mutex;
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::{server::Connected, Server};
use windows_service::define_windows_service;
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::*;

// Build metadata (set in build.rs)
const BUILD_GIT_SHA: &str = env!("BUILD_GIT_SHA");
const BUILD_GIT_TAG: &str = env!("BUILD_GIT_TAG");
const BUILD_TIME: &str = env!("BUILD_TIME");

// gRPC service
mod proto {
    pub mod homedns {
        pub mod v1 {
            tonic::include_proto!("homedns.v1");
        }
    }
}

use proto::homedns::v1::home_dns_server::{HomeDns, HomeDnsServer};
use proto::homedns::v1::{
    Ack, AddRecordRequest, Empty, ListRecordsResponse, Record, RemoveRecordRequest, StatusResponse,
};

const SERVICE_NAME: &str = "HomeDnsService";
const SERVICE_DISPLAY_NAME: &str = "Home DNS Service";
const SERVICE_DESCRIPTION:
    &str =
    r"DNS config + rollback + Windows RPC IPC on ncalrpc endpoint home-dns";

#[cfg(debug_assertions)]
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-dns-dev";
#[cfg(not(debug_assertions))]
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-dns";

fn default_level_filter() -> LevelFilter {
    if cfg!(debug_assertions) {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    }
}

fn default_level_str() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct RecordEntry {
    #[serde(default)]
    a: Vec<String>,
    #[serde(default)]
    aaaa: Vec<String>,
    #[serde(default)]
    ttl: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsConfig {
    servers_v4: Vec<String>,
    #[serde(default)]
    servers_v6: Vec<String>,
    #[serde(default)]
    backups: HashMap<String, DnsBackup>,
    #[serde(default)]
    log_level: Option<String>,
    #[serde(default)]
    records: HashMap<String, RecordEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsBackup {
    alias: String,
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
    let dir = logs_dir();
    fs::create_dir_all(&dir).map_err(|e| {
        eprintln!("cannot create log directory {}: {e}", dir.display());
        e
    })?;
    let logger = match Logger::try_with_str(match level {
        LevelFilter::Debug => "debug",
        _ => "info",
    }) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to configure logger (continuing): {e}");
            return Ok(())
        }
    }
    .log_to_file(
        FileSpec::default()
            .directory(&dir)
            .basename("home-dns")
            .suffix("log"),
    )
    .format(flexi_logger::detailed_format)
    .duplicate_to_stderr(Duplicate::Info)
    .rotate(
        Criterion::AgeOrSize(Age::Day, 5_000_000),
        Naming::Timestamps,
        Cleanup::KeepLogFiles(7),
    );
    match logger.start() {
        Ok(_) => {}
        Err(e) => {
            // If a logger is already set in this process, continue without failing service startup.
            eprintln!("failed to start logger (continuing): {e}");
        }
    }
    Ok(())
}

fn level_from_cfg(cfg: &DnsConfig) -> LevelFilter {
    match cfg
        .log_level
        .as_deref()
        .unwrap_or(default_level_str())
        .to_ascii_lowercase()
        .as_str()
    {
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
            log_level: Some(default_level_str().into()),
            records: HashMap::new(),
        };
        let yaml = serde_yaml::to_string(&cfg)?;
        write_atomic(&p, yaml.as_bytes())?;
        return Ok(cfg);
    }
    let s = fs::read_to_string(&p).with_context(|| format!("lecture config: {}", p.display()))?;
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
    let ps = r"Get-NetAdapter | Select-Object -Property Name,MacAddress,Status | ConvertTo-Json -Compress";
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        anyhow::bail!(
            "Get-NetAdapter a échoué: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let adapters: Vec<PsAdapter> = if stdout.trim_start().starts_with('[') {
        serde_json::from_str(stdout.trim()).context("parse JSON adapters")? 
    } else {
        let single: PsAdapter = 
            serde_json::from_str(stdout.trim()).context("parse JSON adapter")?;
        vec![single]
    };
    Ok(adapters)
}

fn read_current_dns(alias: &str, family: &str) -> Result<(bool, Vec<String>)> {
    let ps = format!(
        "$x = Get-DnsClientServerAddress -InterfaceAlias \"{alias}\" -AddressFamily {family}
if ($x -eq $null -or $x.ServerAddresses -eq $null -or $x.ServerAddresses.Count -eq 0) {{\"DHCP\";\"\"}} else {{\"STATIC\"; [string]::Join(\",\", $x.ServerAddresses)}}",
        alias = alias,
        family = family,
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
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
        .map(|s| format!(r#"\"{}\""#, s))
        .collect::<Vec<_>>()
        .join(",");
    let cmd = format!(
        "Set-DnsClientServerAddress -InterfaceAlias \"{alias}\" -AddressFamily {family} -ServerAddresses {joined}",
        alias = alias,
        family = family,
        joined = joined,
    );
    debug!("Apply DNS [{} {} => {}]", alias, family, joined);
    let status = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd])
        .status()?;
    if !status.success() {
        anyhow::bail!("Set-DnsClientServerAddress({}) a échoué", family);
    }
    Ok(())
}

fn reset_dns_to_dhcp(alias: &str, family: &str) -> Result<()> {
    let cmd = format!(
        "Set-DnsClientServerAddress -InterfaceAlias \"{alias}\" -AddressFamily {family} -ResetServerAddresses",
        alias = alias,
        family = family,
    );
    debug!("Reset DNS [{} {} to DHCP]", alias, family);
    let status = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd])
        .status()?;
    if !status.success() {
        anyhow::bail!("ResetServerAddresses({}) a échoué", family);
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
        debug!(
            "Processing adapter [{} MAC={} Status={}]",
            alias, mac, status
        );
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
                timestamp_unix: chrono::Utc::now().timestamp(),
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
            mac_to_alias.insert(normalize_mac(&mac), ad.name);
        }
    }
    let mut restored = 0usize;
    let keys: Vec<String> = cfg.backups.keys().cloned().collect();
    for mac in keys {
        if let Some(entry) = cfg.backups.get_mut(&mac) {
            if !entry.dirty {
                continue;
            }
            let alias = mac_to_alias
                .get(&mac)
                .cloned()
                .unwrap_or_else(|| entry.alias.clone());
            info!("Restoring adapter [{} MAC={}]", alias, mac);
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

#[derive(Clone)]
struct SharedState {
    cfg: Arc<Mutex<DnsConfig>>,
    stopping: Arc<AtomicBool>,
}

#[derive(Clone)]
struct MyDnsService {
    state: SharedState,
}

#[tonic::async_trait]
impl HomeDns for MyDnsService {
    async fn stop_service(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        info!("gRPC StopService requested");
        self.state.stopping.store(true, Ordering::SeqCst);
        Ok(tonic::Response::new(Ack {
            ok: true,
            message: "stopping".into(),
        }))
    }

    async fn reload_config(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        info!("gRPC ReloadConfig requested");
        match load_config_or_init() {
            Ok(new_cfg) => {
                *self.state.cfg.lock() = new_cfg;
                Ok(tonic::Response::new(Ack {
                    ok: true,
                    message: "reloaded".into(),
                }))
            }
            Err(e) => {
                error!("reload_config failed: {:#}", e);
                Err(tonic::Status::internal(e.to_string()))
            }
        }
    }

    async fn get_status(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<StatusResponse>, tonic::Status> {
        let level = level_from_cfg(&self.state.cfg.lock());
        let state = if self.state.stopping.load(Ordering::SeqCst) {
            "Stopping"
        } else {
            "Running"
        };
        Ok(tonic::Response::new(StatusResponse {
            state: state.into(),
            log_level: format!("{:?}", level).to_lowercase(),
        }))
    }

    async fn add_record(
        &self,
        request: tonic::Request<AddRecordRequest>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let r = request.into_inner();
        if r.name.trim().is_empty() {
            return Err(tonic::Status::invalid_argument("name required"));
        }
        let t = r.rrtype.to_ascii_uppercase();
        if t != "A" && t != "AAAA" {
            return Err(tonic::Status::invalid_argument("type must be A or AAAA"));
        }
        let mut cfg = self.state.cfg.lock();
        let entry = cfg.records.entry(r.name.clone()).or_default();
        match t.as_str() {
            "A" => {
                if !entry.a.contains(&r.value) {
                    entry.a.push(r.value.clone());
                }
            }
            "AAAA" => {
                if !entry.aaaa.contains(&r.value) {
                    entry.aaaa.push(r.value.clone());
                }
            }
            _ => {}
        }
        if r.ttl != 0 {
            entry.ttl = Some(r.ttl);
        }
        if let Err(e) = save_config(&cfg) {
            return Err(tonic::Status::internal(e.to_string()));
        }
        info!("Record added: {} {} {}", r.name, t, r.value);
        Ok(tonic::Response::new(Ack {
            ok: true,
            message: "added".into(),
        }))
    }

    async fn remove_record(
        &self,
        request: tonic::Request<RemoveRecordRequest>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let r = request.into_inner();
        if r.name.trim().is_empty() {
            return Err(tonic::Status::invalid_argument("name required"));
        }
        let mut cfg = self.state.cfg.lock();
        let mut should_remove_key = false;
        if let Some(entry) = cfg.records.get_mut(&r.name) {
            let t = r.rrtype.to_ascii_uppercase();
            if t.is_empty() {
                should_remove_key = true;
            } else if t == "A" {
                if r.value.is_empty() {
                    entry.a.clear();
                } else {
                    entry.a.retain(|v| v != &r.value);
                }
            } else if t == "AAAA" {
                if r.value.is_empty() {
                    entry.aaaa.clear();
                } else {
                    entry.aaaa.retain(|v| v != &r.value);
                }
            } else {
                return Err(tonic::Status::invalid_argument(
                    "type must be A, AAAA or empty",
                ));
            }
            if !should_remove_key && entry.a.is_empty() && entry.aaaa.is_empty() {
                should_remove_key = true;
            }
        } else {
            return Ok(tonic::Response::new(Ack {
                ok: true,
                message: "not found".into(),
            }));
        }
        if should_remove_key {
            cfg.records.remove(&r.name);
        }
        if let Err(e) = save_config(&cfg) {
            return Err(tonic::Status::internal(e.to_string()));
        }
        info!("Record removed: {} {} {}", r.name, r.rrtype, r.value);
        Ok(tonic::Response::new(Ack {
            ok: true,
            message: "removed".into(),
        }))
    }

    async fn list_records(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<ListRecordsResponse>, tonic::Status> {
        let cfg = self.state.cfg.lock().clone();
        let mut out = Vec::new();
        for (name, ent) in cfg.records {
            out.push(Record {
                name,
                a: ent.a,
                aaaa: ent.aaaa,
                ttl: ent.ttl.unwrap_or(0),
            });
        }
        Ok(tonic::Response::new(ListRecordsResponse { records: out }))
    }
}

define_windows_service!(ffi_service_main, service_main);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("[home-dns] FATAL: {e:?}");
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
    })?;

    let set_status = |state: ServiceState| {
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        };
        let _ = status_handle.set_service_status(status);
    };

    set_status(ServiceState::StartPending);

    let rt = Runtime::new()?;
    rt.block_on(async {
        let cfg = load_config_or_init()?;
        let level = level_from_cfg(&cfg);
        init_logger(level)?;
        info!("Service starting (level={:?})", level);
        info!(
            "build tag={} sha={} at {}",
            BUILD_GIT_TAG, BUILD_GIT_SHA, BUILD_TIME
        );

        let shared = SharedState {
            cfg: Arc::new(Mutex::new(cfg)),
            stopping: Arc::new(AtomicBool::new(false)),
        };

        // Start gRPC server
        let grpc_service = MyDnsService {
            state: shared.clone(),
        };
        let grpc_server = Server::builder().add_service(HomeDnsServer::new(grpc_service));
        tokio::spawn(async move {
            info!("gRPC server listening on {}", NAMED_PIPE_NAME);
            let stream = match named_pipe_stream() {
                Ok(stream) => stream,
                Err(e) => {
                    error!("failed to prepare named pipe listener: {}", e);
                    return;
                }
            };
            if let Err(e) = grpc_server.serve_with_incoming(stream).await {
                error!("gRPC server error: {}", e);
            }
        });

        // Heavy tasks in background
        let shared_bg = shared.clone();
        tokio::spawn(async move {
            info!("restoring previous DNS state if any...");
            let _ = restore_all();
            info!("snapshot_and_apply_all starting...");
            let cfg0 = shared_bg.cfg.lock().clone();
            match snapshot_and_apply_all(cfg0) {
                Ok(new_cfg) => {
                    *shared_bg.cfg.lock() = new_cfg;
                    info!("snapshot_and_apply_all finished");
                }
                Err(e) => {
                    error!("snapshot/apply failed: {e:?}");
                }
            }
        });

        set_status(ServiceState::Running);
        info!("Service running");

        while !STOP_REQUESTED.load(Ordering::SeqCst) && !shared.stopping.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        info!("Service stopping");
        let _ = restore_all();
        set_status(ServiceState::Stopped);
        info!("Service stopped");
        Ok(())
    })
}

#[allow(dead_code)]
fn run_console() -> Result<()> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let cfg = load_config_or_init()?;
        let level = level_from_cfg(&cfg);
        init_logger(level)?;
        info!("Console mode starting (level={:?})", level);
        let _ = restore_all();
        let cfg = match snapshot_and_apply_all(cfg) {
            Ok(c) => c,
            Err(e) => {
                warn!("snapshot/apply failed: {e:?}; continuing without applying");
                load_config_or_init()?
            }
        };
        let shared = SharedState {
            cfg: Arc::new(Mutex::new(cfg)),
            stopping: Arc::new(AtomicBool::new(false)),
        };

        // gRPC server
        let grpc_service = MyDnsService {
            state: shared.clone(),
        };
        let grpc_server = Server::builder().add_service(HomeDnsServer::new(grpc_service));
        tokio::spawn(async move {
            info!("gRPC server listening on {}", NAMED_PIPE_NAME);
            let stream = match named_pipe_stream() {
                Ok(stream) => stream,
                Err(e) => {
                    error!("failed to prepare named pipe listener: {}", e);
                    return;
                }
            };
            if let Err(e) = grpc_server.serve_with_incoming(stream).await {
                error!("gRPC server error: {}", e);
            }
        });

        info!("Console mode running. Press Ctrl+C to stop.");
        while !shared.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

fn install_service() -> Result<()> {
    let cfg = load_config_or_init()?;
    if let Err(e) = init_logger(level_from_cfg(&cfg)) {
        eprintln!("[install] logger init failed (continuing): {e}");
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    if let Ok(_svc) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        info!("Service already installed");
        return Ok(())
    }
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
    let service = manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    let _ = service.set_description(SERVICE_DESCRIPTION);
    let _ = configure_recovery_action_run_restore(&exe_path);
    info!("Service installed");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    if let Err(e) = init_logger(default_level_filter()) {
        eprintln!("[uninstall] logger init failed (continuing): {e}");
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
    )?;
    let _ = service.stop();
    for _ in 0..20 {
        if let Ok(st) = service.query_status() {
            if st.current_state == ServiceState::Stopped {
                break;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    service.delete()?;
    drop(service);
    for _ in 0..20 {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(s) => {
                drop(s);
                thread::sleep(Duration::from_millis(250));
            }
            Err(_) => break,
        }
    }
    info!("Service uninstalled");
    Ok(())
}

fn configure_recovery_action_run_restore(exe: &Path) -> Result<()> {
    let exe_str = exe.display().to_string();
    let cmd = format!(
        r#"sc.exe failure "{service}" actions=run/0 reset=0 command=""{exe}" restore""#,
        service = SERVICE_NAME,
        exe = exe_str,
    );
    debug!("Configuring SCM recovery: {}", cmd);
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
            println!(
                "Service installé. Éditez {} si besoin puis démarrez le service.",
                config_path().display()
            );
        }
        "uninstall" => {
            uninstall_service()?;
            println!("Service désinstallé.");
        }
        "run" => {
            if let Err(e) = 
                windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            {
                error!("Erreur démarrage service: {e:?}");
                let _ = restore_all();
            }
        }
        "console" => {
            run_console()?;
        }
        "apply-once" => {
            let cfg = load_config_or_init()?;
            init_logger(level_from_cfg(&cfg))?;
            snapshot_and_apply_all(cfg)?;
            println!("DNS appliqué sur toutes les interfaces.");
        }
        "restore" => {
            let cfg = load_config_or_init()?;
            init_logger(level_from_cfg(&cfg))?;
            restore_all()?;
            println!("DNS restaurés (toutes interfaces connues via dns.yaml).");
        }
        _ => {
            eprintln!("Usage: home-dns [install|uninstall|run|apply-once|restore]");
        }
    }
    Ok(())
}

#[pin_project]
struct PipeConnection {
    #[pin]
    inner: NamedPipeServer,
}

impl PipeConnection {
    fn new(inner: NamedPipeServer) -> Self {
        Self { inner }
    }
}

unsafe impl Send for PipeConnection {}

impl Connected for PipeConnection {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for PipeConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for PipeConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

fn named_pipe_stream(
) -> io::Result<UnboundedReceiverStream<Result<PipeConnection, io::Error>>> {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(NAMED_PIPE_NAME)?;
    let (tx, rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        loop {
            match server.connect().await {
                Ok(()) => {
                    let new_server = match ServerOptions::new().create(NAMED_PIPE_NAME) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = tx.send(Err(e));
                            break;
                        }
                    };
                    let old_server = std::mem::replace(&mut server, new_server);
                    if tx.send(Ok(PipeConnection::new(old_server))).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if tx.send(Err(e)).is_err() {
                        break;
                    }
                }
            }
        }
    });

    Ok(UnboundedReceiverStream::new(rx))
}
