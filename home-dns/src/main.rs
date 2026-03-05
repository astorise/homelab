#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A as RDataA, AAAA as RDataAAAA};
use hickory_proto::rr::{DNSClass, RData, Record as DnsRecord, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use log::{LevelFilter, debug, error, info, warn};
use parking_lot::Mutex;
use pin_project::pin_project;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::rand_core::OsRng;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::{Infallible, TryInto};
use std::ffi::{OsString, c_void};
use std::fs::{self, File};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::{Server, server::Connected};
use windows_service::define_windows_service;
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::*;

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
const SERVICE_DESCRIPTION: &str =
    r"DNS config + rollback + Windows RPC IPC on ncalrpc endpoint home-dns";
const DEFAULT_SERVERS_V4: &[&str] = &["127.0.0.1"];
const LEGACY_DEFAULT_SERVERS_V4: &[&str] = &["1.1.1.1", "1.0.0.1"];
const DEFAULT_DOH_UPSTREAMS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
];
const DEFAULT_DOH_TTL: u32 = 60;

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

fn build_label() -> String {
    let raw = if BUILD_GIT_TAG.trim().is_empty() || BUILD_GIT_TAG == "unknown" {
        BUILD_GIT_SHA
    } else {
        BUILD_GIT_TAG
    };
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.trim_matches('_').is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn build_log_basename(prefix: &str) -> String {
    format!("{prefix}_{}", build_label())
}

fn default_doh_enabled() -> bool {
    true
}

fn default_doh_listen_addr() -> String {
    "127.0.0.1".into()
}

fn default_doh_hostname() -> String {
    "127.0.0.1".into()
}

fn default_doh_port() -> u16 {
    5443
}

fn default_doh_path() -> String {
    "/dns-query".into()
}

fn default_doh_upstreams() -> Vec<String> {
    DEFAULT_DOH_UPSTREAMS
        .iter()
        .map(|value| value.to_string())
        .collect()
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
struct DohConfig {
    #[serde(default = "default_doh_enabled")]
    enabled: bool,
    #[serde(default = "default_doh_listen_addr")]
    listen_addr: String,
    #[serde(default = "default_doh_hostname")]
    hostname: String,
    #[serde(default = "default_doh_port")]
    port: u16,
    #[serde(default = "default_doh_path")]
    path: String,
    #[serde(default = "default_doh_upstreams")]
    upstreams: Vec<String>,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            enabled: default_doh_enabled(),
            listen_addr: default_doh_listen_addr(),
            hostname: default_doh_hostname(),
            port: default_doh_port(),
            path: default_doh_path(),
            upstreams: default_doh_upstreams(),
        }
    }
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
    #[serde(default)]
    doh: DohConfig,
}

impl DnsConfig {
    fn normalized_doh_path(&self) -> String {
        normalize_doh_path(&self.doh.path)
    }

    fn doh_template_url(&self) -> String {
        format!(
            "https://{}:{}{}",
            self.doh.hostname.trim(),
            self.doh.port,
            self.normalized_doh_path()
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsBackup {
    alias: String,
    #[serde(default)]
    if_index: Option<u32>,
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
    #[serde(rename = "ifIndex")]
    if_index: Option<u32>,
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

fn doh_private_key_path() -> PathBuf {
    program_data_dir().join("doh-private-key.pem")
}

fn doh_certificate_path() -> PathBuf {
    program_data_dir().join("doh-cert.pem")
}

fn normalize_doh_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/dns-query".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn init_logger(level: LevelFilter) -> Result<()> {
    let dir = logs_dir();
    let basename = build_log_basename("home-dns");
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
            return Ok(());
        }
    }
    .log_to_file(
        FileSpec::default()
            .directory(&dir)
            .basename(basename)
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

fn as_string_vec(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn matches_servers(values: &[String], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected.iter())
            .all(|(left, right)| left.trim().eq_ignore_ascii_case(right))
}

fn should_migrate_legacy_defaults(cfg: &DnsConfig) -> bool {
    matches_servers(&cfg.servers_v4, LEGACY_DEFAULT_SERVERS_V4)
}

fn load_config_or_init() -> Result<DnsConfig> {
    let p = config_path();
    if !p.exists() {
        let cfg = DnsConfig {
            servers_v4: as_string_vec(DEFAULT_SERVERS_V4),
            servers_v6: vec![],
            backups: HashMap::new(),
            log_level: Some(default_level_str().into()),
            records: HashMap::new(),
            doh: DohConfig::default(),
        };
        let yaml = serde_yaml::to_string(&cfg)?;
        write_atomic(&p, yaml.as_bytes())?;
        return Ok(cfg);
    }
    let s = fs::read_to_string(&p).with_context(|| format!("lecture config: {}", p.display()))?;
    let mut cfg: DnsConfig = serde_yaml::from_str(&s).context("YAML invalide")?;
    let mut changed = false;
    if cfg.servers_v4.is_empty() && cfg.servers_v6.is_empty() {
        anyhow::bail!("dns.yaml invalide: servers_v4 et servers_v6 sont vides");
    }
    if should_migrate_legacy_defaults(&cfg) {
        cfg.servers_v4 = as_string_vec(DEFAULT_SERVERS_V4);
        changed = true;
    }
    if cfg.doh.listen_addr.trim().is_empty() {
        cfg.doh.listen_addr = default_doh_listen_addr();
        changed = true;
    }
    if cfg.doh.hostname.trim().is_empty() {
        cfg.doh.hostname = default_doh_hostname();
        changed = true;
    }
    if cfg.doh.port == 0 {
        cfg.doh.port = default_doh_port();
        changed = true;
    }
    let normalized_path = normalize_doh_path(&cfg.doh.path);
    if normalized_path != cfg.doh.path {
        cfg.doh.path = normalized_path;
        changed = true;
    }
    if cfg.doh.upstreams.is_empty() {
        cfg.doh.upstreams = default_doh_upstreams();
        changed = true;
    }
    if changed {
        save_config(&cfg)?;
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
    let ps = r"Get-NetAdapter | Select-Object -Property Name,ifIndex,MacAddress,Status | ConvertTo-Json -Compress";
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

fn read_current_dns(interface_index: u32, family: &str) -> Result<(bool, Vec<String>)> {
    let ps = format!(
        "$x = Get-DnsClientServerAddress -InterfaceIndex {interface_index} -AddressFamily {family}
if ($x -eq $null -or $x.ServerAddresses -eq $null -or $x.ServerAddresses.Count -eq 0) {{\"DHCP\";\"\"}} else {{\"STATIC\"; [string]::Join(\",\", $x.ServerAddresses)}}",
        interface_index = interface_index,
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

fn set_dns_with_powershell(
    interface_index: u32,
    alias: &str,
    family: &str,
    servers: &[String],
) -> Result<()> {
    let joined = servers
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let ps = format!(
        "$servers = @({joined}); Set-DnsClientServerAddress -InterfaceIndex {interface_index} -ServerAddresses $servers -ErrorAction Stop",
        interface_index = interface_index,
        joined = joined,
    );
    debug!("Apply DNS [{} {} => {}]", alias, family, joined);
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let details = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!(
            "Set-DnsClientServerAddress({}) a échoué: {}",
            family,
            details
        );
    }
    Ok(())
}

fn reset_dns_to_dhcp(interface_index: u32, alias: &str, family: &str) -> Result<()> {
    let ps = format!(
        "Set-DnsClientServerAddress -InterfaceIndex {interface_index} -ResetServerAddresses -ErrorAction Stop",
        interface_index = interface_index,
    );
    debug!("Reset DNS [{} {} to DHCP]", alias, family);
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let details = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!("ResetServerAddresses({}) a échoué: {}", family, details);
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
        let interface_index = match ad.if_index {
            Some(index) => index,
            None => {
                warn!("Skip adapter without ifIndex: {}", alias);
                continue;
            }
        };
        let status = ad.status.unwrap_or_default();
        debug!(
            "Processing adapter [{} MAC={} Status={}]",
            alias, mac, status
        );
        let (is_dhcp_v4, servers_v4) =
            read_current_dns(interface_index, "IPv4").unwrap_or((true, vec![]));
        let (is_dhcp_v6, servers_v6) =
            read_current_dns(interface_index, "IPv6").unwrap_or((true, vec![]));
        cfg.backups.insert(
            mac.clone(),
            DnsBackup {
                alias: alias.clone(),
                if_index: Some(interface_index),
                is_dhcp_v4,
                is_dhcp_v6,
                servers_v4: servers_v4.clone(),
                servers_v6: servers_v6.clone(),
                dirty: true,
                timestamp_unix: chrono::Utc::now().timestamp(),
            },
        );
        if !cfg.servers_v4.is_empty() {
            if let Err(e) =
                set_dns_with_powershell(interface_index, &alias, "IPv4", &cfg.servers_v4)
            {
                warn!("Failed to set IPv4 DNS on {}: {}", alias, e);
            }
        }
        if !cfg.servers_v6.is_empty() {
            if let Err(e) =
                set_dns_with_powershell(interface_index, &alias, "IPv6", &cfg.servers_v6)
            {
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
    let mut mac_to_if_index: HashMap<String, u32> = HashMap::new();
    for ad in adapters {
        if let Some(mac) = ad.mac_address {
            let mac = normalize_mac(&mac);
            mac_to_alias.insert(mac.clone(), ad.name);
            if let Some(if_index) = ad.if_index {
                mac_to_if_index.insert(mac, if_index);
            }
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
            let interface_index = mac_to_if_index.get(&mac).copied().or(entry.if_index);
            let Some(interface_index) = interface_index else {
                warn!(
                    "Cannot restore adapter {} (MAC={}): missing ifIndex",
                    alias, mac
                );
                continue;
            };
            info!("Restoring adapter [{} MAC={}]", alias, mac);
            if entry.is_dhcp_v4 {
                let _ = reset_dns_to_dhcp(interface_index, &alias, "IPv4");
            } else if !entry.servers_v4.is_empty() {
                let _ = set_dns_with_powershell(interface_index, &alias, "IPv4", &entry.servers_v4);
            }
            if entry.is_dhcp_v6 {
                let _ = reset_dns_to_dhcp(interface_index, &alias, "IPv6");
            } else if !entry.servers_v6.is_empty() {
                let _ = set_dns_with_powershell(interface_index, &alias, "IPv6", &entry.servers_v6);
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
struct DohRuntimeState {
    shared: SharedState,
    upstream_client: reqwest::Client,
}

fn parse_doh_listen_addr(cfg: &DnsConfig) -> Result<SocketAddr> {
    let ip: IpAddr = cfg
        .doh
        .listen_addr
        .trim()
        .parse()
        .with_context(|| format!("doh.listen_addr invalide: {}", cfg.doh.listen_addr))?;
    Ok(SocketAddr::new(ip, cfg.doh.port))
}

fn normalize_record_key(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn find_record_entry<'a>(
    records: &'a HashMap<String, RecordEntry>,
    query_name: &str,
) -> Option<&'a RecordEntry> {
    let expected = normalize_record_key(query_name);
    records
        .iter()
        .find(|(name, _)| normalize_record_key(name) == expected)
        .map(|(_, entry)| entry)
}

fn build_local_dns_response(cfg: &DnsConfig, wire_query: &[u8]) -> Result<Option<Vec<u8>>> {
    let request = Message::from_vec(wire_query).context("parse DNS message")?;
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_response_code(ResponseCode::NoError);

    let mut local_hit = false;
    for query in request.queries().iter().cloned() {
        response.add_query(query.clone());
        if query.query_class() != DNSClass::IN {
            continue;
        }
        let query_name = query.name().to_utf8();
        let Some(entry) = find_record_entry(&cfg.records, &query_name) else {
            continue;
        };
        local_hit = true;
        let ttl = entry.ttl.unwrap_or(DEFAULT_DOH_TTL);
        match query.query_type() {
            RecordType::A => {
                for value in &entry.a {
                    match value.parse::<Ipv4Addr>() {
                        Ok(v4) => {
                            response.add_answer(DnsRecord::from_rdata(
                                query.name().clone(),
                                ttl,
                                RData::A(RDataA(v4)),
                            ));
                        }
                        Err(e) => warn!("invalid IPv4 in record {query_name}: {value} ({e})"),
                    }
                }
            }
            RecordType::AAAA => {
                for value in &entry.aaaa {
                    match value.parse::<std::net::Ipv6Addr>() {
                        Ok(v6) => {
                            response.add_answer(DnsRecord::from_rdata(
                                query.name().clone(),
                                ttl,
                                RData::AAAA(RDataAAAA(v6)),
                            ));
                        }
                        Err(e) => warn!("invalid IPv6 in record {query_name}: {value} ({e})"),
                    }
                }
            }
            _ => {}
        }
    }

    if !local_hit {
        return Ok(None);
    }

    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    response
        .emit(&mut encoder)
        .context("encode local DNS response")?;
    Ok(Some(bytes))
}

fn decode_doh_get_param(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .or_else(|_| URL_SAFE.decode(value.as_bytes()))
        .context("invalid base64url dns payload")
}

fn parse_doh_get_payload(query: Option<&str>) -> Result<Vec<u8>> {
    let query = query.ok_or_else(|| anyhow!("missing query string"))?;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key == "dns" {
            return decode_doh_get_param(value.as_ref());
        }
    }
    Err(anyhow!("missing dns query parameter"))
}

type HttpBody = Full<Bytes>;
type HttpResponse = Response<HttpBody>;

fn plain_response(status: StatusCode, message: &str) -> HttpResponse {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::from(Bytes::from(message.to_string())))
        .expect("plain response")
}

fn dns_message_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/dns-message")
        .body(Full::from(Bytes::from(body)))
        .expect("dns response")
}

async fn forward_dns_query(state: &DohRuntimeState, wire_query: Vec<u8>) -> Result<Vec<u8>> {
    let upstreams = state.shared.cfg.lock().doh.upstreams.clone();
    if upstreams.is_empty() {
        anyhow::bail!("doh.upstreams vide");
    }

    let mut last_error: Option<anyhow::Error> = None;
    for upstream in upstreams {
        let response = state
            .upstream_client
            .post(&upstream)
            .header(CONTENT_TYPE, "application/dns-message")
            .header("accept", "application/dns-message")
            .body(wire_query.clone())
            .send()
            .await;
        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    last_error = Some(anyhow!(
                        "DoH upstream {} returned {}",
                        upstream,
                        resp.status()
                    ));
                    continue;
                }
                let payload = resp
                    .bytes()
                    .await
                    .with_context(|| format!("reading upstream response from {}", upstream))?;
                return Ok(payload.to_vec());
            }
            Err(err) => {
                last_error = Some(anyhow!("DoH upstream {} failed: {}", upstream, err));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("all DoH upstreams failed")))
}

async fn resolve_dns_query(state: &DohRuntimeState, wire_query: Vec<u8>) -> Result<Vec<u8>> {
    if let Some(local) = {
        let cfg = state.shared.cfg.lock();
        build_local_dns_response(&cfg, &wire_query)?
    } {
        return Ok(local);
    }
    forward_dns_query(state, wire_query).await
}

async fn handle_doh_http_request(req: Request<Incoming>, state: DohRuntimeState) -> HttpResponse {
    let expected_path = state.shared.cfg.lock().normalized_doh_path();
    if req.uri().path() != expected_path {
        return plain_response(StatusCode::NOT_FOUND, "not found");
    }

    let method = req.method().clone();
    let wire_query = match method {
        Method::GET => match parse_doh_get_payload(req.uri().query()) {
            Ok(payload) => payload,
            Err(e) => return plain_response(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
        },
        Method::POST => {
            if let Some(value) = req.headers().get(CONTENT_TYPE) {
                let content_type = value.to_str().unwrap_or_default();
                if !content_type
                    .to_ascii_lowercase()
                    .contains("application/dns-message")
                {
                    return plain_response(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "content-type must be application/dns-message",
                    );
                }
            }
            match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(e) => return plain_response(StatusCode::BAD_REQUEST, &format!("{e}")),
            }
        }
        _ => return plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };

    match resolve_dns_query(&state, wire_query).await {
        Ok(payload) => dns_message_response(StatusCode::OK, payload),
        Err(e) => {
            error!("DoH resolve failed: {e:#}");
            plain_response(StatusCode::BAD_GATEWAY, "upstream resolution failed")
        }
    }
}

async fn serve_doh(shared: SharedState, tls: Arc<ServerConfig>) -> Result<()> {
    let listen_addr = {
        let cfg = shared.cfg.lock();
        parse_doh_listen_addr(&cfg)?
    };
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind DoH listener on {listen_addr}"))?;
    let acceptor = TlsAcceptor::from(tls);
    let upstream_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .context("building DoH upstream client")?;
    let state = DohRuntimeState {
        shared: shared.clone(),
        upstream_client,
    };
    info!(
        "DoH server listening on https://{}{}",
        listen_addr,
        shared.cfg.lock().normalized_doh_path()
    );

    loop {
        if STOP_REQUESTED.load(Ordering::SeqCst) || shared.stopping.load(Ordering::SeqCst) {
            break;
        }
        let accepted = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
        let (stream, _peer) = match accepted {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                warn!("DoH accept error: {}", e);
                continue;
            }
            Err(_) => continue,
        };

        let acceptor = acceptor.clone();
        let request_state = state.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let svc_state = request_state.clone();
                    let svc = service_fn(move |req| {
                        let svc_state = svc_state.clone();
                        async move {
                            Ok::<HttpResponse, Infallible>(
                                handle_doh_http_request(req, svc_state).await,
                            )
                        }
                    });
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls_stream), svc)
                        .await
                    {
                        warn!("DoH connection error: {}", e);
                    }
                }
                Err(e) => {
                    warn!("DoH TLS accept error: {}", e);
                }
            }
        });
    }
    info!("DoH server stopped");
    Ok(())
}

fn ensure_doh_certificate(cfg: &DnsConfig) -> Result<()> {
    if doh_private_key_path().exists() && doh_certificate_path().exists() {
        return Ok(());
    }

    let host = cfg.doh.hostname.trim();
    if host.is_empty() {
        anyhow::bail!("doh.hostname is empty");
    }

    let mut params = CertificateParams::new(vec![host.to_string()])?;
    params.is_ca = IsCa::NoCa;
    params
        .distinguished_name
        .push(DnType::CommonName, host.to_string());
    params
        .subject_alt_names
        .push(SanType::DnsName("localhost".to_string().try_into()?));
    if host.eq_ignore_ascii_case("localhost") {
        params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        params.subject_alt_names.push(SanType::IpAddress(ip));
    } else {
        params
            .subject_alt_names
            .push(SanType::DnsName(host.to_string().try_into()?));
    }
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    let mut rng = OsRng;
    let rsa_key = RsaPrivateKey::new(&mut rng, 4096).context("generate rsa key")?;
    let key_pem = rsa_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("serialize rsa key to PKCS#8")?
        .to_string();
    let key_pair = KeyPair::from_pem(&key_pem).context("load rcgen key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign DoH certificate")?;
    write_atomic(&doh_private_key_path(), key_pem.as_bytes())?;
    write_atomic(&doh_certificate_path(), cert.pem().as_bytes())?;
    Ok(())
}

fn load_doh_tls_config(cfg: &DnsConfig) -> Result<Arc<ServerConfig>> {
    use std::io::BufReader;

    ensure_doh_certificate(cfg)?;

    let key_pem = fs::read_to_string(doh_private_key_path()).context("read DoH private key")?;
    let cert_pem = fs::read_to_string(doh_certificate_path()).context("read DoH certificate")?;

    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .context("read DoH cert chain")?;

    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("read DoH pkcs8 key")?;
    let key = if let Some(key) = pkcs8_keys.into_iter().next() {
        PrivateKeyDer::from(key)
    } else {
        key_reader = BufReader::new(key_pem.as_bytes());
        let rsa_keys = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("read DoH rsa key")?;
        match rsa_keys.into_iter().next() {
            Some(key) => PrivateKeyDer::from(key),
            None => return Err(anyhow!("no private key found for DoH")),
        }
    };

    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build DoH rustls config")?;
    Ok(Arc::new(tls))
}

fn import_certificate_to_trust_store(path: &Path) -> Result<()> {
    let path_str = path.display().to_string();
    let script = format!(
        "try {{ Import-Certificate -FilePath '{path}' -CertStoreLocation Cert:\\\\LocalMachine\\\\Root -ErrorAction Stop }} catch {{ Import-Certificate -FilePath '{path}' -CertStoreLocation Cert:\\\\CurrentUser\\\\Root }}",
        path = path_str.replace('\'', "''"),
    );
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status()?;
    if !status.success() {
        warn!("DoH certificate import failed with status {:?}", status);
    }
    Ok(())
}

fn ensure_doh_firewall_rule(port: u16) -> Result<()> {
    let rule_name = format!("Home DNS DoH {port}");
    let check = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={rule_name}"),
        ])
        .status();
    if let Ok(status) = check {
        if status.success() {
            return Ok(());
        }
    }
    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={rule_name}"),
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={port}"),
        ])
        .status()?;
    if !status.success() {
        warn!("failed to create DoH firewall rule status {:?}", status);
    }
    Ok(())
}

fn register_windows_doh_template(cfg: &DnsConfig) -> Result<()> {
    if cfg.servers_v4.is_empty() {
        anyhow::bail!("servers_v4 vide: impossible d'enregistrer DoH");
    }
    let server_address = cfg.servers_v4[0].trim().to_string();
    let template = cfg.doh_template_url();
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$server = '{server}'
$template = '{template}'
$existing = Get-DnsClientDohServerAddress -ServerAddress $server -ErrorAction SilentlyContinue
if ($null -eq $existing) {{
  Add-DnsClientDohServerAddress -ServerAddress $server -DohTemplate $template -AllowFallbackToUdp $false -AutoUpgrade $true
}} else {{
  Set-DnsClientDohServerAddress -ServerAddress $server -DohTemplate $template -AllowFallbackToUdp $false -AutoUpgrade $true
}}"#,
        server = server_address.replace('\'', "''"),
        template = template.replace('\'', "''"),
    );
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let details = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!("register DoH template failed: {}", details);
    }
    Ok(())
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
        let doh_tls = if cfg.doh.enabled {
            match load_doh_tls_config(&cfg) {
                Ok(tls) => Some(tls),
                Err(e) => {
                    error!("failed to prepare DoH TLS: {e:#}");
                    None
                }
            }
        } else {
            None
        };
        if cfg.doh.enabled {
            if let Err(e) = register_windows_doh_template(&cfg) {
                warn!("DoH template registration skipped: {e:#}");
            }
        }

        let shared = SharedState {
            cfg: Arc::new(Mutex::new(cfg)),
            stopping: Arc::new(AtomicBool::new(false)),
        };

        if let Some(tls) = doh_tls {
            let doh_shared = shared.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_doh(doh_shared, tls).await {
                    error!("DoH server error: {e:#}");
                }
            });
        } else {
            info!("DoH server disabled");
        }

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
        let doh_tls = if cfg.doh.enabled {
            match load_doh_tls_config(&cfg) {
                Ok(tls) => Some(tls),
                Err(e) => {
                    error!("failed to prepare DoH TLS: {e:#}");
                    None
                }
            }
        } else {
            None
        };
        if cfg.doh.enabled {
            if let Err(e) = register_windows_doh_template(&cfg) {
                warn!("DoH template registration skipped: {e:#}");
            }
        }
        let shared = SharedState {
            cfg: Arc::new(Mutex::new(cfg)),
            stopping: Arc::new(AtomicBool::new(false)),
        };

        if let Some(tls) = doh_tls {
            let doh_shared = shared.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_doh(doh_shared, tls).await {
                    error!("DoH server error: {e:#}");
                }
            });
        } else {
            info!("DoH server disabled");
        }

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
    if cfg.doh.enabled {
        ensure_doh_certificate(&cfg)?;
        let _ = import_certificate_to_trust_store(&doh_certificate_path());
        let _ = ensure_doh_firewall_rule(cfg.doh.port);
        if let Err(e) = register_windows_doh_template(&cfg) {
            warn!("DoH template registration failed during install: {e:#}");
        }
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    if let Ok(_svc) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        info!("Service already installed, reinstalling to refresh binary/config");
        uninstall_service().context("failed to reinstall existing service")?;
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
        "doh-register" => {
            let cfg = load_config_or_init()?;
            init_logger(level_from_cfg(&cfg))?;
            ensure_doh_certificate(&cfg)?;
            let _ = import_certificate_to_trust_store(&doh_certificate_path());
            register_windows_doh_template(&cfg)?;
            println!("Template DoH enregistré: {}", cfg.doh_template_url());
        }
        _ => {
            eprintln!(
                "Usage: home-dns [install|uninstall|run|console|apply-once|restore|doh-register]"
            );
        }
    }
    Ok(())
}

fn named_pipe_stream()
-> anyhow::Result<UnboundedReceiverStream<Result<PipeConnection, std::io::Error>>> {
    let sddl = "D:(A;;GA;;;AC)(A;;GA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)(A;;FA;;;IU)"; // Allow AppContainer, Everyone, System, Admins, Authenticated, Interactive
    info!(
        "Preparing DNS named pipe listener: pipe={} sddl={}",
        NAMED_PIPE_NAME, sddl
    );
    let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    let result = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            windows_sys::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(anyhow::anyhow!(
            "Failed to create security descriptor: {}",
            io::Error::last_os_error()
        ));
    }

    let sd_addr = sd as usize;
    let (tx, rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        struct SecurityDescriptorGuard(usize);
        impl Drop for SecurityDescriptorGuard {
            fn drop(&mut self) {
                if self.0 != 0 {
                    unsafe {
                        windows_sys::Win32::Foundation::LocalFree(self.0 as *mut c_void);
                    }
                }
            }
        }
        let _guard = SecurityDescriptorGuard(sd_addr);

        let mut server = {
            let mut sa_first = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: sd_addr as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
                bInheritHandle: 0,
            };
            match unsafe {
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .create_with_security_attributes_raw(
                        NAMED_PIPE_NAME,
                        &mut sa_first as *mut _ as *mut _,
                    )
            } {
                Ok(s) => Some(s),
                Err(e) => {
                    error!(
                        "Failed to create first DNS named pipe instance: kind={:?} os_code={:?} err={}",
                        e.kind(),
                        e.raw_os_error(),
                        e
                    );
                    let _ = tx.send(Err(e));
                    return;
                }
            }
        };

        let mut accepted_count: u64 = 0;
        loop {
            if let Some(s) = server.take() {
                match s.connect().await {
                    Ok(()) => {
                        accepted_count += 1;
                        info!(
                            "DNS named pipe accepted client connection count={}",
                            accepted_count
                        );
                        let new_server = {
                            let mut sa_loop = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                                nLength: std::mem::size_of::<
                                    windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
                                >() as u32,
                                lpSecurityDescriptor: sd_addr
                                    as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
                                bInheritHandle: 0,
                            };
                            match unsafe {
                                ServerOptions::new().create_with_security_attributes_raw(
                                    NAMED_PIPE_NAME,
                                    &mut sa_loop as *mut _ as *mut _,
                                )
                            } {
                                Ok(s) => s,
                                Err(e) => {
                                    error!(
                                        "Failed to create next DNS named pipe instance after accept count={}: kind={:?} os_code={:?} err={}",
                                        accepted_count,
                                        e.kind(),
                                        e.raw_os_error(),
                                        e
                                    );
                                    let _ = tx.send(Err(e));
                                    break;
                                }
                            }
                        };
                        if tx.send(Ok(PipeConnection::new(s))).is_err() {
                            break;
                        }
                        server = Some(new_server);
                    }
                    Err(e) => {
                        warn!(
                            "DNS named pipe connect() failed: kind={:?} os_code={:?} err={}",
                            e.kind(),
                            e.raw_os_error(),
                            e
                        );
                        if tx.send(Err(e)).is_err() {
                            break;
                        }
                    }
                }
            } else {
                break;
            }
        }
    });

    Ok(UnboundedReceiverStream::new(rx))
}
