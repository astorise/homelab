#![cfg_attr(not(windows), allow(dead_code))]
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
use http::Uri;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use log::{error, info, warn, LevelFilter};
use parking_lot::Mutex;
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use std::ffi::{c_void, OsString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::{server::Connected, Server};
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_manager::*};

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
    pub mod homehttp {
        pub mod v1 {
            tonic::include_proto!("homehttp.v1");
        }
    }
}

use proto::homehttp::v1::home_http_server::{HomeHttp, HomeHttpServer};
use proto::homehttp::v1::{
    list_routes_response, list_tcp_routes_response, Acknowledge, AddRouteRequest,
    AddTcpRouteRequest, Empty, ListRoutesResponse, ListTcpRoutesResponse, RemoveRouteRequest,
    RemoveTcpRouteRequest, StatusResponse, TcpListenScope, TcpTargetKind,
};

// Harmonized naming with DNS service
const SERVICE_NAME: &str = "HomeHttpService";
const SERVICE_DISPLAY_NAME: &str = "Home HTTP Service";
const SERVICE_DESCRIPTION: &str =
    r"HTTP, TLS SNI and TCP L4 proxy to WSL/Windows targets with Windows RPC IPC on endpoint home-http";
#[cfg(debug_assertions)]
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-http-dev";
#[cfg(not(debug_assertions))]
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-http";

#[allow(dead_code)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct HttpConfig {
    #[serde(default = "default_http_port")]
    http: u16,
    #[serde(default = "default_https_port")]
    https: u16,
    #[serde(default)]
    routes: HashMap<String, u16>, // host -> port (u16)
    #[serde(default)]
    tcp_routes: Vec<TcpRouteConfig>,
    #[serde(default)]
    log_level: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum TcpListenScopeConfig {
    #[default]
    Loopback,
    Any,
}

impl TcpListenScopeConfig {
    fn bind_ip(self) -> IpAddr {
        match self {
            Self::Loopback => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Self::Any => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    fn to_proto(self) -> i32 {
        match self {
            Self::Loopback => TcpListenScope::Loopback as i32,
            Self::Any => TcpListenScope::Any as i32,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        match TcpListenScope::try_from(value).unwrap_or(TcpListenScope::Loopback) {
            TcpListenScope::Loopback => Ok(Self::Loopback),
            TcpListenScope::Any => Ok(Self::Any),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum TcpTargetKindConfig {
    #[default]
    Wsl,
    Address,
}

impl TcpTargetKindConfig {
    fn to_proto(self) -> i32 {
        match self {
            Self::Wsl => TcpTargetKind::Wsl as i32,
            Self::Address => TcpTargetKind::Address as i32,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        match TcpTargetKind::try_from(value).unwrap_or(TcpTargetKind::Wsl) {
            TcpTargetKind::Wsl => Ok(Self::Wsl),
            TcpTargetKind::Address => Ok(Self::Address),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct TcpRouteConfig {
    name: String,
    listen_port: u16,
    target_port: u16,
    #[serde(default)]
    listen_scope: TcpListenScopeConfig,
    #[serde(default)]
    target_kind: TcpTargetKindConfig,
    #[serde(default)]
    target_host: Option<String>,
    #[serde(default)]
    server_name: Option<String>,
}

impl TcpRouteConfig {
    fn listener_key(&self) -> String {
        format!("{}:{}", self.listen_scope.bind_ip(), self.listen_port)
    }

    fn bind_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen_scope.bind_ip(), self.listen_port)
    }

    fn resolve_target_hosts(&self) -> Vec<String> {
        match self.target_kind {
            TcpTargetKindConfig::Wsl => select_wsl_target_hosts(),
            TcpTargetKindConfig::Address => vec![
                self.target_host
                    .clone()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| Ipv4Addr::LOCALHOST.to_string()),
            ],
        }
    }

    fn normalized_server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }
}

fn select_wsl_target_hosts() -> Vec<String> {
    vec![Ipv4Addr::LOCALHOST.to_string()]
}

async fn connect_target_hosts(hosts: Vec<String>, port: u16) -> Result<(TcpStream, String)> {
    let mut errors = Vec::new();
    for host in hosts {
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(stream) => return Ok((stream, host)),
            Err(err) => errors.push(format!("{}:{} ({})", host, port, err)),
        }
    }

    anyhow::bail!("connect tcp upstream failed: {}", errors.join(", "))
}

fn default_http_port() -> u16 {
    80
}
fn default_https_port() -> u16 {
    443
}

fn program_data_dir() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\home-http")
}
fn logs_dir() -> PathBuf {
    program_data_dir().join("logs")
}
fn config_path() -> PathBuf {
    program_data_dir().join("http.yaml")
}

fn level_from_cfg(cfg: &HttpConfig) -> LevelFilter {
    match cfg.log_level.as_deref().unwrap_or("info") {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => LevelFilter::Info,
    }
}

fn init_logger(level: LevelFilter) -> Result<()> {
    let dir = logs_dir();
    let basename = build_log_basename("home-http");
    std::fs::create_dir_all(&dir).map_err(|e| {
        eprintln!("cannot create log directory {}: {e}", dir.display());
        e
    })?;
    let logger = Logger::try_with_env_or_str(format!("{level}"))?
        .log_to_file(
            FileSpec::default()
                .directory(&dir)
                .basename(basename)
                .suffix("log"),
        )
        .duplicate_to_stderr(Duplicate::Error)
        .rotate(
            Criterion::Age(Age::Day),
            Naming::Timestamps,
            Cleanup::KeepLogFiles(14),
        );
    match logger.start() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("failed to start logger (continuing): {e}");
        }
    }
    Ok(())
}

fn load_config_or_init() -> Result<HttpConfig> {
    let p = config_path();
    if !p.exists() {
        std::fs::create_dir_all(program_data_dir())?;
        let cfg = HttpConfig {
            http: 80,
            https: 443,
            routes: HashMap::new(),
            tcp_routes: Vec::new(),
            log_level: Some(default_level_str().into()),
        };
        save_config(&cfg)?;
        return Ok(cfg);
    }
    let s =
        std::fs::read_to_string(&p).with_context(|| format!("lecture config: {}", p.display()))?;
    let cfg: HttpConfig = serde_yaml::from_str(&s).context("YAML invalide")?;
    Ok(cfg)
}
fn save_config(cfg: &HttpConfig) -> Result<()> {
    let yaml = serde_yaml::to_string(cfg)?;
    write_atomic(&config_path(), yaml.as_bytes())
}
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn normalize_tcp_route_name(name: &str) -> Result<String> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        anyhow::bail!("tcp route name is required");
    }
    if normalized
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')))
    {
        anyhow::bail!("tcp route name contains unsupported characters");
    }
    Ok(normalized)
}

fn normalize_server_name(value: &str) -> Option<String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn tcp_route_from_request(req: AddTcpRouteRequest) -> Result<TcpRouteConfig> {
    let listen_port = u16::try_from(req.listen_port).context("listen_port out of range")?;
    let target_port = u16::try_from(req.target_port).context("target_port out of range")?;
    if listen_port == 0 {
        anyhow::bail!("listen_port must be greater than zero");
    }
    if target_port == 0 {
        anyhow::bail!("target_port must be greater than zero");
    }

    let target_kind = TcpTargetKindConfig::from_proto(req.target_kind)?;
    let target_host = match target_kind {
        TcpTargetKindConfig::Wsl => None,
        TcpTargetKindConfig::Address => Some(
            req.target_host
                .trim()
                .to_string()
                .chars()
                .collect::<String>(),
        )
        .filter(|value| !value.is_empty()),
    };

    Ok(TcpRouteConfig {
        name: normalize_tcp_route_name(&req.name)?,
        listen_port,
        target_port,
        listen_scope: TcpListenScopeConfig::from_proto(req.listen_scope)?,
        target_kind,
        target_host,
        server_name: normalize_server_name(&req.server_name),
    })
}

async fn proxy_tcp_connection(
    mut inbound: TcpStream,
    route: TcpRouteConfig,
    _shared: Shared,
) -> Result<()> {
    let (mut outbound, target_host) =
        connect_target_hosts(route.resolve_target_hosts(), route.target_port).await?;
    inbound.set_nodelay(true)?;
    outbound.set_nodelay(true)?;
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .with_context(|| {
            format!(
                "tcp proxy copy for route {} via {}:{}",
                route.name, target_host, route.target_port
            )
        })?;
    Ok(())
}

async fn proxy_tcp_sni_connection(
    inbound: TcpStream,
    routes: Vec<TcpRouteConfig>,
    shared: Shared,
) -> Result<()> {
    inbound.set_nodelay(true)?;
    let mut buf = vec![0u8; MAX_CLIENT_HELLO];
    let n = inbound.peek(&mut buf).await?;
    if n < 5 {
        anyhow::bail!("client hello too short");
    }

    let server_name = normalize_server_name(&parse_sni(&buf[..n]).context("parse sni")?)
        .ok_or_else(|| anyhow!("missing server name"))?;
    let route = routes
        .into_iter()
        .find(|route| route.normalized_server_name() == Some(server_name.as_str()))
        .with_context(|| format!("no tcp SNI route for {}", server_name))?;

    proxy_tcp_connection(inbound, route, shared).await
}

async fn run_tcp_route_listener_group(routes: Vec<TcpRouteConfig>, shared: Shared) {
    let Some(first_route) = routes.first().cloned() else {
        return;
    };
    let bind_addr = first_route.bind_addr();
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(
                "tcp route '{}' failed to bind on {}: {}",
                first_route.name, bind_addr, err
            );
            return;
        }
    };
    let sni_mode = routes.iter().all(|route| route.server_name.is_some());

    info!(
        "TCP listener '{}' on {} mode={} route_count={}",
        first_route.name,
        bind_addr,
        if sni_mode { "tls-sni" } else { "raw" },
        routes.len()
    );

    loop {
        if shared.stopping.load(Ordering::SeqCst) || STOP_REQUESTED.load(Ordering::SeqCst) {
            break;
        }

        let accepted = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
        let (inbound, peer) = match accepted {
            Ok(Ok(value)) => value,
            Ok(Err(err)) => {
                warn!(
                    "tcp accept failed for '{}' on {}: {}",
                    first_route.name, bind_addr, err
                );
                continue;
            }
            Err(_) => continue,
        };

        let routes_for_conn = routes.clone();
        let shared_for_conn = shared.clone();
        let first_route_name = first_route.name.clone();
        tokio::spawn(async move {
            let result = if sni_mode {
                proxy_tcp_sni_connection(inbound, routes_for_conn.clone(), shared_for_conn).await
            } else {
                proxy_tcp_connection(inbound, routes_for_conn[0].clone(), shared_for_conn).await
            };
            if let Err(err) = result {
                warn!(
                    "tcp proxy error for route '{}' from {}: {:#}",
                    first_route_name, peer, err
                );
            }
        });
    }

    info!("TCP listener '{}' stopped on {}", first_route.name, bind_addr);
}

async fn sync_tcp_listeners(shared: &Shared) -> Result<()> {
    let desired_routes = shared.cfg.lock().tcp_routes.clone();
    let mut desired_by_key: HashMap<String, Vec<TcpRouteConfig>> = HashMap::new();
    for route in desired_routes {
        desired_by_key
            .entry(route.listener_key())
            .or_default()
            .push(route);
    }
    for routes in desired_by_key.values_mut() {
        routes.sort_by(|left, right| left.name.cmp(&right.name));
        let sni_count = routes.iter().filter(|route| route.server_name.is_some()).count();
        if sni_count > 0 && sni_count != routes.len() {
            anyhow::bail!(
                "tcp listener {} mixes SNI and raw routes, which is unsupported",
                routes[0].listener_key()
            );
        }
        if sni_count == 0 && routes.len() > 1 {
            anyhow::bail!(
                "tcp listener {} has multiple raw routes, which is unsupported",
                routes[0].listener_key()
            );
        }
    }

    let mut listeners = shared.tcp_listeners.lock();
    let existing_keys: Vec<String> = listeners.keys().cloned().collect();

    for key in existing_keys {
        let restart = match listeners.get(&key) {
            Some(runtime) => runtime.handle.is_finished(),
            None => false,
        };
        let keep = match (listeners.get(&key), desired_by_key.get(&key)) {
            (Some(runtime), Some(desired)) if !restart && runtime.routes == *desired => true,
            _ => false,
        };
        if keep {
            continue;
        }
        if let Some(runtime) = listeners.remove(&key) {
            runtime.handle.abort();
            info!(
                "TCP L4 listener '{}' removed/restarted for key {}",
                runtime
                    .routes
                    .first()
                    .map(|route| route.name.as_str())
                    .unwrap_or("<unknown>"),
                key
            );
        }
    }

    for (key, routes) in desired_by_key {
        if listeners.contains_key(&key) {
            continue;
        }
        let routes_for_task = routes.clone();
        let shared_for_task = shared.clone();
        let handle = tokio::spawn(async move {
            run_tcp_route_listener_group(routes_for_task, shared_for_task).await;
        });
        listeners.insert(key, TcpListenerRuntime { routes, handle });
    }

    Ok(())
}

async fn tcp_route_reconciler(shared: Shared) {
    while !shared.stopping.load(Ordering::SeqCst) && !STOP_REQUESTED.load(Ordering::SeqCst) {
        if let Err(err) = sync_tcp_listeners(&shared).await {
            error!("tcp route reconciliation failed: {:#}", err);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let mut listeners = shared.tcp_listeners.lock();
    for (_, runtime) in listeners.drain() {
        runtime.handle.abort();
    }
}

// ---- gRPC service ----
#[derive(Clone)]
struct Shared {
    cfg: Arc<Mutex<HttpConfig>>,
    stopping: Arc<AtomicBool>,
    tcp_listeners: Arc<Mutex<HashMap<String, TcpListenerRuntime>>>,
}

struct TcpListenerRuntime {
    routes: Vec<TcpRouteConfig>,
    handle: JoinHandle<()>,
}

struct MyHttpService {
    shared: Shared,
}

#[tonic::async_trait]
impl HomeHttp for MyHttpService {
    async fn stop_service(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<Acknowledge>, tonic::Status> {
        self.shared.stopping.store(true, Ordering::SeqCst);
        Ok(tonic::Response::new(Acknowledge {
            ok: true,
            message: "stopping".into(),
        }))
    }

    async fn reload_config(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<Acknowledge>, tonic::Status> {
        match load_config_or_init() {
            Ok(new_cfg) => {
                *self.shared.cfg.lock() = new_cfg;
                if let Err(err) = sync_tcp_listeners(&self.shared).await {
                    error!("reload_config failed to sync tcp listeners: {err:#}");
                    return Err(tonic::Status::internal(err.to_string()));
                }
                Ok(tonic::Response::new(Acknowledge {
                    ok: true,
                    message: "reloaded".into(),
                }))
            }
            Err(e) => {
                error!("reload_config failed: {e:#}");
                Err(tonic::Status::internal(e.to_string()))
            }
        }
    }

    async fn get_status(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<StatusResponse>, tonic::Status> {
        let cfg = self.shared.cfg.lock().clone();
        let res = StatusResponse {
            state: if self.shared.stopping.load(Ordering::SeqCst) {
                "stopping".into()
            } else {
                "running".into()
            },
            log_level: cfg.log_level.unwrap_or_else(|| "info".into()),
        };
        Ok(tonic::Response::new(res))
    }

    async fn add_route(
        &self,
        request: tonic::Request<AddRouteRequest>,
    ) -> Result<tonic::Response<Acknowledge>, tonic::Status> {
        let req = request.into_inner();
        let port = u16::try_from(req.port)
            .map_err(|_| tonic::Status::invalid_argument("port out of range for u16"))?;
        let mut cfg = self.shared.cfg.lock().clone();
        cfg.routes.insert(req.host.to_lowercase(), port);
        if let Err(e) = save_config(&cfg) {
            error!("add_route failed to save config: {e:#}");
            return Err(tonic::Status::internal(e.to_string()));
        }
        *self.shared.cfg.lock() = cfg;
        Ok(tonic::Response::new(Acknowledge {
            ok: true,
            message: "added".into(),
        }))
    }

    async fn remove_route(
        &self,
        request: tonic::Request<RemoveRouteRequest>,
    ) -> Result<tonic::Response<Acknowledge>, tonic::Status> {
        let req = request.into_inner();
        let mut cfg = self.shared.cfg.lock().clone();
        cfg.routes.remove(&req.host.to_lowercase());
        if let Err(e) = save_config(&cfg) {
            error!("remove_route failed to save config: {e:#}");
            return Err(tonic::Status::internal(e.to_string()));
        }
        *self.shared.cfg.lock() = cfg;
        Ok(tonic::Response::new(Acknowledge {
            ok: true,
            message: "removed".into(),
        }))
    }

    async fn list_routes(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<ListRoutesResponse>, tonic::Status> {
        let cfg = self.shared.cfg.lock().clone();
        let routes = cfg
            .routes
            .into_iter()
            .map(|(h, p)| list_routes_response::Route {
                host: h,
                port: p as u32,
            })
            .collect();
        Ok(tonic::Response::new(ListRoutesResponse { routes }))
    }

    async fn add_tcp_route(
        &self,
        request: tonic::Request<AddTcpRouteRequest>,
    ) -> Result<tonic::Response<Acknowledge>, tonic::Status> {
        let route = tcp_route_from_request(request.into_inner())
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
        let mut cfg = self.shared.cfg.lock().clone();
        cfg.tcp_routes.retain(|existing| existing.name != route.name);
        cfg.tcp_routes.push(route);
        cfg.tcp_routes.sort_by(|left, right| {
            left.listen_port
                .cmp(&right.listen_port)
                .then_with(|| left.name.cmp(&right.name))
        });
        if let Err(err) = save_config(&cfg) {
            error!("add_tcp_route failed to save config: {err:#}");
            return Err(tonic::Status::internal(err.to_string()));
        }
        *self.shared.cfg.lock() = cfg;
        if let Err(err) = sync_tcp_listeners(&self.shared).await {
            error!("add_tcp_route failed to sync listeners: {err:#}");
            return Err(tonic::Status::internal(err.to_string()));
        }
        Ok(tonic::Response::new(Acknowledge {
            ok: true,
            message: "added".into(),
        }))
    }

    async fn remove_tcp_route(
        &self,
        request: tonic::Request<RemoveTcpRouteRequest>,
    ) -> Result<tonic::Response<Acknowledge>, tonic::Status> {
        let req = request.into_inner();
        let name = normalize_tcp_route_name(&req.name)
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
        let mut cfg = self.shared.cfg.lock().clone();
        cfg.tcp_routes.retain(|route| route.name != name);
        if let Err(err) = save_config(&cfg) {
            error!("remove_tcp_route failed to save config: {err:#}");
            return Err(tonic::Status::internal(err.to_string()));
        }
        *self.shared.cfg.lock() = cfg;
        if let Err(err) = sync_tcp_listeners(&self.shared).await {
            error!("remove_tcp_route failed to sync listeners: {err:#}");
            return Err(tonic::Status::internal(err.to_string()));
        }
        Ok(tonic::Response::new(Acknowledge {
            ok: true,
            message: "removed".into(),
        }))
    }

    async fn list_tcp_routes(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<ListTcpRoutesResponse>, tonic::Status> {
        let cfg = self.shared.cfg.lock().clone();
        let routes = cfg
            .tcp_routes
            .into_iter()
            .map(|route| list_tcp_routes_response::Route {
                name: route.name,
                listen_port: route.listen_port as u32,
                target_port: route.target_port as u32,
                listen_scope: route.listen_scope.to_proto(),
                target_kind: route.target_kind.to_proto(),
                target_host: route.target_host.unwrap_or_default(),
                server_name: route.server_name.unwrap_or_default(),
            })
            .collect();
        Ok(tonic::Response::new(ListTcpRoutesResponse { routes }))
    }
}

// ---- HTTP http (Hyper 1.x) ----
#[derive(Clone)]
struct HttpHttp {
    shared: Shared,
}
impl HttpHttp {
    fn new(shared: Shared) -> Self {
        Self { shared }
    }
    async fn serve(self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("HTTP listening on {}", addr);
        loop {
            let (io, peer) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let me = me.clone();
                    async move {
                        me.handle(req).await.map_err(|e| {
                            warn!("http handler error from {}: {e:?}", peer);
                            e
                        })
                    }
                });
                let io = TokioIo::new(io);
                if let Err(e) = ServerBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, svc)
                    .await
                {
                    warn!("serve_connection error from {}: {e:?}", peer);
                }
            });
        }
    }
    async fn handle(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let host_hdr = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let host = host_hdr
            .split(':')
            .next()
            .unwrap_or(host_hdr)
            .to_lowercase();
        let https_port = self.shared.cfg.lock().https;
        let has_route = self.shared.cfg.lock().routes.contains_key(&host);
        let Some(_) = has_route.then_some(()) else {
            let body = Full::from(Bytes::from_static(b"bad gateway: no route"))
                .map_err(|never| match never {})
                .boxed(); // -> BoxBody<Bytes, hyper::Error>
            return Ok(Response::builder().status(502).body(body).unwrap());
        };
        let path_q = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let authority = if https_port == 443 {
            host
        } else {
            format!("{}:{}", host, https_port)
        };
        let location: Uri = format!("https://{}{}", authority, path_q).parse().unwrap();
        let body = Full::from(Bytes::new())
            .map_err(|never| match never {})
            .boxed();
        Ok(Response::builder()
            .status(http::StatusCode::PERMANENT_REDIRECT)
            .header(http::header::LOCATION, location.to_string())
            .body(body)
            .unwrap())
    }
}

// ---- TLS SNI pass-through ----
struct TlsSnihttp {
    shared: Shared,
}
impl TlsSnihttp {
    fn new(shared: Shared) -> Self {
        Self { shared }
    }
}
impl TlsSnihttp {
    async fn serve(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("HTTPS (SNI pass-through) listening on {}", addr);
        loop {
            let (mut inbound, peer) = listener.accept().await?;
            let shared = self.shared.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_tls_conn(&mut inbound, peer, shared).await {
                    warn!("tls pass-through error from {}: {e:?}", peer);
                }
            });
        }
    }
}
const MAX_CLIENT_HELLO: usize = 8 * 1024;
async fn handle_tls_conn(inb: &mut TcpStream, _peer: SocketAddr, shared: Shared) -> Result<()> {
    inb.set_nodelay(true)?;
    let mut buf = vec![0u8; MAX_CLIENT_HELLO];
    let n = inb.peek(&mut buf).await?;
    if n < 5 {
        return Err(anyhow!("client hello too short"));
    }
    let host = parse_sni(&buf[..n]).context("parse sni")?.to_lowercase();
    let port = shared
        .cfg
        .lock()
        .routes
        .get(&host)
        .copied()
        .context("no route for host")?;
    let (mut outb, _) = connect_target_hosts(select_wsl_target_hosts(), port).await?;
    outb.set_nodelay(true)?;
    let (mut ri, mut wi) = inb.split();
    let (mut ro, mut wo) = outb.split();
    let c2s = async {
        tokio::io::copy(&mut ri, &mut wo).await?;
        tokio::io::AsyncWriteExt::shutdown(&mut wo)
            .await
            .map_err(|e| anyhow!(e))
    };
    let s2c = async {
        tokio::io::copy(&mut ro, &mut wi).await?;
        tokio::io::AsyncWriteExt::shutdown(&mut wi)
            .await
            .map_err(|e| anyhow!(e))
    };
    tokio::try_join!(c2s, s2c)?;
    Ok(())
}
fn parse_sni(mut buf: &[u8]) -> Result<String> {
    if buf.len() < 5 || buf[0] != 22 {
        anyhow::bail!("not handshake");
    }
    buf = &buf[5..];
    if buf.len() < 4 || buf[0] != 1 {
        anyhow::bail!("not clienthello");
    }
    let hs_len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + hs_len {
        anyhow::bail!("hello truncated");
    }
    let mut p = &buf[4..4 + hs_len];
    if p.len() < 34 {
        anyhow::bail!("short");
    }
    p = &p[34..];
    if p.is_empty() {
        anyhow::bail!("sid");
    }
    let sid_len = p[0] as usize;
    p = &p[1 + sid_len..];
    if p.len() < 2 {
        anyhow::bail!("cs");
    }
    let cs_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    p = &p[2 + cs_len..];
    if p.is_empty() {
        anyhow::bail!("cm");
    }
    let cm_len = p[0] as usize;
    p = &p[1 + cm_len..];
    if p.len() < 2 {
        anyhow::bail!("no ext");
    }
    let ext_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    p = &p[2..2 + ext_len];
    let mut q = p;
    while q.len() >= 4 {
        let typ = u16::from_be_bytes([q[0], q[1]]);
        let len = u16::from_be_bytes([q[2], q[3]]) as usize;
        q = &q[4..];
        let body = &q[..len];
        q = &q[len..];
        if typ == 0 {
            let mut r = body;
            if r.len() < 2 {
                anyhow::bail!("sni list len");
            }
            let list_len = u16::from_be_bytes([r[0], r[1]]) as usize;
            r = &r[2..2 + list_len];
            let mut e = r;
            while e.len() >= 3 {
                let name_type = e[0];
                let nl = u16::from_be_bytes([e[1], e[2]]) as usize;
                e = &e[3..];
                let name = &e[..nl];
                e = &e[nl..];
                if name_type == 0 {
                    return Ok(std::str::from_utf8(name)?.to_string());
                }
            }
        }
    }
    anyhow::bail!("no sni")
}

// ---- Service Windows ----
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

define_windows_service!(ffi_service_main, service_main);
#[allow(dead_code)]
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("service error: {e:?}");
    }
}

fn run_service() -> Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                STOP_REQUESTED.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    let set_status = |state: ServiceState| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    set_status(ServiceState::StartPending);

    eprintln!("[home-http] service control handler registered");
    let cfg = load_config_or_init()?;
    let level = level_from_cfg(&cfg);
    init_logger(level)?;
    info!("Service starting (level={:?})", level);
    info!(
        "build tag={} sha={} at {}",
        BUILD_GIT_TAG, BUILD_GIT_SHA, BUILD_TIME
    );

    let shared = Shared {
        cfg: Arc::new(Mutex::new(cfg)),
        stopping: Arc::new(AtomicBool::new(false)),
        tcp_listeners: Arc::new(Mutex::new(HashMap::new())),
    };

    eprintln!("[home-http] creating tokio runtime");
    let rt = Runtime::new()?;
    rt.block_on(sync_tcp_listeners(&shared))?;

    // gRPC server over named pipe
    let grpc_service = MyHttpService {
        shared: shared.clone(),
    };
    let grpc_server = Server::builder().add_service(HomeHttpServer::new(grpc_service));
    rt.spawn(async move {
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

    {
        let tcp_shared = shared.clone();
        rt.spawn(async move {
            tcp_route_reconciler(tcp_shared).await;
        });
    }

    // HTTP/HTTPS servers
    let http_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), shared.cfg.lock().http);
    let https_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), shared.cfg.lock().https);
    let http = HttpHttp::new(shared.clone());
    let tls = TlsSnihttp::new(shared.clone());

    rt.spawn(async move {
        info!("Starting HTTP listener on {}", http_addr);
        if let Err(e) = http.serve(http_addr).await {
            error!("http server: {e:?}");
        }
    });
    rt.spawn(async move {
        info!("Starting HTTPS (SNI) listener on {}", https_addr);
        if let Err(e) = tls.serve(https_addr).await {
            error!("https server: {e:?}");
        }
    });

    set_status(ServiceState::Running);
    info!("Service running");
    eprintln!("[home-http] service entered running state");

    while !STOP_REQUESTED.load(Ordering::SeqCst) && !shared.stopping.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500));
    }

    info!("Service stopping");
    set_status(ServiceState::Stopped);
    info!("Service stopped");
    Ok(())
}

fn install_service() -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    // Upgrade-safe install: if service exists, reinstall it.
    if let Ok(_svc) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        info!("Service already installed, reinstalling to refresh binary/config");
        uninstall_service().context("failed to reinstall existing service")?;
    }
    let service_info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart, // windows-service 0.8
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
    service.set_description(SERVICE_DESCRIPTION)?;
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
    )?;
    // Request stop and wait a bit for it
    let _ = service.stop();
    for _ in 0..20 {
        if let Ok(st) = service.query_status() {
            if st.current_state == ServiceState::Stopped {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    service.delete()?;
    drop(service);
    // Wait until SCM no longer returns the service; tolerate races
    for _ in 0..20 {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(s) => {
                drop(s);
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

fn usage() {
    eprintln!("Usage: home-http [run|install|uninstall|console]");
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        usage();
        return Ok(());
    }
    match args[1].as_str() {
        "run" => {
            #[cfg(windows)]
            {
                if let Err(e) =
                    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
                {
                    eprintln!("service dispatcher start error: {e:?}");
                }
                return Ok(());
            }
            #[cfg(not(windows))]
            {
                anyhow::bail!("Windows only");
            }
        }
        "install" => {
            install_service()?;
            println!(
                "Service installe. Modifiez {} puis demarrez le service.",
                config_path().display()
            );
        }
        "uninstall" => {
            uninstall_service()?;
            println!("Service desinstalle.");
        }
        "console" => {
            let cfg = load_config_or_init()?;
            init_logger(level_from_cfg(&cfg))?;
            info!("Console mode starting");
            let rt = Runtime::new()?;
            rt.block_on(async {
                let shared = Shared {
                    cfg: Arc::new(Mutex::new(cfg)),
                    stopping: Arc::new(AtomicBool::new(false)),
                    tcp_listeners: Arc::new(Mutex::new(HashMap::new())),
                };
                if let Err(err) = sync_tcp_listeners(&shared).await {
                    error!("initial tcp listener sync failed: {err:#}");
                    return;
                }

                // gRPC server
                let grpc_service = MyHttpService {
                    shared: shared.clone(),
                };
                let grpc_server = Server::builder().add_service(HomeHttpServer::new(grpc_service));
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

                {
                    let tcp_shared = shared.clone();
                    tokio::spawn(async move {
                        tcp_route_reconciler(tcp_shared).await;
                    });
                }

                // HTTP/HTTPS servers
                let http_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), shared.cfg.lock().http);
                let https_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), shared.cfg.lock().https);
                let http = HttpHttp::new(shared.clone());
                let tls = TlsSnihttp::new(shared.clone());
                tokio::spawn(async move {
                    if let Err(e) = http.serve(http_addr).await {
                        error!("http server: {e:?}");
                    }
                });
                tokio::spawn(async move {
                    if let Err(e) = tls.serve(https_addr).await {
                        error!("https server: {e:?}");
                    }
                });

                info!("Console mode running. Press Ctrl+C to stop.");
                while !shared.stopping.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            });
        }
        _ => usage(),
    }
    Ok(())
}

fn named_pipe_stream() -> io::Result<UnboundedReceiverStream<Result<PipeConnection, io::Error>>> {
    let sddl = "D:(A;;GA;;;AC)(A;;GA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)(A;;FA;;;IU)"; // Allow AppContainer, Everyone, System, Admins, Authenticated, Interactive
    info!(
        "Preparing HTTP named pipe listener: pipe={} sddl={}",
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
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        error!(
            "FATAL: ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
            err
        );
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Security attributes creation failed",
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

        let first_server = {
            let mut sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
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
                        &mut sa as *mut _ as *mut _,
                    )
            } {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "Failed to create first HTTP named pipe instance: kind={:?} os_code={:?} err={}",
                        e.kind(),
                        e.raw_os_error(),
                        e
                    );
                    let _ = tx.send(Err(e));
                    return;
                }
            }
        };

        let mut server = Some(first_server);
        let mut accepted_count: u64 = 0;

        loop {
            if let Some(s) = server.take() {
                match s.connect().await {
                    Ok(()) => {
                        accepted_count += 1;
                        info!(
                            "HTTP named pipe accepted client connection count={}",
                            accepted_count
                        );
                        let mut sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                            nLength: std::mem::size_of::<
                                windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
                            >() as u32,
                            lpSecurityDescriptor: sd_addr
                                as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
                            bInheritHandle: 0,
                        };
                        let new_server = match unsafe {
                            ServerOptions::new()
                                .first_pipe_instance(false)
                                .create_with_security_attributes_raw(
                                    NAMED_PIPE_NAME,
                                    &mut sa as *mut _ as *mut _,
                                )
                        } {
                            Ok(s) => s,
                            Err(e) => {
                                error!(
                                    "Failed to create next HTTP named pipe instance after accept count={}: kind={:?} os_code={:?} err={}",
                                    accepted_count,
                                    e.kind(),
                                    e.raw_os_error(),
                                    e
                                );
                                let _ = tx.send(Err(e));
                                break;
                            }
                        };
                        if tx.send(Ok(PipeConnection::new(s))).is_err() {
                            break;
                        }
                        server = Some(new_server);
                    }
                    Err(e) => {
                        warn!(
                            "HTTP named pipe connect() failed: kind={:?} os_code={:?} err={}",
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
