#![cfg_attr(not(windows), allow(dead_code))]
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
use http::Uri;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use log::{LevelFilter, error, info, warn};
use parking_lot::Mutex;
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use std::ffi::{OsString, c_void};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::{Server, server::Connected};
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
    Acknowledge, AddRouteRequest, Empty, ListRoutesResponse, RemoveRouteRequest, StatusResponse,
    list_routes_response,
};

// Harmonized naming with DNS service
const SERVICE_NAME: &str = "HomeHttpService";
const SERVICE_DISPLAY_NAME: &str = "Home HTTP Service";
const SERVICE_DESCRIPTION: &str =
    r"HTTP + TLS SNI pass-through to WSL with Windows RPC IPC on ncalrpc endpoint home-http";
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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct HttpConfig {
    #[serde(default = "default_http_port")]
    http: u16,
    #[serde(default = "default_https_port")]
    https: u16,
    #[serde(default = "default_resolve")]
    wsl_resolve: String, // "auto" | "static"
    wsl_ip: Option<String>,
    #[serde(default = "default_refresh")]
    wsl_refresh_secs: u64,
    #[serde(default)]
    routes: HashMap<String, u16>, // host -> port (u16)
    #[serde(default)]
    log_level: Option<String>,
}
fn default_http_port() -> u16 {
    80
}
fn default_https_port() -> u16 {
    443
}
fn default_resolve() -> String {
    "auto".into()
}
fn default_refresh() -> u64 {
    30
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
    std::fs::create_dir_all(&dir).map_err(|e| {
        eprintln!("cannot create log directory {}: {e}", dir.display());
        e
    })?;
    let logger = Logger::try_with_env_or_str(format!("{level}"))?
        .log_to_file(
            FileSpec::default()
                .directory(&dir)
                .basename("home-http")
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
            wsl_resolve: "auto".into(),
            wsl_ip: None,
            wsl_refresh_secs: 30,
            routes: HashMap::new(),
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

fn wsl_ip(cfg: &HttpConfig, cache: &Arc<Mutex<(u64, Option<String>)>>) -> String {
    if cfg.wsl_resolve == "static" {
        return cfg.wsl_ip.clone().unwrap_or_else(|| "127.0.0.1".into());
    }
    let now = chrono::Utc::now().timestamp() as u64;
    {
        let mut guard = cache.lock();
        if let Some(ip) = &guard.1 {
            if now - guard.0 < cfg.wsl_refresh_secs {
                return ip.clone();
            }
        }
        let out = std::process::Command::new("wsl.exe")
            .args(["-e", "sh", "-lc", "hostname -I"])
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                if let Some(ip) = String::from_utf8_lossy(&out.stdout)
                    .split_whitespace()
                    .find(|t| t.parse::<std::net::Ipv4Addr>().is_ok())
                {
                    guard.0 = now;
                    guard.1 = Some(ip.to_string());
                    return ip.to_string();
                }
            }
        }
        "127.0.0.1".into()
    }
}

// ---- gRPC service ----
#[derive(Clone)]
struct Shared {
    cfg: Arc<Mutex<HttpConfig>>,
    cache: Arc<Mutex<(u64, Option<String>)>>,
    stopping: Arc<AtomicBool>,
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
}

// ---- HTTP http (Hyper 1.x) ----
#[derive(Clone)]
struct HttpHttp {
    client: Client<HttpConnector, Full<Bytes>>,
    shared: Shared,
}
impl HttpHttp {
    fn new(shared: Shared) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self { client, shared }
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
        let port = self.shared.cfg.lock().routes.get(&host).copied();
        let Some(port) = port else {
            let body = Full::from(Bytes::from_static(b"bad gateway: no route"))
                .map_err(|never| match never {})
                .boxed(); // -> BoxBody<Bytes, hyper::Error>
            return Ok(Response::builder().status(502).body(body).unwrap());
        };
        let ip = wsl_ip(&self.shared.cfg.lock(), &self.shared.cache);
        let path_q = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let new_uri: Uri = format!("http://{}:{}{}", ip, port, path_q).parse().unwrap();

        // Convert server Incoming -> bytes -> Full
        let (parts, body_in) = req.into_parts();
        let bytes = body_in.collect().await?.to_bytes();
        let mut out_req = Request::from_parts(parts, Full::from(bytes));
        *out_req.uri_mut() = new_uri;

        // Http avec client hyper
        let resp = match self.client.request(out_req).await {
            Ok(r) => r,
            Err(e) => {
                // Convertit l'erreur client en 502 c't' http
                let msg = format!("upstream error: {e}");
                let body = Full::from(Bytes::from(msg))
                    .map_err(|never| match never {})
                    .boxed();
                return Ok(Response::builder().status(502).body(body).unwrap());
            }
        };
        let (parts, body_in) = resp.into_parts();
        let body = body_in.boxed(); // Incoming -> BoxBody<Bytes, hyper::Error>
        Ok(Response::from_parts(parts, body))
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
    let ip = wsl_ip(&shared.cfg.lock(), &shared.cache);
    let mut outb = TcpStream::connect((ip.as_str(), port)).await?;
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
        cache: Arc::new(Mutex::new((0, None))),
        stopping: Arc::new(AtomicBool::new(false)),
    };

    eprintln!("[home-http] creating tokio runtime");
    let rt = Runtime::new()?;

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
    // Idempotent install: if service exists, do nothing.
    if let Ok(_svc) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        info!("Service already installed");
        return Ok(());
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
                    cache: Arc::new(Mutex::new((0, None))),
                    stopping: Arc::new(AtomicBool::new(false)),
                };

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
    let sddl = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)"; // Allow System, Built-in Admins, Authenticated Users
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
        error!("FATAL: ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}", err);
        return Err(io::Error::new(io::ErrorKind::Other, "Security attributes creation failed"));
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
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd_addr as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
                bInheritHandle: 0,
            };
            match unsafe {
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .create_with_security_attributes_raw(NAMED_PIPE_NAME, &mut sa as *mut _ as *mut _)
            } {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            }
        };

        let mut server = Some(first_server);

        loop {
            if let Some(s) = server.take() {
                match s.connect().await {
                    Ok(()) => {
                        let mut sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
                            lpSecurityDescriptor: sd_addr as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
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
