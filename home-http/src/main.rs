#![cfg_attr(not(windows), allow(dead_code))]

use anyhow::{anyhow, Context, Result};
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
use futures_util::StreamExt;
use http::Uri;
use hyper::{Request, Response};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use http_body_util::{Full, BodyExt, combinators::BoxBody};
use bytes::Bytes;
use log::{error, info, warn, LevelFilter};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::mpsc,
};
use tonic::transport::server::Connected;
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_manager::*};

mod homehttp {
    pub mod homehttp {
        pub mod v1 {
            tonic::include_proto!("homehttp.v1");
        }
    }
}
use homehttp::homehttp::v1::home_http_server::{HomeHttp, HomeHttpServer};
use homehttp::homehttp::v1::*;

const SERVICE_NAME: &str = "homehttp";
const SERVICE_DISPLAY_NAME: &str = "Home Http (HTTP/SNI to WSL)";
const SERVICE_DESCRIPTION: &str =
    r"HTTP http + TLS SNI pass-through to WSL with gRPC IPC over named pipe \\.\pipe\home-http";
#[cfg(debug_assertions)]
const PIPE_NAME: &str = r"\\.\pipe\home-http-dev";
#[cfg(not(debug_assertions))]
const PIPE_NAME: &str = r"\\.\pipe\home-http";

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
fn default_http_port() -> u16 { 80 }
fn default_https_port() -> u16 { 443 }
fn default_resolve() -> String { "auto".into() }
fn default_refresh() -> u64 { 30 }

fn program_data_dir() -> PathBuf { PathBuf::from(r"C:\ProgramData\home-http") }
fn logs_dir() -> PathBuf { program_data_dir().join("logs") }
fn config_path() -> PathBuf { program_data_dir().join("http.yaml") }

fn level_from_cfg(cfg: &HttpConfig) -> LevelFilter {
    match cfg.log_level.as_deref().unwrap_or("info") {
        "trace" => LevelFilter::Trace, "debug" => LevelFilter::Debug, "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error, "off" => LevelFilter::Off, _ => LevelFilter::Info
    }
}

fn init_logger(level: LevelFilter) -> Result<()> {
    let dir = logs_dir();
    std::fs::create_dir_all(&dir).map_err(|e| {
        eprintln!("cannot create log directory {}: {e}", dir.display());
        e
    })?;
    Logger::try_with_env_or_str(format!("{level}"))?
        .log_to_file(
            FileSpec::default()
                .directory(dir)
                .basename("home-http")
                .suffix("log"),
        )
        .duplicate_to_stderr(Duplicate::Error)
        .rotate(Criterion::Age(Age::Day), Naming::Timestamps, Cleanup::KeepLogFiles(14))
        .start()
        .map_err(|e| {
            eprintln!("failed to start logger: {e}");
            e
        })?;
    Ok(())
}

fn load_config_or_init() -> Result<HttpConfig> {
    let p = config_path();
    if !p.exists() {
        std::fs::create_dir_all(program_data_dir())?;
        let cfg = HttpConfig {
            http: 80, https: 443, wsl_resolve: "auto".into(), wsl_ip: None, wsl_refresh_secs: 30,
            routes: HashMap::new(), log_level: Some("info".into()),
        };
        save_config(&cfg)?;
        return Ok(cfg);
    }
    let s = std::fs::read_to_string(&p).with_context(|| format!("lecture config: {}", p.display()))?;
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
            if now - guard.0 < cfg.wsl_refresh_secs { return ip.clone(); }
        }
        let out = std::process::Command::new("wsl.exe").args(["-e","sh","-lc","hostname -I"]).output();
        if let Ok(out) = out {
            if out.status.success() {
                if let Some(ip) = String::from_utf8_lossy(&out.stdout).split_whitespace().find(|t| t.parse::<std::net::Ipv4Addr>().is_ok()) {
                    guard.0 = now; guard.1 = Some(ip.to_string()); return ip.to_string();
                }
            }
        }
        "127.0.0.1".into()
    }
}

// ---- gRPC service impl ----
#[derive(Clone)]
struct Shared {
    cfg: Arc<Mutex<HttpConfig>>,
    cache: Arc<Mutex<(u64, Option<String>)>>,
    stopping: Arc<AtomicBool>,
}
struct HomeHttpSvc { shared: Shared }

#[tonic::async_trait]
impl HomeHttp for HomeHttpSvc {
    async fn stop_service(&self, _req: tonic::Request<Empty>) -> std::result::Result<tonic::Response<Acknowledge>, tonic::Status> {
        self.shared.stopping.store(true, Ordering::SeqCst);
        Ok(tonic::Response::new(Acknowledge{ ok: true, message: "stopping".into() }))
    }
    async fn reload_config(&self, _req: tonic::Request<Empty>) -> std::result::Result<tonic::Response<Acknowledge>, tonic::Status> {
        let new_cfg = load_config_or_init().map_err(to_status)?;
        *self.shared.cfg.lock() = new_cfg;
        Ok(tonic::Response::new(Acknowledge{ ok: true, message: "reloaded".into() }))
    }
    async fn get_status(&self, _req: tonic::Request<Empty>) -> std::result::Result<tonic::Response<StatusResponse>, tonic::Status> {
        let cfg = self.shared.cfg.lock().clone();
        Ok(tonic::Response::new(StatusResponse{
            state: if self.shared.stopping.load(Ordering::SeqCst) { "stopping".into() } else { "running".into() },
            log_level: cfg.log_level.unwrap_or_else(|| "info".into())
        }))
    }
    async fn add_route(&self, req: tonic::Request<AddRouteRequest>) -> std::result::Result<tonic::Response<Acknowledge>, tonic::Status> {
        let r = req.into_inner();
        let port_u16: u16 = r.port.try_into().map_err(|_| tonic::Status::invalid_argument("port out of range for u16"))?;
        let mut cfg = self.shared.cfg.lock().clone();
        cfg.routes.insert(r.host.to_lowercase(), port_u16);
        save_config(&cfg).map_err(to_status)?;
        *self.shared.cfg.lock() = cfg;
        Ok(tonic::Response::new(Acknowledge{ ok: true, message: "added".into() }))
    }
    async fn remove_route(&self, req: tonic::Request<RemoveRouteRequest>) -> std::result::Result<tonic::Response<Acknowledge>, tonic::Status> {
        let r = req.into_inner();
        let mut cfg = self.shared.cfg.lock().clone();
        cfg.routes.remove(&r.host.to_lowercase());
        save_config(&cfg).map_err(to_status)?;
        *self.shared.cfg.lock() = cfg;
        Ok(tonic::Response::new(Acknowledge{ ok: true, message: "removed".into() }))
    }
    async fn list_routes(&self, _req: tonic::Request<Empty>) -> std::result::Result<tonic::Response<ListRoutesResponse>, tonic::Status> {
        let cfg = self.shared.cfg.lock().clone();
        let routes = cfg.routes.into_iter().map(|(h,p)| list_routes_response::Route{ host: h, port: p as u32 }).collect();
        Ok(tonic::Response::new(ListRoutesResponse{ routes }))
    }
}
fn to_status(e: anyhow::Error) -> tonic::Status { tonic::Status::internal(format!("{e:#}")) }

// ---- Named pipe incoming (tonic Connected impl pour 0.12) ----
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

struct PipeConn(NamedPipeServer);
impl Connected for PipeConn {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo { () }
}
impl Unpin for PipeConn {}
impl AsyncRead for PipeConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}
impl AsyncWrite for PipeConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
struct PipeIncoming { rx: mpsc::Receiver<Result<NamedPipeServer, std::io::Error>> }
impl PipeIncoming {
    fn new(name: &str) -> Self {
        let (tx, rx) = mpsc::channel(16);
        let name = name.to_string();
        tokio::spawn(async move {
            loop {
                let try_first = ServerOptions::new().first_pipe_instance(true).create(&name)
                    .or_else(|_| ServerOptions::new().first_pipe_instance(false).create(&name));
                match try_first {
                    Ok(pipe) => {
                        let txc = tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = pipe.connect().await {
                                let _ = txc.send(Err(e)).await;
                            } else {
                                let _ = txc.send(Ok(pipe)).await;
                            }
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
        Self { rx }
    }
}
impl futures_util::stream::Stream for PipeIncoming {
    type Item = Result<NamedPipeServer, std::io::Error>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

// ---- HTTP http (Hyper 1.x) ----
#[derive(Clone)]
struct HttpHttp { client: Client<HttpConnector, Full<Bytes>>, shared: Shared }
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
                    async move { me.handle(req).await.map_err(|e| { warn!("http handler error from {}: {e:?}", peer); e }) }
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
    async fn handle(&self, req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let host_hdr = req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        let host = host_hdr.split(':').next().unwrap_or(host_hdr).to_lowercase();
        let port = self.shared.cfg.lock().routes.get(&host).copied();
        let Some(port) = port else {
    let body = Full::from(Bytes::from_static(b"bad gateway: no route"))
        .map_err(|never| match never {})  // Infallible -> hyper::Error
        .boxed();                         // -> BoxBody<Bytes, hyper::Error>
    return Ok(Response::builder().status(502).body(body).unwrap());
};
        let ip = wsl_ip(&self.shared.cfg.lock(), &self.shared.cache);
        let path_q = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
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
        // Convertit l’erreur client en 502 côté http
        let msg = format!("upstream error: {e}");
        let body = Full::from(Bytes::from(msg))
            .map_err(|never| match never {}) // Infallible -> hyper::Error
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
struct TlsSnihttp { shared: Shared }
impl TlsSnihttp { fn new(shared: Shared) -> Self { Self { shared } } }
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
    if n < 5 { return Err(anyhow!("client hello too short")); }
    let host = parse_sni(&buf[..n]).context("parse sni")?.to_lowercase();
    let port = shared.cfg.lock().routes.get(&host).copied().context("no route for host")?;
    let ip = wsl_ip(&shared.cfg.lock(), &shared.cache);
    let mut outb = TcpStream::connect((ip.as_str(), port)).await?;
    outb.set_nodelay(true)?;
    let (mut ri, mut wi) = inb.split();
    let (mut ro, mut wo) = outb.split();
    let c2s = async { tokio::io::copy(&mut ri, &mut wo).await?; wo.shutdown().await.map_err(|e| anyhow!(e)) };
    let s2c = async { tokio::io::copy(&mut ro, &mut wi).await?; wi.shutdown().await.map_err(|e| anyhow!(e)) };
    tokio::try_join!(c2s, s2c)?; Ok(())
}
fn parse_sni(mut buf: &[u8]) -> Result<String> {
    if buf.len() < 5 || buf[0] != 22 { anyhow::bail!("not handshake"); }
    buf = &buf[5..];
    if buf.len() < 4 || buf[0] != 1 { anyhow::bail!("not clienthello"); }
    let hs_len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + hs_len { anyhow::bail!("hello truncated"); }
    let mut p = &buf[4..4+hs_len];
    if p.len() < 34 { anyhow::bail!("short"); }
    p = &p[34..];
    if p.is_empty() { anyhow::bail!("sid"); }
    let sid_len = p[0] as usize; p = &p[1+sid_len..];
    if p.len() < 2 { anyhow::bail!("cs"); }
    let cs_len = u16::from_be_bytes([p[0], p[1]]) as usize; p = &p[2+cs_len..];
    if p.is_empty() { anyhow::bail!("cm"); }
    let cm_len = p[0] as usize; p = &p[1+cm_len..];
    if p.len() < 2 { anyhow::bail!("no ext"); }
    let ext_len = u16::from_be_bytes([p[0], p[1]]) as usize; p = &p[2..2+ext_len];
    let mut q = p;
    while q.len() >= 4 {
        let typ = u16::from_be_bytes([q[0], q[1]]);
        let len = u16::from_be_bytes([q[2], q[3]]) as usize;
        q = &q[4..];
        let body = &q[..len]; q = &q[len..];
        if typ == 0 {
            let mut r = body;
            if r.len() < 2 { anyhow::bail!("sni list len"); }
            let list_len = u16::from_be_bytes([r[0], r[1]]) as usize;
            r = &r[2..2+list_len];
            let mut e = r;
            while e.len() >= 3 {
                let name_type = e[0];
                let nl = u16::from_be_bytes([e[1], e[2]]) as usize;
                e = &e[3..];
                let name = &e[..nl]; e = &e[nl..];
                if name_type == 0 { return Ok(std::str::from_utf8(name)?.to_string()); }
            }
        }
    }
    anyhow::bail!("no sni")
}

// ---- Service Windows ----
static mut STATUS_HANDLE: Option<windows_service::service_control_handler::ServiceStatusHandle> = None;
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[allow(static_mut_refs)]
fn set_status(state: ServiceState) {
    unsafe {
        if let Some(h) = &STATUS_HANDLE {
            let _ = h.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            });
        }
    }
}

define_windows_service!(ffi_service_main, service_main);
#[allow(dead_code)]
fn service_main(_args: Vec<std::ffi::OsString>) {
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
    unsafe { STATUS_HANDLE = Some(service_control_handler::register(SERVICE_NAME, event_handler)?); }
    set_status(ServiceState::StartPending);

    let cfg = load_config_or_init()?; let level = level_from_cfg(&cfg); init_logger(level)?;
    info!("Service starting (level={:?})", level);

    let shared = Shared { cfg: Arc::new(Mutex::new(cfg)), cache: Arc::new(Mutex::new((0, None))), stopping: Arc::new(AtomicBool::new(false)) };
    let shared_clone = shared.clone();

    let rt = Runtime::new()?;
    // gRPC IPC (named pipe)
    rt.spawn(async move {
        let incoming = PipeIncoming::new(PIPE_NAME).map(|res| res.map(PipeConn));
        let svc = HomeHttpServer::new(HomeHttpSvc { shared: shared_clone });
        info!("gRPC IPC listening on named pipe {}", PIPE_NAME);
        if let Err(e) = tonic::transport::Server::builder().add_service(svc).serve_with_incoming(incoming).await {
            error!("gRPC server error: {e:?}");
        }
    });

    // Serveurs HTTP / HTTPS
    let http_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), shared.cfg.lock().http);
    let https_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), shared.cfg.lock().https);
    let http = HttpHttp::new(shared.clone());
    let tls = TlsSnihttp::new(shared.clone());

    rt.spawn(async move {
        if let Err(e) = http.serve(http_addr).await { error!("http server: {e:?}"); }
    });
    rt.spawn(async move {
        if let Err(e) = tls.serve(https_addr).await { error!("https server: {e:?}"); }
    });

    set_status(ServiceState::Running);
    info!("Service running");

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
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
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
    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    service.set_description(SERVICE_DESCRIPTION)?;
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    service.delete()?; Ok(())
}

fn usage() { eprintln!("Usage: home-http [run|install|uninstall|console]"); }

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 { usage(); return Ok(()); }
    match args[1].as_str() {
        "run" => {
            #[cfg(windows)] { return run_service(); }
            #[cfg(not(windows))] { anyhow::bail!("Windows only"); }
        }
        "install" => { install_service()?; println!("Service installé. Modifiez {} puis démarrez le service.", config_path().display()); }
        "uninstall" => { uninstall_service()?; println!("Service désinstallé."); }
        "console" => {
            let cfg = load_config_or_init()?; init_logger(level_from_cfg(&cfg))?;
            info!("Console mode starting");
            let shared = Shared { cfg: Arc::new(Mutex::new(cfg)), cache: Arc::new(Mutex::new((0, None))), stopping: Arc::new(AtomicBool::new(false)) };
            let rt = Runtime::new()?;

            // gRPC IPC sur named pipe: toujours actif même si HTTP/HTTPS échouent
            rt.spawn({
                let shared = shared.clone();
                async move {
                    let incoming = PipeIncoming::new(PIPE_NAME).map(|res| res.map(PipeConn));
                    let svc = HomeHttpServer::new(HomeHttpSvc { shared });
                    info!("[console] gRPC IPC listening on named pipe {}", PIPE_NAME);
                    if let Err(e) = tonic::transport::Server::builder().add_service(svc).serve_with_incoming(incoming).await {
                        error!("gRPC server error: {e:?}");
                    }
                }
            });

            // Serveurs HTTP/HTTPS: on tente, mais on ne bloque pas si ça échoue (ex: ports 80/443 sans admin)
            {
                // En mode console (dev), on écoute en loopback uniquement pour éviter les popups pare-feu/UAC
                let http_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), shared.cfg.lock().http);
                let https_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), shared.cfg.lock().https);
                let http = HttpHttp::new(shared.clone());
                let tls = TlsSnihttp::new(shared.clone());
                rt.spawn(async move { if let Err(e) = http.serve(http_addr).await { error!("http server: {e:?}"); } });
                rt.spawn(async move { if let Err(e) = tls.serve(https_addr).await { error!("https server: {e:?}"); } });
            }

            // Boucle de garde: laisse tourner jusqu'à fermeture du processus
            info!("Console mode running. Press Ctrl+C to stop.");
            loop { thread::sleep(Duration::from_millis(500)); if shared.stopping.load(Ordering::SeqCst) { break; } }
        }
        _ => usage(),
    }
    Ok(())
}
