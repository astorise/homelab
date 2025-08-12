//! home-dns – Service Windows (DNS proxy avec wildcards)
//! Commandes :
//!   home-dns.exe install
//!   home-dns.exe uninstall
//!   home-dns.exe run         (exécution console)
//!   home-dns.exe             (exécution service Windows)
//!
//! Conf : .\conf\dns.yaml  (relatif à l'exécutable)

use std::{
    ffi::OsString,
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use serde::Deserialize;
use thiserror::Error;
use tokio::net::UdpSocket;
use wildmatch::WildMatch;

use trust_dns_proto::op::{Message, MessageType, Query};
use trust_dns_proto::rr::{
    rdata::{A as RDataA, AAAA as RDataAAAA},
    Name, RData, Record, RecordType,
};
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};

/// ===== Config =====
#[derive(Debug, Deserialize, Clone)]
struct Config {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default = "default_upstreams")]
    upstreams: Vec<String>,
    #[serde(default)]
    rules: Vec<Rule>,
}
#[derive(Debug, Deserialize, Clone)]
struct Rule {
    pattern: String,
    ip: IpAddr,
    #[serde(default = "default_ttl")]
    ttl: u32,
}

fn default_listen() -> String {
    "0.0.0.0:53".into()
}
fn default_upstreams() -> Vec<String> {
    vec!["8.8.8.8:53".into(), "1.1.1.1:53".into()]
}
fn default_ttl() -> u32 {
    60
}

#[derive(Error, Debug)]
enum ProxyError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("DNS encode")]
    DnsEncode,
    #[error("Service: {0}")]
    Service(String),
}

fn config_path() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    exe_dir.join("conf").join("dns.yaml")
}

fn load_config() -> Result<Config, ProxyError> {
    let path = config_path();
    let content = fs::read_to_string(&path)?;
    let mut cfg: Config = serde_yaml::from_str(&content)?;
    for r in &mut cfg.rules {
        r.pattern = r.pattern.trim_end_matches('.').to_ascii_lowercase();
    }
    Ok(cfg)
}

fn normalize_qname(q: &Query) -> String {
    q.name().to_utf8().trim_end_matches('.').to_ascii_lowercase()
}

fn best_rule<'a>(name: &str, rules: &'a [Rule]) -> Option<&'a Rule> {
    let mut candidates: Vec<&Rule> = rules
        .iter()
        .filter(|r| WildMatch::new(&r.pattern).matches(name))
        .collect();
    candidates.sort_by_key(|r| r.pattern.len());
    candidates.pop()
}

async fn forward(upstreams: &[String], payload: &[u8]) -> std::io::Result<Vec<u8>> {
    for up in upstreams {
        let upstream = UdpSocket::bind("0.0.0.0:0").await?;
        if upstream.send_to(payload, up).await.is_ok() {
            let mut resp_buf = [0u8; 512];
            let recv = tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut resp_buf)).await;
            if let Ok(Ok((n, _))) = recv {
                return Ok(resp_buf[..n].to_vec());
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "all upstreams failed",
    ))
}

fn build_response_a_or_aaaa(
    request: &Message,
    q: &Query,
    ip: IpAddr,
    ttl: u32,
) -> Result<Vec<u8>, ProxyError> {
    let mut resp = Message::new();
    resp.set_id(request.id());
    resp.set_message_type(MessageType::Response);
    resp.set_recursion_desired(request.recursion_desired());
    resp.set_recursion_available(true);
    resp.add_query(q.clone());

    let name = Name::from_ascii(q.name().to_utf8()).map_err(|_| ProxyError::DnsEncode)?;

    match ip {
        IpAddr::V4(v4) => {
            if q.query_type() == RecordType::A {
                let rec = Record::from_rdata(name, ttl, RData::A(RDataA(v4)));
                resp.add_answer(rec);
            }
        }
        IpAddr::V6(v6) => {
            if q.query_type() == RecordType::AAAA {
                let rec = Record::from_rdata(name, ttl, RData::AAAA(RDataAAAA(v6)));
                resp.add_answer(rec);
            }
        }
    }

    let mut out = Vec::with_capacity(512);
    let mut enc = BinEncoder::new(&mut out);
    resp.emit(&mut enc).map_err(|_| ProxyError::DnsEncode)?;
    Ok(out)
}

async fn run_proxy(cfg: Config, stop_flag: Arc<AtomicBool>) -> Result<(), ProxyError> {
    let socket = UdpSocket::bind(&cfg.listen).await?;
    println!("[home-dns] listening on {}", cfg.listen);

    let mut buf = [0u8; 512];

    while !stop_flag.load(Ordering::Relaxed) {
        // timeout court pour checker le stop_flag
        let recv = tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await;
        let (len, addr) = match recv {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                eprintln!("[home-dns] recv error: {e}");
                continue;
            }
            Err(_) => continue,
        };

        let req_bytes = &buf[..len];

        // trust-dns 0.23: parse via from_vec
        if let Ok(message) = Message::from_vec(req_bytes) {
            if let Some(q) = message.queries().first().cloned() {
                let qname = normalize_qname(&q);
                let qtype = q.query_type();

                if matches!(qtype, RecordType::A | RecordType::AAAA) {
                    if let Some(rule) = best_rule(&qname, &cfg.rules) {
                        if let Ok(resp) = build_response_a_or_aaaa(&message, &q, rule.ip, rule.ttl) {
                            if !resp.is_empty() {
                                let _ = socket.send_to(&resp, addr).await;
                                continue;
                            }
                        }
                    }
                }

                match forward(&cfg.upstreams, req_bytes).await {
                    Ok(resp) => {
                        let _ = socket.send_to(&resp, addr).await;
                    }
                    Err(e) => eprintln!("[home-dns] upstream error: {e}"),
                }
            }
        }
    }

    println!("[home-dns] stopping.");
    Ok(())
}

/// ===== Service Windows =====
#[cfg(target_os = "windows")]
mod winservice {
    use super::*;
    use std::thread;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceInfo,
            ServiceStartType, ServiceState, ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    pub const SERVICE_NAME: &str = "home-dns";
    pub const SERVICE_DISPLAY_NAME: &str = "Home DNS Proxy";
    pub const SERVICE_DESC: &str = "DNS proxy with wildcard overrides (Rust)";

    // Génère le trampoline extern "system"
    define_windows_service!(ffi_service_main, service_main);

    pub fn run_service() -> Result<(), ProxyError> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|e| ProxyError::Service(e.to_string()))
    }

    pub fn install_service() -> Result<(), ProxyError> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
        )
        .map_err(|e| ProxyError::Service(e.to_string()))?;

        let exe_path = std::env::current_exe().map_err(|e| ProxyError::Service(e.to_string()))?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart, // <-- 0.8
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path.into(),
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None,  // LocalSystem
            account_password: None,
        };

        let service = manager
            .create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::START,
            )
            .map_err(|e| ProxyError::Service(e.to_string()))?;

        let _ = service.set_description(SERVICE_DESC);
        println!("Service '{}' installé.", SERVICE_NAME);
        Ok(())
    }

    pub fn uninstall_service() -> Result<(), ProxyError> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| ProxyError::Service(e.to_string()))?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|e| ProxyError::Service(e.to_string()))?;

        if let Ok(status) = service.query_status() {
            if status.current_state == ServiceState::Running {
                let _ = service.stop();
                thread::sleep(Duration::from_secs(1));
            }
        }

        service
            .delete()
            .map_err(|e| ProxyError::Service(e.to_string()))?;
        println!("Service '{}' désinstallé.", SERVICE_NAME);
        Ok(())
    }

    // Point d'entrée logique du service (appelé via le trampoline)
    fn service_main(_args: Vec<OsString>) {
        let stop_flag = Arc::new(AtomicBool::new(false));

        // Enregistre le handler STOP/SHUTDOWN
        let status_handle = match service_control_handler::register(SERVICE_NAME, {
            let stop_flag = stop_flag.clone();
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    stop_flag.store(true, Ordering::Relaxed);
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NoError,
            }
        }) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[home-dns] handler register failed: {e}");
                return;
            }
        };

        // Service RUNNING
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: windows_service::service::ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(0),
            process_id: None,
        });

        // Runtime tokio + boucle
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let result = rt.block_on(async {
            match super::load_config() {
                Ok(cfg) => super::run_proxy(cfg, stop_flag).await,
                Err(e) => Err(e),
            }
        });

        if let Err(e) = result {
            eprintln!("[home-dns] error: {e}");
        }

        // Service STOPPED
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: windows_service::service::ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(0),
            process_id: None,
        });
    }
}

#[cfg(not(target_os = "windows"))]
compile_error!("Ce binaire est prévu pour Windows (service).");

/// ===== Entrée Programme =====
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "install" => {
                #[cfg(target_os = "windows")]
                winservice::install_service()?;
                return Ok(());
            }
            "uninstall" => {
                #[cfg(target_os = "windows")]
                winservice::uninstall_service()?;
                return Ok(());
            }
            "run" => {
                // exécution console (dev)
                let cfg = load_config()?;
                let stop = Arc::new(AtomicBool::new(false));

                let stop2 = stop.clone();
               let rt = tokio::runtime::Builder::new_multi_thread()
    .enable_all()
    .build()
    .expect("tokio runtime");

return Ok(rt.block_on(async move {
    // Ctrl+C
    let stop_task = tokio::spawn(async {
        let _ = tokio::signal::ctrl_c().await;
    });

    let run = run_proxy(cfg, stop.clone());

    // Les DEUX branches retournent Result<(), ProxyError>
    tokio::select! {
        res = run => res,          // <- on retourne le Result directement
        _ = stop_task => Ok(()),   // <- on renvoie aussi un Result
    }
})?);
            }
            _ => { /* mode service */ }
        }
    }

    // Mode SERVICE par défaut
    #[cfg(target_os = "windows")]
    {
        return Ok(winservice::run_service()?);
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Service Windows uniquement".into())
    }
}