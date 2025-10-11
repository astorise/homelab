use std::fmt;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use local_rpc::Client as RpcClient;
use prost::Message;
use windows_service::service::{ServiceAccess, ServiceExitCode, ServiceState, ServiceStatus};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::core::GUID;

#[allow(dead_code)]
mod homedns {
    pub mod homedns {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/homedns.v1.rs"));
        }
    }
}

#[allow(dead_code)]
mod homehttp {
    pub mod homehttp {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/homehttp.v1.rs"));
        }
    }
}

const DNS_UUID: GUID = GUID::from_u128(0x18477de6c4b24746b60492db45db2d31);
const HTTP_UUID: GUID = GUID::from_u128(0x9df99e13af1c480cb5e64864350b5f3e);
const RPC_VERSION: (u16, u16) = (1, 0);
const PROC_GET_STATUS: u32 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ServiceKind {
    Dns,
    Http,
}

impl ServiceKind {
    fn display_name(self) -> &'static str {
        match self {
            ServiceKind::Dns => "Home DNS",
            ServiceKind::Http => "Home HTTP",
        }
    }

    fn windows_service_name(self) -> &'static str {
        match self {
            ServiceKind::Dns => "HomeDnsService",
            ServiceKind::Http => "HomeHttpService",
        }
    }

    fn default_endpoints(self) -> &'static [&'static str] {
        match self {
            ServiceKind::Dns => &["home-dns-dev", "home-dns"],
            ServiceKind::Http => &["home-http-dev", "home-http"],
        }
    }

    fn rpc_uuid(self) -> GUID {
        match self {
            ServiceKind::Dns => DNS_UUID,
            ServiceKind::Http => HTTP_UUID,
        }
    }
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "service-tester",
    version,
    about = "Test Windows service status and RPC connectivity for homelab daemons"
)]
struct Cli {
    /// Services to test (defaults to both when omitted)
    #[arg(value_enum)]
    services: Vec<ServiceKind>,
    /// Override RPC endpoint(s) to test (applies to every selected service)
    #[arg(long, value_delimiter = ',')]
    endpoint: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let targets = if cli.services.is_empty() {
        vec![ServiceKind::Dns, ServiceKind::Http]
    } else {
        cli.services.clone()
    };

    let mut failures = Vec::new();

    for (idx, service) in targets.iter().copied().enumerate() {
        if idx > 0 {
            println!();
        }

        println!("=== {} ===", service.display_name());
        if let Err(err) = check_windows_service(service) {
            println!("  Windows service query failed: {}", err);
        }

        match check_rpc(service, &cli.endpoint) {
            Ok(()) => {}
            Err(err) => {
                println!("  RPC check failed: {}", err);
                failures.push(err);
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("one or more checks failed"))
    }
}

fn check_windows_service(service: ServiceKind) -> Result<()> {
    let status = query_service_status(service.windows_service_name())
        .with_context(|| format!("query status for {}", service.windows_service_name()))?;

    let pid = status
        .process_id
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "-".to_string());
    let exit_summary = match status.exit_code {
        ServiceExitCode::Win32(code) => format!("win32={:#010x}", code),
        ServiceExitCode::ServiceSpecific(code) => format!("service-specific={:#010x}", code),
    };

    println!(
        "  Windows service '{}': state={}, pid={}, exit_code={}",
        service.windows_service_name(),
        describe_service_state(status.current_state),
        pid,
        exit_summary
    );

    Ok(())
}

fn check_rpc(service: ServiceKind, override_endpoints: &[String]) -> Result<()> {
    let endpoints: Vec<String> = if override_endpoints.is_empty() {
        service
            .default_endpoints()
            .iter()
            .map(|ep| (*ep).to_string())
            .collect()
    } else {
        override_endpoints.to_vec()
    };

    if endpoints.is_empty() {
        return Err(anyhow!("no RPC endpoints provided to test"));
    }

    let mut last_err: Option<(String, local_rpc::Error)> = None;
    let mut active: Option<(RpcClient, String)> = None;

    for endpoint in &endpoints {
        match RpcClient::connect(service.rpc_uuid(), RPC_VERSION, endpoint) {
            Ok(client) => {
                active = Some((client, endpoint.clone()));
                break;
            }
            Err(err) => {
                println!("  RPC connect failed on '{}': {}", endpoint, err);
                last_err = Some((endpoint.clone(), err));
            }
        }
    }

    let (client, endpoint) = if let Some(pair) = active {
        pair
    } else if let Some((ep, err)) = last_err {
        return Err(anyhow!("unable to connect to RPC endpoint '{ep}': {err}"));
    } else {
        return Err(anyhow!("no RPC endpoints provided to test"));
    };

    println!("  RPC connected via endpoint '{}'", endpoint);

    let request = match service {
        ServiceKind::Dns => homedns::homedns::v1::Empty {}.encode_to_vec(),
        ServiceKind::Http => homehttp::homehttp::v1::Empty {}.encode_to_vec(),
    };
    let response = client
        .call(PROC_GET_STATUS, &request)
        .map_err(|err| anyhow!("RPC GetStatus call failed: {}", err))?;

    match service {
        ServiceKind::Dns => {
            let status = homedns::homedns::v1::StatusResponse::decode(response.as_slice())
                .context("decode DNS status response")?;
            println!(
                "  RPC status: state='{}', log_level='{}'",
                status.state, status.log_level
            );
        }
        ServiceKind::Http => {
            let status = homehttp::homehttp::v1::StatusResponse::decode(response.as_slice())
                .context("decode HTTP status response")?;
            println!(
                "  RPC status: state='{}', log_level='{}'",
                status.state, status.log_level
            );
        }
    }

    Ok(())
}

fn query_service_status(name: &str) -> windows_service::Result<ServiceStatus> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(name, ServiceAccess::QUERY_STATUS)?;
    service.query_status()
}

fn describe_service_state(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Stopped => "Stopped",
        ServiceState::StartPending => "StartPending",
        ServiceState::StopPending => "StopPending",
        ServiceState::Running => "Running",
        ServiceState::ContinuePending => "ContinuePending",
        ServiceState::PausePending => "PausePending",
        ServiceState::Paused => "Paused",
    }
}
