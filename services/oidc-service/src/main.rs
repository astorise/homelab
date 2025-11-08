#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

#[cfg(windows)]
use service::run_windows_service;

#[cfg(not(windows))]
fn main() {
    eprintln!("oidc-service is only supported on Windows targets");
}

#[cfg(windows)]
fn main() {
    if let Err(err) = run_windows_service() {
        eprintln!("oidc-service failed: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;

    use anyhow::{anyhow, Context, Result};
    use tokio::runtime::Runtime;
    use tokio::sync::oneshot;
    use tracing::{error, info};
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control::ServiceControl;
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    use crate::oidc::{self, OidcPaths};

    const SERVICE_NAME: &str = "oidc-service";
    const SERVICE_DISPLAY_NAME: &str = "OIDC Identity Provider (Local)";
    const SERVICE_DESCRIPTION: &str = "Local OIDC provider for CI/CD and K3S auth";

    pub fn run_windows_service() -> Result<()> {
        if std::env::args().any(|arg| arg == "--run-as-console") {
            run_console()
        } else {
            service_dispatcher::start(SERVICE_NAME, ffi_service_main)
                .with_context(|| "failed to start service dispatcher")
        }
    }

    fn run_console() -> Result<()> {
        let paths = OidcPaths::discover()?;
        oidc::init_tracing(&paths)?;
        let state = oidc::load_state(&paths)?;
        let tls = oidc::tls_config(&paths)?;
        let runtime = Runtime::new()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = {
            let _guard = runtime.enter();
            oidc::spawn_server(state, tls, shutdown_rx)?
        };
        ctrlc::set_handler(move || {
            let _ = shutdown_tx.send(());
        })
        .context("failed to install ctrlc handler")?;
        runtime.block_on(async {
            match server.await {
                Ok(result) => result,
                Err(err) => Err(anyhow!("join error: {err}")),
            }
        })?;
        Ok(())
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(err) = run_service() {
            error!(%err, "service terminated with error");
        }
    }

    enum ServiceEvent {
        Stop,
    }

    fn run_service() -> Result<()> {
        let paths = OidcPaths::discover()?;
        oidc::init_tracing(&paths)?;
        let state = oidc::load_state(&paths)?;
        let tls = oidc::tls_config(&paths)?;
        let runtime = Runtime::new()?;
        let (service_tx, service_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = service_tx.send(ServiceEvent::Stop);
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5).as_millis() as u32,
            process_id: None,
        })?;

        let server = {
            let _guard = runtime.enter();
            oidc::spawn_server(state, tls, shutdown_rx)?
        };

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: 0,
            process_id: None,
        })?;

        info!(
            service = SERVICE_DISPLAY_NAME,
            description = SERVICE_DESCRIPTION,
            "oidc-service is running"
        );

        while let Ok(event) = service_rx.recv() {
            match event {
                ServiceEvent::Stop => {
                    info!(
                        service = SERVICE_DISPLAY_NAME,
                        description = SERVICE_DESCRIPTION,
                        "service stop requested"
                    );
                    let _ = shutdown_tx.send(());
                    break;
                }
            }
        }

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5).as_millis() as u32,
            process_id: None,
        })?;

        runtime.block_on(async {
            match server.await {
                Ok(result) => result,
                Err(err) => Err(anyhow!("join error: {err}")),
            }
        })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: 0,
            process_id: None,
        })?;

        Ok(())
    }
}

#[cfg(windows)]
mod oidc;

#[cfg(not(windows))]
mod oidc {}
