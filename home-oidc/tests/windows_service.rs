#![cfg(target_os = "windows")]

use std::io;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use assert_cmd::cargo::CommandCargoExt;
use assert_cmd::Command;
use windows_service::service::{Service, ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "HomeOidcService";
const WAIT_TIMEOUT: Duration = Duration::from_secs(45);

fn cargo_bin() -> Result<Command> {
    Ok(Command::cargo_bin("home-oidc").context("build home-oidc binary")?)
}

fn ensure_service_absent() {
    if let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        if let Ok(service) = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
        ) {
            let _ = service.stop();
            let _ = wait_for_transition(&service, ServiceState::Stopped, Duration::from_secs(10));
            let _ = service.delete();
        }
    }
}

fn run_cli(args: &[&str]) -> Result<()> {
    let mut cmd = cargo_bin()?;
    cmd.args(args);
    let output = cmd
        .output()
        .with_context(|| format!("running home-oidc {:?}", args))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "home-oidc {:?} failed: status={:?}\nstdout:{}\nstderr:{}",
        args,
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn wait_for_transition(service: &Service, desired: ServiceState, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = service.query_status()?;
        if status.current_state == desired {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "timeout waiting for {:?}, current={:?}",
                desired,
                status.current_state
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn open_service(access: ServiceAccess) -> Result<Service> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    Ok(manager.open_service(SERVICE_NAME, access)?)
}

fn expect_not_found(err: anyhow::Error) -> Result<()> {
    if let Some(io_err) = err.downcast_ref::<io::Error>() {
        if io_err.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
    }
    Err(err)
}

#[test]
#[ignore = "Requires administrator privileges on Windows to install services"]
fn install_start_stop_cycle() -> Result<()> {
    ensure_service_absent();

    run_cli(&["install"])?;

    let service =
        open_service(ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;

    service.start(&[]).context("start installed service")?;
    wait_for_transition(&service, ServiceState::Running, WAIT_TIMEOUT)?;

    service.stop().context("stop running service")?;
    wait_for_transition(&service, ServiceState::Stopped, WAIT_TIMEOUT)?;

    drop(service);

    run_cli(&["uninstall"])?;

    match open_service(ServiceAccess::QUERY_STATUS) {
        Ok(_) => Err(anyhow!("service still present after uninstall")),
        Err(err) => expect_not_found(err),
    }
}
