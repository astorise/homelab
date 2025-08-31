use std::{io::{BufRead, BufReader}, path::{Path, PathBuf}, process::{Child, Command, Stdio}, thread};
use anyhow::Result;
use tracing::{info, error};
use tauri::{AppHandle, Manager, Wry};

#[cfg(target_os = "windows")]
fn cargo_bin() -> &'static str { "cargo" }
#[cfg(not(target_os = "windows"))]
fn cargo_bin() -> &'static str { "cargo" }

struct ProcGuard {
    name: &'static str,
    child: Child,
}

impl ProcGuard {
    fn new(name: &'static str, mut child: Child) -> Self {
        if let Some(out) = child.stdout.take() {
            let svc = name.to_string();
            thread::spawn(move || {
                let reader = BufReader::new(out);
                for line in reader.lines().flatten() {
                    info!(svc = %svc, "{}", line);
                }
            });
        }
        if let Some(err) = child.stderr.take() {
            let svc = name.to_string();
            thread::spawn(move || {
                let reader = BufReader::new(err);
                for line in reader.lines().flatten() {
                    error!(svc = %svc, "{}", line);
                }
            });
        }
        Self { name, child }
    }
}

impl Drop for ProcGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

pub struct DevServices {
    _dns: Option<ProcGuard>,
    _http: Option<ProcGuard>,
}

fn workspace_root() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent().unwrap_or(&here).parent().unwrap_or(&here).to_path_buf()
}

fn spawn_cargo_package(pkg: &str, args: &[&str]) -> Result<Child> {
    let mut cmd = Command::new(cargo_bin());
    cmd.arg("run").arg("-p").arg(pkg).arg("--");
    for a in args { cmd.arg(a); }
    cmd.current_dir(workspace_root())
        .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn()?;
    Ok(child)
}

fn spawn_binary<P: AsRef<Path>>(exe: P, args: &[&str]) -> Result<Child> {
    let exe = exe.as_ref();
    let mut cmd = Command::new(exe);
    for a in args { cmd.arg(a); }
    cmd.current_dir(workspace_root())
        .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn()?;
    Ok(child)
}

pub fn spawn(app: &AppHandle<Wry>) -> Result<()> {
    // Skip when disabled
    if std::env::var("NO_DEV_SERVICES").ok().as_deref() == Some("1") {
        info!("NO_DEV_SERVICES=1 → skipping dev services spawn");
        return Ok(());
    }

    #[cfg(all(debug_assertions, target_os = "windows"))]
    {
        info!("Spawning dev services: home-dns & home-http (console)");
        // Essaye d'abord les binaires précompilés, puis fallback sur cargo run
        let bin_dir = workspace_root().join("home-lab").join("src-tauri").join("bin");
        let dns = spawn_cargo_package("home-dns", &["console"]).ok()
            .or_else(|| {
                if cfg!(target_os = "windows") {
                    let exe = bin_dir.join("home-dns.exe");
                    if exe.exists() { spawn_binary(exe, &["console"]).ok() } else { None }
                } else { None }
            })
            .map(|c| ProcGuard::new("home-dns", c));
        if dns.is_none() { error!("Failed to spawn home-dns (console)"); }

        let http = spawn_cargo_package("home-http", &["console"]).ok()
            .or_else(|| {
                if cfg!(target_os = "windows") {
                    let exe = bin_dir.join("home-http.exe");
                    if exe.exists() { spawn_binary(exe, &["console"]).ok() } else { None }
                } else { None }
            })
            .map(|c| ProcGuard::new("home-http", c));
        if http.is_none() { error!("Failed to spawn home-http (console)"); }
        app.manage(DevServices{ _dns: dns, _http: http });
    }
    Ok(())
}
