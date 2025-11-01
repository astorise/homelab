//! Manual smoke tests to verify the WSL import/remove flow end-to-end.
//!
//! These tests are ignored by default because they require:
//! - Windows with WSL enabled.
//! - A valid rootfs archive referenced through `HOME_LAB_WSL_ROOTFS`.
//! - Optionally `HOME_LAB_WSL_INSTALL_DIR` to force the installation directory.
//!
//! Example execution:
//! ```powershell
//! $env:HOME_LAB_WSL_ROOTFS = 'C:\path\to\wsl-rootfs.tar'
//! cargo test --test wsl_integration -- --ignored
//! ```

#![cfg(target_os = "windows")]

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{bail, ensure, Context, Result};

const DISTRO_NAME: &str = "home-lab-integration-test";

fn decode_cli_output(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    if let Ok(utf8) = std::str::from_utf8(data) {
        return utf8.to_string();
    }

    if data.len() % 2 == 0 {
        let utf16: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16_lossy(&utf16);
    }

    String::from_utf8_lossy(data).into_owned()
}

fn sanitize_cli_field(value: &str) -> String {
    fn is_disallowed(c: char) -> bool {
        matches!(
            c,
            '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{feff}'
                | '\u{fffd}'
        ) || c.is_control()
    }

    let filtered: String = value.chars().filter(|c| !is_disallowed(*c)).collect();
    filtered.trim().to_string()
}

fn run_command(mut command: Command) -> Result<(Output, String)> {
    let description = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("Failed to execute {description}"))?;
    Ok((output, description))
}

fn ensure_instance_presence(expected: bool) -> Result<()> {
    let mut list_cmd = Command::new("wsl.exe");
    list_cmd.args(["--list", "--verbose", "--all"]);
    let (output, description) = run_command(list_cmd)?;
    let stdout = decode_cli_output(&output.stdout);
    if !output.status.success() {
        let stderr = decode_cli_output(&output.stderr);
        bail!(
            "Command {description} failed (code {:?})\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }

    let found = stdout
        .lines()
        .map(|line| sanitize_cli_field(line))
        .any(|line| line.contains(DISTRO_NAME));

    if found != expected {
        bail!(
            "Unexpected presence for {DISTRO_NAME}. Expected={expected}, found={found}. Output:\n{stdout}"
        );
    }

    Ok(())
}

fn cleanup_distro(name: &str) {
    let _ = Command::new("wsl.exe").args(["--terminate", name]).output();
    let _ = Command::new("wsl.exe")
        .args(["--unregister", name])
        .output();
}

#[test]
#[ignore = "Requires a local WSL rootfs and manual execution"]
fn import_and_remove_wsl_instance() -> Result<()> {
    let rootfs = env::var("HOME_LAB_WSL_ROOTFS")
        .context("Set HOME_LAB_WSL_ROOTFS with the path to wsl-rootfs.tar")?;

    let rootfs_path = Path::new(&rootfs);
    ensure!(
        rootfs_path.is_file(),
        "ROOTFS not found or invalid: {}",
        rootfs_path.display()
    );

    let install_dir_env = env::var("HOME_LAB_WSL_INSTALL_DIR").ok();
    let mut temp_dir_guard: Option<tempfile::TempDir> = None;
    let install_dir: PathBuf = if let Some(dir) = install_dir_env {
        PathBuf::from(dir)
    } else {
        let temp = tempfile::Builder::new()
            .prefix("home-lab-wsl-test-")
            .tempdir()
            .context("Unable to create a temporary directory")?;
        let path = temp.path().to_path_buf();
        temp_dir_guard = Some(temp);
        path
    };

    cleanup_distro(DISTRO_NAME);

    let mut import_command = Command::new("wsl.exe");
    import_command
        .arg("--import")
        .arg(DISTRO_NAME)
        .arg(&install_dir)
        .arg(rootfs_path)
        .arg("--version")
        .arg("2");
    let (import_output, import_cmd) = run_command(import_command)?;

    let import_stdout = decode_cli_output(&import_output.stdout);
    let import_stderr = decode_cli_output(&import_output.stderr);
    ensure!(
        import_output.status.success(),
        "WSL import failed via {import_cmd}\nstdout:\n{import_stdout}\nstderr:\n{import_stderr}"
    );

    ensure_instance_presence(true)?;

    let mut unregister_command = Command::new("wsl.exe");
    unregister_command.arg("--unregister").arg(DISTRO_NAME);
    let (unregister_output, unregister_cmd) = run_command(unregister_command)?;
    let unregister_stdout = decode_cli_output(&unregister_output.stdout);
    let unregister_stderr = decode_cli_output(&unregister_output.stderr);
    ensure!(
        unregister_output.status.success(),
        "WSL removal failed via {unregister_cmd}\nstdout:\n{unregister_stdout}\nstderr:\n{unregister_stderr}"
    );

    ensure_instance_presence(false)?;

    drop(temp_dir_guard);

    Ok(())
}
