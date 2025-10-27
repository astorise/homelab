use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use tauri::{AppHandle, Manager};
use tracing::{error, info, warn};

#[derive(Serialize)]
pub struct ProvisionResult {
    ok: bool,
    message: String,
}

fn resolve_install_dir(app: &AppHandle) -> Result<PathBuf> {
    if let Some(pd) = std::env::var_os("PROGRAMDATA") {
        return Ok(PathBuf::from(pd).join("home-lab").join("wsl"));
    }

    app.path()
        .app_data_dir()
        .map(|p| p.join("wsl"))
        .context("Impossible de déterminer le dossier d'installation WSL")
}

#[tauri::command]
pub async fn wsl_import_instance(
    app: AppHandle,
    force: Option<bool>,
) -> Result<ProvisionResult, String> {
    let force_import = force.unwrap_or(false);
    let handle = app.clone();

    info!(target: "wsl", force = force_import, "Demande d'import WSL reçue");

    tauri::async_runtime::spawn_blocking(move || run_wsl_setup(&handle, force_import))
        .await
        .map_err(|e| {
            error!(target: "wsl", "Erreur JoinHandle: {e}");
            format!("Erreur interne: {e}")
        })
        .and_then(|result| {
            result.map_err(|e| {
                error!(target: "wsl", "Échec import WSL: {e}");
                e.to_string()
            })
        })
}

fn run_wsl_setup(app: &AppHandle, force_import: bool) -> Result<ProvisionResult> {
    let resource_dir = app
        .path()
        .resource_dir()
        .context("Impossible de récupérer le dossier des ressources")?;
    let wsl_dir = resource_dir.join("wsl");
    let script_path = wsl_dir.join("setup-wsl.ps1");
    if !script_path.exists() {
        return Err(anyhow!(
            "Script setup-wsl.ps1 introuvable dans {:?}",
            script_path
        ));
    }

    let rootfs_path = wsl_dir.join("wsl-rootfs.tar");
    if !rootfs_path.exists() {
        return Err(anyhow!("Archive rootfs introuvable dans {:?}", rootfs_path));
    }

    let install_dir = resolve_install_dir(app)?;

    info!(
        target: "wsl",
        script = %script_path.display(),
        rootfs = %rootfs_path.display(),
        install = %install_dir.display(),
        force = force_import,
        "Lancement de setup-wsl.ps1"
    );

    let mut command = Command::new("powershell.exe");
    command
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&script_path)
        .arg("-InstallDir")
        .arg(&install_dir)
        .arg("-Rootfs")
        .arg(&rootfs_path);

    if force_import {
        command.arg("-ForceImport");
    }

    let output = command
        .output()
        .with_context(|| "Impossible d'exécuter setup-wsl.ps1".to_string())?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        if !stderr.is_empty() {
            warn!(target: "wsl", "setup-wsl.ps1 stderr: {stderr}");
        }
        let mut message = if !stdout.is_empty() {
            stdout
        } else {
            String::from("Instance WSL importée avec succès.")
        };
        if !stderr.is_empty() {
            if !message.is_empty() {
                message.push_str("\n");
            }
            message.push_str(&stderr);
        }
        info!(target: "wsl", "Import WSL terminé");
        Ok(ProvisionResult { ok: true, message })
    } else {
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "(code inconnu)".into());
        let mut combined = stderr;
        if combined.is_empty() {
            combined = stdout;
        }
        if combined.is_empty() {
            combined = format!("setup-wsl.ps1 a échoué (code {code})");
        }
        Err(anyhow!(combined))
    }
}
