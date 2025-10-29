use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::Serialize;
use tauri::{AppHandle, Manager};
use tracing::{error, info, warn};

#[derive(Serialize)]
pub struct ProvisionResult {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
pub struct WslOperationResult {
    ok: bool,
    message: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct WslInstance {
    name: String,
    state: String,
    version: Option<String>,
    is_default: bool,
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
        .context("Impossible de recuperer le dossier des ressources")?;
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
        .with_context(|| "Impossible d'executer setup-wsl.ps1".to_string())?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        if !stdout.is_empty() {
            info!(target: "wsl", "setup-wsl.ps1 stdout:\n{stdout}");
        }
        if !stderr.is_empty() {
            warn!(target: "wsl", "setup-wsl.ps1 stderr: {stderr}");
        }
        let mut message = if !stdout.is_empty() {
            stdout
        } else {
            String::from("Instance WSL importee avec succes.")
        };
        if !stderr.is_empty() {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(&stderr);
        }
        info!(target: "wsl", "Import WSL termine");
        Ok(ProvisionResult { ok: true, message })
    } else {
        error!(
            target: "wsl",
            status = %output.status,
            stdout = %stdout,
            stderr = %stderr,
            "setup-wsl.ps1 a echoue"
        );
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
            combined = format!("setup-wsl.ps1 a echoue (code {code})");
        }
        Err(anyhow!(combined))
    }
}

fn parse_wsl_list_output(output: &str) -> Result<Vec<WslInstance>> {
    let splitter = Regex::new(r"\s{2,}")?;
    let mut instances = Vec::new();
    let mut header_skipped = false;

    for raw_line in output.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !header_skipped {
            header_skipped = true;
            // Première ligne = en-tête (NAME/STATE/VERSION ou équivalent localisé).
            continue;
        }

        let working = raw_line.trim_start();
        let (is_default, without_marker) = if working.starts_with('*') {
            (true, working.trim_start_matches('*').trim_start())
        } else {
            (false, working)
        };

        let columns: Vec<&str> = splitter
            .split(without_marker)
            .filter_map(|chunk| {
                let value = chunk.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value)
                }
            })
            .collect();

        if columns.is_empty() {
            continue;
        }

        let name = columns[0].to_string();
        let state = columns
            .get(1)
            .map(|v| v.to_string())
            .unwrap_or_else(String::new);
        let version = columns
            .get(2)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string());

        instances.push(WslInstance {
            name,
            state,
            version,
            is_default,
        });
    }

    Ok(instances)
}

fn collect_wsl_instances() -> Result<Vec<WslInstance>> {
    let output = Command::new("wsl.exe")
        .args(["--list", "--verbose", "--all"])
        .output()
        .context("Impossible d'exécuter wsl.exe --list --verbose --all")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            "wsl.exe --list a échoué".to_string()
        };
        return Err(anyhow!(message));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_wsl_list_output(stdout.as_ref())
}

fn run_wsl_unregister(name: &str) -> Result<WslOperationResult> {
    if name.trim().is_empty() {
        return Err(anyhow!("Le nom de l'instance WSL est requis"));
    }

    let output = Command::new("wsl.exe")
        .args(["--unregister", name])
        .output()
        .with_context(|| format!("Impossible de supprimer l'instance WSL {name}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        let mut message = if !stdout.is_empty() {
            stdout
        } else {
            format!("Instance WSL '{name}' supprimée.")
        };
        if !stderr.is_empty() {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(&stderr);
        }
        Ok(WslOperationResult { ok: true, message })
    } else {
        let mut combined = stderr;
        if combined.is_empty() {
            combined = stdout;
        }
        if combined.is_empty() {
            combined = format!("Échec de la suppression de l'instance '{name}'.");
        }
        Err(anyhow!(combined))
    }
}

#[tauri::command]
pub async fn wsl_list_instances() -> Result<Vec<WslInstance>, String> {
    info!(target: "wsl", "Listing des instances WSL");
    tauri::async_runtime::spawn_blocking(collect_wsl_instances)
        .await
        .map_err(|e| {
            error!(target: "wsl", "Erreur JoinHandle (list): {e}");
            format!("Erreur interne: {e}")
        })
        .and_then(|result| result.map_err(|e| e.to_string()))
}

#[tauri::command]
pub async fn wsl_remove_instance(name: String) -> Result<WslOperationResult, String> {
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err("Le nom de l'instance est requis.".into());
    }

    info!(target: "wsl", instance = %trimmed, "Suppression d'une instance WSL demandée");

    let instance_name = trimmed.clone();
    tauri::async_runtime::spawn_blocking(move || run_wsl_unregister(&instance_name))
        .await
        .map_err(|e| {
            error!(target: "wsl", "Erreur JoinHandle (remove): {e}");
            format!("Erreur interne: {e}")
        })
        .and_then(|result| {
            result.map_err(|e| {
                error!(target: "wsl", "Échec suppression WSL: {e}");
                e.to_string()
            })
        })
}
