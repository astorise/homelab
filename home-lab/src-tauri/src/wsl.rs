use std::path::PathBuf;
use std::process::Command;

use regex::Regex;
use serde::{Deserialize, Serialize};
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

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);

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
        .context("Impossible d'executer wsl.exe --list --verbose --all")?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);

    if !output.status.success() {
        let stdout_trim = stdout.trim();
        let stderr_trim = stderr.trim();
        let lower_stdout = stdout_trim.to_lowercase();
        let lower_stderr = stderr_trim.to_lowercase();
        let no_distro = lower_stdout.contains("no installed distributions")
            || lower_stdout.contains("aucune distribution install")
            || lower_stderr.contains("no installed distributions")
            || lower_stderr.contains("aucune distribution install");

        if no_distro {
            info!(target: "wsl", "wsl.exe indique qu'aucune distribution n'est installee");
            return Ok(Vec::new());
        }

        let message = if !stderr_trim.is_empty() {
            stderr_trim.to_string()
        } else if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            "wsl.exe --list a echoue".to_string()
        };
        return Err(anyhow!(message));
    }

    parse_wsl_list_output(stdout.as_str())
}

fn run_wsl_unregister(name: &str) -> Result<WslOperationResult> {
    if name.trim().is_empty() {
        return Err(anyhow!("Le nom de l'instance WSL est requis"));
    }

    info!(target: "wsl", instance = name, "Appel wsl.exe --unregister");

    let output = Command::new("wsl.exe")
        .args(["--unregister", name])
        .output()
        .with_context(|| format!("Impossible de supprimer l'instance WSL {name}"))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();

    if output.status.success() {
        let mut message = if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            format!("Instance WSL '{name}' supprimee.")
        };
        if !stderr_trim.is_empty() && stderr_trim != message {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(stderr_trim);
        }
        info!(
            target: "wsl",
            instance = name,
            status = %output.status,
            stdout = %stdout_trim,
            stderr = %stderr_trim,
            "Instance WSL supprimee"
        );
        Ok(WslOperationResult { ok: true, message })
    } else {
        let lower_stdout = stdout_trim.to_lowercase();
        let lower_stderr = stderr_trim.to_lowercase();
        let not_found = lower_stdout.contains("wsl_e_distro_not_found")
            || lower_stderr.contains("wsl_e_distro_not_found")
            || lower_stdout.contains("no distribution")
            || lower_stderr.contains("no distribution")
            || lower_stdout.contains("aucune distribution")
            || lower_stderr.contains("aucune distribution");

        if not_found {
            info!(
                target: "wsl",
                instance = name,
                stdout = %stdout_trim,
                stderr = %stderr_trim,
                "Suppression WSL consideree comme deja effectuee (distribution absente)"
            );
            return Ok(WslOperationResult {
                ok: true,
                message: format!("Instance WSL '{name}' introuvable ou deja supprimee."),
            });
        }

        let mut combined = stderr_trim.to_string();
        if combined.is_empty() {
            combined = stdout_trim.to_string();
        }
        if combined.is_empty() {
            let code = output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "(code inconnu)".into());
            combined = format!("Suppression de l'instance '{name}' a echoue (code {code})");
        }
        error!(
            target: "wsl",
            instance = name,
            status = %output.status,
            stdout = %stdout_trim,
            stderr = %stderr_trim,
            "Suppression WSL a echoue"
        );
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

#[derive(serde::Deserialize)]
pub struct WslRemoveInstanceArgs {
    name: String,
}

#[tauri::command]
pub async fn wsl_remove_instance(args: WslRemoveInstanceArgs) -> Result<WslOperationResult, String> {
    let trimmed = args.name.trim().to_string();
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
