use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn escape_for_log(input: &str) -> String {
    input.escape_debug().to_string()
}

fn format_cli_command(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return program.to_string();
    }

    let rendered_args: Vec<String> = args
        .iter()
        .map(|arg| {
            if arg
                .chars()
                .any(|c| c.is_whitespace() || c == '"' || c == '\'')
            {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg.to_string()
            }
        })
        .collect();

    format!("{} {}", program, rendered_args.join(" "))
}

static WSL_LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn wsl_log_lock() -> &'static Mutex<()> {
    WSL_LOG_LOCK.get_or_init(|| Mutex::new(()))
}

fn wsl_log_file_path() -> PathBuf {
    let base = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
    base.join("home-lab").join("logs").join("wsl-actions.log")
}

fn epoch_timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            let millis = duration.subsec_millis();
            format!("{secs}.{millis:03}")
        }
        Err(_) => "0".to_string(),
    }
}

fn append_wsl_log(message: &str) -> std::io::Result<()> {
    let path = wsl_log_file_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "[{}] {}", epoch_timestamp(), message)?;
    Ok(())
}

fn log_wsl_event(message: impl AsRef<str>) {
    let sanitized = message.as_ref().replace('\r', "\\r").replace('\n', "\\n");

    let lock = wsl_log_lock().lock();
    if let Ok(_guard) = lock {
        if let Err(err) = append_wsl_log(&sanitized) {
            warn!(target: "wsl", "Echec ecriture log WSL: {err}");
        }
    } else {
        warn!(target: "wsl", "Impossible d'obtenir le verrou du journal WSL");
    }
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

    log_wsl_event(format!("Demande d'import WSL (force={})", force_import));
    info!(target: "wsl", force = force_import, "Demande d'import WSL reçue");

    tauri::async_runtime::spawn_blocking(move || run_wsl_setup(&handle, force_import))
        .await
        .map_err(|e| {
            error!(target: "wsl", "Erreur JoinHandle: {e}");
            log_wsl_event(format!("Erreur JoinHandle pendant l'import WSL: {e}"));
            format!("Erreur interne: {e}")
        })
        .and_then(|result| {
            result.map_err(|e| {
                error!(target: "wsl", "Échec import WSL: {e}");
                log_wsl_event(format!("Échec import WSL: {e}"));
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
    log_wsl_event(format!(
        "Lancement de setup-wsl.ps1 (force={}, script={}, rootfs={}, install={})",
        force_import,
        script_path.display(),
        rootfs_path.display(),
        install_dir.display()
    ));

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

    let mut command_preview = format!(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\" -InstallDir \"{}\" -Rootfs \"{}\"",
        script_path.display(),
        install_dir.display(),
        rootfs_path.display()
    );
    if force_import {
        command_preview.push_str(" -ForceImport");
    }

    info!(
        target: "wsl",
        command = %command_preview,
        "Execution d'une commande WSL (setup)"
    );
    log_wsl_event(format!(
        "Execution commande WSL (setup): {}",
        command_preview
    ));

    let output = command
        .output()
        .with_context(|| "Impossible d'executer setup-wsl.ps1".to_string())?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    info!(
        target: "wsl",
        command = %command_preview,
        status = %output.status,
        stdout = %stdout_log,
        stderr = %stderr_log,
        "Commande WSL terminee (setup)"
    );
    log_wsl_event(format!(
        "Commande terminee (setup) status={} stdout={} stderr={}",
        output.status, stdout_log, stderr_log
    ));

    if output.status.success() {
        if !stdout_trim.is_empty() {
            info!(target: "wsl", "setup-wsl.ps1 stdout:\n{stdout_trim}");
        }
        if !stderr_trim.is_empty() {
            warn!(target: "wsl", "setup-wsl.ps1 stderr: {stderr_trim}");
        }
        let mut message = if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            String::from("Instance WSL importee avec succes.")
        };
        if !stderr_trim.is_empty() {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(stderr_trim);
        }
        info!(target: "wsl", "Import WSL termine");
        log_wsl_event(format!("Import WSL termine: {}", escape_for_log(&message)));
        Ok(ProvisionResult { ok: true, message })
    } else {
        error!(
            target: "wsl",
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "setup-wsl.ps1 a echoue"
        );
        log_wsl_event(format!(
            "setup-wsl.ps1 a echoue: status={} stdout={} stderr={}",
            output.status, stdout_log, stderr_log
        ));
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
    let entry_re = Regex::new(r"^(?P<name>.+?)\s{2,}(?P<state>\S.*?)(?:\s{2,}(?P<version>\S+))?$")?;
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

        if without_marker.is_empty() {
            warn!(
                target: "wsl",
                line = %escape_for_log(raw_line),
                "Ligne WSL vide apres retrait du marqueur par defaut; ignoree"
            );
            continue;
        }

        let Some(caps) = entry_re.captures(without_marker) else {
            warn!(
                target: "wsl",
                line = %escape_for_log(without_marker),
                "Impossible d'analyser la ligne WSL; ligne ignoree"
            );
            continue;
        };

        let name_raw = caps.name("name").map(|m| m.as_str()).unwrap_or_default();
        let state_raw = caps.name("state").map(|m| m.as_str()).unwrap_or_default();
        let version_raw = caps.name("version").map(|m| m.as_str());

        let name = sanitize_cli_field(name_raw);
        if name.is_empty() {
            warn!(
                target: "wsl",
                line = %escape_for_log(raw_line),
                "Nom d'instance WSL vide apres nettoyage; ligne ignoree"
            );
            continue;
        }

        let state = sanitize_cli_field(state_raw);
        let version =
            version_raw
                .map(sanitize_cli_field)
                .and_then(|v| if v.is_empty() { None } else { Some(v) });

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
    let args = ["--list", "--verbose", "--all"];
    let command_line = format_cli_command("wsl.exe", &args);

    log_wsl_event(format!("Execution commande WSL (list): {command_line}"));
    let output = Command::new("wsl.exe")
        .args(args)
        .output()
        .context("Impossible d'executer wsl.exe --list --verbose --all")?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    info!(
        target: "wsl",
        command = %command_line,
        status = %output.status,
        stdout = %stdout_log,
        stderr = %stderr_log,
        "Commande WSL terminee"
    );
    log_wsl_event(format!(
        "Commande terminee (list) status={} stdout={} stderr={}",
        output.status, stdout_log, stderr_log
    ));

    if !output.status.success() {
        let lower_stdout = stdout_trim.to_lowercase();
        let lower_stderr = stderr_trim.to_lowercase();
        let no_distro = lower_stdout.contains("no installed distributions")
            || lower_stdout.contains("aucune distribution install")
            || lower_stderr.contains("no installed distributions")
            || lower_stderr.contains("aucune distribution install");

        if no_distro {
            info!(target: "wsl", "wsl.exe indique qu'aucune distribution n'est installee");
            log_wsl_event("wsl.exe indique qu'aucune distribution n'est installee");
            return Ok(Vec::new());
        }

        let message = if !stderr_trim.is_empty() {
            stderr_trim.to_string()
        } else if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            "wsl.exe --list a echoue".to_string()
        };
        log_wsl_event(format!("Echec wsl.exe --list --verbose --all: {message}"));
        return Err(anyhow!(message));
    }

    let instances = parse_wsl_list_output(stdout.as_str())?;

    for inst in &instances {
        let version_ref = inst.version.as_deref().unwrap_or("");
        info!(
            target: "wsl",
            instance = %inst.name,
            instance_debug = %escape_for_log(&inst.name),
            state = %inst.state,
            state_debug = %escape_for_log(&inst.state),
            version = %version_ref,
            version_debug = %escape_for_log(version_ref),
            "Instance WSL detectee"
        );
        log_wsl_event(format!(
            "Instance detectee: name={} state={} version={} default={}",
            escape_for_log(&inst.name),
            escape_for_log(&inst.state),
            escape_for_log(version_ref),
            inst.is_default
        ));
    }

    Ok(instances)
}

fn run_wsl_unregister(name: &str) -> Result<WslOperationResult> {
    if name.trim().is_empty() {
        return Err(anyhow!("Le nom de l'instance WSL est requis"));
    }

    let command_line = format_cli_command("wsl.exe", &["--unregister", name]);
    let instance_debug = escape_for_log(name);

    info!(
        target: "wsl",
        instance = name,
        instance_debug = %instance_debug,
        command = %command_line,
        "Execution d'une commande WSL"
    );
    log_wsl_event(format!(
        "Suppression WSL demandee pour {} via {}",
        instance_debug, command_line
    ));

    let output = Command::new("wsl.exe")
        .args(["--unregister", name])
        .output()
        .with_context(|| format!("Impossible de supprimer l'instance WSL {name}"))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

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
            instance_debug = %instance_debug,
            command = %command_line,
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "Instance WSL supprimee"
        );
        log_wsl_event(format!(
            "Instance WSL supprimee: {} message={} stdout={} stderr={}",
            instance_debug,
            escape_for_log(&message),
            stdout_log,
            stderr_log
        ));
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
                instance_debug = %instance_debug,
                command = %command_line,
                stdout = %stdout_log,
                stderr = %stderr_log,
                "Suppression WSL consideree comme deja effectuee (distribution absente)"
            );
            log_wsl_event(format!(
                "Suppression WSL consideree comme deja effectuee (absente): {}",
                instance_debug
            ));
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
            instance_debug = %instance_debug,
            command = %command_line,
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "Suppression WSL a echoue"
        );
        log_wsl_event(format!(
            "Suppression WSL a echoue: {} message={} stdout={} stderr={}",
            instance_debug,
            escape_for_log(&combined),
            stdout_log,
            stderr_log
        ));
        Err(anyhow!(combined))
    }
}

#[tauri::command]
pub async fn wsl_list_instances() -> Result<Vec<WslInstance>, String> {
    info!(target: "wsl", "Listing des instances WSL");
    log_wsl_event("Listing des instances WSL");
    tauri::async_runtime::spawn_blocking(collect_wsl_instances)
        .await
        .map_err(|e| {
            error!(target: "wsl", "Erreur JoinHandle (list): {e}");
            log_wsl_event(format!("Erreur JoinHandle lors du listing WSL: {e}"));
            format!("Erreur interne: {e}")
        })
        .and_then(|result| result.map_err(|e| e.to_string()))
}

#[tauri::command]
pub async fn wsl_remove_instance(name: String) -> Result<WslOperationResult, String> {
    let raw_trimmed = name.trim();
    if raw_trimmed.is_empty() {
        return Err("Le nom de l'instance est requis.".into());
    }

    let sanitized = sanitize_cli_field(raw_trimmed);
    if sanitized.is_empty() {
        return Err("Le nom de l'instance est invalide.".into());
    }

    if sanitized != raw_trimmed {
        info!(
            target: "wsl",
            instance_raw = %escape_for_log(raw_trimmed),
            instance_sanitized = %escape_for_log(&sanitized),
            "Nom d'instance WSL nettoyé avant suppression"
        );
        log_wsl_event(format!(
            "Nom d'instance WSL nettoye avant suppression: brut={} nettoye={}",
            escape_for_log(raw_trimmed),
            escape_for_log(&sanitized)
        ));
    }

    let instance_name = sanitized;
    let instance_debug = escape_for_log(&instance_name);
    info!(
        target: "wsl",
        instance = %instance_name,
        instance_debug = %instance_debug,
        "Suppression d'une instance WSL demandée"
    );
    log_wsl_event(format!(
        "Suppression d'une instance WSL demandee: {}",
        instance_debug
    ));

    tauri::async_runtime::spawn_blocking({
        let instance_name = instance_name.clone();
        move || run_wsl_unregister(&instance_name)
    })
    .await
    .map_err(|e| {
        error!(target: "wsl", "Erreur JoinHandle (remove): {e}");
        log_wsl_event(format!("Erreur JoinHandle (remove): {e}"));
        format!("Erreur interne: {e}")
    })
    .and_then(|result| {
        result.map_err(|e| {
            error!(target: "wsl", "Échec suppression WSL: {e}");
            log_wsl_event(format!("Échec suppression WSL: {e}"));
            e.to_string()
        })
    })
}
