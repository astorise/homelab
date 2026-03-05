#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use std::{fs, path::PathBuf};
#[cfg(debug_assertions)]
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use tracing::{error, info, warn};
use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_subscriber::{EnvFilter, fmt};

#[cfg(all(debug_assertions, target_os = "windows"))]
mod dev_services;
mod dns;
mod http;
mod icons;
mod menu;
mod oidc;
mod ui;
mod wsl;

static mut LOG_GUARD: Option<WorkerGuard> = None;
const BUILD_GIT_SHA: &str = env!("BUILD_GIT_SHA");
const BUILD_GIT_TAG: &str = env!("BUILD_GIT_TAG");

fn default_log_filter() -> &'static str {
    if cfg!(debug_assertions) {
        "debug,tauri=info"
    } else {
        "info"
    }
}

fn build_label() -> String {
    let raw = if BUILD_GIT_TAG.trim().is_empty() || BUILD_GIT_TAG == "unknown" {
        BUILD_GIT_SHA
    } else {
        BUILD_GIT_TAG
    };
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.trim_matches('_').is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn log_dir() -> PathBuf {
    // 1. ProgramData (preferred when the app is installed)
    if let Some(pd) = std::env::var_os("PROGRAMDATA") {
        return PathBuf::from(pd).join("home-lab").join("logs");
    }
    // 2. LocalAppData (user scope, common during development)
    if let Some(la) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(la).join("home-lab").join("logs");
    }
    // 3. Temp (always available)
    if let Some(t) = std::env::var_os("TEMP").or_else(|| std::env::var_os("TMP")) {
        return PathBuf::from(t).join("home-lab").join("logs");
    }
    // 4. Current directory (last resort)
    PathBuf::from(".").join("home-lab").join("logs")
}

fn init_file_logger() {
    let dir = log_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("Unable to create {}: {e}", dir.display());
    }

    let filter_directive =
        std::env::var("RUST_LOG").unwrap_or_else(|_| default_log_filter().to_string());
    let filter = EnvFilter::try_new(filter_directive.clone())
        .unwrap_or_else(|_| EnvFilter::new(default_log_filter()));

    let logfile_name = format!("app_{}.log", build_label());
    let file_appender = rolling::daily(&dir, &logfile_name);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let builder = fmt()
        .with_env_filter(filter)
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_level(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    match builder.try_init() {
        Ok(()) => {
            unsafe {
                LOG_GUARD = Some(guard);
            }
            info!(
                "File logger initialised in {} (file={})",
                dir.display(),
                logfile_name
            );
        }
        Err(err) => {
            drop(guard);
            let fallback_filter = EnvFilter::try_new(filter_directive)
                .unwrap_or_else(|_| EnvFilter::new(default_log_filter()));
            if fmt()
                .with_env_filter(fallback_filter)
                .with_ansi(false)
                .with_level(true)
                .with_target(true)
                .with_file(true)
                .with_line_number(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .try_init()
                .is_ok()
            {
                warn!("File logger initialisation failed: {err}. Logging to console instead.");
            } else {
                eprintln!("Logger initialisation failed: {err}");
            }
        }
    }
}

#[cfg(all(target_os = "windows", not(debug_assertions)))]
fn ensure_service_running(service_name: &'static str) {
    let service = service_name.to_string();
    tauri::async_runtime::spawn(async move {
        let service_for_cmd = service.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            let escaped = service_for_cmd.replace('\'', "''");
            let cmd = format!(
                "Try {{ $svc = Get-Service -Name '{escaped}' -ErrorAction Stop; if ($svc.Status -ne 'Running') {{ Start-Service -Name '{escaped}' -ErrorAction Stop; Write-Output 'started' }} else {{ Write-Output 'already-running' }} }} Catch {{ Write-Output ('error: ' + $_.Exception.Message) }}"
            );
            std::process::Command::new("powershell.exe")
                .arg("-NoProfile")
                .arg("-Command")
                .arg(cmd)
                .output()
        })
        .await;

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if !output.status.success() || stdout.starts_with("error:") {
                    warn!(
                        service = %service,
                        status = %output.status,
                        stdout = %stdout,
                        stderr = %stderr,
                        "Failed to ensure Windows service is running"
                    );
                } else {
                    info!(
                        service = %service,
                        status = %output.status,
                        stdout = %stdout,
                        "Windows service startup check completed"
                    );
                }
            }
            Ok(Err(err)) => {
                warn!(
                    service = %service,
                    error = %err,
                    "Failed to run Start-Service command"
                );
            }
            Err(err) => {
                warn!(
                    service = %service,
                    error = %err,
                    "Failed to join Start-Service task"
                );
            }
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    std::env::set_var("RUST_BACKTRACE", "1");

    // ⚠️ Initialise AVANT le Builder pour garantir la création du dossier/log
    init_file_logger();
    info!("boot…");

    tauri::Builder::default()
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close(); // n'arrête pas l'app
                let _ = window.hide(); // cache la fenêtre
            }
        })
        .setup(|app| {
            let loaded_icons = Arc::new(crate::icons::Icons::load(&app.handle(), 20)?);
            crate::menu::setup_ui(&app.handle(), loaded_icons)?;

            #[cfg(all(target_os = "windows", not(debug_assertions)))]
            {
                ensure_service_running("HomeDnsService");
            }

            // En dev sur Windows, lance les services en mode console et redirige leurs logs
            #[cfg(all(debug_assertions, target_os = "windows"))]
            {
                let _ = crate::dev_services::spawn(&app.handle());
            }

            // En dev, assure que la fenêtre principale est visible
            // (sinon on a tendance à ouvrir le serveur Vite dans un navigateur externe,
            //  où l'API Tauri n'est pas disponible).
            #[cfg(debug_assertions)]
            {
                if let Some(main) = app.get_webview_window("main") {
                    let _ = main.show();
                    let _ = main.set_focus();
                } else {
                    // Si aucune fenêtre 'main' n'existe (ex: config la masque/retard), on la crée.
                    let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
                        .title("Home Lab")
                        .center()
                        .build()?;
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Tes handlers d’origine :
            dns::dns_get_status,
            dns::dns_stop_service,
            dns::dns_reload_config,
            dns::dns_list_records,
            dns::dns_add_record,
            dns::dns_remove_record,
            http::http_get_status,
            http::http_stop_service,
            http::http_reload_config,
            http::http_list_routes,
            http::http_add_route,
            http::http_remove_route,
            oidc::oidc_get_status,
            oidc::oidc_list_clients,
            oidc::oidc_register_client,
            oidc::oidc_remove_client,
            wsl::wsl_import_instance,
            wsl::wsl_list_instances,
            wsl::wsl_sync_windows_kubeconfig,
            wsl::wsl_remove_instance,
            wsl::wsl_kubectl_exec,
            wsl::wsl_kubectl_apply_yaml,
            ui::ui_log,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            error!("erreur critique: {:?}", e);
            panic!("Erreur Tauri: {:?}", e);
        });
}
