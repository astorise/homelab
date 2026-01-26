#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use std::{fs, path::PathBuf};
#[cfg(debug_assertions)]
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use tracing::{error, info, warn};
use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_subscriber::{fmt, EnvFilter};

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

fn default_log_filter() -> &'static str {
    if cfg!(debug_assertions) {
        "debug,tauri=info"
    } else {
        "info"
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

    let file_appender = rolling::daily(&dir, "app.log");
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
            info!("File logger initialised in {}", dir.display());
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
            wsl::wsl_remove_instance,
            ui::ui_log,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            error!("erreur critique: {:?}", e);
            panic!("Erreur Tauri: {:?}", e);
        });
}
