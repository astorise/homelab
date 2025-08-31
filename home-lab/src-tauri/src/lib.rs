#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{fs, path::PathBuf};
use tracing::{error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, EnvFilter};
use std::sync::Arc;
#[cfg(debug_assertions)]
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

mod icons;
mod menu;
mod dns;
mod http;
mod ui;
#[cfg(all(debug_assertions, target_os = "windows"))]
mod dev_services;

static mut LOG_GUARD: Option<WorkerGuard> = None;

fn log_dir() -> PathBuf {
    // 1. ProgramData (idéal pour une app installée)
    if let Some(pd) = std::env::var_os("PROGRAMDATA") {
        return PathBuf::from(pd).join("home-lab").join("logs");
    }
    // 2. LocalAppData (dev / per-user)
    if let Some(la) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(la).join("home-lab").join("logs");
    }
    // 3. Temp (toujours présent)
    if let Some(t) = std::env::var_os("TEMP").or_else(|| std::env::var_os("TMP")) {
        return PathBuf::from(t).join("home-lab").join("logs");
    }
    // 4. Répertoire courant (dernier recours)
    PathBuf::from(".").join("home-lab").join("logs")
}

fn init_file_logger() {
    // défaut si RUST_LOG absent
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let dir = log_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("Impossible de créer {:?}: {:?}", dir, e);
    }

    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("app.log"))
        .ok();

    match file {
        Some(file) => {
            let (nb, guard) = tracing_appender::non_blocking(file);
            unsafe { LOG_GUARD = Some(guard); }
            let _ = fmt().with_env_filter(filter).with_writer(nb).try_init();
            info!("logger initialisé → {:?}", dir);
        }
        None => {
            let _ = fmt().with_env_filter(filter).try_init();
            warn!("logger en console uniquement — échec d’ouverture du fichier dans {:?}", dir);
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
        api.prevent_close();           // n'arrête pas l'app
        let _ = window.hide();         // cache la fenêtre
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
            ui::ui_log,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            error!("erreur critique: {:?}", e);
            panic!("Erreur Tauri: {:?}", e);
        });
 
        
}
