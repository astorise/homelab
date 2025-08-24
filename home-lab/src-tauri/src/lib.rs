// src-tauri/src/lib.rs

use std::{fs, path::PathBuf};
use tracing::{error, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, EnvFilter};
mod http;
mod dns;


// ====== LOGGING ======

static mut LOG_GUARD: Option<WorkerGuard> = None;

fn resolve_log_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        // Release -> %ProgramData%, Dev -> %LocalAppData% (fallback si indispo)
        let base = if cfg!(debug_assertions) {
            std::env::var_os("LOCALAPPDATA")
        } else {
            std::env::var_os("PROGRAMDATA").or_else(|| std::env::var_os("LOCALAPPDATA"))
        }
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
        base.join("home-lab").join("logs")
    } else {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("home-lab")
            .join("logs")
    }
}

fn init_file_logger() {
    // Règle par défaut si RUST_LOG non défini
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let log_dir = resolve_log_dir();
    let _ = fs::create_dir_all(&log_dir);

    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("app.log"))
        .ok();

    match file {
        Some(file) => {
            let (nb, guard) = tracing_appender::non_blocking(file);
            unsafe { LOG_GUARD = Some(guard) } // évite la perte de logs à la fermeture

            let _ = fmt()
                .with_env_filter(filter)
                .with_writer(nb)
                .try_init();

            info!("Logger initialisé → {}", log_dir.to_string_lossy());
        }
        None => {
            let _ = fmt().with_env_filter(filter).try_init();
            info!(
                "Logger (console only) — impossible d’ouvrir {}",
                log_dir.to_string_lossy()
            );
        }
    }
}

// ====== ENTRYPOINT ======

pub fn run() {
    // Backtrace utile en cas de panic
    std::env::set_var("RUST_BACKTRACE", "1");

    tauri::Builder::default()
        .setup(|_app| {
            init_file_logger();
            info!("Démarrage de l’application Tauri…");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Tes handlers d’origine :

            dns::get_status,
            dns::stop_service,
            dns::reload_config,
            dns::list_records,
            dns::add_record,
            dns::remove_record,
            http::get_status,
            http::stop_service,
            http::reload_config,
            http::list_routes,
            http::add_route,
            http::remove_route,
   
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            error!("Erreur critique Tauri: {:?}", e);
            panic!("Erreur Tauri: {:?}", e);
        });
}
