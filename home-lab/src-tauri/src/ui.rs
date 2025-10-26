use tracing::{debug, error, info, trace, warn};

#[tauri::command]
pub fn ui_log(level: String, message: String) {
    let lvl = level.to_lowercase();
    match lvl.as_str() {
        "error" | "err" => {
            error!(target: "ui", "{}", message);
            println!("[ui][error] {}", message);
        }
        "warn" | "warning" => {
            warn!(target: "ui", "{}", message);
            println!("[ui][warn] {}", message);
        }
        "info" => {
            info!(target: "ui", "{}", message);
            println!("[ui][info] {}", message);
        }
        "debug" => {
            debug!(target: "ui", "{}", message);
            println!("[ui][debug] {}", message);
        }
        "trace" => {
            trace!(target: "ui", "{}", message);
            println!("[ui][trace] {}", message);
        }
        _ => {
            info!(target: "ui", "{}", message);
            println!("[ui][info] {}", message);
        }
    }
}
