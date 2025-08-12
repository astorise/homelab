#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod icons;
mod menu;

use std::sync::Arc;

pub fn run() -> tauri::Result<()> {
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
            Ok(())
        })
        .run(tauri::generate_context!())
}