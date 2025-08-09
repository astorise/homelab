// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            use tauri::menu::{MenuBuilder, MenuItem};
            use tauri::tray::{TrayIconBuilder, TrayIconEvent};
            use tauri::Manager;

            let app_handle = app.app_handle();

            let quit = MenuItem::with_id(app_handle, "quit", "Quit", true, None::<&str>)?;
            let menu = MenuBuilder::new(app_handle)
                .item(&quit)
                .build()?;

            TrayIconBuilder::new()
                .icon(app_handle.default_window_icon().unwrap().clone())
                .menu(&menu)
                .on_tray_icon_event(|_, event| match event {
                    TrayIconEvent::Enter { .. } => println!("tray hover"),
                    TrayIconEvent::DoubleClick { .. } => println!("tray double click"),
                    _ => {}
                })
                .build(app_handle)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
