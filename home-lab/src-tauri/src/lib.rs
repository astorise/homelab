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
        use std::convert::TryInto;

            use tauri::image::Image;
            use tauri::menu::{MenuBuilder, MenuItem, SubmenuBuilder};
            use tauri::path::BaseDirectory;
            use tauri::tray::{MenuEvent, TrayIconBuilder, TrayIconEvent};
            use tauri::Manager;

            let app_handle = app.app_handle();
let resolver = app_handle.path();

            // Helper to load an icon from the bundled resources directory
            let load_icon = |name: &str| {
                Image::from_path(
                    resolver.resolve(format!("icons/{name}.png"), BaseDirectory::Resource)?,
                )
            };

            // DNS submenu
            let dns = SubmenuBuilder::new(app_handle, "DNS")
                .item(&MenuItem::with_id(
                    app_handle,
                    "dns_start",
                    "Start",
                    true,
                    None::<&str>,
                )?)
                .item(&MenuItem::with_id(
                    app_handle,
                    "dns_stop",
                    "Stop",
                    true,
                    None::<&str>,
                )?)
                .item(&MenuItem::with_id(
                    app_handle,
                    "dns_configure",
                    "Configure",
                    true,
                    None::<&str>,
                )?)
                .build()?;
            dns.inner().set_icon(Some(load_icon("dns")?.try_into()?));

            // HTTPS submenu
            let https = SubmenuBuilder::new(app_handle, "HTTPS")
                .item(&MenuItem::with_id(
                    app_handle,
                    "https_start",
                    "Start",
                    true,
                    None::<&str>,
                )?)
                .item(&MenuItem::with_id(
                    app_handle,
                    "https_stop",
                    "Stop",
                    true,
                    None::<&str>,
                )?)
                .item(&MenuItem::with_id(
                    app_handle,
                    "https_configure",
                    "Configure",
                    true,
                    None::<&str>,
                )?)
                .build()?;
            https
                .inner()
                .set_icon(Some(load_icon("https")?.try_into()?));

            // k3s submenu
            let k3s = SubmenuBuilder::new(app_handle, "k3s")
                .item(&MenuItem::with_id(
                    app_handle,
                    "k3s_start",
                    "Start",
                    true,
                    None::<&str>,
                )?)
                .item(&MenuItem::with_id(
                    app_handle,
                    "k3s_stop",
                    "Stop",
                    true,
                    None::<&str>,
                )?)
                .item(&MenuItem::with_id(
                    app_handle,
                    "k3s_configure",
                    "Configure",
                    true,
                    None::<&str>,
                )?)
                .build()?;
            k3s.inner().set_icon(Some(load_icon("k3s")?.try_into()?));
            let quit = MenuItem::with_id(app_handle, "quit", "Quit", true, None::<&str>)?;
            let menu = MenuBuilder::new(app_handle)
               .item(&dns)
                .item(&https)
                .item(&k3s)
                .item(&quit)
                .build()?;

            TrayIconBuilder::new()
                .icon(app_handle.default_window_icon().unwrap().clone())
                .menu(&menu)
                 .on_menu_event(|app, event: MenuEvent| match event.id.as_ref() {
                    "dns_start" => {
                        let _ = app.emit("dns-start", ());
                    }
                    "dns_stop" => {
                        let _ = app.emit("dns-stop", ());
                    }
                    "dns_configure" => {
                        let _ = app.emit("dns-configure", ());
                    }
                    "https_start" => {
                        let _ = app.emit("https-start", ());
                    }
                    "https_stop" => {
                        let _ = app.emit("https-stop", ());
                    }
                    "https_configure" => {
                        let _ = app.emit("https-configure", ());
                    }
                    "k3s_start" => {
                        let _ = app.emit("k3s-start", ());
                    }
                    "k3s_stop" => {
                        let _ = app.emit("k3s-stop", ());
                    }
                    "k3s_configure" => {
                        let _ = app.emit("k3s-configure", ());
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
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
