// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[derive(Clone, Copy)]
enum ServiceState {
    Running,
    Stopped,
    Error,
}

fn icon_for_state<R: tauri::Runtime>(
    resolver: &tauri::path::PathResolver<R>,
    service: &str,
    state: ServiceState,
) -> tauri::Result<tauri::image::Image<'static>> {
    let color = match state {
        ServiceState::Running => "green",
        ServiceState::Stopped => "orange",
        ServiceState::Error => "red",
    };
    let name = format!("{service}-{color}.png");
    let path = resolver.resolve(
        format!("icons/{name}"),
        tauri::path::BaseDirectory::Resource,
    )?;
    let bytes = std::fs::read(path)?;
    tauri::image::Image::from_bytes(&bytes)
}

#[tauri::command]
fn read_service_log(app_handle: tauri::AppHandle, service: &str) -> Result<String, String> {
    use std::fs;
    use tauri::path::BaseDirectory;

    let resolver = app_handle.path();
    let path = resolver
        .resolve(format!("logs/{service}.log"), BaseDirectory::Resource)
        .map_err(|e| e.to_string())?;
    fs::read_to_string(path).map_err(|e| e.to_string())
}

fn show_history_window(app: &tauri::AppHandle, service: &str) {
    use tauri::{WebviewUrl, WebviewWindowBuilder};

    let label = format!("{service}-history");
    if app.get_window(&label).is_none() {
        let url = WebviewUrl::App(format!("history.html?service={service}").into());
        let _ = WebviewWindowBuilder::new(app, &label, url)
            .title(format!("{service} history"))
            .build();
    } else if let Some(window) = app.get_window(&label) {
        let _ = window.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            use std::convert::TryInto;
            use std::sync::mpsc;
            use std::thread;
            use std::time::Duration;

            use tauri::image::Image;
            use tauri::menu::{MenuBuilder, MenuItem, SubmenuBuilder};
            use tauri::menu::MenuEvent;
            use tauri::path::BaseDirectory;
            use tauri::tray::{TrayIcon, TrayIconBuilder, TrayIconEvent};
            use tauri::Manager;

            let app_handle = app.app_handle();
            let resolver = app_handle.path();
            let (status_tx, status_rx) = mpsc::channel::<(&'static str, ServiceState)>();

            // Helper to load an icon from the bundled resources directory
            let load_icon = |name: &str| -> tauri::Result<Image<'static>> {
                let path =
                    resolver.resolve(format!("icons/{name}.png"), BaseDirectory::Resource)?;
                let bytes = std::fs::read(path)?;
                Image::from_bytes(&bytes)
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
            let dns_handle = dns.clone();
            let https_handle = https.clone();
            let k3s_handle = k3s.clone();
            let quit = MenuItem::with_id(app_handle, "quit", "Quit", true, None::<&str>)?;
            let menu = MenuBuilder::new(app_handle)
                .item(&dns)
                .item(&https)
                .item(&k3s)
                .item(&quit)
                .build()?;

            let tray = TrayIconBuilder::new()
                .icon(app_handle.default_window_icon().unwrap().clone())
                .menu(&menu)
                .on_menu_event({
                    let status_tx = status_tx.clone();
                    move |app, event: MenuEvent| match event.id.as_ref() {
                        "dns_start" => {
                            let _ = status_tx.send(("dns", ServiceState::Running));
                            let _ = app.emit("dns-start", ());
                        }
                        "dns_stop" => {
                            let _ = status_tx.send(("dns", ServiceState::Stopped));
                            let _ = app.emit("dns-stop", ());
                        }
                        "dns_configure" => {
                            let _ = app.emit("dns-configure", ());
                        }
                        "https_start" => {
                            let _ = status_tx.send(("https", ServiceState::Running));
                            let _ = app.emit("https-start", ());
                        }
                        "https_stop" => {
                            let _ = status_tx.send(("https", ServiceState::Stopped));
                            let _ = app.emit("https-stop", ());
                        }
                        "https_configure" => {
                            let _ = app.emit("https-configure", ());
                        }
                        "k3s_start" => {
                            let _ = status_tx.send(("k3s", ServiceState::Running));
                            let _ = app.emit("k3s-start", ());
                        }
                        "k3s_stop" => {
                            let _ = status_tx.send(("k3s", ServiceState::Stopped));
                            let _ = app.emit("k3s-stop", ());
                        }
                        "k3s_configure" => {
                            let _ = app.emit("k3s-configure", ());
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .build(app_handle)?;

            let dns_tray = TrayIconBuilder::with_id("dns")
                .icon(icon_for_state(&resolver, "dns", ServiceState::Running)?)
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::DoubleClick { .. } = event {
                        show_history_window(tray.app_handle(), "dns");
                    }
                })
                .build(app_handle)?;

            let https_tray = TrayIconBuilder::with_id("https")
                .icon(icon_for_state(&resolver, "https", ServiceState::Running)?)
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::DoubleClick { .. } = event {
                        show_history_window(tray.app_handle(), "https");
                    }
                })
                .build(app_handle)?;

            let k3s_tray = TrayIconBuilder::with_id("k3s")
                .icon(icon_for_state(&resolver, "k3s", ServiceState::Running)?)
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::DoubleClick { .. } = event {
                        show_history_window(tray.app_handle(), "k3s");
                    }
                })
                .build(app_handle)?;

            let tray_handle = tray.clone();
            let dns_tray_handle = dns_tray.clone();
            let https_tray_handle = https_tray.clone();
            let k3s_tray_handle = k3s_tray.clone();
            let app_handle_clone = app_handle.clone();

            thread::spawn(move || {
                let resolver = app_handle_clone.path();
                while let Ok((service, state)) = status_rx.recv() {
                    if let Ok(img) = icon_for_state(&resolver, service, state) {
                        if let Ok(icon) = img.try_into() {
                            match service {
                                "dns" => {
                                    let _ = dns_handle.inner().set_icon(Some(icon.clone()));
                                    let _ = dns_tray_handle.set_icon(Some(icon.clone()));
                                }
                                "https" => {
                                    let _ = https_handle.inner().set_icon(Some(icon.clone()));
                                    let _ = https_tray_handle.set_icon(Some(icon.clone()));
                                }
                                "k3s" => {
                                    let _ = k3s_handle.inner().set_icon(Some(icon.clone()));
                                    let _ = k3s_tray_handle.set_icon(Some(icon.clone()));
                                }
                                _ => {}
                            }
                            let _ = tray_handle.set_icon(Some(icon));
                        }
                    }
                }
            });

            // Periodic task placeholder for monitoring services
            let periodic_tx = status_tx.clone();
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(60));
                // TODO: query actual service states
                let _ = periodic_tx.send(("dns", ServiceState::Running));
                let _ = periodic_tx.send(("https", ServiceState::Running));
                let _ = periodic_tx.send(("k3s", ServiceState::Running));
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![greet, read_service_log])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
