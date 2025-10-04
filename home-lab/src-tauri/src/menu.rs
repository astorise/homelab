use std::sync::Arc;

use tauri::{
    image::Image,
    menu::{Menu, MenuBuilder, Submenu, SubmenuBuilder},
    tray::{TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, Result, WebviewUrl, WebviewWindowBuilder, Wry,
};

use crate::icons::{IconState, Icons};

#[derive(Debug, Clone, Copy)]
pub enum Service {
    Http,
    Dns,
    K3s,
}
fn service_name(s: Service) -> &'static str {
    match s {
        Service::Http => "http",
        Service::Dns => "dns",
        Service::K3s => "k3s",
    }
}

// Essaie de charger une icône depuis ton gestionnaire d’icônes
fn try_icon(icons: &Icons, app: &AppHandle<Wry>, name: &str) -> Option<Image<'static>> {
    icons.get(name, IconState::Ok, app).ok()
}

// Sous-menu d’un service. Si `running`:
//  - true  => Stop + Param
//  - false => Start + Param
fn build_service_submenu(
    app: &AppHandle<Wry>,
    icons: &Icons,
    svc: Service,
    running: bool,
) -> Result<Submenu<Wry>> {
    let id = service_name(svc);
    let mut sb = SubmenuBuilder::new(app, id);

    if running {
        if let Some(img) = try_icon(icons, app, "stop") {
            sb = sb.icon(&format!("{id}-stop"), "Stop", img);
        } else {
            sb = sb.text(&format!("{id}-stop"), "Stop");
        }
    } else {
        if let Some(img) = try_icon(icons, app, "start") {
            sb = sb.icon(&format!("{id}-start"), "Start", img);
        } else {
            sb = sb.text(&format!("{id}-start"), "Start");
        }
    }

    if let Some(img) = try_icon(icons, app, "param") {
        sb = sb.icon(&format!("{id}-param"), "Param", img);
    } else {
        sb = sb.text(&format!("{id}-param"), "Param");
    }

    sb.build()
}

fn build_tray_menu(app: &AppHandle<Wry>, icons: &Icons) -> Result<Menu<Wry>> {
    // TODO: remplace `false` par l’état réel de chaque service
    let http = build_service_submenu(app, icons, Service::Http, false)?;
    let dns = build_service_submenu(app, icons, Service::Dns, false)?;
    let k3s = build_service_submenu(app, icons, Service::K3s, false)?;

    let mut mb = MenuBuilder::new(app)
        .text("open-ui", "Ouvrir l’interface")
        .separator();

    // Injecte les sous-menus
    mb = mb.items(&[&http, &dns, &k3s]);

    mb = mb.separator().text("quit", "Quitter");
    mb.build()
}

fn open_or_focus_main(app: &AppHandle<Wry>) -> Result<()> {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
        return Ok(());
    }

    WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
        .title("Home-Lab")
        .center()
        .build()?;
    Ok(())
}

// Appelée depuis ton setup (ex: dans lib.rs): crate::menu::setup_ui(&app.handle(), icons)?
pub fn setup_ui(app: &AppHandle<Wry>, icons: Arc<Icons>) -> Result<()> {
    let menu = build_tray_menu(app, &icons)?;

    // icône de la tray (optionnelle)
    let tray_img = icons.get("icon", IconState::Ok, app).ok();

    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::DoubleClick { .. } = ev {
                let _ = open_or_focus_main(&tray.app_handle());
            }
        })
        .on_menu_event({
            let icons = icons.clone();
            move |app, event| {
                let id: &str = event.id.as_ref(); // <- MenuId -> &str
                match id {
                    "open-ui" => {
                        let _ = open_or_focus_main(app);
                    }
                    "quit" => {
                        std::process::exit(0);
                    }

                    // À compléter: start/stop/param, puis reconstruire le menu
                    "http-start" | "http-stop" | "http-param" | "dns-start" | "dns-stop"
                    | "dns-param" | "k3s-start" | "k3s-stop" | "k3s-param" => {
                        // TODO: applique l’action correspondante, puis:
                        let _ = rebuild_tray_menu(app, &icons);
                    }

                    _ => {}
                }
            }
        });

    if let Some(img) = tray_img {
        builder = builder.icon(img); // .icon() attend un Image, pas un Option
    }

    builder.build(app)?;
    Ok(())
}

// Si tu veux refléter l’état courant, reconstruis le menu et ré-assigne au tray
fn rebuild_tray_menu(app: &AppHandle<Wry>, icons: &Icons) -> Result<()> {
    let new_menu = build_tray_menu(app, icons)?;
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_menu(Some(new_menu));
    }
    Ok(())
}
