#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use tauri::Manager;
use serde::Serialize;
use std::time::Duration;
use anyhow::Result;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tokio::net::windows::named_pipe::ClientOptions;

// === gRPC generated modules (prost/tonic) ===
pub mod homedns {
    pub mod homedns {
        pub mod v1 {
            tonic::include_proto!("homedns.v1");
        }
    }
}
use homedns::homedns::v1::home_dns_client::HomeDnsClient;
use homedns::homedns::v1::*;

const PIPE_NAME: &str = r"\\.\pipe\home-dns";

async fn make_channel() -> Result<Channel> {
    // Endpoint URI is dummy; transport comes from the connector (named pipe stream).
    let ep = Endpoint::try_from("http://localhost:50051")?
        .connect_timeout(Duration::from_secs(5))
        .tcp_nodelay(true);
    let path = PIPE_NAME.to_string();
    let ch = ep.connect_with_connector(service_fn(move |_uri: Uri| {
        let path = path.clone();
        async move {
            // Open the named pipe client; succeeds when the server pipe exists.
            let client = ClientOptions::new().open(&path)?;
            Ok::<_, std::io::Error>(client)
        }
    })).await?;
    Ok(ch)
}

fn map_err<E: std::fmt::Display>(e: E) -> String { e.to_string() }

#[derive(Serialize)]
struct AckOut { ok: bool, message: String }

#[derive(Serialize)]
struct StatusOut { state: String, log_level: String }

#[derive(Serialize)]
struct RecordOut { name: String, a: Vec<String>, aaaa: Vec<String>, ttl: u32 }

#[derive(Serialize)]
struct ListRecordsOut { records: Vec<RecordOut> }

#[tauri::command]
async fn ping() -> String { "pong".into() }

#[tauri::command]
async fn grpc_get_status() -> Result<StatusOut, String> {
    let ch = make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.get_status(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let s = resp.into_inner();
    Ok(StatusOut{ state: s.state, log_level: s.log_level })
}

#[tauri::command]
async fn grpc_stop_service() -> Result<AckOut, String> {
    let ch = make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.stop_service(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
async fn grpc_reload_config() -> Result<AckOut, String> {
    let ch = make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.reload_config(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
async fn grpc_list_records() -> Result<ListRecordsOut, String> {
    let ch = make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.list_records(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let list = resp.into_inner();
    let out = ListRecordsOut {
        records: list.records.into_iter().map(|r| RecordOut {
            name: r.name, a: r.a, aaaa: r.aaaa, ttl: r.ttl
        }).collect()
    };
    Ok(out)
}

#[tauri::command]
async fn grpc_add_record(name: String, rrtype: String, value: String, ttl: u32) -> Result<AckOut, String> {
    let ch = make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let req = AddRecordRequest { name, rrtype, value, ttl };
    let resp = client.add_record(tonic::Request::new(req)).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
async fn grpc_remove_record(name: String, rrtype: String, value: String) -> Result<AckOut, String> {
    let ch = make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let req = RemoveRecordRequest { name, rrtype, value };
    let resp = client.remove_record(tonic::Request::new(req)).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            ping,
            grpc_get_status,
            grpc_stop_service,
            grpc_reload_config,
            grpc_list_records,
            grpc_add_record,
            grpc_remove_record,
        ])
        .setup(|app| {
            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState};

            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&quit_item])?;

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(true);

            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }

            tray_builder
                .on_menu_event(|app, event| if event.id.as_ref() == "quit" { app.exit(0); })
                .on_tray_icon_event(|tray, event| match event {
                    TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } => {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.unminimize();
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|_window, _event| {})
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}