#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use tauri::Manager;
use serde::Serialize;
use std::time::Duration;
use anyhow::Result;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tokio::net::windows::named_pipe::ClientOptions;
use std::sync::Arc;
mod icons;
mod menu;
mod proxy;
use crate::proxy::{
    proxy_get_status,
    proxy_stop_service,
    proxy_reload_config,
    proxy_list_routes,
    proxy_add_route,
    proxy_remove_route,
};


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

async fn dns_make_channel() -> Result<Channel> {
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
async fn dns_get_status() -> Result<StatusOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.get_status(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let s = resp.into_inner();
    Ok(StatusOut{ state: s.state, log_level: s.log_level })
}

#[tauri::command]
async fn dns_stop_service() -> Result<AckOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.stop_service(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
async fn dns_reload_config() -> Result<AckOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.reload_config(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
async fn dns_list_records() -> Result<ListRecordsOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
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
async fn dns_add_record(name: String, rrtype: String, value: String, ttl: u32) -> Result<AckOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let req = AddRecordRequest { name, rrtype, value, ttl };
    let resp = client.add_record(tonic::Request::new(req)).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
async fn dns_remove_record(name: String, rrtype: String, value: String) -> Result<AckOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
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
            dns_get_status,
            dns_stop_service,
            dns_reload_config,
            dns_list_records,
            dns_add_record,
            dns_remove_record,
            proxy::proxy_get_status,
            proxy::proxy_stop_service,
            proxy::proxy_reload_config,
            proxy::proxy_list_routes,
            proxy::proxy_add_route,
            proxy::proxy_remove_route,
        ])
        .setup(|app| {
                     let loaded_icons = Arc::new(crate::icons::Icons::load(&app.handle(), 20)?);
            crate::menu::setup_ui(&app.handle(), loaded_icons)?;
            Ok(())
        })
        .on_window_event(|window, event| {
      if let tauri::WindowEvent::CloseRequested { api, .. } = event {
        api.prevent_close();           // n'arrête pas l'app
        let _ = window.hide();         // cache la fenêtre
      }
    })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}