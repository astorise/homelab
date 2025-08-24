use anyhow::Result;
use serde::Serialize;
use tonic::transport::{Channel, Endpoint, Uri};
use tokio::net::windows::named_pipe::ClientOptions;
use tower::service_fn;

// === gRPC generated modules (prost/tonic) ===
// (tonic-build 0.11 / tonic 0.11 produit le même path de module)
pub mod homehttp {
    pub mod homehttp {
        pub mod v1 {
            tonic::include_proto!("homehttp.v1");
        }
    }
}

use homehttp::homehttp::v1::*;

const PIPE_NAME: &str = r"\\.\pipe\home-http";

async fn http_make_channel() -> Result<Channel> {
    // L'URI est fictive (requise par Endpoint) ; on fournit un connecteur custom vers le pipe
    let endpoint = Endpoint::try_from("http://pipe.invalid")?;
    let ch = endpoint.connect_with_connector(service_fn(|_uri: Uri| async move {
        let pipe = ClientOptions::new().open(PIPE_NAME)?;
        Ok::<_, std::io::Error>(pipe)
    })).await?;
    Ok(ch)
}

fn map_err<E: std::fmt::Display>(e: E) -> String { e.to_string() }

#[derive(Serialize)]
pub struct AckOut { pub ok: bool, pub message: String }

#[derive(Serialize)]
pub struct StatusOut { pub state: String, pub log_level: String }

#[derive(Serialize)]
pub struct RouteOut { pub host: String, pub port: u32 }

#[derive(Serialize)]
pub struct ListRoutesOut { pub routes: Vec<RouteOut> }

#[tauri::command]
pub async fn get_status() -> Result<StatusOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomehttpClient::new(ch);
    let resp = client.get_status(Empty{}).await.map_err(map_err)?;
    let s = resp.into_inner();
    Ok(StatusOut { state: s.state, log_level: s.log_level })
}

#[tauri::command]
pub async fn reload_config() -> Result<AckOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomehttpClient::new(ch);
    let resp = client.reload_config(Empty{}).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut { ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn stop_service() -> Result<AckOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomehttpClient::new(ch);
    let resp = client.stop_service(Empty{}).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut { ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn list_routes() -> Result<ListRoutesOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomehttpClient::new(ch);
    let resp = client.list_routes(Empty{}).await.map_err(map_err)?;
    let list = resp.into_inner();
    Ok(ListRoutesOut {
        routes: list.routes.into_iter().map(|r| RouteOut { host: r.host, port: r.port }).collect()
    })
}

#[tauri::command]
pub async fn add_route(host: String, port: u32) -> Result<AckOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomehttpClient::new(ch);
    let req = AddRouteRequest { host, port };
    let resp = client.add_route(req).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut { ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn remove_route(host: String) -> Result<AckOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomehttpClient::new(ch);
    let req = RemoveRouteRequest { host };
    let resp = client.remove_route(req).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut { ok: a.ok, message: a.message })
}
