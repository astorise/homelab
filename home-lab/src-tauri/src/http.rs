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
use homehttp::homehttp::v1::home_http_client::HomeHttpClient;
use homehttp::homehttp::v1::*;

#[cfg(debug_assertions)]
const PIPE_NAME: &str = r"\\.\pipe\home-http-dev";
#[cfg(not(debug_assertions))]
// Supporte à la fois les pipes de dev et de prod
const PIPE_DEV: &str = r"\\.\pipe\home-http-dev";
const PIPE_REL: &str = r"\\.\pipe\home-http";
#[cfg(debug_assertions)]
const PIPE_DEV: &str = r"\\.\pipe\home-http-dev";

async fn connect_pipe(path: &str) -> Result<Channel> {
    let endpoint = Endpoint::try_from("http://pipe.invalid")?;
    let p = path.to_string();
    let ch = endpoint.connect_with_connector(service_fn(move |_uri: Uri| {
        let pp = p.clone();
        async move {
            let pipe = ClientOptions::new().open(pp)?;
            Ok::<_, std::io::Error>(pipe)
        }
    })).await?;
    Ok(ch)
}

async fn http_make_channel() -> Result<Channel> {
    match connect_pipe(PIPE_DEV).await {
        Ok(ch) => Ok(ch),
        Err(_) => connect_pipe(PIPE_REL).await,
    }
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
pub async fn http_get_status() -> Result<StatusOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomeHttpClient::new(ch);
    let resp = client.get_status(Empty{}).await.map_err(map_err)?;
    let s = resp.into_inner();
    Ok(StatusOut { state: s.state, log_level: s.log_level })
}

#[tauri::command]
pub async fn http_reload_config() -> Result<AckOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomeHttpClient::new(ch);
    let resp = client.reload_config(Empty{}).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut { ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn http_stop_service() -> Result<AckOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomeHttpClient::new(ch);
    let resp = client.stop_service(Empty{}).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut { ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn http_list_routes() -> Result<ListRoutesOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomeHttpClient::new(ch);
    let resp = client.list_routes(Empty{}).await.map_err(map_err)?;
    let list = resp.into_inner();
    Ok(ListRoutesOut {
        routes: list.routes.into_iter().map(|r| RouteOut { host: r.host, port: r.port }).collect()
    })
}

#[tauri::command]
pub async fn http_add_route(host: String, port: u32) -> Result<AckOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomeHttpClient::new(ch);
    let req = AddRouteRequest { host, port };
    let resp = client.add_route(req).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut { ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn http_remove_route(host: String) -> Result<AckOut, String> {
    let ch = http_make_channel().await.map_err(map_err)?;
    let mut client = HomeHttpClient::new(ch);
    let req = RemoveRouteRequest { host };
    let resp = client.remove_route(req).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut { ok: a.ok, message: a.message })
}
