use anyhow::{anyhow, Result};
use local_rpc::Client as RpcClient;
use prost::Message;
use serde::Serialize;
use tokio::task;
use windows_sys::core::GUID;

pub mod homehttp {
    pub mod homehttp {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/homehttp.v1.rs"));
        }
    }
}
use homehttp::homehttp::v1::*;

#[cfg(debug_assertions)]
const RPC_ENDPOINTS: &[&str] = &["home-http-dev", "home-http"];
#[cfg(not(debug_assertions))]
const RPC_ENDPOINTS: &[&str] = &["home-http", "home-http-dev"];

const RPC_INTERFACE_UUID: GUID = GUID::from_u128(0x9df99e13af1c480cb5e64864350b5f3e);
const RPC_INTERFACE_VERSION: (u16, u16) = (1, 0);
const PROC_STOP_SERVICE: u32 = 0;
const PROC_RELOAD_CONFIG: u32 = 1;
const PROC_GET_STATUS: u32 = 2;
const PROC_ADD_ROUTE: u32 = 3;
const PROC_REMOVE_ROUTE: u32 = 4;
const PROC_LIST_ROUTES: u32 = 5;

fn connect_rpc() -> Result<RpcClient> {
    let mut last_err = None;
    for endpoint in RPC_ENDPOINTS {
        match RpcClient::connect(RPC_INTERFACE_UUID, RPC_INTERFACE_VERSION, endpoint) {
            Ok(client) => return Ok(client),
            Err(err) => last_err = Some((*endpoint, err)),
        }
    }
    let (endpoint, err) = last_err.expect("RPC_ENDPOINTS is not empty");
    Err(anyhow!("connect {endpoint}: {err}"))
}

fn format_transport_error(msg: impl std::fmt::Display) -> String {
    let mut text = msg.to_string();
    if text.trim().is_empty() {
        text = format!("{:?}", msg.to_string());
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("rpc_s_server_unavailable") || lower.contains("1722") {
        text.push_str(
            " - service introuvable ? Verifiez que le service Windows correspondant est demarre.",
        );
    }
    if lower.contains("os error 5") || lower.contains("access denied") {
        text.push_str(" - acces refuse (lancez l'application avec des droits suffisants).");
    }
    text
}

async fn rpc_call(proc_num: u32, request: Vec<u8>) -> Result<Vec<u8>, String> {
    task::spawn_blocking(move || {
        let client = connect_rpc().map_err(|e| format_transport_error(e))?;
        client
            .call(proc_num, &request)
            .map_err(|e| format_transport_error(e))
    })
    .await
    .map_err(|e| format_transport_error(e))?
}

fn decode_response<T: Message + Default>(bytes: Vec<u8>) -> Result<T, String> {
    T::decode(bytes.as_slice())
        .map_err(|e| format_transport_error(format!("decodage reponse: {e}")))
}

#[derive(Serialize)]
pub struct AckOut {
    pub ok: bool,
    pub message: String,
}

#[derive(Serialize)]
pub struct StatusOut {
    pub state: String,
    pub log_level: String,
}

#[derive(Serialize)]
pub struct RouteOut {
    pub host: String,
    pub port: u32,
}

#[derive(Serialize)]
pub struct ListRoutesOut {
    pub routes: Vec<RouteOut>,
}

#[tauri::command]
pub async fn http_get_status() -> Result<StatusOut, String> {
    let bytes = rpc_call(PROC_GET_STATUS, Empty {}.encode_to_vec()).await?;
    let resp: StatusResponse = decode_response(bytes)?;
    Ok(StatusOut {
        state: resp.state,
        log_level: resp.log_level,
    })
}

#[tauri::command]
pub async fn http_reload_config() -> Result<AckOut, String> {
    let bytes = rpc_call(PROC_RELOAD_CONFIG, Empty {}.encode_to_vec()).await?;
    let ack: Acknowledge = decode_response(bytes)?;
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}

#[tauri::command]
pub async fn http_stop_service() -> Result<AckOut, String> {
    let bytes = rpc_call(PROC_STOP_SERVICE, Empty {}.encode_to_vec()).await?;
    let ack: Acknowledge = decode_response(bytes)?;
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}

#[tauri::command]
pub async fn http_list_routes() -> Result<ListRoutesOut, String> {
    let bytes = rpc_call(PROC_LIST_ROUTES, Empty {}.encode_to_vec()).await?;
    let list: ListRoutesResponse = decode_response(bytes)?;
    let routes = list
        .routes
        .into_iter()
        .map(|r| RouteOut {
            host: r.host,
            port: r.port,
        })
        .collect();
    Ok(ListRoutesOut { routes })
}

#[tauri::command]
pub async fn http_add_route(host: String, port: u32) -> Result<AckOut, String> {
    let req = AddRouteRequest { host, port };
    let bytes = rpc_call(PROC_ADD_ROUTE, req.encode_to_vec()).await?;
    let ack: Acknowledge = decode_response(bytes)?;
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}

#[tauri::command]
pub async fn http_remove_route(host: String) -> Result<AckOut, String> {
    let req = RemoveRouteRequest { host };
    let bytes = rpc_call(PROC_REMOVE_ROUTE, req.encode_to_vec()).await?;
    let ack: Acknowledge = decode_response(bytes)?;
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}
