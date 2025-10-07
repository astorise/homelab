use anyhow::{anyhow, Result};
use local_rpc::Client as RpcClient;
use prost::Message;
use serde::Serialize;
use tokio::task;
use tracing::{debug, error, info, instrument, trace, warn};
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

fn procedure_name(proc_num: u32) -> &'static str {
    match proc_num {
        PROC_STOP_SERVICE => "STOP_SERVICE",
        PROC_RELOAD_CONFIG => "RELOAD_CONFIG",
        PROC_GET_STATUS => "GET_STATUS",
        PROC_ADD_ROUTE => "ADD_ROUTE",
        PROC_REMOVE_ROUTE => "REMOVE_ROUTE",
        PROC_LIST_ROUTES => "LIST_ROUTES",
        _ => "UNKNOWN",
    }
}

fn connect_rpc() -> Result<RpcClient> {
    let mut last_err = None;
    for endpoint in RPC_ENDPOINTS {
        debug!("Trying HTTP RPC endpoint `{endpoint}`");
        match RpcClient::connect(RPC_INTERFACE_UUID, RPC_INTERFACE_VERSION, endpoint) {
            Ok(client) => {
                info!("Connected to HTTP RPC endpoint `{endpoint}`");
                return Ok(client);
            }
            Err(err) => {
                warn!("HTTP RPC endpoint `{endpoint}` connection failed: {err} (will try next)");
                last_err = Some((*endpoint, err));
            }
        }
    }
    let (endpoint, err) = last_err.expect("RPC_ENDPOINTS is not empty");
    error!("All HTTP RPC endpoint attempts failed, last endpoint `{endpoint}`: {err}");
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

#[instrument(
    level = "trace",
    skip(request),
    fields(proc = procedure_name(proc_num))
)]
async fn rpc_call(proc_num: u32, request: Vec<u8>) -> Result<Vec<u8>, String> {
    let payload_size = request.len();
    trace!(
        proc = procedure_name(proc_num),
        payload_size,
        "Dispatching HTTP RPC call"
    );
    task::spawn_blocking(move || {
        trace!(
            proc = procedure_name(proc_num),
            payload_size,
            "Starting HTTP RPC call in blocking task"
        );
        let client = connect_rpc().map_err(|e| {
            let msg = format_transport_error(e);
            error!(
                proc = procedure_name(proc_num),
                payload_size,
                error = %msg,
                "HTTP RPC connect failed"
            );
            msg
        })?;
        trace!(
            proc = procedure_name(proc_num),
            payload_size,
            "HTTP RPC client ready"
        );
        client
            .call(proc_num, &request)
            .map(|response| {
                trace!(
                    proc = procedure_name(proc_num),
                    payload_size,
                    response_size = response.len(),
                    "HTTP RPC call succeeded"
                );
                response
            })
            .map_err(|e| {
                let msg = format_transport_error(e);
                error!(
                    proc = procedure_name(proc_num),
                    payload_size,
                    error = %msg,
                    "HTTP RPC call failed"
                );
                msg
            })
    })
    .await
    .map_err(|e| {
        let msg = format_transport_error(e);
        error!(
            proc = procedure_name(proc_num),
            payload_size,
            error = %msg,
            "HTTP RPC join error"
        );
        msg
    })?
}

fn decode_response<T: Message + Default>(bytes: Vec<u8>) -> Result<T, String> {
    let response_type = std::any::type_name::<T>();
    let payload_size = bytes.len();
    trace!(
        response_type,
        payload_size,
        "Decoding HTTP RPC response payload"
    );
    T::decode(bytes.as_slice()).map_err(|e| {
        let msg = format_transport_error(format!("decodage reponse: {e}"));
        error!(
            response_type,
            payload_size,
            error = %msg,
            "HTTP RPC response decode failed"
        );
        msg
    })
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
#[instrument(level = "debug")]
pub async fn http_get_status() -> Result<StatusOut, String> {
    debug!("Requesting HTTP service status");
    let bytes = rpc_call(PROC_GET_STATUS, Empty {}.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "HTTP status RPC call failed");
            e
        })?;
    trace!("HTTP status response received ({} bytes)", bytes.len());
    let resp: StatusResponse = decode_response(bytes).map_err(|e| {
        error!(error = %e, "HTTP status response decode failed");
        e
    })?;
    let state = resp.state;
    let log_level = resp.log_level;
    debug!(state = %state, log_level = %log_level, "HTTP status retrieved");
    Ok(StatusOut { state, log_level })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_reload_config() -> Result<AckOut, String> {
    debug!("Sending HTTP reload configuration command");
    let bytes = rpc_call(PROC_RELOAD_CONFIG, Empty {}.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "HTTP reload RPC call failed");
            e
        })?;
    let ack: Acknowledge = decode_response(bytes).map_err(|e| {
        error!(error = %e, "HTTP reload response decode failed");
        e
    })?;
    let ok = ack.ok;
    let message = ack.message;
    info!(ok, message = %message, "HTTP reload configuration acknowledged");
    Ok(AckOut { ok, message })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_stop_service() -> Result<AckOut, String> {
    debug!("Sending HTTP stop service command");
    let bytes = rpc_call(PROC_STOP_SERVICE, Empty {}.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "HTTP stop RPC call failed");
            e
        })?;
    let ack: Acknowledge = decode_response(bytes).map_err(|e| {
        error!(error = %e, "HTTP stop response decode failed");
        e
    })?;
    let ok = ack.ok;
    let message = ack.message;
    info!(ok, message = %message, "HTTP stop service acknowledged");
    Ok(AckOut { ok, message })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_list_routes() -> Result<ListRoutesOut, String> {
    debug!("Requesting HTTP route list");
    let bytes = rpc_call(PROC_LIST_ROUTES, Empty {}.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "HTTP list routes RPC call failed");
            e
        })?;
    let list: ListRoutesResponse = decode_response(bytes).map_err(|e| {
        error!(error = %e, "HTTP list routes response decode failed");
        e
    })?;
    let total = list.routes.len();
    let routes = list
        .routes
        .into_iter()
        .map(|r| RouteOut {
            host: r.host,
            port: r.port,
        })
        .collect();
    info!(total, "HTTP route list retrieved");
    Ok(ListRoutesOut { routes })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_add_route(host: String, port: u32) -> Result<AckOut, String> {
    debug!(host = %host, port, "Adding HTTP route via RPC");
    let req = AddRouteRequest { host, port };
    let bytes = rpc_call(PROC_ADD_ROUTE, req.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "HTTP add route RPC call failed");
            e
        })?;
    let ack: Acknowledge = decode_response(bytes).map_err(|e| {
        error!(error = %e, "HTTP add route response decode failed");
        e
    })?;
    let ok = ack.ok;
    let message = ack.message;
    info!(ok, message = %message, "HTTP add route acknowledged");
    Ok(AckOut { ok, message })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_remove_route(host: String) -> Result<AckOut, String> {
    debug!(host = %host, "Removing HTTP route via RPC");
    let req = RemoveRouteRequest { host };
    let bytes = rpc_call(PROC_REMOVE_ROUTE, req.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "HTTP remove route RPC call failed");
            e
        })?;
    let ack: Acknowledge = decode_response(bytes).map_err(|e| {
        error!(error = %e, "HTTP remove route response decode failed");
        e
    })?;
    let ok = ack.ok;
    let message = ack.message;
    info!(ok, message = %message, "HTTP remove route acknowledged");
    Ok(AckOut { ok, message })
}
