use anyhow::{anyhow, Result};
use local_rpc::Client as RpcClient;
use prost::Message;
use serde::Serialize;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::task;
use tracing::{debug, error, info, instrument, trace, warn, Span};
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

static CALL_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static DIAGNOSTICS_LOGGED: AtomicBool = AtomicBool::new(false);
const SERVICE_CANDIDATES: &[&str] = &[
    "HomeHttpService",
    "HomeHttpDevService",
    "home-http",
    "home-http-dev",
    "HomeHttp",
    "HomeHttpDev",
];
const ENV_VARS_OF_INTEREST: &[&str] = &[
    "PROGRAMDATA",
    "LOCALAPPDATA",
    "APPDATA",
    "TEMP",
    "TMP",
    "USERNAME",
    "USERDOMAIN",
];

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

fn log_env_snapshot(context: &str) {
    for var in ENV_VARS_OF_INTEREST {
        let value = std::env::var_os(var)
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<unset>".into());
        info!(
            context = context,
            env_var = *var,
            value = %value,
            "Environment snapshot captured for diagnostics"
        );
    }
    match std::env::current_dir() {
        Ok(dir) => info!(
            context = context,
            cwd = %dir.display(),
            "Current working directory captured for diagnostics"
        ),
        Err(err) => warn!(
            context = context,
            error = %err,
            "Unable to read current working directory during diagnostics"
        ),
    }
}

fn log_service_state(context: &str, service: &str) {
    match Command::new("sc").args(["query", service]).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout_summary = stdout
                .lines()
                .filter(|line| !line.trim().is_empty())
                .take(12)
                .collect::<Vec<_>>()
                .join(" | ");
            let stderr_summary = stderr
                .lines()
                .filter(|line| !line.trim().is_empty())
                .take(12)
                .collect::<Vec<_>>()
                .join(" | ");
            let exit_code = output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "terminated".into());
            info!(
                context = context,
                service = service,
                exit_code = %exit_code,
                stdout = %stdout_summary,
                stderr = %stderr_summary,
                "Windows service query result (sc query)"
            );
        }
        Err(err) => warn!(
            context = context,
            service = service,
            error = %err,
            "Failed to run `sc query` during diagnostics"
        ),
    }
}

fn log_service_snapshots(context: &str, services: &[&str]) {
    for service in services {
        log_service_state(context, service);
    }
}

fn log_http_diagnostics(error: &str) {
    if DIAGNOSTICS_LOGGED.swap(true, Ordering::SeqCst) {
        debug!(
            context = "http",
            error = %error,
            "HTTP diagnostics already recorded earlier in this session"
        );
        return;
    }
    warn!(
        context = "http",
        error = %error,
        "HTTP RPC diagnostics triggered after repeated failures"
    );
    log_env_snapshot("http");
    log_service_snapshots("http", SERVICE_CANDIDATES);
}

fn connect_rpc() -> Result<RpcClient> {
    let mut last_err = None;
    for endpoint in RPC_ENDPOINTS {
        info!(
            endpoint = endpoint,
            "Attempting HTTP RPC endpoint discovery"
        );
        match RpcClient::connect(RPC_INTERFACE_UUID, RPC_INTERFACE_VERSION, endpoint) {
            Ok(client) => {
                info!(endpoint = endpoint, "Connected to HTTP RPC endpoint");
                return Ok(client);
            }
            Err(err) => {
                warn!(
                    endpoint = endpoint,
                    error = %err,
                    "HTTP RPC endpoint connection failed, will try next candidate"
                );
                last_err = Some((*endpoint, err));
            }
        }
    }
    let (endpoint, err) = last_err.expect("RPC_ENDPOINTS is not empty");
    let failure = anyhow!("connect {endpoint}: {err}");
    error!(
        endpoint = endpoint,
        error = %failure,
        "All HTTP RPC endpoint attempts failed"
    );
    log_http_diagnostics(&failure.to_string());
    Err(failure)
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
    fields(
        proc = procedure_name(proc_num),
        call_id = tracing::field::Empty,
        payload_size = tracing::field::Empty
    )
)]
async fn rpc_call(proc_num: u32, request: Vec<u8>) -> Result<Vec<u8>, String> {
    let payload_size = request.len();
    let payload_size_u64 = payload_size as u64;
    let call_id = CALL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Span::current().record("call_id", &call_id);
    Span::current().record("payload_size", &payload_size_u64);
    trace!(
        proc = procedure_name(proc_num),
        call_id,
        payload_size,
        "Dispatching HTTP RPC call"
    );
    let span = Span::current();
    task::spawn_blocking(move || {
        span.in_scope(|| {
            trace!(
                proc = procedure_name(proc_num),
                call_id,
                payload_size,
                "Starting HTTP RPC call in blocking task"
            );
            let client = connect_rpc().map_err(|e| {
                let msg = format_transport_error(e);
                log_http_diagnostics(&msg);
                error!(
                    proc = procedure_name(proc_num),
                    call_id,
                    payload_size,
                    error = %msg,
                    "HTTP RPC connect failed"
                );
                msg
            })?;
            trace!(
                proc = procedure_name(proc_num),
                call_id,
                payload_size,
                "HTTP RPC client ready"
            );
            client
                .call(proc_num, &request)
                .map(|response| {
                    trace!(
                        proc = procedure_name(proc_num),
                        call_id,
                        payload_size,
                        response_size = response.len(),
                        "HTTP RPC call succeeded"
                    );
                    response
                })
                .map_err(|e| {
                    let msg = format_transport_error(e);
                    log_http_diagnostics(&msg);
                    error!(
                        proc = procedure_name(proc_num),
                        call_id,
                        payload_size,
                        error = %msg,
                        "HTTP RPC call failed"
                    );
                    msg
                })
        })
    })
    .await
    .map_err(|e| {
        let msg = format_transport_error(e);
        log_http_diagnostics(&msg);
        error!(
            proc = procedure_name(proc_num),
            call_id,
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
        log_http_diagnostics(&msg);
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
