use anyhow::Result;
use local_rpc::Client as RpcClient;
use prost::Message;
use serde::Serialize;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::task;
use tracing::{debug, error, info, instrument, trace, warn, Span};
use windows_sys::core::GUID;

pub mod homedns {
    pub mod homedns {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/homedns.v1.rs"));
        }
    }
}
use homedns::homedns::v1::*;

#[cfg(debug_assertions)]
const RPC_ENDPOINTS: &[&str] = &["home-dns-dev", "home-dns"];
#[cfg(not(debug_assertions))]
const RPC_ENDPOINTS: &[&str] = &["home-dns", "home-dns-dev"];

const RPC_INTERFACE_UUID: GUID = GUID::from_u128(0x18477de6c4b24746b60492db45db2d31);
const RPC_INTERFACE_VERSION: (u16, u16) = (1, 0);
const PROC_STOP_SERVICE: u32 = 0;
const PROC_RELOAD_CONFIG: u32 = 1;
const PROC_GET_STATUS: u32 = 2;
const PROC_ADD_RECORD: u32 = 3;
const PROC_REMOVE_RECORD: u32 = 4;
const PROC_LIST_RECORDS: u32 = 5;
const RPC_STATUS_SERVER_NOT_LISTENING: i32 = 1715;
const RPC_STATUS_SERVER_UNAVAILABLE: i32 = 1722;
const RPC_STATUS_ENDPOINT_NOT_FOUND: i32 = 1753;

static CALL_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static DIAGNOSTICS_LOGGED: AtomicBool = AtomicBool::new(false);
const SERVICE_CANDIDATES: &[&str] = &[
    "HomeDnsService",
    "HomeDnsDevService",
    "home-dns",
    "home-dns-dev",
    "HomeDns",
    "HomeDnsDev",
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
        PROC_ADD_RECORD => "ADD_RECORD",
        PROC_REMOVE_RECORD => "REMOVE_RECORD",
        PROC_LIST_RECORDS => "LIST_RECORDS",
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

fn log_dns_diagnostics(error: &str) {
    if DIAGNOSTICS_LOGGED.swap(true, Ordering::SeqCst) {
        debug!(
            context = "dns",
            error = %error,
            "DNS diagnostics already recorded earlier in this session"
        );
        return;
    }
    warn!(
        context = "dns",
        error = %error,
        "DNS RPC diagnostics triggered after repeated failures"
    );
    log_env_snapshot("dns");
    log_service_snapshots("dns", SERVICE_CANDIDATES);
}

fn call_rpc_with_fallback(
    proc_num: u32,
    request: &[u8],
    call_id: u64,
    payload_size: usize,
) -> Result<Vec<u8>, String> {
    let mut last_error: Option<String> = None;
    for endpoint in RPC_ENDPOINTS {
        info!(
            proc = procedure_name(proc_num),
            call_id,
            payload_size,
            endpoint = endpoint,
            "Attempting DNS RPC endpoint discovery"
        );
        match RpcClient::connect(RPC_INTERFACE_UUID, RPC_INTERFACE_VERSION, endpoint) {
            Ok(client) => {
                info!(
                    proc = procedure_name(proc_num),
                    call_id,
                    payload_size,
                    endpoint = endpoint,
                    "Connected to DNS RPC endpoint"
                );
                trace!(
                    proc = procedure_name(proc_num),
                    call_id,
                    payload_size,
                    endpoint = endpoint,
                    "DNS RPC client ready"
                );
                match client.call(proc_num, request) {
                    Ok(response) => {
                        let response_size = response.len();
                        trace!(
                            proc = procedure_name(proc_num),
                            call_id,
                            payload_size,
                            endpoint = endpoint,
                            response_size,
                            "DNS RPC call succeeded"
                        );
                        return Ok(response);
                    }
                    Err(err) => {
                        let code = err.code();
                        let err_text = err.to_string();
                        let formatted = format_transport_error(&err_text);
                        if is_transient_rpc_status(code) {
                            warn!(
                                proc = procedure_name(proc_num),
                                call_id,
                                payload_size,
                                endpoint = endpoint,
                                code,
                                error = %formatted,
                                "DNS RPC call transport failed, trying next endpoint"
                            );
                            last_error = Some(format!(
                                "endpoint {endpoint}: {formatted} (code {code})"
                            ));
                            continue;
                        } else {
                            error!(
                                proc = procedure_name(proc_num),
                                call_id,
                                payload_size,
                                endpoint = endpoint,
                                code,
                                error = %formatted,
                                "DNS RPC call failed without recovery"
                            );
                            log_dns_diagnostics(&formatted);
                            return Err(formatted);
                        }
                    }
                }
            }
            Err(err) => {
                let code = err.code();
                let err_text = err.to_string();
                let formatted = format_transport_error(&err_text);
                warn!(
                    proc = procedure_name(proc_num),
                    call_id,
                    payload_size,
                    endpoint = endpoint,
                    code,
                    error = %formatted,
                    "DNS RPC endpoint connection failed, will try next candidate"
                );
                last_error = Some(format!(
                    "endpoint {endpoint}: {formatted} (code {code})"
                ));
                continue;
            }
        }
    }
    let failure = last_error.unwrap_or_else(|| "aucun point de terminaison RPC valide".into());
    error!(
        proc = procedure_name(proc_num),
        call_id,
        payload_size,
        error = %failure,
        "All DNS RPC endpoint attempts failed"
    );
    log_dns_diagnostics(&failure);
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

fn is_transient_rpc_status(code: i32) -> bool {
    matches!(
        code,
        RPC_STATUS_SERVER_NOT_LISTENING
            | RPC_STATUS_SERVER_UNAVAILABLE
            | RPC_STATUS_ENDPOINT_NOT_FOUND
    )
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
        "Dispatching DNS RPC call"
    );
    let span = Span::current();
    task::spawn_blocking(move || {
        span.in_scope(|| {
            trace!(
                proc = procedure_name(proc_num),
                call_id,
                payload_size,
                "Starting DNS RPC call in blocking task"
            );
            call_rpc_with_fallback(proc_num, &request, call_id, payload_size)
        })
    })
    .await
    .map_err(|e| {
        let msg = format_transport_error(e);
        log_dns_diagnostics(&msg);
        error!(
            proc = procedure_name(proc_num),
            call_id,
            payload_size,
            error = %msg,
            "DNS RPC join error"
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
        "Decoding DNS RPC response payload"
    );
    T::decode(bytes.as_slice()).map_err(|e| {
        let msg = format_transport_error(format!("decodage reponse: {e}"));
        log_dns_diagnostics(&msg);
        error!(
            response_type,
            payload_size,
            error = %msg,
            "DNS RPC response decode failed"
        );
        msg
    })
}

#[derive(Serialize)]
pub struct AckOut {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
pub struct StatusOut {
    state: String,
    log_level: String,
}

#[derive(Serialize)]
pub struct RecordOut {
    name: String,
    a: Vec<String>,
    aaaa: Vec<String>,
    ttl: u32,
}

#[derive(Serialize)]
pub struct ListRecordsOut {
    records: Vec<RecordOut>,
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_get_status() -> Result<StatusOut, String> {
    debug!("Requesting DNS status from service");
    let bytes = rpc_call(PROC_GET_STATUS, Empty {}.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "DNS status RPC call failed");
            e
        })?;
    trace!("DNS status response received ({} bytes)", bytes.len());
    let resp: StatusResponse = decode_response(bytes).map_err(|e| {
        error!(error = %e, "DNS status response decode failed");
        e
    })?;
    let state = resp.state;
    let log_level = resp.log_level;
    debug!(state = %state, log_level = %log_level, "DNS status retrieved");
    Ok(StatusOut { state, log_level })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_stop_service() -> Result<AckOut, String> {
    debug!("Sending DNS stop service command");
    let bytes = rpc_call(PROC_STOP_SERVICE, Empty {}.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "DNS stop RPC call failed");
            e
        })?;
    let ack: Ack = decode_response(bytes).map_err(|e| {
        error!(error = %e, "DNS stop response decode failed");
        e
    })?;
    let ok = ack.ok;
    let message = ack.message;
    info!(ok, message = %message, "DNS stop service acknowledged");
    Ok(AckOut { ok, message })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_reload_config() -> Result<AckOut, String> {
    debug!("Sending DNS reload configuration command");
    let bytes = rpc_call(PROC_RELOAD_CONFIG, Empty {}.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "DNS reload RPC call failed");
            e
        })?;
    let ack: Ack = decode_response(bytes).map_err(|e| {
        error!(error = %e, "DNS reload response decode failed");
        e
    })?;
    let ok = ack.ok;
    let message = ack.message;
    info!(ok, message = %message, "DNS reload configuration acknowledged");
    Ok(AckOut { ok, message })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_list_records() -> Result<ListRecordsOut, String> {
    debug!("Requesting DNS record list");
    let bytes = rpc_call(PROC_LIST_RECORDS, Empty {}.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "DNS list records RPC call failed");
            e
        })?;
    let list: ListRecordsResponse = decode_response(bytes).map_err(|e| {
        error!(error = %e, "DNS list records response decode failed");
        e
    })?;
    let total = list.records.len();
    let records = list
        .records
        .into_iter()
        .map(|r| RecordOut {
            name: r.name,
            a: r.a,
            aaaa: r.aaaa,
            ttl: r.ttl,
        })
        .collect();
    info!(total, "DNS record list retrieved");
    Ok(ListRecordsOut { records })
}

#[tauri::command]
#[instrument(level = "debug", skip(value))]
pub async fn dns_add_record(
    name: String,
    rrtype: String,
    value: String,
    ttl: u32,
) -> Result<AckOut, String> {
    debug!(
        name = %name,
        rrtype = %rrtype,
        ttl,
        "Adding DNS record via RPC"
    );
    let req = AddRecordRequest {
        name,
        rrtype,
        value,
        ttl,
    };
    let bytes = rpc_call(PROC_ADD_RECORD, req.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "DNS add record RPC call failed");
            e
        })?;
    let ack: Ack = decode_response(bytes).map_err(|e| {
        error!(error = %e, "DNS add record response decode failed");
        e
    })?;
    let ok = ack.ok;
    let message = ack.message;
    info!(ok, message = %message, "DNS add record acknowledged");
    Ok(AckOut { ok, message })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_remove_record(
    name: String,
    rrtype: String,
    value: String,
) -> Result<AckOut, String> {
    debug!(
        name = %name,
        rrtype = %rrtype,
        value = %value,
        "Removing DNS record via RPC"
    );
    let req = RemoveRecordRequest {
        name,
        rrtype,
        value,
    };
    let bytes = rpc_call(PROC_REMOVE_RECORD, req.encode_to_vec())
        .await
        .map_err(|e| {
            error!(error = %e, "DNS remove record RPC call failed");
            e
        })?;
    let ack: Ack = decode_response(bytes).map_err(|e| {
        error!(error = %e, "DNS remove record response decode failed");
        e
    })?;
    let ok = ack.ok;
    let message = ack.message;
    info!(ok, message = %message, "DNS remove record acknowledged");
    Ok(AckOut { ok, message })
}
