use anyhow::{anyhow, Result};
use local_rpc::Client as RpcClient;
use prost::Message;
use serde::Serialize;
use tokio::task;
use tracing::{debug, error, info, instrument, trace, warn};
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

fn connect_rpc() -> Result<RpcClient> {
    let mut last_err = None;
    for endpoint in RPC_ENDPOINTS {
        debug!("Trying DNS RPC endpoint `{endpoint}`");
        match RpcClient::connect(RPC_INTERFACE_UUID, RPC_INTERFACE_VERSION, endpoint) {
            Ok(client) => {
                info!("Connected to DNS RPC endpoint `{endpoint}`");
                return Ok(client);
            }
            Err(err) => {
                warn!("DNS RPC endpoint `{endpoint}` connection failed: {err} (will try next)");
                last_err = Some((*endpoint, err));
            }
        }
    }
    let (endpoint, err) = last_err.expect("RPC_ENDPOINTS is not empty");
    error!("All DNS RPC endpoint attempts failed, last endpoint `{endpoint}`: {err}");
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
        "Dispatching DNS RPC call"
    );
    task::spawn_blocking(move || {
        trace!(
            proc = procedure_name(proc_num),
            payload_size,
            "Starting DNS RPC call in blocking task"
        );
        let client = connect_rpc().map_err(|e| {
            let msg = format_transport_error(e);
            error!(
                proc = procedure_name(proc_num),
                payload_size,
                error = %msg,
                "DNS RPC connect failed"
            );
            msg
        })?;
        trace!(
            proc = procedure_name(proc_num),
            payload_size,
            "DNS RPC client ready"
        );
        client
            .call(proc_num, &request)
            .map(|response| {
                trace!(
                    proc = procedure_name(proc_num),
                    payload_size,
                    response_size = response.len(),
                    "DNS RPC call succeeded"
                );
                response
            })
            .map_err(|e| {
                let msg = format_transport_error(e);
                error!(
                    proc = procedure_name(proc_num),
                    payload_size,
                    error = %msg,
                    "DNS RPC call failed"
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
