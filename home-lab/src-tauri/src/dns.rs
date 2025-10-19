use pin_project::pin_project;
use serde::Serialize;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::OnceCell;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;
use tracing::{debug, error, info, instrument};

// gRPC generated code
mod proto {
    pub mod homedns {
        pub mod v1 {
            tonic::include_proto!("homedns.v1");
        }
    }
}

use proto::homedns::v1::home_dns_client::HomeDnsClient;
use proto::homedns::v1::{AddRecordRequest, Empty, RemoveRecordRequest};

// The name of the named pipe the gRPC server is listening on.
#[cfg(debug_assertions)]
const NAMED_PIPE_NAME: &str = r"\\.\\pipe\\home-dns-dev";
#[cfg(not(debug_assertions))]
const NAMED_PIPE_NAME: &str = r"\\.\\pipe\\home-dns";

type DnsClient = HomeDnsClient<tonic::transport::Channel>;

static CLIENT: OnceCell<DnsClient> = OnceCell::const_new();

#[pin_project]
struct SendablePipeClient {
    #[pin]
    inner: NamedPipeClient,
}

impl SendablePipeClient {
    fn new(inner: NamedPipeClient) -> Self {
        Self { inner }
    }
}

// Safety: Named pipe handles can be used from any thread; we wrap the client to satisfy tonic's Send bound.
unsafe impl Send for SendablePipeClient {}


impl AsyncRead for SendablePipeClient {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for SendablePipeClient {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// Establishes a connection to the gRPC service over a named pipe.
async fn get_client() -> Result<&'static DnsClient, String> {
    CLIENT
        .get_or_try_init(|| async {
            info!("Connecting to DNS gRPC service at {}", NAMED_PIPE_NAME);
            let channel = Endpoint::try_from("http://[::]:50052") // Dummy URI
                .unwrap()
                .connect_with_connector(service_fn(|_uri: Uri| async {
                    ClientOptions::new()
                        .open(NAMED_PIPE_NAME)
                        .map(SendablePipeClient::new)
                }))
                .await
                .map_err(|e| {
                    let msg = format!("Failed to connect to DNS service: {}. Is the service running?", e);
                    error!(error = %e, "DNS service connection failed");
                    msg
                })?;

            info!("Successfully connected to DNS gRPC service.");
            Ok(HomeDnsClient::new(channel))
        })
        .await
}

// Data structures for Tauri commands (serializable)
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

// Tauri command implementations

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_get_status() -> Result<StatusOut, String> {
    debug!("Requesting DNS status from service");
    let client = get_client().await?;
    let response = client
        .clone()
        .get_status(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let status = response.into_inner();
    debug!(state = %status.state, log_level = %status.log_level, "DNS status retrieved");
    Ok(StatusOut {
        state: status.state,
        log_level: status.log_level,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_stop_service() -> Result<AckOut, String> {
    debug!("Sending DNS stop service command");
    let client = get_client().await?;
    let response = client
        .clone()
        .stop_service(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "DNS stop service acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_reload_config() -> Result<AckOut, String> {
    debug!("Sending DNS reload configuration command");
    let client = get_client().await?;
    let response = client
        .clone()
        .reload_config(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "DNS reload configuration acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_list_records() -> Result<ListRecordsOut, String> {
    debug!("Requesting DNS record list");
    let client = get_client().await?;
    let response = client
        .clone()
        .list_records(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let list = response.into_inner();
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
    let client = get_client().await?;
    let req = AddRecordRequest {
        name,
        rrtype,
        value,
        ttl,
    };
    let response = client
        .clone()
        .add_record(req)
        .await
        .map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "DNS add record acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
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
    let client = get_client().await?;
    let req = RemoveRecordRequest {
        name,
        rrtype,
        value,
    };
    let response = client
        .clone()
        .remove_record(req)
        .await
        .map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "DNS remove record acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}
