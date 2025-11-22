use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use serde::Serialize;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::time::{sleep, Duration};
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;
use tracing::{debug, error, info, instrument, warn};

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
const PIPE_RELEASE: &str = r"\\.\pipe\home-dns";
const PIPE_DEV: &str = r"\\.\pipe\home-dns-dev";

const CONNECT_RETRIES: usize = 5;
const CONNECT_RETRY_DELAY_MS: u64 = 500;

type DnsClient = HomeDnsClient<tonic::transport::Channel>;

fn pipe_candidates() -> &'static [&'static str] {
    #[cfg(debug_assertions)]
    {
        &[PIPE_DEV, PIPE_RELEASE]
    }
    #[cfg(not(debug_assertions))]
    {
        &[PIPE_RELEASE, PIPE_DEV]
    }
}

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
async fn connect_client() -> Result<DnsClient, String> {
    let mut last_error = None;
    for attempt in 1..=CONNECT_RETRIES {
        for pipe in pipe_candidates() {
            info!(
                attempt,
                pipe = %pipe,
                "Attempting DNS gRPC connection via {}",
                pipe
            );
            let pipe_path = pipe.to_string();
            match Endpoint::try_from("http://[::]:50052")
                .unwrap()
                .connect_with_connector(service_fn(move |_uri: Uri| {
                    let path = pipe_path.clone();
                    async move {
                        ClientOptions::new()
                            .open(&path)
                            .map(SendablePipeClient::new)
                            .map(TokioIo::new)
                    }
                }))
                .await
            {
                Ok(channel) => {
                    info!(
                        attempt,
                        pipe = %pipe,
                        "Connected to DNS gRPC service via {}",
                        pipe
                    );
                    return Ok(HomeDnsClient::new(channel));
                }
                Err(err) => {
                    warn!(
                        attempt,
                        pipe = %pipe,
                        error = ?err,
                        "DNS pipe {} connection failed",
                        pipe
                    );
                    last_error = Some(err);
                }
            }
        }
        if attempt < CONNECT_RETRIES {
            let delay = CONNECT_RETRY_DELAY_MS * attempt as u64;
            info!(
                attempt,
                delay_ms = delay,
                "DNS gRPC connection failed, retrying after delay"
            );
            sleep(Duration::from_millis(delay)).await;
        }
    }

    let err = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "no pipe candidates available".to_string());
    let msg = format!(
        "Failed to connect to DNS service after {} attempt(s): {}. Is the service running?",
        CONNECT_RETRIES, err
    );
    error!("{}", msg);
    Err(msg)
}

// Data structures for Tauri commands (serializable)
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
pub struct RecordOut {
    pub name: String,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub ttl: u32,
}

#[derive(Serialize)]
pub struct ListRecordsOut {
    pub records: Vec<RecordOut>,
}

// Tauri command implementations

#[tauri::command]
#[instrument(level = "debug")]
pub async fn dns_get_status() -> Result<StatusOut, String> {
    debug!("Requesting DNS status from service");
    let mut client = connect_client().await?;
    let response = client
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
    let mut client = connect_client().await?;
    let response = client
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
    let mut client = connect_client().await?;
    let response = client
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
    let mut client = connect_client().await?;
    let response = client
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
    let mut client = connect_client().await?;
    let req = AddRecordRequest {
        name,
        rrtype,
        value,
        ttl,
    };
    let response = client.add_record(req).await.map_err(|e| e.to_string())?;
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
    let mut client = connect_client().await?;
    let req = RemoveRecordRequest {
        name,
        rrtype,
        value,
    };
    let response = client.remove_record(req).await.map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "DNS remove record acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}
