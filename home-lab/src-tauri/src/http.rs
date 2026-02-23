use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use serde::Serialize;
use std::{
    io,
    pin::Pin,
    process::Command,
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
    pub mod homehttp {
        pub mod v1 {
            tonic::include_proto!("homehttp.v1");
        }
    }
}

use proto::homehttp::v1::home_http_client::HomeHttpClient;
use proto::homehttp::v1::{AddRouteRequest, Empty, RemoveRouteRequest};

// The name of the named pipe the gRPC server is listening on.
const PIPE_RELEASE: &str = r"\\.\pipe\home-http";
const PIPE_DEV: &str = r"\\.\pipe\home-http-dev";

const SERVICE_NAME: &str = "HomeHttpService";
const LOOPBACK_ENDPOINT: &str = "http://[::]:50051";
const CONNECT_RETRIES: usize = 5;
const CONNECT_RETRY_DELAY_MS: u64 = 500;
const PIPE_OPEN_RETRIES: usize = 4;
const PIPE_OPEN_RETRY_DELAY_MS: u64 = 75;
const DIAG_MAX_FAILURES: usize = 8;

type HttpClient = HomeHttpClient<tonic::transport::Channel>;

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

// Safety: Windows named pipe handles are thread-safe to move across threads.
// Tokio doesn't mark `NamedPipeClient` as `Send`, so we wrap it to satisfy tonic's requirement.
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

async fn connect_client() -> Result<HttpClient, String> {
    let mut last_error = None::<String>;
    let mut sampled_failures: Vec<String> = Vec::new();
    for attempt in 1..=CONNECT_RETRIES {
        for pipe in pipe_candidates() {
            info!(
                attempt,
                pipe = %pipe,
                "Attempting HTTP gRPC connection via {}",
                pipe
            );
            let pipe_path = pipe.to_string();
            match Endpoint::try_from(LOOPBACK_ENDPOINT)
                .unwrap()
                .connect_with_connector(service_fn(move |_uri: Uri| {
                    let path = pipe_path.clone();
                    async move { open_pipe_with_retry(&path).await }
                }))
                .await
            {
                Ok(channel) => {
                    info!(
                        attempt,
                        pipe = %pipe,
                        "Connected to HTTP gRPC service via {}",
                        pipe
                    );
                    return Ok(HomeHttpClient::new(channel));
                }
                Err(err) => {
                    let err_dbg = format!("{err:?}");
                    warn!(
                        attempt,
                        pipe = %pipe,
                        error = %err_dbg,
                        "HTTP pipe {} connection failed",
                        pipe
                    );
                    if sampled_failures.len() < DIAG_MAX_FAILURES {
                        sampled_failures.push(format!(
                            "attempt={attempt}, pipe={pipe}, error={err_dbg}"
                        ));
                    }
                    last_error = Some(err_dbg);
                }
            }
        }
        if attempt < CONNECT_RETRIES {
            let delay = CONNECT_RETRY_DELAY_MS * attempt as u64;
            info!(
                attempt,
                delay_ms = delay,
                "HTTP gRPC connection failed, retrying after delay"
            );
            sleep(Duration::from_millis(delay)).await;
        }
    }

    let err = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "no pipe candidates available".to_string());
    let svc_state = service_state_snapshot(SERVICE_NAME);
    let home_pipes = list_home_pipes_snapshot();
    let sampled = if sampled_failures.is_empty() {
        "none".to_string()
    } else {
        sampled_failures.join(" | ")
    };
    let msg = format!(
        "Failed to connect to HTTP service after {CONNECT_RETRIES} attempt(s): {err}. \
service={SERVICE_NAME} state=[{svc_state}] visible_pipes=[{home_pipes}] sampled_failures=[{sampled}]",
    );
    error!("{}", msg);
    Err(msg)
}

async fn open_pipe_with_retry(path: &str) -> io::Result<TokioIo<SendablePipeClient>> {
    for open_attempt in 1..=PIPE_OPEN_RETRIES {
        match ClientOptions::new().open(path) {
            Ok(client) => return Ok(TokioIo::new(SendablePipeClient::new(client))),
            Err(err) => {
                let is_busy = matches!(err.raw_os_error(), Some(231));
                if is_busy && open_attempt < PIPE_OPEN_RETRIES {
                    let delay = PIPE_OPEN_RETRY_DELAY_MS * open_attempt as u64;
                    debug!(
                        path = %path,
                        open_attempt,
                        delay_ms = delay,
                        "HTTP pipe busy, retrying open"
                    );
                    sleep(Duration::from_millis(delay)).await;
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        "named pipe open retry exhausted",
    ))
}

fn service_state_snapshot(service_name: &str) -> String {
    match Command::new("sc").args(["query", service_name]).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let state = stdout
                .lines()
                .find(|line| line.contains("STATE"))
                .map(str::trim)
                .unwrap_or("STATE unavailable");
            if output.status.success() {
                state.to_string()
            } else {
                format!("{} (sc exit={:?})", state, output.status.code())
            }
        }
        Err(err) => format!("sc query failed: {err}"),
    }
}

fn list_home_pipes_snapshot() -> String {
    match std::fs::read_dir("\\\\.\\pipe\\") {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| name.starts_with("home-"))
                .collect();
            names.sort();
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(",")
            }
        }
        Err(err) => format!("unavailable: {err}"),
    }
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
pub struct RouteOut {
    pub host: String,
    pub port: u32,
}

#[derive(Serialize)]
pub struct ListRoutesOut {
    pub routes: Vec<RouteOut>,
}

// Tauri command implementations

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_get_status() -> Result<StatusOut, String> {
    debug!("Requesting HTTP service status");
    let mut client = connect_client().await?;
    let response = client
        .get_status(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let status = response.into_inner();
    debug!(state = %status.state, log_level = %status.log_level, "HTTP status retrieved");
    Ok(StatusOut {
        state: status.state,
        log_level: status.log_level,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_reload_config() -> Result<AckOut, String> {
    debug!("Sending HTTP reload configuration command");
    let mut client = connect_client().await?;
    let response = client
        .reload_config(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "HTTP reload configuration acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_stop_service() -> Result<AckOut, String> {
    debug!("Sending HTTP stop service command");
    let mut client = connect_client().await?;
    let response = client
        .stop_service(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "HTTP stop service acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_list_routes() -> Result<ListRoutesOut, String> {
    debug!("Requesting HTTP route list");
    let mut client = connect_client().await?;
    let response = client
        .list_routes(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let list = response.into_inner();
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
    let mut client = connect_client().await?;
    let req = AddRouteRequest { host, port };
    let response = client.add_route(req).await.map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "HTTP add route acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_remove_route(host: String) -> Result<AckOut, String> {
    debug!(host = %host, "Removing HTTP route via RPC");
    let mut client = connect_client().await?;
    let req = RemoveRouteRequest { host };
    let response = client.remove_route(req).await.map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "HTTP remove route acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}
