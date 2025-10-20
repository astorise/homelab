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
    pub mod homehttp {
        pub mod v1 {
            tonic::include_proto!("homehttp.v1");
        }
    }
}

use proto::homehttp::v1::home_http_client::HomeHttpClient;
use proto::homehttp::v1::{AddRouteRequest, Empty, RemoveRouteRequest};

// The name of the named pipe the gRPC server is listening on.
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-http";

type HttpClient = HomeHttpClient<tonic::transport::Channel>;

static CLIENT: OnceCell<HttpClient> = OnceCell::const_new();

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
async fn get_client() -> Result<&'static HttpClient, String> {
    CLIENT
        .get_or_try_init(|| async {
            info!("Connecting to HTTP gRPC service at {}", NAMED_PIPE_NAME);
            // A dummy URI is required by Endpoint, but it's not used for connection.
            let channel = Endpoint::try_from("http://[::]:50051")
                .unwrap()
                .connect_with_connector(service_fn(|_uri: Uri| async {
                    ClientOptions::new()
                        .open(NAMED_PIPE_NAME)
                        .map(SendablePipeClient::new)
                }))
                .await
                .map_err(|e| {
                    let msg = format!("Failed to connect to HTTP service: {}. Is the service running?", e);
                    error!(error = %e, "HTTP service connection failed");
                    msg
                })?;

            info!("Successfully connected to HTTP gRPC service.");
            Ok(HomeHttpClient::new(channel))
        })
        .await
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
    let client = get_client().await?;
    let response = client
        .clone()
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
    let client = get_client().await?;
    let response = client
        .clone()
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
    let client = get_client().await?;
    let response = client
        .clone()
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
    let client = get_client().await?;
    let response = client
        .clone()
        .list_routes(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let list = response.into_inner();
    let total = list.routes.len();
    let routes = list
        .routes
        .into_iter()
        .map(|r| RouteOut { host: r.host, port: r.port })
        .collect();
    info!(total, "HTTP route list retrieved");
    Ok(ListRoutesOut { routes })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn http_add_route(host: String, port: u32) -> Result<AckOut, String> {
    debug!(host = %host, port, "Adding HTTP route via RPC");
    let client = get_client().await?;
    let req = AddRouteRequest { host, port };
    let response = client
        .clone()
        .add_route(req)
        .await
        .map_err(|e| e.to_string())?;
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
    let client = get_client().await?;
    let req = RemoveRouteRequest { host };
    let response = client
        .clone()
        .remove_route(req)
        .await
        .map_err(|e| e.to_string())?;
    let ack = response.into_inner();
    info!(ok = ack.ok, message = %ack.message, "HTTP remove route acknowledged");
    Ok(AckOut {
        ok: ack.ok,
        message: ack.message,
    })
}
