use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
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

mod proto {
    pub mod homeoidc {
        pub mod v1 {
            tonic::include_proto!("homeoidc.v1");
        }
    }
}

use proto::homeoidc::v1::home_oidc_client::HomeOidcClient;
use proto::homeoidc::v1::{
    Acknowledge, Empty, ListClientsResponse, RegisterClientRequest, RemoveClientRequest,
    StatusResponse,
};

const PIPE_RELEASE: &str = r"\\.\pipe\home-oidc";
const PIPE_DEV: &str = r"\\.\pipe\home-oidc-dev";

const CONNECT_RETRIES: usize = 5;
const CONNECT_RETRY_DELAY_MS: u64 = 500;

type OidcClient = HomeOidcClient<tonic::transport::Channel>;

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

async fn connect_client() -> Result<OidcClient, String> {
    let mut last_error = None;
    for attempt in 1..=CONNECT_RETRIES {
        for pipe in pipe_candidates() {
            info!(
                attempt,
                pipe = %pipe,
                "Attempting OIDC gRPC connection via {}",
                pipe
            );
            let pipe_path = pipe.to_string();
            match Endpoint::try_from("http://[::]:50053")
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
                        "Connected to OIDC gRPC service via {}",
                        pipe
                    );
                    return Ok(HomeOidcClient::new(channel));
                }
                Err(err) => {
                    warn!(
                        attempt,
                        pipe = %pipe,
                        error = ?err,
                        "OIDC pipe {} connection failed",
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
                "OIDC gRPC connection failed, retrying after delay"
            );
            sleep(Duration::from_millis(delay)).await;
        }
    }

    let err = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "no pipe candidates available".to_string());
    let msg = format!(
        "Failed to connect to OIDC service after {} attempt(s): {}. Is the service running?",
        CONNECT_RETRIES, err
    );
    error!("{}", msg);
    Err(msg)
}

#[derive(Serialize)]
pub struct StatusOut {
    pub state: String,
    pub log_level: String,
    pub issuer: String,
    pub token_endpoint: String,
}

#[derive(Serialize)]
pub struct PasswordUserOut {
    pub username: String,
    pub subject: String,
    pub scopes: Vec<String>,
}

#[derive(Serialize)]
pub struct ClientOut {
    pub client_id: String,
    pub subject: String,
    pub allowed_scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub password_users: Vec<PasswordUserOut>,
    pub auth_method: String,
    pub public_key_pem: String,
}

#[derive(Serialize)]
pub struct ListClientsOut {
    pub clients: Vec<ClientOut>,
}

#[derive(Serialize)]
pub struct AckOut {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterClientIn {
    pub client_id: String,
    pub subject: Option<String>,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    pub public_key_pem: String,
    #[serde(default)]
    pub auth_method: Option<String>,
}

fn map_clients(response: ListClientsResponse) -> Vec<ClientOut> {
    response
        .clients
        .into_iter()
        .map(|client| {
            let password_users = client
                .password_users
                .into_iter()
                .map(|user| PasswordUserOut {
                    username: user.username,
                    subject: user.subject,
                    scopes: user.scopes,
                })
                .collect();
            ClientOut {
                client_id: client.client_id,
                subject: client.subject,
                allowed_scopes: client.allowed_scopes,
                audiences: client.audiences,
                password_users,
                auth_method: client.auth_method,
                public_key_pem: client.public_key_pem,
            }
        })
        .collect()
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

fn normalize_auth_method(method: Option<String>) -> String {
    method
        .unwrap_or_else(|| "private_key_jwt".to_string())
        .trim()
        .to_lowercase()
}

fn build_register_request(mut input: RegisterClientIn) -> RegisterClientRequest {
    input.client_id = input.client_id.trim().to_string();
    let subject = input
        .subject
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| input.client_id.clone());
    RegisterClientRequest {
        client_id: input.client_id,
        subject,
        allowed_scopes: normalize_list(input.allowed_scopes),
        audiences: normalize_list(input.audiences),
        public_key_pem: input.public_key_pem.trim().to_string(),
        auth_method: normalize_auth_method(input.auth_method),
    }
}

impl From<Acknowledge> for AckOut {
    fn from(value: Acknowledge) -> Self {
        AckOut {
            ok: value.ok,
            message: value.message,
        }
    }
}

pub async fn register_client_config(payload: RegisterClientIn) -> Result<AckOut, String> {
    let mut client = connect_client().await?;
    let request = build_register_request(payload);
    let response = client
        .register_client(request)
        .await
        .map_err(|e| e.to_string())?;
    Ok(response.into_inner().into())
}

pub async fn remove_client_config(client_id: &str) -> Result<AckOut, String> {
    let trimmed = client_id.trim();
    if trimmed.is_empty() {
        return Err("client_id est requis.".into());
    }
    let mut client = connect_client().await?;
    let response = client
        .remove_client(RemoveClientRequest {
            client_id: trimmed.to_string(),
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(response.into_inner().into())
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn oidc_get_status() -> Result<StatusOut, String> {
    debug!("Requesting OIDC service status");
    let mut client = connect_client().await?;
    let response = client
        .get_status(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let StatusResponse {
        state,
        log_level,
        issuer,
        token_endpoint,
    } = response.into_inner();
    Ok(StatusOut {
        state,
        log_level,
        issuer,
        token_endpoint,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn oidc_list_clients() -> Result<ListClientsOut, String> {
    debug!("Requesting OIDC client list");
    let mut client = connect_client().await?;
    let response = client
        .list_clients(Empty {})
        .await
        .map_err(|e| e.to_string())?;
    let list = response.into_inner();
    let total = list.clients.len();
    let clients = map_clients(list);
    info!(total, "OIDC client list retrieved");
    Ok(ListClientsOut { clients })
}

#[tauri::command]
#[instrument(level = "debug", skip(payload))]
pub async fn oidc_register_client(payload: RegisterClientIn) -> Result<AckOut, String> {
    register_client_config(payload).await
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn oidc_remove_client(client_id: String) -> Result<AckOut, String> {
    remove_client_config(&client_id).await
}
