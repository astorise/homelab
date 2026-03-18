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

mod proto {
    pub mod homes3 {
        pub mod v1 {
            tonic::include_proto!("homes3.v1");
        }
    }
}

use proto::homes3::v1::home_s3_client::HomeS3Client;
use proto::homes3::v1::{
    Acknowledge, CreateBucketRequest, DeleteBucketRequest, Empty, ListBucketObjectsRequest,
    UpdateBucketRequest,
};

const PIPE_RELEASE: &str = r"\\.\pipe\home-s3";
const PIPE_DEV: &str = r"\\.\pipe\home-s3-dev";
const SERVICE_NAME: &str = "HomeS3Service";
const LOOPBACK_ENDPOINT: &str = "http://[::]:50054";
const CONNECT_RETRIES: usize = 5;
const CONNECT_RETRY_DELAY_MS: u64 = 500;
const PIPE_OPEN_RETRIES: usize = 4;
const PIPE_OPEN_RETRY_DELAY_MS: u64 = 75;
const DIAG_MAX_FAILURES: usize = 8;

type S3Client = HomeS3Client<tonic::transport::Channel>;

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

async fn connect_client() -> Result<S3Client, String> {
    let mut last_error = None::<String>;
    let mut sampled_failures = Vec::new();

    for attempt in 1..=CONNECT_RETRIES {
        for pipe in pipe_candidates() {
            info!(attempt, pipe = %pipe, "Attempting S3 gRPC connection via {}", pipe);
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
                    info!(attempt, pipe = %pipe, "Connected to S3 gRPC service via {}", pipe);
                    return Ok(HomeS3Client::new(channel));
                }
                Err(err) => {
                    let err_dbg = format!("{err:?}");
                    warn!(
                        attempt,
                        pipe = %pipe,
                        error = %err_dbg,
                        "S3 pipe {} connection failed",
                        pipe
                    );
                    if sampled_failures.len() < DIAG_MAX_FAILURES {
                        sampled_failures
                            .push(format!("attempt={attempt}, pipe={pipe}, error={err_dbg}"));
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
                "S3 gRPC connection failed, retrying after delay"
            );
            sleep(Duration::from_millis(delay)).await;
        }
    }

    let err = last_error.unwrap_or_else(|| "no pipe candidates available".to_string());
    let svc_state = service_state_snapshot(SERVICE_NAME);
    let home_pipes = list_home_pipes_snapshot();
    let sampled = if sampled_failures.is_empty() {
        "none".to_string()
    } else {
        sampled_failures.join(" | ")
    };
    let msg = format!(
        "Failed to connect to S3 service after {CONNECT_RETRIES} attempt(s): {err}. service={SERVICE_NAME} state=[{svc_state}] visible_pipes=[{home_pipes}] sampled_failures=[{sampled}]",
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
                        "S3 pipe busy, retrying open"
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

#[derive(Serialize)]
pub struct AckOut {
    pub ok: bool,
    pub message: String,
}

#[derive(Serialize)]
pub struct StatusOut {
    pub state: String,
    pub log_level: String,
    pub endpoint: String,
    pub region: String,
    pub access_key_id: String,
    pub force_path_style: bool,
}

#[derive(Serialize)]
pub struct BucketOut {
    pub name: String,
    pub created_at: String,
    pub source_path: String,
}

#[derive(Serialize)]
pub struct ListBucketsOut {
    pub buckets: Vec<BucketOut>,
}

#[derive(Serialize)]
pub struct BucketObjectOut {
    pub key: String,
    pub size: i64,
    pub last_modified: String,
}

#[derive(Serialize)]
pub struct ListBucketObjectsOut {
    pub objects: Vec<BucketObjectOut>,
}

impl From<Acknowledge> for AckOut {
    fn from(value: Acknowledge) -> Self {
        Self {
            ok: value.ok,
            message: value.message,
        }
    }
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn s3_get_status() -> Result<StatusOut, String> {
    let mut client = connect_client().await?;
    let response = client
        .get_status(Empty {})
        .await
        .map_err(|err| err.to_string())?;
    let status = response.into_inner();
    Ok(StatusOut {
        state: status.state,
        log_level: status.log_level,
        endpoint: status.endpoint,
        region: status.region,
        access_key_id: status.access_key_id,
        force_path_style: status.force_path_style,
    })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn s3_reload_config() -> Result<AckOut, String> {
    let mut client = connect_client().await?;
    let response = client
        .reload_config(Empty {})
        .await
        .map_err(|err| err.to_string())?;
    Ok(response.into_inner().into())
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn s3_stop_service() -> Result<AckOut, String> {
    let mut client = connect_client().await?;
    let response = client
        .stop_service(Empty {})
        .await
        .map_err(|err| err.to_string())?;
    Ok(response.into_inner().into())
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn s3_list_buckets() -> Result<ListBucketsOut, String> {
    let mut client = connect_client().await?;
    let response = client
        .list_buckets(Empty {})
        .await
        .map_err(|err| err.to_string())?;
    let list = response.into_inner();
    let buckets = list
        .buckets
        .into_iter()
        .map(|bucket| BucketOut {
            name: bucket.name,
            created_at: bucket.created_at,
            source_path: bucket.source_path,
        })
        .collect();
    Ok(ListBucketsOut { buckets })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn s3_list_bucket_objects(bucket_name: String) -> Result<ListBucketObjectsOut, String> {
    let mut client = connect_client().await?;
    let response = client
        .list_bucket_objects(ListBucketObjectsRequest { bucket_name })
        .await
        .map_err(|err| err.to_string())?;
    let list = response.into_inner();
    let objects = list
        .objects
        .into_iter()
        .map(|object| BucketObjectOut {
            key: object.key,
            size: object.size,
            last_modified: object.last_modified,
        })
        .collect();
    Ok(ListBucketObjectsOut { objects })
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn s3_create_bucket(
    bucket_name: String,
    source_path: Option<String>,
) -> Result<AckOut, String> {
    let mut client = connect_client().await?;
    let response = client
        .create_bucket(CreateBucketRequest {
            name: bucket_name,
            source_path: source_path.unwrap_or_default(),
        })
        .await
        .map_err(|err| err.to_string())?;
    Ok(response.into_inner().into())
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn s3_update_bucket(
    current_bucket_name: String,
    new_bucket_name: Option<String>,
    source_path: Option<String>,
    replace_objects: bool,
) -> Result<AckOut, String> {
    let mut client = connect_client().await?;
    let response = client
        .update_bucket(UpdateBucketRequest {
            current_name: current_bucket_name,
            new_name: new_bucket_name.unwrap_or_default(),
            source_path: source_path.unwrap_or_default(),
            replace_objects,
        })
        .await
        .map_err(|err| err.to_string())?;
    Ok(response.into_inner().into())
}

#[tauri::command]
#[instrument(level = "debug")]
pub async fn s3_delete_bucket(bucket_name: String, delete_objects: bool) -> Result<AckOut, String> {
    let mut client = connect_client().await?;
    let response = client
        .delete_bucket(DeleteBucketRequest {
            name: bucket_name,
            delete_objects,
        })
        .await
        .map_err(|err| err.to_string())?;
    Ok(response.into_inner().into())
}
