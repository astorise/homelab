#![cfg_attr(not(windows), allow(dead_code))]
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use anyhow::{anyhow, bail, Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_s3::{
    config::{Credentials, Region},
    primitives::ByteStream,
    types::{Delete, ObjectIdentifier},
    Client,
};
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
use log::{debug, error, info, warn, LevelFilter};
use pin_project::pin_project;
use rustfs::{CancellationToken as RustfsCancellationToken, Config as RustfsConfig};
use serde::{Deserialize, Serialize};
use std::ffi::{c_void, OsString};
use std::fs as std_fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::{server::Connected, Server};
use tonic::{Request as GrpcRequest, Response as GrpcResponse, Status};
use walkdir::WalkDir;
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_manager::*};

#[pin_project]
struct PipeConnection {
    #[pin]
    inner: NamedPipeServer,
}

impl PipeConnection {
    fn new(inner: NamedPipeServer) -> Self {
        Self { inner }
    }
}

unsafe impl Send for PipeConnection {}

impl Connected for PipeConnection {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for PipeConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for PipeConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

const BUILD_GIT_SHA: &str = env!("BUILD_GIT_SHA");
const BUILD_GIT_TAG: &str = env!("BUILD_GIT_TAG");
const BUILD_TIME: &str = env!("BUILD_TIME");

mod proto {
    pub mod homes3 {
        pub mod v1 {
            tonic::include_proto!("homes3.v1");
        }
    }
}

use proto::homes3::v1::home_s3_server::{HomeS3, HomeS3Server};
use proto::homes3::v1::{
    Acknowledge, CreateBucketRequest, DeleteBucketRequest, Empty, ListBucketObjectsRequest,
    ListBucketObjectsResponse, ListBucketsResponse, StatusResponse, UpdateBucketRequest,
};

const SERVICE_NAME: &str = "HomeS3Service";
const SERVICE_DISPLAY_NAME: &str = "Home S3 Service";
const SERVICE_DESCRIPTION: &str =
    "Local RustFS-compatible S3 bucket manager for Windows filesystem sources";
#[cfg(debug_assertions)]
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-s3-dev";
#[cfg(not(debug_assertions))]
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-s3";

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ServiceConfig {
    #[serde(default = "default_endpoint")]
    endpoint: String,
    #[serde(default = "default_region")]
    region: String,
    #[serde(default = "default_access_key_id")]
    access_key_id: String,
    #[serde(default = "default_secret_access_key")]
    secret_access_key: String,
    #[serde(default = "default_force_path_style")]
    force_path_style: bool,
    #[serde(default = "default_data_dir")]
    data_dir: String,
    #[serde(default)]
    log_level: Option<String>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            region: default_region(),
            access_key_id: default_access_key_id(),
            secret_access_key: default_secret_access_key(),
            force_path_style: default_force_path_style(),
            data_dir: default_data_dir(),
            log_level: Some(default_level_str().to_string()),
        }
    }
}

#[derive(Debug, Clone)]
enum EmbeddedRustfsState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Error(String),
}

impl EmbeddedRustfsState {
    fn as_status_str(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Error(_) => "error",
        }
    }

    fn error_message(&self) -> Option<&str> {
        match self {
            Self::Error(message) => Some(message),
            _ => None,
        }
    }
}

#[derive(Default)]
struct EmbeddedRustfsRuntime {
    state: Option<EmbeddedRustfsState>,
    shutdown: Option<RustfsCancellationToken>,
    task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Clone)]
struct SharedState {
    cfg: Arc<Mutex<ServiceConfig>>,
    embedded: Arc<Mutex<EmbeddedRustfsRuntime>>,
    stopping: Arc<AtomicBool>,
}

struct HomeS3GrpcService {
    shared: SharedState,
}

fn program_data_dir() -> PathBuf {
    PathBuf::from(r"C:\\ProgramData\\home-s3")
}

fn logs_dir() -> PathBuf {
    program_data_dir().join("logs")
}

fn config_path() -> PathBuf {
    program_data_dir().join("s3-config.json")
}

fn bucket_metadata_path() -> PathBuf {
    program_data_dir().join("bucket-metadata.json")
}

fn default_data_dir() -> String {
    program_data_dir().join("data").display().to_string()
}

fn default_endpoint() -> String {
    "http://127.0.0.1:9000".to_string()
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_access_key_id() -> String {
    "rustfsadmin".to_string()
}

fn default_secret_access_key() -> String {
    "rustfssecret".to_string()
}

fn default_force_path_style() -> bool {
    true
}

fn default_level_filter() -> LevelFilter {
    if cfg!(debug_assertions) {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    }
}

fn default_level_str() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    }
}

fn level_filter_to_str(level: LevelFilter) -> &'static str {
    match level {
        LevelFilter::Off => "off",
        LevelFilter::Error => "error",
        LevelFilter::Warn => "warn",
        LevelFilter::Info => "info",
        LevelFilter::Debug => "debug",
        LevelFilter::Trace => "trace",
    }
}

fn level_from_cfg(cfg: &ServiceConfig) -> LevelFilter {
    cfg.log_level
        .as_deref()
        .map(|value| match value.trim().to_ascii_lowercase().as_str() {
            "off" => LevelFilter::Off,
            "error" => LevelFilter::Error,
            "warn" | "warning" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => default_level_filter(),
        })
        .unwrap_or_else(default_level_filter)
}

fn is_endpoint_unreachable(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("dispatch failure")
        || lower.contains("connect error")
        || lower.contains("connection refused")
        || lower.contains("tcp connect error")
        || lower.contains("timed out")
        || lower.contains("dns error")
}

fn internal_status(operation: &str, err: anyhow::Error) -> Status {
    let message = format!("{operation} failed: {err:#}");
    error!("{message}");
    Status::internal(message)
}

fn endpoint_status(operation: &str, endpoint: &str, err: anyhow::Error) -> Status {
    let detail = format!("{err:#}");
    let message = if is_endpoint_unreachable(&detail) {
        format!(
            "{operation} failed: the embedded RustFS instance bound to {endpoint} is unavailable. Check the home-s3 logs or update {}. details: {detail}",
            config_path().display()
        )
    } else {
        format!("{operation} failed against {endpoint}: {detail}")
    };
    error!("{message}");
    Status::internal(message)
}

fn build_label() -> String {
    let raw = if BUILD_GIT_TAG.trim().is_empty() || BUILD_GIT_TAG == "unknown" {
        BUILD_GIT_SHA
    } else {
        BUILD_GIT_TAG
    };
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.trim_matches('_').is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn build_log_basename(prefix: &str) -> String {
    format!("{prefix}_{}", build_label())
}

fn ensure_layout() -> Result<()> {
    std_fs::create_dir_all(program_data_dir()).context("create ProgramData directory")?;
    std_fs::create_dir_all(logs_dir()).context("create logs directory")?;
    Ok(())
}

fn ensure_data_dir(path: &Path) -> Result<()> {
    std_fs::create_dir_all(path)
        .with_context(|| format!("create embedded RustFS data directory {}", path.display()))?;
    Ok(())
}

fn load_config_or_init() -> Result<ServiceConfig> {
    ensure_layout()?;
    let path = config_path();
    if !path.exists() {
        let cfg = ServiceConfig::default();
        let json = serde_json::to_string_pretty(&cfg)?;
        std_fs::write(&path, format!("{json}\n")).context("write default S3 config")?;
        return Ok(cfg);
    }
    let raw = std_fs::read_to_string(&path).context("read S3 config")?;
    let cfg: ServiceConfig = serde_json::from_str(&raw).context("parse S3 config")?;
    ensure_data_dir(Path::new(&cfg.data_dir))?;
    Ok(cfg)
}

fn load_bucket_metadata() -> Result<std::collections::BTreeMap<String, String>> {
    ensure_layout()?;
    let path = bucket_metadata_path();
    if !path.exists() {
        return Ok(std::collections::BTreeMap::new());
    }
    let raw = std_fs::read_to_string(&path).context("read bucket metadata")?;
    let metadata = serde_json::from_str(&raw).context("parse bucket metadata")?;
    Ok(metadata)
}

fn save_bucket_metadata(metadata: &std::collections::BTreeMap<String, String>) -> Result<()> {
    ensure_layout()?;
    let path = bucket_metadata_path();
    let json = serde_json::to_string_pretty(metadata)?;
    std_fs::write(&path, format!("{json}\n")).context("write bucket metadata")?;
    Ok(())
}

fn get_bucket_source_path(bucket: &str) -> Result<Option<String>> {
    let metadata = load_bucket_metadata()?;
    Ok(metadata.get(bucket).cloned())
}

fn set_bucket_source_path(bucket: &str, source_path: Option<&Path>) -> Result<()> {
    let mut metadata = load_bucket_metadata()?;
    match source_path {
        Some(path) => {
            metadata.insert(bucket.to_string(), path.display().to_string());
        }
        None => {
            metadata.remove(bucket);
        }
    }
    save_bucket_metadata(&metadata)
}

fn rename_bucket_source_path(current_bucket: &str, new_bucket: &str) -> Result<()> {
    if current_bucket == new_bucket {
        return Ok(());
    }
    let mut metadata = load_bucket_metadata()?;
    if let Some(source_path) = metadata.remove(current_bucket) {
        metadata.insert(new_bucket.to_string(), source_path);
    }
    save_bucket_metadata(&metadata)
}

fn init_logger(level: LevelFilter) -> Result<()> {
    ensure_layout()?;
    Logger::try_with_str(level_filter_to_str(level))?
        .log_to_file(
            FileSpec::default()
                .directory(logs_dir())
                .basename(build_log_basename("home-s3")),
        )
        .duplicate_to_stderr(Duplicate::Warn)
        .rotate(
            Criterion::Age(Age::Day),
            Naming::Numbers,
            Cleanup::KeepLogFiles(10),
        )
        .use_utc()
        .start()
        .context("start logger")?;
    Ok(())
}

async fn current_config(shared: &SharedState) -> ServiceConfig {
    shared.cfg.lock().await.clone()
}

async fn reload_config(shared: &SharedState) -> Result<ServiceConfig> {
    let cfg = load_config_or_init()?;
    let active = current_config(shared).await;
    if cfg != active {
        warn!(
            "home-s3 config file changed, but embedded RustFS uses the startup configuration until the service restarts"
        );
    }
    Ok(cfg)
}

async fn current_embedded_state(shared: &SharedState) -> EmbeddedRustfsState {
    shared
        .embedded
        .lock()
        .await
        .state
        .clone()
        .unwrap_or(EmbeddedRustfsState::Stopped)
}

fn rustfs_address_from_endpoint(endpoint: &str) -> Result<String> {
    let trimmed = endpoint.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let without_path = without_scheme.trim_end_matches('/');
    if without_path.is_empty() {
        bail!("endpoint must not be empty");
    }
    if without_path.contains('/') || without_path.contains('?') || without_path.contains('#') {
        bail!("endpoint must contain only scheme, host and port: {endpoint}");
    }
    if !without_path.contains(':') {
        bail!("endpoint must include an explicit host and port: {endpoint}");
    }
    Ok(without_path.to_string())
}

fn build_embedded_rustfs_config(cfg: &ServiceConfig) -> Result<RustfsConfig> {
    let data_dir = PathBuf::from(&cfg.data_dir);
    ensure_data_dir(&data_dir)?;
    Ok(RustfsConfig {
        volumes: vec![data_dir.display().to_string()],
        address: rustfs_address_from_endpoint(&cfg.endpoint)?,
        server_domains: Vec::new(),
        access_key: cfg.access_key_id.clone(),
        secret_key: cfg.secret_access_key.clone(),
        console_enable: false,
        console_address: String::new(),
        obs_endpoint: String::new(),
        tls_path: None,
        license: None,
        region: Some(cfg.region.clone()),
        kms_enable: false,
        kms_backend: "local".to_string(),
        kms_key_dir: None,
        kms_vault_address: None,
        kms_vault_token: None,
        kms_default_key_id: None,
        buffer_profile_disable: false,
        buffer_profile: "GeneralPurpose".to_string(),
    })
}

async fn wait_for_embedded_rustfs(shared: &SharedState, cfg: &ServiceConfig) -> Result<()> {
    let client = make_s3_client(cfg).await?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_error = None::<String>;

    loop {
        let state = current_embedded_state(shared).await;
        if let Some(message) = state.error_message() {
            bail!("embedded RustFS failed to start: {message}");
        }

        match client.list_buckets().send().await {
            Ok(_) => return Ok(()),
            Err(err) => {
                last_error = Some(format!("{err:#}"));
            }
        }

        if Instant::now() >= deadline {
            let detail = last_error.unwrap_or_else(|| "no response received".to_string());
            bail!(
                "timed out waiting for embedded RustFS at {} to become ready: {detail}",
                cfg.endpoint
            );
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn start_embedded_rustfs(shared: &SharedState) -> Result<()> {
    let cfg = current_config(shared).await;
    let rustfs_cfg = build_embedded_rustfs_config(&cfg)?;
    let shutdown = RustfsCancellationToken::new();

    {
        let mut embedded = shared.embedded.lock().await;
        if embedded.task.is_some() {
            bail!("embedded RustFS is already running");
        }
        embedded.state = Some(EmbeddedRustfsState::Starting);
        embedded.shutdown = Some(shutdown.clone());
    }

    let embedded_runtime = shared.embedded.clone();
    let service_stopping = shared.stopping.clone();
    let task = tokio::spawn(async move {
        let result = rustfs::run_embedded(rustfs_cfg, shutdown.clone()).await;
        let mut embedded = embedded_runtime.lock().await;
        match result {
            Ok(()) => {
                if service_stopping.load(Ordering::SeqCst) {
                    embedded.state = Some(EmbeddedRustfsState::Stopped);
                } else if !matches!(embedded.state, Some(EmbeddedRustfsState::Error(_))) {
                    embedded.state = Some(EmbeddedRustfsState::Stopped);
                }
            }
            Err(err) => {
                let message = format!("{err:#}");
                error!("embedded RustFS stopped with an error: {message}");
                embedded.state = Some(EmbeddedRustfsState::Error(message));
            }
        }
        embedded.shutdown = None;
    });

    {
        let mut embedded = shared.embedded.lock().await;
        embedded.task = Some(task);
    }

    if let Err(err) = wait_for_embedded_rustfs(shared, &cfg).await {
        let _ = stop_embedded_rustfs(shared).await;
        return Err(err);
    }

    let mut embedded = shared.embedded.lock().await;
    if !matches!(embedded.state, Some(EmbeddedRustfsState::Error(_))) {
        embedded.state = Some(EmbeddedRustfsState::Running);
    }

    info!(
        "embedded RustFS ready on {} with data directory {}",
        cfg.endpoint, cfg.data_dir
    );
    Ok(())
}

async fn stop_embedded_rustfs(shared: &SharedState) -> Result<()> {
    let task = {
        let mut embedded = shared.embedded.lock().await;
        if embedded.task.is_none() {
            embedded.state = Some(EmbeddedRustfsState::Stopped);
            embedded.shutdown = None;
            return Ok(());
        }
        embedded.state = Some(EmbeddedRustfsState::Stopping);
        if let Some(shutdown) = embedded.shutdown.take() {
            shutdown.cancel();
        }
        embedded.task.take()
    };

    if let Some(task) = task {
        if let Err(err) = task.await {
            error!("failed to join embedded RustFS task: {err}");
        }
    }

    let mut embedded = shared.embedded.lock().await;
    embedded.state = Some(EmbeddedRustfsState::Stopped);
    embedded.shutdown = None;
    Ok(())
}

async fn make_s3_client(cfg: &ServiceConfig) -> Result<Client> {
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(cfg.region.clone()))
        .credentials_provider(Credentials::new(
            cfg.access_key_id.clone(),
            cfg.secret_access_key.clone(),
            None,
            None,
            "home-s3",
        ))
        .endpoint_url(cfg.endpoint.clone())
        .load()
        .await;

    let s3_config = aws_sdk_s3::config::Builder::from(&shared_config)
        .force_path_style(cfg.force_path_style)
        .build();
    Ok(Client::from_conf(s3_config))
}

fn validate_bucket_name(name: &str) -> Result<()> {
    if name.len() < 3 || name.len() > 63 {
        bail!("bucket name must be between 3 and 63 characters");
    }
    if name.starts_with('.') || name.ends_with('.') || name.starts_with('-') || name.ends_with('-')
    {
        bail!("bucket name must start and end with an alphanumeric character");
    }
    if name.contains("..") {
        bail!("bucket name must not contain consecutive dots");
    }
    if name.bytes().any(|byte| {
        !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-')
    }) {
        bail!("bucket name must contain only lowercase letters, digits, dots or hyphens");
    }
    if looks_like_ipv4(name) {
        bail!("bucket name must not be formatted like an IPv4 address");
    }
    Ok(())
}

fn looks_like_ipv4(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

fn normalize_source_path(input: &str) -> Result<Option<PathBuf>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(trimmed);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolve source path {}", path.display()))?;
    if !canonical.exists() {
        bail!("source path does not exist: {}", canonical.display());
    }
    Ok(Some(canonical))
}

fn object_key_from_relative(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().replace('\\', "/")),
            Component::CurDir => {}
            _ => bail!("unsupported path component in {}", path.display()),
        }
    }
    if parts.is_empty() {
        bail!("unable to derive an object key from {}", path.display());
    }
    Ok(parts.join("/"))
}

async fn upload_file(
    client: &Client,
    bucket: &str,
    source_file: &Path,
    object_key: &str,
) -> Result<()> {
    let body = ByteStream::from(
        fs::read(source_file)
            .await
            .with_context(|| format!("read {}", source_file.display()))?,
    );
    client
        .put_object()
        .bucket(bucket)
        .key(object_key)
        .body(body)
        .send()
        .await
        .with_context(|| {
            format!(
                "upload {} as s3://{bucket}/{object_key}",
                source_file.display()
            )
        })?;
    Ok(())
}

async fn import_source_path(client: &Client, bucket: &str, source_path: &Path) -> Result<usize> {
    if source_path.is_file() {
        let object_key = object_key_from_relative(Path::new(
            source_path
                .file_name()
                .ok_or_else(|| anyhow!("source file has no file name"))?,
        ))?;
        upload_file(client, bucket, source_path, &object_key).await?;
        return Ok(1);
    }

    if !source_path.is_dir() {
        bail!("source path is neither a file nor a directory");
    }

    let mut uploaded = 0usize;
    for entry in WalkDir::new(source_path)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(source_path)
            .with_context(|| format!("strip prefix {}", source_path.display()))?;
        let object_key = object_key_from_relative(relative)?;
        upload_file(client, bucket, entry.path(), &object_key).await?;
        uploaded += 1;
    }
    Ok(uploaded)
}

async fn bucket_exists(client: &Client, bucket: &str) -> bool {
    client.head_bucket().bucket(bucket).send().await.is_ok()
}

async fn create_bucket_and_import(
    client: &Client,
    bucket: &str,
    source_path: Option<&Path>,
) -> Result<(bool, usize)> {
    let existed = bucket_exists(client, bucket).await;
    if !existed {
        client
            .create_bucket()
            .bucket(bucket)
            .send()
            .await
            .with_context(|| format!("create bucket {bucket}"))?;
    }
    let imported = if let Some(path) = source_path {
        import_source_path(client, bucket, path).await?
    } else {
        0
    };
    Ok((!existed, imported))
}

#[derive(Debug, Default)]
struct UpdateBucketOutcome {
    renamed: bool,
    copied_objects: usize,
    imported_files: usize,
    cleared_objects: usize,
    deleted_source_objects: usize,
}

async fn list_bucket_object_keys(client: &Client, bucket: &str) -> Result<Vec<String>> {
    let mut continuation_token = None::<String>;
    let mut keys = Vec::new();

    loop {
        let mut request = client.list_objects_v2().bucket(bucket);
        if let Some(token) = &continuation_token {
            request = request.continuation_token(token);
        }
        let output = request
            .send()
            .await
            .with_context(|| format!("list objects in bucket {bucket}"))?;

        keys.extend(
            output
                .contents()
                .iter()
                .filter_map(|object| object.key().map(ToOwned::to_owned)),
        );

        continuation_token = output.next_continuation_token().map(ToOwned::to_owned);
        if continuation_token.is_none() {
            break;
        }
    }

    Ok(keys)
}

async fn copy_bucket_contents(
    client: &Client,
    source_bucket: &str,
    target_bucket: &str,
) -> Result<usize> {
    let keys = list_bucket_object_keys(client, source_bucket).await?;
    for key in &keys {
        let object = client
            .get_object()
            .bucket(source_bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("download s3://{source_bucket}/{key}"))?;
        let body = object
            .body
            .collect()
            .await
            .with_context(|| format!("read object body s3://{source_bucket}/{key}"))?
            .into_bytes()
            .to_vec();
        client
            .put_object()
            .bucket(target_bucket)
            .key(key)
            .body(ByteStream::from(body))
            .send()
            .await
            .with_context(|| {
                format!("copy s3://{source_bucket}/{key} to s3://{target_bucket}/{key}")
            })?;
    }
    Ok(keys.len())
}

async fn update_bucket(
    client: &Client,
    current_bucket: &str,
    new_bucket: &str,
    source_path: Option<&Path>,
    replace_objects: bool,
) -> Result<UpdateBucketOutcome> {
    if replace_objects && source_path.is_none() {
        bail!("replace_objects requires a source_path");
    }
    if !bucket_exists(client, current_bucket).await {
        bail!("bucket {current_bucket} does not exist");
    }

    let mut outcome = UpdateBucketOutcome {
        renamed: current_bucket != new_bucket,
        ..UpdateBucketOutcome::default()
    };

    if outcome.renamed {
        let target_exists = bucket_exists(client, new_bucket).await;
        if target_exists && !replace_objects {
            bail!("bucket {new_bucket} already exists");
        }
        if !target_exists {
            client
                .create_bucket()
                .bucket(new_bucket)
                .send()
                .await
                .with_context(|| format!("create bucket {new_bucket}"))?;
        }

        if replace_objects {
            outcome.cleared_objects = empty_bucket(client, new_bucket).await?;
        } else {
            outcome.copied_objects =
                copy_bucket_contents(client, current_bucket, new_bucket).await?;
        }

        if let Some(path) = source_path {
            outcome.imported_files = import_source_path(client, new_bucket, path).await?;
        }

        outcome.deleted_source_objects = delete_bucket(client, current_bucket, true).await?;
        return Ok(outcome);
    }

    if replace_objects {
        outcome.cleared_objects = empty_bucket(client, current_bucket).await?;
    }
    if let Some(path) = source_path {
        outcome.imported_files = import_source_path(client, current_bucket, path).await?;
    }

    Ok(outcome)
}

async fn empty_bucket(client: &Client, bucket: &str) -> Result<usize> {
    let mut deleted = 0usize;
    loop {
        let keys = list_bucket_object_keys(client, bucket).await?;
        let objects: Vec<ObjectIdentifier> = keys
            .iter()
            .map(|key| {
                ObjectIdentifier::builder()
                    .key(key)
                    .build()
                    .map_err(|err| anyhow!(err.to_string()))
            })
            .collect::<Result<_>>()?;

        if objects.is_empty() {
            break;
        }

        deleted += objects.len();
        client
            .delete_objects()
            .bucket(bucket)
            .delete(
                Delete::builder()
                    .set_objects(Some(objects))
                    .quiet(true)
                    .build()
                    .map_err(|err| anyhow!(err.to_string()))?,
            )
            .send()
            .await
            .with_context(|| format!("delete objects from bucket {bucket}"))?;
    }
    Ok(deleted)
}

async fn delete_bucket(client: &Client, bucket: &str, delete_objects: bool) -> Result<usize> {
    let deleted = if delete_objects {
        empty_bucket(client, bucket).await?
    } else {
        0
    };
    client
        .delete_bucket()
        .bucket(bucket)
        .send()
        .await
        .with_context(|| format!("delete bucket {bucket}"))?;
    Ok(deleted)
}

#[tonic::async_trait]
impl HomeS3 for HomeS3GrpcService {
    async fn get_status(
        &self,
        _request: GrpcRequest<Empty>,
    ) -> Result<GrpcResponse<StatusResponse>, Status> {
        let cfg = current_config(&self.shared).await;
        let embedded_state = current_embedded_state(&self.shared).await;
        let response = StatusResponse {
            state: if self.shared.stopping.load(Ordering::SeqCst) {
                "stopping".to_string()
            } else {
                embedded_state.as_status_str().to_string()
            },
            log_level: cfg
                .log_level
                .clone()
                .unwrap_or_else(|| default_level_str().to_string()),
            endpoint: cfg.endpoint,
            region: cfg.region,
            access_key_id: cfg.access_key_id,
            force_path_style: cfg.force_path_style,
        };
        Ok(GrpcResponse::new(response))
    }

    async fn reload_config(
        &self,
        _request: GrpcRequest<Empty>,
    ) -> Result<GrpcResponse<Acknowledge>, Status> {
        let cfg = reload_config(&self.shared)
            .await
            .map_err(|err| internal_status("reload configuration", err))?;
        Ok(GrpcResponse::new(Acknowledge {
            ok: true,
            message: format!(
                "configuration file validated for endpoint {}. Restart the service to apply embedded RustFS changes.",
                cfg.endpoint
            ),
        }))
    }

    async fn stop_service(
        &self,
        _request: GrpcRequest<Empty>,
    ) -> Result<GrpcResponse<Acknowledge>, Status> {
        self.shared.stopping.store(true, Ordering::SeqCst);
        Ok(GrpcResponse::new(Acknowledge {
            ok: true,
            message: "stop requested".to_string(),
        }))
    }

    async fn list_buckets(
        &self,
        _request: GrpcRequest<Empty>,
    ) -> Result<GrpcResponse<ListBucketsResponse>, Status> {
        let cfg = current_config(&self.shared).await;
        let client = make_s3_client(&cfg)
            .await
            .map_err(|err| internal_status("initialise S3 client", err))?;
        let output = client
            .list_buckets()
            .send()
            .await
            .with_context(|| format!("list buckets via {}", cfg.endpoint))
            .map_err(|err| endpoint_status("list buckets", &cfg.endpoint, err))?;
        let buckets = output
            .buckets()
            .iter()
            .map(|bucket| proto::homes3::v1::list_buckets_response::Bucket {
                name: bucket.name().unwrap_or_default().to_string(),
                created_at: bucket
                    .creation_date()
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_default(),
                source_path: get_bucket_source_path(bucket.name().unwrap_or_default())
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
            })
            .collect();
        Ok(GrpcResponse::new(ListBucketsResponse { buckets }))
    }

    async fn list_bucket_objects(
        &self,
        request: GrpcRequest<ListBucketObjectsRequest>,
    ) -> Result<GrpcResponse<ListBucketObjectsResponse>, Status> {
        let request = request.into_inner();
        let bucket = request.bucket_name.trim().to_string();
        validate_bucket_name(&bucket).map_err(|err| Status::invalid_argument(err.to_string()))?;

        let cfg = current_config(&self.shared).await;
        let client = make_s3_client(&cfg)
            .await
            .map_err(|err| internal_status("initialise S3 client", err))?;

        let mut continuation_token = None::<String>;
        let mut objects = Vec::new();

        loop {
            let mut list_request = client.list_objects_v2().bucket(&bucket);
            if let Some(token) = &continuation_token {
                list_request = list_request.continuation_token(token);
            }

            let output = list_request
                .send()
                .await
                .with_context(|| format!("list objects in bucket {bucket} via {}", cfg.endpoint))
                .map_err(|err| endpoint_status("list bucket objects", &cfg.endpoint, err))?;

            objects.extend(output.contents().iter().map(|object| {
                proto::homes3::v1::list_bucket_objects_response::ObjectEntry {
                    key: object.key().unwrap_or_default().to_string(),
                    size: object.size().unwrap_or_default(),
                    last_modified: object
                        .last_modified()
                        .map(|value| format!("{value:?}"))
                        .unwrap_or_default(),
                }
            }));

            continuation_token = output.next_continuation_token().map(ToOwned::to_owned);
            if continuation_token.is_none() {
                break;
            }
        }

        Ok(GrpcResponse::new(ListBucketObjectsResponse { objects }))
    }

    async fn create_bucket(
        &self,
        request: GrpcRequest<CreateBucketRequest>,
    ) -> Result<GrpcResponse<Acknowledge>, Status> {
        let request = request.into_inner();
        let bucket = request.name.trim().to_string();
        validate_bucket_name(&bucket).map_err(|err| Status::invalid_argument(err.to_string()))?;
        let source_path = normalize_source_path(&request.source_path)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        let cfg = current_config(&self.shared).await;
        let client = make_s3_client(&cfg)
            .await
            .map_err(|err| internal_status("initialise S3 client", err))?;
        let (created, imported) =
            create_bucket_and_import(&client, &bucket, source_path.as_deref())
                .await
                .map_err(|err| endpoint_status("create bucket", &cfg.endpoint, err))?;
        if source_path.is_some() {
            set_bucket_source_path(&bucket, source_path.as_deref())
                .map_err(|err| internal_status("persist bucket metadata", err))?;
        }

        let message = match (created, imported) {
            (true, 0) => format!("bucket {bucket} created"),
            (false, 0) => format!("bucket {bucket} already existed"),
            (true, count) => format!("bucket {bucket} created and {count} file(s) imported"),
            (false, count) => {
                format!("bucket {bucket} already existed and {count} file(s) imported")
            }
        };
        Ok(GrpcResponse::new(Acknowledge { ok: true, message }))
    }

    async fn update_bucket(
        &self,
        request: GrpcRequest<UpdateBucketRequest>,
    ) -> Result<GrpcResponse<Acknowledge>, Status> {
        let request = request.into_inner();
        let current_bucket = request.current_name.trim().to_string();
        let new_bucket = if request.new_name.trim().is_empty() {
            current_bucket.clone()
        } else {
            request.new_name.trim().to_string()
        };

        validate_bucket_name(&current_bucket)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        validate_bucket_name(&new_bucket)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let source_path = normalize_source_path(&request.source_path)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        let cfg = current_config(&self.shared).await;
        let client = make_s3_client(&cfg)
            .await
            .map_err(|err| internal_status("initialise S3 client", err))?;
        let outcome = update_bucket(
            &client,
            &current_bucket,
            &new_bucket,
            source_path.as_deref(),
            request.replace_objects,
        )
        .await
        .map_err(|err| endpoint_status("update bucket", &cfg.endpoint, err))?;

        if outcome.renamed {
            rename_bucket_source_path(&current_bucket, &new_bucket)
                .map_err(|err| internal_status("persist bucket metadata", err))?;
        }
        if let Some(source_path) = source_path.as_deref() {
            set_bucket_source_path(&new_bucket, Some(source_path))
                .map_err(|err| internal_status("persist bucket metadata", err))?;
        }

        let action = if outcome.renamed {
            format!("bucket {current_bucket} updated to {new_bucket}")
        } else {
            format!("bucket {current_bucket} updated")
        };
        let mut details = Vec::new();
        if outcome.copied_objects > 0 {
            details.push(format!("{} object(s) copied", outcome.copied_objects));
        }
        if outcome.cleared_objects > 0 {
            details.push(format!("{} object(s) cleared", outcome.cleared_objects));
        }
        if outcome.imported_files > 0 {
            details.push(format!("{} file(s) imported", outcome.imported_files));
        }
        if outcome.deleted_source_objects > 0 {
            details.push(format!(
                "{} source object(s) removed",
                outcome.deleted_source_objects
            ));
        }
        let message = if details.is_empty() {
            action
        } else {
            format!("{action}: {}", details.join(", "))
        };

        Ok(GrpcResponse::new(Acknowledge { ok: true, message }))
    }

    async fn delete_bucket(
        &self,
        request: GrpcRequest<DeleteBucketRequest>,
    ) -> Result<GrpcResponse<Acknowledge>, Status> {
        let request = request.into_inner();
        let bucket = request.name.trim().to_string();
        validate_bucket_name(&bucket).map_err(|err| Status::invalid_argument(err.to_string()))?;

        let cfg = current_config(&self.shared).await;
        let client = make_s3_client(&cfg)
            .await
            .map_err(|err| internal_status("initialise S3 client", err))?;
        let deleted = delete_bucket(&client, &bucket, request.delete_objects)
            .await
            .map_err(|err| endpoint_status("delete bucket", &cfg.endpoint, err))?;
        set_bucket_source_path(&bucket, None)
            .map_err(|err| internal_status("persist bucket metadata", err))?;
        let message = if request.delete_objects {
            format!("bucket {bucket} deleted after removing {deleted} object(s)")
        } else {
            format!("bucket {bucket} deleted")
        };
        Ok(GrpcResponse::new(Acknowledge { ok: true, message }))
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(err) = run_service() {
        eprintln!("service error: {err:?}");
    }
}

fn run_service() -> Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                STOP_REQUESTED.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    let set_status = |state: ServiceState| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };

    set_status(ServiceState::StartPending);
    let cfg = load_config_or_init()?;
    init_logger(level_from_cfg(&cfg))?;
    info!(
        "home-s3 service starting build_tag={} sha={} at {}",
        BUILD_GIT_TAG, BUILD_GIT_SHA, BUILD_TIME
    );

    let shared = SharedState {
        cfg: Arc::new(Mutex::new(cfg)),
        embedded: Arc::new(Mutex::new(EmbeddedRustfsRuntime::default())),
        stopping: Arc::new(AtomicBool::new(false)),
    };

    let rt = Runtime::new()?;
    rt.block_on(start_embedded_rustfs(&shared))?;
    {
        let grpc_shared = shared.clone();
        rt.spawn(async move {
            serve_grpc(grpc_shared).await;
        });
    }

    set_status(ServiceState::Running);
    info!("home-s3 service running on {}", NAMED_PIPE_NAME);

    while !STOP_REQUESTED.load(Ordering::SeqCst) && !shared.stopping.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500));
    }

    info!("home-s3 service stopping");
    shared.stopping.store(true, Ordering::SeqCst);
    rt.block_on(stop_embedded_rustfs(&shared))?;
    set_status(ServiceState::Stopped);
    Ok(())
}

async fn serve_grpc(shared: SharedState) {
    let grpc_service = HomeS3GrpcService { shared };
    let grpc_server = Server::builder().add_service(HomeS3Server::new(grpc_service));
    let stream = match named_pipe_stream() {
        Ok(stream) => stream,
        Err(err) => {
            error!("failed to prepare home-s3 named pipe listener: {err}");
            return;
        }
    };
    if let Err(err) = grpc_server.serve_with_incoming(stream).await {
        error!("home-s3 gRPC server error: {err}");
    }
}

fn install_service() -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    if let Ok(_svc) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        uninstall_service().context("failed to reinstall existing service")?;
    }
    let service_info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec!["run".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    service.set_description(SERVICE_DESCRIPTION)?;
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
    )?;
    let _ = service.stop();
    for _ in 0..20 {
        if let Ok(status) = service.query_status() {
            if status.current_state == ServiceState::Stopped {
                break;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    service.delete()?;
    drop(service);
    for _ in 0..20 {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(service) => {
                drop(service);
                thread::sleep(Duration::from_millis(250));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

fn usage() {
    eprintln!("Usage: home-s3 [run|install|uninstall|console]");
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        usage();
        return Ok(());
    }
    match args[1].as_str() {
        "run" => {
            #[cfg(windows)]
            {
                if let Err(err) =
                    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
                {
                    eprintln!("service dispatcher start error: {err:?}");
                }
                Ok(())
            }
            #[cfg(not(windows))]
            {
                bail!("Windows only");
            }
        }
        "install" => {
            install_service()?;
            println!(
                "Service installed. Update {} then start the service.",
                config_path().display()
            );
            Ok(())
        }
        "uninstall" => {
            uninstall_service()?;
            println!("Service uninstalled.");
            Ok(())
        }
        "console" => {
            let cfg = load_config_or_init()?;
            init_logger(level_from_cfg(&cfg))?;
            let shared = SharedState {
                cfg: Arc::new(Mutex::new(cfg)),
                embedded: Arc::new(Mutex::new(EmbeddedRustfsRuntime::default())),
                stopping: Arc::new(AtomicBool::new(false)),
            };
            let rt = Runtime::new()?;
            rt.block_on(async move {
                start_embedded_rustfs(&shared).await?;
                let grpc_shared = shared.clone();
                tokio::spawn(async move {
                    serve_grpc(grpc_shared).await;
                });
                info!("home-s3 console mode running on {}", NAMED_PIPE_NAME);
                let _ = tokio::signal::ctrl_c().await;
                shared.stopping.store(true, Ordering::SeqCst);
                stop_embedded_rustfs(&shared).await
            })?;
            Ok(())
        }
        _ => {
            usage();
            Ok(())
        }
    }
}

fn named_pipe_stream() -> io::Result<UnboundedReceiverStream<Result<PipeConnection, io::Error>>> {
    let sddl = "D:(A;;GA;;;AC)(A;;GA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)(A;;FA;;;IU)";
    info!(
        "Preparing home-s3 named pipe listener: pipe={} sddl={}",
        NAMED_PIPE_NAME, sddl
    );

    let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let result = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            windows_sys::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };

    if result == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("security attributes creation failed: {err}"),
        ));
    }

    let sd_addr = sd as usize;
    let (tx, rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        struct SecurityDescriptorGuard(usize);
        impl Drop for SecurityDescriptorGuard {
            fn drop(&mut self) {
                if self.0 != 0 {
                    unsafe {
                        windows_sys::Win32::Foundation::LocalFree(self.0 as *mut c_void);
                    }
                }
            }
        }

        let _guard = SecurityDescriptorGuard(sd_addr);
        let first_server = {
            let mut sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: sd_addr as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
                bInheritHandle: 0,
            };
            match unsafe {
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .create_with_security_attributes_raw(
                        NAMED_PIPE_NAME,
                        &mut sa as *mut _ as *mut _,
                    )
            } {
                Ok(server) => server,
                Err(err) => {
                    let _ = tx.send(Err(err));
                    return;
                }
            }
        };

        let mut server = Some(first_server);
        let mut accepted_count = 0u64;
        loop {
            let Some(pipe_server) = server.take() else {
                break;
            };

            match pipe_server.connect().await {
                Ok(()) => {
                    accepted_count += 1;
                    debug!("home-s3 pipe accepted client count={accepted_count}");
                    let mut sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                        nLength: std::mem::size_of::<
                            windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
                        >() as u32,
                        lpSecurityDescriptor: sd_addr
                            as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
                        bInheritHandle: 0,
                    };
                    let next_server = match unsafe {
                        ServerOptions::new()
                            .first_pipe_instance(false)
                            .create_with_security_attributes_raw(
                                NAMED_PIPE_NAME,
                                &mut sa as *mut _ as *mut _,
                            )
                    } {
                        Ok(server) => server,
                        Err(err) => {
                            let _ = tx.send(Err(err));
                            break;
                        }
                    };
                    if tx.send(Ok(PipeConnection::new(pipe_server))).is_err() {
                        break;
                    }
                    server = Some(next_server);
                }
                Err(err) => {
                    warn!(
                        "home-s3 named pipe connect() failed: kind={:?} os_code={:?} err={}",
                        err.kind(),
                        err.raw_os_error(),
                        err
                    );
                    if tx.send(Err(err)).is_err() {
                        break;
                    }
                }
            }
        }
    });

    Ok(UnboundedReceiverStream::new(rx))
}
