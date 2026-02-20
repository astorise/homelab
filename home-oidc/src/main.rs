#![cfg_attr(not(windows), allow(dead_code))]
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming};
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{error, info};
use rand::{rng, Rng};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};
use rsa::rand_core::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::skip_serializing_none;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio_util::sync::CancellationToken;
#[cfg(windows)]
use tonic::transport::{server::Connected, Server};
use tonic::{async_trait, Request as GrpcRequest, Response as GrpcResponse, Status};
use url::Url;

#[cfg(windows)]
use pin_project::pin_project;
#[cfg(windows)]
use std::pin::Pin;
#[cfg(windows)]
use std::task::{Context as TaskContext, Poll};
#[cfg(windows)]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(windows)]
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
#[cfg(windows)]
use tokio_stream::wrappers::UnboundedReceiverStream;

#[cfg(windows)]
use log::warn;
use once_cell::sync::Lazy;
#[cfg(windows)]
use std::ffi::{c_void, OsString};

#[cfg(windows)]
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(windows)]
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const SERVICE_NAME: &str = "HomeOidcService";
const SERVICE_DISPLAY_NAME: &str = "Home OIDC Service";
const SERVICE_DESCRIPTION: &str = "Minimal HTTPS OIDC provider with HTTP mirror";
const CLIENT_ASSERTION_JWT: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[cfg(all(debug_assertions, windows))]
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-oidc-dev";
#[cfg(all(not(debug_assertions), windows))]
const NAMED_PIPE_NAME: &str = r"\\.\pipe\home-oidc";

mod proto {
    pub mod homeoidc {
        pub mod v1 {
            tonic::include_proto!("homeoidc.v1");
        }
    }
}

use proto::homeoidc::v1::home_oidc_server::{HomeOidc, HomeOidcServer};
use proto::homeoidc::v1::list_clients_response::{
    Client as ClientMsg, PasswordUser as PasswordUserMsg,
};
use proto::homeoidc::v1::{
    Acknowledge, Empty, ListClientsResponse, RegisterClientRequest, RemoveClientRequest,
    StatusResponse,
};

fn program_data_dir() -> PathBuf {
    PathBuf::from(r"C:\\ProgramData\\home-oidc\\oidc")
}

fn logs_dir() -> PathBuf {
    program_data_dir().join("logs")
}

fn config_path() -> PathBuf {
    program_data_dir().join("oidc-config.json")
}

fn private_key_path() -> PathBuf {
    program_data_dir().join("oidc-private-key.pem")
}

fn certificate_path() -> PathBuf {
    program_data_dir().join("oidc-cert.pem")
}

fn jwks_path() -> PathBuf {
    program_data_dir().join("oidc-jwks.json")
}

fn default_http_port() -> u16 {
    8000
}

fn default_https_port() -> u16 {
    8443
}

fn default_issuer() -> String {
    "https://127.0.0.1:8443".to_string()
}

fn default_token_ttl() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasswordUser {
    username: String,
    password: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientConfig {
    client_id: String,
    client_secret: String,
    #[serde(default)]
    allowed_scopes: Vec<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    password_users: Vec<PasswordUser>,
    #[serde(default)]
    auth_method: ClientAuthMethod,
    #[serde(default)]
    client_public_key_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ClientAuthMethod {
    ClientSecret,
    PrivateKeyJwt,
}

impl Default for ClientAuthMethod {
    fn default() -> Self {
        ClientAuthMethod::ClientSecret
    }
}

impl ClientAuthMethod {
    fn as_str(&self) -> &'static str {
        match self {
            ClientAuthMethod::ClientSecret => "client_secret_post",
            ClientAuthMethod::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceConfig {
    #[serde(default = "default_http_port")]
    http_port: u16,
    #[serde(default = "default_https_port")]
    https_port: u16,
    #[serde(default = "default_issuer")]
    issuer: String,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    clients: Vec<ClientConfig>,
    #[serde(default = "default_token_ttl")]
    token_ttl_secs: u64,
    #[serde(default)]
    log_level: Option<String>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        let mut secret = [0u8; 24];
        rng().fill_bytes(&mut secret);
        let default_secret = URL_SAFE_NO_PAD.encode(secret);
        ServiceConfig {
            http_port: default_http_port(),
            https_port: default_https_port(),
            issuer: default_issuer(),
            audiences: vec!["https://example-app".to_string()],
            clients: vec![ClientConfig {
                client_id: "demo-client".to_string(),
                client_secret: default_secret,
                allowed_scopes: vec!["demo.read".to_string()],
                subject: Some("demo-client".to_string()),
                audiences: vec![],
                password_users: vec![PasswordUser {
                    username: "demo-user".to_string(),
                    password: "change-me".to_string(),
                    subject: Some("demo-user".to_string()),
                    scopes: vec!["demo.read".to_string()],
                }],
                auth_method: ClientAuthMethod::ClientSecret,
                client_public_key_pem: None,
            }],
            token_ttl_secs: default_token_ttl(),
            log_level: Some("info".to_string()),
        }
    }
}

fn level_from_cfg(cfg: &ServiceConfig) -> log::LevelFilter {
    match cfg.log_level.as_deref().unwrap_or("info") {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        "off" => log::LevelFilter::Off,
        _ => log::LevelFilter::Info,
    }
}

fn init_logger(level: log::LevelFilter) -> Result<()> {
    let dir = logs_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating log directory {}", dir.display()))?;
    Logger::try_with_env_or_str(level.as_str())?
        .log_to_file(
            FileSpec::default()
                .directory(dir)
                .basename("home-oidc")
                .suffix("log"),
        )
        .duplicate_to_stderr(Duplicate::Error)
        .rotate(
            Criterion::Age(Age::Day),
            Naming::Timestamps,
            Cleanup::KeepLogFiles(7),
        )
        .start()?;
    Ok(())
}

fn ensure_program_data() -> Result<()> {
    let dir = program_data_dir();
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(())
}

fn load_config_or_init() -> Result<ServiceConfig> {
    ensure_program_data()?;
    let cfg_path = config_path();
    if cfg_path.exists() {
        let data =
            fs::read(&cfg_path).with_context(|| format!("reading {}", cfg_path.display()))?;
        let cfg: ServiceConfig = serde_json::from_slice(&data).with_context(|| "parsing config")?;
        Ok(cfg)
    } else {
        let cfg = ServiceConfig::default();
        let json = serde_json::to_vec_pretty(&cfg)?;
        fs::write(&cfg_path, json).with_context(|| format!("writing {}", cfg_path.display()))?;
        Ok(cfg)
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp_path)
            .with_context(|| format!("create temp {}", tmp_path.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

struct KeyMaterial {
    encoding: EncodingKey,
    kid: String,
    jwks_json: String,
    tls_config: Arc<ServerConfig>,
}

fn ensure_certificate(cfg: &ServiceConfig) -> Result<()> {
    if private_key_path().exists() && certificate_path().exists() {
        return Ok(());
    }
    let issuer = Url::parse(&cfg.issuer).context("invalid issuer url")?;
    let host = issuer
        .host_str()
        .ok_or_else(|| anyhow!("issuer host missing"))?
        .to_string();
    let mut params = CertificateParams::new(vec![host.clone()])?;
    params.is_ca = IsCa::NoCa;
    params
        .distinguished_name
        .push(DnType::CommonName, host.clone());
    params
        .subject_alt_names
        .push(SanType::DnsName("localhost".to_string().try_into()?));
    params
        .subject_alt_names
        .push(SanType::DnsName(host.clone().try_into()?));
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(ip)));
    }
    let mut rng = OsRng;
    let rsa_key = RsaPrivateKey::new(&mut rng, 4096).context("generate rsa key")?;
    let key_pem = rsa_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("serialize rsa key to PKCS#8")?
        .to_string();
    let key_pair = KeyPair::from_pem(&key_pem).context("load rcgen key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign certificate with rsa key")?;
    let cert_pem = cert.pem();
    write_atomic(&private_key_path(), key_pem.as_bytes())?;
    write_atomic(&certificate_path(), cert_pem.as_bytes())?;
    Ok(())
}

fn load_key_material(cfg: &ServiceConfig) -> Result<KeyMaterial> {
    ensure_certificate(cfg)?;
    let key_pem = fs::read_to_string(private_key_path()).context("read private key")?;
    let cert_pem = fs::read_to_string(certificate_path()).context("read certificate")?;

    let encoding = EncodingKey::from_rsa_pem(key_pem.as_bytes()).context("encoding key")?;

    let rsa_key = RsaPrivateKey::from_pkcs1_pem(&key_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&key_pem))
        .context("parsing rsa key")?;
    let public_key = rsa_key.to_public_key();
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    let mut hasher = Sha256::new();
    hasher.update(&n_bytes);
    hasher.update(&e_bytes);
    let kid = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let jwk = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(&n_bytes),
        "e": URL_SAFE_NO_PAD.encode(&e_bytes),
    });
    let jwks = json!({ "keys": [jwk] });
    let jwks_json = serde_json::to_string_pretty(&jwks)?;
    write_atomic(&jwks_path(), jwks_json.as_bytes())?;

    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .context("read rustls certs")?;
    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("read pkcs8 key")?;
    let key = if let Some(key) = pkcs8_keys.into_iter().next() {
        PrivateKeyDer::from(key)
    } else {
        key_reader = BufReader::new(key_pem.as_bytes());
        let rsa_keys = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("read rsa key")?;
        match rsa_keys.into_iter().next() {
            Some(key) => PrivateKeyDer::from(key),
            None => return Err(anyhow!("no private key material")),
        }
    };
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(KeyMaterial {
        encoding,
        kid,
        jwks_json,
        tls_config: Arc::new(tls_config),
    })
}

#[skip_serializing_none]
#[derive(Serialize)]
struct WellKnownResponse {
    issuer: String,
    authorization_endpoint: Option<String>,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
    subject_types_supported: Vec<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    client_assertion_type: Option<String>,
    #[serde(default)]
    client_assertion: Option<String>,
}

fn persist_service_config(cfg: &ServiceConfig) -> Result<()> {
    let data = serde_json::to_vec_pretty(cfg)?;
    write_atomic(&config_path(), &data)
}

#[derive(Serialize, Deserialize)]
struct TokenClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    iat: u64,
    exp: u64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, expected: &str) -> bool {
        match self {
            AudienceClaim::Single(value) => value == expected,
            AudienceClaim::Multiple(values) => values.iter().any(|v| v == expected),
        }
    }
}

#[derive(Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    aud: AudienceClaim,
    exp: u64,
    iat: Option<u64>,
    jti: Option<String>,
}

struct AppState {
    cfg: ServiceConfig,
    clients: RwLock<HashMap<String, ClientConfig>>,
    key: EncodingKey,
    kid: String,
    jwks_json: String,
    token_endpoint: String,
}

impl AppState {
    fn audience_for(
        &self,
        client: &ClientConfig,
        requested: Option<String>,
        resource: Option<String>,
    ) -> Result<Vec<String>> {
        if let Some(req) = requested.or(resource) {
            let allowed = if client.audiences.is_empty() {
                &self.cfg.audiences
            } else {
                &client.audiences
            };
            if allowed.is_empty() || allowed.iter().any(|a| a == &req) {
                return Ok(vec![req]);
            } else {
                anyhow::bail!("audience not allowed");
            }
        }
        if !client.audiences.is_empty() {
            return Ok(client.audiences.clone());
        }
        if !self.cfg.audiences.is_empty() {
            return Ok(vec![self.cfg.audiences[0].clone()]);
        }
        anyhow::bail!("no audience configured");
    }

    fn scopes_for(&self, client: &ClientConfig, request_scope: Option<String>) -> Result<String> {
        if let Some(scope) = request_scope {
            if client.allowed_scopes.is_empty() {
                return Ok(scope);
            }
            let requested: Vec<&str> = scope.split_whitespace().collect();
            let mut invalid = vec![];
            for s in &requested {
                if !client.allowed_scopes.iter().any(|allowed| allowed == s) {
                    invalid.push((*s).to_string());
                }
            }
            if !invalid.is_empty() {
                anyhow::bail!(format!("invalid scope(s): {}", invalid.join(", ")));
            }
            return Ok(scope);
        }
        if client.allowed_scopes.is_empty() {
            Ok(String::new())
        } else {
            Ok(client.allowed_scopes.join(" "))
        }
    }
}

fn collect_supported_scopes(clients: &HashMap<String, ClientConfig>) -> Vec<String> {
    let mut scopes = Vec::new();
    for client in clients.values() {
        for scope in &client.allowed_scopes {
            if !scopes.contains(scope) {
                scopes.push(scope.clone());
            }
        }
    }
    scopes
}

#[derive(Clone)]
struct OidcGrpcService {
    state: Arc<AppState>,
}

#[async_trait]
impl HomeOidc for OidcGrpcService {
    async fn get_status(
        &self,
        _request: GrpcRequest<Empty>,
    ) -> Result<GrpcResponse<StatusResponse>, Status> {
        let level = self
            .state
            .cfg
            .log_level
            .clone()
            .unwrap_or_else(|| "info".to_string());
        let issuer = self.state.cfg.issuer.trim_end_matches('/').to_string();
        Ok(GrpcResponse::new(StatusResponse {
            state: "running".to_string(),
            log_level: level,
            issuer,
            token_endpoint: self.state.token_endpoint.clone(),
        }))
    }

    async fn list_clients(
        &self,
        _request: GrpcRequest<Empty>,
    ) -> Result<GrpcResponse<ListClientsResponse>, Status> {
        let clients_guard = self.state.clients.read().await;
        let clients = clients_guard
            .values()
            .map(|client| {
                let password_users = client
                    .password_users
                    .iter()
                    .map(|user| PasswordUserMsg {
                        username: user.username.clone(),
                        subject: user.subject.clone().unwrap_or_default(),
                        scopes: user.scopes.clone(),
                    })
                    .collect();
                ClientMsg {
                    client_id: client.client_id.clone(),
                    subject: client.subject.clone().unwrap_or_default(),
                    allowed_scopes: client.allowed_scopes.clone(),
                    audiences: client.audiences.clone(),
                    password_users,
                    auth_method: client.auth_method.as_str().to_string(),
                    public_key_pem: client.client_public_key_pem.clone().unwrap_or_default(),
                }
            })
            .collect();
        Ok(GrpcResponse::new(ListClientsResponse { clients }))
    }

    async fn register_client(
        &self,
        request: GrpcRequest<RegisterClientRequest>,
    ) -> Result<GrpcResponse<Acknowledge>, Status> {
        let req = request.into_inner();
        let raw_id = req.client_id.trim();
        if raw_id.is_empty() {
            return Err(Status::invalid_argument("client_id required"));
        }
        let auth_method = match req.auth_method.trim() {
            "" | "private_key_jwt" => ClientAuthMethod::PrivateKeyJwt,
            other
                if other.eq_ignore_ascii_case("client_secret")
                    || other.eq_ignore_ascii_case("client_secret_post") =>
            {
                return Err(Status::invalid_argument(
                    "client_secret clients must be managed via configuration file",
                ))
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported auth_method '{other}'"
                )))
            }
        };
        let public_key = req.public_key_pem.trim().to_string();
        if auth_method == ClientAuthMethod::PrivateKeyJwt && public_key.is_empty() {
            return Err(Status::invalid_argument("public_key_pem required"));
        }
        let subject = if req.subject.trim().is_empty() {
            Some(raw_id.to_string())
        } else {
            Some(req.subject.trim().to_string())
        };
        let allowed_scopes = req
            .allowed_scopes
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let audiences = req
            .audiences
            .into_iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect::<Vec<_>>();
        let client = ClientConfig {
            client_id: raw_id.to_string(),
            client_secret: String::new(),
            allowed_scopes,
            subject,
            audiences,
            password_users: vec![],
            auth_method: auth_method.clone(),
            client_public_key_pem: if public_key.is_empty() {
                None
            } else {
                Some(public_key.clone())
            },
        };
        let cfg_guard = CONFIG_WRITE_LOCK.lock().await;
        let mut cfg = load_config_or_init().map_err(|e| Status::internal(e.to_string()))?;
        cfg.clients.retain(|c| c.client_id != client.client_id);
        cfg.clients.push(client.clone());
        persist_service_config(&cfg).map_err(|e| Status::internal(e.to_string()))?;
        drop(cfg_guard);
        {
            let mut map = self.state.clients.write().await;
            map.insert(client.client_id.clone(), client);
        }
        Ok(GrpcResponse::new(Acknowledge {
            ok: true,
            message: "client registered".into(),
        }))
    }

    async fn remove_client(
        &self,
        request: GrpcRequest<RemoveClientRequest>,
    ) -> Result<GrpcResponse<Acknowledge>, Status> {
        let req = request.into_inner();
        let raw_id = req.client_id.trim();
        if raw_id.is_empty() {
            return Err(Status::invalid_argument("client_id required"));
        }
        let cfg_guard = CONFIG_WRITE_LOCK.lock().await;
        let mut cfg = load_config_or_init().map_err(|e| Status::internal(e.to_string()))?;
        let before = cfg.clients.len();
        cfg.clients.retain(|c| c.client_id != raw_id);
        let removed = before != cfg.clients.len();
        if removed {
            persist_service_config(&cfg).map_err(|e| Status::internal(e.to_string()))?;
        }
        drop(cfg_guard);
        if removed {
            let mut map = self.state.clients.write().await;
            map.remove(raw_id);
        }
        Ok(GrpcResponse::new(Acknowledge {
            ok: removed,
            message: if removed {
                "client removed".into()
            } else {
                "client not found".into()
            },
        }))
    }
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>> {
    let path = req.uri().path().to_string();
    match (req.method(), path.as_str()) {
        (&Method::GET, "/.well-known/openid-configuration") => {
            let issuer = state.cfg.issuer.trim_end_matches('/').to_string();
            let token_endpoint = format!("{}/token", issuer);
            let jwks_uri = format!("{}/jwks.json", issuer);
            let clients_guard = state.clients.read().await;
            let mut auth_methods = vec!["client_secret_basic".into(), "client_secret_post".into()];
            if clients_guard
                .values()
                .any(|c| c.auth_method == ClientAuthMethod::PrivateKeyJwt)
            {
                auth_methods.push("private_key_jwt".into());
            }
            let scopes_supported = collect_supported_scopes(&clients_guard);
            drop(clients_guard);
            let response = WellKnownResponse {
                issuer,
                authorization_endpoint: None,
                token_endpoint,
                jwks_uri,
                response_types_supported: vec!["token".into()],
                grant_types_supported: vec!["client_credentials".into(), "password".into()],
                token_endpoint_auth_methods_supported: auth_methods,
                scopes_supported,
                subject_types_supported: vec!["public".into()],
            };
            let body = serde_json::to_vec(&response)?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Full::from(body))?)
        }
        (&Method::GET, "/jwks.json") => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::from(state.jwks_json.clone()))?),
        (&Method::POST, "/token") => handle_token(req, state).await,
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::from("not found"))?),
    }
}

fn parse_basic_auth(header: &str) -> Option<(String, String)> {
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

async fn handle_token(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>> {
    let headers = req.headers().clone();
    let collected = req.into_body().collect().await?;
    let body_bytes = collected.to_bytes();
    let mut params: HashMap<String, String> =
        serde_urlencoded::from_bytes(&body_bytes).unwrap_or_default();
    if let Some(auth) = headers.get(http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some((client_id, client_secret)) = parse_basic_auth(auth_str) {
                params.entry("client_id".into()).or_insert(client_id);
                params
                    .entry("client_secret".into())
                    .or_insert(client_secret);
            }
        }
    }
    let request = TokenRequest::from(params);
    process_token_request(request, state).await
}

impl From<HashMap<String, String>> for TokenRequest {
    fn from(mut map: HashMap<String, String>) -> Self {
        TokenRequest {
            grant_type: map.remove("grant_type").unwrap_or_default(),
            scope: map.remove("scope"),
            audience: map.remove("audience"),
            resource: map.remove("resource"),
            client_id: map.remove("client_id"),
            client_secret: map.remove("client_secret"),
            username: map.remove("username"),
            password: map.remove("password"),
            client_assertion_type: map.remove("client_assertion_type"),
            client_assertion: map.remove("client_assertion"),
        }
    }
}

fn json_error(status: StatusCode, code: &str, desc: &str) -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::from(
            json!({"error": code, "error_description": desc}).to_string(),
        ))?)
}

async fn process_token_request(
    req: TokenRequest,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>> {
    if req.grant_type.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "grant_type required",
        );
    }
    let client_id = match req.client_id.clone() {
        Some(id) => id,
        None => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication required",
            )
        }
    };
    let client = {
        let guard = state.clients.read().await;
        guard.get(&client_id).cloned()
    };
    let client = match client {
        Some(c) => c,
        None => return json_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client"),
    };
    match client.auth_method {
        ClientAuthMethod::ClientSecret => {
            if client.client_secret != req.client_secret.as_deref().unwrap_or_default() {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "invalid client secret",
                );
            }
        }
        ClientAuthMethod::PrivateKeyJwt => {
            if req
                .client_assertion_type
                .as_deref()
                .map(|t| t.eq_ignore_ascii_case(CLIENT_ASSERTION_JWT))
                != Some(true)
            {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "client assertion required",
                );
            }
            let assertion = match req.client_assertion.as_deref() {
                Some(value) if !value.is_empty() => value,
                _ => {
                    return json_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "client assertion required",
                    )
                }
            };
            let pem = match client.client_public_key_pem.as_ref() {
                Some(pem) if !pem.is_empty() => pem,
                _ => {
                    error!(
                        "client {} configured for private_key_jwt without public key",
                        client.client_id
                    );
                    return json_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "client public key missing",
                    );
                }
            };
            let decoding = match DecodingKey::from_rsa_pem(pem.as_bytes()) {
                Ok(key) => key,
                Err(err) => {
                    error!(
                        "invalid client public key for {}: {err:?}",
                        client.client_id
                    );
                    return json_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "invalid client public key",
                    );
                }
            };
            let mut validation = Validation::new(Algorithm::RS256);
            let expected = vec![state.token_endpoint.clone()];
            validation.set_audience(expected.as_slice());
            validation.validate_aud = true;
            let claims = match jsonwebtoken::decode::<ClientAssertionClaims>(
                assertion,
                &decoding,
                &validation,
            ) {
                Ok(token) => token.claims,
                Err(err) => {
                    error!(
                        "client assertion validation failed for {}: {err:?}",
                        client.client_id
                    );
                    return json_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "invalid client assertion",
                    );
                }
            };
            if claims.iss != client.client_id || claims.sub != client.client_id {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "invalid client assertion issuer",
                );
            }
            if !claims.aud.contains(&state.token_endpoint) {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "invalid client assertion audience",
                );
            }
        }
    }
    match req.grant_type.as_str() {
        "client_credentials" => issue_client_credentials_token(req, state, &client),
        "password" => issue_password_token(req, state, &client),
        _ => json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant type not supported",
        ),
    }
}

fn issue_client_credentials_token(
    req: TokenRequest,
    state: Arc<AppState>,
    client: &ClientConfig,
) -> Result<Response<Full<Bytes>>> {
    let scopes = state
        .scopes_for(client, req.scope.clone())
        .map_err(|e| anyhow!(e))?;
    let aud = state
        .audience_for(client, req.audience.clone(), req.resource.clone())
        .map_err(|e| anyhow!(e))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let exp = now + Duration::from_secs(state.cfg.token_ttl_secs);
    let claims = TokenClaims {
        iss: state.cfg.issuer.clone(),
        sub: client
            .subject
            .clone()
            .unwrap_or_else(|| client.client_id.clone()),
        aud,
        iat: now.as_secs(),
        exp: exp.as_secs(),
        scope: scopes.clone(),
        client_id: Some(client.client_id.clone()),
    };
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(state.kid.clone());
    let token = jsonwebtoken::encode(&header, &claims, &state.key).map_err(|e| anyhow!(e))?;
    let body = serde_json::to_vec(&TokenResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in: state.cfg.token_ttl_secs,
        scope: scopes,
    })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::from(body))?)
}

fn issue_password_token(
    req: TokenRequest,
    state: Arc<AppState>,
    client: &ClientConfig,
) -> Result<Response<Full<Bytes>>> {
    let username = match req.username.clone() {
        Some(u) => u,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "username required",
            )
        }
    };
    let password = match req.password.clone() {
        Some(p) => p,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "password required",
            )
        }
    };
    let user = match client
        .password_users
        .iter()
        .find(|u| u.username == username && u.password == password)
    {
        Some(u) => u,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid user credentials",
            )
        }
    };
    let scopes = if !user.scopes.is_empty() {
        user.scopes.join(" ")
    } else {
        state
            .scopes_for(client, req.scope.clone())
            .map_err(|e| anyhow!(e))?
    };
    let aud = state
        .audience_for(client, req.audience.clone(), req.resource.clone())
        .map_err(|e| anyhow!(e))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let exp = now + Duration::from_secs(state.cfg.token_ttl_secs);
    let claims = TokenClaims {
        iss: state.cfg.issuer.clone(),
        sub: user.subject.clone().unwrap_or_else(|| username.clone()),
        aud,
        iat: now.as_secs(),
        exp: exp.as_secs(),
        scope: scopes.clone(),
        client_id: Some(client.client_id.clone()),
    };
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(state.kid.clone());
    let token = jsonwebtoken::encode(&header, &claims, &state.key).map_err(|e| anyhow!(e))?;
    let body = serde_json::to_vec(&TokenResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in: state.cfg.token_ttl_secs,
        scope: scopes,
    })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::from(body))?)
}

async fn serve_http(
    addr: SocketAddr,
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("HTTP server on {} stopping", addr);
                break;
            }
            accept = listener.accept() => {
                let (stream, _) = accept?;
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service_fn(|req| {
                            let state = state.clone();
                            async move {
                                match handle_request(req, state).await {
                                    Ok(resp) => Ok::<_, anyhow::Error>(resp),
                                    Err(e) => {
                                        error!("request error: {e:?}");
                                        let body = Full::from(json!({"error": "server_error"}).to_string());
                                        Ok(Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .header(http::header::CONTENT_TYPE, "application/json")
                                            .body(body)
                                            .unwrap())
                                    }
                                }
                            }
                        }))
                        .await {
                        error!("http connection error: {e:?}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn serve_https(
    addr: SocketAddr,
    state: Arc<AppState>,
    cancel: CancellationToken,
    tls: Arc<ServerConfig>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("HTTPS server on {} stopping", addr);
                break;
            }
            accept = listener.accept() => {
                let (stream, _) = accept?;
                let state = state.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(tls_stream), service_fn(|req| {
                                    let state = state.clone();
                                    async move {
                                        match handle_request(req, state).await {
                                            Ok(resp) => Ok::<_, anyhow::Error>(resp),
                                            Err(e) => {
                                                error!("request error: {e:?}");
                                                let body = Full::from(json!({"error": "server_error"}).to_string());
                                                Ok(Response::builder()
                                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                    .header(http::header::CONTENT_TYPE, "application/json")
                                                    .body(body)
                                                    .unwrap())
                                            }
                                        }
                                    }
                                }))
                                .await {
                                error!("https connection error: {e:?}");
                            }
                        }
                        Err(e) => {
                            error!("tls accept error: {e:?}");
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
async fn run_grpc_server(state: Arc<AppState>, cancel: CancellationToken) -> Result<()> {
    let service = OidcGrpcService { state };
    let server = Server::builder().add_service(HomeOidcServer::new(service));

    let incoming =
        named_pipe_stream().map_err(|e| anyhow!("failed to prepare management pipe: {e}"))?;
    info!("gRPC server listening on {}", NAMED_PIPE_NAME);

    tokio::select! {
        res = server.serve_with_incoming(incoming) => {
            res.map_err(|e| anyhow!(e))?;
        }
        _ = cancel.cancelled() => {
            info!("gRPC server cancellation requested");
        }
    }
    Ok(())
}

fn run_servers(cfg: ServiceConfig, material: KeyMaterial, cancel: CancellationToken) -> Result<()> {
    let rt = Runtime::new()?;
    let clients = cfg
        .clients
        .iter()
        .map(|c| (c.client_id.clone(), c.clone()))
        .collect();
    let issuer = cfg.issuer.trim_end_matches('/').to_string();
    let token_endpoint = format!("{}/token", issuer);
    let state = Arc::new(AppState {
        cfg: cfg.clone(),
        clients: RwLock::new(clients),
        key: material.encoding,
        kid: material.kid,
        jwks_json: material.jwks_json,
        token_endpoint,
    });
    let http_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cfg.http_port);
    let https_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cfg.https_port);
    let tls = material.tls_config.clone();
    rt.block_on(async {
        let cancel_http = cancel.clone();
        let cancel_https = cancel.clone();
        let http = tokio::spawn(serve_http(http_addr, state.clone(), cancel_http));
        let https = tokio::spawn(serve_https(https_addr, state.clone(), cancel_https, tls));
        #[cfg(windows)]
        {
            let cancel_grpc = cancel.clone();
            let state_grpc = state.clone();
            tokio::spawn(async move {
                if let Err(err) = run_grpc_server(state_grpc, cancel_grpc).await {
                    error!("gRPC server error: {err:?}");
                }
            });
        }
        tokio::select! {
            res = http => {
                if let Err(e) = res {
                    error!("http task join error: {e:?}");
                }
            }
            res = https => {
                if let Err(e) = res {
                    error!("https task join error: {e:?}");
                }
            }
            _ = cancel.cancelled() => {}
        }
    });
    Ok(())
}

#[cfg(windows)]
#[pin_project]
struct PipeConnection {
    #[pin]
    inner: NamedPipeServer,
}

#[cfg(windows)]
impl PipeConnection {
    fn new(inner: NamedPipeServer) -> Self {
        Self { inner }
    }
}

#[cfg(windows)]
unsafe impl Send for PipeConnection {}

#[cfg(windows)]
impl Connected for PipeConnection {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

#[cfg(windows)]
impl AsyncRead for PipeConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

#[cfg(windows)]
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

#[cfg(windows)]
fn named_pipe_stream() -> io::Result<UnboundedReceiverStream<Result<PipeConnection, io::Error>>> {
    let sddl = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;AU)(A;;FA;;;IU)"; // Allow System, Built-in Admins, Authenticated Users, Interactive Users
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
        error!("FATAL: ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}", err);
        return Err(io::Error::new(io::ErrorKind::Other, "Security attributes creation failed"));
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

        let server = {
            let mut sa_first = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd_addr as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
                bInheritHandle: 0,
            };
            match unsafe {
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .create_with_security_attributes_raw(NAMED_PIPE_NAME, &mut sa_first as *mut _ as *mut _)
            } {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            }
        };

        let mut server = Some(server);

        loop {
            if let Some(s) = server.take() {
                match s.connect().await {
                    Ok(()) => {
                        let mut sa_loop = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
                            lpSecurityDescriptor: sd_addr as windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
                            bInheritHandle: 0,
                        };
                        let new_server = match unsafe {
                            ServerOptions::new().create_with_security_attributes_raw(
                                NAMED_PIPE_NAME,
                                &mut sa_loop as *mut _ as *mut _,
                            )
                        } {
                            Ok(s) => s,
                            Err(e) => {
                                let _ = tx.send(Err(e));
                                break;
                            }
                        };
                        if tx.send(Ok(PipeConnection::new(s))).is_err() {
                            break;
                        }
                        server = Some(new_server);
                    }
                    Err(e) => {
                        if tx.send(Err(e)).is_err() {
                            break;
                        }
                    }
                }
            } else {
                break;
            }
        }
    });

    Ok(UnboundedReceiverStream::new(rx))
}

#[cfg(windows)]
fn install_service() -> Result<()> {
    ensure_program_data().context("ensure program data directory")?;
    append_install_log("=== home-oidc install_service starting ===");
    let cfg = load_config_or_init().context("load or initialize config")?;
    append_install_log("Configuration loaded");
    load_key_material(&cfg).context("ensure TLS key material")?;
    append_install_log("Key material ensured");
    import_certificate_to_trust_store(&certificate_path())
        .context("import certificate to Windows trust store")?;
    append_install_log("Certificate imported (best effort)");
    ensure_firewall_rule(cfg.https_port).context("ensure firewall rule")?;
    append_install_log(&format!(
        "Firewall rule verified for port {}",
        cfg.https_port
    ));
    let exe_path = std::env::current_exe().context("determine current executable path")?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    if let Ok(_) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        info!("service already installed, reinstalling to refresh binary/config");
        append_install_log("Service already installed, reinstalling");
        uninstall_service().context("failed to reinstall existing service")?;
    }
    let service_info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.clone(),
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
    append_install_log("Service registration completed");
    Ok(())
}

#[cfg(windows)]
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
        std::thread::sleep(Duration::from_millis(250));
    }
    service.delete()?;
    drop(service);
    for _ in 0..20 {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(s) => {
                drop(s);
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

#[cfg(windows)]
fn import_certificate_to_trust_store(path: &Path) -> Result<()> {
    let path_str = path.display().to_string();
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "try {{ Import-Certificate -FilePath '{}' -CertStoreLocation Cert:\\LocalMachine\\Root -ErrorAction Stop }} catch {{ Import-Certificate -FilePath '{}' -CertStoreLocation Cert:\\CurrentUser\\Root }}",
                path_str, path_str
            ),
        ])
        .status()?;
    if !status.success() {
        warn!("certificate import failed with status {:?}", status);
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_firewall_rule(port: u16) -> Result<()> {
    let rule_name = format!("OIDC Service {port}");
    let check = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={rule_name}"),
        ])
        .status();
    if let Ok(status) = check {
        if status.success() {
            return Ok(());
        }
    }
    let status = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={rule_name}"),
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={port}"),
        ])
        .status()?;
    if !status.success() {
        warn!("failed to create firewall rule status {:?}", status);
    }
    Ok(())
}

#[cfg(windows)]
fn append_install_log(message: &str) {
    use std::io::Write;
    use std::time::SystemTime;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{ts}] {message}");
    let path = program_data_dir().join("install.log");
    if let Ok(mut file) = OpenOptions::new().append(true).create(true).open(&path) {
        let _ = writeln!(file, "{line}");
    }
}

#[cfg(windows)]
static STOP_TOKEN: Lazy<CancellationToken> = Lazy::new(CancellationToken::new);
static CONFIG_WRITE_LOCK: Lazy<AsyncMutex<()>> = Lazy::new(|| AsyncMutex::new(()));

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("service error: {e:?}");
    }
}

#[cfg(windows)]
fn run_service() -> Result<()> {
    let cancel = STOP_TOKEN.clone();
    let handler_cancel = cancel.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_cancel.cancel();
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
    let level = level_from_cfg(&cfg);
    init_logger(level)?;
    info!("OIDC service starting");
    let material = load_key_material(&cfg)?;
    set_status(ServiceState::Running);
    run_servers(cfg, material, cancel)?;
    set_status(ServiceState::Stopped);
    Ok(())
}

#[cfg(windows)]
fn usage() {
    eprintln!("Usage: home-oidc [run|install|uninstall|console]");
}

#[cfg(windows)]
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        usage();
        return Ok(());
    }
    match args[1].as_str() {
        "run" => {
            if let Err(e) =
                windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            {
                error!("service dispatcher error: {e:?}");
            }
        }
        "install" => match install_service() {
            Ok(_) => {
                append_install_log("Install completed successfully");
                println!(
                    "Service installed. Update {} then start the service.",
                    config_path().display()
                );
            }
            Err(e) => {
                append_install_log(&format!("ERROR: {e:?}"));
                return Err(e);
            }
        },
        "uninstall" => {
            uninstall_service()?;
            println!("Service uninstalled.");
        }
        "console" => {
            let cfg = load_config_or_init()?;
            init_logger(level_from_cfg(&cfg))?;
            let cancel = CancellationToken::new();
            let material = load_key_material(&cfg)?;
            run_servers(cfg, material, cancel)?;
        }
        _ => usage(),
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() -> Result<()> {
    anyhow::bail!("Windows only");
}
