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
use jsonwebtoken::{EncodingKey, Header};
use log::{error, info};
use rand::RngCore;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use rustls::{Certificate as RustlsCertificate, PrivateKey as RustlsPrivateKey, ServerConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::skip_serializing_none;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use url::Url;

#[cfg(windows)]
use log::warn;
#[cfg(windows)]
use once_cell::sync::Lazy;
#[cfg(windows)]
use std::ffi::OsString;
use tokio_rustls::TlsAcceptor;

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
        rand::thread_rng().fill_bytes(&mut secret);
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
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;
    let cert = params.self_signed(&key_pair)?;
    let key_pem = key_pair.serialize_pem();
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
    let certs = rustls_pemfile::certs(&mut cert_reader).context("read rustls certs")?;
    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader).context("read pkcs8 key")?;
    if keys.is_empty() {
        key_reader = BufReader::new(key_pem.as_bytes());
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader).context("read rsa key")?;
    }
    if keys.is_empty() {
        return Err(anyhow!("no private key material"));
    }
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            certs.into_iter().map(RustlsCertificate).collect(),
            RustlsPrivateKey(keys[0].clone()),
        )?;

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

struct AppState {
    cfg: ServiceConfig,
    clients: HashMap<String, ClientConfig>,
    key: EncodingKey,
    kid: String,
    jwks_json: String,
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

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>> {
    let path = req.uri().path().to_string();
    match (req.method(), path.as_str()) {
        (&Method::GET, "/.well-known/openid-configuration") => {
            let response = WellKnownResponse {
                issuer: state.cfg.issuer.clone(),
                authorization_endpoint: None,
                token_endpoint: format!("{}/token", state.cfg.issuer),
                jwks_uri: format!("{}/jwks.json", state.cfg.issuer),
                response_types_supported: vec!["token".into()],
                grant_types_supported: vec!["client_credentials".into(), "password".into()],
                token_endpoint_auth_methods_supported: vec![
                    "client_secret_basic".into(),
                    "client_secret_post".into(),
                ],
                scopes_supported: collect_supported_scopes(&state.clients),
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
    process_token_request(request, state)
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

fn process_token_request(req: TokenRequest, state: Arc<AppState>) -> Result<Response<Full<Bytes>>> {
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
    let client = match state.clients.get(&client_id).cloned() {
        Some(c) => c,
        None => return json_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client"),
    };
    if client.client_secret != req.client_secret.as_deref().unwrap_or_default() {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "invalid client secret",
        );
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

fn run_servers(cfg: ServiceConfig, material: KeyMaterial, cancel: CancellationToken) -> Result<()> {
    let rt = Runtime::new()?;
    let clients = cfg
        .clients
        .iter()
        .map(|c| (c.client_id.clone(), c.clone()))
        .collect();
    let state = Arc::new(AppState {
        cfg: cfg.clone(),
        clients,
        key: material.encoding,
        kid: material.kid,
        jwks_json: material.jwks_json,
    });
    let http_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cfg.http_port);
    let https_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cfg.https_port);
    let tls = material.tls_config.clone();
    rt.block_on(async {
        let cancel_http = cancel.clone();
        let cancel_https = cancel.clone();
        let http = tokio::spawn(serve_http(http_addr, state.clone(), cancel_http));
        let https = tokio::spawn(serve_https(https_addr, state.clone(), cancel_https, tls));
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
fn install_service() -> Result<()> {
    ensure_program_data()?;
    let cfg = load_config_or_init()?;
    let _material = load_key_material(&cfg)?;
    import_certificate_to_trust_store(&certificate_path())?;
    ensure_firewall_rule(cfg.https_port)?;
    let exe_path = std::env::current_exe()?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    if let Ok(_) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        info!("service already installed");
        return Ok(());
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
static STOP_TOKEN: Lazy<CancellationToken> = Lazy::new(CancellationToken::new);

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
        "install" => {
            install_service()?;
            println!(
                "Service installed. Update {} then start the service.",
                config_path().display()
            );
        }
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
