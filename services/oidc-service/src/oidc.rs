use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;
use tracing::{info, warn};
use uuid::Uuid;

#[cfg(windows)]
use {
    axum::routing::{get, post},
    hyper::server::accept::from_stream,
    hyper_rustls::TlsAcceptor,
    rustls::{pki_types::CertificateDer, ServerConfig},
    rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys},
    std::io::{BufReader, Seek},
    tokio::net::TcpListener,
    tokio::task::JoinHandle,
};

const APP_NAME: &str = "home-lab";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcClient {
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub port: u16,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub clients: Vec<OidcClient>,
}

#[derive(Clone)]
pub struct OidcState {
    pub config: OidcConfig,
    pub clients: HashMap<String, OidcClient>,
    pub encoding_key: EncodingKey,
    pub jwks: serde_json::Value,
    pub key_id: String,
}

pub struct OidcPaths {
    pub base_dir: PathBuf,
    pub config_path: PathBuf,
    pub private_key_path: PathBuf,
    pub certificate_path: PathBuf,
    pub jwks_path: PathBuf,
    pub log_dir: PathBuf,
}

impl OidcPaths {
    pub fn discover() -> Result<Self> {
        let program_data =
            env::var("PROGRAMDATA").unwrap_or_else(|_| String::from(r"C:\\ProgramData"));
        let base_dir = Path::new(&program_data).join(APP_NAME).join("oidc");
        let log_dir = Path::new(&program_data).join(APP_NAME).join("logs");
        Ok(Self {
            base_dir: base_dir.clone(),
            config_path: base_dir.join("oidc-config.json"),
            private_key_path: base_dir.join("oidc-private-key.pem"),
            certificate_path: base_dir.join("oidc-cert.pem"),
            jwks_path: base_dir.join("oidc-jwks.json"),
            log_dir,
        })
    }
}

pub fn build_router(state: Arc<OidcState>) -> Router {
    #[cfg(windows)]
    {
        Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(openid_configuration),
            )
            .route("/jwks.json", get(jwks))
            .route("/token", post(token))
            .with_state(state)
    }
    #[cfg(not(windows))]
    {
        Router::new().with_state(state)
    }
}

#[cfg(windows)]
fn openid_configuration(State(state): State<Arc<OidcState>>) -> Json<serde_json::Value> {
    let mut scopes: HashSet<String> = HashSet::new();
    for client in state.clients.values() {
        scopes.extend(client.scopes.iter().cloned());
    }
    let scopes: Vec<String> = scopes.into_iter().collect();
    let issuer = state.config.issuer.clone();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "scopes_supported": scopes,
        "grant_types_supported": ["client_credentials", "password"],
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }))
}

#[cfg(windows)]
fn jwks(State(state): State<Arc<OidcState>>) -> Json<serde_json::Value> {
    Json(state.jwks.clone())
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
}

#[derive(Debug)]
enum TokenErrorKind {
    InvalidClient,
    InvalidGrant,
    UnsupportedGrant,
    Internal,
}

struct TokenError {
    kind: TokenErrorKind,
    description: String,
}

impl TokenError {
    fn invalid_client(msg: impl Into<String>) -> Self {
        Self {
            kind: TokenErrorKind::InvalidClient,
            description: msg.into(),
        }
    }

    fn invalid_grant(msg: impl Into<String>) -> Self {
        Self {
            kind: TokenErrorKind::InvalidGrant,
            description: msg.into(),
        }
    }

    fn unsupported_grant(msg: impl Into<String>) -> Self {
        Self {
            kind: TokenErrorKind::UnsupportedGrant,
            description: msg.into(),
        }
    }

    fn internal(msg: impl Into<String>) -> Self {
        Self {
            kind: TokenErrorKind::Internal,
            description: msg.into(),
        }
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let (status, error) = match self.kind {
            TokenErrorKind::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client"),
            TokenErrorKind::InvalidGrant => (StatusCode::BAD_REQUEST, "invalid_grant"),
            TokenErrorKind::UnsupportedGrant => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
            TokenErrorKind::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        let body = json!({
            "error": error,
            "error_description": self.description,
        });
        (status, Json(body)).into_response()
    }
}

#[cfg(windows)]
async fn token(
    State(state): State<Arc<OidcState>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Json<TokenResponse>, TokenError> {
    let (client_id, client_secret) = extract_client_credentials(&headers, &form)?;
    let client = state
        .clients
        .get(&client_id)
        .ok_or_else(|| TokenError::invalid_client("unknown client"))?;
    if !secure_equals(client_secret.as_bytes(), client.client_secret.as_bytes()) {
        return Err(TokenError::invalid_client("invalid client secret"));
    }

    let scope = form
        .scope
        .clone()
        .unwrap_or_else(|| client.scopes.join(" "));

    let grant_type = form.grant_type.as_str();
    let sub = match grant_type {
        "client_credentials" => client_id.clone(),
        "password" => form
            .username
            .clone()
            .ok_or_else(|| TokenError::invalid_grant("username is required for password grant"))?,
        _ => {
            return Err(TokenError::unsupported_grant(format!(
                "{grant_type} not supported"
            )))
        }
    };

    if grant_type == "password" && form.password.is_none() {
        return Err(TokenError::invalid_grant(
            "password is required for password grant",
        ));
    }

    let expires_in = 3600u64;
    let issued_at = OffsetDateTime::now_utc();
    let expiry = issued_at + Duration::seconds(expires_in as i64);
    let aud_claims = compute_audiences(&state.config, form.audience.as_ref())
        .map_err(TokenError::invalid_grant)?;

    let claims = Claims {
        iss: state.config.issuer.clone(),
        sub,
        aud: aud_claims,
        scope: scope.clone(),
        exp: expiry.unix_timestamp() as u64,
        iat: issued_at.unix_timestamp() as u64,
        jti: Uuid::new_v4().to_string(),
        client_id,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(state.key_id.clone());
    header.typ = Some("JWT".to_string());

    let token = encode(&header, &claims, &state.encoding_key)
        .map_err(|err| TokenError::internal(format!("unable to sign token: {err}")))?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "bearer",
        expires_in,
        scope,
    }))
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    scope: String,
    exp: u64,
    iat: u64,
    jti: String,
    client_id: String,
}

fn secure_equals(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

fn extract_client_credentials(
    headers: &HeaderMap,
    form: &TokenForm,
) -> Result<(String, String), TokenError> {
    if let Some((id, secret)) = extract_basic_auth(headers) {
        return Ok((id, secret));
    }
    match (&form.client_id, &form.client_secret) {
        (Some(id), Some(secret)) => Ok((id.clone(), secret.clone())),
        _ => Err(TokenError::invalid_client(
            "client credentials are required",
        )),
    }
}

fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let header_value = headers.get(axum::http::header::AUTHORIZATION)?;
    let header_value = header_value.to_str().ok()?;
    let prefix = "Basic ";
    if !header_value.starts_with(prefix) {
        return None;
    }
    let b64 = &header_value[prefix.len()..];
    let decoded = STANDARD.decode(b64).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let mut split = decoded.splitn(2, ':');
    let id = split.next()?.to_string();
    let secret = split.next()?.to_string();
    Some((id, secret))
}

fn compute_audiences(
    config: &OidcConfig,
    requested: Option<&String>,
) -> Result<Vec<String>, String> {
    if let Some(aud) = requested {
        if config.audiences.iter().any(|value| value == aud) {
            return Ok(vec![aud.clone()]);
        }
        return Err(format!("audience {aud} is not allowed"));
    }
    if config.audiences.is_empty() {
        return Err("no audiences configured".to_string());
    }
    Ok(config.audiences.clone())
}

#[cfg(windows)]
pub fn load_state(paths: &OidcPaths) -> Result<Arc<OidcState>> {
    let config = read_config(&paths.config_path)?;
    let clients = config
        .clients
        .iter()
        .map(|client| (client.client_id.clone(), client.clone()))
        .collect();
    let jwks_contents = fs::read_to_string(&paths.jwks_path)
        .with_context(|| format!("unable to read jwks at {}", paths.jwks_path.display()))?;
    let jwks: serde_json::Value = serde_json::from_str(&jwks_contents)
        .with_context(|| format!("invalid jwks json at {}", paths.jwks_path.display()))?;
    let kid = jwks
        .get("keys")
        .and_then(|keys| keys.get(0))
        .and_then(|key| key.get("kid"))
        .and_then(|kid| kid.as_str())
        .ok_or_else(|| anyhow!("jwks missing kid"))?
        .to_string();
    let key_pem = fs::read(&paths.private_key_path)
        .with_context(|| format!("unable to read key at {}", paths.private_key_path.display()))?;
    let encoding_key = EncodingKey::from_rsa_pem(&key_pem)
        .map_err(|err| anyhow!("failed to load RSA key: {err}"))?;
    Ok(Arc::new(OidcState {
        config,
        clients,
        encoding_key,
        jwks,
        key_id: kid,
    }))
}

fn read_config(path: &Path) -> Result<OidcConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("unable to read config at {}", path.display()))?;
    let cfg: OidcConfig = serde_json::from_str(&raw)
        .with_context(|| format!("invalid config json at {}", path.display()))?;
    Ok(cfg)
}

#[cfg(windows)]
pub fn init_tracing(paths: &OidcPaths) -> Result<()> {
    use std::fs::OpenOptions;
    use std::sync::OnceLock;

    use tracing_appender::non_blocking;
    use tracing_subscriber::fmt::time::UtcTime;
    use tracing_subscriber::FmtSubscriber;

    static GUARD: OnceLock<non_blocking::WorkerGuard> = OnceLock::new();

    fs::create_dir_all(&paths.log_dir)
        .with_context(|| format!("unable to create log directory {}", paths.log_dir.display()))?;
    let log_path = paths.log_dir.join("oidc-service.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("unable to open log file {}", log_path.display()))?;
    let (writer, guard) = non_blocking(file);
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_writer(writer)
        .with_timer(UtcTime::rfc_3339())
        .json()
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|err| anyhow!("unable to set global subscriber: {err}"))?;
    let _ = GUARD.set(guard);
    Ok(())
}

#[cfg(windows)]
pub fn tls_config(paths: &OidcPaths) -> Result<Arc<ServerConfig>> {
    let cert_file = fs::File::open(&paths.certificate_path).with_context(|| {
        format!(
            "unable to open certificate {}",
            paths.certificate_path.display()
        )
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut cert_reader).map_err(|err| anyhow!("invalid certificate: {err}"))?;
    if cert_chain.is_empty() {
        return Err(anyhow!("certificate chain is empty"));
    }

    let key_file = fs::File::open(&paths.private_key_path).with_context(|| {
        format!(
            "unable to open private key {}",
            paths.private_key_path.display()
        )
    })?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys =
        rsa_private_keys(&mut key_reader).map_err(|err| anyhow!("invalid private key: {err}"))?;
    if keys.is_empty() {
        key_reader
            .rewind()
            .map_err(|err| anyhow!("unable to rewind key reader: {err}"))?;
        keys = pkcs8_private_keys(&mut key_reader)
            .map_err(|err| anyhow!("invalid private key: {err}"))?;
    }
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no private key entries found"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|err| anyhow!("unable to build TLS config: {err}"))?;
    Ok(Arc::new(config))
}

#[cfg(windows)]
pub fn spawn_server(
    state: Arc<OidcState>,
    tls_config: Arc<ServerConfig>,
    shutdown_signal: oneshot::Receiver<()>,
) -> Result<JoinHandle<Result<()>>> {
    let port = state.config.port;
    let addr = ([127, 0, 0, 1], port).into();
    let acceptor: TlsAcceptor = tls_config.into();
    let router = build_router(state);

    let handle = tokio::spawn(async move {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind to https://127.0.0.1:{port}"))?;
        info!("listening on https://127.0.0.1:{port}");
        let tcp_stream = TcpListenerStream::new(listener);
        let tls_acceptor = acceptor.clone();
        let svc = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
        let incoming = from_stream(tcp_stream.then(move |stream| {
            let tls_acceptor = tls_acceptor.clone();
            async move {
                match stream {
                    Ok(stream) => match tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => Ok::<_, std::io::Error>(tls_stream),
                        Err(err) => {
                            warn!("TLS handshake failed: {err}");
                            Err(std::io::Error::new(std::io::ErrorKind::Other, err))
                        }
                    },
                    Err(err) => Err(err),
                }
            }
        }));

        axum::serve(incoming, svc)
            .with_graceful_shutdown(async move {
                let _ = shutdown_signal.await;
                info!("shutdown signal received");
            })
            .await
            .map_err(|err| anyhow!("server error: {err}"))?;
        Ok(())
    });
    Ok(handle)
}
