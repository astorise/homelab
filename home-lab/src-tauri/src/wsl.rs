use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::TcpStream as StdTcpStream;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

use crate::dns;
use crate::http;
use crate::oidc::{
    oidc_get_status, oidc_list_clients, register_client_config, ClientOut, RegisterClientIn,
    StatusOut,
};
use anyhow::{anyhow, Context, Result};
use home_pki::ServerCertificateRequest;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Event as CoreEvent, Namespace, Node, Pod, Secret};
use k8s_openapi::api::events::v1::Event as EventsV1Event;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, Time};
use kube::api::{Api, DynamicObject, ListParams, LogParams, Patch, PatchParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::discovery::{self, verbs, Discovery, Scope as DiscoveryScope};
use kube::{Client, Config as KubeClientConfig, ResourceExt};
use regex::Regex;
use reqwest::Url;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::{OsRng, RngCore};
use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig as RustlsClientConfig, ClientConnection, RootCertStore};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use tauri::{AppHandle, Manager};
use tracing::{error, info, warn};

#[derive(Serialize)]
pub struct ProvisionResult {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
pub struct WslOperationResult {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
pub struct WslKubectlExecResult {
    ok: bool,
    instance: String,
    exit_code: Option<i32>,
    command: String,
    trace_id: String,
    duration_ms: u64,
    stdout: String,
    stderr: String,
}

#[derive(Serialize)]
pub struct WslKubeconfigSyncResult {
    ok: bool,
    path: String,
    contexts: Vec<String>,
    skipped: Vec<String>,
    message: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct WindowsKubeconfig {
    #[serde(rename = "apiVersion", default)]
    api_version: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    preferences: serde_yaml::Value,
    #[serde(default)]
    clusters: Vec<KubeNamedCluster>,
    #[serde(default)]
    users: Vec<KubeNamedUser>,
    #[serde(default)]
    contexts: Vec<KubeNamedContext>,
    #[serde(rename = "current-context", default)]
    current_context: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
struct KubeNamedCluster {
    name: String,
    cluster: serde_yaml::Value,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
struct KubeNamedUser {
    name: String,
    user: serde_yaml::Value,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
struct KubeNamedContext {
    name: String,
    context: KubeContextRef,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct KubeContextRef {
    cluster: String,
    user: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Deserialize)]
struct KubectlConfigView {
    #[serde(default, deserialize_with = "deserialize_vec_or_null")]
    clusters: Vec<KubectlNamedCluster>,
    #[serde(default, deserialize_with = "deserialize_vec_or_null")]
    users: Vec<KubectlNamedUser>,
    #[serde(default, deserialize_with = "deserialize_vec_or_null")]
    contexts: Vec<KubectlNamedContext>,
    #[serde(rename = "current-context", default)]
    current_context: Option<String>,
}

#[derive(Deserialize)]
struct KubectlNamedCluster {
    name: String,
    cluster: serde_json::Value,
}

#[derive(Deserialize)]
struct KubectlNamedUser {
    name: String,
    user: serde_json::Value,
}

#[derive(Deserialize)]
struct KubectlNamedContext {
    name: String,
    context: KubectlContextRef,
}

#[derive(Deserialize)]
struct KubectlContextRef {
    cluster: String,
    user: String,
    #[serde(default)]
    namespace: Option<String>,
}

fn deserialize_vec_or_null<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

struct ManagedKubeEntry {
    context_name: String,
    cluster: KubeNamedCluster,
    user: KubeNamedUser,
    context: KubeNamedContext,
}

#[derive(Serialize, Clone, Debug)]
pub struct WslInstance {
    name: String,
    state: String,
    version: Option<String>,
    is_default: bool,
    cluster: Option<WslClusterStatus>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ClusterOidcInfo {
    present: bool,
    client_id: Option<String>,
    scopes: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ClusterRouteBinding {
    host: String,
    port: u16,
}

#[derive(Serialize, Clone, Debug)]
pub struct ClusterProxyInfo {
    inbound_http: u16,
    inbound_https: u16,
    routes: Vec<ClusterRouteBinding>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ClusterDnsEntry {
    name: String,
    a: Vec<String>,
    ttl: Option<u32>,
}

#[derive(Serialize, Clone, Debug)]
pub struct WslClusterStatus {
    domains: Vec<String>,
    proxy: ClusterProxyInfo,
    api_port: u16,
    dns_records: Vec<ClusterDnsEntry>,
    oidc: ClusterOidcInfo,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct WslHostCapabilities {
    nvidia_available: bool,
    nvidia_gpu_names: Vec<String>,
}

const DEFAULT_DOMAIN_TEMPLATE: &str = "{name}.wsl";
const ENV_DOMAIN_TEMPLATES: &str = "HOME_LAB_WSL_DOMAIN_TEMPLATES";
const DEFAULT_DNS_TARGET: &str = "127.0.0.1";
const ENV_DNS_TARGET: &str = "HOME_LAB_WSL_DNS_TARGET";
const DEFAULT_DNS_TTL: u32 = 60;
const ENV_DNS_TTL: &str = "HOME_LAB_WSL_DNS_TTL";
const DEFAULT_HTTP_PORT_BASE: u16 = 2001;
// Ingress backends use an adjacent HTTP/HTTPS pair, so blocks must not overlap.
const DEFAULT_HTTP_PORT_STEP: u16 = 2;
const DEFAULT_HTTP_PORT_MAX: u16 = 60000;
const ENV_HTTP_PORT_BASE: &str = "HOME_LAB_WSL_HTTP_PORT_BASE";
const ENV_HTTP_PORT_STEP: &str = "HOME_LAB_WSL_HTTP_PORT_STEP";
const ENV_HTTP_PORT_MAX: &str = "HOME_LAB_WSL_HTTP_PORT_MAX";
const DEFAULT_HTTP_INBOUND: u16 = 80;
const DEFAULT_HTTPS_INBOUND: u16 = 443;
const ENV_HTTP_INBOUND: &str = "HOME_LAB_WSL_HTTP_INBOUND";
const ENV_HTTPS_INBOUND: &str = "HOME_LAB_WSL_HTTPS_INBOUND";
const DEFAULT_API_PORT: u16 = 6443;
const ENV_API_PORT: &str = "HOME_LAB_WSL_K3S_API_PORT";
const DEFAULT_API_PORT_BASE: u16 = 1001;
// k3s uses an adjacent supervisor listener, so consecutive API ports collide.
const DEFAULT_API_PORT_STEP: u16 = 2;
const DEFAULT_API_PORT_MAX: u16 = 60000;
const ENV_API_PORT_BASE: &str = "HOME_LAB_WSL_K3S_API_PORT_BASE";
const ENV_API_PORT_STEP: &str = "HOME_LAB_WSL_K3S_API_PORT_STEP";
const ENV_API_PORT_MAX: &str = "HOME_LAB_WSL_K3S_API_PORT_MAX";
const DEFAULT_API_INBOUND_PORT: u16 = 6443;
const ENV_API_INBOUND_PORT: &str = "HOME_LAB_WSL_K3S_API_INBOUND_PORT";
const DEFAULT_API_PROXY_SCOPE: &str = "loopback";
const ENV_API_PROXY_SCOPE: &str = "HOME_LAB_WSL_K3S_API_PROXY_SCOPE";
const DEFAULT_K3S_NODEPORT_SPAN: u16 = 57;
const DEFAULT_K3S_NODEPORT_BASE: u16 = 20000;
const DEFAULT_K3S_NODEPORT_STEP: u16 = 100;
const DEFAULT_K3S_NODEPORT_MAX: u16 = 60000;
const ENV_K3S_NODEPORT_BASE: &str = "HOME_LAB_WSL_K3S_NODEPORT_BASE";
const ENV_K3S_NODEPORT_STEP: &str = "HOME_LAB_WSL_K3S_NODEPORT_STEP";
const ENV_K3S_NODEPORT_MAX: &str = "HOME_LAB_WSL_K3S_NODEPORT_MAX";
const DEFAULT_CONTAINERD_STREAM_PORT_BASE: u16 = 10010;
const DEFAULT_K3S_LOCAL_PORT_BASE: u16 = 11040;
const DEFAULT_K3S_LOCAL_PORT_STEP: u16 = 20;
const DEFAULT_SSH_PORT_BASE: u16 = 3001;
const DEFAULT_SSH_PORT_STEP: u16 = 1;
const DEFAULT_SSH_PORT_MAX: u16 = 60000;
const ENV_SSH_PORT_BASE: &str = "HOME_LAB_WSL_SSH_PORT_BASE";
const ENV_SSH_PORT_STEP: &str = "HOME_LAB_WSL_SSH_PORT_STEP";
const ENV_SSH_PORT_MAX: &str = "HOME_LAB_WSL_SSH_PORT_MAX";
const SERVICE_RPC_RETRIES: usize = 8;
const SERVICE_RPC_BASE_DELAY_MS: u64 = 750;
const HTTP_SERVICE_NAME: &str = "HomeHttpService";
const DNS_SERVICE_NAME: &str = "HomeDnsService";
const MANAGED_KUBECONFIG_PREFIX: &str = "home-lab-wsl-";
const K3S_BOOTSTRAP_TIMEOUT_SECONDS: u64 = 180;
const KUBECTL_CONFIG_VIEW_RETRY_ATTEMPTS_AFTER_BOOTSTRAP: usize = 12;
const KUBECTL_CONFIG_VIEW_RETRY_DELAY_MS: u64 = 1000;
const K3S_INIT_SCRIPT_RESOURCE: &str = include_str!("../resources/wsl/k3s-init.sh");
const KUBECTL_EXEC_TIMEOUT_SECONDS: u64 = 25;
const KUBECTL_PREPARE_TIMEOUT_SECONDS: u64 = 45;
const KUBE_CONNECT_TIMEOUT_SECONDS: u64 = 5;
const KUBE_IO_TIMEOUT_SECONDS: u64 = 15;
const KUBE_API_READY_TIMEOUT_SECONDS: u64 = 30;
const KUBE_API_READY_POLL_INTERVAL_MS: u64 = 350;
const KUBECTL_APPLY_MAX_BYTES: usize = 2 * 1024 * 1024;
const KUBECTL_APPLY_FIELD_MANAGER: &str = "home-lab-tauri";
const HOME_LAB_DEFAULT_TLS_SECRET_NAME: &str = "home-lab-default-tls";
const HOME_LAB_DEFAULT_TLS_NAMESPACE: &str = "kube-system";
const HOME_LAB_TRAEFIK_DEPLOYMENT_NAME: &str = "traefik";
const HOME_LAB_TRAEFIK_RESTART_ANNOTATION: &str = "kubectl.kubernetes.io/restartedAt";
const HOME_LAB_TRAEFIK_TLSSTORE_KIND: &str = "TLSStore";
const HOME_LAB_TRAEFIK_TLSSTORE_API_VERSIONS: &[&str] =
    &["traefik.io/v1alpha1", "traefik.containo.us/v1alpha1"];
const HOME_LAB_TRAEFIK_TLSSTORE_DISCOVERY_TIMEOUT_SECONDS: u64 = 45;
const HOME_LAB_TRAEFIK_TLSSTORE_DISCOVERY_INTERVAL_MS: u64 = 1500;
const HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS: u64 = 180;
const HOME_LAB_TRAEFIK_ROLLOUT_POLL_INTERVAL_MS: u64 = 1500;
const HOME_LAB_TRAEFIK_TLS_SERVE_VERIFY_TIMEOUT_SECONDS: u64 = 30;
const HOME_LAB_TRAEFIK_TLS_SERVE_VERIFY_INTERVAL_MS: u64 = 750;
const HOME_LAB_TRAEFIK_TLS_RESTART_MAX_ATTEMPTS: usize = 2;
const HOME_LAB_WSL_INSTANCE_PREFIX: &str = "home-lab-k3s";
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Clone, Debug)]
struct WslExecutionPaths {
    resource_root: PathBuf,
    install_root: PathBuf,
    cache_root: PathBuf,
}

fn env_or_default_u16(var: &str, default: u16) -> u16 {
    match std::env::var(var) {
        Ok(value) => value
            .trim()
            .parse::<u16>()
            .map_err(|_| {
                warn!(
                    target: "wsl",
                    variable = var,
                    value = %value,
                    "Valeur u16 invalide, utilisation de la valeur par defaut"
                )
            })
            .unwrap_or(default),
        Err(_) => default,
    }
}

fn env_or_default_u32(var: &str, default: u32) -> u32 {
    match std::env::var(var) {
        Ok(value) => value
            .trim()
            .parse::<u32>()
            .map_err(|_| {
                warn!(
                    target: "wsl",
                    variable = var,
                    value = %value,
                    "Valeur u32 invalide, utilisation de la valeur par defaut"
                )
            })
            .unwrap_or(default),
        Err(_) => default,
    }
}

fn cluster_domain_templates() -> Vec<String> {
    if let Ok(raw) = std::env::var(ENV_DOMAIN_TEMPLATES) {
        let templates: Vec<String> = raw
            .split(|c| c == ',' || c == ';')
            .map(|chunk| chunk.trim())
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| chunk.to_string())
            .collect();
        if !templates.is_empty() {
            return templates;
        }
    }
    vec![DEFAULT_DOMAIN_TEMPLATE.to_string()]
}

fn cluster_domain_slug(source: &str) -> String {
    let mut slug = String::new();
    let trimmed = source.trim();
    let lower = trimmed.to_ascii_lowercase();
    let mut last_dash = false;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_dash = false;
        } else if matches!(ch, '-' | '_' | '.' | ' ') {
            if !slug.is_empty() && !last_dash {
                slug.push('-');
                last_dash = true;
            }
        }
    }
    let mut slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        slug = "cluster".into();
    }
    if slug.len() > 63 {
        slug.truncate(63);
    }
    slug
}

fn normalize_domain(candidate: &str) -> Option<String> {
    let mut labels = Vec::new();
    for raw_label in candidate.split('.') {
        let mut label = String::new();
        for ch in raw_label.chars() {
            let lower = ch.to_ascii_lowercase();
            if lower.is_ascii_alphanumeric() {
                label.push(lower);
            } else if matches!(lower, '-' | '_' | ' ') {
                if !label.ends_with('-') {
                    label.push('-');
                }
            }
        }
        let label = label.trim_matches('-').to_string();
        if !label.is_empty() {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn cluster_domains(instance: &str) -> Vec<String> {
    let slug = cluster_domain_slug(instance);
    let templates = cluster_domain_templates();
    let mut result = Vec::new();
    for tpl in templates {
        let rendered = if tpl.contains("{name}") {
            tpl.replace("{name}", &slug)
        } else {
            format!("{slug}{tpl}")
        };
        if let Some(domain) = normalize_domain(&rendered) {
            if !result
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(domain.as_str()))
            {
                result.push(domain);
            }
        }
    }
    result
}

fn primary_cluster_domain(instance: &str) -> Option<String> {
    cluster_domains(instance).into_iter().next()
}

fn push_unique_domain(domains: &mut Vec<String>, candidate: String) {
    if !domains
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(candidate.as_str()))
    {
        domains.push(candidate);
    }
}

fn wildcard_domain_for_host(host: &str) -> Option<String> {
    let (_, suffix) = host.split_once('.')?;
    let suffix = suffix.trim().trim_matches('.');
    if suffix.is_empty() {
        None
    } else {
        Some(format!("*.{suffix}"))
    }
}

fn cluster_tls_dns_names(instance: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for host in cluster_domains(instance) {
        push_unique_domain(&mut domains, host.clone());
        if let Some(wildcard) = wildcard_domain_for_host(&host) {
            push_unique_domain(&mut domains, wildcard);
        }
    }
    domains
}

fn indent_yaml_block(value: &str, spaces: usize) -> String {
    let indent = " ".repeat(spaces);
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let trimmed = normalized.trim_end_matches('\n');
    if trimmed.is_empty() {
        return format!("{indent}\n");
    }

    let mut rendered = String::new();
    for line in trimmed.lines() {
        rendered.push_str(&indent);
        rendered.push_str(line);
        rendered.push('\n');
    }
    rendered
}

#[derive(Clone, Debug)]
struct HomeLabDefaultTlsAssets {
    #[cfg(test)]
    cert_pem: String,
    secret_manifest: String,
    #[cfg(test)]
    tls_store_manifest: String,
}

#[derive(Clone, Copy, Debug)]
struct TraefikDeploymentRolloutState {
    desired_replicas: i32,
    observed_generation: i64,
    ready_replicas: i32,
    updated_replicas: i32,
    available_replicas: i32,
    unavailable_replicas: i32,
}

impl TraefikDeploymentRolloutState {
    fn from_deployment(deployment: &Deployment) -> Self {
        let desired_replicas = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.replicas)
            .unwrap_or(1);
        let status = deployment.status.as_ref();
        Self {
            desired_replicas,
            observed_generation: status
                .and_then(|value| value.observed_generation)
                .unwrap_or_default(),
            ready_replicas: status
                .and_then(|value| value.ready_replicas)
                .unwrap_or_default(),
            updated_replicas: status
                .and_then(|value| value.updated_replicas)
                .unwrap_or_default(),
            available_replicas: status
                .and_then(|value| value.available_replicas)
                .unwrap_or_default(),
            unavailable_replicas: status
                .and_then(|value| value.unavailable_replicas)
                .unwrap_or_default(),
        }
    }

    fn is_available(&self) -> bool {
        self.ready_replicas >= self.desired_replicas
            && self.updated_replicas >= self.desired_replicas
            && self.available_replicas >= self.desired_replicas
            && self.unavailable_replicas == 0
    }

    fn is_available_for_generation(&self, expected_generation: i64) -> bool {
        self.observed_generation >= expected_generation && self.is_available()
    }
}

fn render_home_lab_default_tls_secret_manifest(cert_pem: &str, key_pem: &str) -> String {
    let cert_block = indent_yaml_block(cert_pem, 4);
    let key_block = indent_yaml_block(key_pem, 4);
    format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: {secret_name}\n  namespace: {namespace}\ntype: kubernetes.io/tls\nstringData:\n  tls.crt: |\n{cert_block}  tls.key: |\n{key_block}",
        secret_name = HOME_LAB_DEFAULT_TLS_SECRET_NAME,
        namespace = HOME_LAB_DEFAULT_TLS_NAMESPACE,
        cert_block = cert_block,
        key_block = key_block,
    )
}

fn render_home_lab_default_tls_store_manifest(tls_store_api_version: &str) -> String {
    format!(
        "apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: default\n  namespace: {namespace}\nspec:\n  defaultCertificate:\n    secretName: {secret_name}\n",
        api_version = tls_store_api_version,
        kind = HOME_LAB_TRAEFIK_TLSSTORE_KIND,
        namespace = HOME_LAB_DEFAULT_TLS_NAMESPACE,
        secret_name = HOME_LAB_DEFAULT_TLS_SECRET_NAME,
    )
}

fn build_home_lab_default_tls_assets(
    instance: &str,
    _tls_store_api_version: &str,
) -> Result<HomeLabDefaultTlsAssets> {
    let dns_names = cluster_tls_dns_names(instance);
    let common_name = dns_names.first().cloned().ok_or_else(|| {
        anyhow!("Aucun hostname disponible pour le certificat TLS de '{instance}'")
    })?;
    let issued = home_pki::issue_server_certificate(&ServerCertificateRequest {
        common_name,
        dns_names,
        ip_addresses: Vec::new(),
        existing_key_pair_pem: None,
    })?;

    Ok(HomeLabDefaultTlsAssets {
        #[cfg(test)]
        cert_pem: issued.cert_pem.clone(),
        secret_manifest: render_home_lab_default_tls_secret_manifest(
            &issued.cert_pem,
            &issued.key_pem,
        ),
        #[cfg(test)]
        tls_store_manifest: render_home_lab_default_tls_store_manifest(_tls_store_api_version),
    })
}

fn home_lab_default_tls_dns_names_match_instance(
    actual_dns_names: &[String],
    instance: &str,
) -> bool {
    let expected_dns_names = cluster_tls_dns_names(instance);
    expected_dns_names.iter().all(|expected| {
        actual_dns_names
            .iter()
            .any(|actual| actual.eq_ignore_ascii_case(expected))
    })
}

fn home_lab_default_tls_cert_matches_instance(cert_pem: &str, instance: &str) -> Result<bool> {
    if !home_pki::is_certificate_signed_by_current_root(cert_pem)? {
        return Ok(false);
    }

    let actual_dns_names = home_pki::certificate_dns_names(cert_pem)?;
    Ok(home_lab_default_tls_dns_names_match_instance(
        &actual_dns_names,
        instance,
    ))
}

fn kube_api_proxy_route_name(instance: &str) -> String {
    let slug = cluster_domain_slug(instance);
    if slug.is_empty() {
        "kube-api".to_string()
    } else {
        format!("{slug}-kube-api")
    }
}

fn ssh_proxy_route_name(instance: &str) -> String {
    let slug = cluster_domain_slug(instance);
    if slug.is_empty() {
        "cluster-ssh".to_string()
    } else {
        format!("{slug}-ssh")
    }
}

fn dns_target_ipv4() -> String {
    std::env::var(ENV_DNS_TARGET)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_DNS_TARGET.to_string())
}

fn dns_record_ttl() -> u32 {
    let ttl = env_or_default_u32(ENV_DNS_TTL, DEFAULT_DNS_TTL);
    ttl.max(1)
}

fn http_port_base() -> u16 {
    // The configured base is the HTTPS backend port; the paired HTTP port uses base - 1.
    env_or_default_u16(ENV_HTTP_PORT_BASE, DEFAULT_HTTP_PORT_BASE).max(2)
}

fn http_port_step() -> u16 {
    let step = env_or_default_u16(ENV_HTTP_PORT_STEP, DEFAULT_HTTP_PORT_STEP);
    if step < 2 {
        DEFAULT_HTTP_PORT_STEP
    } else {
        step
    }
}

fn http_port_max() -> u16 {
    env_or_default_u16(ENV_HTTP_PORT_MAX, DEFAULT_HTTP_PORT_MAX)
}

fn inbound_http_port() -> u16 {
    env_or_default_u16(ENV_HTTP_INBOUND, DEFAULT_HTTP_INBOUND)
}

fn inbound_https_port() -> u16 {
    env_or_default_u16(ENV_HTTPS_INBOUND, DEFAULT_HTTPS_INBOUND)
}

fn kube_api_proxy_scope() -> http::TcpListenScopeIn {
    match std::env::var(ENV_API_PROXY_SCOPE)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("any") | Some("host") | Some("lan") => http::TcpListenScopeIn::Any,
        _ => match DEFAULT_API_PROXY_SCOPE {
            "any" => http::TcpListenScopeIn::Any,
            _ => http::TcpListenScopeIn::Loopback,
        },
    }
}

fn k3s_api_port_base() -> u16 {
    env_or_default_u16(ENV_API_PORT_BASE, DEFAULT_API_PORT_BASE)
}

fn k3s_api_port_step() -> u16 {
    let step = env_or_default_u16(ENV_API_PORT_STEP, DEFAULT_API_PORT_STEP);
    if step < 2 {
        DEFAULT_API_PORT_STEP
    } else {
        step
    }
}

fn k3s_api_port_max() -> u16 {
    let max = env_or_default_u16(ENV_API_PORT_MAX, DEFAULT_API_PORT_MAX);
    max.max(k3s_api_port_base())
}

fn home_lab_instance_slot(instance: &str) -> Option<u32> {
    let normalized = instance.trim().to_ascii_lowercase();
    if normalized == HOME_LAB_WSL_INSTANCE_PREFIX {
        return Some(0);
    }

    let suffix = normalized.strip_prefix(HOME_LAB_WSL_INSTANCE_PREFIX)?;
    let numeric = suffix.strip_prefix('-')?;
    let parsed = numeric.parse::<u32>().ok()?;
    Some(parsed.saturating_sub(1))
}

fn fallback_instance_hash(instance: &str) -> u32 {
    let mut hash: u32 = 0x811C_9DC5;
    for byte in instance.trim().to_ascii_lowercase().bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn bounded_instance_slot(instance: &str, slots: u32) -> u32 {
    if slots <= 1 {
        return 0;
    }

    if let Some(slot) = home_lab_instance_slot(instance) {
        return slot % slots;
    }

    fallback_instance_hash(instance) % slots
}

fn deterministic_port_for_instance(instance: &str, base: u16, step: u16, max: u16) -> u16 {
    let step = step.max(1);
    let max = max.max(base);
    let slots = ((u32::from(max) - u32::from(base)) / u32::from(step)).saturating_add(1);
    if slots == 0 {
        return base;
    }

    let slot = bounded_instance_slot(instance, slots);
    let offset = slot % slots;
    let computed = u32::from(base) + offset * u32::from(step);
    u16::try_from(computed).unwrap_or(base)
}

fn public_k3s_api_port() -> u16 {
    env_or_default_u16(ENV_API_INBOUND_PORT, DEFAULT_API_INBOUND_PORT)
}

fn k3s_nodeport_base() -> u16 {
    env_or_default_u16(ENV_K3S_NODEPORT_BASE, DEFAULT_K3S_NODEPORT_BASE)
}

fn k3s_nodeport_step() -> u16 {
    let step = env_or_default_u16(ENV_K3S_NODEPORT_STEP, DEFAULT_K3S_NODEPORT_STEP);
    if step == 0 {
        DEFAULT_K3S_NODEPORT_STEP
    } else {
        step
    }
}

fn k3s_nodeport_max() -> u16 {
    let max = env_or_default_u16(ENV_K3S_NODEPORT_MAX, DEFAULT_K3S_NODEPORT_MAX);
    max.max(k3s_nodeport_base())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct K3sLocalPortLayout {
    lb_server_port: u16,
    kubelet_port: u16,
    kubelet_healthz_port: u16,
    kube_controller_manager_secure_port: u16,
    kube_cloud_controller_manager_secure_port: u16,
    kube_scheduler_secure_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InstancePortPlan {
    inbound_http: u16,
    inbound_https: u16,
    api_public_port: u16,
    api_backend_port: u16,
    api_reserved_ports: PortRange,
    ingress_http_backend_port: u16,
    ingress_https_backend_port: u16,
    ssh_public_port: u16,
    nodeport_range: PortRange,
    containerd_stream_port: u16,
    k3s_local: K3sLocalPortLayout,
}

fn k3s_local_port_layout_for_instance(instance: &str) -> K3sLocalPortLayout {
    let base = u32::from(DEFAULT_K3S_LOCAL_PORT_BASE);
    let step = u32::from(DEFAULT_K3S_LOCAL_PORT_STEP);
    let max_offset = 7u32;
    let capacity = ((u32::from(u16::MAX) - base - max_offset) / step).saturating_add(1);
    let slot = bounded_instance_slot(instance, capacity);
    let block_base = base + slot * step;

    let port_at = |offset: u32| -> u16 {
        u16::try_from(block_base + offset).unwrap_or(DEFAULT_K3S_LOCAL_PORT_BASE)
    };

    K3sLocalPortLayout {
        lb_server_port: port_at(0),
        kubelet_port: port_at(1),
        kubelet_healthz_port: port_at(2),
        kube_controller_manager_secure_port: port_at(5),
        kube_cloud_controller_manager_secure_port: port_at(6),
        kube_scheduler_secure_port: port_at(7),
    }
}

fn containerd_stream_port_for_instance(instance: &str) -> u16 {
    let capacity = u32::from(u16::MAX) - u32::from(DEFAULT_CONTAINERD_STREAM_PORT_BASE) + 1;
    let slot = bounded_instance_slot(instance, capacity);
    let port = u32::from(DEFAULT_CONTAINERD_STREAM_PORT_BASE) + slot;
    u16::try_from(port).unwrap_or(DEFAULT_CONTAINERD_STREAM_PORT_BASE)
}

fn instance_port_plan(instance: &str) -> InstancePortPlan {
    let api_backend_port = if std::env::var(ENV_API_PORT).is_ok() {
        env_or_default_u16(ENV_API_PORT, DEFAULT_API_PORT)
    } else {
        deterministic_port_for_instance(
            instance,
            k3s_api_port_base(),
            k3s_api_port_step(),
            k3s_api_port_max(),
        )
    };
    let ingress_https_backend_port = deterministic_port_for_instance(
        instance,
        http_port_base(),
        http_port_step(),
        http_port_max(),
    );
    let nodeport_start = deterministic_port_for_instance(
        instance,
        k3s_nodeport_base(),
        k3s_nodeport_step(),
        k3s_nodeport_max(),
    );

    InstancePortPlan {
        inbound_http: inbound_http_port(),
        inbound_https: inbound_https_port(),
        api_public_port: public_k3s_api_port(),
        api_backend_port,
        api_reserved_ports: PortRange {
            start: api_backend_port,
            end: api_backend_port.saturating_add(1),
        },
        ingress_http_backend_port: ingress_https_backend_port.saturating_sub(1),
        ingress_https_backend_port,
        ssh_public_port: deterministic_port_for_instance(
            instance,
            env_or_default_u16(ENV_SSH_PORT_BASE, DEFAULT_SSH_PORT_BASE),
            env_or_default_u16(ENV_SSH_PORT_STEP, DEFAULT_SSH_PORT_STEP).max(1),
            env_or_default_u16(ENV_SSH_PORT_MAX, DEFAULT_SSH_PORT_MAX),
        ),
        nodeport_range: PortRange {
            start: nodeport_start,
            end: nodeport_start.saturating_add(DEFAULT_K3S_NODEPORT_SPAN),
        },
        containerd_stream_port: containerd_stream_port_for_instance(instance),
        k3s_local: k3s_local_port_layout_for_instance(instance),
    }
}

fn k3s_api_port_for_instance(instance: &str) -> u16 {
    instance_port_plan(instance).api_backend_port
}

fn home_http_config_path() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\home-http\http.yaml")
}

fn write_text_file_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Creation du dossier {}", parent.display()))?;
    }
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, contents)
        .with_context(|| format!("Ecriture du fichier temporaire {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Remplacement atomique de {} par {} impossible",
            path.display(),
            tmp_path.display()
        )
    })?;
    Ok(())
}

fn home_http_set_yaml_string(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
    value: &str,
) -> Result<bool> {
    let key_value = serde_yaml::Value::String(key.to_string());
    let value_value = serde_yaml::to_value(value).context("Conversion YAML string impossible")?;
    let changed = mapping.get(&key_value) != Some(&value_value);
    if changed {
        mapping.insert(key_value, value_value);
    }
    Ok(changed)
}

fn home_http_set_yaml_u64(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
    value: u64,
) -> Result<bool> {
    let key_value = serde_yaml::Value::String(key.to_string());
    let value_value = serde_yaml::to_value(value).context("Conversion YAML numeric impossible")?;
    let changed = mapping.get(&key_value) != Some(&value_value);
    if changed {
        mapping.insert(key_value, value_value);
    }
    Ok(changed)
}

fn home_http_should_skip_wsl_interface(iface: &str) -> bool {
    let iface = iface.trim();
    iface.eq_ignore_ascii_case("lo")
        || iface.starts_with("cni")
        || iface.starts_with("flannel")
        || iface.starts_with("docker")
        || iface.starts_with("veth")
        || iface.starts_with("br-")
        || iface.eq_ignore_ascii_case("kube-ipvs0")
}

fn parse_default_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        tokens.windows(2).find_map(|pair| {
            if pair[0] == "dev" {
                let candidate = pair[1].trim().trim_matches('\0');
                (!candidate.is_empty()).then(|| candidate.to_string())
            } else {
                None
            }
        })
    })
}

fn parse_wsl_instance_ipv4(addr_output: &str, preferred_interface: Option<&str>) -> Option<String> {
    let mut fallback = None::<String>;

    for line in addr_output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(iface) = tokens.get(1).copied() else {
            continue;
        };
        if home_http_should_skip_wsl_interface(iface) {
            continue;
        }
        let Some(inet_index) = tokens.iter().position(|token| *token == "inet") else {
            continue;
        };
        let Some(raw_ip) = tokens.get(inet_index + 1) else {
            continue;
        };
        let Some(host) = raw_ip.split('/').next() else {
            continue;
        };
        let Ok(ip) = host.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        let candidate = ip.to_string();
        if preferred_interface
            .map(|preferred| preferred == iface)
            .unwrap_or(false)
        {
            return Some(candidate);
        }
        if fallback.is_none() {
            fallback = Some(candidate);
        }
    }

    fallback
}

async fn resolve_wsl_instance_host_ipv4(instance: &str, trace_id: &str) -> Result<String> {
    const SPLIT_MARKER: &str = "__HOME_LAB_SPLIT__";
    let instance_owned = instance.to_string();
    let script = format!(
        "ip -o -4 route show default 2>/dev/null || true; printf '{SPLIT_MARKER}\\n'; ip -o -4 addr show scope global 2>/dev/null || true"
    );
    let output = tauri::async_runtime::spawn_blocking(move || {
        Command::new("wsl.exe")
            .args(["-d", &instance_owned, "--", "sh", "-lc", &script])
            .output()
    })
    .await
    .context("JoinHandle resolution IP WSL impossible")?
    .context("Execution wsl.exe pour resolution IP WSL impossible")?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    if !output.status.success() {
        anyhow::bail!(
            "Impossible de resoudre l'IP WSL de '{}' (code={:?}, stdout='{}', stderr='{}').",
            instance,
            output.status.code(),
            stdout.trim(),
            stderr.trim()
        );
    }

    let (route_section, addr_section) = stdout
        .split_once(SPLIT_MARKER)
        .unwrap_or(("", stdout.as_str()));
    let preferred_interface = parse_default_route_interface(route_section);
    let ip =
        parse_wsl_instance_ipv4(addr_section, preferred_interface.as_deref()).ok_or_else(|| {
            anyhow!(
                "Aucune IPv4 WSL joignable n'a pu etre detectee pour '{}'.",
                instance
            )
        })?;

    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        wsl_ip = %ip,
        preferred_interface = %preferred_interface.as_deref().unwrap_or(""),
        "Adresse IPv4 WSL retenue pour home-http"
    );
    log_wsl_event(format!(
        "[{trace_id}] IP WSL retenue pour {}: {} (iface={})",
        escape_for_log(instance),
        escape_for_log(&ip),
        escape_for_log(preferred_interface.as_deref().unwrap_or(""))
    ));

    Ok(ip)
}

fn update_home_http_wsl_ip_config(ip: &str) -> Result<bool> {
    let path = home_http_config_path();
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Lecture de {} impossible", path.display()))?;
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&raw).with_context(|| format!("YAML invalide: {}", path.display()))?;
    let mapping = value.as_mapping_mut().ok_or_else(|| {
        anyhow!(
            "La configuration home-http {} n'est pas une mapping YAML.",
            path.display()
        )
    })?;

    let mut changed = false;
    changed |= home_http_set_yaml_string(mapping, "wsl_resolve", "manual")?;
    changed |= home_http_set_yaml_string(mapping, "wsl_ip", ip)?;
    changed |= home_http_set_yaml_u64(mapping, "wsl_refresh_secs", 30)?;

    if !changed {
        return Ok(false);
    }

    let rendered = serde_yaml::to_string(&value)
        .with_context(|| format!("Serialisation YAML impossible pour {}", path.display()))?;
    write_text_file_atomic(&path, &rendered)?;
    Ok(true)
}

async fn sync_home_http_wsl_target(instance: &str, trace_id: &str) -> Result<()> {
    if !is_home_lab_wsl_instance(instance) {
        return Ok(());
    }

    let wsl_ip = resolve_wsl_instance_host_ipv4(instance, trace_id).await?;
    let changed = tauri::async_runtime::spawn_blocking({
        let wsl_ip = wsl_ip.clone();
        move || update_home_http_wsl_ip_config(&wsl_ip)
    })
    .await
    .context("JoinHandle mise a jour config home-http impossible")?
    .context("Mise a jour config home-http impossible")?;

    if changed {
        retry_http_rpc("reload_config", || http::http_reload_config())
            .await
            .context("Reload config home-http impossible")?;
        info!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            wsl_ip = %wsl_ip,
            "Configuration home-http synchronisee avec l'IP WSL"
        );
        log_wsl_event(format!(
            "[{trace_id}] home-http synchronise avec l'IP WSL pour {}: {}",
            escape_for_log(instance),
            escape_for_log(&wsl_ip)
        ));
    }

    Ok(())
}

async fn configure_cluster_networking(instance: &str) -> Result<String> {
    let hosts = cluster_domains(instance);
    if hosts.is_empty() {
        anyhow::bail!("Aucun nom de domaine valide pour l'instance {instance}");
    }

    sync_home_http_wsl_target(instance, "configure-cluster-networking").await?;

    let plan = instance_port_plan(instance);
    let https_backend_port = plan.ingress_https_backend_port;

    let mut applied_hosts = Vec::new();
    for host in &hosts {
        retry_http_rpc("add_route", || {
            http::http_add_route(host.clone(), https_backend_port as u32)
        })
        .await
        .map_err(|e| anyhow!("http_add_route({host}): {e}"))?;
        applied_hosts.push(host.clone());
    }

    let dns_ip = dns_target_ipv4();
    let ttl = dns_record_ttl();
    for host in &hosts {
        retry_dns_rpc("add_record", || {
            dns::dns_add_record(host.clone(), "A".into(), dns_ip.clone(), ttl)
        })
        .await
        .map_err(|e| anyhow!("dns_add_record({host}): {e}"))?;
    }

    let api_public_port = plan.api_public_port;
    let api_backend_port = plan.api_backend_port;
    let tcp_route_name = kube_api_proxy_route_name(instance);
    let api_scope = kube_api_proxy_scope();
    let api_server_name = primary_cluster_domain(instance)
        .ok_or_else(|| anyhow!("Aucun domaine principal pour l'instance {instance}"))?;
    retry_http_rpc("add_tcp_route", || {
        http::http_add_tcp_route(http::TcpRouteIn {
            name: tcp_route_name.clone(),
            listen_port: api_public_port as u32,
            target_port: api_backend_port as u32,
            listen_scope: api_scope,
            target_kind: http::TcpTargetKindIn::Wsl,
            target_host: None,
            server_name: Some(api_server_name.clone()),
        })
    })
    .await
    .map_err(|e| anyhow!("http_add_tcp_route({tcp_route_name}): {e}"))?;

    let ssh_public_port = plan.ssh_public_port;
    let ssh_route_name = ssh_proxy_route_name(instance);
    retry_http_rpc("add_tcp_route", || {
        http::http_add_tcp_route(http::TcpRouteIn {
            name: ssh_route_name.clone(),
            listen_port: ssh_public_port as u32,
            target_port: ssh_public_port as u32,
            listen_scope: api_scope,
            target_kind: http::TcpTargetKindIn::Wsl,
            target_host: None,
            server_name: None,
        })
    })
    .await
    .map_err(|e| anyhow!("http_add_tcp_route({ssh_route_name}): {e}"))?;

    info!(
        target: "wsl",
        instance = %instance,
        hosts = %applied_hosts.join(","),
        https_backend_port,
        api_public_port,
        api_backend_port,
        ssh_public_port,
        dns_ip = %dns_ip,
        ttl,
        "Configuration DNS/HTTP/TCP appliquee pour l'instance WSL"
    );
    log_wsl_event(format!(
        "Configuration DNS/HTTP/TCP pour {}: hosts={} https_backend_port={} api_public_port={} api_backend_port={} ssh_public_port={} ip={} ttl={}",
        escape_for_log(instance),
        escape_for_log(&applied_hosts.join(",")),
        https_backend_port,
        api_public_port,
        api_backend_port,
        ssh_public_port,
        escape_for_log(&dns_ip),
        ttl
    ));

    Ok(format!(
        "DNS/HTTP/TCP configures pour {} (https-backend={}, api-public={}, ssh-public={}).",
        applied_hosts.join(", "),
        https_backend_port,
        api_public_port,
        ssh_public_port
    ))
}

async fn start_service_if_needed(service_name: &str) {
    let name = service_name.to_string();
    let name_log = escape_for_log(&name);
    let result = tauri::async_runtime::spawn_blocking(move || {
        Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(format!(
                "Try {{ $svc = Get-Service -Name '{name}' -ErrorAction Stop; if ($svc.Status -ne 'Running') {{ Start-Service -Name '{name}' -ErrorAction Stop; Write-Output 'started' }} else {{ Write-Output 'already-running' }} }} Catch {{ Write-Output ('error: ' + $_.Exception.Message) }}",
            ))
            .output()
    })
    .await;

    match result {
        Ok(Ok(output)) => {
            let stdout = decode_cli_output(&output.stdout);
            let stderr = decode_cli_output(&output.stderr);
            let stdout_trim = stdout.trim();
            let stderr_trim = stderr.trim();
            if !output.status.success() || stdout_trim.starts_with("error:") {
                warn!(
                    target: "wsl",
                    service = %name_log,
                    status = %output.status,
                    stdout = %escape_for_log(stdout_trim),
                    stderr = %escape_for_log(stderr_trim),
                    "Start-Service attempt failed"
                );
                log_wsl_event(format!(
                    "Start-Service {name_log} failed: status={} stdout={} stderr={}",
                    output.status,
                    escape_for_log(stdout_trim),
                    escape_for_log(stderr_trim)
                ));
            } else {
                info!(
                    target: "wsl",
                    service = %name_log,
                    status = %output.status,
                    stdout = %escape_for_log(stdout_trim),
                    "Start-Service invoked"
                );
                log_wsl_event(format!(
                    "Start-Service {name_log}: status={} stdout={}",
                    output.status,
                    escape_for_log(stdout_trim)
                ));
            }
        }
        Ok(Err(err)) => {
            warn!(
                target: "wsl",
                service = %name_log,
                error = %err,
                "Start-Service command failed to run"
            );
            log_wsl_event(format!(
                "Start-Service {name_log} failed to run: {}",
                escape_for_log(&err.to_string())
            ));
        }
        Err(err) => {
            warn!(
                target: "wsl",
                service = %name_log,
                error = %err,
                "Start-Service JoinHandle failed"
            );
            log_wsl_event(format!(
                "Start-Service {name_log} JoinHandle failed: {}",
                escape_for_log(&err.to_string())
            ));
        }
    }
}

async fn retry_http_rpc<T, Fut>(op_name: &str, mut op: impl FnMut() -> Fut) -> Result<T>
where
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut last_error = String::new();
    for attempt in 1..=SERVICE_RPC_RETRIES {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_error = err.clone();
                warn!(
                    target: "wsl",
                    attempt,
                    op = op_name,
                    error = %err,
                    "HTTP RPC attempt failed"
                );
                if attempt == 1 {
                    start_service_if_needed(HTTP_SERVICE_NAME).await;
                }
                if attempt < SERVICE_RPC_RETRIES {
                    let delay = SERVICE_RPC_BASE_DELAY_MS * attempt as u64;
                    sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }
    Err(anyhow!(
        "HTTP service unreachable after {} attempts (op={}): {}",
        SERVICE_RPC_RETRIES,
        op_name,
        last_error
    ))
}

async fn retry_dns_rpc<T, Fut>(op_name: &str, mut op: impl FnMut() -> Fut) -> Result<T>
where
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut last_error = String::new();
    for attempt in 1..=SERVICE_RPC_RETRIES {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_error = err.clone();
                warn!(
                    target: "wsl",
                    attempt,
                    op = op_name,
                    error = %err,
                    "DNS RPC attempt failed"
                );
                if attempt == 1 {
                    start_service_if_needed(DNS_SERVICE_NAME).await;
                }
                if attempt < SERVICE_RPC_RETRIES {
                    let delay = SERVICE_RPC_BASE_DELAY_MS * attempt as u64;
                    sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }
    Err(anyhow!(
        "DNS service unreachable after {} attempts (op={}): {}",
        SERVICE_RPC_RETRIES,
        op_name,
        last_error
    ))
}

async fn attach_cluster_details(instances: &mut [WslInstance]) {
    if instances.is_empty() {
        return;
    }

    let http_routes = match http::http_list_routes().await {
        Ok(list) => Some(list.routes),
        Err(err) => {
            warn!(
                target: "wsl",
                error = %err,
                "Impossible de recuperer la liste des routes HTTP"
            );
            None
        }
    };

    let dns_records = match dns::dns_list_records().await {
        Ok(list) => Some(list.records),
        Err(err) => {
            warn!(
                target: "wsl",
                error = %err,
                "Impossible de recuperer les enregistrements DNS"
            );
            None
        }
    };

    let oidc_clients: Option<Vec<ClientOut>> = match oidc_list_clients().await {
        Ok(list) => Some(list.clients),
        Err(err) => {
            warn!(
                target: "wsl",
                error = %err,
                "Impossible de recuperer les clients OIDC"
            );
            None
        }
    };

    for instance in instances.iter_mut() {
        let plan = instance_port_plan(&instance.name);
        let domains = cluster_domains(&instance.name);
        if domains.is_empty() {
            instance.cluster = None;
            continue;
        }

        let mut routes = Vec::new();
        if let Some(all_routes) = http_routes.as_ref() {
            for route in all_routes {
                if domains
                    .iter()
                    .any(|domain| domain.eq_ignore_ascii_case(&route.host))
                {
                    if let Ok(port) = u16::try_from(route.port) {
                        if !routes.iter().any(|binding: &ClusterRouteBinding| {
                            binding.host.eq_ignore_ascii_case(&route.host)
                        }) {
                            routes.push(ClusterRouteBinding {
                                host: route.host.clone(),
                                port,
                            });
                        }
                    }
                }
            }
        }

        let dns_entries = if let Some(all_records) = dns_records.as_ref() {
            let mut entries = Vec::new();
            for record in all_records {
                if domains
                    .iter()
                    .any(|domain| domain.eq_ignore_ascii_case(&record.name))
                {
                    entries.push(ClusterDnsEntry {
                        name: record.name.clone(),
                        a: record.a.clone(),
                        ttl: if record.ttl == 0 {
                            None
                        } else {
                            Some(record.ttl)
                        },
                    });
                }
            }
            entries
        } else {
            Vec::new()
        };

        let oidc_info = if let Some(clients) = oidc_clients.as_ref() {
            if let Some(client) = clients
                .iter()
                .find(|client| client.subject.eq_ignore_ascii_case(&instance.name))
            {
                ClusterOidcInfo {
                    present: true,
                    client_id: Some(client.client_id.clone()),
                    scopes: client.allowed_scopes.clone(),
                }
            } else {
                ClusterOidcInfo::default()
            }
        } else {
            ClusterOidcInfo::default()
        };

        instance.cluster = Some(WslClusterStatus {
            domains,
            proxy: ClusterProxyInfo {
                inbound_http: plan.inbound_http,
                inbound_https: plan.inbound_https,
                routes,
            },
            api_port: plan.api_public_port,
            dns_records: dns_entries,
            oidc: oidc_info,
        });
    }
}

fn decode_cli_output(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    if let Ok(utf8) = std::str::from_utf8(data) {
        if !utf8.contains('\0') {
            return utf8.to_string();
        }
    }

    if data.len() % 2 == 0 {
        let utf16: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        if let Ok(text) = String::from_utf16(&utf16) {
            return text;
        }
        return String::from_utf16_lossy(&utf16);
    }

    String::from_utf8_lossy(data).into_owned()
}

fn escape_for_log(input: &str) -> String {
    input.escape_debug().to_string()
}

fn format_cli_command(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return program.to_string();
    }

    let rendered_args: Vec<String> = args
        .iter()
        .map(|arg| {
            if arg
                .chars()
                .any(|c| c.is_whitespace() || c == '"' || c == '\'')
            {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg.to_string()
            }
        })
        .collect();

    format!("{} {}", program, rendered_args.join(" "))
}

fn normalize_windows_path_for_cli(path: &Path) -> PathBuf {
    let rendered = path.as_os_str().to_string_lossy();

    if let Some(rest) = rendered.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{}", rest));
    }

    if let Some(rest) = rendered.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }

    path.to_path_buf()
}

fn wsl_cli_reports_missing_system_file(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("the system cannot find the file specified")
        || lower.contains("le fichier specifie est introuvable")
        || lower.contains("le fichier spécifié est introuvable")
}

fn annotate_wsl_cli_failure(message: &str) -> String {
    if !wsl_cli_reports_missing_system_file(message) {
        return message.to_string();
    }

    let hint = "WSL ne repond pas correctement sur cet hote. Verifiez que WSL est installe puis redemarrez Windows (souvent requis apres 'wsl --install --no-distribution') avant de relancer Home Lab.";
    if message.contains(hint) {
        return message.to_string();
    }

    format!("{message}\n{hint}")
}

static WSL_LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static KUBECTL_TRACE_SEQ: AtomicU64 = AtomicU64::new(1);

fn wsl_log_lock() -> &'static Mutex<()> {
    WSL_LOG_LOCK.get_or_init(|| Mutex::new(()))
}

fn wsl_log_file_path() -> PathBuf {
    let base = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
    base.join("home-lab").join("logs").join("wsl-actions.log")
}

fn epoch_timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            let millis = duration.subsec_millis();
            format!("{secs}.{millis:03}")
        }
        Err(_) => "0".to_string(),
    }
}

fn next_kubectl_trace_id() -> String {
    let seq = KUBECTL_TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("k8s-{millis}-{seq}")
}

fn elapsed_ms(started_at: &Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn append_wsl_log(message: &str) -> std::io::Result<()> {
    let path = wsl_log_file_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "[{}] {}", epoch_timestamp(), message)?;
    Ok(())
}

fn log_wsl_event(message: impl AsRef<str>) {
    let sanitized = message.as_ref().replace('\r', "\\r").replace('\n', "\\n");

    let lock = wsl_log_lock().lock();
    if let Ok(_guard) = lock {
        if let Err(err) = append_wsl_log(&sanitized) {
            warn!(target: "wsl", "Echec ecriture log WSL: {err}");
        }
    } else {
        warn!(target: "wsl", "Impossible d'obtenir le verrou du journal WSL");
    }
}

fn append_provision_message(target: &mut String, extra: &str) {
    if extra.trim().is_empty() {
        return;
    }
    if !target.trim().is_empty() {
        target.push('\n');
    }
    target.push_str(extra);
}

fn sanitize_cli_field(value: &str) -> String {
    fn is_disallowed(c: char) -> bool {
        matches!(
            c,
            '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{feff}'
                | '\u{fffd}'
        ) || c.is_control()
    }

    let filtered: String = value.chars().filter(|c| !is_disallowed(*c)).collect();
    filtered.trim().to_string()
}

fn sanitize_wsl_instance_name(raw: &str) -> Result<String> {
    let sanitized = sanitize_cli_field(raw);
    if sanitized.is_empty() {
        return Err(anyhow!("Le nom de l'instance WSL est requis."));
    }

    if sanitized.len() > 60 {
        return Err(anyhow!(
            "Le nom de l'instance WSL est trop long (60 caractères maximum)."
        ));
    }

    let valid = sanitized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '));
    if !valid {
        return Err(anyhow!(
            "Le nom de l'instance WSL ne peut contenir que des lettres, chiffres, espaces, points, tirets ou underscores."
        ));
    }

    Ok(sanitized)
}

fn resolve_install_dir(app: &AppHandle) -> Result<PathBuf> {
    if let Some(pd) = std::env::var_os("PROGRAMDATA") {
        return Ok(PathBuf::from(pd).join("home-lab").join("wsl"));
    }

    app.path()
        .app_data_dir()
        .map(|p| p.join("wsl"))
        .context("Impossible de déterminer le dossier d'installation WSL")
}

fn default_home_lab_data_root() -> PathBuf {
    if let Some(pd) = std::env::var_os("PROGRAMDATA") {
        return PathBuf::from(pd).join("home-lab");
    }

    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("home-lab");
    }

    std::env::temp_dir().join("home-lab")
}

fn default_home_lab_cache_root() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("home-lab").join("cache");
    }

    default_home_lab_data_root().join("cache")
}

fn resolve_wsl_resource_root(app: Option<&AppHandle>) -> Result<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(app) = app {
        if let Ok(resource_dir) = app.path().resource_dir() {
            candidates.push(resource_dir.join("wsl"));
            candidates.push(resource_dir.join("resources").join("wsl"));
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(bin_dir) = exe_path.parent() {
            candidates.push(bin_dir.join("wsl"));
            candidates.push(bin_dir.join("resources").join("wsl"));

            if let Some(install_dir) = bin_dir.parent() {
                candidates.push(install_dir.join("wsl"));
                candidates.push(install_dir.join("resources").join("wsl"));
            }
        }
    }

    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("wsl"),
    );

    for candidate in &candidates {
        if candidate.join("setup-wsl.ps1").exists() && candidate.join("wsl-rootfs.tar").exists() {
            return Ok(candidate.clone());
        }
    }

    let searched = candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(anyhow!(
        "Impossible de trouver les ressources WSL (setup-wsl.ps1 et wsl-rootfs.tar). Dossiers testes: {searched}"
    ))
}

fn wsl_execution_paths_from_app(app: &AppHandle) -> Result<WslExecutionPaths> {
    let cache_root = app
        .path()
        .app_cache_dir()
        .unwrap_or_else(|_| default_home_lab_cache_root());
    Ok(WslExecutionPaths {
        resource_root: resolve_wsl_resource_root(Some(app))?,
        install_root: resolve_install_dir(app)?,
        cache_root,
    })
}

fn wsl_execution_paths_headless() -> Result<WslExecutionPaths> {
    Ok(WslExecutionPaths {
        resource_root: resolve_wsl_resource_root(None)?,
        install_root: default_home_lab_data_root().join("wsl"),
        cache_root: default_home_lab_cache_root(),
    })
}

fn cluster_config_root() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir())
        .join("home-oidc")
        .join("clusters")
}

fn windows_kubeconfig_path() -> Result<PathBuf> {
    let home_dir = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .ok_or_else(|| anyhow!("Impossible de determiner le repertoire utilisateur Windows"))?;
    Ok(home_dir.join(".kube").join("config"))
}

fn managed_kube_base_name(instance: &str) -> String {
    let slug = cluster_domain_slug(instance);
    let id = if slug.trim().is_empty() {
        "cluster".to_string()
    } else {
        slug
    };
    format!("{MANAGED_KUBECONFIG_PREFIX}{id}")
}

fn is_managed_kube_name(name: &str) -> bool {
    name.starts_with(MANAGED_KUBECONFIG_PREFIX)
}

fn load_windows_kubeconfig(path: &Path) -> Result<WindowsKubeconfig> {
    if !path.exists() {
        return Ok(WindowsKubeconfig::default());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("Lecture du kubeconfig Windows {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(WindowsKubeconfig::default());
    }

    serde_yaml::from_str(&raw)
        .with_context(|| format!("Deserialisation du kubeconfig Windows {}", path.display()))
}

fn save_windows_kubeconfig(path: &Path, mut config: WindowsKubeconfig) -> Result<()> {
    if config
        .api_version
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        config.api_version = Some("v1".to_string());
    }
    if config
        .kind
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        config.kind = Some("Config".to_string());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Creation du dossier kubeconfig {}", parent.display()))?;
    }

    let rendered =
        serde_yaml::to_string(&config).context("Serialisation du kubeconfig Windows impossible")?;
    fs::write(path, rendered)
        .with_context(|| format!("Ecriture du kubeconfig Windows {}", path.display()))?;
    Ok(())
}

fn read_instance_kubectl_config_view_once(instance: &str) -> Result<KubectlConfigView> {
    let command_line = format_cli_command(
        "wsl.exe",
        &[
            "-d",
            instance,
            "--",
            "/usr/local/bin/k3s",
            "kubectl",
            "--kubeconfig",
            "/etc/rancher/k3s/k3s.yaml",
            "config",
            "view",
            "--raw",
            "-o",
            "json",
        ],
    );

    let output = Command::new("wsl.exe")
        .args([
            "-d",
            instance,
            "--",
            "/usr/local/bin/k3s",
            "kubectl",
            "--kubeconfig",
            "/etc/rancher/k3s/k3s.yaml",
            "config",
            "view",
            "--raw",
            "-o",
            "json",
        ])
        .output()
        .with_context(|| {
            format!(
                "Impossible d'executer la commande kubectl pour l'instance {}",
                instance
            )
        })?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    if !output.status.success() {
        anyhow::bail!(
            "kubectl config view a echoue pour {} (cmd={}): {}",
            instance,
            command_line,
            if !stderr_trim.is_empty() {
                stderr_trim
            } else if !stdout_trim.is_empty() {
                stdout_trim
            } else {
                "erreur inconnue"
            }
        );
    }

    if stdout_trim.is_empty() {
        anyhow::bail!("Aucune sortie kubectl pour l'instance {}", instance);
    }

    serde_json::from_str::<KubectlConfigView>(stdout_trim).with_context(|| {
        format!(
            "Impossible de parser la sortie kubectl (instance={}, stdout={}, stderr={})",
            instance, stdout_log, stderr_log
        )
    })
}

fn kubectl_view_has_required_entries(view: &KubectlConfigView) -> bool {
    !view.contexts.is_empty() && !view.clusters.is_empty() && !view.users.is_empty()
}

fn run_wsl_shell_script_via_stdin(
    instance: &str,
    script: &str,
    description: &str,
) -> Result<(String, String)> {
    let command_line = format_cli_command("wsl.exe", &["-d", instance, "--", "sh", "-s"]);
    let mut child = Command::new("wsl.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-d", instance, "--", "sh", "-s"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "Impossible d'executer le script WSL pour {} ({})",
                instance, description
            )
        })?;

    {
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            anyhow!(
                "Impossible d'ouvrir stdin pour le script WSL {} ({})",
                instance,
                description
            )
        })?;
        stdin.write_all(script.as_bytes()).with_context(|| {
            format!(
                "Ecriture stdin WSL impossible pour {} ({})",
                instance, description
            )
        })?;
        if !script.ends_with('\n') {
            stdin.write_all(b"\n").with_context(|| {
                format!(
                    "Finalisation stdin WSL impossible pour {} ({})",
                    instance, description
                )
            })?;
        }
    }

    let output = child.wait_with_output().with_context(|| {
        format!(
            "Impossible d'attendre le script WSL pour {} ({})",
            instance, description
        )
    })?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();

    if !output.status.success() {
        anyhow::bail!(
            "Script WSL a echoue pour {} ({}, cmd={}): {}",
            instance,
            description,
            command_line,
            if !stderr_trim.is_empty() {
                stderr_trim
            } else if !stdout_trim.is_empty() {
                stdout_trim
            } else {
                "erreur inconnue"
            }
        );
    }

    Ok((stdout, stderr))
}

fn render_k3s_env_file_for_instance(instance: &str) -> Result<String> {
    let plan = instance_port_plan(instance);
    let tls_sans = cluster_domains(instance).join(",");
    let local_ports = plan.k3s_local;

    Ok(format!(
        "WSL_ROLE=server\nK3S_API_PORT={api_port}\nPORT_RANGE={nodeport_start}-{nodeport_end}\nCONTAINERD_STREAM_PORT={stream_port}\nK3S_LB_SERVER_PORT={lb_server_port}\nK3S_KUBELET_PORT={kubelet_port}\nK3S_KUBELET_HEALTHZ_PORT={kubelet_healthz_port}\nK3S_KUBE_CONTROLLER_MANAGER_SECURE_PORT={kube_controller_manager_secure_port}\nK3S_KUBE_CLOUD_CONTROLLER_MANAGER_SECURE_PORT={kube_cloud_controller_manager_secure_port}\nK3S_KUBE_SCHEDULER_SECURE_PORT={kube_scheduler_secure_port}\nK3S_INGRESS_HTTP_PORT={ingress_http_port}\nK3S_INGRESS_HTTPS_PORT={ingress_https_port}\nK3S_GIT_SSH_PORT={ssh_port}\nK3S_TLS_SANS={tls_sans}\n",
        api_port = plan.api_backend_port,
        nodeport_start = plan.nodeport_range.start,
        nodeport_end = plan.nodeport_range.end,
        stream_port = plan.containerd_stream_port,
        lb_server_port = local_ports.lb_server_port,
        kubelet_port = local_ports.kubelet_port,
        kubelet_healthz_port = local_ports.kubelet_healthz_port,
        kube_controller_manager_secure_port = local_ports.kube_controller_manager_secure_port,
        kube_cloud_controller_manager_secure_port =
            local_ports.kube_cloud_controller_manager_secure_port,
        kube_scheduler_secure_port = local_ports.kube_scheduler_secure_port,
        ingress_http_port = plan.ingress_http_backend_port,
        ingress_https_port = plan.ingress_https_backend_port,
        ssh_port = plan.ssh_public_port,
    ))
}

fn render_k3s_env_rewrite_script(env_file: &str) -> String {
    format!(
        r#"PRESERVE_ENABLE_NVIDIA_TOOLKIT=0
if [ -f /etc/k3s-env ]; then
    . /etc/k3s-env || true
    PRESERVE_ENABLE_NVIDIA_TOOLKIT=${{ENABLE_NVIDIA_TOOLKIT:-0}}
fi
cat > /etc/k3s-env <<'EOF'
{env_file}EOF
if [ "$PRESERVE_ENABLE_NVIDIA_TOOLKIT" = "1" ]; then
    printf '%s\n' 'ENABLE_NVIDIA_TOOLKIT=1' >> /etc/k3s-env
fi
"#
    )
}

fn detect_host_nvidia_gpu_names() -> Result<Vec<String>> {
    let detection_script = r#"
$ErrorActionPreference = 'Stop'
$gpus = @(
    Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Name -match 'NVIDIA') -or
            ($_.AdapterCompatibility -match 'NVIDIA') -or
            ($_.PNPDeviceID -match 'VEN_10DE')
        } |
        ForEach-Object { $_.Name } |
        Sort-Object -Unique
)
if ($gpus.Count -eq 0) {
    Write-Output '[]'
} else {
    $gpus | ConvertTo-Json -Compress
}
"#;

    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(detection_script)
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("Impossible d'executer la detection GPU Nvidia")?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();

    if !output.status.success() {
        let message = if !stderr_trim.is_empty() {
            stderr_trim.to_string()
        } else if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            "Detection GPU Nvidia echouee".to_string()
        };
        anyhow::bail!(message);
    }

    if stdout_trim.is_empty() {
        return Ok(Vec::new());
    }

    let parsed = serde_json::from_str::<Vec<String>>(stdout_trim)
        .or_else(|_| serde_json::from_str::<String>(stdout_trim).map(|value| vec![value]))
        .with_context(|| format!("Impossible d'analyser la sortie GPU Nvidia: {stdout_trim}"))?;

    Ok(parsed
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect())
}

fn render_k3s_config_yaml_for_instance(instance: &str) -> String {
    let plan = instance_port_plan(instance);
    let mut config = format!(
        "write-kubeconfig-mode: \"0644\"\nhttps-listen-port: {api_port}\nservice-node-port-range: {nodeport_start}-{nodeport_end}\n",
        api_port = plan.api_backend_port,
        nodeport_start = plan.nodeport_range.start,
        nodeport_end = plan.nodeport_range.end
    );
    let domains = cluster_domains(instance);
    if !domains.is_empty() {
        config.push_str("tls-san:\n");
        for domain in domains {
            config.push_str("  - ");
            config.push_str(&domain);
            config.push('\n');
        }
    }
    config
}

fn repair_k3s_runtime_for_instance(instance: &str) -> Result<()> {
    let k3s_init_script = K3S_INIT_SCRIPT_RESOURCE
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let env_file = render_k3s_env_file_for_instance(instance)?;
    let rewrite_env_script = render_k3s_env_rewrite_script(&env_file);
    let k3s_config_yaml = render_k3s_config_yaml_for_instance(instance);
    let script = format!(
        r#"set -eu
mkdir -p /usr/local/bin /etc/rancher/k3s /var/lib/rancher/k3s/agent/etc/containerd /root/.kube
cat > /usr/local/bin/k3s-init.sh <<'__HOME_LAB_K3S_INIT_EOF__'
{k3s_init_script}
__HOME_LAB_K3S_INIT_EOF__
chmod +x /usr/local/bin/k3s-init.sh
{rewrite_env_script}
mkdir -p /etc/local.d
cat > /etc/wsl.conf <<'EOF'
[boot]
command="sh /usr/local/bin/k3s-init.sh"
EOF
cat > /etc/local.d/k3s.start <<'EOF'
#!/bin/sh
exec sh /usr/local/bin/k3s-init.sh
EOF
chmod +x /etc/local.d/k3s.start
cat > /etc/rancher/k3s/config.yaml <<EOF
{k3s_config_yaml}EOF
rm -f /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl
rm -f /var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl
rm -rf /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d
rm -rf /var/lib/rancher/k3s/agent/etc/containerd/config.toml.d
rm -f /var/lib/rancher/k3s/data/.lock || true
rm -rf /run/k3s-init.lock || true
find /var/lib/rancher/k3s/agent -maxdepth 1 -type f \( -name '*.crt' -o -name '*.key' -o -name '*.kubeconfig' \) -delete 2>/dev/null || true
pkill k3s || true
rm -f /etc/rancher/k3s/k3s.yaml /root/.kube/config || true
"#
    );

    let (stdout, stderr) =
        run_wsl_shell_script_via_stdin(instance, &script, "reparation du runtime k3s")?;

    info!(
        target: "wsl",
        instance = %instance,
        stdout = %escape_for_log(stdout.trim()),
        stderr = %escape_for_log(stderr.trim()),
        "Reparation runtime k3s terminee"
    );
    log_wsl_event(format!(
        "Reparation runtime k3s pour {} terminee: stdout={} stderr={}",
        escape_for_log(instance),
        escape_for_log(stdout.trim()),
        escape_for_log(stderr.trim())
    ));
    Ok(())
}

fn bootstrap_k3s_for_instance_if_available(instance: &str) -> Result<()> {
    let script = format!(
        "set -eu; if [ ! -s /usr/local/bin/k3s-init.sh ] || [ ! -x /usr/local/bin/k3s ]; then exit 0; fi; BOOTSTRAP_ONLY=1 BOOTSTRAP_TIMEOUT={} sh /usr/local/bin/k3s-init.sh",
        K3S_BOOTSTRAP_TIMEOUT_SECONDS
    );
    let command_line = format_cli_command("wsl.exe", &["-d", instance, "--", "sh", "-lc", &script]);

    let output = Command::new("wsl.exe")
        .args(["-d", instance, "--", "sh", "-lc", &script])
        .output()
        .with_context(|| format!("Impossible d'executer k3s-init.sh pour {}", instance))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    if !output.status.success() {
        anyhow::bail!(
            "k3s-init.sh a echoue pour {} (cmd={}): {}",
            instance,
            command_line,
            if !stderr_trim.is_empty() {
                stderr_trim
            } else if !stdout_trim.is_empty() {
                stdout_trim
            } else {
                "erreur inconnue"
            }
        );
    }

    info!(
        target: "wsl",
        instance = %instance,
        command = %command_line,
        stdout = %stdout_log,
        stderr = %stderr_log,
        "Bootstrap k3s termine"
    );
    log_wsl_event(format!(
        "Bootstrap k3s pour {} termine: status={} stdout={} stderr={}",
        escape_for_log(instance),
        output.status,
        stdout_log,
        stderr_log
    ));
    Ok(())
}

fn instance_has_running_k3s_server(instance: &str) -> Result<bool> {
    let script = "set -eu; if pgrep -f '^/usr/local/bin/k3s server( |$)' >/dev/null 2>&1; then printf '%s\\n' yes; fi";
    let command_line = format_cli_command("wsl.exe", &["-d", instance, "--", "sh", "-lc", script]);

    let output = Command::new("wsl.exe")
        .args(["-d", instance, "--", "sh", "-lc", script])
        .output()
        .with_context(|| format!("Impossible de verifier le runtime k3s pour {}", instance))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();

    if !output.status.success() {
        anyhow::bail!(
            "Verification du runtime k3s impossible pour {} (cmd={}): {}",
            instance,
            command_line,
            if !stderr_trim.is_empty() {
                stderr_trim
            } else if !stdout_trim.is_empty() {
                stdout_trim
            } else {
                "erreur inconnue"
            }
        );
    }

    Ok(stdout_trim.eq_ignore_ascii_case("yes"))
}

async fn enforce_instance_api_port_range(instance: &str, _api_port: u16) -> Result<()> {
    let instance_owned = instance.to_string();
    let env_file = render_k3s_env_file_for_instance(instance)?;
    let rewrite_env_script = render_k3s_env_rewrite_script(&env_file);
    let script = format!("set -eu\n{rewrite_env_script}");
    let command_line = format_cli_command("wsl.exe", &["-d", instance, "--", "sh", "-c", &script]);

    let output = tauri::async_runtime::spawn_blocking(move || {
        Command::new("wsl.exe")
            .args(["-d", &instance_owned, "--", "sh", "-c", &script])
            .output()
    })
    .await
    .map_err(|e| anyhow!("Erreur JoinHandle lors de la correction /etc/k3s-env: {e}"))?
    .with_context(|| format!("Impossible de corriger /etc/k3s-env pour '{}'", instance))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    if !output.status.success() {
        anyhow::bail!(
            "Correction /etc/k3s-env impossible pour {} (cmd={}): {}",
            instance,
            command_line,
            if !stderr_trim.is_empty() {
                stderr_trim
            } else if !stdout_trim.is_empty() {
                stdout_trim
            } else {
                "erreur inconnue"
            }
        );
    }
    Ok(())
}

fn read_instance_kubectl_config_view(instance: &str) -> Result<KubectlConfigView> {
    let mut last_issue = match read_instance_kubectl_config_view_once(instance) {
        Ok(first) => {
            if kubectl_view_has_required_entries(&first) {
                return Ok(first);
            }

            let issue = format!(
                "config incomplet (contexts={}, clusters={}, users={})",
                first.contexts.len(),
                first.clusters.len(),
                first.users.len()
            );

            warn!(
                target: "wsl",
                instance = %instance,
                contexts = first.contexts.len(),
                clusters = first.clusters.len(),
                users = first.users.len(),
                "kubectl config view incomplet; tentative de bootstrap k3s"
            );
            log_wsl_event(format!(
                "kubectl config view incomplet pour {} (contexts={}, clusters={}, users={}), tentative bootstrap k3s",
                escape_for_log(instance),
                first.contexts.len(),
                first.clusters.len(),
                first.users.len()
            ));
            Some(issue)
        }
        Err(err) => {
            let issue = err.to_string();
            warn!(
                target: "wsl",
                instance = %instance,
                error = %err,
                "kubectl config view initial indisponible; tentative de bootstrap k3s"
            );
            log_wsl_event(format!(
                "kubectl config view initial indisponible pour {}: {}, tentative bootstrap k3s",
                escape_for_log(instance),
                escape_for_log(&issue)
            ));
            Some(issue)
        }
    };

    if instance_has_running_k3s_server(instance)? {
        warn!(
            target: "wsl",
            instance = %instance,
            "k3s server deja actif; attente du kubeconfig sans bootstrap destructif"
        );
        log_wsl_event(format!(
            "k3s server deja actif pour {}; attente du kubeconfig avant reparation/bootstrap",
            escape_for_log(instance)
        ));

        for attempt in 1..=KUBECTL_CONFIG_VIEW_RETRY_ATTEMPTS_AFTER_BOOTSTRAP {
            match read_instance_kubectl_config_view_once(instance) {
                Ok(view) if kubectl_view_has_required_entries(&view) => return Ok(view),
                Ok(view) => {
                    last_issue = Some(format!(
                        "config toujours incomplet avec k3s deja actif (tentative {attempt}/{}) (contexts={}, clusters={}, users={})",
                        KUBECTL_CONFIG_VIEW_RETRY_ATTEMPTS_AFTER_BOOTSTRAP,
                        view.contexts.len(),
                        view.clusters.len(),
                        view.users.len()
                    ));
                }
                Err(err) => {
                    last_issue = Some(format!(
                        "lecture kubectl impossible avec k3s deja actif (tentative {attempt}/{}): {}",
                        KUBECTL_CONFIG_VIEW_RETRY_ATTEMPTS_AFTER_BOOTSTRAP,
                        err
                    ));
                }
            }

            std::thread::sleep(Duration::from_millis(KUBECTL_CONFIG_VIEW_RETRY_DELAY_MS));
        }
    }

    repair_k3s_runtime_for_instance(instance).with_context(|| {
        format!(
            "Reparation k3s impossible pour {} avant tentative de bootstrap",
            instance
        )
    })?;
    bootstrap_k3s_for_instance_if_available(instance)?;

    for attempt in 1..=KUBECTL_CONFIG_VIEW_RETRY_ATTEMPTS_AFTER_BOOTSTRAP {
        match read_instance_kubectl_config_view_once(instance) {
            Ok(view) if kubectl_view_has_required_entries(&view) => return Ok(view),
            Ok(view) => {
                last_issue = Some(format!(
                    "config incomplet apres bootstrap (tentative {attempt}/{}) (contexts={}, clusters={}, users={})",
                    KUBECTL_CONFIG_VIEW_RETRY_ATTEMPTS_AFTER_BOOTSTRAP,
                    view.contexts.len(),
                    view.clusters.len(),
                    view.users.len()
                ));
            }
            Err(err) => {
                last_issue = Some(format!(
                    "lecture kubectl impossible apres bootstrap (tentative {attempt}/{}): {}",
                    KUBECTL_CONFIG_VIEW_RETRY_ATTEMPTS_AFTER_BOOTSTRAP, err
                ));
            }
        }

        std::thread::sleep(Duration::from_millis(KUBECTL_CONFIG_VIEW_RETRY_DELAY_MS));
    }

    anyhow::bail!(
        "Aucun contexte kubectl disponible pour {} apres tentative de bootstrap k3s (dernier etat: {}).",
        instance,
        last_issue.unwrap_or_else(|| "etat inconnu".to_string())
    )
}

fn build_managed_kube_entry(instance: &str) -> Result<ManagedKubeEntry> {
    let view = read_instance_kubectl_config_view(instance)?;

    let selected_context = if let Some(current) = view.current_context.as_ref() {
        view.contexts
            .iter()
            .find(|ctx| ctx.name == *current)
            .or_else(|| view.contexts.first())
    } else {
        view.contexts.first()
    }
    .ok_or_else(|| anyhow!("Aucun contexte kubectl disponible"))?;

    let selected_cluster = view
        .clusters
        .iter()
        .find(|cluster| cluster.name == selected_context.context.cluster)
        .or_else(|| view.clusters.first())
        .ok_or_else(|| anyhow!("Aucun cluster kubectl disponible"))?;

    let selected_user = view
        .users
        .iter()
        .find(|user| user.name == selected_context.context.user)
        .or_else(|| view.users.first())
        .ok_or_else(|| anyhow!("Aucun utilisateur kubectl disponible"))?;

    let plan = instance_port_plan(instance);
    let base_name = managed_kube_base_name(instance);
    let cluster_name = format!("{base_name}-cluster");
    let user_name = format!("{base_name}-user");
    let context_name = base_name;
    let api_port = if is_home_lab_wsl_instance(instance) {
        plan.api_public_port
    } else {
        plan.api_backend_port
    };
    let api_host = primary_cluster_domain(instance).unwrap_or_else(|| "127.0.0.1".to_string());

    let mut cluster_json = selected_cluster.cluster.clone();
    if let serde_json::Value::Object(map) = &mut cluster_json {
        map.insert(
            "server".to_string(),
            serde_json::Value::String(format!("https://{api_host}:{api_port}")),
        );
        map.remove("tls-server-name");
    }

    let cluster_value = serde_yaml::to_value(&cluster_json).context("Conversion cluster YAML")?;
    let user_value = serde_yaml::to_value(&selected_user.user).context("Conversion user YAML")?;

    Ok(ManagedKubeEntry {
        context_name: context_name.clone(),
        cluster: KubeNamedCluster {
            name: cluster_name.clone(),
            cluster: cluster_value,
            extra: BTreeMap::new(),
        },
        user: KubeNamedUser {
            name: user_name.clone(),
            user: user_value,
            extra: BTreeMap::new(),
        },
        context: KubeNamedContext {
            name: context_name,
            context: KubeContextRef {
                cluster: cluster_name,
                user: user_name,
                namespace: selected_context.context.namespace.clone(),
                extra: BTreeMap::new(),
            },
            extra: BTreeMap::new(),
        },
    })
}

fn sync_windows_kubeconfig_internal() -> Result<WslKubeconfigSyncResult> {
    let path = windows_kubeconfig_path()?;
    let mut config = load_windows_kubeconfig(&path)?;

    config
        .clusters
        .retain(|entry| !is_managed_kube_name(entry.name.as_str()));
    config
        .users
        .retain(|entry| !is_managed_kube_name(entry.name.as_str()));
    config
        .contexts
        .retain(|entry| !is_managed_kube_name(entry.name.as_str()));

    let mut instances = collect_wsl_instances()?;
    instances.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));

    let mut contexts = Vec::new();
    let mut skipped = Vec::new();

    for instance in instances {
        match build_managed_kube_entry(&instance.name) {
            Ok(entry) => {
                contexts.push(entry.context_name.clone());
                config.clusters.push(entry.cluster);
                config.users.push(entry.user);
                config.contexts.push(entry.context);
            }
            Err(err) => {
                let reason = format!("{}: {}", instance.name, err);
                warn!(target: "wsl", instance = %instance.name, error = %err, "Kubeconfig WSL ignore pour cette instance");
                skipped.push(reason);
            }
        }
    }

    if let Some(current) = config.current_context.as_ref() {
        let is_missing = !config.contexts.iter().any(|ctx| &ctx.name == current);
        if is_managed_kube_name(current) && is_missing {
            config.current_context = contexts.first().cloned();
        }
    }

    save_windows_kubeconfig(&path, config)?;

    let message = if contexts.is_empty() {
        format!(
            "Kubeconfig Windows synchronise (aucun contexte Home Lab actif) dans {}.",
            path.display()
        )
    } else if skipped.is_empty() {
        format!(
            "Kubeconfig Windows synchronise: {} contexte(s) Home Lab ecrit(s) dans {}.",
            contexts.len(),
            path.display()
        )
    } else {
        format!(
            "Kubeconfig Windows synchronise: {} contexte(s) Home Lab ecrit(s), {} instance(s) ignoree(s).",
            contexts.len(),
            skipped.len()
        )
    };

    Ok(WslKubeconfigSyncResult {
        ok: true,
        path: path.display().to_string(),
        contexts,
        skipped,
        message,
    })
}

async fn sync_windows_kubeconfig_task() -> Result<WslKubeconfigSyncResult> {
    tauri::async_runtime::spawn_blocking(sync_windows_kubeconfig_internal)
        .await
        .map_err(|e| anyhow!("Erreur JoinHandle lors de la synchronisation kubeconfig: {e}"))?
}

fn persist_cluster_credentials(
    instance: &str,
    client_id: &str,
    private_key: &str,
    public_key: &str,
    status: &StatusOut,
    scopes: &[String],
) -> Result<PathBuf> {
    let dir = cluster_config_root().join(instance);
    fs::create_dir_all(&dir).with_context(|| format!("Création de {}", dir.display()))?;
    fs::write(dir.join("oidc-client.key"), private_key)
        .with_context(|| "Écriture de la clé privée OIDC")?;
    fs::write(dir.join("oidc-client.pub"), public_key)
        .with_context(|| "Écriture de la clé publique OIDC")?;
    let metadata = json!({
        "client_id": client_id,
        "issuer": status.issuer,
        "token_endpoint": status.token_endpoint,
        "allowed_scopes": scopes,
    });
    fs::write(
        dir.join("oidc-client.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )
    .with_context(|| "Écriture du fichier de configuration OIDC")?;
    Ok(dir)
}

async fn configure_k3s_oidc_client(instance: &str) -> Result<String> {
    let mut rng = OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 4096).context("Génération de la clé privée OIDC")?;
    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("Sérialisation de la clé privée")?
        .to_string();
    let public_key = private_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .context("Sérialisation de la clé publique")?;
    let suffix = rng.next_u32();
    let normalized = instance.to_lowercase();
    let client_id = format!("k3s-{normalized}-{suffix:08x}");
    let scopes = vec!["k3s.admin".to_string()];
    let ack = register_client_config(RegisterClientIn {
        client_id: client_id.clone(),
        subject: Some(instance.to_string()),
        allowed_scopes: scopes.clone(),
        audiences: Vec::new(),
        public_key_pem: public_key.clone(),
        auth_method: Some("private_key_jwt".into()),
    })
    .await
    .map_err(|e| anyhow!(e))?;
    if !ack.ok {
        anyhow::bail!(ack.message);
    }
    let status = oidc_get_status().await.map_err(|e| anyhow!(e))?;
    let dir = persist_cluster_credentials(
        instance,
        &client_id,
        &private_pem,
        &public_key,
        &status,
        &scopes,
    )?;
    Ok(format!(
        "OIDC client '{client_id}' enregistré. Clés stockées dans {}.",
        dir.display()
    ))
}

async fn wsl_import_instance_with_paths(
    paths: WslExecutionPaths,
    force: Option<bool>,
    name: Option<String>,
    enable_nvidia: Option<bool>,
) -> Result<ProvisionResult, String> {
    let force_import = force.unwrap_or(false);
    let enable_nvidia = enable_nvidia.unwrap_or(false);
    let provided_name = name.unwrap_or_else(|| "home-lab-k3s".to_string());
    let sanitized_name = sanitize_wsl_instance_name(&provided_name).map_err(|e| {
        error!(target: "wsl", error = %e, "Nom d'instance WSL invalide");
        e.to_string()
    })?;
    let sanitized_debug = escape_for_log(&sanitized_name);
    let setup_paths = paths.clone();
    let instance_name = sanitized_name.clone();

    log_wsl_event(format!(
        "Demande d'import WSL (force={}, instance={}, enable_nvidia={})",
        force_import, sanitized_debug, enable_nvidia
    ));
    info!(
        target: "wsl",
        force = force_import,
        enable_nvidia,
        instance = %sanitized_name,
        instance_debug = %sanitized_debug,
        "Demande d'import WSL recue"
    );

    let setup_result = tauri::async_runtime::spawn_blocking(move || {
        run_wsl_setup_with_paths(&setup_paths, force_import, &instance_name, enable_nvidia)
    })
    .await
    .map_err(|e| {
        error!(target: "wsl", "Erreur JoinHandle: {e}");
        log_wsl_event(format!(
            "Erreur JoinHandle pendant l'import WSL (instance={}): {e}",
            sanitized_debug
        ));
        format!("Erreur interne: {e}")
    })?;

    let mut provision = match setup_result {
        Ok(prov) => prov,
        Err(err) => {
            let message = annotate_wsl_cli_failure(&err.to_string());
            error!(target: "wsl", "Echec import WSL: {err}");
            log_wsl_event(format!(
                "Echec import WSL pour l'instance {}: {err}",
                sanitized_debug
            ));
            ProvisionResult { ok: false, message }
        }
    };

    let mut allow_post_config = provision.ok;
    let expected_api_port = k3s_api_port_for_instance(&sanitized_name);
    if !allow_post_config {
        if wsl_cli_reports_missing_system_file(&provision.message) {
            warn!(
                target: "wsl",
                instance = %sanitized_name,
                "Verification de presence ignoree car WSL n'est pas disponible cote hote"
            );
            log_wsl_event(format!(
                "Verification de presence ignoree pour {}: WSL indisponible cote hote",
                sanitized_debug
            ));
        } else {
            match is_wsl_instance_present(&sanitized_name).await {
                Ok(true) => {
                    match enforce_instance_api_port_range(&sanitized_name, expected_api_port).await
                    {
                        Ok(_) => {
                            append_provision_message(
                                &mut provision.message,
                                &format!(
                                    "Port API Kubernetes reconcilie sur /etc/k3s-env ({expected_api_port})."
                                ),
                            );
                            log_wsl_event(format!(
                                "Reconciliation /etc/k3s-env pour {}: api_port={}",
                                sanitized_debug, expected_api_port
                            ));
                        }
                        Err(err) => {
                            warn!(
                                target: "wsl",
                                instance = %sanitized_name,
                                error = %err,
                                "Reconciliation /etc/k3s-env impossible apres echec setup"
                            );
                            append_provision_message(
                                &mut provision.message,
                                &format!("Reconciliation /etc/k3s-env impossible: {err}"),
                            );
                        }
                    }
                    allow_post_config = true;
                    info!(
                        target: "wsl",
                        instance = %sanitized_name,
                        "Instance presente malgre une erreur setup, tentative de configuration reseau/OIDC"
                    );
                    log_wsl_event(format!(
                        "Instance {} presente malgre erreur setup, configuration reseau/OIDC en cours",
                        sanitized_debug
                    ));
                }
                Ok(false) => {
                    info!(
                        target: "wsl",
                        instance = %sanitized_name,
                        "Instance absente apres echec setup, configuration reseau/OIDC ignoree"
                    );
                }
                Err(err) => {
                    let message = annotate_wsl_cli_failure(&err.to_string());
                    warn!(
                        target: "wsl",
                        instance = %sanitized_name,
                        error = %message,
                        "Impossible de verifier la presence de l'instance WSL apres echec setup"
                    );
                    append_provision_message(
                        &mut provision.message,
                        &format!("Verification de l'instance WSL impossible: {message}"),
                    );
                }
            }
        }
    }

    if allow_post_config {
        match download_and_install_k3s_with_paths(&paths, &sanitized_name).await {
            Ok(extra) => {
                append_provision_message(&mut provision.message, &extra);
                log_wsl_event(format!(
                    "Installation de K3S reussie pour {}: {}",
                    sanitized_debug,
                    escape_for_log(&extra)
                ));

                match bootstrap_k3s_for_instance_if_available(&sanitized_name) {
                    Ok(()) => {
                        append_provision_message(
                            &mut provision.message,
                            "Bootstrap K3S initialise apres installation du binaire.",
                        );
                        log_wsl_event(format!(
                            "Bootstrap K3S relance apres installation pour {}",
                            sanitized_debug
                        ));
                    }
                    Err(err) => {
                        warn!(
                            target: "wsl",
                            instance = %sanitized_name,
                            error = %err,
                            "Bootstrap K3S impossible apres installation"
                        );
                        append_provision_message(
                            &mut provision.message,
                            &format!("Bootstrap K3S impossible apres installation: {err}"),
                        );
                        log_wsl_event(format!(
                            "Bootstrap K3S impossible apres installation pour {}: {}",
                            sanitized_debug,
                            escape_for_log(&err.to_string())
                        ));
                    }
                }
            }
            Err(err) => {
                warn!(
                    target: "wsl",
                    instance = %sanitized_name,
                    error = %err,
                    "Installation de K3S impossible"
                );
                append_provision_message(
                    &mut provision.message,
                    &format!("Installation de K3S impossible: {err}"),
                );
                log_wsl_event(format!(
                    "Installation de K3S impossible pour {}: {}",
                    sanitized_debug,
                    escape_for_log(&err.to_string())
                ));
            }
        }

        match configure_k3s_oidc_client(&sanitized_name).await {
            Ok(extra) => {
                append_provision_message(&mut provision.message, &extra);
                log_wsl_event(format!(
                    "Client OIDC k3s cree pour {}: {}",
                    sanitized_debug,
                    escape_for_log(&extra)
                ));
            }
            Err(err) => {
                warn!(
                    target: "wsl",
                    instance = %sanitized_name,
                    error = %err,
                    "Configuration OIDC pour k3s impossible"
                );
                append_provision_message(
                    &mut provision.message,
                    &format!("Configuration OIDC impossible: {err}"),
                );
                log_wsl_event(format!(
                    "Configuration OIDC pour {} impossible: {}",
                    sanitized_debug,
                    escape_for_log(&err.to_string())
                ));
            }
        }

        match configure_cluster_networking(&sanitized_name).await {
            Ok(extra) => {
                append_provision_message(&mut provision.message, &extra);
                log_wsl_event(format!(
                    "Reseau WSL configure pour {}: {}",
                    sanitized_debug,
                    escape_for_log(&extra)
                ));
            }
            Err(err) => {
                warn!(
                    target: "wsl",
                    instance = %sanitized_name,
                    error = %err,
                    "Configuration DNS/HTTP pour WSL impossible"
                );
                append_provision_message(
                    &mut provision.message,
                    &format!("Configuration DNS/HTTP impossible: {err}"),
                );
                log_wsl_event(format!(
                    "Configuration DNS/HTTP pour {} impossible: {}",
                    sanitized_debug,
                    escape_for_log(&err.to_string())
                ));
            }
        }

        if is_home_lab_wsl_instance(&sanitized_name) {
            let tls_trace_id = format!("{}-tls", next_kubectl_trace_id());
            match reconcile_home_lab_cluster_default_tls(&sanitized_name, &tls_trace_id).await {
                Ok(HomeLabTraefikTlsReconcileStatus::Reconciled) => {
                    append_provision_message(
                        &mut provision.message,
                        "Certificat TLS par defaut Traefik reconcilie.",
                    );
                }
                Ok(HomeLabTraefikTlsReconcileStatus::Deferred) => {
                    append_provision_message(
                        &mut provision.message,
                        "Reconciliation TLS Traefik differee le temps que Traefik termine son bootstrap.",
                    );
                }
                Err(err) => {
                    warn!(
                        target: "wsl",
                        instance = %sanitized_name,
                        trace_id = %tls_trace_id,
                        error = %err,
                        "Reconciliation TLS Traefik impossible apres import"
                    );
                    append_provision_message(
                        &mut provision.message,
                        &format!("Reconciliation TLS Traefik impossible: {err}"),
                    );
                    log_wsl_event(format!(
                        "[{}] Reconciliation TLS Traefik impossible apres import {}: {}",
                        tls_trace_id,
                        sanitized_debug,
                        escape_for_log(&err.to_string())
                    ));
                }
            }
        }

        match sync_windows_kubeconfig_task().await {
            Ok(sync) => {
                append_provision_message(&mut provision.message, &sync.message);
                log_wsl_event(format!(
                    "Kubeconfig Windows synchronise apres import {}: {}",
                    sanitized_debug,
                    escape_for_log(&sync.message)
                ));
            }
            Err(err) => {
                warn!(
                    target: "wsl",
                    instance = %sanitized_name,
                    error = %err,
                    "Synchronisation kubeconfig Windows impossible apres import"
                );
                append_provision_message(
                    &mut provision.message,
                    &format!("Synchronisation kubeconfig Windows impossible: {err}"),
                );
                log_wsl_event(format!(
                    "Synchronisation kubeconfig Windows impossible apres import {}: {}",
                    sanitized_debug,
                    escape_for_log(&err.to_string())
                ));
            }
        }

        if is_home_lab_wsl_instance(&sanitized_name) {
            match ensure_wsl_keepalive(&sanitized_name, "post-import").await {
                Ok(_) => {}
                Err(err) => {
                    warn!(
                        target: "wsl",
                        instance = %sanitized_name,
                        error = %err,
                        "Impossible de lancer keepalive WSL apres import"
                    );
                    append_provision_message(
                        &mut provision.message,
                        &format!("Activation keepalive WSL impossible: {err}"),
                    );
                    log_wsl_event(format!(
                        "Activation keepalive WSL impossible apres import {}: {}",
                        sanitized_debug,
                        escape_for_log(&err.to_string())
                    ));
                }
            }
        }
    }

    Ok(provision)
}

#[tauri::command]
pub async fn wsl_import_instance(
    app: AppHandle,
    force: Option<bool>,
    name: Option<String>,
    enable_nvidia: Option<bool>,
) -> Result<ProvisionResult, String> {
    let paths = wsl_execution_paths_from_app(&app).map_err(|e| {
        error!(target: "wsl", error = %e, "Impossible de determiner les chemins WSL");
        e.to_string()
    })?;
    wsl_import_instance_with_paths(paths, force, name, enable_nvidia).await
}

pub async fn wsl_import_instance_headless(
    force: Option<bool>,
    name: Option<String>,
    enable_nvidia: Option<bool>,
) -> Result<ProvisionResult, String> {
    let paths = wsl_execution_paths_headless().map_err(|e| {
        error!(target: "wsl", error = %e, "Impossible de determiner les chemins WSL headless");
        e.to_string()
    })?;
    wsl_import_instance_with_paths(paths, force, name, enable_nvidia).await
}

fn run_wsl_setup_with_paths(
    paths: &WslExecutionPaths,
    force_import: bool,
    instance_name: &str,
    enable_nvidia: bool,
) -> Result<ProvisionResult> {
    let script_path = paths.resource_root.join("setup-wsl.ps1");
    if !script_path.exists() {
        return Err(anyhow!(
            "Script setup-wsl.ps1 introuvable dans {:?}",
            script_path
        ));
    }

    let rootfs_path = paths.resource_root.join("wsl-rootfs.tar");
    if !rootfs_path.exists() {
        return Err(anyhow!("Archive rootfs introuvable dans {:?}", rootfs_path));
    }

    let install_dir = paths.install_root.join(instance_name);
    let script_path_cli = normalize_windows_path_for_cli(&script_path);
    let rootfs_path_cli = normalize_windows_path_for_cli(&rootfs_path);
    let install_dir_cli = normalize_windows_path_for_cli(&install_dir);
    let instance_debug = escape_for_log(instance_name);
    let plan = instance_port_plan(instance_name);
    let api_port = plan.api_backend_port;
    let nodeport_range_end = plan.nodeport_range.end;

    info!(
        target: "wsl",
        script = %script_path_cli.display(),
        rootfs = %rootfs_path_cli.display(),
        install = %install_dir_cli.display(),
        force = force_import,
        enable_nvidia,
        instance = %instance_name,
        instance_debug = %instance_debug,
        api_port,
        nodeport_range_end,
        "Lancement de setup-wsl.ps1"
    );
    log_wsl_event(format!(
        "Lancement de setup-wsl.ps1 (force={}, instance={}, enable_nvidia={}, script={}, rootfs={}, install={}, api_port={} nodeport_end={})",
        force_import,
        instance_debug,
        enable_nvidia,
        script_path_cli.display(),
        rootfs_path_cli.display(),
        install_dir_cli.display(),
        api_port,
        nodeport_range_end
    ));

    let mut command = Command::new("powershell.exe");
    command
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&script_path_cli)
        .arg("-InstallDir")
        .arg(&install_dir_cli)
        .arg("-Rootfs")
        .arg(&rootfs_path_cli)
        .arg("-DistroName")
        .arg(instance_name)
        .arg("-ApiPort")
        .arg(api_port.to_string());

    if force_import {
        command.arg("-ForceImport");
    }
    if enable_nvidia {
        command.arg("-EnableNvidia");
    }

    let mut command_preview = format!(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\" -InstallDir \"{}\" -Rootfs \"{}\" -DistroName \"{}\" -ApiPort {}",
        script_path_cli.display(),
        install_dir_cli.display(),
        rootfs_path_cli.display(),
        instance_name,
        api_port
    );
    if force_import {
        command_preview.push_str(" -ForceImport");
    }
    if enable_nvidia {
        command_preview.push_str(" -EnableNvidia");
    }

    info!(
        target: "wsl",
        command = %command_preview,
        "Execution d'une commande WSL (setup)"
    );
    log_wsl_event(format!(
        "Execution commande WSL (setup): {}",
        command_preview
    ));

    let output = command
        .output()
        .with_context(|| "Impossible d'executer setup-wsl.ps1".to_string())?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    info!(
        target: "wsl",
        command = %command_preview,
        status = %output.status,
        stdout = %stdout_log,
        stderr = %stderr_log,
        "Commande WSL terminee (setup)"
    );
    log_wsl_event(format!(
        "Commande terminee (setup) status={} stdout={} stderr={}",
        output.status, stdout_log, stderr_log
    ));

    if output.status.success() {
        if !stdout_trim.is_empty() {
            info!(target: "wsl", "setup-wsl.ps1 stdout:\n{stdout_trim}");
        }
        if !stderr_trim.is_empty() {
            warn!(target: "wsl", "setup-wsl.ps1 stderr: {stderr_trim}");
        }
        let mut message = if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            format!("Instance WSL '{instance_name}' importee avec succes.")
        };
        if !stderr_trim.is_empty() {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(stderr_trim);
        }
        info!(
            target: "wsl",
            instance = %instance_name,
            instance_debug = %instance_debug,
            "Import WSL termine"
        );
        log_wsl_event(format!(
            "Import WSL termine pour {}: {}",
            instance_debug,
            escape_for_log(&message)
        ));
        Ok(ProvisionResult { ok: true, message })
    } else {
        error!(
            target: "wsl",
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "setup-wsl.ps1 a echoue"
        );
        log_wsl_event(format!(
            "setup-wsl.ps1 a echoue pour {}: status={} stdout={} stderr={}",
            instance_debug, output.status, stdout_log, stderr_log
        ));
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "(code inconnu)".into());
        let mut combined = stderr;
        if combined.is_empty() {
            combined = stdout;
        }
        if combined.is_empty() {
            combined = format!("setup-wsl.ps1 a echoue (code {code})");
        }
        Err(anyhow!(annotate_wsl_cli_failure(&combined)))
    }
}

fn parse_wsl_list_output(output: &str) -> Result<Vec<WslInstance>> {
    let entry_re = Regex::new(r"^(?P<name>.+?)\s{2,}(?P<state>.+?)(?:\s{2,}(?P<version>\S+))?$")?;
    let mut instances = Vec::new();
    let mut header_skipped = false;

    for raw_line in output.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !header_skipped {
            header_skipped = true;
            // Première ligne = en-tête (NAME/STATE/VERSION ou équivalent localisé).
            continue;
        }

        let working = raw_line.trim_start();
        let (is_default, without_marker) = if working.starts_with('*') {
            (true, working.trim_start_matches('*').trim_start())
        } else {
            (false, working)
        };

        if without_marker.is_empty() {
            warn!(
                target: "wsl",
                line = %escape_for_log(raw_line),
                "Ligne WSL vide apres retrait du marqueur par defaut; ignoree"
            );
            continue;
        }

        let Some(caps) = entry_re.captures(without_marker) else {
            warn!(
                target: "wsl",
                line = %escape_for_log(without_marker),
                "Impossible d'analyser la ligne WSL; ligne ignoree"
            );
            continue;
        };

        let name_raw = caps.name("name").map(|m| m.as_str()).unwrap_or_default();
        let state_raw = caps.name("state").map(|m| m.as_str()).unwrap_or_default();
        let version_raw = caps.name("version").map(|m| m.as_str());

        let name = sanitize_cli_field(name_raw);
        if name.is_empty() {
            warn!(
                target: "wsl",
                line = %escape_for_log(raw_line),
                "Nom d'instance WSL vide apres nettoyage; ligne ignoree"
            );
            continue;
        }

        let state = sanitize_cli_field(state_raw);
        let version =
            version_raw
                .map(sanitize_cli_field)
                .and_then(|v| if v.is_empty() { None } else { Some(v) });

        instances.push(WslInstance {
            name,
            state,
            version,
            is_default,
            cluster: None,
        });
    }

    Ok(instances)
}

fn collect_wsl_instances() -> Result<Vec<WslInstance>> {
    let args = ["--list", "--verbose", "--all"];
    let command_line = format_cli_command("wsl.exe", &args);

    log_wsl_event(format!("Execution commande WSL (list): {command_line}"));
    let output = Command::new("wsl.exe")
        .args(args)
        .output()
        .context("Impossible d'executer wsl.exe --list --verbose --all")?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    info!(
        target: "wsl",
        command = %command_line,
        status = %output.status,
        stdout = %stdout_log,
        stderr = %stderr_log,
        "Commande WSL terminee"
    );
    log_wsl_event(format!(
        "Commande terminee (list) status={} stdout={} stderr={}",
        output.status, stdout_log, stderr_log
    ));

    if !output.status.success() {
        let lower_stdout = stdout_trim.to_lowercase();
        let lower_stderr = stderr_trim.to_lowercase();
        let no_distro = lower_stdout.contains("no installed distributions")
            || lower_stdout.contains("aucune distribution install")
            || lower_stderr.contains("no installed distributions")
            || lower_stderr.contains("aucune distribution install");

        if no_distro {
            info!(target: "wsl", "wsl.exe indique qu'aucune distribution n'est installee");
            log_wsl_event("wsl.exe indique qu'aucune distribution n'est installee");
            return Ok(Vec::new());
        }

        let message = if !stderr_trim.is_empty() {
            stderr_trim.to_string()
        } else if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            "wsl.exe --list a echoue".to_string()
        };
        let message = annotate_wsl_cli_failure(&message);
        log_wsl_event(format!("Echec wsl.exe --list --verbose --all: {message}"));
        return Err(anyhow!(message));
    }

    let instances = parse_wsl_list_output(stdout.as_str())?;

    for inst in &instances {
        let version_ref = inst.version.as_deref().unwrap_or("");
        info!(
            target: "wsl",
            instance = %inst.name,
            instance_debug = %escape_for_log(&inst.name),
            state = %inst.state,
            state_debug = %escape_for_log(&inst.state),
            version = %version_ref,
            version_debug = %escape_for_log(version_ref),
            "Instance WSL detectee"
        );
        log_wsl_event(format!(
            "Instance detectee: name={} state={} version={} default={}",
            escape_for_log(&inst.name),
            escape_for_log(&inst.state),
            escape_for_log(version_ref),
            inst.is_default
        ));
    }

    Ok(instances)
}

async fn is_wsl_instance_present(name: &str) -> Result<bool> {
    let target = name.to_ascii_lowercase();
    tauri::async_runtime::spawn_blocking(move || {
        collect_wsl_instances().map(|instances| {
            instances
                .iter()
                .any(|instance| instance.name.to_ascii_lowercase() == target)
        })
    })
    .await
    .map_err(|e| anyhow!("Erreur JoinHandle pour verifier l'instance WSL: {e}"))?
}

fn run_wsl_unregister(name: &str) -> Result<WslOperationResult> {
    if name.trim().is_empty() {
        return Err(anyhow!("Le nom de l'instance WSL est requis"));
    }

    let command_line = format_cli_command("wsl.exe", &["--unregister", name]);
    let instance_debug = escape_for_log(name);

    info!(
        target: "wsl",
        instance = name,
        instance_debug = %instance_debug,
        command = %command_line,
        "Execution d'une commande WSL"
    );
    log_wsl_event(format!(
        "Suppression WSL demandee pour {} via {}",
        instance_debug, command_line
    ));

    let output = Command::new("wsl.exe")
        .args(["--unregister", name])
        .output()
        .with_context(|| format!("Impossible de supprimer l'instance WSL {name}"))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    let stdout_trim = stdout.trim();
    let stderr_trim = stderr.trim();
    let stdout_log = escape_for_log(stdout_trim);
    let stderr_log = escape_for_log(stderr_trim);

    if output.status.success() {
        let mut message = if !stdout_trim.is_empty() {
            stdout_trim.to_string()
        } else {
            format!("Instance WSL '{name}' supprimee.")
        };
        if !stderr_trim.is_empty() && stderr_trim != message {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(stderr_trim);
        }
        info!(
            target: "wsl",
            instance = name,
            instance_debug = %instance_debug,
            command = %command_line,
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "Instance WSL supprimee"
        );
        log_wsl_event(format!(
            "Instance WSL supprimee: {} message={} stdout={} stderr={}",
            instance_debug,
            escape_for_log(&message),
            stdout_log,
            stderr_log
        ));
        Ok(WslOperationResult { ok: true, message })
    } else {
        let lower_stdout = stdout_trim.to_lowercase();
        let lower_stderr = stderr_trim.to_lowercase();
        let not_found = lower_stdout.contains("wsl_e_distro_not_found")
            || lower_stderr.contains("wsl_e_distro_not_found")
            || lower_stdout.contains("no distribution")
            || lower_stderr.contains("no distribution")
            || lower_stdout.contains("aucune distribution")
            || lower_stderr.contains("aucune distribution");

        if not_found {
            info!(
                target: "wsl",
                instance = name,
                instance_debug = %instance_debug,
                command = %command_line,
                stdout = %stdout_log,
                stderr = %stderr_log,
                "Suppression WSL consideree comme deja effectuee (distribution absente)"
            );
            log_wsl_event(format!(
                "Suppression WSL consideree comme deja effectuee (absente): {}",
                instance_debug
            ));
            return Ok(WslOperationResult {
                ok: true,
                message: format!("Instance WSL '{name}' introuvable ou deja supprimee."),
            });
        }

        let mut combined = stderr_trim.to_string();
        if combined.is_empty() {
            combined = stdout_trim.to_string();
        }
        if combined.is_empty() {
            let code = output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "(code inconnu)".into());
            combined = format!("Suppression de l'instance '{name}' a echoue (code {code})");
        }
        error!(
            target: "wsl",
            instance = name,
            instance_debug = %instance_debug,
            command = %command_line,
            status = %output.status,
            stdout = %stdout_log,
            stderr = %stderr_log,
            "Suppression WSL a echoue"
        );
        log_wsl_event(format!(
            "Suppression WSL a echoue: {} message={} stdout={} stderr={}",
            instance_debug,
            escape_for_log(&combined),
            stdout_log,
            stderr_log
        ));
        Err(anyhow!(combined))
    }
}

#[tauri::command]
pub async fn wsl_list_instances() -> Result<Vec<WslInstance>, String> {
    info!(target: "wsl", "Listing des instances WSL");
    log_wsl_event("Listing des instances WSL");
    let mut instances = tauri::async_runtime::spawn_blocking(collect_wsl_instances)
        .await
        .map_err(|e| {
            error!(target: "wsl", "Erreur JoinHandle (list): {e}");
            log_wsl_event(format!("Erreur JoinHandle lors du listing WSL: {e}"));
            format!("Erreur interne: {e}")
        })?
        .map_err(|e| annotate_wsl_cli_failure(&e.to_string()))?;

    attach_cluster_details(&mut instances).await;

    for instance in &instances {
        if is_home_lab_wsl_instance(&instance.name) && wsl_state_is_running(&instance.state) {
            if let Err(err) = ensure_wsl_keepalive(&instance.name, "list-instances").await {
                warn!(
                    target: "wsl",
                    instance = %instance.name,
                    error = %err,
                    "Impossible de lancer keepalive WSL pendant le listing"
                );
                log_wsl_event(format!(
                    "Keepalive WSL impossible pendant listing pour {}: {}",
                    escape_for_log(&instance.name),
                    escape_for_log(&err.to_string())
                ));
            }
        }
    }

    Ok(instances)
}

#[tauri::command]
pub async fn wsl_get_host_capabilities() -> Result<WslHostCapabilities, String> {
    info!(target: "wsl", "Detection des capacites GPU de l'hote demandee");
    log_wsl_event("Detection des capacites GPU de l'hote demandee");

    let nvidia_gpu_names = tauri::async_runtime::spawn_blocking(detect_host_nvidia_gpu_names)
        .await
        .map_err(|e| format!("Erreur interne detection GPU Nvidia: {e}"));

    match nvidia_gpu_names {
        Ok(Ok(names)) => {
            let capabilities = WslHostCapabilities {
                nvidia_available: !names.is_empty(),
                nvidia_gpu_names: names,
            };
            info!(
                target: "wsl",
                nvidia_available = capabilities.nvidia_available,
                nvidia_gpu_count = capabilities.nvidia_gpu_names.len(),
                "Detection des capacites GPU de l'hote terminee"
            );
            Ok(capabilities)
        }
        Ok(Err(err)) => {
            warn!(
                target: "wsl",
                error = %err,
                "Detection GPU Nvidia indisponible, retour des capacites par defaut"
            );
            log_wsl_event(format!(
                "Detection GPU Nvidia indisponible, retour par defaut: {}",
                escape_for_log(&err.to_string())
            ));
            Ok(WslHostCapabilities::default())
        }
        Err(err) => {
            warn!(
                target: "wsl",
                error = %err,
                "JoinHandle detection GPU Nvidia en echec, retour des capacites par defaut"
            );
            log_wsl_event(format!(
                "JoinHandle detection GPU Nvidia en echec, retour par defaut: {}",
                escape_for_log(&err.to_string())
            ));
            Ok(WslHostCapabilities::default())
        }
    }
}

#[tauri::command]
pub async fn wsl_sync_windows_kubeconfig() -> Result<WslKubeconfigSyncResult, String> {
    info!(target: "wsl", "Synchronisation du kubeconfig Windows demandee");
    log_wsl_event("Synchronisation du kubeconfig Windows demandee");

    let result = sync_windows_kubeconfig_task().await.map_err(|e| {
        error!(target: "wsl", "Echec synchronisation kubeconfig Windows: {e}");
        log_wsl_event(format!("Echec synchronisation kubeconfig Windows: {e}"));
        e.to_string()
    })?;

    info!(
        target: "wsl",
        path = %result.path,
        contexts = result.contexts.len(),
        skipped = result.skipped.len(),
        "Synchronisation kubeconfig Windows terminee"
    );
    log_wsl_event(format!(
        "Synchronisation kubeconfig Windows terminee: path={} contexts={} skipped={}",
        escape_for_log(&result.path),
        result.contexts.len(),
        result.skipped.len()
    ));

    Ok(result)
}

#[tauri::command]
pub async fn wsl_remove_instance(name: String) -> Result<WslOperationResult, String> {
    let raw_trimmed = name.trim();
    if raw_trimmed.is_empty() {
        return Err("Le nom de l'instance est requis.".into());
    }

    let sanitized = sanitize_wsl_instance_name(raw_trimmed).map_err(|e| e.to_string())?;

    if sanitized != raw_trimmed {
        info!(
            target: "wsl",
            instance_raw = %escape_for_log(raw_trimmed),
            instance_sanitized = %escape_for_log(&sanitized),
            "Nom d'instance WSL nettoye avant suppression"
        );
        log_wsl_event(format!(
            "Nom d'instance WSL nettoye avant suppression: brut={} nettoye={}",
            escape_for_log(raw_trimmed),
            escape_for_log(&sanitized)
        ));
    }

    let instance_name = sanitized;
    let instance_debug = escape_for_log(&instance_name);
    info!(
        target: "wsl",
        instance = %instance_name,
        instance_debug = %instance_debug,
        "Suppression d'une instance WSL demandee"
    );
    log_wsl_event(format!(
        "Suppression d'une instance WSL demandee: {}",
        instance_debug
    ));

    let mut removal = tauri::async_runtime::spawn_blocking({
        let instance_name = instance_name.clone();
        move || run_wsl_unregister(&instance_name)
    })
    .await
    .map_err(|e| {
        error!(target: "wsl", "Erreur JoinHandle (remove): {e}");
        log_wsl_event(format!("Erreur JoinHandle (remove): {e}"));
        format!("Erreur interne: {e}")
    })
    .and_then(|result| {
        result.map_err(|e| {
            error!(target: "wsl", "Echec suppression WSL: {e}");
            log_wsl_event(format!(
                "Echec suppression WSL pour {}: {e}",
                instance_debug
            ));
            e.to_string()
        })
    })?;

    for host in cluster_domains(&instance_name) {
        if let Err(err) =
            retry_http_rpc("remove_route", || http::http_remove_route(host.clone())).await
        {
            warn!(
                target: "wsl",
                instance = %instance_name,
                host = %host,
                error = %err,
                "Suppression de la route HTTP impossible apres suppression d'instance"
            );
        }
        let dns_value = dns_target_ipv4();
        if let Err(err) = retry_dns_rpc("remove_record", || {
            dns::dns_remove_record(host.clone(), "A".into(), dns_value.clone())
        })
        .await
        {
            warn!(
                target: "wsl",
                instance = %instance_name,
                host = %host,
                error = %err,
                "Suppression de l'enregistrement DNS impossible apres suppression d'instance"
            );
        }
    }

    let tcp_route_name = kube_api_proxy_route_name(&instance_name);
    if let Err(err) = retry_http_rpc("remove_tcp_route", || {
        http::http_remove_tcp_route(tcp_route_name.clone())
    })
    .await
    {
        warn!(
            target: "wsl",
            instance = %instance_name,
            route = %tcp_route_name,
            error = %err,
            "Suppression de la route TCP API impossible apres suppression d'instance"
        );
    }

    let ssh_route_name = ssh_proxy_route_name(&instance_name);
    if let Err(err) = retry_http_rpc("remove_tcp_route", || {
        http::http_remove_tcp_route(ssh_route_name.clone())
    })
    .await
    {
        warn!(
            target: "wsl",
            instance = %instance_name,
            route = %ssh_route_name,
            error = %err,
            "Suppression de la route TCP SSH impossible apres suppression d'instance"
        );
    }

    match sync_windows_kubeconfig_task().await {
        Ok(sync) => {
            append_provision_message(&mut removal.message, &sync.message);
            log_wsl_event(format!(
                "Kubeconfig Windows synchronise apres suppression {}: {}",
                instance_debug,
                escape_for_log(&sync.message)
            ));
        }
        Err(err) => {
            warn!(
                target: "wsl",
                instance = %instance_name,
                error = %err,
                "Synchronisation kubeconfig Windows impossible apres suppression"
            );
            append_provision_message(
                &mut removal.message,
                &format!("Synchronisation kubeconfig Windows impossible: {err}"),
            );
            log_wsl_event(format!(
                "Synchronisation kubeconfig Windows impossible apres suppression {}: {}",
                instance_debug,
                escape_for_log(&err.to_string())
            ));
        }
    }

    Ok(removal)
}
#[derive(Clone, Debug)]
enum KubectlGetResource {
    Nodes,
    Namespaces,
    Pods,
    Events,
    Dynamic(String),
}

#[derive(Clone, Debug)]
struct KubectlGetRequest {
    resource: KubectlGetResource,
    name: Option<String>,
    namespace: Option<String>,
    all_namespaces: bool,
    wide: bool,
}

#[derive(Clone, Debug)]
struct KubectlDescribeRequest {
    resource: String,
    names: Vec<String>,
    namespace: Option<String>,
    all_namespaces: bool,
}

#[derive(Clone, Debug)]
struct KubectlLogsRequest {
    pod: String,
    namespace: Option<String>,
    container: Option<String>,
    all_containers: bool,
    previous: bool,
    tail_lines: Option<i64>,
    since_seconds: Option<i64>,
    timestamps: bool,
    limit_bytes: Option<i64>,
}

#[derive(Clone, Debug)]
struct KubectlObjectRef {
    kind: String,
    name: String,
    namespace: Option<String>,
}

#[derive(Clone, Debug)]
struct KubectlEventsRequest {
    namespace: Option<String>,
    all_namespaces: bool,
    wide: bool,
    for_object: Option<KubectlObjectRef>,
    event_name: Option<String>,
}

#[derive(Clone, Debug)]
enum KubectlCommand {
    Get(KubectlGetRequest),
    Describe(KubectlDescribeRequest),
    Logs(KubectlLogsRequest),
    Events(KubectlEventsRequest),
}

#[derive(Clone, Debug)]
struct KubectlApplyManifest {
    api_version: String,
    kind: String,
    name: String,
    namespace: Option<String>,
    payload: serde_json::Value,
}

#[derive(Clone, Debug)]
struct ResolvedResource {
    api_resource: discovery::ApiResource,
    scope: DiscoveryScope,
}

#[derive(Clone, Debug, Serialize)]
struct EventRow {
    namespace: String,
    event: String,
    last_seen: String,
    type_: String,
    reason: String,
    object: String,
    source: String,
    count: i32,
    message: String,
    sort_timestamp: i64,
}

fn build_kubectl_command_line(context_name: &str, args: &[String]) -> String {
    let mut command_args = Vec::with_capacity(args.len() + 2);
    command_args.push("--context".to_string());
    command_args.push(context_name.to_string());
    command_args.extend(args.iter().cloned());
    let refs: Vec<&str> = command_args.iter().map(String::as_str).collect();
    format_cli_command("kubectl", &refs)
}

fn build_kubectl_apply_command_line(context_name: &str, source_name: Option<&str>) -> String {
    let mut command_args = Vec::with_capacity(6);
    command_args.push("--context".to_string());
    command_args.push(context_name.to_string());
    command_args.push("apply".to_string());
    command_args.push("-f".to_string());
    command_args.push(
        source_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("<uploaded-yaml>")
            .to_string(),
    );
    let refs: Vec<&str> = command_args.iter().map(String::as_str).collect();
    format_cli_command("kubectl", &refs)
}

fn kubectl_error_result(
    instance: &str,
    command: &str,
    trace_id: &str,
    duration_ms: u64,
    message: String,
) -> WslKubectlExecResult {
    WslKubectlExecResult {
        ok: false,
        instance: instance.to_string(),
        exit_code: Some(1),
        command: command.to_string(),
        trace_id: trace_id.to_string(),
        duration_ms,
        stdout: String::new(),
        stderr: message,
    }
}

fn format_error_chain(err: &anyhow::Error) -> String {
    let mut parts = Vec::new();
    for cause in err.chain() {
        let rendered = cause.to_string();
        let trimmed = rendered.trim();
        if trimmed.is_empty() {
            continue;
        }
        if parts
            .last()
            .is_some_and(|previous: &String| previous == trimmed)
        {
            continue;
        }
        parts.push(trimmed.to_string());
    }

    if parts.is_empty() {
        "Erreur inconnue.".to_string()
    } else {
        parts.join(" | cause: ")
    }
}

async fn format_kubernetes_runtime_error(instance: &str, err: &anyhow::Error) -> String {
    let mut message = format_error_chain(err);

    if is_home_lab_wsl_instance(instance) {
        if let Some(hint) = collect_k3s_runtime_failure_hint(instance).await {
            let hint = hint.trim();
            if !hint.is_empty() && !message.contains(hint) {
                message.push_str(" | Diagnostic runtime: ");
                message.push_str(hint);
            }
        }
    }

    message
}

fn parse_kubectl_get_request(args: &[String]) -> Result<KubectlGetRequest> {
    if args.is_empty() {
        return Err(anyhow!("La commande kubectl est requise."));
    }

    let Some(verb) = args.first() else {
        return Err(anyhow!("La commande kubectl est requise."));
    };
    if !verb.eq_ignore_ascii_case("get") {
        return Err(anyhow!(
            "Seule la commande 'kubectl get' est supportee via le client API integre."
        ));
    }

    let Some(resource_token) = args.get(1) else {
        return Err(anyhow!(
            "La ressource kubectl est requise (nodes, namespaces, pods)."
        ));
    };

    let resource = if resource_token.eq_ignore_ascii_case("nodes")
        || resource_token.eq_ignore_ascii_case("node")
        || resource_token.eq_ignore_ascii_case("no")
    {
        KubectlGetResource::Nodes
    } else if resource_token.eq_ignore_ascii_case("namespaces")
        || resource_token.eq_ignore_ascii_case("namespace")
        || resource_token.eq_ignore_ascii_case("ns")
    {
        KubectlGetResource::Namespaces
    } else if resource_token.eq_ignore_ascii_case("pods")
        || resource_token.eq_ignore_ascii_case("pod")
        || resource_token.eq_ignore_ascii_case("po")
    {
        KubectlGetResource::Pods
    } else if resource_token.eq_ignore_ascii_case("events")
        || resource_token.eq_ignore_ascii_case("event")
        || resource_token.eq_ignore_ascii_case("ev")
    {
        KubectlGetResource::Events
    } else {
        KubectlGetResource::Dynamic(normalize_resource_alias(resource_token))
    };

    let mut request = KubectlGetRequest {
        resource,
        name: None,
        namespace: None,
        all_namespaces: false,
        wide: false,
    };

    let mut i = 2;
    while i < args.len() {
        if parse_namespace_flag(args, &mut i, &mut request.namespace)? {
            continue;
        }
        let token = &args[i];
        if token.eq_ignore_ascii_case("-A") || token.eq_ignore_ascii_case("--all-namespaces") {
            request.all_namespaces = true;
            i += 1;
            continue;
        }

        if token.eq_ignore_ascii_case("-o") || token.eq_ignore_ascii_case("--output") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| anyhow!("L'option {} attend une valeur.", token))?;
            if value.eq_ignore_ascii_case("wide") {
                request.wide = true;
            } else if value.eq_ignore_ascii_case("table") {
                request.wide = false;
            } else {
                return Err(anyhow!(
                    "Format de sortie non supporte: '{}'. Seul '-o wide' est supporte.",
                    value
                ));
            }
            i += 2;
            continue;
        }

        if let Some(value) = token.strip_prefix("-o=") {
            if value.eq_ignore_ascii_case("wide") {
                request.wide = true;
            } else if !value.eq_ignore_ascii_case("table") {
                return Err(anyhow!(
                    "Format de sortie non supporte: '{}'. Seul '-o wide' est supporte.",
                    value
                ));
            }
            i += 1;
            continue;
        }

        if let Some(value) = token.strip_prefix("--output=") {
            if value.eq_ignore_ascii_case("wide") {
                request.wide = true;
            } else if !value.eq_ignore_ascii_case("table") {
                return Err(anyhow!(
                    "Format de sortie non supporte: '{}'. Seul '-o wide' est supporte.",
                    value
                ));
            }
            i += 1;
            continue;
        }

        if token.starts_with('-') {
            return Err(anyhow!("Option kubectl non supportee: '{}'.", token));
        }

        if request.name.is_none() {
            request.name = Some(token.clone());
            i += 1;
            continue;
        }

        return Err(anyhow!("Arguments kubectl inattendus: '{}'.", token));
    }

    if request.all_namespaces && request.namespace.is_some() {
        return Err(anyhow!(
            "Les options --all-namespaces et --namespace ne peuvent pas etre combinees."
        ));
    }

    Ok(request)
}

fn normalize_resource_alias(raw: &str) -> String {
    let token = raw.trim().to_ascii_lowercase();
    match token.as_str() {
        "node" | "no" => "nodes".to_string(),
        "namespace" | "ns" => "namespaces".to_string(),
        "pod" | "po" => "pods".to_string(),
        "deployment" | "deploy" => "deployments".to_string(),
        "daemonset" | "ds" => "daemonsets".to_string(),
        "statefulset" | "sts" => "statefulsets".to_string(),
        "replicaset" | "rs" => "replicasets".to_string(),
        "service" | "svc" => "services".to_string(),
        "ingress" | "ing" => "ingresses".to_string(),
        "configmap" | "cm" => "configmaps".to_string(),
        "secret" => "secrets".to_string(),
        "event" | "ev" => "events".to_string(),
        other => other.to_string(),
    }
}

fn normalize_kind_alias(raw: &str) -> String {
    let token = raw.trim().to_ascii_lowercase();
    match token.as_str() {
        "pods" | "pod" | "po" => "pod".to_string(),
        "nodes" | "node" | "no" => "node".to_string(),
        "namespaces" | "namespace" | "ns" => "namespace".to_string(),
        "services" | "service" | "svc" => "service".to_string(),
        "deployments" | "deployment" | "deploy" => "deployment".to_string(),
        "daemonsets" | "daemonset" | "ds" => "daemonset".to_string(),
        "statefulsets" | "statefulset" | "sts" => "statefulset".to_string(),
        "replicasets" | "replicaset" | "rs" => "replicaset".to_string(),
        "events" | "event" | "ev" => "event".to_string(),
        other => other.trim_end_matches('s').to_string(),
    }
}

fn split_resource_and_inline_name(token: &str) -> (String, Option<String>) {
    let raw = token.trim();
    if let Some((resource, name)) = raw.split_once('/') {
        let resource = resource.trim();
        let name = name.trim();
        if !resource.is_empty() && !name.is_empty() {
            return (resource.to_string(), Some(name.to_string()));
        }
    }
    (raw.to_string(), None)
}

fn parse_namespace_flag(
    args: &[String],
    i: &mut usize,
    namespace: &mut Option<String>,
) -> Result<bool> {
    let token = &args[*i];
    if token.eq_ignore_ascii_case("-n") || token.eq_ignore_ascii_case("--namespace") {
        let value = args
            .get(*i + 1)
            .ok_or_else(|| anyhow!("L'option {} attend un namespace.", token))?;
        let ns = value.trim();
        if ns.is_empty() {
            return Err(anyhow!("Le namespace ne peut pas etre vide."));
        }
        *namespace = Some(ns.to_string());
        *i += 2;
        return Ok(true);
    }
    if let Some(value) = token.strip_prefix("--namespace=") {
        let ns = value.trim();
        if ns.is_empty() {
            return Err(anyhow!("Le namespace ne peut pas etre vide."));
        }
        *namespace = Some(ns.to_string());
        *i += 1;
        return Ok(true);
    }
    Ok(false)
}

fn parse_duration_seconds(raw: &str) -> Result<i64> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(anyhow!("La duree --since ne peut pas etre vide."));
    }

    let (digits, factor) = if let Some(head) = value.strip_suffix("ms") {
        (head, 0.001_f64)
    } else if let Some(head) = value.strip_suffix('s') {
        (head, 1.0_f64)
    } else if let Some(head) = value.strip_suffix('m') {
        (head, 60.0_f64)
    } else if let Some(head) = value.strip_suffix('h') {
        (head, 3600.0_f64)
    } else if let Some(head) = value.strip_suffix('d') {
        (head, 86400.0_f64)
    } else {
        (value.as_str(), 1.0_f64)
    };

    let base: f64 = digits
        .trim()
        .parse()
        .with_context(|| format!("Duree invalide: {}", raw))?;
    let seconds = (base * factor).round() as i64;
    if seconds < 0 {
        return Err(anyhow!("La duree --since doit etre positive."));
    }
    Ok(seconds)
}

fn parse_kubectl_object_ref(raw: &str) -> Result<KubectlObjectRef> {
    let trimmed = raw.trim();
    let (kind_raw, name_raw) = trimmed
        .split_once('/')
        .ok_or_else(|| anyhow!("Format --for invalide. Attendu: kind/name."))?;
    let kind = normalize_kind_alias(kind_raw);
    let name = name_raw.trim();
    if kind.is_empty() || name.is_empty() {
        return Err(anyhow!("Format --for invalide. Attendu: kind/name."));
    }
    Ok(KubectlObjectRef {
        kind,
        name: name.to_string(),
        namespace: None,
    })
}

fn parse_kubectl_describe_request(args: &[String]) -> Result<KubectlDescribeRequest> {
    if args.len() < 2 || !args[0].eq_ignore_ascii_case("describe") {
        return Err(anyhow!("La commande attendue est 'kubectl describe'."));
    }

    let (resource_raw, inline_name) = split_resource_and_inline_name(&args[1]);
    if resource_raw.trim().is_empty() {
        return Err(anyhow!("La ressource kubectl est requise pour describe."));
    }

    let mut request = KubectlDescribeRequest {
        resource: normalize_resource_alias(&resource_raw),
        names: inline_name.into_iter().collect(),
        namespace: None,
        all_namespaces: false,
    };

    let mut i = 2;
    while i < args.len() {
        if parse_namespace_flag(args, &mut i, &mut request.namespace)? {
            continue;
        }
        let token = &args[i];
        if token.eq_ignore_ascii_case("-A") || token.eq_ignore_ascii_case("--all-namespaces") {
            request.all_namespaces = true;
            i += 1;
            continue;
        }
        if token.starts_with('-') {
            return Err(anyhow!("Option kubectl non supportee: '{}'.", token));
        }
        request.names.push(token.clone());
        i += 1;
    }

    if request.all_namespaces && request.namespace.is_some() {
        return Err(anyhow!(
            "Les options --all-namespaces et --namespace ne peuvent pas etre combinees."
        ));
    }
    Ok(request)
}

fn parse_kubectl_logs_request(args: &[String]) -> Result<KubectlLogsRequest> {
    if args.is_empty()
        || (!args[0].eq_ignore_ascii_case("logs") && !args[0].eq_ignore_ascii_case("log"))
    {
        return Err(anyhow!("La commande attendue est 'kubectl logs'."));
    }

    let mut request = KubectlLogsRequest {
        pod: String::new(),
        namespace: None,
        container: None,
        all_containers: false,
        previous: false,
        tail_lines: None,
        since_seconds: None,
        timestamps: false,
        limit_bytes: None,
    };

    let mut i = 1;
    while i < args.len() {
        if parse_namespace_flag(args, &mut i, &mut request.namespace)? {
            continue;
        }
        let token = &args[i];

        if token.eq_ignore_ascii_case("-c") || token.eq_ignore_ascii_case("--container") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| anyhow!("L'option {} attend une valeur.", token))?;
            request.container = Some(value.trim().to_string());
            i += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--container=") {
            request.container = Some(value.trim().to_string());
            i += 1;
            continue;
        }
        if token.eq_ignore_ascii_case("--all-containers") {
            request.all_containers = true;
            i += 1;
            continue;
        }
        if token.eq_ignore_ascii_case("--previous") {
            request.previous = true;
            i += 1;
            continue;
        }
        if token.eq_ignore_ascii_case("--timestamps") {
            request.timestamps = true;
            i += 1;
            continue;
        }
        if token.eq_ignore_ascii_case("-f") || token.eq_ignore_ascii_case("--follow") {
            return Err(anyhow!(
                "Le mode follow n'est pas supporte dans Home Lab (commande bloquante)."
            ));
        }
        if token.eq_ignore_ascii_case("--tail") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| anyhow!("L'option {} attend une valeur.", token))?;
            request.tail_lines = Some(
                value
                    .trim()
                    .parse()
                    .with_context(|| format!("Valeur --tail invalide: {}", value))?,
            );
            i += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--tail=") {
            request.tail_lines = Some(
                value
                    .trim()
                    .parse()
                    .with_context(|| format!("Valeur --tail invalide: {}", value))?,
            );
            i += 1;
            continue;
        }
        if token.eq_ignore_ascii_case("--limit-bytes") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| anyhow!("L'option {} attend une valeur.", token))?;
            request.limit_bytes = Some(
                value
                    .trim()
                    .parse()
                    .with_context(|| format!("Valeur --limit-bytes invalide: {}", value))?,
            );
            i += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--limit-bytes=") {
            request.limit_bytes = Some(
                value
                    .trim()
                    .parse()
                    .with_context(|| format!("Valeur --limit-bytes invalide: {}", value))?,
            );
            i += 1;
            continue;
        }
        if token.eq_ignore_ascii_case("--since") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| anyhow!("L'option {} attend une valeur.", token))?;
            request.since_seconds = Some(parse_duration_seconds(value)?);
            i += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--since=") {
            request.since_seconds = Some(parse_duration_seconds(value)?);
            i += 1;
            continue;
        }
        if token.starts_with('-') {
            return Err(anyhow!("Option kubectl non supportee: '{}'.", token));
        }
        if request.pod.is_empty() {
            let (resource, inline_name) = split_resource_and_inline_name(token);
            if let Some(name) = inline_name {
                if normalize_resource_alias(&resource) != "pods" {
                    return Err(anyhow!(
                        "La commande logs supporte uniquement les pods (recu '{}').",
                        resource
                    ));
                }
                request.pod = name;
            } else {
                request.pod = token.to_string();
            }
            i += 1;
            continue;
        }
        if request.container.is_none() {
            request.container = Some(token.to_string());
            i += 1;
            continue;
        }
        return Err(anyhow!("Arguments logs inattendus: '{}'.", token));
    }

    if request.pod.trim().is_empty() {
        return Err(anyhow!("Le nom du pod est requis pour la commande logs."));
    }
    if request.all_containers && request.container.is_some() {
        return Err(anyhow!(
            "Les options --all-containers et --container ne peuvent pas etre combinees."
        ));
    }
    Ok(request)
}

fn parse_kubectl_events_request(args: &[String]) -> Result<KubectlEventsRequest> {
    if args.is_empty() || !args[0].eq_ignore_ascii_case("events") {
        return Err(anyhow!("La commande attendue est 'kubectl events'."));
    }

    let mut request = KubectlEventsRequest {
        namespace: None,
        all_namespaces: false,
        wide: false,
        for_object: None,
        event_name: None,
    };

    let mut i = 1;
    while i < args.len() {
        if parse_namespace_flag(args, &mut i, &mut request.namespace)? {
            continue;
        }
        let token = &args[i];
        if token.eq_ignore_ascii_case("-A") || token.eq_ignore_ascii_case("--all-namespaces") {
            request.all_namespaces = true;
            i += 1;
            continue;
        }
        if token.eq_ignore_ascii_case("-o") || token.eq_ignore_ascii_case("--output") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| anyhow!("L'option {} attend une valeur.", token))?;
            request.wide = value.eq_ignore_ascii_case("wide");
            i += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("-o=") {
            request.wide = value.eq_ignore_ascii_case("wide");
            i += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("--output=") {
            request.wide = value.eq_ignore_ascii_case("wide");
            i += 1;
            continue;
        }
        if token.eq_ignore_ascii_case("--for") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| anyhow!("L'option {} attend une valeur.", token))?;
            request.for_object = Some(parse_kubectl_object_ref(value)?);
            i += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--for=") {
            request.for_object = Some(parse_kubectl_object_ref(value)?);
            i += 1;
            continue;
        }
        if token.starts_with('-') {
            return Err(anyhow!("Option kubectl non supportee: '{}'.", token));
        }
        if request.event_name.is_none() {
            request.event_name = Some(token.clone());
            i += 1;
            continue;
        }
        return Err(anyhow!("Argument kubectl inattendu: '{}'.", token));
    }

    if request.all_namespaces && request.namespace.is_some() {
        return Err(anyhow!(
            "Les options --all-namespaces et --namespace ne peuvent pas etre combinees."
        ));
    }
    Ok(request)
}

fn parse_kubectl_command(args: &[String]) -> Result<KubectlCommand> {
    if args.is_empty() {
        return Err(anyhow!("La commande kubectl est requise."));
    }
    if args[0].eq_ignore_ascii_case("get") {
        return Ok(KubectlCommand::Get(parse_kubectl_get_request(args)?));
    }
    if args[0].eq_ignore_ascii_case("describe") {
        return Ok(KubectlCommand::Describe(parse_kubectl_describe_request(
            args,
        )?));
    }
    if args[0].eq_ignore_ascii_case("logs") || args[0].eq_ignore_ascii_case("log") {
        return Ok(KubectlCommand::Logs(parse_kubectl_logs_request(args)?));
    }
    if args[0].eq_ignore_ascii_case("events") {
        return Ok(KubectlCommand::Events(parse_kubectl_events_request(args)?));
    }
    Err(anyhow!(
        "Commande kubectl non supportee: '{}'. Commandes supportees: get, describe, logs, events.",
        args[0]
    ))
}

fn split_api_version(api_version: &str) -> (String, String) {
    if let Some((group, version)) = api_version.split_once('/') {
        return (group.trim().to_string(), version.trim().to_string());
    }
    (String::new(), api_version.trim().to_string())
}

fn collect_apply_manifest_from_value(
    value: serde_json::Value,
    location: &str,
    manifests: &mut Vec<KubectlApplyManifest>,
) -> Result<()> {
    let Some(object) = value.as_object() else {
        anyhow::bail!("Le document YAML {} doit etre un objet.", location);
    };

    let kind = object
        .get("kind")
        .and_then(|raw| raw.as_str())
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| anyhow!("Le champ 'kind' est requis dans {}.", location))?
        .to_string();

    if kind.eq_ignore_ascii_case("list") {
        let items = object
            .get("items")
            .and_then(|raw| raw.as_array())
            .ok_or_else(|| {
                anyhow!(
                    "Le manifest List {} doit contenir un tableau 'items'.",
                    location
                )
            })?;
        for (index, item) in items.iter().enumerate() {
            let nested = format!("{location}.items[{}]", index + 1);
            collect_apply_manifest_from_value(item.clone(), &nested, manifests)?;
        }
        return Ok(());
    }

    let api_version = object
        .get("apiVersion")
        .and_then(|raw| raw.as_str())
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| anyhow!("Le champ 'apiVersion' est requis dans {}.", location))?
        .to_string();

    let metadata = object
        .get("metadata")
        .and_then(|raw| raw.as_object())
        .ok_or_else(|| anyhow!("Le champ 'metadata' est requis dans {}.", location))?;

    let name = metadata
        .get("name")
        .and_then(|raw| raw.as_str())
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| anyhow!("Le champ 'metadata.name' est requis dans {}.", location))?
        .to_string();

    let namespace = metadata
        .get("namespace")
        .and_then(|raw| raw.as_str())
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(str::to_string);

    manifests.push(KubectlApplyManifest {
        api_version,
        kind,
        name,
        namespace,
        payload: value,
    });
    Ok(())
}

fn parse_apply_manifest_documents(manifest_yaml: &str) -> Result<Vec<KubectlApplyManifest>> {
    let mut manifests = Vec::new();

    for (index, document) in serde_yaml::Deserializer::from_str(manifest_yaml).enumerate() {
        let yaml_value = serde_yaml::Value::deserialize(document)
            .with_context(|| format!("Document YAML #{} invalide.", index + 1))?;
        if yaml_value.is_null() {
            continue;
        }
        let json_value = serde_json::to_value(yaml_value).with_context(|| {
            format!(
                "Conversion JSON impossible pour le document #{}.",
                index + 1
            )
        })?;
        let location = format!("#{}", index + 1);
        collect_apply_manifest_from_value(json_value, &location, &mut manifests)?;
    }

    if manifests.is_empty() {
        anyhow::bail!("Aucune ressource YAML exploitable n'a ete trouvee.");
    }

    Ok(manifests)
}

fn ensure_manifest_namespace(payload: &mut serde_json::Value, namespace: &str) -> Result<()> {
    let Some(object) = payload.as_object_mut() else {
        anyhow::bail!("Le manifest applique n'est pas un objet valide.");
    };

    let metadata = object
        .entry("metadata".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !metadata.is_object() {
        *metadata = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(metadata_object) = metadata.as_object_mut() {
        metadata_object.insert(
            "namespace".to_string(),
            serde_json::Value::String(namespace.to_string()),
        );
    }
    Ok(())
}

fn render_apply_resource_name(manifest: &KubectlApplyManifest) -> String {
    let (group, _) = split_api_version(&manifest.api_version);
    let kind = manifest.kind.trim().to_ascii_lowercase();
    if group.is_empty() {
        format!("{kind}/{}", manifest.name)
    } else {
        format!("{kind}.{group}/{}", manifest.name)
    }
}

fn manifest_requests_home_lab_traefik_restart(manifest: &KubectlApplyManifest) -> bool {
    let kind = manifest.kind.trim();
    if kind.eq_ignore_ascii_case("Ingress") || kind.eq_ignore_ascii_case("IngressClass") {
        return true;
    }

    let (group, _) = split_api_version(&manifest.api_version);
    if group.eq_ignore_ascii_case("traefik.io") || group.eq_ignore_ascii_case("traefik.containo.us")
    {
        return true;
    }

    kind.eq_ignore_ascii_case("Secret")
        && manifest
            .name
            .eq_ignore_ascii_case(HOME_LAB_DEFAULT_TLS_SECRET_NAME)
        && manifest
            .namespace
            .as_deref()
            .map(|ns| ns.eq_ignore_ascii_case(HOME_LAB_DEFAULT_TLS_NAMESPACE))
            .unwrap_or(false)
}

fn manifests_require_home_lab_traefik_restart(manifests: &[KubectlApplyManifest]) -> bool {
    manifests
        .iter()
        .any(manifest_requests_home_lab_traefik_restart)
}

async fn resolve_dynamic_resource_for_gvk(
    client: &Client,
    api_version: &str,
    kind: &str,
) -> Result<ResolvedResource> {
    let (group, version) = split_api_version(api_version);
    if version.trim().is_empty() {
        anyhow::bail!("apiVersion invalide: '{}'.", api_version);
    }

    let discovery = match Discovery::new(client.clone()).run_aggregated().await {
        Ok(discovery) => discovery,
        Err(err) => {
            warn!(
                target: "wsl",
                api_version = %api_version,
                kind = %kind,
                error = %err,
                "Aggregated discovery indisponible pour apply, bascule sur discovery classique"
            );
            Discovery::new(client.clone()).run().await?
        }
    };

    for discovered_group in discovery.groups() {
        for (api_resource, capabilities) in discovered_group.recommended_resources() {
            if api_resource.plural.contains('/') {
                continue;
            }
            if !api_resource.kind.eq_ignore_ascii_case(kind) {
                continue;
            }
            if !api_resource.group.eq_ignore_ascii_case(&group) {
                continue;
            }
            if !api_resource.version.eq_ignore_ascii_case(&version) {
                continue;
            }
            if !capabilities.supports_operation(verbs::PATCH) {
                continue;
            }

            return Ok(ResolvedResource {
                api_resource: api_resource.clone(),
                scope: capabilities.scope.clone(),
            });
        }
    }

    anyhow::bail!(
        "Ressource API introuvable pour kind='{}', apiVersion='{}'.",
        kind,
        api_version
    );
}

async fn execute_kubectl_apply_yaml(
    client: &Client,
    config: &KubeClientConfig,
    manifest_yaml: &str,
) -> Result<String> {
    let manifests = parse_apply_manifest_documents(manifest_yaml)?;
    let mut applied_lines = Vec::with_capacity(manifests.len());

    for manifest in manifests {
        let resolved =
            resolve_dynamic_resource_for_gvk(client, &manifest.api_version, &manifest.kind).await?;
        let mut payload = manifest.payload.clone();

        let namespace = match resolved.scope {
            DiscoveryScope::Cluster => None,
            DiscoveryScope::Namespaced => {
                let ns = manifest
                    .namespace
                    .clone()
                    .unwrap_or_else(|| config.default_namespace.clone());
                ensure_manifest_namespace(&mut payload, &ns)?;
                Some(ns)
            }
        };

        let patch_params = PatchParams::apply(KUBECTL_APPLY_FIELD_MANAGER).force();
        match resolved.scope {
            DiscoveryScope::Cluster => {
                let api: Api<DynamicObject> = Api::all_with(client.clone(), &resolved.api_resource);
                api.patch(&manifest.name, &patch_params, &Patch::Apply(&payload))
                    .await
                    .with_context(|| {
                        format!(
                            "Apply impossible pour {} (scope cluster).",
                            render_apply_resource_name(&manifest)
                        )
                    })?;
            }
            DiscoveryScope::Namespaced => {
                let ns = namespace
                    .as_deref()
                    .unwrap_or(config.default_namespace.as_str())
                    .to_string();
                let api: Api<DynamicObject> =
                    Api::namespaced_with(client.clone(), &ns, &resolved.api_resource);
                api.patch(&manifest.name, &patch_params, &Patch::Apply(&payload))
                    .await
                    .with_context(|| {
                        format!(
                            "Apply impossible pour {} dans namespace '{}'.",
                            render_apply_resource_name(&manifest),
                            ns
                        )
                    })?;
            }
        }

        let mut line = format!("{} configured", render_apply_resource_name(&manifest));
        if let Some(ns) = namespace {
            line.push_str(&format!(" (namespace/{ns})"));
        }
        applied_lines.push(line);
    }

    let count = applied_lines.len();
    applied_lines.push(format!("{count} ressource(s) appliquee(s)."));
    Ok(applied_lines.join("\n"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HomeLabTraefikTlsReconcileStatus {
    Reconciled,
    Deferred,
}

async fn wait_for_home_lab_traefik_deployment_presence(
    client: &Client,
    trace_id: &str,
    instance: &str,
) -> Result<bool> {
    let deployments: Api<Deployment> =
        Api::namespaced(client.clone(), HOME_LAB_DEFAULT_TLS_NAMESPACE);
    let started_at = Instant::now();
    let timeout = Duration::from_secs(HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS);
    let mut last_error = String::new();

    while started_at.elapsed() < timeout {
        match deployments.get_opt(HOME_LAB_TRAEFIK_DEPLOYMENT_NAME).await {
            Ok(Some(_)) => {
                info!(
                    target: "wsl",
                    trace_id = %trace_id,
                    instance = %instance,
                    deployment = HOME_LAB_TRAEFIK_DEPLOYMENT_NAME,
                    "Deployment Traefik detecte"
                );
                return Ok(true);
            }
            Ok(None) => {
                last_error = format!(
                    "Deployment '{}' absent dans namespace '{}'",
                    HOME_LAB_TRAEFIK_DEPLOYMENT_NAME, HOME_LAB_DEFAULT_TLS_NAMESPACE
                );
            }
            Err(err) => {
                last_error = err.to_string();
            }
        }

        sleep(Duration::from_millis(
            HOME_LAB_TRAEFIK_ROLLOUT_POLL_INTERVAL_MS,
        ))
        .await;
    }

    warn!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        timeout_seconds = HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS,
        error = %last_error,
        "Deployment Traefik indisponible pour la reconciliation TLS initiale"
    );
    log_wsl_event(format!(
        "[{trace_id}] Deployment Traefik indisponible pour {} avant reconciliation TLS initiale apres {}s: {}",
        escape_for_log(instance),
        HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS,
        escape_for_log(&last_error)
    ));
    Ok(false)
}

async fn wait_for_traefik_tls_store_resource(
    client: &Client,
    trace_id: &str,
    instance: &str,
) -> Result<(String, ResolvedResource)> {
    let started_at = Instant::now();
    let timeout = Duration::from_secs(HOME_LAB_TRAEFIK_TLSSTORE_DISCOVERY_TIMEOUT_SECONDS);
    let mut last_error = String::new();

    while started_at.elapsed() < timeout {
        for api_version in HOME_LAB_TRAEFIK_TLSSTORE_API_VERSIONS {
            match resolve_dynamic_resource_for_gvk(
                client,
                api_version,
                HOME_LAB_TRAEFIK_TLSSTORE_KIND,
            )
            .await
            {
                Ok(resource) => {
                    info!(
                        target: "wsl",
                        trace_id = %trace_id,
                        instance = %instance,
                        api_version = %api_version,
                        kind = HOME_LAB_TRAEFIK_TLSSTORE_KIND,
                        "CRD Traefik TLSStore detecte"
                    );
                    return Ok((api_version.to_string(), resource));
                }
                Err(err) => {
                    last_error = err.to_string();
                }
            }
        }

        sleep(Duration::from_millis(
            HOME_LAB_TRAEFIK_TLSSTORE_DISCOVERY_INTERVAL_MS,
        ))
        .await;
    }

    anyhow::bail!(
        "CRD Traefik {} indisponible apres {}s: {}",
        HOME_LAB_TRAEFIK_TLSSTORE_KIND,
        HOME_LAB_TRAEFIK_TLSSTORE_DISCOVERY_TIMEOUT_SECONDS,
        last_error
    )
}

async fn verify_home_lab_default_tls_resources(
    client: &Client,
    tls_store_resource: &ResolvedResource,
    instance: &str,
) -> Result<()> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), HOME_LAB_DEFAULT_TLS_NAMESPACE);
    let secret = secrets
        .get(HOME_LAB_DEFAULT_TLS_SECRET_NAME)
        .await
        .with_context(|| {
            format!(
                "Secret TLS '{}' introuvable dans namespace '{}'.",
                HOME_LAB_DEFAULT_TLS_SECRET_NAME, HOME_LAB_DEFAULT_TLS_NAMESPACE
            )
        })?;

    let cert_bytes = secret
        .data
        .as_ref()
        .and_then(|data| data.get("tls.crt"))
        .ok_or_else(|| {
            anyhow!(
                "Le secret TLS '{}' ne contient pas la cle 'tls.crt'.",
                HOME_LAB_DEFAULT_TLS_SECRET_NAME
            )
        })?;
    let cert_pem =
        String::from_utf8(cert_bytes.0.clone()).context("Certificat TLS Traefik non UTF-8")?;

    let tls_stores: Api<DynamicObject> = Api::namespaced_with(
        client.clone(),
        HOME_LAB_DEFAULT_TLS_NAMESPACE,
        &tls_store_resource.api_resource,
    );
    let tls_store = tls_stores.get("default").await.with_context(|| {
        format!(
            "TLSStore default introuvable dans namespace '{}'.",
            HOME_LAB_DEFAULT_TLS_NAMESPACE
        )
    })?;
    let referenced_secret = tls_store
        .data
        .get("spec")
        .and_then(|spec| spec.get("defaultCertificate"))
        .and_then(|default_certificate| default_certificate.get("secretName"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("Le TLSStore default ne reference aucun secret par defaut."))?;
    if referenced_secret != HOME_LAB_DEFAULT_TLS_SECRET_NAME {
        anyhow::bail!(
            "Le TLSStore default reference '{}' au lieu de '{}'.",
            referenced_secret,
            HOME_LAB_DEFAULT_TLS_SECRET_NAME
        );
    }

    let expected_domain = primary_cluster_domain(instance).ok_or_else(|| {
        anyhow!(
            "Aucun domaine principal disponible pour verifier le certificat de '{}'.",
            instance
        )
    })?;
    let dns_names = home_pki::certificate_dns_names(&cert_pem)?;
    if !home_lab_default_tls_cert_matches_instance(&cert_pem, instance)? {
        anyhow::bail!(
            "Le certificat TLS par defaut ne couvre pas l'instance '{}' ou n'est pas signe par la racine Home Lab courante (domaine principal attendu '{}', SAN actuels: {}).",
            instance,
            expected_domain,
            dns_names.join(", ")
        );
    }

    Ok(())
}

async fn read_home_lab_default_tls_secret_cert_pem(client: &Client) -> Result<Option<String>> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), HOME_LAB_DEFAULT_TLS_NAMESPACE);
    let Some(secret) = secrets
        .get_opt(HOME_LAB_DEFAULT_TLS_SECRET_NAME)
        .await
        .with_context(|| {
            format!(
                "Lecture du secret TLS '{}' impossible dans namespace '{}'.",
                HOME_LAB_DEFAULT_TLS_SECRET_NAME, HOME_LAB_DEFAULT_TLS_NAMESPACE
            )
        })?
    else {
        return Ok(None);
    };

    let Some(data) = secret.data.as_ref() else {
        return Ok(None);
    };
    let Some(cert_bytes) = data.get("tls.crt") else {
        return Ok(None);
    };

    let cert_pem =
        String::from_utf8(cert_bytes.0.clone()).context("Certificat TLS Traefik non UTF-8")?;
    Ok(Some(cert_pem))
}

fn probe_home_lab_traefik_served_tls_certificate(instance: &str) -> Result<()> {
    let expected_host = primary_cluster_domain(instance).ok_or_else(|| {
        anyhow!(
            "Aucun domaine principal disponible pour verifier le certificat servi par '{}'.",
            instance
        )
    })?;
    let port = instance_port_plan(instance).ingress_https_backend_port;

    let root_der = home_pki::current_root_ca_certificate_der()?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der))
        .context("Ajout de la racine Home Lab au store Rustls impossible")?;
    let client_config = Arc::new(
        RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_name = ServerName::try_from(expected_host.clone())
        .map_err(|_| anyhow!("Nom DNS invalide pour la verification TLS: {expected_host}"))?;

    let mut socket = StdTcpStream::connect(("127.0.0.1", port)).with_context(|| {
        format!(
            "Connexion TCP au backend HTTPS Traefik impossible pour '{}' sur 127.0.0.1:{}.",
            instance, port
        )
    })?;
    let io_timeout = std::time::Duration::from_secs(KUBE_CONNECT_TIMEOUT_SECONDS.max(1));
    socket
        .set_read_timeout(Some(io_timeout))
        .context("Configuration du read timeout TLS impossible")?;
    socket
        .set_write_timeout(Some(io_timeout))
        .context("Configuration du write timeout TLS impossible")?;

    let mut connection = ClientConnection::new(client_config, server_name).with_context(|| {
        format!(
            "Initialisation du client TLS Rustls impossible pour '{}' ({expected_host}).",
            instance
        )
    })?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).with_context(|| {
            format!(
                "Handshake TLS Traefik invalide pour '{}' sur 127.0.0.1:{} avec SNI '{}'.",
                instance, port, expected_host
            )
        })?;
    }

    let served_cert_der = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| {
            anyhow!(
                "Aucun certificat serveur retourne par Traefik pour '{}' sur 127.0.0.1:{}.",
                instance,
                port
            )
        })?;
    let actual_dns_names = home_pki::certificate_dns_names_from_der(served_cert_der.as_ref())
        .with_context(|| {
            format!(
                "Lecture des SAN du certificat TLS servi par Traefik impossible pour '{}'.",
                instance
            )
        })?;
    if !home_lab_default_tls_dns_names_match_instance(&actual_dns_names, instance) {
        let expected_dns_names = cluster_tls_dns_names(instance);
        let expected_display = if expected_dns_names.is_empty() {
            "(aucun)".to_string()
        } else {
            expected_dns_names.join(", ")
        };
        let actual_display = if actual_dns_names.is_empty() {
            "(aucun)".to_string()
        } else {
            actual_dns_names.join(", ")
        };
        anyhow::bail!(
            "Le certificat TLS servi par Traefik pour '{}' ne correspond pas a l'instance attendue (SAN attendus: {}; SAN servis: {}).",
            instance,
            expected_display,
            actual_display
        );
    }

    Ok(())
}

async fn wait_for_home_lab_traefik_served_tls_certificate(
    instance: &str,
    trace_id: &str,
    reason: &str,
    restart_attempt: usize,
) -> Result<()> {
    let started_at = Instant::now();
    let timeout = Duration::from_secs(HOME_LAB_TRAEFIK_TLS_SERVE_VERIFY_TIMEOUT_SECONDS);
    let mut last_error = String::new();

    while started_at.elapsed() < timeout {
        let instance_owned = instance.to_string();
        match tauri::async_runtime::spawn_blocking(move || {
            probe_home_lab_traefik_served_tls_certificate(&instance_owned)
        })
        .await
        {
            Ok(Ok(())) => {
                info!(
                    target: "wsl",
                    trace_id = %trace_id,
                    instance = %instance,
                    reason = %reason,
                    restart_attempt,
                    "Certificat TLS effectivement servi par Traefik valide"
                );
                log_wsl_event(format!(
                    "[{trace_id}] Certificat TLS servi valide pour {} apres restart Traefik: reason={} attempt={}",
                    escape_for_log(instance),
                    escape_for_log(reason),
                    restart_attempt
                ));
                return Ok(());
            }
            Ok(Err(err)) => {
                last_error = err.to_string();
            }
            Err(err) => {
                last_error = format!("Verification TLS interrompue: {err}");
            }
        }

        sleep(Duration::from_millis(
            HOME_LAB_TRAEFIK_TLS_SERVE_VERIFY_INTERVAL_MS,
        ))
        .await;
    }

    anyhow::bail!(
        "Le certificat TLS servi par Traefik pour '{}' reste invalide apres {}s (reason={}, attempt={}): {}",
        instance,
        HOME_LAB_TRAEFIK_TLS_SERVE_VERIFY_TIMEOUT_SECONDS,
        reason,
        restart_attempt,
        last_error
    )
}

async fn restart_home_lab_traefik_deployment(
    client: &Client,
    instance: &str,
    trace_id: &str,
    reason: &str,
) -> Result<()> {
    let deployments: Api<Deployment> =
        Api::namespaced(client.clone(), HOME_LAB_DEFAULT_TLS_NAMESPACE);
    let warmup_started_at = Instant::now();
    let warmup_timeout = Duration::from_secs(HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS);
    loop {
        let Some(deployment) = deployments
            .get_opt(HOME_LAB_TRAEFIK_DEPLOYMENT_NAME)
            .await
            .with_context(|| {
                format!(
                    "Lecture du deployment '{}' impossible avant redemarrage.",
                    HOME_LAB_TRAEFIK_DEPLOYMENT_NAME
                )
            })?
        else {
            if warmup_started_at.elapsed() >= warmup_timeout {
                warn!(
                    target: "wsl",
                    trace_id = %trace_id,
                    instance = %instance,
                    reason = %reason,
                    timeout_seconds = HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS,
                    "Deployment Traefik absent avant redemarrage force; restart ignore"
                );
                log_wsl_event(format!(
                    "[{trace_id}] Redemarrage Traefik ignore pour {}: deployment absent avant restart (reason={} timeout={}s)",
                    escape_for_log(instance),
                    escape_for_log(reason),
                    HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS
                ));
                return Ok(());
            }

            sleep(Duration::from_millis(
                HOME_LAB_TRAEFIK_ROLLOUT_POLL_INTERVAL_MS,
            ))
            .await;
            continue;
        };
        let state = TraefikDeploymentRolloutState::from_deployment(&deployment);
        if state.is_available() {
            break;
        }
        if warmup_started_at.elapsed() >= warmup_timeout {
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                reason = %reason,
                desired_replicas = state.desired_replicas,
                ready_replicas = state.ready_replicas,
                updated_replicas = state.updated_replicas,
                available_replicas = state.available_replicas,
                unavailable_replicas = state.unavailable_replicas,
                "Traefik non disponible avant redemarrage force; poursuite du patch"
            );
            break;
        }

        sleep(Duration::from_millis(
            HOME_LAB_TRAEFIK_ROLLOUT_POLL_INTERVAL_MS,
        ))
        .await;
    }

    for restart_attempt in 1..=HOME_LAB_TRAEFIK_TLS_RESTART_MAX_ATTEMPTS {
        let restart_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string();
        let patch = json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            HOME_LAB_TRAEFIK_RESTART_ANNOTATION: restart_at
                        }
                    }
                }
            }
        });
        let patched = deployments
            .patch(
                HOME_LAB_TRAEFIK_DEPLOYMENT_NAME,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
            .with_context(|| {
                format!(
                    "Redemarrage du deployment '{}' impossible dans le namespace '{}'.",
                    HOME_LAB_TRAEFIK_DEPLOYMENT_NAME, HOME_LAB_DEFAULT_TLS_NAMESPACE
                )
            })?;
        let expected_generation = patched.metadata.generation.unwrap_or_default();

        info!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            reason = %reason,
            restart_attempt,
            expected_generation,
            "Redemarrage du deployment Traefik demande"
        );
        log_wsl_event(format!(
            "[{trace_id}] Redemarrage Traefik demande pour {}: reason={} generation={} attempt={}",
            escape_for_log(instance),
            escape_for_log(reason),
            expected_generation,
            restart_attempt
        ));

        let started_at = Instant::now();
        let timeout = Duration::from_secs(HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS);
        loop {
            let deployment = deployments
                .get(HOME_LAB_TRAEFIK_DEPLOYMENT_NAME)
                .await
                .with_context(|| {
                    format!(
                        "Lecture du deployment '{}' impossible apres redemarrage.",
                        HOME_LAB_TRAEFIK_DEPLOYMENT_NAME
                    )
                })?;
            let state = TraefikDeploymentRolloutState::from_deployment(&deployment);
            if state.is_available_for_generation(expected_generation) {
                info!(
                    target: "wsl",
                    trace_id = %trace_id,
                    instance = %instance,
                    reason = %reason,
                    restart_attempt,
                    desired_replicas = state.desired_replicas,
                    "Deployment Traefik redemarre et disponible"
                );
                log_wsl_event(format!(
                    "[{trace_id}] Deployment Traefik disponible pour {} apres restart: reason={} replicas={} attempt={}",
                    escape_for_log(instance),
                    escape_for_log(reason),
                    state.desired_replicas,
                    restart_attempt
                ));

                match wait_for_home_lab_traefik_served_tls_certificate(
                    instance,
                    trace_id,
                    reason,
                    restart_attempt,
                )
                .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) if restart_attempt < HOME_LAB_TRAEFIK_TLS_RESTART_MAX_ATTEMPTS => {
                        warn!(
                            target: "wsl",
                            trace_id = %trace_id,
                            instance = %instance,
                            reason = %reason,
                            restart_attempt,
                            error = %err,
                            "Certificat TLS servi invalide apres restart Traefik; nouvelle tentative"
                        );
                        log_wsl_event(format!(
                            "[{trace_id}] Certificat TLS servi invalide pour {} apres restart Traefik: reason={} attempt={} error={}",
                            escape_for_log(instance),
                            escape_for_log(reason),
                            restart_attempt,
                            escape_for_log(&err.to_string())
                        ));
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }

            if started_at.elapsed() >= timeout {
                anyhow::bail!(
                    "Le deployment '{}' n'est pas redevenu disponible apres {}s (reason={}, attempt={}, generation observee={}, ready={}, updated={}, available={}, unavailable={}).",
                    HOME_LAB_TRAEFIK_DEPLOYMENT_NAME,
                    HOME_LAB_TRAEFIK_ROLLOUT_TIMEOUT_SECONDS,
                    reason,
                    restart_attempt,
                    state.observed_generation,
                    state.ready_replicas,
                    state.updated_replicas,
                    state.available_replicas,
                    state.unavailable_replicas
                );
            }

            sleep(Duration::from_millis(
                HOME_LAB_TRAEFIK_ROLLOUT_POLL_INTERVAL_MS,
            ))
            .await;
        }
    }

    Ok(())
}

fn format_age_from_seconds(created: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let delta = (now - created).max(0);

    if delta >= 60 * 60 * 24 * 365 {
        format!("{}y", delta / (60 * 60 * 24 * 365))
    } else if delta >= 60 * 60 * 24 {
        format!("{}d", delta / (60 * 60 * 24))
    } else if delta >= 60 * 60 {
        format!("{}h", delta / (60 * 60))
    } else if delta >= 60 {
        format!("{}m", delta / 60)
    } else {
        format!("{delta}s")
    }
}

fn format_age(timestamp: Option<&Time>) -> String {
    timestamp
        .map(|value| format_age_from_seconds(value.0.as_second()))
        .unwrap_or_else(|| "-".to_string())
}

fn format_age_micro(timestamp: Option<&MicroTime>) -> String {
    timestamp
        .map(|value| format_age_from_seconds(value.0.as_second()))
        .unwrap_or_else(|| "-".to_string())
}

fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (idx, value) in row.iter().enumerate() {
            if idx < widths.len() && value.len() > widths[idx] {
                widths[idx] = value.len();
            }
        }
    }

    let mut output = String::new();
    for (idx, header) in headers.iter().enumerate() {
        if idx > 0 {
            output.push_str("   ");
        }
        output.push_str(&format!("{:<width$}", header, width = widths[idx]));
    }

    for row in rows {
        output.push('\n');
        for (idx, value) in row.iter().enumerate() {
            if idx > 0 {
                output.push_str("   ");
            }
            let width = widths.get(idx).copied().unwrap_or(value.len());
            output.push_str(&format!("{:<width$}", value, width = width));
        }
    }

    output
}

fn node_ready_status(node: &Node) -> String {
    let Some(status) = node.status.as_ref() else {
        return "Unknown".to_string();
    };
    let Some(conditions) = status.conditions.as_ref() else {
        return "Unknown".to_string();
    };

    for condition in conditions {
        if condition.type_ == "Ready" {
            return match condition.status.as_str() {
                "True" => "Ready".to_string(),
                "False" => "NotReady".to_string(),
                _ => "Unknown".to_string(),
            };
        }
    }
    "Unknown".to_string()
}

fn node_roles(node: &Node) -> String {
    let Some(labels) = node.metadata.labels.as_ref() else {
        return "<none>".to_string();
    };

    let mut roles = Vec::new();
    for (key, value) in labels {
        if key == "node-role.kubernetes.io/control-plane" {
            roles.push("control-plane".to_string());
            continue;
        }
        if key == "node-role.kubernetes.io/master" {
            roles.push("master".to_string());
            continue;
        }
        if key == "node-role.kubernetes.io/worker" {
            if value.trim().is_empty() {
                roles.push("worker".to_string());
            } else {
                roles.push(value.to_string());
            }
            continue;
        }
        if let Some(role) = key.strip_prefix("node-role.kubernetes.io/") {
            if !role.trim().is_empty() {
                roles.push(role.to_string());
            }
        }
    }

    if roles.is_empty() {
        return "<none>".to_string();
    }

    roles.sort_unstable();
    roles.dedup();
    roles.join(",")
}

fn node_address(node: &Node, kind: &str) -> String {
    node.status
        .as_ref()
        .and_then(|status| status.addresses.as_ref())
        .and_then(|addresses| {
            addresses
                .iter()
                .find(|address| address.type_.eq_ignore_ascii_case(kind))
                .map(|address| address.address.clone())
        })
        .unwrap_or_else(|| "-".to_string())
}

fn pod_ready_counts(pod: &Pod) -> String {
    let total_from_spec = pod
        .spec
        .as_ref()
        .map(|spec| spec.containers.len())
        .unwrap_or(0);

    let Some(statuses) = pod
        .status
        .as_ref()
        .and_then(|status| status.container_statuses.as_ref())
    else {
        return format!("0/{total_from_spec}");
    };

    let ready = statuses.iter().filter(|status| status.ready).count();
    let total = statuses.len().max(total_from_spec);
    format!("{ready}/{total}")
}

fn pod_status_label(pod: &Pod) -> String {
    if let Some(status) = pod.status.as_ref() {
        if let Some(container_statuses) = status.container_statuses.as_ref() {
            if let Some(waiting) = container_statuses
                .iter()
                .filter_map(|item| item.state.as_ref())
                .filter_map(|state| state.waiting.as_ref())
                .find_map(|waiting| waiting.reason.as_ref())
            {
                if !waiting.trim().is_empty() {
                    return waiting.to_string();
                }
            }
            if let Some(terminated) = container_statuses
                .iter()
                .filter_map(|item| item.state.as_ref())
                .filter_map(|state| state.terminated.as_ref())
                .find_map(|terminated| terminated.reason.as_ref())
            {
                if !terminated.trim().is_empty() {
                    return terminated.to_string();
                }
            }
        }
        if let Some(reason) = status.reason.as_ref() {
            if !reason.trim().is_empty() {
                return reason.to_string();
            }
        }
        if let Some(phase) = status.phase.as_ref() {
            if !phase.trim().is_empty() {
                return phase.to_string();
            }
        }
    }
    "Unknown".to_string()
}

fn pod_restarts(pod: &Pod) -> String {
    let restarts: i64 = pod
        .status
        .as_ref()
        .and_then(|status| status.container_statuses.as_ref())
        .map(|statuses| {
            statuses
                .iter()
                .map(|status| i64::from(status.restart_count))
                .sum()
        })
        .unwrap_or(0);
    restarts.to_string()
}

fn kube_context_for_instance(instance: &str) -> String {
    managed_kube_base_name(instance)
}

fn kubeconfig_has_context(kubeconfig: &Kubeconfig, context_name: &str) -> bool {
    kubeconfig
        .contexts
        .iter()
        .any(|ctx| ctx.name == context_name)
}

fn wsl_state_is_running(state: &str) -> bool {
    let normalized = state.trim().to_lowercase();
    normalized == "running"
        || normalized.contains("running")
        || normalized.contains("exécution")
        || normalized.contains("execution")
}

fn is_home_lab_wsl_instance(name: &str) -> bool {
    name.trim()
        .to_ascii_lowercase()
        .starts_with(HOME_LAB_WSL_INSTANCE_PREFIX)
}

fn keepalive_children() -> &'static Mutex<BTreeMap<String, Child>> {
    static KEEPALIVE: OnceLock<Mutex<BTreeMap<String, Child>>> = OnceLock::new();
    KEEPALIVE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn k3s_runtime_children() -> &'static Mutex<BTreeMap<String, Child>> {
    static K3S_RUNTIME: OnceLock<Mutex<BTreeMap<String, Child>>> = OnceLock::new();
    K3S_RUNTIME.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn run_keepalive_launcher(instance: &str) -> Result<()> {
    let instance_trimmed = instance.trim();
    if instance_trimmed.is_empty() {
        anyhow::bail!("Nom d'instance WSL vide pour keepalive");
    }

    {
        let mut guard = keepalive_children()
            .lock()
            .map_err(|e| anyhow!("Mutex keepalive WSL empoisonne: {e}"))?;
        if let Some(child) = guard.get_mut(instance_trimmed) {
            match child.try_wait() {
                Ok(None) => return Ok(()),
                Ok(Some(_)) | Err(_) => {
                    guard.remove(instance_trimmed);
                }
            }
        }
    }

    // Keep one Windows-side wsl.exe client attached so the distro does not idle-stop.
    let child = Command::new("wsl.exe")
        .args([
            "-d",
            instance_trimmed,
            "--",
            "sh",
            "-lc",
            "while true; do sleep 3600; done",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .with_context(|| {
            format!(
                "Impossible de demarrer le process keepalive WSL pour {}",
                instance_trimmed
            )
        })?;

    let mut guard = keepalive_children()
        .lock()
        .map_err(|e| anyhow!("Mutex keepalive WSL empoisonne: {e}"))?;
    guard.insert(instance_trimmed.to_string(), child);
    Ok(())
}

fn run_k3s_runtime_launcher(instance: &str) -> Result<()> {
    let instance_trimmed = instance.trim();
    {
        let mut guard = k3s_runtime_children()
            .lock()
            .map_err(|e| anyhow!("Mutex runtime k3s empoisonne: {e}"))?;
        if let Some(existing) = guard.get_mut(instance_trimmed) {
            match existing.try_wait() {
                Ok(None) => return Ok(()),
                Ok(Some(_)) | Err(_) => {
                    guard.remove(instance_trimmed);
                }
            }
        }
    }

    let child = Command::new("wsl.exe")
        .args([
            "-d",
            instance_trimmed,
            "--",
            "sh",
            "-lc",
            "exec sh /usr/local/bin/k3s-init.sh >/tmp/k3s-init.out 2>/tmp/k3s-init.err",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .with_context(|| {
            format!(
                "Impossible de demarrer le process runtime k3s pour {}",
                instance_trimmed
            )
        })?;

    let mut guard = k3s_runtime_children()
        .lock()
        .map_err(|e| anyhow!("Mutex runtime k3s empoisonne: {e}"))?;
    guard.insert(instance_trimmed.to_string(), child);
    Ok(())
}

async fn ensure_wsl_keepalive(instance: &str, context: &str) -> Result<()> {
    let instance_owned = instance.to_string();
    tauri::async_runtime::spawn_blocking(move || run_keepalive_launcher(&instance_owned))
        .await
        .map_err(|e| anyhow!("Erreur JoinHandle keepalive WSL: {e}"))??;

    info!(
        target: "wsl",
        instance = %instance,
        context = %context,
        "Keepalive WSL lance"
    );
    log_wsl_event(format!(
        "Keepalive WSL lance pour {} (context={})",
        escape_for_log(instance),
        escape_for_log(context)
    ));
    Ok(())
}

async fn wsl_instance_state(instance: &str) -> Result<Option<String>> {
    let target = instance.to_ascii_lowercase();
    tauri::async_runtime::spawn_blocking(move || {
        let instances = collect_wsl_instances()?;
        Ok::<Option<String>, anyhow::Error>(
            instances
                .into_iter()
                .find(|item| item.name.to_ascii_lowercase() == target)
                .map(|item| item.state),
        )
    })
    .await
    .map_err(|e| anyhow!("Erreur JoinHandle lors de la lecture etat WSL: {e}"))?
}

async fn ensure_wsl_instance_running(instance: &str, trace_id: &str) -> Result<()> {
    let Some(initial_state) = wsl_instance_state(instance).await? else {
        anyhow::bail!("Instance WSL '{}' introuvable.", instance);
    };

    if wsl_state_is_running(&initial_state) {
        info!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            state = %initial_state,
            "Instance WSL deja demarree pour execution Kubernetes"
        );
        if is_home_lab_wsl_instance(instance) {
            ensure_wsl_keepalive(instance, "already-running").await?;
            ensure_home_lab_k3s_runtime_started(instance, trace_id, true).await?;
        }
        return Ok(());
    }

    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        state = %initial_state,
        "Demarrage automatique de l'instance WSL pour execution Kubernetes"
    );
    log_wsl_event(format!(
        "[{trace_id}] Demarrage auto de l'instance WSL {} (etat initial={})",
        escape_for_log(instance),
        escape_for_log(&initial_state)
    ));

    let instance_owned = instance.to_string();
    let output = tauri::async_runtime::spawn_blocking(move || {
        Command::new("wsl.exe")
            .args(["-d", &instance_owned, "--", "sh", "-lc", "true"])
            .output()
    })
    .await
    .map_err(|e| anyhow!("Erreur JoinHandle lors du demarrage WSL: {e}"))?
    .with_context(|| format!("Impossible de demarrer l'instance WSL '{}'", instance))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    if !output.status.success() {
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else if !stdout.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            format!("wsl.exe -d {} a echoue ({})", instance, output.status)
        };
        anyhow::bail!("{detail}");
    }

    sleep(Duration::from_millis(300)).await;
    let Some(final_state) = wsl_instance_state(instance).await? else {
        anyhow::bail!(
            "Instance WSL '{}' introuvable apres tentative de demarrage.",
            instance
        );
    };

    if !wsl_state_is_running(&final_state) {
        anyhow::bail!(
            "Instance WSL '{}' non demarree apres tentative automatique (etat='{}').",
            instance,
            final_state
        );
    }

    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        state = %final_state,
        "Instance WSL demarree pour execution Kubernetes"
    );
    log_wsl_event(format!(
        "[{trace_id}] Instance WSL demarree: {} (etat={})",
        escape_for_log(instance),
        escape_for_log(&final_state)
    ));
    if is_home_lab_wsl_instance(instance) {
        ensure_wsl_keepalive(instance, trace_id).await?;
        ensure_home_lab_k3s_runtime_started(instance, trace_id, false).await?;
    }
    Ok(())
}

async fn sync_home_lab_k3s_runtime_files(instance: &str, trace_id: &str) -> Result<()> {
    if !is_home_lab_wsl_instance(instance) {
        return Ok(());
    }

    let k3s_init_script = K3S_INIT_SCRIPT_RESOURCE
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let env_file = render_k3s_env_file_for_instance(instance)?;
    let rewrite_env_script = render_k3s_env_rewrite_script(&env_file);
    let script = format!(
        r#"set -eu
mkdir -p /usr/local/bin /etc/local.d
cat > /usr/local/bin/k3s-init.sh <<'__HOME_LAB_K3S_INIT_EOF__'
{k3s_init_script}
__HOME_LAB_K3S_INIT_EOF__
chmod +x /usr/local/bin/k3s-init.sh
{rewrite_env_script}
cat > /etc/wsl.conf <<'EOF'
[boot]
command="sh /usr/local/bin/k3s-init.sh"
EOF
cat > /etc/local.d/k3s.start <<'EOF'
#!/bin/sh
exec sh /usr/local/bin/k3s-init.sh
EOF
chmod +x /etc/local.d/k3s.start
"#
    );

    let instance_owned = instance.to_string();
    let script_owned = script.clone();
    let (stdout, stderr) = tauri::async_runtime::spawn_blocking(move || {
        run_wsl_shell_script_via_stdin(
            &instance_owned,
            &script_owned,
            "synchronisation des scripts k3s",
        )
    })
    .await
    .map_err(|e| anyhow!("Erreur JoinHandle lors de la synchronisation k3s-init: {e}"))??;

    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        stdout = %escape_for_log(stdout.trim()),
        stderr = %escape_for_log(stderr.trim()),
        "Scripts k3s synchronises dans l'instance WSL"
    );
    log_wsl_event(format!(
        "[{trace_id}] Synchronisation scripts k3s pour {}: stdout={} stderr={}",
        escape_for_log(instance),
        escape_for_log(stdout.trim()),
        escape_for_log(stderr.trim())
    ));

    Ok(())
}

async fn ensure_home_lab_k3s_runtime_started(
    instance: &str,
    trace_id: &str,
    allow_stale_repair: bool,
) -> Result<()> {
    if !is_home_lab_wsl_instance(instance) {
        return Ok(());
    }

    sync_home_lab_k3s_runtime_files(instance, trace_id).await?;
    if let Err(err) = configure_cluster_networking(instance).await {
        warn!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            error = %err,
            "Reconciliation reseau/proxy impossible avant demarrage k3s"
        );
        log_wsl_event(format!(
            "[{trace_id}] Reconciliation reseau/proxy impossible pour {}: {}",
            escape_for_log(instance),
            escape_for_log(&err.to_string())
        ));
    }

    let api_port = instance_port_plan(instance).api_backend_port;
    let instance_owned = instance.to_string();
    let repair_flag = if allow_stale_repair { "1" } else { "0" };
    let script = format!(
        r#"set -eu
if [ ! -s /usr/local/bin/k3s-init.sh ]; then
    exit 0
fi
if [ -f /run/k3s-init.lock/pid ]; then
    lock_pid=$(cat /run/k3s-init.lock/pid 2>/dev/null | tr -dc '0-9' || true)
    lock_cmdline=''
    if [ -n "$lock_pid" ] && [ -r /proc/"$lock_pid"/cmdline ]; then
        lock_cmdline=$(tr '\000' ' ' < "/proc/$lock_pid/cmdline" 2>/dev/null || true)
    fi
    case "$lock_cmdline" in
        "sh /usr/local/bin/k3s-init.sh"*|"/bin/sh /usr/local/bin/k3s-init.sh"*)
            ;;
        *)
            rm -rf /run/k3s-init.lock || true
            printf '%s\n' 'stale-k3s-init-lock-cleared'
            ;;
    esac
fi
if pgrep -f '^/usr/local/bin/k3s server( |$)' >/dev/null 2>&1; then
    printf '%s\n' 'k3s-server-present'
    exit 0
fi
if pgrep -f '^sh /usr/local/bin/k3s-init.sh( |$)' >/dev/null 2>&1 || pgrep -f '^/bin/sh /usr/local/bin/k3s-init.sh( |$)' >/dev/null 2>&1; then
    if [ "{repair_flag}" != "1" ]; then
        printf '%s\n' 'k3s-init-present'
        exit 0
    fi
    printf '%s\n' 'restart-stale-k3s-init'
    pkill -f '^sh /usr/local/bin/k3s-init.sh( |$)' >/dev/null 2>&1 || true
    pkill -f '^/bin/sh /usr/local/bin/k3s-init.sh( |$)' >/dev/null 2>&1 || true
    pkill -f '^/usr/local/bin/k3s server( |$)' >/dev/null 2>&1 || true
    rm -rf /run/k3s-init.lock || true
    sleep 1
fi
printf 'launch-k3s-init port=%s repair=%s\n' '{api_port}' '{repair_flag}'
"#
    );
    let command_line = format_cli_command("wsl.exe", &["-d", instance, "--", "sh", "-lc", &script]);
    let output = tauri::async_runtime::spawn_blocking(move || {
        Command::new("wsl.exe")
            .args(["-d", &instance_owned, "--", "sh", "-lc", &script])
            .output()
    })
    .await
    .map_err(|e| anyhow!("Erreur JoinHandle lors du lancement k3s-init: {e}"))?
    .with_context(|| format!("Impossible de lancer k3s-init.sh pour '{}'", instance))?;

    let stdout = decode_cli_output(&output.stdout);
    let stderr = decode_cli_output(&output.stderr);
    if !output.status.success() {
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else if !stdout.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            format!("wsl.exe -d {} a echoue ({})", instance, output.status)
        };
        anyhow::bail!(
            "Demarrage k3s-init impossible pour {} (cmd={}): {}",
            instance,
            command_line,
            detail
        );
    }

    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        command = %command_line,
        stdout = %escape_for_log(stdout.trim()),
        stderr = %escape_for_log(stderr.trim()),
        "Lancement k3s-init demande pour l'instance WSL"
    );
    log_wsl_event(format!(
        "[{trace_id}] Lancement k3s-init demande pour {}: stdout={} stderr={}",
        escape_for_log(instance),
        escape_for_log(stdout.trim()),
        escape_for_log(stderr.trim())
    ));

    if stdout.contains("launch-k3s-init") {
        let instance_for_launcher = instance.to_string();
        tauri::async_runtime::spawn_blocking(move || {
            run_k3s_runtime_launcher(&instance_for_launcher)
        })
        .await
        .map_err(|e| anyhow!("Erreur JoinHandle lors du demarrage runtime k3s: {e}"))??;
    }

    sleep(Duration::from_millis(350)).await;
    Ok(())
}

async fn tcp_connect_once(
    host: &str,
    port: u16,
    timeout: Duration,
) -> std::result::Result<(), String> {
    match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err("timeout TCP".to_string()),
    }
}

async fn collect_k3s_runtime_failure_hint(instance: &str) -> Option<String> {
    let instance_owned = instance.to_string();
    let script = r#"set -eu
for file in /tmp/k3s-init.err /tmp/k3s-init.out /tmp/k3s-init.boot.err /tmp/k3s-init.boot.out; do
    if [ -f "$file" ]; then
        if grep -Ei 'error|fail|already in use|another k3s-init|unable|refused' "$file" >/dev/null 2>&1; then
            grep -Ei 'error|fail|already in use|another k3s-init|unable|refused' "$file" | tail -n 3
            exit 0
        fi
    fi
done
ps -ef | grep -E 'k3s-init|/usr/local/bin/k3s server|containerd' | grep -v grep | tail -n 3 || true
"#;
    let output = tauri::async_runtime::spawn_blocking(move || {
        Command::new("wsl.exe")
            .args(["-d", &instance_owned, "--", "sh", "-lc", script])
            .output()
    })
    .await
    .ok()?
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let summary = decode_cli_output(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .join(" | ");

    if summary.is_empty() {
        None
    } else {
        Some(summary)
    }
}

fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim().to_ascii_lowercase();
    if normalized == "localhost" {
        return true;
    }
    normalized
        .parse::<Ipv4Addr>()
        .map(|addr| addr.is_loopback())
        .unwrap_or(normalized == "::1")
}

async fn resolve_kube_api_port_for_instance(instance: &str, trace_id: &str) -> u16 {
    let plan = instance_port_plan(instance);
    if !is_home_lab_wsl_instance(instance) {
        let expected_port = plan.api_backend_port;
        let instance_owned = instance.to_string();
        let script = "set -eu; if [ -f /etc/k3s-env ]; then line=$(grep '^K3S_API_PORT=' /etc/k3s-env | head -n1 || true); if [ -n \"$line\" ]; then port=${line#K3S_API_PORT=}; printf '%s\\n' \"$port\"; exit 0; fi; line=$(grep '^PORT_RANGE=' /etc/k3s-env | head -n1 || true); if [ -n \"$line\" ]; then range=${line#PORT_RANGE=}; port=${range%%-*}; printf '%s\\n' \"$port\"; exit 0; fi; fi; if [ -f /etc/rancher/k3s/k3s.yaml ]; then line=$(grep -E '^[[:space:]]*server:[[:space:]]*https?://' /etc/rancher/k3s/k3s.yaml | head -n1 || true); if [ -n \"$line\" ]; then port=$(printf '%s\\n' \"$line\" | sed -n 's#.*://[^:]*:\\([0-9][0-9]*\\).*#\\1#p' | head -n1); if [ -n \"$port\" ]; then printf '%s\\n' \"$port\"; exit 0; fi; fi; fi; exit 0";
        let detected = tauri::async_runtime::spawn_blocking(move || {
            Command::new("wsl.exe")
                .args(["-d", &instance_owned, "--", "sh", "-lc", script])
                .output()
        })
        .await
        .ok()
        .and_then(|result| result.ok())
        .and_then(|output| {
            if !output.status.success() {
                return None;
            }
            decode_cli_output(&output.stdout)
                .lines()
                .map(|line| line.trim())
                .find_map(|line| line.parse::<u16>().ok())
        });

        let api_port = detected.unwrap_or(expected_port);
        if api_port != expected_port {
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                expected_api_port = expected_port,
                detected_api_port = api_port,
                "Port API Kubernetes detecte differe du port attendu; utilisation du port detecte depuis les fichiers d'instance"
            );
        }
        return api_port;
    }

    let api_port = plan.api_backend_port;
    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        selected_api_port = api_port,
        "Port API Kubernetes backend retenu pour les operations internes"
    );
    api_port
}

#[derive(Clone, Debug)]
struct KubeApiEndpoint {
    host: String,
    port: u16,
    tls_server_name: Option<String>,
}

fn home_lab_public_kube_api_endpoint(instance: &str) -> Result<KubeApiEndpoint> {
    let plan = instance_port_plan(instance);
    let domain = primary_cluster_domain(instance).ok_or_else(|| {
        anyhow!(
            "Aucun domaine principal disponible pour l'endpoint API Kubernetes de '{}'.",
            instance
        )
    })?;

    Ok(KubeApiEndpoint {
        host: domain.clone(),
        port: plan.api_public_port,
        tls_server_name: Some(domain),
    })
}

async fn resolve_kube_api_endpoint_for_instance(
    instance: &str,
    trace_id: &str,
) -> Result<KubeApiEndpoint> {
    if is_home_lab_wsl_instance(instance) {
        sync_home_http_wsl_target(instance, trace_id).await?;
        let endpoint = home_lab_public_kube_api_endpoint(instance)?;
        info!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            api_host = %endpoint.host,
            api_port = endpoint.port,
            tls_server_name = %endpoint.tls_server_name.as_deref().unwrap_or(""),
            "Endpoint API Kubernetes retenu (proxy SNI public)"
        );
        log_wsl_event(format!(
            "[{trace_id}] Endpoint API Kubernetes pour {}: {}:{} (proxy-sni-public)",
            escape_for_log(instance),
            escape_for_log(&endpoint.host),
            endpoint.port
        ));
        return Ok(endpoint);
    }

    let api_port = resolve_kube_api_port_for_instance(instance, trace_id).await;
    if let Some(domain) = primary_cluster_domain(instance) {
        if tcp_connect_once(&domain, api_port, Duration::from_millis(700))
            .await
            .is_ok()
        {
            return Ok(KubeApiEndpoint {
                host: domain,
                port: api_port,
                tls_server_name: None,
            });
        }
    }

    if tcp_connect_once("127.0.0.1", api_port, Duration::from_millis(700))
        .await
        .is_ok()
    {
        return Ok(KubeApiEndpoint {
            host: "127.0.0.1".to_string(),
            port: api_port,
            tls_server_name: None,
        });
    }

    if let Some(domain) = primary_cluster_domain(instance) {
        info!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            api_host = %domain,
            api_port = api_port,
            "Endpoint API Kubernetes retenu (proxy SNI public)"
        );
        log_wsl_event(format!(
            "[{trace_id}] Endpoint API Kubernetes pour {}: {}:{}",
            escape_for_log(instance),
            escape_for_log(&domain),
            api_port
        ));
        return Ok(KubeApiEndpoint {
            host: domain,
            port: api_port,
            tls_server_name: None,
        });
    }

    anyhow::bail!(
        "Aucun domaine principal disponible pour l'endpoint API Kubernetes de '{}'.",
        instance
    )
}

async fn wait_for_kube_api_port(
    instance: &str,
    endpoint: &KubeApiEndpoint,
    trace_id: &str,
) -> Result<KubeApiEndpoint> {
    let started_at = Instant::now();
    let timeout = Duration::from_secs(KUBE_API_READY_TIMEOUT_SECONDS);
    let mut attempt: u32 = 0;
    let mut last_error = String::new();
    let probe_targets = vec![(endpoint.host.clone(), endpoint.port)];

    loop {
        if started_at.elapsed() >= timeout {
            let mut message = if last_error.trim().is_empty() {
                format!(
                    "API Kubernetes indisponible sur {}:{} apres {}s.",
                    endpoint.host, endpoint.port, KUBE_API_READY_TIMEOUT_SECONDS
                )
            } else {
                format!(
                    "API Kubernetes indisponible sur {}:{} apres {}s (dernier essai: {}).",
                    endpoint.host, endpoint.port, KUBE_API_READY_TIMEOUT_SECONDS, last_error
                )
            };
            if let Some(hint) = collect_k3s_runtime_failure_hint(instance).await {
                message.push_str(" Diagnostic runtime: ");
                message.push_str(&hint);
            }
            return Err(anyhow!(message));
        }

        attempt += 1;
        for (probe_host, probe_port) in &probe_targets {
            match tcp_connect_once(probe_host, *probe_port, Duration::from_millis(900)).await {
                Ok(()) => {
                    info!(
                        target: "wsl",
                        trace_id = %trace_id,
                        instance = %instance,
                        api_host = %probe_host,
                        api_port = %probe_port,
                        attempts = attempt,
                        "Port API Kubernetes joignable"
                    );
                    return Ok(endpoint.clone());
                }
                Err(err) => {
                    last_error = format!("{probe_host}:{probe_port}: {err}");
                }
            }
        }

        sleep(Duration::from_millis(KUBE_API_READY_POLL_INTERVAL_MS)).await;
    }
}

fn kubeconfig_cluster_for_context_mut<'a>(
    kubeconfig: &'a mut Kubeconfig,
    context_name: &str,
) -> Option<&'a mut kube::config::Cluster> {
    let cluster_name = kubeconfig
        .contexts
        .iter()
        .find(|ctx| ctx.name == context_name)
        .and_then(|named| named.context.as_ref())
        .map(|ctx| ctx.cluster.clone())?;

    kubeconfig
        .clusters
        .iter_mut()
        .find(|named| named.name == cluster_name)
        .and_then(|named| named.cluster.as_mut())
}

fn apply_kube_api_endpoint_override(
    kubeconfig: &mut Kubeconfig,
    context_name: &str,
    api_host: &str,
    api_port: u16,
    tls_server_name: Option<&str>,
) -> Result<()> {
    let Some(cluster) = kubeconfig_cluster_for_context_mut(kubeconfig, context_name) else {
        anyhow::bail!(
            "Cluster kubeconfig introuvable pour le contexte '{}'.",
            context_name
        );
    };

    let base_server = cluster
        .server
        .as_deref()
        .and_then(|value| Url::parse(value).ok())
        .map(|url| {
            if url.scheme() == "http" {
                "http".to_string()
            } else {
                "https".to_string()
            }
        })
        .unwrap_or_else(|| "https".to_string());

    cluster.server = Some(format!("{base_server}://{api_host}:{api_port}"));
    if let Some(server_name) = tls_server_name.filter(|value| !value.trim().is_empty()) {
        cluster.tls_server_name = Some(server_name.to_string());
    } else if is_loopback_host(api_host) || api_host.parse::<Ipv4Addr>().is_ok() {
        cluster.tls_server_name = None;
    } else {
        cluster.tls_server_name = Some(api_host.to_string());
    }
    cluster.proxy_url = None;
    Ok(())
}

fn ensure_rustls_crypto_provider(trace_id: &str, instance: &str) -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_ok()
    {
        info!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            provider = "aws-lc-rs",
            "Provider TLS Rustls installe"
        );
        return Ok(());
    }

    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_ok()
    {
        info!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            provider = "ring",
            "Provider TLS Rustls installe"
        );
        return Ok(());
    }

    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    anyhow::bail!("Impossible d'initialiser le provider TLS Rustls (aws-lc-rs/ring).");
}

async fn build_kube_client_for_instance(
    instance: &str,
    api_endpoint: Option<&KubeApiEndpoint>,
) -> Result<(Client, KubeClientConfig, String, PathBuf)> {
    let context_name = kube_context_for_instance(instance);
    let kubeconfig_path = windows_kubeconfig_path()?;
    if !kubeconfig_path.exists() {
        info!(
            target: "wsl",
            context = %context_name,
            kubeconfig = %kubeconfig_path.display(),
            "Kubeconfig Windows absent; tentative de synchronisation automatique"
        );
        sync_windows_kubeconfig_task().await?;
    }
    if !kubeconfig_path.exists() {
        anyhow::bail!(
            "Aucun kubeconfig Windows detecte sur {}. Lance d'abord la synchronisation kubeconfig.",
            kubeconfig_path.display()
        );
    }

    let mut kubeconfig = Kubeconfig::read_from(kubeconfig_path.clone()).with_context(|| {
        format!(
            "Lecture du kubeconfig Windows impossible sur {}",
            kubeconfig_path.display()
        )
    })?;

    if !kubeconfig_has_context(&kubeconfig, &context_name) {
        info!(
            target: "wsl",
            context = %context_name,
            kubeconfig = %kubeconfig_path.display(),
            "Contexte kubeconfig manquant; tentative de synchronisation automatique"
        );
        let sync = sync_windows_kubeconfig_task().await?;
        kubeconfig = Kubeconfig::read_from(kubeconfig_path.clone()).with_context(|| {
            format!(
                "Lecture du kubeconfig Windows impossible sur {} apres synchronisation automatique",
                kubeconfig_path.display()
            )
        })?;
        if !kubeconfig_has_context(&kubeconfig, &context_name) {
            let hint = if sync.skipped.is_empty() {
                "Aucune instance WSL n'a fourni de kubeconfig valide.".to_string()
            } else {
                format!(
                    "Instances ignorees lors de la sync: {}",
                    sync.skipped.join(" | ")
                )
            };
            anyhow::bail!(
                "Contexte kubeconfig '{}' introuvable apres synchronisation automatique. {}",
                context_name,
                hint
            );
        }
    }

    if let Some(endpoint) = api_endpoint {
        apply_kube_api_endpoint_override(
            &mut kubeconfig,
            &context_name,
            &endpoint.host,
            endpoint.port,
            endpoint.tls_server_name.as_deref(),
        )
        .with_context(|| {
            format!(
                "Application endpoint API Kubernetes impossible pour le contexte '{}'",
                context_name
            )
        })?;
        info!(
            target: "wsl",
            instance = %instance,
            context = %context_name,
            api_host = %endpoint.host,
            api_port = endpoint.port,
            "Endpoint API Kubernetes applique au kubeconfig en memoire"
        );
    }

    let options = KubeConfigOptions {
        context: Some(context_name.clone()),
        ..KubeConfigOptions::default()
    };
    let mut config = KubeClientConfig::from_custom_kubeconfig(kubeconfig, &options)
        .await
        .with_context(|| format!("Chargement du contexte kubeconfig '{}'", context_name))?;
    // Guard against long hangs when the API endpoint is unreachable.
    config.connect_timeout = Some(Duration::from_secs(KUBE_CONNECT_TIMEOUT_SECONDS));
    config.read_timeout = Some(Duration::from_secs(KUBE_IO_TIMEOUT_SECONDS));
    config.write_timeout = Some(Duration::from_secs(KUBE_IO_TIMEOUT_SECONDS));
    // Ignore system proxy settings for local k3s API access via 127.0.0.1.
    config.proxy_url = None;
    let client = Client::try_from(config.clone())
        .with_context(|| format!("Creation du client Kubernetes pour '{}'", context_name))?;

    Ok((client, config, context_name, kubeconfig_path))
}

async fn list_nodes(client: &Client, wide: bool) -> Result<String> {
    let api: Api<Node> = Api::all(client.clone());
    let mut items = api.list(&ListParams::default()).await?.items;
    items.sort_by(|left, right| {
        left.metadata
            .name
            .as_deref()
            .unwrap_or("")
            .cmp(right.metadata.name.as_deref().unwrap_or(""))
    });

    if items.is_empty() {
        return Ok("No resources found.".to_string());
    }

    let mut rows = Vec::with_capacity(items.len());
    for node in items {
        let name = node
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        let status = node_ready_status(&node);
        let roles = node_roles(&node);
        let age = format_age(node.metadata.creation_timestamp.as_ref());
        let version = node
            .status
            .as_ref()
            .and_then(|status| status.node_info.as_ref())
            .map(|info| info.kubelet_version.clone())
            .unwrap_or_else(|| "-".to_string());

        let mut row = vec![name, status, roles, age, version];
        if wide {
            let internal_ip = node_address(&node, "InternalIP");
            let external_ip = node_address(&node, "ExternalIP");
            let (os_image, kernel, runtime) = node
                .status
                .as_ref()
                .and_then(|status| status.node_info.as_ref())
                .map(|info| {
                    (
                        info.os_image.clone(),
                        info.kernel_version.clone(),
                        info.container_runtime_version.clone(),
                    )
                })
                .unwrap_or_else(|| ("-".to_string(), "-".to_string(), "-".to_string()));
            row.extend([internal_ip, external_ip, os_image, kernel, runtime]);
        }
        rows.push(row);
    }

    let headers: Vec<&str> = if wide {
        vec![
            "NAME",
            "STATUS",
            "ROLES",
            "AGE",
            "VERSION",
            "INTERNAL-IP",
            "EXTERNAL-IP",
            "OS-IMAGE",
            "KERNEL-VERSION",
            "CONTAINER-RUNTIME",
        ]
    } else {
        vec!["NAME", "STATUS", "ROLES", "AGE", "VERSION"]
    };

    Ok(render_table(&headers, &rows))
}

async fn list_namespaces(client: &Client) -> Result<String> {
    let api: Api<Namespace> = Api::all(client.clone());
    let mut items = api.list(&ListParams::default()).await?.items;
    items.sort_by(|left, right| {
        left.metadata
            .name
            .as_deref()
            .unwrap_or("")
            .cmp(right.metadata.name.as_deref().unwrap_or(""))
    });

    if items.is_empty() {
        return Ok("No resources found.".to_string());
    }

    let mut rows = Vec::with_capacity(items.len());
    for namespace in items {
        let name = namespace
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        let phase = namespace
            .status
            .as_ref()
            .and_then(|status| status.phase.clone())
            .unwrap_or_else(|| "-".to_string());
        let age = format_age(namespace.metadata.creation_timestamp.as_ref());
        rows.push(vec![name, phase, age]);
    }

    Ok(render_table(&["NAME", "STATUS", "AGE"], &rows))
}

async fn list_pods(
    client: &Client,
    config: &KubeClientConfig,
    namespace: Option<&str>,
    all_namespaces: bool,
    wide: bool,
) -> Result<String> {
    let selected_namespace = namespace.unwrap_or(config.default_namespace.as_str());
    let mut items = if all_namespaces {
        let api: Api<Pod> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<Pod> = Api::namespaced(client.clone(), selected_namespace);
        api.list(&ListParams::default()).await?.items
    };

    items.sort_by(|left, right| {
        let left_ns = left.metadata.namespace.as_deref().unwrap_or("");
        let right_ns = right.metadata.namespace.as_deref().unwrap_or("");
        match left_ns.cmp(right_ns) {
            std::cmp::Ordering::Equal => left
                .metadata
                .name
                .as_deref()
                .unwrap_or("")
                .cmp(right.metadata.name.as_deref().unwrap_or("")),
            order => order,
        }
    });

    if items.is_empty() {
        if all_namespaces {
            return Ok("No resources found.".to_string());
        }
        return Ok(format!(
            "No resources found in {} namespace.",
            selected_namespace
        ));
    }

    let mut rows = Vec::with_capacity(items.len());
    for pod in items {
        let namespace = pod
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| selected_namespace.to_string());
        let name = pod
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        let ready = pod_ready_counts(&pod);
        let status = pod_status_label(&pod);
        let restarts = pod_restarts(&pod);
        let age = format_age(pod.metadata.creation_timestamp.as_ref());
        let ip = pod
            .status
            .as_ref()
            .and_then(|status| status.pod_ip.clone())
            .unwrap_or_else(|| "-".to_string());
        let node = pod
            .spec
            .as_ref()
            .and_then(|spec| spec.node_name.clone())
            .unwrap_or_else(|| "-".to_string());

        let mut row = Vec::new();
        if all_namespaces {
            row.push(namespace);
        }
        row.push(name);
        row.push(ready);
        row.push(status);
        row.push(restarts);
        row.push(age);
        if wide {
            row.push(ip);
            row.push(node);
        }
        rows.push(row);
    }

    let headers: Vec<&str> = if all_namespaces {
        if wide {
            vec![
                "NAMESPACE",
                "NAME",
                "READY",
                "STATUS",
                "RESTARTS",
                "AGE",
                "IP",
                "NODE",
            ]
        } else {
            vec!["NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE"]
        }
    } else if wide {
        vec!["NAME", "READY", "STATUS", "RESTARTS", "AGE", "IP", "NODE"]
    } else {
        vec!["NAME", "READY", "STATUS", "RESTARTS", "AGE"]
    };

    Ok(render_table(&headers, &rows))
}

fn default_namespace(config: &KubeClientConfig, namespace: Option<&str>) -> String {
    namespace
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(config.default_namespace.as_str())
        .to_string()
}

fn singularize_plural(plural: &str) -> String {
    if plural.ends_with("ies") && plural.len() > 3 {
        let mut base = plural[..plural.len() - 3].to_string();
        base.push('y');
        return base;
    }
    for suffix in ["sses", "xes", "zes", "ches", "shes"] {
        if plural.ends_with(suffix) && plural.len() > 2 {
            return plural[..plural.len() - 2].to_string();
        }
    }
    if plural.ends_with('s') && plural.len() > 1 {
        return plural[..plural.len() - 1].to_string();
    }
    plural.to_string()
}

fn split_group_hint(resource: &str) -> (String, Option<String>) {
    let token = resource.trim().to_ascii_lowercase();
    if let Some((base, group_hint)) = token.split_once('.') {
        let normalized_base = normalize_resource_alias(base);
        let hint = group_hint.trim().to_string();
        if !hint.is_empty() {
            return (normalized_base, Some(hint));
        }
        return (normalized_base, None);
    }
    (normalize_resource_alias(&token), None)
}

fn resource_match_score(
    resource_token: &str,
    group_hint: Option<&str>,
    api_resource: &discovery::ApiResource,
) -> i32 {
    let plural = api_resource.plural.to_ascii_lowercase();
    let kind = api_resource.kind.to_ascii_lowercase();
    let singular = singularize_plural(&plural);

    let mut score = if resource_token == plural {
        300
    } else if resource_token == kind {
        280
    } else if resource_token == singular {
        260
    } else {
        0
    };
    if score == 0 {
        return 0;
    }

    let group = api_resource.group.to_ascii_lowercase();
    if let Some(hint) = group_hint {
        let matches = group == hint || group.ends_with(&format!(".{hint}"));
        if !matches {
            return 0;
        }
        score += 80;
    } else if resource_token == "events" {
        if group == "events.k8s.io" {
            score += 40;
        } else if group.is_empty() {
            score += 20;
        }
    } else if group.is_empty() {
        score += 20;
    }

    if api_resource.version == "v1" {
        score += 5;
    }
    score
}

fn resource_tie_breaker(resolved: &ResolvedResource) -> i32 {
    if resolved.api_resource.group == "events.k8s.io" {
        3
    } else if resolved.api_resource.group.is_empty() {
        2
    } else {
        1
    }
}

async fn resolve_dynamic_resource(client: &Client, resource: &str) -> Result<ResolvedResource> {
    let (normalized, group_hint) = split_group_hint(resource);
    let discovery = match Discovery::new(client.clone()).run_aggregated().await {
        Ok(discovery) => discovery,
        Err(err) => {
            warn!(
                target: "wsl",
                resource = %resource,
                error = %err,
                "Aggregated discovery indisponible, bascule sur discovery classique"
            );
            Discovery::new(client.clone()).run().await?
        }
    };

    let mut best: Option<(i32, ResolvedResource)> = None;
    for group in discovery.groups() {
        for (api_resource, capabilities) in group.recommended_resources() {
            if !capabilities.supports_operation(verbs::LIST)
                && !capabilities.supports_operation(verbs::GET)
            {
                continue;
            }
            let score = resource_match_score(&normalized, group_hint.as_deref(), &api_resource);
            if score <= 0 {
                continue;
            }

            let candidate = ResolvedResource {
                api_resource: api_resource.clone(),
                scope: capabilities.scope.clone(),
            };
            match &best {
                None => best = Some((score, candidate)),
                Some((current_score, current)) => {
                    if score > *current_score
                        || (score == *current_score
                            && resource_tie_breaker(&candidate) > resource_tie_breaker(current))
                    {
                        best = Some((score, candidate));
                    }
                }
            }
        }
    }

    best.map(|(_, resolved)| resolved).ok_or_else(|| {
        anyhow!(
            "Ressource kubectl '{}' introuvable via l'API Kubernetes.",
            resource
        )
    })
}

async fn list_dynamic_objects(
    client: &Client,
    config: &KubeClientConfig,
    resolved: &ResolvedResource,
    namespace: Option<&str>,
    all_namespaces: bool,
    field_selector: Option<&str>,
) -> Result<Vec<DynamicObject>> {
    let mut params = ListParams::default();
    if let Some(selector) = field_selector {
        params = params.fields(selector);
    }

    match resolved.scope {
        DiscoveryScope::Cluster => {
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &resolved.api_resource);
            Ok(api.list(&params).await?.items)
        }
        DiscoveryScope::Namespaced => {
            if all_namespaces {
                let api: Api<DynamicObject> = Api::all_with(client.clone(), &resolved.api_resource);
                Ok(api.list(&params).await?.items)
            } else {
                let namespace = default_namespace(config, namespace);
                let api: Api<DynamicObject> =
                    Api::namespaced_with(client.clone(), &namespace, &resolved.api_resource);
                Ok(api.list(&params).await?.items)
            }
        }
    }
}

async fn get_named_dynamic_objects(
    client: &Client,
    config: &KubeClientConfig,
    resolved: &ResolvedResource,
    names: &[String],
    namespace: Option<&str>,
    all_namespaces: bool,
) -> Result<Vec<DynamicObject>> {
    let mut objects = Vec::new();
    for name in names {
        if name.trim().is_empty() {
            continue;
        }
        match resolved.scope {
            DiscoveryScope::Cluster => {
                let api: Api<DynamicObject> = Api::all_with(client.clone(), &resolved.api_resource);
                let object = api.get(name).await.with_context(|| {
                    format!(
                        "Ressource {} '{}' introuvable",
                        resolved.api_resource.plural, name
                    )
                })?;
                objects.push(object);
            }
            DiscoveryScope::Namespaced => {
                if all_namespaces {
                    let selector = format!("metadata.name={}", name);
                    let mut matched =
                        list_dynamic_objects(client, config, resolved, None, true, Some(&selector))
                            .await?;
                    if matched.is_empty() {
                        anyhow::bail!(
                            "Ressource {} '{}' introuvable dans les namespaces.",
                            resolved.api_resource.plural,
                            name
                        );
                    }
                    objects.append(&mut matched);
                } else {
                    let ns = default_namespace(config, namespace);
                    let api: Api<DynamicObject> =
                        Api::namespaced_with(client.clone(), &ns, &resolved.api_resource);
                    let object = api.get(name).await.with_context(|| {
                        format!(
                            "Ressource {} '{}' introuvable dans le namespace '{}'",
                            resolved.api_resource.plural, name, ns
                        )
                    })?;
                    objects.push(object);
                }
            }
        }
    }
    Ok(objects)
}

fn sort_dynamic_objects(objects: &mut [DynamicObject]) {
    objects.sort_by(|left, right| {
        let left_ns = left.metadata.namespace.as_deref().unwrap_or("");
        let right_ns = right.metadata.namespace.as_deref().unwrap_or("");
        match left_ns.cmp(right_ns) {
            std::cmp::Ordering::Equal => left.name_any().cmp(&right.name_any()),
            order => order,
        }
    });
}

fn dynamic_status(object: &DynamicObject) -> String {
    if let Some(phase) = object
        .data
        .get("status")
        .and_then(|status| status.get("phase"))
        .and_then(|phase| phase.as_str())
        .filter(|phase| !phase.trim().is_empty())
    {
        return phase.to_string();
    }
    "-".to_string()
}

fn render_dynamic_get_table(
    resolved: &ResolvedResource,
    objects: &[DynamicObject],
    all_namespaces: bool,
    wide: bool,
) -> String {
    if objects.is_empty() {
        return "No resources found.".to_string();
    }
    let include_namespace = all_namespaces && resolved.scope == DiscoveryScope::Namespaced;
    let mut rows = Vec::with_capacity(objects.len());
    for object in objects {
        let mut row = Vec::new();
        if include_namespace {
            row.push(
                object
                    .metadata
                    .namespace
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            );
        }
        row.push(object.name_any());
        row.push(dynamic_status(object));
        row.push(format_age(object.metadata.creation_timestamp.as_ref()));
        if wide {
            row.push(
                object
                    .types
                    .as_ref()
                    .map(|types| types.kind.clone())
                    .unwrap_or_else(|| resolved.api_resource.kind.clone()),
            );
            row.push(
                object
                    .types
                    .as_ref()
                    .map(|types| types.api_version.clone())
                    .unwrap_or_else(|| resolved.api_resource.api_version.clone()),
            );
        }
        rows.push(row);
    }

    let headers: Vec<&str> = if include_namespace {
        if wide {
            vec!["NAMESPACE", "NAME", "STATUS", "AGE", "KIND", "API-VERSION"]
        } else {
            vec!["NAMESPACE", "NAME", "STATUS", "AGE"]
        }
    } else if wide {
        vec!["NAME", "STATUS", "AGE", "KIND", "API-VERSION"]
    } else {
        vec!["NAME", "STATUS", "AGE"]
    };

    render_table(&headers, &rows)
}

fn yaml_block(value: &serde_json::Value) -> Result<String> {
    let mut rendered = serde_yaml::to_string(value).context("Serialisation YAML impossible")?;
    if rendered.starts_with("---\n") {
        rendered = rendered.trim_start_matches("---\n").to_string();
    }
    Ok(rendered.trim_end().to_string())
}

fn append_map_section(output: &mut String, title: &str, map: Option<&BTreeMap<String, String>>) {
    output.push_str(title);
    output.push_str(":\n");
    match map {
        Some(values) if !values.is_empty() => {
            for (key, value) in values {
                output.push_str("  ");
                output.push_str(key);
                output.push_str(": ");
                output.push_str(value);
                output.push('\n');
            }
        }
        _ => output.push_str("  <none>\n"),
    }
}

fn append_json_section(output: &mut String, title: &str, value: Option<&serde_json::Value>) {
    output.push_str(title);
    output.push_str(":\n");
    match value {
        Some(value) => match yaml_block(value) {
            Ok(rendered) if !rendered.trim().is_empty() => {
                for line in rendered.lines() {
                    output.push_str("  ");
                    output.push_str(line);
                    output.push('\n');
                }
            }
            _ => output.push_str("  <none>\n"),
        },
        None => output.push_str("  <none>\n"),
    }
}

fn render_dynamic_describe_object(object: &DynamicObject, resolved: &ResolvedResource) -> String {
    let mut output = String::new();
    let kind = object
        .types
        .as_ref()
        .map(|types| types.kind.clone())
        .unwrap_or_else(|| resolved.api_resource.kind.clone());
    let api_version = object
        .types
        .as_ref()
        .map(|types| types.api_version.clone())
        .unwrap_or_else(|| resolved.api_resource.api_version.clone());

    output.push_str("Name:         ");
    output.push_str(&object.name_any());
    output.push('\n');
    if let Some(namespace) = object.metadata.namespace.as_deref() {
        output.push_str("Namespace:    ");
        output.push_str(namespace);
        output.push('\n');
    }
    output.push_str("Kind:         ");
    output.push_str(&kind);
    output.push('\n');
    output.push_str("API Version:  ");
    output.push_str(&api_version);
    output.push('\n');
    output.push_str("Created:      ");
    output.push_str(
        &object
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|value| value.0.to_string())
            .unwrap_or_else(|| "-".to_string()),
    );
    output.push('\n');
    output.push_str("Age:          ");
    output.push_str(&format_age(object.metadata.creation_timestamp.as_ref()));
    output.push('\n');

    append_map_section(&mut output, "Labels", object.metadata.labels.as_ref());
    append_map_section(
        &mut output,
        "Annotations",
        object.metadata.annotations.as_ref(),
    );
    append_json_section(&mut output, "Spec", object.data.get("spec"));
    append_json_section(&mut output, "Status", object.data.get("status"));

    output.trim_end().to_string()
}

fn object_matches_filter(
    object_kind: Option<&str>,
    object_name: Option<&str>,
    object_namespace: Option<&str>,
    filter: &KubectlObjectRef,
) -> bool {
    let filter_kind = normalize_kind_alias(&filter.kind);
    let kind = object_kind
        .map(normalize_kind_alias)
        .unwrap_or_else(|| "-".to_string());
    if kind != filter_kind {
        return false;
    }
    if object_name.unwrap_or_default() != filter.name {
        return false;
    }
    if let Some(expected_ns) = filter.namespace.as_deref() {
        return object_namespace.unwrap_or_default() == expected_ns;
    }
    true
}

fn event_sort_time_v1(event: &EventsV1Event) -> i64 {
    if let Some(event_time) = event.event_time.as_ref() {
        return event_time.0.as_second();
    }
    if let Some(last) = event.deprecated_last_timestamp.as_ref() {
        return last.0.as_second();
    }
    if let Some(first) = event.deprecated_first_timestamp.as_ref() {
        return first.0.as_second();
    }
    0
}

fn event_sort_time_core(event: &CoreEvent) -> i64 {
    if let Some(last) = event.last_timestamp.as_ref() {
        return last.0.as_second();
    }
    if let Some(first) = event.first_timestamp.as_ref() {
        return first.0.as_second();
    }
    if let Some(event_time) = event.event_time.as_ref() {
        return event_time.0.as_second();
    }
    0
}

fn convert_v1_event_rows(
    events: Vec<EventsV1Event>,
    filter: Option<&KubectlObjectRef>,
) -> Vec<EventRow> {
    let mut rows = Vec::new();
    for event in events {
        let object_kind = event
            .regarding
            .as_ref()
            .and_then(|ref_obj| ref_obj.kind.as_deref());
        let object_name = event
            .regarding
            .as_ref()
            .and_then(|ref_obj| ref_obj.name.as_deref());
        let object_ns = event
            .regarding
            .as_ref()
            .and_then(|ref_obj| ref_obj.namespace.as_deref());
        if let Some(filter) = filter {
            if !object_matches_filter(object_kind, object_name, object_ns, filter) {
                continue;
            }
        }

        let object = match (object_kind, object_name) {
            (Some(kind), Some(name)) if !kind.is_empty() && !name.is_empty() => {
                format!("{}/{}", kind, name)
            }
            _ => "-".to_string(),
        };
        let source = event
            .reporting_controller
            .clone()
            .or_else(|| {
                event
                    .deprecated_source
                    .as_ref()
                    .and_then(|source| source.component.clone())
            })
            .unwrap_or_else(|| "-".to_string());

        rows.push(EventRow {
            namespace: event
                .metadata
                .namespace
                .clone()
                .or_else(|| object_ns.map(str::to_string))
                .unwrap_or_else(|| "-".to_string()),
            event: event
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            last_seen: if event.event_time.is_some() {
                format_age_micro(event.event_time.as_ref())
            } else if event.deprecated_last_timestamp.is_some() {
                format_age(event.deprecated_last_timestamp.as_ref())
            } else {
                format_age(event.deprecated_first_timestamp.as_ref())
            },
            type_: event.type_.clone().unwrap_or_else(|| "-".to_string()),
            reason: event.reason.clone().unwrap_or_else(|| "-".to_string()),
            object,
            source,
            count: event.deprecated_count.unwrap_or(1),
            message: event.note.clone().unwrap_or_else(|| "-".to_string()),
            sort_timestamp: event_sort_time_v1(&event),
        });
    }
    rows
}

fn convert_core_event_rows(
    events: Vec<CoreEvent>,
    filter: Option<&KubectlObjectRef>,
) -> Vec<EventRow> {
    let mut rows = Vec::new();
    for event in events {
        let object_kind = event.involved_object.kind.as_deref();
        let object_name = event.involved_object.name.as_deref();
        let object_ns = event.involved_object.namespace.as_deref();

        if let Some(filter) = filter {
            if !object_matches_filter(object_kind, object_name, object_ns, filter) {
                continue;
            }
        }

        let source = event
            .reporting_component
            .clone()
            .or_else(|| {
                event
                    .source
                    .as_ref()
                    .and_then(|source| source.component.clone())
            })
            .unwrap_or_else(|| "-".to_string());

        rows.push(EventRow {
            namespace: event
                .metadata
                .namespace
                .clone()
                .or_else(|| object_ns.map(str::to_string))
                .unwrap_or_else(|| "-".to_string()),
            event: event
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            last_seen: if event.last_timestamp.is_some() {
                format_age(event.last_timestamp.as_ref())
            } else if event.first_timestamp.is_some() {
                format_age(event.first_timestamp.as_ref())
            } else {
                format_age_micro(event.event_time.as_ref())
            },
            type_: event.type_.clone().unwrap_or_else(|| "-".to_string()),
            reason: event.reason.clone().unwrap_or_else(|| "-".to_string()),
            object: format!(
                "{}/{}",
                event
                    .involved_object
                    .kind
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                event
                    .involved_object
                    .name
                    .clone()
                    .unwrap_or_else(|| "-".to_string())
            ),
            source,
            count: event.count.unwrap_or(1),
            message: event.message.clone().unwrap_or_else(|| "-".to_string()),
            sort_timestamp: event_sort_time_core(&event),
        });
    }
    rows
}

fn render_events_rows(rows: &[EventRow], all_namespaces: bool, wide: bool) -> String {
    if rows.is_empty() {
        return "No resources found.".to_string();
    }

    let mut rows_out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut rendered = Vec::new();
        if all_namespaces {
            rendered.push(row.namespace.clone());
        }
        rendered.push(row.last_seen.clone());
        rendered.push(row.type_.clone());
        rendered.push(row.reason.clone());
        rendered.push(row.object.clone());
        if wide {
            rendered.push(row.source.clone());
            rendered.push(row.count.to_string());
        }
        rendered.push(row.message.clone());
        rows_out.push(rendered);
    }

    let headers: Vec<&str> = if all_namespaces {
        if wide {
            vec![
                "NAMESPACE",
                "LAST SEEN",
                "TYPE",
                "REASON",
                "OBJECT",
                "SOURCE",
                "COUNT",
                "MESSAGE",
            ]
        } else {
            vec![
                "NAMESPACE",
                "LAST SEEN",
                "TYPE",
                "REASON",
                "OBJECT",
                "MESSAGE",
            ]
        }
    } else if wide {
        vec![
            "LAST SEEN",
            "TYPE",
            "REASON",
            "OBJECT",
            "SOURCE",
            "COUNT",
            "MESSAGE",
        ]
    } else {
        vec!["LAST SEEN", "TYPE", "REASON", "OBJECT", "MESSAGE"]
    };
    render_table(&headers, &rows_out)
}

async fn execute_kubectl_events(
    client: &Client,
    config: &KubeClientConfig,
    request: KubectlEventsRequest,
) -> Result<String> {
    let namespace = default_namespace(config, request.namespace.as_deref());
    let mut rows = if request.all_namespaces {
        let api: Api<EventsV1Event> = Api::all(client.clone());
        match api.list(&ListParams::default()).await {
            Ok(list) => convert_v1_event_rows(list.items, request.for_object.as_ref()),
            Err(_) => {
                let fallback_api: Api<CoreEvent> = Api::all(client.clone());
                let fallback = fallback_api.list(&ListParams::default()).await?;
                convert_core_event_rows(fallback.items, request.for_object.as_ref())
            }
        }
    } else {
        let api: Api<EventsV1Event> = Api::namespaced(client.clone(), &namespace);
        match api.list(&ListParams::default()).await {
            Ok(list) => convert_v1_event_rows(list.items, request.for_object.as_ref()),
            Err(_) => {
                let fallback_api: Api<CoreEvent> = Api::namespaced(client.clone(), &namespace);
                let fallback = fallback_api.list(&ListParams::default()).await?;
                convert_core_event_rows(fallback.items, request.for_object.as_ref())
            }
        }
    };

    if let Some(event_name) = request.event_name.as_deref() {
        rows.retain(|row| row.event == event_name);
    }

    rows.sort_by(|left, right| {
        right
            .sort_timestamp
            .cmp(&left.sort_timestamp)
            .then_with(|| left.namespace.cmp(&right.namespace))
            .then_with(|| left.object.cmp(&right.object))
    });

    Ok(render_events_rows(
        &rows,
        request.all_namespaces,
        request.wide,
    ))
}

async fn execute_kubectl_logs(
    client: &Client,
    config: &KubeClientConfig,
    request: KubectlLogsRequest,
) -> Result<String> {
    let namespace = default_namespace(config, request.namespace.as_deref());
    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);

    let base_log_params = LogParams {
        container: request.container.clone(),
        follow: false,
        limit_bytes: request.limit_bytes,
        pretty: false,
        previous: request.previous,
        since_seconds: request.since_seconds,
        since_time: None,
        tail_lines: request.tail_lines,
        timestamps: request.timestamps,
    };

    if request.all_containers {
        let pod = pods.get(&request.pod).await.with_context(|| {
            format!(
                "Pod '{}' introuvable dans le namespace '{}'",
                request.pod, namespace
            )
        })?;
        let mut container_names = Vec::new();
        if let Some(spec) = pod.spec.as_ref() {
            if let Some(init_containers) = spec.init_containers.as_ref() {
                for container in init_containers {
                    container_names.push(container.name.clone());
                }
            }
            for container in &spec.containers {
                container_names.push(container.name.clone());
            }
            if let Some(ephemeral_containers) = spec.ephemeral_containers.as_ref() {
                for container in ephemeral_containers {
                    container_names.push(container.name.clone());
                }
            }
        }
        container_names.sort();
        container_names.dedup();
        if container_names.is_empty() {
            anyhow::bail!("Aucun conteneur detecte pour le pod '{}'.", request.pod);
        }

        let mut outputs = Vec::new();
        for container in container_names {
            let mut params = base_log_params.clone();
            params.container = Some(container.clone());
            let logs = pods.logs(&request.pod, &params).await.with_context(|| {
                format!(
                    "Lecture des logs impossible pour le conteneur '{}'.",
                    container
                )
            })?;
            outputs.push(format!("==> container/{container} <==\n{logs}"));
        }
        return Ok(outputs.join("\n\n"));
    }

    pods.logs(&request.pod, &base_log_params)
        .await
        .with_context(|| {
            format!(
                "Lecture des logs impossible pour le pod '{}' dans le namespace '{}'.",
                request.pod, namespace
            )
        })
}

async fn execute_kubectl_describe(
    client: &Client,
    config: &KubeClientConfig,
    request: KubectlDescribeRequest,
) -> Result<String> {
    let resolved = resolve_dynamic_resource(client, &request.resource).await?;
    let mut objects = if request.names.is_empty() {
        list_dynamic_objects(
            client,
            config,
            &resolved,
            request.namespace.as_deref(),
            request.all_namespaces,
            None,
        )
        .await?
    } else {
        get_named_dynamic_objects(
            client,
            config,
            &resolved,
            &request.names,
            request.namespace.as_deref(),
            request.all_namespaces,
        )
        .await?
    };
    sort_dynamic_objects(&mut objects);

    if objects.is_empty() {
        return Ok("No resources found.".to_string());
    }

    Ok(objects
        .iter()
        .map(|object| render_dynamic_describe_object(object, &resolved))
        .collect::<Vec<String>>()
        .join("\n\n---\n\n"))
}

async fn execute_kubectl_get(
    client: &Client,
    config: &KubeClientConfig,
    request: KubectlGetRequest,
) -> Result<String> {
    if let Some(name) = request.name.clone() {
        return match request.resource {
            KubectlGetResource::Events => {
                execute_kubectl_events(
                    client,
                    config,
                    KubectlEventsRequest {
                        namespace: request.namespace,
                        all_namespaces: request.all_namespaces,
                        wide: request.wide,
                        for_object: None,
                        event_name: Some(name),
                    },
                )
                .await
            }
            KubectlGetResource::Nodes => {
                let resolved = resolve_dynamic_resource(client, "nodes").await?;
                let mut objects = get_named_dynamic_objects(
                    client,
                    config,
                    &resolved,
                    &[name],
                    request.namespace.as_deref(),
                    request.all_namespaces,
                )
                .await?;
                sort_dynamic_objects(&mut objects);
                Ok(render_dynamic_get_table(
                    &resolved,
                    &objects,
                    request.all_namespaces,
                    request.wide,
                ))
            }
            KubectlGetResource::Namespaces => {
                let resolved = resolve_dynamic_resource(client, "namespaces").await?;
                let mut objects = get_named_dynamic_objects(
                    client,
                    config,
                    &resolved,
                    &[name],
                    request.namespace.as_deref(),
                    request.all_namespaces,
                )
                .await?;
                sort_dynamic_objects(&mut objects);
                Ok(render_dynamic_get_table(
                    &resolved,
                    &objects,
                    request.all_namespaces,
                    request.wide,
                ))
            }
            KubectlGetResource::Pods => {
                let resolved = resolve_dynamic_resource(client, "pods").await?;
                let mut objects = get_named_dynamic_objects(
                    client,
                    config,
                    &resolved,
                    &[name],
                    request.namespace.as_deref(),
                    request.all_namespaces,
                )
                .await?;
                sort_dynamic_objects(&mut objects);
                Ok(render_dynamic_get_table(
                    &resolved,
                    &objects,
                    request.all_namespaces,
                    request.wide,
                ))
            }
            KubectlGetResource::Dynamic(resource) => {
                let resolved = resolve_dynamic_resource(client, &resource).await?;
                let mut objects = get_named_dynamic_objects(
                    client,
                    config,
                    &resolved,
                    &[name],
                    request.namespace.as_deref(),
                    request.all_namespaces,
                )
                .await?;
                sort_dynamic_objects(&mut objects);
                Ok(render_dynamic_get_table(
                    &resolved,
                    &objects,
                    request.all_namespaces,
                    request.wide,
                ))
            }
        };
    }

    match request.resource {
        KubectlGetResource::Nodes => list_nodes(client, request.wide).await,
        KubectlGetResource::Namespaces => list_namespaces(client).await,
        KubectlGetResource::Pods => {
            list_pods(
                client,
                config,
                request.namespace.as_deref(),
                request.all_namespaces,
                request.wide,
            )
            .await
        }
        KubectlGetResource::Events => {
            execute_kubectl_events(
                client,
                config,
                KubectlEventsRequest {
                    namespace: request.namespace,
                    all_namespaces: request.all_namespaces,
                    wide: request.wide,
                    for_object: None,
                    event_name: None,
                },
            )
            .await
        }
        KubectlGetResource::Dynamic(resource) => {
            let resolved = resolve_dynamic_resource(client, &resource).await?;
            let mut objects = list_dynamic_objects(
                client,
                config,
                &resolved,
                request.namespace.as_deref(),
                request.all_namespaces,
                None,
            )
            .await?;
            sort_dynamic_objects(&mut objects);
            Ok(render_dynamic_get_table(
                &resolved,
                &objects,
                request.all_namespaces,
                request.wide,
            ))
        }
    }
}

async fn execute_kubectl_command(
    client: &Client,
    config: &KubeClientConfig,
    command: KubectlCommand,
) -> Result<String> {
    match command {
        KubectlCommand::Get(request) => execute_kubectl_get(client, config, request).await,
        KubectlCommand::Describe(request) => {
            execute_kubectl_describe(client, config, request).await
        }
        KubectlCommand::Logs(request) => execute_kubectl_logs(client, config, request).await,
        KubectlCommand::Events(request) => execute_kubectl_events(client, config, request).await,
    }
}

async fn ensure_home_lab_cluster_default_tls(
    client: &Client,
    config: &KubeClientConfig,
    instance: &str,
    trace_id: &str,
) -> Result<()> {
    if !is_home_lab_wsl_instance(instance) {
        return Ok(());
    }

    let (tls_store_api_version, tls_store_resource) =
        wait_for_traefik_tls_store_resource(client, trace_id, instance).await?;
    let existing_cert_pem = read_home_lab_default_tls_secret_cert_pem(client).await?;
    let secret_is_already_valid = match existing_cert_pem.as_deref() {
        Some(cert_pem) => match home_lab_default_tls_cert_matches_instance(cert_pem, instance) {
            Ok(valid) => valid,
            Err(err) => {
                warn!(
                    target: "wsl",
                    trace_id = %trace_id,
                    instance = %instance,
                    error = %err,
                    "Verification du secret TLS Traefik existant impossible; regeneration forcee"
                );
                false
            }
        },
        None => false,
    };
    let secret_stdout = if secret_is_already_valid {
        "secret/home-lab-default-tls deja valide".to_string()
    } else {
        let assets = build_home_lab_default_tls_assets(instance, &tls_store_api_version)?;
        execute_kubectl_apply_yaml(client, config, &assets.secret_manifest).await?
    };
    let tls_store_manifest = render_home_lab_default_tls_store_manifest(&tls_store_api_version);
    let tls_store_stdout = execute_kubectl_apply_yaml(client, config, &tls_store_manifest).await?;
    verify_home_lab_default_tls_resources(client, &tls_store_resource, instance).await?;
    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        secret_reused = secret_is_already_valid,
        tls_store_api_version = %tls_store_api_version,
        secret_stdout = %escape_for_log(secret_stdout.trim()),
        tls_store_stdout = %escape_for_log(tls_store_stdout.trim()),
        "Certificat TLS par defaut Traefik reconcilie et verifie"
    );
    log_wsl_event(format!(
        "[{trace_id}] Certificat TLS Traefik reconcilie pour {}: secret={} tlsstore={} apiVersion={}",
        escape_for_log(instance),
        escape_for_log(secret_stdout.trim()),
        escape_for_log(tls_store_stdout.trim()),
        escape_for_log(&tls_store_api_version)
    ));
    Ok(())
}

async fn reconcile_home_lab_cluster_default_tls(
    instance: &str,
    trace_id: &str,
) -> Result<HomeLabTraefikTlsReconcileStatus> {
    if !is_home_lab_wsl_instance(instance) {
        return Ok(HomeLabTraefikTlsReconcileStatus::Reconciled);
    }

    ensure_rustls_crypto_provider(trace_id, instance)?;
    ensure_wsl_instance_running(instance, trace_id).await?;
    let endpoint = resolve_kube_api_endpoint_for_instance(instance, trace_id).await?;
    let endpoint = wait_for_kube_api_port(instance, &endpoint, trace_id).await?;
    let (client, config, _, _) = build_kube_client_for_instance(instance, Some(&endpoint)).await?;
    if !wait_for_home_lab_traefik_deployment_presence(&client, trace_id, instance).await? {
        return Ok(HomeLabTraefikTlsReconcileStatus::Deferred);
    }
    ensure_home_lab_cluster_default_tls(&client, &config, instance, trace_id).await?;
    restart_home_lab_traefik_deployment(&client, instance, trace_id, "tls-reconcile").await?;
    Ok(HomeLabTraefikTlsReconcileStatus::Reconciled)
}

async fn run_wsl_kubectl_exec(instance: &str, args: &[String]) -> Result<WslKubectlExecResult> {
    if args.is_empty() {
        return Err(anyhow!("La commande kubectl est requise."));
    }

    let started_at = Instant::now();
    let trace_id = next_kubectl_trace_id();
    let context_name = kube_context_for_instance(instance);
    let command_line = build_kubectl_command_line(&context_name, args);
    let instance_log = escape_for_log(instance);

    let command = match parse_kubectl_command(args) {
        Ok(command) => command,
        Err(err) => {
            let message = err.to_string();
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                error = %message,
                "Commande kubectl refusee (syntaxe non supportee)"
            );
            log_wsl_event(format!(
                "[{trace_id}] Commande kubectl refusee pour {} via {}: {}",
                instance_log,
                command_line,
                escape_for_log(&message)
            ));
            return Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ));
        }
    };

    if let Err(err) = ensure_rustls_crypto_provider(&trace_id, instance) {
        let message = err.to_string();
        warn!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            command = %command_line,
            error = %message,
            "Initialisation provider TLS Rustls en echec"
        );
        log_wsl_event(format!(
            "[{trace_id}] Initialisation provider TLS Rustls en echec pour {}: {}",
            instance_log,
            escape_for_log(&message)
        ));
        return Ok(kubectl_error_result(
            instance,
            &command_line,
            &trace_id,
            elapsed_ms(&started_at),
            message,
        ));
    }

    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        command = %command_line,
        context = %context_name,
        "Execution kubectl via client Kubernetes Rust"
    );
    log_wsl_event(format!(
        "[{trace_id}] Execution kubectl pour {} via API Kubernetes: {}",
        instance_log, command_line
    ));

    let prepare_outcome = tokio::time::timeout(
        Duration::from_secs(KUBECTL_PREPARE_TIMEOUT_SECONDS),
        async {
            ensure_wsl_instance_running(instance, &trace_id).await?;
            let endpoint = resolve_kube_api_endpoint_for_instance(instance, &trace_id).await?;
            let endpoint = wait_for_kube_api_port(instance, &endpoint, &trace_id).await?;
            Ok::<KubeApiEndpoint, anyhow::Error>(endpoint)
        },
    )
    .await;

    let api_endpoint = match prepare_outcome {
        Ok(Ok(endpoint)) => endpoint,
        Ok(Err(err)) => {
            let message = format_kubernetes_runtime_error(instance, &err).await;
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                error = %message,
                "Preparation Kubernetes en echec"
            );
            log_wsl_event(format!(
                "[{trace_id}] Preparation Kubernetes en echec pour {}: {}",
                instance_log,
                escape_for_log(&message)
            ));
            return Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ));
        }
        Err(_) => {
            let message = format!(
                "Timeout apres {}s lors de la preparation Kubernetes (demarrage instance/API). \
Verifie que '{}' peut demarrer et exposer l'API Kubernetes.",
                KUBECTL_PREPARE_TIMEOUT_SECONDS, instance
            );
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                timeout_seconds = KUBECTL_PREPARE_TIMEOUT_SECONDS,
                "Preparation Kubernetes en timeout"
            );
            log_wsl_event(format!(
                "[{trace_id}] Preparation Kubernetes en timeout pour {}: timeout={}s",
                instance_log, KUBECTL_PREPARE_TIMEOUT_SECONDS
            ));
            return Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ));
        }
    };

    let trace_for_task = trace_id.clone();
    let instance_for_task = instance.to_string();
    let api_endpoint_for_task = api_endpoint.clone();
    let mut operation = tauri::async_runtime::spawn(async move {
        ensure_rustls_crypto_provider(&trace_for_task, &instance_for_task)?;
        info!(
            target: "wsl",
            trace_id = %trace_for_task,
            instance = %instance_for_task,
            api_host = %api_endpoint_for_task.host,
            api_port = api_endpoint_for_task.port,
            "Initialisation du client Kubernetes"
        );
        let (client, config, resolved_context, kubeconfig_path) =
            build_kube_client_for_instance(&instance_for_task, Some(&api_endpoint_for_task))
                .await?;
        info!(
            target: "wsl",
            trace_id = %trace_for_task,
            instance = %instance_for_task,
            context = %resolved_context,
            kubeconfig = %kubeconfig_path.display(),
            "Client Kubernetes initialise"
        );
        if let Err(err) = ensure_home_lab_cluster_default_tls(
            &client,
            &config,
            &instance_for_task,
            &trace_for_task,
        )
        .await
        {
            warn!(
                target: "wsl",
                trace_id = %trace_for_task,
                instance = %instance_for_task,
                error = %err,
                "Reconciliation TLS Traefik ignoree avant kubectl"
            );
            log_wsl_event(format!(
                "[{}] Reconciliation TLS Traefik ignoree pour {} avant kubectl: {}",
                trace_for_task,
                escape_for_log(&instance_for_task),
                escape_for_log(&err.to_string())
            ));
        }
        let stdout = execute_kubectl_command(&client, &config, command).await?;
        Ok::<(String, String, PathBuf), anyhow::Error>((stdout, resolved_context, kubeconfig_path))
    });

    let outcome = tokio::time::timeout(
        Duration::from_secs(KUBECTL_EXEC_TIMEOUT_SECONDS),
        &mut operation,
    )
    .await;

    match outcome {
        Ok(Ok(Ok((stdout, resolved_context, kubeconfig_path)))) => {
            let stdout_log = escape_for_log(stdout.trim());
            let duration_ms = elapsed_ms(&started_at);
            info!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                context = %resolved_context,
                kubeconfig = %kubeconfig_path.display(),
                duration_ms = duration_ms,
                stdout = %stdout_log,
                "Commande kubectl terminee via API Kubernetes"
            );
            log_wsl_event(format!(
                "[{trace_id}] Commande kubectl terminee pour {}: status=0 duration_ms={} context={} kubeconfig={} stdout={}",
                instance_log,
                duration_ms,
                escape_for_log(&resolved_context),
                escape_for_log(&kubeconfig_path.display().to_string()),
                stdout_log
            ));

            Ok(WslKubectlExecResult {
                ok: true,
                instance: instance.to_string(),
                exit_code: Some(0),
                command: command_line,
                trace_id,
                duration_ms,
                stdout,
                stderr: String::new(),
            })
        }
        Ok(Ok(Err(err))) => {
            let message = format_kubernetes_runtime_error(instance, &err).await;
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                error = %message,
                "Commande kubectl en echec via API Kubernetes"
            );
            log_wsl_event(format!(
                "[{trace_id}] Commande kubectl en echec pour {}: status=1 stderr={}",
                instance_log,
                escape_for_log(&message)
            ));
            Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ))
        }
        Ok(Err(join_err)) => {
            let message = format!("Execution Kubernetes interrompue: {join_err}");
            error!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                error = %message,
                "JoinHandle kubectl en echec"
            );
            log_wsl_event(format!(
                "[{trace_id}] JoinHandle kubectl en echec pour {}: {}",
                instance_log,
                escape_for_log(&message)
            ));
            Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ))
        }
        Err(_) => {
            operation.abort();
            let message = format!(
                "Timeout apres {}s lors de l'execution Kubernetes. \
Verifie que k3s est demarre dans '{}' et que l'API est joignable depuis Windows.",
                KUBECTL_EXEC_TIMEOUT_SECONDS, instance
            );
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                timeout_seconds = KUBECTL_EXEC_TIMEOUT_SECONDS,
                "Commande kubectl en timeout via API Kubernetes"
            );
            log_wsl_event(format!(
                "[{trace_id}] Commande kubectl en timeout pour {}: status=1 timeout={}s",
                instance_log, KUBECTL_EXEC_TIMEOUT_SECONDS
            ));
            Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ))
        }
    }
}

async fn run_wsl_kubectl_apply_yaml(
    instance: &str,
    manifest_yaml: &str,
    source_name: Option<&str>,
) -> Result<WslKubectlExecResult> {
    if manifest_yaml.trim().is_empty() {
        return Err(anyhow!("Le contenu YAML est vide."));
    }

    if manifest_yaml.as_bytes().len() > KUBECTL_APPLY_MAX_BYTES {
        return Err(anyhow!(
            "Le fichier YAML depasse la limite de {} Ko.",
            KUBECTL_APPLY_MAX_BYTES / 1024
        ));
    }

    let started_at = Instant::now();
    let trace_id = next_kubectl_trace_id();
    let context_name = kube_context_for_instance(instance);
    let command_line = build_kubectl_apply_command_line(&context_name, source_name);
    let instance_log = escape_for_log(instance);
    let source_log = source_name.unwrap_or("<uploaded-yaml>");
    let parsed_manifests = parse_apply_manifest_documents(manifest_yaml)?;
    let restart_traefik_after_apply = is_home_lab_wsl_instance(instance)
        && manifests_require_home_lab_traefik_restart(&parsed_manifests);

    if let Err(err) = ensure_rustls_crypto_provider(&trace_id, instance) {
        let message = err.to_string();
        warn!(
            target: "wsl",
            trace_id = %trace_id,
            instance = %instance,
            command = %command_line,
            error = %message,
            "Initialisation provider TLS Rustls en echec (apply)"
        );
        log_wsl_event(format!(
            "[{trace_id}] Initialisation provider TLS Rustls en echec pour apply sur {}: {}",
            instance_log,
            escape_for_log(&message)
        ));
        return Ok(kubectl_error_result(
            instance,
            &command_line,
            &trace_id,
            elapsed_ms(&started_at),
            message,
        ));
    }

    info!(
        target: "wsl",
        trace_id = %trace_id,
        instance = %instance,
        command = %command_line,
        context = %context_name,
        source = %source_log,
        bytes = manifest_yaml.as_bytes().len(),
        "Execution kubectl apply via client Kubernetes Rust"
    );
    log_wsl_event(format!(
        "[{trace_id}] Execution kubectl apply pour {} via API Kubernetes: {} (source={} bytes={})",
        instance_log,
        command_line,
        escape_for_log(source_log),
        manifest_yaml.as_bytes().len()
    ));

    let prepare_outcome = tokio::time::timeout(
        Duration::from_secs(KUBECTL_PREPARE_TIMEOUT_SECONDS),
        async {
            ensure_wsl_instance_running(instance, &trace_id).await?;
            let endpoint = resolve_kube_api_endpoint_for_instance(instance, &trace_id).await?;
            let endpoint = wait_for_kube_api_port(instance, &endpoint, &trace_id).await?;
            Ok::<KubeApiEndpoint, anyhow::Error>(endpoint)
        },
    )
    .await;

    let api_endpoint = match prepare_outcome {
        Ok(Ok(endpoint)) => endpoint,
        Ok(Err(err)) => {
            let message = format_kubernetes_runtime_error(instance, &err).await;
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                error = %message,
                "Preparation Kubernetes en echec (apply)"
            );
            log_wsl_event(format!(
                "[{trace_id}] Preparation Kubernetes en echec pour apply sur {}: {}",
                instance_log,
                escape_for_log(&message)
            ));
            return Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ));
        }
        Err(_) => {
            let message = format!(
                "Timeout apres {}s lors de la preparation Kubernetes (demarrage instance/API). \
Verifie que '{}' peut demarrer et exposer l'API Kubernetes.",
                KUBECTL_PREPARE_TIMEOUT_SECONDS, instance
            );
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                timeout_seconds = KUBECTL_PREPARE_TIMEOUT_SECONDS,
                "Preparation Kubernetes en timeout (apply)"
            );
            log_wsl_event(format!(
                "[{trace_id}] Preparation Kubernetes en timeout pour apply sur {}: timeout={}s",
                instance_log, KUBECTL_PREPARE_TIMEOUT_SECONDS
            ));
            return Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ));
        }
    };

    let trace_for_task = trace_id.clone();
    let instance_for_task = instance.to_string();
    let api_endpoint_for_task = api_endpoint.clone();
    let manifest_for_task = manifest_yaml.to_string();
    let restart_traefik_after_apply_for_task = restart_traefik_after_apply;
    let mut operation = tauri::async_runtime::spawn(async move {
        ensure_rustls_crypto_provider(&trace_for_task, &instance_for_task)?;
        info!(
            target: "wsl",
            trace_id = %trace_for_task,
            instance = %instance_for_task,
            api_host = %api_endpoint_for_task.host,
            api_port = api_endpoint_for_task.port,
            "Initialisation du client Kubernetes (apply)"
        );
        let (client, config, resolved_context, kubeconfig_path) =
            build_kube_client_for_instance(&instance_for_task, Some(&api_endpoint_for_task))
                .await?;
        if let Err(err) = ensure_home_lab_cluster_default_tls(
            &client,
            &config,
            &instance_for_task,
            &trace_for_task,
        )
        .await
        {
            warn!(
                target: "wsl",
                trace_id = %trace_for_task,
                instance = %instance_for_task,
                error = %err,
                "Reconciliation TLS Traefik ignoree avant kubectl apply"
            );
            log_wsl_event(format!(
                "[{}] Reconciliation TLS Traefik ignoree pour {} avant kubectl apply: {}",
                trace_for_task,
                escape_for_log(&instance_for_task),
                escape_for_log(&err.to_string())
            ));
        }
        let stdout = execute_kubectl_apply_yaml(&client, &config, &manifest_for_task).await?;
        if restart_traefik_after_apply_for_task {
            restart_home_lab_traefik_deployment(
                &client,
                &instance_for_task,
                &trace_for_task,
                "apply-manifest",
            )
            .await?;
        }
        Ok::<(String, String, PathBuf), anyhow::Error>((stdout, resolved_context, kubeconfig_path))
    });

    let outcome = tokio::time::timeout(
        Duration::from_secs(KUBECTL_EXEC_TIMEOUT_SECONDS),
        &mut operation,
    )
    .await;

    match outcome {
        Ok(Ok(Ok((stdout, resolved_context, kubeconfig_path)))) => {
            let stdout_log = escape_for_log(stdout.trim());
            let duration_ms = elapsed_ms(&started_at);
            info!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                context = %resolved_context,
                kubeconfig = %kubeconfig_path.display(),
                duration_ms = duration_ms,
                stdout = %stdout_log,
                "Kubectl apply termine via API Kubernetes"
            );
            log_wsl_event(format!(
                "[{trace_id}] Kubectl apply termine pour {}: status=0 duration_ms={} context={} kubeconfig={} stdout={}",
                instance_log,
                duration_ms,
                escape_for_log(&resolved_context),
                escape_for_log(&kubeconfig_path.display().to_string()),
                stdout_log
            ));

            Ok(WslKubectlExecResult {
                ok: true,
                instance: instance.to_string(),
                exit_code: Some(0),
                command: command_line,
                trace_id,
                duration_ms,
                stdout,
                stderr: String::new(),
            })
        }
        Ok(Ok(Err(err))) => {
            let message = format_kubernetes_runtime_error(instance, &err).await;
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                error = %message,
                "Kubectl apply en echec via API Kubernetes"
            );
            log_wsl_event(format!(
                "[{trace_id}] Kubectl apply en echec pour {}: status=1 stderr={}",
                instance_log,
                escape_for_log(&message)
            ));
            Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ))
        }
        Ok(Err(join_err)) => {
            let message = format!("Execution Kubernetes interrompue: {join_err}");
            error!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                error = %message,
                "JoinHandle kubectl apply en echec"
            );
            log_wsl_event(format!(
                "[{trace_id}] JoinHandle kubectl apply en echec pour {}: {}",
                instance_log,
                escape_for_log(&message)
            ));
            Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ))
        }
        Err(_) => {
            operation.abort();
            let message = format!(
                "Timeout apres {}s lors de l'execution Kubernetes. \
Verifie que k3s est demarre dans '{}' et que l'API est joignable depuis Windows.",
                KUBECTL_EXEC_TIMEOUT_SECONDS, instance
            );
            warn!(
                target: "wsl",
                trace_id = %trace_id,
                instance = %instance,
                command = %command_line,
                timeout_seconds = KUBECTL_EXEC_TIMEOUT_SECONDS,
                "Kubectl apply en timeout via API Kubernetes"
            );
            log_wsl_event(format!(
                "[{trace_id}] Kubectl apply en timeout pour {}: status=1 timeout={}s",
                instance_log, KUBECTL_EXEC_TIMEOUT_SECONDS
            ));
            Ok(kubectl_error_result(
                instance,
                &command_line,
                &trace_id,
                elapsed_ms(&started_at),
                message,
            ))
        }
    }
}

#[tauri::command]
pub async fn wsl_kubectl_exec(
    instance: String,
    args: Vec<String>,
) -> Result<WslKubectlExecResult, String> {
    let raw_instance = instance.trim();
    if raw_instance.is_empty() {
        return Err("Le nom de l'instance WSL est requis.".into());
    }

    let sanitized_instance = sanitize_wsl_instance_name(raw_instance).map_err(|e| e.to_string())?;
    let sanitized_args: Vec<String> = args
        .into_iter()
        .map(|arg| sanitize_cli_field(&arg))
        .filter(|arg| !arg.is_empty())
        .collect();
    if sanitized_args.is_empty() {
        return Err("La commande kubectl est requise.".into());
    }

    run_wsl_kubectl_exec(&sanitized_instance, &sanitized_args)
        .await
        .map_err(|e| {
            error!(target: "wsl", "Erreur execution kubectl API: {e}");
            log_wsl_event(format!(
                "Erreur execution kubectl API pour {}: {e}",
                escape_for_log(&sanitized_instance)
            ));
            e.to_string()
        })
}

#[tauri::command]
pub async fn wsl_kubectl_apply_yaml(
    instance: String,
    manifest_yaml: String,
    source_name: Option<String>,
) -> Result<WslKubectlExecResult, String> {
    let raw_instance = instance.trim();
    if raw_instance.is_empty() {
        return Err("Le nom de l'instance WSL est requis.".into());
    }

    let sanitized_instance = sanitize_wsl_instance_name(raw_instance).map_err(|e| e.to_string())?;
    let normalized_manifest = manifest_yaml.replace('\0', "");
    if normalized_manifest.trim().is_empty() {
        return Err("Le contenu YAML est vide.".into());
    }
    if normalized_manifest.as_bytes().len() > KUBECTL_APPLY_MAX_BYTES {
        return Err(format!(
            "Le fichier YAML depasse la limite de {} Ko.",
            KUBECTL_APPLY_MAX_BYTES / 1024
        ));
    }

    let sanitized_source_name = source_name
        .map(|value| sanitize_cli_field(&value))
        .filter(|value| !value.is_empty());

    run_wsl_kubectl_apply_yaml(
        &sanitized_instance,
        &normalized_manifest,
        sanitized_source_name.as_deref(),
    )
    .await
    .map_err(|e| {
        error!(target: "wsl", "Erreur kubectl apply YAML API: {e}");
        log_wsl_event(format!(
            "Erreur kubectl apply YAML API pour {}: {e}",
            escape_for_log(&sanitized_instance)
        ));
        e.to_string()
    })
}

#[derive(serde::Deserialize, Debug)]
struct GitHubReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(serde::Deserialize, Debug)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubReleaseAsset>,
}

async fn download_and_install_k3s_with_paths(
    paths: &WslExecutionPaths,
    instance_name: &str,
) -> Result<String> {
    let client = reqwest::Client::new();
    let release_url = "https://api.github.com/repos/k3s-io/k3s/releases/latest";
    let sanitized_instance = escape_for_log(instance_name);

    info!(target: "wsl", "Recuperation de la derniere version de K3S");
    log_wsl_event(format!(
        "Recuperation de la derniere version de K3S pour {}",
        sanitized_instance
    ));

    let release: GitHubRelease = client
        .get(release_url)
        .header("User-Agent", "home-lab-tauri-app")
        .send()
        .await
        .context("Impossible d'interroger l'API GitHub pour les versions de K3S")?
        .json()
        .await
        .context("Impossible de désérialiser la réponse des versions de K3S")?;

    let asset_name = "k3s"; // x86_64
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .context(format!(
            "Impossible de trouver l'asset K3S '{}' dans la version {}",
            asset_name, release.tag_name
        ))?;

    let k3s_cache_dir = paths.cache_root.join("k3s");
    fs::create_dir_all(&k3s_cache_dir)
        .context("Impossible de créer le dossier de cache pour K3S")?;

    let cached_file_path = k3s_cache_dir.join(format!("{}-{}", release.tag_name, asset_name));

    if !cached_file_path.exists() {
        info!(
            target: "wsl",
            url = %asset.browser_download_url,
            path = %cached_file_path.display(),
            "Telechargement de K3S"
        );
        log_wsl_event(format!(
            "Telechargement de K3S {} vers {}",
            asset.browser_download_url,
            cached_file_path.display()
        ));

        let mut response = client
            .get(&asset.browser_download_url)
            .send()
            .await
            .context(format!(
                "Impossible de télécharger l'asset K3S depuis {}",
                asset.browser_download_url
            ))?;

        let mut file = fs::File::create(&cached_file_path).context(format!(
            "Impossible de créer le fichier de cache K3S sur {}",
            cached_file_path.display()
        ))?;

        while let Some(chunk) = response
            .chunk()
            .await
            .context("Erreur lors du telechargement de K3s")?
        {
            file.write_all(&chunk)
                .context("Erreur ecriture dans le fichier de cache K3s")?;
        }
    } else {
        info!(
            target: "wsl",
            path = %cached_file_path.display(),
            "K3S est deja en cache"
        );
        log_wsl_event(format!(
            "K3S est deja en cache sur {}",
            cached_file_path.display()
        ));
    }

    let wsl_path = format!("\\\\wsl$\\{}\\usr\\local\\bin\\k3s", instance_name);
    let wsl_path_buf = PathBuf::from(&wsl_path);

    info!(
        target: "wsl",
        source = %cached_file_path.display(),
        dest = %wsl_path,
        "Copie de K3S dans l'instance WSL"
    );
    log_wsl_event(format!(
        "Copie de K3S de {} vers {}",
        cached_file_path.display(),
        wsl_path
    ));

    fs::copy(&cached_file_path, &wsl_path_buf).context(format!(
        "Impossible de copier K3S dans WSL sur {}",
        wsl_path_buf.display()
    ))?;

    let command_line = format_cli_command(
        "wsl.exe",
        &["-d", instance_name, "chmod", "+x", "/usr/local/bin/k3s"],
    );
    info!(
        target: "wsl",
        command = %command_line,
        "Execution de la commande pour rendre K3S executable"
    );
    log_wsl_event(format!(
        "Execution de la commande pour rendre K3S executable : {}",
        command_line
    ));

    let output = Command::new("wsl.exe")
        .args(["-d", instance_name, "chmod", "+x", "/usr/local/bin/k3s"])
        .output()
        .context("Impossible de rendre K3S executable dans WSL")?;

    if !output.status.success() {
        let stderr = decode_cli_output(&output.stderr);
        anyhow::bail!("Impossible de rendre K3S executable dans WSL: {}", stderr);
    }

    Ok(format!("K3S {} installe avec succes.", release.tag_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation_overrides_present() -> bool {
        [
            ENV_API_PORT,
            ENV_API_PORT_BASE,
            ENV_API_PORT_STEP,
            ENV_API_PORT_MAX,
            ENV_HTTP_PORT_BASE,
            ENV_HTTP_PORT_STEP,
            ENV_HTTP_PORT_MAX,
            ENV_K3S_NODEPORT_BASE,
            ENV_K3S_NODEPORT_STEP,
            ENV_K3S_NODEPORT_MAX,
            ENV_SSH_PORT_BASE,
            ENV_SSH_PORT_STEP,
            ENV_SSH_PORT_MAX,
        ]
        .iter()
        .any(|var| std::env::var_os(var).is_some())
    }

    fn default_home_lab_plans() -> Option<(InstancePortPlan, InstancePortPlan)> {
        if allocation_overrides_present() {
            return None;
        }

        Some((
            instance_port_plan(HOME_LAB_WSL_INSTANCE_PREFIX),
            instance_port_plan("home-lab-k3s-2"),
        ))
    }

    #[test]
    fn api_blocks_do_not_overlap_between_instances() {
        let Some((first, second)) = default_home_lab_plans() else {
            return;
        };

        assert_eq!(first.api_reserved_ports.end, first.api_backend_port + 1);
        assert_eq!(second.api_reserved_ports.end, second.api_backend_port + 1);
        assert!(first.api_reserved_ports.end < second.api_reserved_ports.start);
    }

    #[test]
    fn ingress_backend_pairs_do_not_overlap_between_instances() {
        let Some((first, second)) = default_home_lab_plans() else {
            return;
        };

        assert_eq!(
            first.ingress_http_backend_port + 1,
            first.ingress_https_backend_port
        );
        assert_eq!(
            second.ingress_http_backend_port + 1,
            second.ingress_https_backend_port
        );

        let first_ports = [
            first.ingress_http_backend_port,
            first.ingress_https_backend_port,
        ];
        let second_ports = [
            second.ingress_http_backend_port,
            second.ingress_https_backend_port,
        ];

        assert!(first_ports
            .iter()
            .all(|left| second_ports.iter().all(|right| left != right)));
    }

    #[test]
    fn default_home_lab_instances_use_expected_publication_ports() {
        let Some((first, second)) = default_home_lab_plans() else {
            return;
        };

        assert_eq!(first.api_backend_port, 1001);
        assert_eq!(second.api_backend_port, 1003);
        assert_eq!(first.ingress_http_backend_port, 2000);
        assert_eq!(first.ingress_https_backend_port, 2001);
        assert_eq!(second.ingress_http_backend_port, 2002);
        assert_eq!(second.ingress_https_backend_port, 2003);
    }

    #[test]
    fn home_lab_instances_use_public_dns_endpoint_for_kube_api() {
        if allocation_overrides_present() {
            return;
        }

        let endpoint =
            home_lab_public_kube_api_endpoint(HOME_LAB_WSL_INSTANCE_PREFIX).expect("endpoint");
        assert_eq!(endpoint.host, "home-lab-k3s.wsl");
        assert_eq!(endpoint.port, DEFAULT_API_INBOUND_PORT);
        assert_eq!(
            endpoint.tls_server_name.as_deref(),
            Some("home-lab-k3s.wsl")
        );
    }

    #[test]
    fn nodeport_ranges_do_not_overlap_between_instances() {
        let Some((first, second)) = default_home_lab_plans() else {
            return;
        };

        assert!(first.nodeport_range.end < second.nodeport_range.start);
    }

    #[test]
    fn home_lab_default_tls_manifests_are_valid_and_root_signed() {
        let assets =
            build_home_lab_default_tls_assets(HOME_LAB_WSL_INSTANCE_PREFIX, "traefik.io/v1alpha1")
                .expect("tls assets");

        assert!(
            home_pki::is_certificate_signed_by_current_root(&assets.cert_pem)
                .expect("verify root-signed cert"),
            "the generated Traefik default certificate must be signed by the Home Lab root CA"
        );

        let combined = format!(
            "{}\n---\n{}",
            assets.secret_manifest, assets.tls_store_manifest
        );
        let manifests = parse_apply_manifest_documents(&combined).expect("parse TLS manifests");
        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0].kind, "Secret");
        assert_eq!(manifests[1].kind, HOME_LAB_TRAEFIK_TLSSTORE_KIND);
        assert_eq!(manifests[0].name, HOME_LAB_DEFAULT_TLS_SECRET_NAME);
        assert_eq!(manifests[1].name, "default");
    }

    #[test]
    fn generated_home_lab_default_tls_cert_matches_expected_instance_only() {
        let first_assets =
            build_home_lab_default_tls_assets(HOME_LAB_WSL_INSTANCE_PREFIX, "traefik.io/v1alpha1")
                .expect("first tls assets");
        let second_assets =
            build_home_lab_default_tls_assets("home-lab-k3s-2", "traefik.io/v1alpha1")
                .expect("second tls assets");

        assert!(home_lab_default_tls_cert_matches_instance(
            &first_assets.cert_pem,
            HOME_LAB_WSL_INSTANCE_PREFIX
        )
        .expect("match first instance"),);
        assert!(!home_lab_default_tls_cert_matches_instance(
            &first_assets.cert_pem,
            "home-lab-k3s-2"
        )
        .expect("reject second instance"),);
        assert!(home_lab_default_tls_cert_matches_instance(
            &second_assets.cert_pem,
            "home-lab-k3s-2"
        )
        .expect("match second instance"),);
    }

    #[test]
    fn tls_dns_names_do_not_accept_other_instance_via_shared_wildcard() {
        let first_dns_names = vec!["*.wsl".to_string(), "home-lab-k3s.wsl".to_string()];
        let second_dns_names = vec!["*.wsl".to_string(), "home-lab-k3s-2.wsl".to_string()];

        assert!(home_lab_default_tls_dns_names_match_instance(
            &first_dns_names,
            HOME_LAB_WSL_INSTANCE_PREFIX
        ));
        assert!(!home_lab_default_tls_dns_names_match_instance(
            &first_dns_names,
            "home-lab-k3s-2"
        ));
        assert!(home_lab_default_tls_dns_names_match_instance(
            &second_dns_names,
            "home-lab-k3s-2"
        ));
        assert!(!home_lab_default_tls_dns_names_match_instance(
            &second_dns_names,
            HOME_LAB_WSL_INSTANCE_PREFIX
        ));
    }

    #[test]
    fn ingress_manifest_requests_traefik_restart() {
        let manifests = parse_apply_manifest_documents(
            r#"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo
  namespace: default
spec:
  ingressClassName: traefik
"#,
        )
        .expect("parse ingress manifest");
        assert!(manifests_require_home_lab_traefik_restart(&manifests));
    }

    #[test]
    fn ordinary_workload_manifest_does_not_request_traefik_restart() {
        let manifests = parse_apply_manifest_documents(
            r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  selector:
    matchLabels:
      app: demo
  template:
    metadata:
      labels:
        app: demo
    spec:
      containers:
        - name: demo
          image: traefik/whoami:v1.10.1
"#,
        )
        .expect("parse deployment manifest");
        assert!(!manifests_require_home_lab_traefik_restart(&manifests));
    }

    #[test]
    fn windows_verbatim_paths_are_normalized_for_cli() {
        assert_eq!(
            normalize_windows_path_for_cli(Path::new(
                r"\\?\C:\Program Files\home-lab\wsl\setup-wsl.ps1"
            )),
            PathBuf::from(r"C:\Program Files\home-lab\wsl\setup-wsl.ps1")
        );
        assert_eq!(
            normalize_windows_path_for_cli(Path::new(r"\\?\UNC\server\share\demo.txt")),
            PathBuf::from(r"\\server\share\demo.txt")
        );
    }

    #[test]
    fn wsl_cli_file_not_found_errors_include_actionable_hint() {
        let annotated = annotate_wsl_cli_failure("Le fichier spécifié est introuvable.");
        assert!(annotated.contains("WSL ne repond pas correctement"));
    }
}
