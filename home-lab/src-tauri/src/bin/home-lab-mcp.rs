use std::{fs, path::PathBuf};

use anyhow::Result;
use home_lab_lib::{
    dns, http,
    oidc::{self, RegisterClientIn},
    s3, wsl,
};
use rmcp::schemars;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Implementation, ServerCapabilities, ServerInfo},
    schemars::JsonSchema,
    tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use tracing_appender::rolling;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
struct WslImportRequest {
    #[serde(default)]
    force: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enable_nvidia: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct WslNameRequest {
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct WslKubectlExecRequest {
    instance: String,
    args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct WslKubectlApplyYamlRequest {
    instance: String,
    manifest_yaml: String,
    #[serde(default)]
    source_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct DnsAddRecordRequest {
    name: String,
    rrtype: String,
    value: String,
    ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct DnsRemoveRecordRequest {
    name: String,
    rrtype: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct HttpAddRouteRequest {
    host: String,
    port: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct HttpRemoveRouteRequest {
    host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct OidcRegisterClientRequest {
    client_id: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    allowed_scopes: Vec<String>,
    #[serde(default)]
    audiences: Vec<String>,
    public_key_pem: String,
    #[serde(default)]
    auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct OidcRemoveClientRequest {
    client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct S3CreateBucketRequest {
    bucket_name: String,
    #[serde(default)]
    source_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct S3UpdateBucketRequest {
    current_bucket_name: String,
    #[serde(default)]
    new_bucket_name: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    replace_objects: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct S3DeleteBucketRequest {
    bucket_name: String,
    #[serde(default)]
    delete_objects: Option<bool>,
}

impl From<OidcRegisterClientRequest> for RegisterClientIn {
    fn from(value: OidcRegisterClientRequest) -> Self {
        RegisterClientIn {
            client_id: value.client_id,
            subject: value.subject,
            allowed_scopes: value.allowed_scopes,
            audiences: value.audiences,
            public_key_pem: value.public_key_pem,
            auth_method: value.auth_method,
        }
    }
}

#[derive(Debug, Clone)]
struct HomeLabMcpServer {
    tool_router: ToolRouter<Self>,
}

impl HomeLabMcpServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for HomeLabMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("home-lab-mcp", env!("CARGO_PKG_VERSION"))
                    .with_title("Home Lab MCP")
                    .with_description("MCP bridge for Home Lab WSL, k3s, DNS, S3, OIDC and HTTPS orchestration."),
            )
            .with_instructions(
                "Use these tools to provision Home Lab WSL clusters, deploy manifests to k3s, and manage DNS, S3, OIDC and HTTPS routes.",
            )
    }
}

#[tool_router(router = tool_router)]
impl HomeLabMcpServer {
    #[tool(
        name = "wsl_list_instances",
        description = "List WSL instances and any Home Lab cluster metadata detected for them."
    )]
    async fn wsl_list_instances(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(wsl::wsl_list_instances().await)
    }

    #[tool(
        name = "wsl_get_host_capabilities",
        description = "Detect host-side WSL capabilities such as Nvidia GPU availability."
    )]
    async fn wsl_get_host_capabilities(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(wsl::wsl_get_host_capabilities().await)
    }

    #[tool(
        name = "wsl_import_instance",
        description = "Provision a Home Lab WSL instance and bootstrap k3s, DNS, HTTP routing, OIDC and kubeconfig sync."
    )]
    async fn wsl_import_instance(
        &self,
        Parameters(request): Parameters<WslImportRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(
            wsl::wsl_import_instance_headless(request.force, request.name, request.enable_nvidia)
                .await,
        )
    }

    #[tool(
        name = "wsl_remove_instance",
        description = "Unregister a WSL instance and clean its Home Lab bindings."
    )]
    async fn wsl_remove_instance(
        &self,
        Parameters(request): Parameters<WslNameRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(wsl::wsl_remove_instance(request.name).await)
    }

    #[tool(
        name = "wsl_sync_windows_kubeconfig",
        description = "Synchronize kubeconfig contexts from managed WSL k3s clusters into the Windows kubeconfig."
    )]
    async fn wsl_sync_windows_kubeconfig(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(wsl::wsl_sync_windows_kubeconfig().await)
    }

    #[tool(
        name = "wsl_kubectl_exec",
        description = "Execute a kubectl command against a managed WSL k3s cluster."
    )]
    async fn wsl_kubectl_exec(
        &self,
        Parameters(request): Parameters<WslKubectlExecRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(wsl::wsl_kubectl_exec(request.instance, request.args).await)
    }

    #[tool(
        name = "wsl_kubectl_apply_yaml",
        description = "Apply a Kubernetes YAML manifest to a managed WSL k3s cluster."
    )]
    async fn wsl_kubectl_apply_yaml(
        &self,
        Parameters(request): Parameters<WslKubectlApplyYamlRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(
            wsl::wsl_kubectl_apply_yaml(
                request.instance,
                request.manifest_yaml,
                request.source_name,
            )
            .await,
        )
    }

    #[tool(
        name = "dns_get_status",
        description = "Return the current Home DNS service status."
    )]
    async fn dns_get_status(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(dns::dns_get_status().await)
    }

    #[tool(
        name = "dns_reload_config",
        description = "Reload the Home DNS configuration from disk."
    )]
    async fn dns_reload_config(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(dns::dns_reload_config().await)
    }

    #[tool(
        name = "dns_list_records",
        description = "List DNS records managed by Home Lab."
    )]
    async fn dns_list_records(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(dns::dns_list_records().await)
    }

    #[tool(
        name = "dns_add_record",
        description = "Add a DNS record managed by Home Lab."
    )]
    async fn dns_add_record(
        &self,
        Parameters(request): Parameters<DnsAddRecordRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(
            dns::dns_add_record(request.name, request.rrtype, request.value, request.ttl).await,
        )
    }

    #[tool(
        name = "dns_remove_record",
        description = "Remove a DNS record managed by Home Lab."
    )]
    async fn dns_remove_record(
        &self,
        Parameters(request): Parameters<DnsRemoveRecordRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(dns::dns_remove_record(request.name, request.rrtype, request.value).await)
    }

    #[tool(
        name = "http_get_status",
        description = "Return the current Home HTTP service status."
    )]
    async fn http_get_status(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(http::http_get_status().await)
    }

    #[tool(
        name = "http_reload_config",
        description = "Reload the Home HTTP configuration from disk."
    )]
    async fn http_reload_config(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(http::http_reload_config().await)
    }

    #[tool(
        name = "http_list_routes",
        description = "List HTTPS host routes managed by Home Lab."
    )]
    async fn http_list_routes(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(http::http_list_routes().await)
    }

    #[tool(
        name = "http_add_route",
        description = "Add an HTTPS host route managed by Home Lab."
    )]
    async fn http_add_route(
        &self,
        Parameters(request): Parameters<HttpAddRouteRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(http::http_add_route(request.host, request.port).await)
    }

    #[tool(
        name = "http_remove_route",
        description = "Remove an HTTPS host route managed by Home Lab."
    )]
    async fn http_remove_route(
        &self,
        Parameters(request): Parameters<HttpRemoveRouteRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(http::http_remove_route(request.host).await)
    }

    #[tool(
        name = "s3_get_status",
        description = "Return the current Home S3 service status and RustFS endpoint configuration."
    )]
    async fn s3_get_status(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(s3::s3_get_status().await)
    }

    #[tool(
        name = "s3_list_buckets",
        description = "List S3 buckets managed through Home S3."
    )]
    async fn s3_list_buckets(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(s3::s3_list_buckets().await)
    }

    #[tool(
        name = "s3_create_bucket",
        description = "Create an S3 bucket, optionally importing a Windows filesystem path into it."
    )]
    async fn s3_create_bucket(
        &self,
        Parameters(request): Parameters<S3CreateBucketRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(s3::s3_create_bucket(request.bucket_name, request.source_path).await)
    }

    #[tool(
        name = "s3_update_bucket",
        description = "Rename an S3 bucket and/or re-import content from a Windows filesystem path."
    )]
    async fn s3_update_bucket(
        &self,
        Parameters(request): Parameters<S3UpdateBucketRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(
            s3::s3_update_bucket(
                request.current_bucket_name,
                request.new_bucket_name,
                request.source_path,
                request.replace_objects.unwrap_or(false),
            )
            .await,
        )
    }

    #[tool(
        name = "s3_delete_bucket",
        description = "Delete an S3 bucket, optionally removing all objects first."
    )]
    async fn s3_delete_bucket(
        &self,
        Parameters(request): Parameters<S3DeleteBucketRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(
            s3::s3_delete_bucket(request.bucket_name, request.delete_objects.unwrap_or(false))
                .await,
        )
    }

    #[tool(
        name = "oidc_get_status",
        description = "Return the current Home OIDC service status and issuer metadata."
    )]
    async fn oidc_get_status(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(oidc::oidc_get_status().await)
    }

    #[tool(
        name = "oidc_list_clients",
        description = "List OIDC clients managed by Home Lab."
    )]
    async fn oidc_list_clients(&self) -> Result<CallToolResult, McpError> {
        json_tool_result(oidc::oidc_list_clients().await)
    }

    #[tool(
        name = "oidc_register_client",
        description = "Register an OIDC client managed by Home Lab."
    )]
    async fn oidc_register_client(
        &self,
        Parameters(request): Parameters<OidcRegisterClientRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(oidc::oidc_register_client(request.into()).await)
    }

    #[tool(
        name = "oidc_remove_client",
        description = "Remove an OIDC client managed by Home Lab."
    )]
    async fn oidc_remove_client(
        &self,
        Parameters(request): Parameters<OidcRemoveClientRequest>,
    ) -> Result<CallToolResult, McpError> {
        json_tool_result(oidc::oidc_remove_client(request.client_id).await)
    }
}

fn json_tool_result<T>(result: std::result::Result<T, String>) -> Result<CallToolResult, McpError>
where
    T: Serialize,
{
    let value = result.map_err(|err| McpError::internal_error(err, None))?;
    let json = serde_json::to_value(value)
        .map_err(|err| McpError::internal_error(err.to_string(), None))?;
    Ok(CallToolResult::structured(json))
}

fn log_dir() -> PathBuf {
    if let Some(pd) = std::env::var_os("PROGRAMDATA") {
        return PathBuf::from(pd).join("home-lab").join("logs");
    }

    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("home-lab").join("logs");
    }

    std::env::temp_dir().join("home-lab").join("logs")
}

fn init_file_logger() {
    let dir = log_dir();
    let _ = fs::create_dir_all(&dir);

    let filter = EnvFilter::try_new(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let file_appender = rolling::daily(&dir, "home-lab-mcp.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let _ = Box::leak(Box::new(guard));

    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_level(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .try_init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_file_logger();
    let server = HomeLabMcpServer::new();
    server.serve(stdio()).await?.waiting().await?;
    Ok(())
}
