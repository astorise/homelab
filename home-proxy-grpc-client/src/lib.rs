
use anyhow::Result;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

pub mod homeproxy {
    tonic::include_proto!("homeproxy.v1");
}
use homeproxy::home_proxy_client::HomeProxyClient;
pub use homeproxy::*;

#[cfg(windows)]
async fn connect_named_pipe(pipe_name: &str) -> Result<Channel> {
    use tokio::net::windows::named_pipe::ClientOptions;
    // Endpoint needs a valid URI but it's ignored by the custom connector
    let endpoint = Endpoint::try_from("http://pipe.local")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_| {
            let name = pipe_name.to_string();
            async move { ClientOptions::new().open(&name) }
        }))
        .await?;
    Ok(channel)
}

#[cfg(not(windows))]
async fn connect_named_pipe(_pipe_name: &str) -> Result<Channel> {
    anyhow::bail!("Named pipes are only supported on Windows");
}

/// Create a HomeProxy gRPC client connected to the default pipe `\\.\pipe\home-proxy`.
pub async fn connect_default() -> Result<HomeProxyClient<Channel>> {
    connect_named_pipe(r"\\.\pipe\home-proxy").await.map(HomeProxyClient::new)
}

/// Create a HomeProxy gRPC client to a specific pipe path, e.g. `\\.\pipe\home-proxy`.
pub async fn connect(pipe_path: &str) -> Result<HomeProxyClient<Channel>> {
    connect_named_pipe(pipe_path).await.map(HomeProxyClient::new)
}
