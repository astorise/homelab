use anyhow::{anyhow, Context, Result};
use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

mod proto {
    pub mod homedns {
        pub mod v1 {
            tonic::include_proto!("homedns.v1");
        }
    }
    pub mod homehttp {
        pub mod v1 {
            tonic::include_proto!("homehttp.v1");
        }
    }
}

use proto::homedns::v1::home_dns_client::HomeDnsClient;
use proto::homedns::v1::Empty as DnsEmpty;
use proto::homehttp::v1::home_http_client::HomeHttpClient;
use proto::homehttp::v1::Empty as HttpEmpty;

const DNS_URI: &str = "http://[::]:50052";
const HTTP_URI: &str = "http://[::]:50051";

#[tokio::main]
async fn main() -> Result<()> {
    println!("Homelab named pipe connectivity tester");
    println!("-------------------------------------\n");

    test_dns().await.context("DNS check failed")?;
    println!();
    test_http().await.context("HTTP check failed")?;

    Ok(())
}

async fn test_dns() -> Result<()> {
    println!("DNS service:");
    try_pipes(dns_pipe_candidates(), |pipe| async move {
        let mut client = connect_dns(&pipe).await?;
        let response = client
            .get_status(DnsEmpty {})
            .await
            .with_context(|| format!("DNS get_status via '{}'", pipe))?;
        let status = response.into_inner();
        println!("  state     : {}", status.state);
        println!("  log_level : {}", status.log_level);
        Ok(())
    })
    .await
}

async fn test_http() -> Result<()> {
    println!("HTTP service:");
    try_pipes(http_pipe_candidates(), |pipe| async move {
        let mut client = connect_http(&pipe).await?;
        let response = client
            .get_status(HttpEmpty {})
            .await
            .with_context(|| format!("HTTP get_status via '{}'", pipe))?;
        let status = response.into_inner();
        println!("  state     : {}", status.state);
        println!("  log_level : {}", status.log_level);
        Ok(())
    })
    .await
}

fn dns_pipe_candidates() -> &'static [&'static str] {
    if cfg!(debug_assertions) {
        &[r"\\.\pipe\home-dns-dev", r"\\.\pipe\home-dns"]
    } else {
        &[r"\\.\pipe\home-dns", r"\\.\pipe\home-dns-dev"]
    }
}

fn http_pipe_candidates() -> &'static [&'static str] {
    if cfg!(debug_assertions) {
        &[r"\\.\pipe\home-http-dev", r"\\.\pipe\home-http"]
    } else {
        &[r"\\.\pipe\home-http", r"\\.\pipe\home-http-dev"]
    }
}

async fn try_pipes<F, Fut>(candidates: &[&str], mut attempt: F) -> Result<()>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut last_error: Option<String> = None;

    for &pipe in candidates {
        let owned = pipe.to_string();
        println!("  trying pipe '{}'", owned);
        match attempt(owned.clone()).await {
            Ok(()) => {
                println!("  success on '{}'", owned);
                return Ok(());
            }
            Err(err) => {
                println!("  failed on '{}': {}", owned, err);
                last_error = Some(err.to_string());
            }
        }
    }

    Err(anyhow!(
        "all pipe attempts failed: {}",
        last_error.unwrap_or_else(|| "no candidates available".to_string())
    ))
}

async fn connect_dns(pipe: &str) -> Result<HomeDnsClient<Channel>> {
    let channel = connect_pipe(pipe, DNS_URI)
        .await
        .with_context(|| format!("connect DNS pipe '{}'", pipe))?;
    Ok(HomeDnsClient::new(channel))
}

async fn connect_http(pipe: &str) -> Result<HomeHttpClient<Channel>> {
    let channel = connect_pipe(pipe, HTTP_URI)
        .await
        .with_context(|| format!("connect HTTP pipe '{}'", pipe))?;
    Ok(HomeHttpClient::new(channel))
}

async fn connect_pipe(pipe: &str, uri: &'static str) -> Result<Channel, tonic::transport::Error> {
    let pipe_path = pipe.to_string();
    Endpoint::from_static(uri)
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

// Windows named pipe handles can move across threads, but tonic requires transports to be Send.
unsafe impl Send for SendablePipeClient {}

impl AsyncRead for SendablePipeClient {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for SendablePipeClient {
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
