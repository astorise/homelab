#![cfg(test)]

use anyhow::Result;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::ClientOptions;
use tonic::transport::Endpoint;
use tower::service_fn;

mod proto {
    pub mod homehttp {
        pub mod v1 {
            tonic::include_proto!("homehttp.v1");
        }
    }
}

use proto::homehttp::v1::home_http_client::HomeHttpClient;
use proto::homehttp::v1::Empty;

const PIPE_DEV: &str = r"\\.\\pipe\\home-http-dev";

#[pin_project::pin_project]
struct SendablePipeClient {
    #[pin]
    inner: tokio::net::windows::named_pipe::NamedPipeClient,
}

impl SendablePipeClient {
    fn new(inner: tokio::net::windows::named_pipe::NamedPipeClient) -> Self {
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

#[tokio::test]
async fn test_grpc_connection() -> Result<()> {
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(|_uri| {
            async {
                ClientOptions::new()
                    .open(PIPE_DEV)
                    .map(SendablePipeClient::new)
            }
        }))
        .await?;

    let mut client = HomeHttpClient::new(channel);

    let response = client.get_status(Empty {}).await?;

    assert_eq!(response.into_inner().state, "running");

    Ok(())
}
