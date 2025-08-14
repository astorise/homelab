use anyhow::Result;
use tauri::async_runtime::Mutex;
use tonic::transport::{Channel, Endpoint, Uri};
use homedns::homedns::v1::home_dns_client::HomeDnsClient;
use tokio::net::windows::named_pipe::ClientOptions;
use std::sync::Arc;

pub mod homedns {
    pub mod homedns {
        pub mod v1 {
            tonic::include_proto!("homedns.v1");
        }
    }
}

const PIPE_NAME: &str = r"\\.\pipe\home-dns";

#[derive(Clone)]
pub struct GrpcState {
    pub client: Arc<Mutex<HomeDnsClient<Channel>>>,
}

pub async fn connect_npipe() -> Result<HomeDnsClient<Channel>> {
    // Endpoint dummy; the connector overrides actual transport
    let endpoint = Endpoint::try_from("http://[::]:50051")?;
    let channel = endpoint.connect_with_connector(tower::service_fn(|_uri: Uri| async move {
        let pipe = ClientOptions::new().open(PIPE_NAME)?;
        Ok::<_, std::io::Error>(pipe)
    })).await?;
    Ok(HomeDnsClient::new(channel))
}