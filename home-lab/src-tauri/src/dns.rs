use anyhow::Result;
use tauri::async_runtime::Mutex;
use tonic::transport::{Channel, Endpoint, Uri};
use homedns::homedns::v1::home_dns_client::HomeDnsClient;
use tokio::net::windows::named_pipe::ClientOptions;
use std::sync::Arc;
use serde::Serialize;
use std::time::Duration;
use tower::service_fn;

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



use homedns::homedns::v1::*;


async fn dns_make_channel() -> Result<Channel> {
    // Endpoint URI is dummy; transport comes from the connector (named pipe stream).
    let ep = Endpoint::try_from("http://localhost:50051")?
        .connect_timeout(Duration::from_secs(5))
        .tcp_nodelay(true);
    let path = PIPE_NAME.to_string();
    let ch = ep.connect_with_connector(service_fn(move |_uri: Uri| {
        let path = path.clone();
        async move {
            // Open the named pipe client; succeeds when the server pipe exists.
            let client = ClientOptions::new().open(&path)?;
            Ok::<_, std::io::Error>(client)
        }
    })).await?;
    Ok(ch)
}

fn map_err<E: std::fmt::Display>(e: E) -> String { e.to_string() }

#[derive(Serialize)]
pub struct AckOut { ok: bool, message: String }

#[derive(Serialize)]
pub struct StatusOut { state: String, log_level: String }

#[derive(Serialize)]
pub struct RecordOut { name: String, a: Vec<String>, aaaa: Vec<String>, ttl: u32 }

#[derive(Serialize)]
pub struct ListRecordsOut { records: Vec<RecordOut> }

#[tauri::command]
async fn dns_ping() -> String { "pong".into() }

#[tauri::command]
pub async fn dns_get_status() -> Result<StatusOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.get_status(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let s = resp.into_inner();
    Ok(StatusOut{ state: s.state, log_level: s.log_level })
}

#[tauri::command]
pub async fn dns_stop_service() -> Result<AckOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.stop_service(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn dns_reload_config() -> Result<AckOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.reload_config(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn dns_list_records() -> Result<ListRecordsOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let resp = client.list_records(tonic::Request::new(Empty{})).await.map_err(map_err)?;
    let list = resp.into_inner();
    let out = ListRecordsOut {
        records: list.records.into_iter().map(|r| RecordOut {
            name: r.name, a: r.a, aaaa: r.aaaa, ttl: r.ttl
        }).collect()
    };
    Ok(out)
}

#[tauri::command]
pub async fn dns_add_record(name: String, rrtype: String, value: String, ttl: u32) -> Result<AckOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let req = AddRecordRequest { name, rrtype, value, ttl };
    let resp = client.add_record(tonic::Request::new(req)).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}

#[tauri::command]
pub async fn dns_remove_record(name: String, rrtype: String, value: String) -> Result<AckOut, String> {
    let ch = dns_make_channel().await.map_err(map_err)?;
    let mut client = HomeDnsClient::new(ch);
    let req = RemoveRecordRequest { name, rrtype, value };
    let resp = client.remove_record(tonic::Request::new(req)).await.map_err(map_err)?;
    let a = resp.into_inner();
    Ok(AckOut{ ok: a.ok, message: a.message })
}
