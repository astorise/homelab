use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::grpc::homedns::homedns::v1::*;
use crate::grpc::{connect_npipe, GrpcState};

#[derive(Serialize)]
pub struct AckOut { ok: bool, message: String }

#[tauri::command]
pub async fn start_service(home_dns_exe: Option<String>) -> Result<AckOut, String> {
    // Lancer "home-dns.exe start" (ou via SC) côté Tauri
    // Par défaut, tente: sc start HomeDnsService
    let result = if let Some(exe) = home_dns_exe {
        std::process::Command::new(exe).arg("start").spawn()
    } else {
        std::process::Command::new("sc").args(["start", "HomeDnsService"]).spawn()
    };
    match result {
        Ok(mut child) => {
            let _ = child.wait();
            Ok(AckOut{ ok: true, message: "started".into() })
        }
        Err(e) => Err(format!("Failed to start service: {e}")),
    }
}

#[tauri::command]
pub async fn stop_service(state: State<'_, GrpcState>) -> Result<AckOut, String> {
    let mut client = state.client.lock().await;
    client.stop_service(Empty{}).await
        .map(|r| AckOut{ ok: r.get_ref().ok, message: r.get_ref().message.clone() })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn reload_config(state: State<'_, GrpcState>) -> Result<AckOut, String> {
    let mut client = state.client.lock().await;
    client.reload_config(Empty{}).await
        .map(|r| AckOut{ ok: r.get_ref().ok, message: r.get_ref().message.clone() })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_status(state: State<'_, GrpcState>) -> Result<StatusResponse, String> {
    let mut client = state.client.lock().await;
    client.get_status(Empty{}).await
        .map(|r| r.into_inner())
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
pub struct NewRecord { pub name: String, pub r#type: String, pub value: String, pub ttl: Option<u32> }

#[tauri::command]
pub async fn add_record(state: State<'_, GrpcState>, rec: NewRecord) -> Result<AckOut, String> {
    let mut client = state.client.lock().await;
    let req = AddRecordRequest{
        name: rec.name, r#type: rec.r#type, value: rec.value, ttl: rec.ttl.unwrap_or(0)
    };
    client.add_record(req).await
        .map(|r| AckOut{ ok: r.get_ref().ok, message: r.get_ref().message.clone() })
        .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
pub struct RemoveReq { pub name: String, pub r#type: Option<String>, pub value: Option<String> }

#[tauri::command]
pub async fn remove_record(state: State<'_, GrpcState>, req: RemoveReq) -> Result<AckOut, String> {
    let mut client = state.client.lock().await;
    let req = RemoveRecordRequest{
        name: req.name, r#type: req.r#type.unwrap_or_default(), value: req.value.unwrap_or_default()
    };
    client.remove_record(req).await
        .map(|r| AckOut{ ok: r.get_ref().ok, message: r.get_ref().message.clone() })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_records(state: State<'_, GrpcState>) -> Result<Vec<Record>, String> {
    let mut client = state.client.lock().await;
    client.list_records(Empty{}).await
        .map(|r| r.into_inner().records)
        .map_err(|e| e.to_string())
}

/// "Pipe" logique qui liste les résolutions définies dans dns.yaml (via gRPC ListRecords)
/// Pour l'UI, on expose un event stream simple qui renvoie une photo actuelle (pas de stream serveur).
#[tauri::command]
pub async fn list_yaml_resolutions(state: State<'_, GrpcState>) -> Result<Vec<Record>, String> {
    list_records(state).await
}