use reqwest::blocking::Client;
use serde::Deserialize;
use std::error::Error;
use std::process::Command;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    prerelease: bool,
}

pub(crate) fn check_wsl_update(include_prerelease: bool) -> Result<(), Box<dyn Error>> {
    let output = Command::new("wsl").arg("--version").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut installed = "unknown".to_string();
    for line in stdout.lines() {
        if let Some(ver) = line.strip_prefix("WSL version:") {
            installed = ver.trim().to_string();
            break;
        }
    }
    println!("Installed WSL version: {}", installed);

    let client = Client::new();
    let resp = client
        .get("https://api.github.com/repos/microsoft/WSL/releases")
        .header("User-Agent", "request")
        .send()?;
    if !resp.status().is_success() {
        println!("Failed to fetch WSL releases: {}", resp.status());
        return Ok(());
    }
    let releases: Vec<Release> = serde_json::from_str(&resp.text()?)?;
    let latest = releases
        .into_iter()
        .find(|r| include_prerelease || !r.prerelease);

    if let Some(r) = latest {
        let remote = r.tag_name.trim_start_matches('v');
        if installed != remote {
            println!(
                "New WSL version available: {} (installed {})",
                remote, installed
            );
        } else {
            println!("WSL is up to date (version {})", installed);
        }
    } else {
        println!("No release information found");
    }
    Ok(())
}
