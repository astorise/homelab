use std::error::Error;
use std::process::Command;

pub(crate) fn update_components(instance_name: &str) -> Result<(), Box<dyn Error>> {
    update_k3s(instance_name)?;
    update_helm(instance_name)?;
    Ok(())
}

fn update_k3s(instance_name: &str) -> Result<(), Box<dyn Error>> {
    let url_k3s = "https://api.github.com/repos/k3s-io/k3s/releases/latest";
    let client = reqwest::blocking::Client::new();
    let response = client.get(url_k3s).header("User-Agent", "request").send()?;

    if !response.status().is_success() {
        println!("Failed to fetch k3s version: {}", response.status());
        return Ok(());
    }

    let release: serde_json::Value = serde_json::from_str(&response.text()?)?;
    let k3s_url = release["assets"]
        .as_array()
        .and_then(|assets| assets.iter().find(|a| a["name"] == "k3s"))
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or("k3s asset not found")?;

    Command::new("wsl")
        .args(&[
            "-d",
            instance_name,
            "--",
            "sh",
            "-c",
            &format!(
                "wget -O /usr/local/bin/k3s {} && chmod +x /usr/local/bin/k3s",
                k3s_url
            ),
        ])
        .status()?;

    Command::new("wsl")
        .args(&[
            "-d",
            instance_name,
            "--",
            "sh",
            "-c",
            "pkill k3s || true && /etc/init.d/k3s",
        ])
        .status()?;

    Ok(())
}

fn update_helm(instance_name: &str) -> Result<(), Box<dyn Error>> {
    let url_version_helm = "https://get.helm.sh/helm-latest-version";
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(url_version_helm)
        .header("User-Agent", "request")
        .send()?;

    if !response.status().is_success() {
        println!("Failed to fetch Helm version: {}", response.status());
        return Ok(());
    }

    let helm_version = response.text()?;

    Command::new("wsl")
        .args(&[
            "-d",
            instance_name,
            "--",
            "sh",
            "-c",
            &format!(
                "wget -P /tmp https://get.helm.sh/helm-{}-linux-amd64.tar.gz && \
                      tar xf /tmp/helm-{}-linux-amd64.tar.gz -C /tmp/ && \
                      cp /tmp/linux-amd64/helm /usr/local/bin/ && \
                      chmod +x /usr/local/bin/helm && rm -r /tmp/*",
                helm_version.trim(),
                helm_version.trim()
            ),
        ])
        .status()?;

    Ok(())
}
