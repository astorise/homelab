use std::error::Error;
use std::process::Command;

pub(crate) fn install_helm(instance_name: &str) -> std::result::Result<(), Box<dyn Error>> {
    std::thread::sleep(std::time::Duration::from_secs(10));
    let url_version_helm = "https://get.helm.sh/helm-latest-version";
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(url_version_helm)
        .header("User-Agent", "request")
        .send()?;

    // Vérifier le statut de la réponse
    if !response.status().is_success() {
        println!("Échec de la requête version_helm: {}", response.status());
        return Ok(());
    }
    // Imprimer la réponse brute

    let helm_version = response.text()?;

    Command::new("wsl")
        .arg("-d")
        .arg(instance_name)
        .args([
            "sh",
            "-c",
            format!(
                "wget  -P  /tmp https://get.helm.sh/helm-{}-linux-amd64.tar.gz && tar xf /tmp/helm-{}-linux-amd64.tar.gz -C /tmp/ && cp /tmp/linux-amd64/helm /usr/local/bin/  && chmod +x /usr/local/bin/helm && rm -r /tmp/*",
                helm_version.trim(),
                helm_version.trim()
            )
            .as_str(),
        ])
        .output()
        .expect("Échec de l'exécution de la commande");

    Ok(())
}

pub(crate) fn uninstall_helm(instance_name: &str) -> Result<(), Box<dyn Error>> {
    Command::new("wsl")
        .arg("-d")
        .arg(instance_name)
        .args([
            "sh",
            "-c",
            "helm list --short | xargs -r -n1 helm uninstall",
        ])
        .status()?;
    Ok(())
}
