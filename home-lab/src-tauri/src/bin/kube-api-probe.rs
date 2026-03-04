use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use k8s_openapi::api::core::v1::Node;
use kube::api::{Api, ListParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config as KubeClientConfig, ResourceExt};

fn install_rustls_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_ok()
    {
        return Ok(());
    }
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_ok()
    {
        return Ok(());
    }
    Err(anyhow!(
        "Impossible d'initialiser le provider Rustls (aws-lc-rs/ring)."
    ))
}

fn slugify(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_dash = false;
    for ch in raw.trim().chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "cluster".to_string()
    } else {
        trimmed.to_string()
    }
}

fn usage() -> &'static str {
    "Usage:
  cargo run --manifest-path home-lab/src-tauri/Cargo.toml --bin kube-api-probe -- [--instance NAME] [--context CTX] [--kubeconfig PATH]

Examples:
  cargo run --manifest-path home-lab/src-tauri/Cargo.toml --bin kube-api-probe -- --instance home-lab-k3s
  cargo run --manifest-path home-lab/src-tauri/Cargo.toml --bin kube-api-probe -- --context home-lab-wsl-home-lab-k3s"
}

fn parse_args() -> Result<(String, Option<String>, Option<PathBuf>)> {
    let mut instance = "home-lab-k3s".to_string();
    let mut context = None;
    let mut kubeconfig = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--instance" => {
                instance = args
                    .next()
                    .ok_or_else(|| anyhow!("--instance attend une valeur"))?;
            }
            "--context" => {
                context = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("--context attend une valeur"))?,
                );
            }
            "--kubeconfig" => {
                let raw = args
                    .next()
                    .ok_or_else(|| anyhow!("--kubeconfig attend une valeur"))?;
                kubeconfig = Some(PathBuf::from(raw));
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => {
                return Err(anyhow!("Argument inconnu: {other}\n\n{}", usage()));
            }
        }
    }

    Ok((instance, context, kubeconfig))
}

fn default_kubeconfig_path() -> Result<PathBuf> {
    let home = env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .ok_or_else(|| anyhow!("Impossible de determiner USERPROFILE"))?;
    Ok(home.join(".kube").join("config"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let (instance, context_override, kubeconfig_override) = parse_args()?;
    install_rustls_provider()?;
    let context =
        context_override.unwrap_or_else(|| format!("home-lab-wsl-{}", slugify(&instance)));
    let kubeconfig_path = match kubeconfig_override {
        Some(path) => path,
        None => default_kubeconfig_path()?,
    };

    eprintln!("[probe] instance={instance}");
    eprintln!("[probe] context={context}");
    eprintln!("[probe] kubeconfig={}", kubeconfig_path.display());

    let kubeconfig = Kubeconfig::read_from(kubeconfig_path.clone()).with_context(|| {
        format!(
            "Lecture du kubeconfig Windows impossible sur {}",
            kubeconfig_path.display()
        )
    })?;

    let options = KubeConfigOptions {
        context: Some(context.clone()),
        ..KubeConfigOptions::default()
    };

    eprintln!("[probe] build config...");
    let mut config = KubeClientConfig::from_custom_kubeconfig(kubeconfig, &options)
        .await
        .with_context(|| format!("Chargement du contexte kubeconfig '{}'", context))?;
    config.connect_timeout = Some(Duration::from_secs(5));
    config.read_timeout = Some(Duration::from_secs(10));
    config.write_timeout = Some(Duration::from_secs(10));
    config.proxy_url = None;

    eprintln!("[probe] create client...");
    let client = Client::try_from(config).context("Creation client Kubernetes impossible")?;

    eprintln!("[probe] list nodes...");
    let nodes: Api<Node> = Api::all(client.clone());
    let listed = tokio::time::timeout(Duration::from_secs(20), nodes.list(&ListParams::default()))
        .await
        .context("Timeout API Kubernetes (list nodes)")?
        .context("Echec API Kubernetes (list nodes)")?;

    println!("nodes={}", listed.items.len());
    for node in listed.items {
        println!("{}", node.name_any());
    }

    Ok(())
}
