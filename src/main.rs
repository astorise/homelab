use std::error::Error;

mod alpine;
mod cli;
mod gitlab;
mod helm;
mod k3s;
mod minio;
mod prometheus;
mod tools;
mod vcluster;
use clap::Parser;
use cli::{Cli, Command};

//#[tokio::main]
fn main() -> std::result::Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let instance_k3_name = "k3s";

    match args.command {
        Command::Install => {
            println!("Installation Alpine");
            alpine::import_alpine(instance_k3_name)?;
            println!("Installation K3S");
            k3s::install_k3s(instance_k3_name)?;
            println!("Installation Helm");
            helm::install_helm(instance_k3_name)?;
        }
        Command::Helm => {
            helm::install_helm(instance_k3_name)?;
        }
        Command::Minio { create_bucket, delete_bucket } => {
            if create_bucket.is_none() && delete_bucket.is_none() {
                minio::deploy_minio(instance_k3_name)?;
            }
            if let Some(b) = create_bucket {
                minio::create_bucket(instance_k3_name, &b)?;
            }
            if let Some(b) = delete_bucket {
                minio::delete_bucket(instance_k3_name, &b)?;
            }
        }
        Command::Gitlab => {
            gitlab::deploy_gitlab(instance_k3_name)?;
        }
        Command::Prometheus => {
            prometheus::deploy_prometheus(instance_k3_name)?;
        }
        Command::AddCluster => {
            vcluster::deploy_vclusters(instance_k3_name)?;
        }
        Command::Uninstall {
            k3s,
            helm,
            namespace,
        } => {
            if k3s {
                k3s::uninstall_k3s(instance_k3_name)?;
            }
            if helm {
                helm::uninstall_helm(instance_k3_name)?;
            }
            for ns in namespace {
                k3s::delete_namespace(instance_k3_name, &ns)?;
            }
            alpine::unregister(instance_k3_name)?;
        }
        Command::Update => {
            println!("Update not implemented");
        }
    }

    Ok(())
}
