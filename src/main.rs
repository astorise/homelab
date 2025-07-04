
use std::error::Error;


mod alpine;
mod k3s;
mod helm;
mod vcluster;
mod minio;
mod tools;
mod gitlab;
mod prometheus;
mod cli;
use cli::{Cli, Command};
use clap::Parser;






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
        Command::Minio => {
            minio::deploy_minio(instance_k3_name)?;
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
        Command::Uninstall => {
            println!("Uninstall not implemented");
        }
        Command::Update => {
            println!("Update not implemented");
        }
    }

    Ok(())
}
