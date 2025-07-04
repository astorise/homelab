use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "homelab")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Install Alpine, K3S and Helm
    Install,
    /// Remove installed components
    Uninstall {
        /// Uninstall k3s cluster
        #[arg(long)]
        k3s: bool,
        /// Uninstall all Helm releases
        #[arg(long)]
        helm: bool,
        /// Namespaces to delete (comma separated)
        #[arg(long, value_delimiter = ',')]
        namespace: Vec<String>,
    },
    /// Install Helm only
    Helm,
    /// Deploy Minio
    Minio,
    /// Deploy Gitlab
    Gitlab,
    /// Deploy Prometheus
    Prometheus,
    /// Deploy additional clusters
    AddCluster,
    /// Update components
    Update,
}
