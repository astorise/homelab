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
    /// Placeholder for uninstall logic
    Uninstall,
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
