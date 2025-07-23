use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "homelab")]
pub struct Cli {
    /// Base directory where the WSL distro will be stored
    /// Can also be set with the `HOMELAB_DISTRO_PATH` environment variable.
    /// Providing the flag without a value defaults to the system temp directory.
    #[arg(long, env = "HOMELAB_DISTRO_PATH", num_args = 0..=1, value_name = "PATH", default_missing_value = "")]
    pub distro_path: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Import the k3s image and install Helm
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
    Minio {
        /// Create bucket in Minio
        #[arg(long)]
        create_bucket: Option<String>,
        /// Delete bucket from Minio
        #[arg(long)]
        delete_bucket: Option<String>,
    },
    /// Deploy Gitlab
    Gitlab,
    /// Deploy Prometheus
    Prometheus,
    /// Deploy additional clusters
    AddCluster,
    /// Update components
    Update,
    /// Install CUDA support for NVIDIA GPUs
    Cuda,
    /// Check if a newer WSL version is available
    CheckWsl {
        /// Include pre-release versions
        #[arg(long)]
        pre: bool,
    },
}
