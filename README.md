# Homelab

Command line interface to bootstrap and manage a local Kubernetes lab using Windows Subsystem for Linux (WSL).
It installs a minimal Alpine distribution, a k3s cluster and common services such as Helm, MinIO, GitLab and Prometheus.

The repository also provides a `Dockerfile` for running the compiled `env-dev`
binary. The runtime image is based on **Alpine Linux 3.20** and installs the
k3s binary using the official installation script (`curl -sfL https://get.k3s.io | sh -`).

## Requirements

- Windows machine with **WSL2** enabled
- **Rust** toolchain with `cargo`

## Usage

Run the CLI with cargo followed by one of the available commands:

```bash
cargo run -- <COMMAND>
```

### Commands

- `install` - install Alpine, K3S and Helm
- `uninstall` - remove the WSL distro and optionally clean K3S, Helm and namespaces
- `helm` - install only Helm
- `minio` - deploy the MinIO operator and tenant
  - `--create-bucket <name>` - create a bucket in MinIO
  - `--delete-bucket <name>` - delete a bucket from MinIO
- `gitlab` - deploy Gitlab
- `prometheus` - deploy Prometheus
- `add-cluster` - deploy additional clusters
- `update` - update the K3S and Helm binaries inside the WSL distro
- `cuda` - install CUDA support in the WSL distro when an NVIDIA GPU is detected

### Examples

```bash
# Install Alpine, K3S and Helm
cargo run -- install

# Uninstall everything and remove the namespaces 'minio' and 'gitlab'
cargo run -- uninstall --k3s --helm --namespace minio,gitlab

# Update K3S and Helm to the latest versions
cargo run -- update

# Deploy MinIO and create a bucket
cargo run -- minio
cargo run -- minio --create-bucket my-bucket

# Delete a bucket from MinIO
cargo run -- minio --delete-bucket my-bucket
# Install CUDA support
cargo run -- cuda
```
