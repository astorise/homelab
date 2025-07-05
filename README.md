# Homelab

Command line interface to bootstrap and manage a local Kubernetes lab using Windows Subsystem for Linux (WSL).
It installs a minimal Alpine distribution, a k3s cluster and common services such as Helm, MinIO, GitLab and Prometheus.
The Docker image archive used for the WSL distro is generated during the GitHub Action build and embedded in the binary, allowing installation to run completely offline.

CI builds produce both Linux and Windows (x86_64) binaries. The Windows executable is available as `env-dev.exe`.

The repository also provides a `Dockerfile` for running the compiled `env-dev`
binary. The runtime image is based on **Alpine Linux 3.20**, installs `openrc` so
the k3s install script can run, and downloads the k3s binary using
`INSTALL_K3S_SKIP_START=true INSTALL_K3S_SKIP_ENABLE=true curl -sfL https://get.k3s.io | sh -`.

When compiling the project, set the `WSL_IMAGE_ARCHIVE` environment variable to
the Docker image tarball produced by the CI workflow so the archive can be
embedded into the binary.

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
- `check-wsl` - compare installed WSL version with the latest available on GitHub
  - `--pre` - include pre-release versions when checking


### Pre-built WSL image

You can import a ready-to-use WSL distro instead of building it from scratch. Go
to the repository's **Actions** tab on GitHub and download the `env-dev-image.tar`
artifact from the latest successful workflow. When available, the Linux image is
published as `env-dev-image-linux.tar` and the Windows image as
`env-dev-image-windows.tar`.

Set the `WSL_IMAGE_ARCHIVE` environment variable to the downloaded archive
before running commands, for example:

```bash
export WSL_IMAGE_ARCHIVE=/path/to/env-dev-image.tar
cargo run -- install
```

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
# Check if a newer WSL version is available
cargo run -- check-wsl
cargo run -- check-wsl --pre
```
