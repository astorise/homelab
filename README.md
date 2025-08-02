# Homelab

Command line interface to bootstrap and manage a local Kubernetes lab using Windows Subsystem for Linux (WSL).
It imports a WSL distribution based on BusyBox, downloads the `k3s` binary from the official `rancher/k3s` image during installation, and includes common services such as Helm, MinIO, GitLab and Prometheus.
The CI workflow builds a Docker image, exports its **root filesystem** from a container and embeds this tarball in the binary, allowing installation to run completely offline.

The CI workflow includes separate jobs that build Linux and Windows (x86_64) binaries. The Windows executable is available as `env-dev.exe`.

The repository also provides a `Dockerfile` used to build this image. It uses a multi-stage build where the final image is based on BusyBox. The `k3s` binary is retrieved from the official image at runtime rather than bundled.

When compiling the project **from source**, set the `WSL_IMAGE_ARCHIVE` environment
variable to the root filesystem tarball produced by the CI workflow (exported
from a container) so the archive can be embedded into the binary. Compilation will fail if this variable is not
set. The `env-dev.exe` binary produced by the CI workflow already contains the
image and therefore does not require this variable.

## Requirements

- Windows machine with **WSL2** enabled
- **Rust** toolchain with `cargo`

## Usage

Run the CLI with cargo followed by one of the available commands:

```bash
cargo run -- <COMMAND>
```

Use `--distro-path [PATH]` or the `HOMELAB_DISTRO_PATH` environment variable to
change where the WSL distribution is stored. Providing the option without a
value stores the files in the system temporary directory.

### Commands

- `install` - import the k3s WSL image and install Helm
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

You can import a ready-to-use WSL distro instead of building it from scratch.
To do so:

1. Navigate to the repository's **Actions** tab on GitHub.
2. Open the latest successful workflow run and expand the **Artifacts** section.
3. Download the WSL image archive. On Linux, the file is published as
   `env-dev-image-linux.tar`, while on Windows the file is named
   `env-dev-image-windows.tar`. Both artifacts contain the same
   `env-dev-image.tar` file, which is the root filesystem exported from the
   container built by the workflow.

   Extract it with `tar -xf env-dev-image-windows.tar` (or
   `env-dev-image-linux.tar` on Linux), then import the distro:

   ```powershell
   wsl --import k3s <path> <path>\env-dev-image.tar --version 2
   ```

   The default distribution path is `C:\wsldistros`.

If you plan to compile the project yourself, set the `WSL_IMAGE_ARCHIVE`
environment variable to the path of the extracted root filesystem tarball
before running commands so the image can be embedded into the binary. This
variable is only required when compiling from source; the `env-dev.exe`
produced by the CI workflow already includes the WSL image. For example:

```bash
export WSL_IMAGE_ARCHIVE=/path/to/env-dev-image.tar
cargo run -- install
```

### Examples

```bash
# Import the k3s image and install Helm
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

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

