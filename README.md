# Homelab

Command line interface to manage the local homelab setup.

## Usage

Run the application with one of the available subcommands:

```bash
cargo run -- <COMMAND>
```

### Commands

- `install` - install Alpine, K3S and Helm
- `uninstall` - uninstall the WSL distro and optionally clean k3s, Helm and namespaces
- `helm` - install only Helm
- `minio` - deploy Minio
- `gitlab` - deploy Gitlab
- `prometheus` - deploy Prometheus
- `add-cluster` - deploy additional clusters
- `update` - update components (not implemented)

### Examples

```bash
# Install Alpine, K3S and Helm
cargo run -- install

# Deploy Minio
cargo run -- minio
```
