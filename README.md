# home-lab

A Windows-native desktop application for managing local network services — DNS, HTTPS reverse proxy, S3 object storage, and OIDC authentication — with first-class support for WSL2 k3s clusters.

## Overview

`home-lab` runs as a system tray application and orchestrates four Windows services that handle all local traffic routing. WSL2 instances running k3s are provisioned, configured, and reconciled automatically: DNS records, TLS certificates, Traefik ingress routes, and S3 access are all set up without manual steps.

```
┌─────────────────────────────────────────────────┐
│              home-lab (Tauri tray app)           │
│        gRPC / Named Pipe management API          │
└────────┬──────────┬──────────┬──────────┬───────┘
         │          │          │          │
    home-dns   home-http   home-s3   home-oidc
    (DNS +    (SNI proxy  (RustFS   (OIDC
     DoH)     port 443)   S3)       provider)
         │          │
         └──────────┴──── WSL2 k3s clusters
                              (Traefik, pods)
```

## Services

| Service | Description | Named Pipe |
|---|---|---|
| `home-dns` | Authoritative DNS for `.wsl` domains, DoH, IPv6 loopback | `\.\pipe\home-dns` |
| `home-http` | TLS SNI pass-through proxy (port 443) + TCP routing for k3s API | `\.\pipe\home-http` |
| `home-s3` | Embedded S3 storage (RustFS) on `127.0.0.1:9000` | `\.\pipe\home-s3` |
| `home-oidc` | Local OpenID Connect provider | `\.\pipe\home-oidc` |

Each service exposes a gRPC API over a Windows Named Pipe, consumed by the Tauri app and the MCP server.

### home-s3 validation and debug logs

`home-s3 validate` checks the configured S3 endpoint end to end. It loads
`C:\ProgramData\home-s3\s3-config.json`, lists buckets, creates a temporary
validation bucket, writes an object, reads it back, deletes the object, then
removes the bucket.

Enable debug logging by setting `log_level` in
`C:\ProgramData\home-s3\s3-config.json`:

```json
{
  "endpoint": "http://127.0.0.1:9000",
  "region": "us-east-1",
  "access_key_id": "rustfsadmin",
  "secret_access_key": "rustfssecret",
  "force_path_style": true,
  "data_dir": "C:\\ProgramData\\home-s3\\data",
  "log_level": "debug"
}
```

Logs are written under `C:\ProgramData\home-s3\logs`.

## WSL2 / k3s

Each WSL instance is a single-node k3s cluster. The homelab app handles the full lifecycle:

- Deterministic port assignment per instance (k3s API, Traefik ingress, NodePort range)
- TLS certificate issuance from the Home Lab Root CA, installed as Traefik default cert
- DNS records (`<name>.wsl A 127.0.0.1`, `<name>.wsl AAAA ::1`)
- HTTP SNI route (`<name>.wsl → Traefik HTTPS loopback`)
- S3 access: `s3.wsl → 10.255.255.254` (stable WSL loopback alias) via iptables DNAT + portproxy

## Requirements

- **Windows 11** (services use Windows-specific APIs)
- **Rust** stable toolchain, target `x86_64-pc-windows-msvc`
- **Node.js** v24 (frontend)
- **WSL2** with a kernel that supports k3s (for cluster features)

`protoc` is auto-installed via `protoc-bin-vendored`.

## Building

```powershell
# Build all services
cargo build --release

# Build a single service
cargo build -p home-dns --release

# Run tests
cargo test

# Build and run the Tauri app (dev mode)
cd home-lab
npm ci
npm run tauri dev
```

### Release installers

```powershell
cd home-lab
npm run build
npx tauri build   # produces NSIS (.exe) and MSI (.msi) in target/release/bundle/
```

## Project Structure

```
homelab/
├── home-dns/           # DNS service
├── home-http/          # HTTPS reverse proxy + TCP router
├── home-s3/            # S3 storage (RustFS)
├── home-oidc/          # OIDC provider
├── home-pki/           # PKI: Root CA + certificate issuance
├── home-lab/           # Tauri desktop application
│   ├── src/            # Frontend (Vanilla JS + Web Components)
│   └── src-tauri/      # Tauri backend (Rust)
│       ├── proto/      # Shared protobuf definitions
│       ├── resources/  # Bundled resources (WSL rootfs, configs, scripts)
│       └── src/        # App logic (WSL provisioning, reconciliation)
├── docker-image/       # WSL rootfs Docker image source
├── scripts/            # Build and installation helpers (PowerShell)
└── openspec/           # Capability specs (source of truth)
```

## MCP Server

The `home-lab-mcp` binary exposes the full homelab API via the [Model Context Protocol](https://modelcontextprotocol.io), allowing AI assistants to manage DNS records, HTTP routes, S3 buckets, OIDC clients, and WSL clusters directly.

```json
{
  "mcpServers": {
    "homelab": {
      "command": "home-lab-mcp.exe"
    }
  }
}
```

## CI/CD

Three-job GitHub Actions pipeline:

1. **build-docker-image** (Ubuntu) — builds the WSL rootfs Docker image
2. **build-services** (Windows) — compiles all four services
3. **build-tauri-win** (Windows) — downloads artifacts, builds NSIS + MSI installers

Code signing is supported via `WINDOWS_CERTIFICATE` / `WINDOWS_CERT_PASSWORD` repository secrets.

## License

GPL-3.0-only — see [LICENSE](LICENSE).
