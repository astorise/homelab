# CLAUDE.md - Homelab Project Guide for AI Assistants

## Project Overview

This is a **Windows-based homelab management system** built with Rust and Tauri. The project provides a desktop application for managing local network services including DNS, HTTP reverse proxy, and OIDC authentication.

### Key Technologies
- **Language**: Rust (Edition 2021/2024)
- **UI Framework**: Tauri v2 (Vite + Vanilla JS + Tailwind CSS)
- **IPC**: gRPC over Windows Named Pipes
- **Build System**: Cargo workspace
- **CI/CD**: GitHub Actions
- **Dependency Management**: Renovate

### License
GPL-3.0-only

---

## Repository Structure

```
homelab/
├── home-dns/           # DNS service (Windows service)
│   ├── proto/          # Protocol buffers definitions
│   ├── src/            # Rust source code
│   └── Cargo.toml      # Package manifest
│
├── home-http/          # HTTP reverse proxy service (Windows service)
│   ├── proto/          # Protocol buffers definitions
│   ├── src/            # Rust source code
│   ├── tests/          # Integration tests
│   └── Cargo.toml      # Package manifest
│
├── home-oidc/          # OIDC authentication service (Windows service)
│   ├── proto/          # Protocol buffers definitions
│   ├── src/            # Rust source code
│   ├── tests/          # Integration tests
│   └── Cargo.toml      # Package manifest
│
├── home-lab/           # Tauri desktop application
│   ├── src/            # Frontend (Vanilla JS)
│   │   └── components/ # Web components
│   ├── src-tauri/      # Tauri backend (Rust)
│   │   ├── proto/      # Shared proto definitions
│   │   ├── resources/  # Bundled resources
│   │   │   ├── bin/    # Service executables
│   │   │   ├── conf/   # Configuration files
│   │   │   ├── scripts/ # PowerShell scripts
│   │   │   └── wsl/    # WSL rootfs image
│   │   └── src/        # Tauri Rust code
│   ├── package.json    # NPM dependencies
│   └── tailwind.config.js
│
├── local-rpc/          # Shared RPC utilities
├── pipe-test/          # Named pipe testing utilities
├── service-tester/     # Service testing utilities
├── docker-image/       # Development environment Docker image
├── scripts/            # Build and installation scripts
│   ├── install-elevated.ps1
│   ├── generate-codesign-cert.ps1
│   └── tauri-msi-relink.ps1
│
├── .github/
│   └── workflows/
│       └── build-tauri.yml  # CI/CD pipeline
│
├── Cargo.toml          # Workspace configuration
└── renovate.json       # Dependency updates config
```

---

## Architecture

### System Components

1. **Windows Services** (home-dns, home-http, home-oidc)
   - Run as system services on Windows
   - Expose gRPC APIs over Named Pipes (`\\.\pipe\home-{service}`)
   - Self-contained with logging via flexi_logger
   - Build metadata embedded via build.rs (git SHA, tag, timestamp)

2. **Tauri Desktop Application** (home-lab)
   - System tray application (hidden main window)
   - Frontend: Vanilla JS with Web Components + Tailwind CSS
   - Backend: Rust with Tauri APIs
   - Communicates with services via gRPC
   - Bundles services and WSL rootfs for installation

3. **WSL Environment**
   - Docker image packaged as WSL rootfs
   - Deployed via Tauri resources
   - Used for development/testing containers

### Communication Pattern

```
[Tauri Frontend]
    ↓ Tauri IPC
[Tauri Backend (Rust)]
    ↓ gRPC over Named Pipes
[Windows Services (home-dns, home-http, home-oidc)]
```

### Build Metadata

All services embed build information via `build.rs`:
- `BUILD_GIT_SHA` - Git commit hash
- `BUILD_GIT_TAG` - Git tag (if any)
- `BUILD_TIME` - Build timestamp

---

## Development Workflows

### Prerequisites
- **Windows**: Primary development platform
- **Rust**: Stable toolchain (x86_64-pc-windows-msvc)
- **Node.js**: v24 (for frontend development)
- **protoc**: Auto-installed via protoc-bin-vendored

### Local Development

#### Working on Services

```bash
# Build individual service
cargo build -p home-dns
cargo build -p home-http
cargo build -p home-oidc

# Run tests
cargo test -p home-http
cargo test -p home-oidc

# Build all in workspace
cargo build --release
```

#### Working on Tauri Application

```bash
cd home-lab

# Install dependencies
npm ci  # or npm install

# Development mode (Vite only)
npm run dev

# Development with Tauri
npm run tauri dev

# Development variants
npm run tauri:mock      # With VITE_TAURI_MOCK=1
npm run tauri:no-svc    # Without dev services
npm run tauri:verbose   # With RUST_LOG=debug

# Build frontend
npm run build

# Preview production build
npm run preview
```

#### Frontend Components

Web components are used for UI:
- `<dns-status>` - DNS service state and log level
- `<dns-records>` - DNS records display
- `<http-status>` - HTTP service state and log level
- `<http-routes>` - HTTP routes configuration
- `<toast-container>` - Error message display (use `showError(message)`)

### Protocol Buffers

Proto files are duplicated:
- Service-specific: `{service}/proto/*.proto`
- Tauri copy: `home-lab/src-tauri/proto/*.proto`

**IMPORTANT**: When modifying proto definitions, update BOTH locations.

Code generation happens via `build.rs` using:
- `tonic-build` for gRPC services
- `prost-build` for message types

---

## Build and Deployment

### CI/CD Pipeline (.github/workflows/build-tauri.yml)

The build process has 3 jobs:

1. **build-docker-image** (Ubuntu)
   - Builds WSL development environment
   - Exports as tar artifact

2. **build-services** (Windows)
   - Builds home-dns, home-http, home-oidc
   - Target: x86_64-pc-windows-msvc
   - Uses Rust cache for faster builds
   - Uploads service executables

3. **build-tauri-win** (Windows)
   - Downloads service artifacts
   - Downloads WSL rootfs
   - Builds Tauri app (NSIS + MSI installers)
   - Supports code signing (secrets: WINDOWS_CERTIFICATE, WINDOWS_CERT_PASSWORD)
   - Uploads NSIS and MSI packages

### Release Artifacts

- NSIS installer: `target/release/bundle/nsis/*.exe`
- MSI installer: `target/release/bundle/msi/*.msi`

### Code Signing

- Certificate imported from GitHub secrets
- Only on release builds
- Uses Windows certificate store

---

## Key Conventions

### Code Style

1. **Rust Edition**:
   - home-dns: Edition 2024
   - Others: Edition 2021

2. **Windows Subsystem**:
   ```rust
   #![cfg_attr(
       all(not(debug_assertions), target_os = "windows"),
       windows_subsystem = "windows"
   )]
   ```
   This hides console window in release builds.

3. **Error Handling**:
   - Use `anyhow` crate for error propagation
   - Context-rich errors: `.context("description")?`

4. **Logging**:
   - Use `flexi_logger` with:
     - Rotation: Age-based with cleanup
     - Duplicate to stderr in debug mode
     - File logging in service directories

5. **Async Runtime**:
   - `tokio` with workspace-level version pinning
   - Features: `["macros", "rt-multi-thread", "net"]`

6. **Named Pipe Pattern**:
   ```rust
   #[pin_project]
   struct PipeConnection {
       #[pin]
       inner: NamedPipeServer,
   }

   unsafe impl Send for PipeConnection {}

   impl Connected for PipeConnection {
       type ConnectInfo = ();
       fn connect_info(&self) -> Self::ConnectInfo {}
   }
   ```
   Required for gRPC over Windows Named Pipes.

### Configuration Files

Services use YAML configuration files:
- DNS: Records, zones, upstream servers
- HTTP: Routes, backends, TLS settings
- OIDC: Clients, keys, token settings

Located in bundled `resources/conf/` directory.

### Workspace Dependencies

Shared dependencies in workspace `Cargo.toml`:
```toml
sysinfo = "0.37.0"
tokio = "1.47.1"
tokio-tungstenite = "0.28.0"
windows-service = "0.8.0"
```

Use `{ workspace = true }` in member Cargo.toml files.

### Release Profile

```toml
[profile.release]
lto = "thin"           # Link-time optimization
codegen-units = 1      # Better optimization, slower builds
```

---

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Test specific package
cargo test -p home-http
cargo test -p home-oidc
```

### Integration Tests

- Located in `{service}/tests/`
- Example: `home-http/tests/grpc_connection.rs`
- Use `tokio::test` for async tests

### Test Utilities

- `service-tester/`: Helper crate for service testing
- `pipe-test/`: Named pipe connection testing

---

## Common Tasks for AI Assistants

### Adding a New gRPC Method

1. Update `{service}/proto/*.proto`
2. Update `home-lab/src-tauri/proto/*.proto` (MUST MATCH)
3. Implement method in service's `main.rs`
4. Add frontend integration in Tauri backend
5. Test with service running

### Adding a New Configuration Option

1. Update config struct in service `main.rs`
2. Update YAML schema documentation
3. Add validation logic
4. Test with sample config file

### Modifying Build Process

1. Update `build.rs` for compile-time changes
2. Update `.github/workflows/build-tauri.yml` for CI changes
3. Update `scripts/` for installation changes
4. Test locally before pushing

### Adding Dependencies

1. Add to workspace `Cargo.toml` if shared
2. Or add to individual `Cargo.toml` with version
3. Consider impact on build size
4. Renovate will manage updates

### Working with Tauri Resources

Resources are bundled from `home-lab/src-tauri/resources/`:
- `bin/` → Service executables (from CI artifacts)
- `conf/` → Default configurations
- `scripts/` → Installation scripts
- `wsl/` → WSL rootfs (from CI artifacts)

Accessed at runtime via Tauri resource resolver.

---

## Troubleshooting

### Build Issues

1. **Missing protoc**: Should auto-install via `protoc-bin-vendored`
2. **Workspace dependency conflicts**: Ensure versions match in workspace root
3. **Named pipe errors**: Windows-specific, requires actual Windows environment

### Service Issues

1. **Service won't start**: Check logs in service directory
2. **gRPC connection failed**: Verify named pipe path `\\.\pipe\home-{service}`
3. **Permission denied**: Services may need admin privileges

### Frontend Issues

1. **Components not updating**: Check console bridge in `console-bridge.js`
2. **Tauri commands failing**: Verify backend command registration
3. **Dev server not starting**: Ensure port 5173 is available

---

## Git Workflow

### Branches

- Work on feature branches with `claude/` prefix
- CI ignores `codex/*` branches
- Default branch for PRs: (check repository settings)

### Commits

- Use conventional commit messages when possible
- CI builds on all pushes except ignored branches

### Pull Requests

- Ensure CI passes (all 3 jobs)
- Test installers if modifying build process
- Update documentation for API changes

---

## Important Notes

1. **Platform-Specific**: This is a Windows-only project. Services use Windows-specific APIs (windows-service, windows-sys, named pipes).

2. **Proto Duplication**: Always update both service and Tauri proto files when changing gRPC definitions.

3. **Build Metadata**: Services embed git info at compile time. Requires git repository for builds.

4. **CI Artifacts**: The build process downloads service executables and WSL rootfs from earlier jobs. Don't modify Tauri resources/bin manually.

5. **Code Signing**: Production builds need certificate secrets configured in GitHub repository.

6. **Renovate**: Dependency updates are automated. Review and test PRs from Renovate bot.

7. **Edition 2024**: home-dns uses Rust edition 2024. Be aware of edition-specific features.

---

## Useful Commands Reference

```bash
# Development
cargo build                          # Build all workspace members
cargo build -p home-dns --release    # Build specific service (release)
cargo test                           # Run all tests
cd home-lab && npm run tauri dev    # Run Tauri in dev mode

# Cleaning
cargo clean                          # Clean all build artifacts
cd home-lab && rm -rf node_modules   # Clean npm modules

# Release
cargo build --release                # Build all in release mode
cd home-lab && npm run build         # Build frontend for production
cd home-lab && npx tauri build      # Build Tauri installers

# Utilities
cargo tree -p home-http              # View dependency tree
cargo outdated                       # Check for outdated dependencies
```

---

## Additional Resources

- **Tauri Docs**: https://tauri.app/
- **Tonic (gRPC)**: https://github.com/hyperium/tonic
- **Windows Services**: https://github.com/mullvad/windows-service-rs
- **Rust Edition Guide**: https://doc.rust-lang.org/edition-guide/

---

**Last Updated**: 2025-11-27 (Auto-generated via Claude Code)
