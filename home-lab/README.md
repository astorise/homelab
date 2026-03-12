# Home Lab UI

This Tauri + Vite application now uses Tailwind CSS for styling.

## Development

```bash
npm run dev        # start Vite dev server
npm run tauri dev  # start Tauri desktop app
```

## Components

- `<dns-status>`: displays the DNS service state and log level.
- `<dns-records>`: shows available DNS records.
- `<http-status>`: displays the HTTP service state and log level.
- `<http-routes>`: shows configured HTTP routes.
- `<toast-container>`: hosts transient error messages; use `showError(message)` to display a toast.
- `<k8s-client>`: runs `kubectl` commands against k3s clusters in selected WSL instances and syncs the Windows kubeconfig.

## MCP Server

The Tauri package now includes a console binary named `home-lab-mcp.exe`.

- Transport: `stdio`
- Scope: WSL provisioning, `kubectl` execution and YAML apply, DNS records, OIDC clients, and HTTPS route management
- Installed path on Windows bundles: `bin/home-lab-mcp.exe`

Example local run from the workspace root:

```bash
cargo run --manifest-path src-tauri/Cargo.toml --bin home-lab-mcp
```
