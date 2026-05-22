# Tauri Desktop Application (home-lab)

## Purpose
System tray application that orchestrates all homelab services. Hidden main window
(skipTaskbar: true, visible: false). Communicates with Windows services via gRPC
Named Pipes. Manages WSL cluster lifecycle.

---

### Requirement: System tray presence
The application MUST run as a system tray icon without a visible window or taskbar entry.
The window MUST be accessible via single click OR double click on the tray icon.

#### Scenario: Tray icon single click opens window
- GIVEN the main window is hidden
- WHEN the user single-clicks the tray icon
- THEN the window is shown and focused
- AND the window state is restored (not a new window)

#### Scenario: Tray icon double click opens window
- GIVEN the main window is hidden
- WHEN the user double-clicks the tray icon
- THEN `open_or_focus_main()` is called (same as single click)

#### Scenario: Window close hides to tray
- GIVEN the main window is visible
- WHEN the user clicks the window close button (X)
- THEN `CloseRequested` event fires, `prevent_close()` is called
- AND `window.hide()` is called (window hidden, not destroyed)
- AND the tray icon remains in the notification area

#### Scenario: "Ouvrir l'interface" menu item
- GIVEN the tray context menu is open
- WHEN "Ouvrir l'interface" is clicked
- THEN `open_or_focus_main()` is called

#### Scenario: "Quitter" terminates the process
- GIVEN the tray context menu is open
- WHEN "Quitter" is clicked
- THEN `std::process::exit(0)` is called immediately

---

### Requirement: Service startup on boot
In release builds, the application MUST attempt to start Windows services
if they are not already running: HomeDnsService, HomeHttpService, HomeS3Service, HomeOidcService.

#### Scenario: Service auto-start
- GIVEN `HomeDnsService` is stopped at application launch
- WHEN the Tauri app starts in release mode
- THEN `ensure_service_running("HomeDnsService")` is called asynchronously
- AND `sc.exe start HomeDnsService` is invoked

---

### Requirement: MCP server binary
The application MUST ship an `home-lab-mcp` binary that exposes homelab
capabilities (DNS, HTTP, WSL, S3, OIDC) via the Model Context Protocol,
allowing AI assistants to manage the homelab programmatically.

#### Scenario: MCP tools available
- GIVEN the home-lab-mcp binary is running
- WHEN an MCP client connects
- THEN the following tool groups are available:
  dns_add_record, dns_remove_record, dns_list_records, dns_get_status, dns_reload_config
  http_add_route, http_remove_route, http_list_routes, http_get_status, http_reload_config
  s3_create_bucket, s3_delete_bucket, s3_list_buckets, s3_get_status, s3_update_bucket
  oidc_register_client, oidc_remove_client, oidc_list_clients, oidc_get_status
  wsl_import_instance, wsl_remove_instance, wsl_list_instances
  wsl_kubectl_exec, wsl_kubectl_apply_yaml
  wsl_sync_windows_kubeconfig, wsl_get_host_capabilities

---

### Requirement: Frontend Web Components
The frontend MUST use Vanilla JS Web Components. The following components MUST exist:
- `<dns-status>` — DNS service state and log level
- `<dns-records>` — DNS records display
- `<http-status>` — HTTP service state and log level
- `<http-routes>` — HTTP routes configuration
- `<toast-container>` — Error message display (`showError(message)`)

---

### Requirement: Build metadata embedding
All services and the Tauri app MUST embed git metadata at compile time via `build.rs`:
- `BUILD_GIT_SHA` — git commit hash
- `BUILD_GIT_TAG` — git tag (if any)
- `BUILD_TIME` — build timestamp (UTC)
