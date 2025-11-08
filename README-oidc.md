# OIDC Service Deployment Notes

This document describes how the local OIDC provider is provisioned on Windows hosts during the Tauri installer flow.

## Installation flow

1. The NSIS installer copies `oidc-service.exe` and `setup-oidc.exe` into `C:\Program Files\home-lab\bin` (or the selected installation directory).
2. During the `POSTINSTALL` hook, `setup-oidc.exe` runs with administrative privileges. It performs the following tasks:
   - Creates `C:\ProgramData\home-lab\oidc` if it does not already exist.
   - Generates a 2048-bit RSA key pair and a self-signed certificate (CN=`127.0.0.1`, SAN includes `127.0.0.1` and `localhost`) whenever the key material is missing.
   - Writes:
     - `oidc-private-key.pem`
     - `oidc-cert.pem`
     - `oidc-config.json`
     - `oidc-jwks.json`
   - Restricts ACLs on the PEM files to `SYSTEM` and `Administrators` (read-only).
   - Imports the certificate into `Cert:\LocalMachine\Root`, with a fallback to `Cert:\CurrentUser\Root` if elevation is not available.
   - Opens the Windows Firewall port `8443/TCP` with a persistent rule named **OIDC Local 8443**.
   - Registers (or updates) the `oidc-service` Windows service pointing to `oidc-service.exe`, sets it to automatic start, and starts it immediately.

## Service behaviour

`oidc-service.exe` is implemented in Rust using `axum` + `rustls`. When the service starts it:

- Reads configuration from `C:\ProgramData\home-lab\oidc\oidc-config.json`.
- Loads the persisted RSA key and JWKS payload.
- Listens on `https://127.0.0.1:8443` with TLS terminated by `rustls`.
- Exposes the following endpoints:
  - `/.well-known/openid-configuration`
  - `/jwks.json`
  - `/token`
- Issues RS256-signed JWTs for the `client_credentials` and `password` grant types. Client credentials are validated against the `clients` array from the configuration file.
- Writes JSON tracing logs to `C:\ProgramData\home-lab\logs\oidc-service.log`.

## Manual operations

- **Regenerate configuration:** Delete the contents of `C:\ProgramData\home-lab\oidc` and rerun `setup-oidc.exe` as Administrator.
- **Restart the service:**
  ```powershell
  sc.exe stop oidc-service
  sc.exe start oidc-service
  ```
- **Reimport certificate (if trust is lost):**
  ```powershell
  Import-Certificate -FilePath "C:\ProgramData\home-lab\oidc\oidc-cert.pem" -CertStoreLocation "Cert:\LocalMachine\Root"
  ```

## Troubleshooting

- Check `%ProgramData%\home-lab\logs\oidc-service.log` for runtime diagnostics.
- Ensure `OIDC Local 8443` firewall rule is enabled:
  ```powershell
  Get-NetFirewallRule -DisplayName "OIDC Local 8443"
  ```
- Verify the JWKS payload:
  ```powershell
  Invoke-WebRequest https://127.0.0.1:8443/jwks.json -SkipCertificateCheck | ConvertFrom-Json
  ```
- Validate token issuance with a configured client:
  ```powershell
  $body = "grant_type=client_credentials&client_id=ci-client&client_secret=<secret>"
  Invoke-RestMethod -Method Post -Uri https://127.0.0.1:8443/token -Body $body -ContentType 'application/x-www-form-urlencoded' -SkipCertificateCheck
  ```
