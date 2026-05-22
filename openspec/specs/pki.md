# PKI (home-pki)

## Purpose
Manages the Home Lab Root CA and issues server certificates for homelab services.
Certificates are ECC P-256, self-signed CA installed in the Windows trust store.

---

### Requirement: Root CA persistence
The Root CA MUST be stored as PEM files in `C:\ProgramData\home-lab\pki\`:
- `home-lab-root-ca.pem` — certificate
- `home-lab-root-ca-key.pem` — private key

If the files do not exist, they MUST be generated on first call to `ensure_root_ca()`.

#### Scenario: First-run CA generation
- GIVEN no CA files exist at the PKI path
- WHEN `ensure_root_ca()` is called
- THEN an ECC P-256 CA certificate is generated with 10-year validity
- AND both PEM files are written atomically (via temp file + rename)

#### Scenario: CA files exist — loaded without regeneration
- GIVEN `home-lab-root-ca.pem` and `home-lab-root-ca-key.pem` exist and are valid
- WHEN `ensure_root_ca()` is called
- THEN the existing CA is loaded
- AND no new CA is generated

---

### Requirement: Windows trust store installation
The Root CA MUST be installed in the Windows certificate store so that
browsers and system tools trust homelab TLS certificates without warnings.

#### Scenario: CA already installed
- GIVEN the CA thumbprint is already in `Cert:\LocalMachine\Root`
- WHEN `ensure_root_ca_installed()` is called
- THEN the function returns `AlreadyPresent`
- AND no duplicate certificate is imported

#### Scenario: Installing CA requires elevation
- GIVEN the CA is not in any trust store
- WHEN installation to `LocalMachine\Root` fails due to insufficient privileges
- THEN fallback installation to `CurrentUser\Root` is attempted

---

### Requirement: Server certificate issuance
The service MUST issue server certificates signed by the Root CA for any
provided hostname list, with SAN (Subject Alternative Names) for all domains.
Certificates are valid for 825 days (Apple browser limit).

#### Scenario: Certificate for WSL cluster domain
- GIVEN the Root CA is available
- WHEN `issue_server_certificate({common_name: "tachyon-mesh.wsl", dns_names: ["tachyon-mesh.wsl", "*.tachyon-mesh.wsl"]})` is called
- THEN a certificate is returned with the correct SANs
- AND the certificate is signed by the Root CA
- AND the `IssuedServerCertificate` contains `cert_pem`, `key_pem`, and `ca_cert_pem`

---

### Requirement: PKI directory visibility caveat
The PKI files have special attributes making them invisible to `Get-ChildItem`
in PowerShell but accessible via `[System.IO.Directory]::GetFiles()`.

#### Scenario: Verifying CA file existence
- GIVEN `C:\ProgramData\home-lab\pki\home-lab-root-ca.pem` exists
- WHEN `Get-ChildItem "C:\ProgramData\home-lab\pki"` is run
- THEN the file is NOT listed (invisible to PS cmdlet)
- WHEN `[System.IO.Directory]::GetFiles("C:\ProgramData\home-lab\pki")` is called
- THEN the file IS returned

---

### Requirement: Certificate validity check against current CA
The service MUST be able to determine if an existing certificate was signed
by the current Root CA, to avoid unnecessary certificate renewal.

#### Scenario: Certificate signed by current CA
- GIVEN a certificate PEM and the current Root CA
- WHEN `is_certificate_signed_by_current_root(cert_pem)` is called
- THEN `true` is returned if the issuer matches and signature verifies
- THEN `false` is returned if the CA was rotated since certificate issuance
