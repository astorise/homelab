# WSL Cluster Management

## Purpose
Lifecycle management of WSL2 instances running k3s (Kubernetes). The homelab app
provisions, configures, and reconciles WSL instances as single-node k3s clusters.
Each instance gets deterministic port assignments, TLS certificates, DNS records,
and HTTP routes.

---

### Requirement: Deterministic port assignment
Each WSL instance MUST receive a unique, stable set of ports computed from
the instance name using a hash function. Ports MUST NOT collide between:
- k3s API port (`api_backend_port`)
- k3s API supervisor port (`api_backend_port + 1`)
- Traefik HTTPS ingress port (`ingress_https_backend_port`)
- Traefik HTTP ingress port (`ingress_http_backend_port = ingress_https - 1`)

#### Scenario: Port collision resolution
- GIVEN `deterministic_port_for_instance("tachyon-mesh", base=1001, step=2)` = 3915
- AND `deterministic_port_for_instance("tachyon-mesh", base=2001, step=2)` = 3915 (collision)
- WHEN `instance_port_plan("tachyon-mesh")` computes ports
- THEN `ingress_https_backend_port` is incremented by `step` (2) until ≠ 3915 and ≠ 3916
- AND the final value is 3919 (skipping 3917 because `ingress_http = ingress_https - 1 = 3916` would collide)

---

### Requirement: k3s-init.sh boot configuration
The WSL image MUST run `k3s-init.sh` as the wsl.conf `[boot] command`.
This script reads `/etc/k3s-env`, configures k3s, Traefik, and networking.

#### Scenario: Instance boots with correct port plan
- GIVEN `/etc/k3s-env` contains `K3S_API_PORT=3915`, `K3S_INGRESS_HTTPS_PORT=3919`
- WHEN WSL starts and k3s-init.sh runs
- THEN k3s API listens on `:::3915` (IPv6 all interfaces)
- AND Traefik loopback binds `127.0.0.1:3919` via kubectl port-forward
- AND home-http routes `tachyon-mesh.wsl → 3919`

---

### Requirement: Default TLS certificate for Traefik
The homelab app MUST provision a TLS certificate signed by the Home Lab Root CA
and install it as the Traefik default certificate in the `kube-system` namespace.

#### Scenario: TLS secret creation
- GIVEN the Home Lab Root CA exists at `C:\ProgramData\home-lab\pki\home-lab-root-ca.pem`
- WHEN `build_home_lab_default_tls_assets(instance)` is called
- THEN a server certificate for the cluster domain (e.g. `tachyon-mesh.wsl`, `*.tachyon-mesh.wsl`) is issued
- AND a `kubernetes.io/tls` secret `home-lab-default-tls` is applied in `kube-system`
- AND a Traefik `TLSStore/default` referencing that secret is applied

#### Scenario: Existing valid certificate is reused
- GIVEN `home-lab-default-tls` exists and is signed by the current Root CA
- WHEN `configure_cluster_tls` runs
- THEN the secret is not recreated
- AND Traefik continues using the existing certificate

---

### Requirement: DNS and HTTP route provisioning
On cluster provisioning, the homelab app MUST create DNS A records and HTTP
SNI routes for all cluster domains, and update the S3 routing.

#### Scenario: configure_cluster_networking for new instance
- GIVEN instance `tachyon-mesh` with domain template `{name}.wsl`
- WHEN `configure_cluster_networking("tachyon-mesh")` runs
- THEN DNS `tachyon-mesh.wsl A 127.0.0.1` is added
- AND DNS `tachyon-mesh.wsl AAAA ::1` is added (for IPv6 k3s API)
- AND HTTP route `tachyon-mesh.wsl → ingress_https_backend_port` is added
- AND `sync_home_s3_wsl_binding()` runs (portproxy + s3.wsl DNS)

---

### Requirement: Kubeconfig synchronisation
The homelab app MUST synchronise the k3s kubeconfig into the Windows
`~/.kube/config` with context name `home-lab-wsl-{instance}`.
The server endpoint MUST use the cluster domain (e.g. `https://tachyon-mesh.wsl:3915`)
to leverage DNS resolution.

#### Scenario: IPv6-only k3s API reachable after sync
- GIVEN k3s API listens on `:::3915` (IPv6 only)
- AND DNS `tachyon-mesh.wsl AAAA ::1` resolves to IPv6 loopback
- WHEN kubeconfig `server: https://tachyon-mesh.wsl:3915` is used
- THEN kubectl connects to `[::1]:3915` and reaches k3s

---

### Requirement: k3s supervisor port adjacency
k3s allocates an adjacent supervisor port at `api_backend_port + 1`.
Port assignments MUST reserve both `api_backend_port` and `api_backend_port + 1`
to avoid conflicts with Traefik loopback or other services.
