# HTTP Proxy Service (home-http)

## Purpose
TLS SNI pass-through reverse proxy and TCP layer-4 router. Routes HTTPS
traffic to WSL backends (Traefik) and the k3s API, based on SNI hostname.
Runs as a Windows service; listens on port 443 (HTTPS) and port 80 (HTTP→HTTPS redirect).

---

### Requirement: TLS SNI pass-through for HTTPS routes
The service MUST forward raw TLS streams to WSL backends based on the
SNI hostname extracted from the TLS ClientHello, without terminating TLS.
The backend (Traefik) is responsible for TLS termination.

#### Scenario: HTTPS request to a WSL cluster service
- GIVEN route `tachyon-mesh.wsl → port 3919` is configured
- AND Traefik loopback binds `127.0.0.1:3919` in WSL
- WHEN a client connects to `https://tachyon-mesh.wsl`
- THEN DNS resolves to `127.0.0.1`, hitting home-http on port 443
- AND home-http extracts SNI `tachyon-mesh.wsl`, connects to WSL:3919
- AND the raw TLS bytes are piped bidirectionally (Traefik handles TLS)

#### Scenario: Backend must speak TLS
- GIVEN route `example.wsl → port N` is configured
- WHEN port N serves plain HTTP (not TLS)
- THEN the TLS handshake fails with an SSL protocol error at the client
- BECAUSE SNI pass-through requires the backend to respond with a TLS ServerHello

---

### Requirement: HTTP redirects to HTTPS
The service MUST redirect HTTP requests (port 80) to HTTPS with 301.
The redirect includes the `https://` scheme and preserves path and query.

#### Scenario: HTTP request redirected
- GIVEN a client sends `GET http://tachyon-mesh.wsl/api`
- WHEN the request arrives on port 80
- THEN the service responds 301 with `Location: https://tachyon-mesh.wsl/api`

---

### Requirement: TCP SNI routing for k3s API
The service MUST support TCP-level SNI routing for the Kubernetes API endpoint,
forwarding connections to the WSL instance's k3s port via the Hyper-V interface.

#### Scenario: kubectl connects to k3s API
- GIVEN TCP route `kube-api` listening on public port 6443, target port 3915 in WSL
- WHEN kubectl connects to `tachyon-mesh.wsl:6443`
- THEN home-http forwards the TCP stream to WSL IP:3915

---

### Requirement: Dynamic WSL IP synchronisation
The service MUST update its upstream WSL target IP whenever the Hyper-V
virtual switch reassigns addresses. The IP is stored as `wsl_ip` in
`C:\ProgramData\home-http\http.yaml` and reloaded via gRPC without restart.

#### Scenario: WSL IP changes after reboot
- GIVEN the previous WSL IP was `172.18.194.89`
- WHEN the homelab app detects a new WSL IP `172.18.197.12`
- THEN `update_home_http_wsl_ip_config()` writes the new IP to http.yaml
- AND `reload_config` RPC is called
- AND subsequent SNI connections use the new WSL IP

---

### Requirement: Ingress port conflict avoidance
The service MUST NOT route HTTPS traffic to the k3s API port.
The Traefik HTTPS loopback port MUST differ from `api_backend_port`.

#### Scenario: Port collision detection for new WSL instance
- GIVEN `deterministic_port_for_instance()` returns the same value for
  both `api_backend_port` and `ingress_https_backend_port`
- WHEN `instance_port_plan()` is called
- THEN `ingress_https_backend_port` is incremented by `http_port_step`
  until it no longer equals `api_backend_port` or `api_backend_port + 1`
