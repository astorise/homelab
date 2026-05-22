# DNS Service (home-dns)

## Purpose
Local authoritative DNS server for `.wsl` domains and custom records.
Runs as a Windows service, exposes gRPC over Named Pipe for management,
and supports DNS-over-HTTPS (DoH).

---

### Requirement: Local name resolution
The service MUST answer DNS queries for records managed by the homelab
on the Windows loopback interfaces (127.0.0.1 and ::1).

#### Scenario: A record query for a WSL cluster domain
- GIVEN a DNS record `tachyon-mesh.wsl A 127.0.0.1` exists
- WHEN a client queries `tachyon-mesh.wsl` type A
- THEN the service returns `127.0.0.1` with the configured TTL

#### Scenario: AAAA record for IPv6 loopback (k3s API access)
- GIVEN a DNS record `tachyon-mesh.wsl AAAA ::1` exists
- WHEN a client queries `tachyon-mesh.wsl` type AAAA
- THEN the service returns `::1`
- AND the k3s API on `:::PORT` becomes reachable via IPv6

---

### Requirement: Stable S3 loopback alias
The service MUST maintain an A record `s3.wsl → 10.255.255.254`
pointing to the stable WSL loopback alias (present on `lo` interface
as `inet 10.255.255.254/32`), independent of Hyper-V IP changes.

#### Scenario: S3 access from WSL pods
- GIVEN `s3.wsl A 10.255.255.254` is configured
- WHEN a pod inside k3s resolves `s3.wsl`
- THEN it gets `10.255.255.254`
- AND iptables DNAT in WSL redirects the connection to the Hyper-V gateway

---

### Requirement: Record management via gRPC
The service MUST expose add/remove/list operations for DNS records
via Named Pipe `\\.\pipe\home-dns` (release) or `\\.\pipe\home-dns-dev` (debug).

#### Scenario: Adding a new record
- GIVEN the Named Pipe is connected
- WHEN `AddRecord(name, rrtype, value, ttl)` is called
- THEN the record is persisted and served immediately
- AND subsequent queries for that name/type return the new value

---

### Requirement: DNS-over-HTTPS (DoH)
The service SHOULD support DoH for encrypted DNS resolution.
A Windows firewall rule is created automatically for the DoH port.

#### Scenario: DoH firewall rule idempotency
- GIVEN the DoH port rule `Home DNS DoH {port}` already exists
- WHEN the service starts
- THEN no duplicate rule is created
- AND the existing rule is left unchanged

---

### Requirement: IPv6 listener
The service MUST listen on `::1` (IPv6 loopback) in addition to `127.0.0.1`
so that applications connecting via IPv6 can resolve homelab domains.

#### Scenario: k3s kubeconfig endpoint resolution
- GIVEN kubeconfig `server: https://tachyon-mesh.wsl:3915`
- WHEN the Kubernetes client resolves `tachyon-mesh.wsl`
- THEN the AAAA record `::1` is returned
- AND the connection to `[::1]:3915` reaches the k3s API (IPv6-only socket)
