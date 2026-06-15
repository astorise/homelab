## Context

Today the homelab models **cluster ≡ WSL instance ≡ node (1:1:1)**. `instance_port_plan()` in `home-lab/src-tauri/src/wsl.rs` computes a deterministic, collision-free per-instance port plan; `k3s-init.sh` launches a single `k3s server`; `home-dns`/`home-http` expose the cluster north-south as `{name}.wsl:port`.

The hard constraint (confirmed empirically — two WSL2 distros report the same `eth0` inet address): **all WSL2 distros run in one shared utility VM with one shared network namespace and one IP.** Standard multi-node k3s requires each node to own a distinct IP *and* its own CNI interface namespace (`cni0`, `flannel.1`, pod `veth`s). In a shared netns those interfaces collide by name and pod-CIDR routing is ambiguous, regardless of how many IPs are available.

The only primitive that yields a per-node *interface namespace* inside one VM is a **Linux network namespace per node**. It is achievable in pure shell (`ip netns` + a private bridge), with no Docker and no k3d, reusing the `WSL_ROLE=server|agent` + `K3S_URL` branch already present in `k3s-init.sh`.

The driving use case is **scheduling tests** (taints/tolerations, affinities, `nodeSelector`, topology spread, DaemonSets, `drain`/`cordon`, rolling updates) on nodes that *really run pods* with working cross-node pod networking.

## Goals / Non-Goals

**Goals:**
- Run an N-node k3s cluster (1 server + N−1 agents) inside **one** WSL instance, each node in its own netns on a shared private bridge, with a distinct node IP and working east-west pod networking.
- Preserve the existing north-south exposure (`{name}.wsl:port` via `home-dns`/`home-http`, Traefik loopback, default TLS cert) **unchanged** from the operator's point of view.
- Keep `node_count == 1` byte-for-byte identical to today's single-node path (no netns, no bridge) for 100% backward compatibility with already-provisioned instances.
- Keep S3 pod→`home-s3` routing working from every node's pod network.
- Stay within the project's shell-orchestration model; no new external runtime dependency (no Docker/k3d).

**Non-Goals:**
- Per-node LAN/VLAN exposure or per-node DNS names (documented as a future variant, see Decisions §6).
- Routing the east-west **data plane** through `home-http` (architecturally impossible — pod↔pod is raw L3/L4 by IP).
- HA control plane (multiple servers + embedded etcd). Single server only in this change; multi-server is a follow-up.
- True hardware/kernel isolation per node (would require real Hyper-V VMs — explicitly rejected, see Decisions §6).
- Changing any Windows service gRPC/proto interface.

## Decisions

### 1. One WSL instance per *cluster*; one netns per *node* on a private bridge
Each node runs in netns `k3s-node-<i>` (i=0 is the server). A Linux bridge `k3s-br0` lives in the WSL host netns at `10.50.0.1/24`; each node gets a `veth` pair (`v<i>h` in host netns enslaved to the bridge, `v<i>n` moved into the node netns) addressed `10.50.0.<10+i>/24` with default route `via 10.50.0.1`.

```
WSL instance "tachyon-mesh"  (one VM)
  host netns          ── bridge k3s-br0 10.50.0.1/24 ── k3s SERVER (node-0)
                         --node-ip 10.50.0.1 --flannel-iface k3s-br0 --node-name tachyon-mesh-0
  ├─ netns k3s-node-1  v1n=10.50.0.11  → k3s agent  --data-dir /var/lib/rancher/k3s-node-1  --node-name tachyon-mesh-1
  └─ netns k3s-node-2  v2n=10.50.0.12  → k3s agent  --data-dir /var/lib/rancher/k3s-node-2  --node-name tachyon-mesh-2
```

The server runs in the **host netns** (so its API stays on host loopback for Windows — see §4). Each **agent** is launched with `ip netns exec k3s-node-<i> k3s agent …`, a distinct `--data-dir` and `--node-name`. The server token is read from `/var/lib/rancher/k3s/server/node-token` and passed to agents as `K3S_TOKEN` + `K3S_URL=https://10.50.0.1:<api_backend_port>` (the bridge gateway + the cluster API port).

**Alternatives considered:** Docker/k3d (per-node netns via containers — clean but adds a Docker dependency + image weight, contradicts the shell model, nested-container overhead); distro-per-node (all distros share the same netns → identical collision, no win); multiple k3s processes in the *shared* netns (the naive ask — fails on `cni0`/`flannel.1` collisions and shared IP). The netns-on-private-bridge approach is the minimal isolation (network only) that makes CNI work, while keeping one shared rootfs and the existing launch model.

### 2. flannel `host-gw` backend (no VXLAN)
All node netns sit on the same L2 bridge (`k3s-br0`), so flannel `host-gw` is sufficient: pod-CIDR routes (`10.42.<i>.0/24 via 10.50.0.<10+i>`) are plain kernel routes over the bridge. This avoids VXLAN encapsulation entirely.

- k3s flags (multi-node only): `--flannel-backend=host-gw` and `--flannel-iface=v<i>n` so flannel binds the node's bridge interface (not a stray host route).
- Single-node (`node_count == 1`) keeps k3s defaults untouched.

**Alternatives considered:** VXLAN backend (works on the shared bridge too, but pure overhead since there is no real L3 separation between nodes); a non-flannel CNI (more moving parts, no benefit here).

### 3. Port plan stays cluster-level; per-node ports become netns-local
The deterministic `instance_port_plan()` continues to govern **cluster-level** ports (north-south API `api_backend_port`, ingress, SSH, NodePort range) exactly as today. Because each node now has its own netns, the per-node component ports (kubelet 10250, lb-server, scheduler, controller-manager, cloud-controller-manager, containerd stream) **no longer need to be globally unique** — every node can use k3s defaults inside its own netns without colliding.

- This is a *simplification opportunity* but is **deferred**: `K3S_KUBELET_PORT` & friends remain honored for the single-node path to avoid regressions. For multi-node, nodes use netns-local defaults.
- The cluster API the operator targets stays `api_backend_port` (deterministic) on the Windows side; inside the server netns the API can stay on `6443` and be republished (see §4).

### 4. Keep the server in the host netns — no API forwarder needed (refined during implementation)
**Refinement vs. the original sketch:** rather than putting the server in `k3s-node-0` and republishing its API through a raw TCP forwarder (fragile: needs `socat`/loop or `route_localnet` DNAT for both IPv4 and IPv6 loopback), the **server runs in the host network namespace** — exactly like single-node today. Only the **agents** (nodes 1..N-1) get their own namespaces. This eliminates the most fragile piece entirely.

- **API:** the server binds `https-listen-port` on all host-netns interfaces as today, so Windows keeps reaching `https://{name}.wsl:<api_backend_port>` on host loopback **with zero new plumbing**. Agents join over the bridge at `https://<bridge-gw=10.50.0.1>:<api_backend_port>`.
- **node-0 identity:** the server uses `--node-ip=10.50.0.1` (the bridge gateway) and `--flannel-iface=k3s-br0`, so `host-gw` routes between node-0's pod CIDR and the agent namespaces over the shared bridge L2.
- **TLS SANs:** `ensure_server_config` appends `10.50.0.1` (bridge gateway) to the `tls-san` list when `NODE_COUNT>1`, so agent join validates against the server cert. Cluster domains remain in the SAN list as today.
- **Traefik:** the existing `kubectl port-forward service/traefik` loopback wrapper runs in the host netns and reaches the cluster through the host-loopback API, so it works regardless of which node hosts the Traefik pod — **completely unchanged**.
- **kubeconfig:** unchanged — one endpoint per cluster (`https://{name}.wsl:<api_backend_port>`), synced to Windows `~/.kube/config` as `home-lab-wsl-{instance}`.
- **Trade-off:** node-0 is not network-isolated from the WSL host system (its pod network lives in the host netns, as in single-node today). For scheduling tests this is irrelevant, and it buys a much simpler, more robust boot path.

### 5. S3 DNAT must reach `home-s3` from every node's pods
`ensure_s3_iptables_dnat()` currently installs PREROUTING/OUTPUT DNAT + POSTROUTING MASQUERADE in the host netns for `10.255.255.254:9000 → <hyperv-gw>:9000`. For multi-node:

- The **DNAT/MASQUERADE stays in the host netns** (it owns the default route to the Hyper-V gateway).
- Each node netns gets a default route `via 10.50.0.1` (already required for egress), so pod traffic to `10.255.255.254` transits into the host netns where the DNAT applies.
- The host-netns POSTROUTING MASQUERADE must cover the pod source CIDRs (`10.42.0.0/16`) and the bridge CIDR so return packets find their way back to the originating node netns.

iptables (host netns) summary — additions over today:
- `nat OUTPUT`/`nat PREROUTING` DNAT `127.0.0.1|::1:<api_backend_port> → 10.50.0.10:<api_backend_port>` *(or the TCP forwarder of §4, preferred)*
- `nat POSTROUTING -s 10.42.0.0/16 -j MASQUERADE` and `-s 10.50.0.0/24` as needed for S3 egress
- existing S3 DNAT rules unchanged

### 6. Data model: first-class Cluster owning Nodes
Introduce (Rust, `wsl.rs`) a Cluster that owns what is already per-instance (port plan, domains, TLS, routes, kubeconfig context) and a node list:

```rust
struct ClusterNode { role: NodeRole /* Server|Agent */, name: String, netns: String, node_ip: Ipv4Addr }
// WslClusterStatus gains: node_count: u32, nodes: Vec<ClusterNode>
```

- `node_count` (default `1`) is threaded through `wsl_import_instance`/provisioning and persisted in `/etc/k3s-env` as `NODE_COUNT`, plus `CLUSTER_BRIDGE=k3s-br0`, `CLUSTER_BRIDGE_CIDR=10.50.0.0/24`, `NODE_IP_BASE=10.50.0.10`.
- `node_count == 1` ⇒ the **legacy path** runs verbatim (no bridge, no netns), guaranteeing backward compatibility.
- MCP (`home-lab-mcp.rs`): `wsl_import_instance` gains optional `node_count`; add `wsl_add_node` / `wsl_remove_node`. UI (`wsl-instance.js`) renders the node list with role + Ready status from `kubectl get nodes`.

**Alternatives considered for the whole feature direction:**

| Approach | Per-node netns? | Distinct node IP? | Verdict |
|---|---|---|---|
| Ports-on-same-IP / `home-http` data-plane routing | ✗ | ✗ | Impossible for pod↔pod (raw L3/L4) |
| Hyper-V VLAN / vSwitch on the WSL VM | ✗ (VM-level) | ✗ inside VM | Isolates at VM boundary; one VM for all distros |
| **WSLAttachSwitch** (HCN/HCS attach `eth1..N` to the VM) | ✗ (VM-level) | adds VM NICs | Needs admin + pre-made vSwitch, **does not survive VM restart**, unsupported API. Useful only *on top of* netns as a future LAN/VLAN-per-node exposure variant (move an attached `ethN` into a node netns). Not a substitute for netns. |
| Real Hyper-V VMs per node | ✓ | ✓ | Genuine isolation + VLANs, but abandons the WSL socket, N kernels, heavy boot — overkill for scheduling tests |
| kwok virtual nodes | n/a | n/a | Great for *pure* scheduler-decision tests but pods are simulated (don't run) — doesn't meet "nodes that really run pods" |
| **netns-per-node + private bridge (chosen)** | ✓ | ✓ | Minimal isolation that makes CNI work; no Docker; reuses shell model |

## Risks / Trade-offs

- **[Shared kernel/cgroups across nodes]** Nodes share one kernel and sysctls; this is *simulated* multi-node, not hardware isolation. → Acceptable and even desirable for the scheduling use case; documented clearly as experimental.
- **[netns lifecycle leaks]** Crashes could leave dangling netns/veth/bridge. → `k3s-init.sh` must idempotently tear down and recreate (`ip netns del`, flush veths) on each boot before (re)creating, mirroring existing idempotent patterns (lock dir, S3 DNAT delete-then-add).
- **[API forwarder is a new failure point]** If the host-netns forwarder dies, Windows loses API access. → Use the existing supervised wrapper pattern (restart loop) already used for the Traefik loopback forwarder.
- **[S3/MASQUERADE correctness across netns]** Mis-scoped MASQUERADE could break pod→S3 or return paths. → Explicit test: `wget http://10.255.255.254:9000/...` from a pod scheduled on a non-server node.
- **[Backward-compat regressions]** Refactor to a Cluster/Node model could perturb the single-node path. → Gate every multi-node branch on `node_count > 1`; add a regression check that a `node_count == 1` instance produces an identical `/etc/k3s-env` (minus the new always-present-but-inert keys) and identical port plan.
- **[Resource pressure]** N nodes × (kubelet + containerd) in one VM. → Document recommended WSL `.wslconfig` memory/CPU and a sane default cap on `node_count` (e.g. 5) in the UI.
- **[Token/data-dir confinement]** Per-node `--data-dir` must not overlap. → Deterministic `/var/lib/rancher/k3s/node-<i>` layout; token read only from node-0.

## Migration Plan

- **Forward:** ship behind an experimental flag; existing instances stay single-node (`node_count` defaults to 1, legacy path). New `/etc/k3s-env` keys are written but inert when `NODE_COUNT=1`. Creating a multi-node cluster is a fresh `wsl_import_instance(node_count=N)` or an `wsl_add_node` on an experimental instance.
- **Rollback:** set `node_count` back to 1 (or remove added nodes) → on next boot `k3s-init.sh` tears down the bridge/netns and reverts to the legacy single-node launch; no change to DNS/HTTP/TLS/kubeconfig (all cluster-level). Worst case, remove and re-import the instance.
- **Reconciliation:** the existing reconcile path rewrites `/etc/k3s-env`; it must preserve `NODE_COUNT` like it already preserves `ENABLE_NVIDIA_TOOLKIT`.

## Open Questions

- Should `node_count` changes on a *running* instance be supported online (add/remove node without full restart), or require a WSL restart? (Lean: online add via `ip netns` + `k3s agent`; online remove via `kubectl delete node` + netns teardown.)
- Server API inside netns: keep `6443` netns-local, or keep the deterministic `api_backend_port` inside the netns too? (Lean: `6443` netns-local + forwarder on the deterministic port, simplest.)
- Default `node_count` cap exposed in the UI, and recommended `.wslconfig` sizing per node — pick concrete numbers during implementation.
- Pod CIDR sizing: k3s default `10.42.0.0/16` gives /24 per node — confirm it does not overlap the bridge `10.50.0.0/24` or the S3 loopback `10.255.255.254` (it does not).
