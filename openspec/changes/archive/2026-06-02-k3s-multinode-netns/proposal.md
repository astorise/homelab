## Why

Today the homelab models **one WSL instance = one single-node k3s cluster** (cluster ≡ instance ≡ node, 1:1:1). This blocks the primary user goal: **testing Kubernetes scheduling** (taints/tolerations, affinities, `nodeSelector`, topology spread, DaemonSets, `drain`/`cordon`, rolling updates) on nodes that *really run pods* with working cross-node pod networking.

The naive ways to get multi-node under WSL all fail for one root cause: **all WSL2 distros share a single network namespace and a single IP** (the WSL VM). Putting several k3s nodes in that shared netns collides on flannel's per-node interfaces (`cni0`, `flannel.1`) and pod-CIDR routing, and the nodes would share one IP (VXLAN endpoint ambiguity). Hyper-V VLANs operate at the VM boundary (one VM for all distros, so no help). The existing `home-dns`/`home-http` hostname→port routing solves north-south (Windows→cluster) but cannot route the east-west **data plane** (pod↔pod is raw L3/L4 by IP, no hostname). Mirrored Windows interfaces give distinct IPs but still land in the single shared netns.

The irreducible primitive is a **network namespace per node**: it gives each node its own interface namespace (`cni0`/`flannel.1`/`veth`), not just a distinct IP. This can be done in pure shell (`ip netns` + a private bridge) with **no Docker and no k3d**, staying inside the project's existing "shell script launches k3s" architecture.

## What Changes

- **Multi-node clusters in a single WSL instance.** A cluster keeps **one** WSL instance; inside it, each node runs in its own Linux network namespace, attached via a `veth` pair to a private Linux bridge (`k3s-br0`, `10.50.0.0/24`). Each node gets a distinct bridge IP, its own `--data-dir`, and its own `--node-name`.
- **Server/agent topology in-instance.** One `k3s server` netns + N `k3s agent` netns. The agent join token (`/var/lib/rancher/k3s/server/node-token`) is read by the launch script and passed to agents via `K3S_URL=https://<server-bridge-ip>:6443`. This builds on the existing `WSL_ROLE=server|agent` + `K3S_URL` branch already present in `k3s-init.sh`.
- **flannel `host-gw` backend** for the multi-node case: all nodes share the private bridge L2, so plain kernel routes replace VXLAN (lighter, no overlay).
- **Cluster API & Traefik republish.** Because the server now lives in a netns, the cluster API and Traefik loopback are republished from the server netns to the WSL "host" netns (DNAT on the bridge IP) so Windows keeps reaching `{name}.wsl:port` unchanged — analogous to the existing S3 iptables DNAT.
- **Data-model evolution.** Introduce a first-class **Cluster** that owns the port plan / DNS / TLS / routes / kubeconfig (all already per-instance) and contains `nodes: Vec<Node{role, name, netns, node_ip}>`. A new `node_count` parameter (default `1`) decouples node count from the instance.
- **Provisioning & MCP/UI surface.** `wsl_import_instance` gains a `node_count`; new MCP tools to add/remove nodes; the `<wsl-instance>` UI lists nodes with role and status.
- **EXPERIMENTAL / opt-in.** `node_count == 1` keeps the **exact current single-node path** (no netns, no bridge) for 100% backward compatibility. Multi-node (`node_count > 1`) is gated as experimental.

This proposal is **design + spec deltas + tasks only — no source code is modified.**

## Capabilities

### New Capabilities
- `cluster-node-networking`: per-node Linux network namespace + private bridge (`k3s-br0`) data plane; distinct node IPs; flannel `host-gw`; server-netns→host-netns republish of the cluster API and Traefik; S3 DNAT reachable from all nodes' pods.

### Modified Capabilities
- `wsl-clusters`: a cluster is decoupled from a single node — adds `node_count`, a Cluster→Nodes model, multi-node provisioning/reconciliation, and node add/remove lifecycle, while preserving the existing single-node behavior and the cluster-level deterministic port plan, TLS, DNS, and kubeconfig sync.

## Impact

- **Affects:** WSL **and** the Tauri app (Windows-side orchestration). No change to the Windows *services'* on-the-wire behavior.
- **Named Pipe services impacted:** none at the protocol level. `home-dns` and `home-http` are consumed exactly as today for north-south exposure; east-west control plane goes directly over the private bridge (not through `home-http`). Optional per-node DNS names / control-plane proxying are explicitly **out of scope** here (future).
- **WSL assets:** `home-lab/src-tauri/resources/wsl/k3s-init.sh` (netns/bridge orchestration, server/agent launch, republish, S3 DNAT across nodes), `home-lab/src-tauri/resources/wsl/setup-wsl.ps1` (`/etc/k3s-env` gains node-topology vars).
- **Tauri app:** `home-lab/src-tauri/src/wsl.rs` (Cluster/Node model, `instance_port_plan` stays cluster-level, multi-node provisioning + reconciliation, kubeconfig sync unchanged — one endpoint per cluster), `home-lab/src-tauri/src/bin/home-lab-mcp.rs` (`node_count`, add/remove node tools), `home-lab/src/components/wsl-instance.js` (node list UI).
- **Spec:** `openspec/specs/wsl-clusters.md` updated; new `cluster-node-networking` spec added.
- **iptables (WSL):** new rules to DNAT the cluster API + Traefik from the host netns to the server node's bridge IP; existing S3 DNAT must keep working from every node's pod network.

## Security considerations

- The private bridge `10.50.0.0/24` is **internal to the WSL VM** — not exposed to LAN/WAN, consistent with the existing Hyper-V `vEthernet(WSL)` private-interface posture.
- No new `0.0.0.0` bindings. The cluster API stays reachable from Windows only via the existing `{name}.wsl:port` path; republish DNAT targets a private bridge IP, not a public interface.
- `home-s3` continues to bind loopback only; pod→S3 traffic keeps flowing through the existing DNAT→Hyper-V gateway→portproxy chain, now validated from multiple node namespaces.
- The k3s join token never leaves the WSL instance (read locally from the server netns, passed to agent netns on the same VM).
- Multi-node is **opt-in and experimental**; the default `node_count == 1` path is byte-for-byte the current, audited single-node behavior.
