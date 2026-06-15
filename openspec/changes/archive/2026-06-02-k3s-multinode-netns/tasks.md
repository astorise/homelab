## 1. Spike — validate the networking model manually (de-risk before code)

- [ ] 1.1 [WSL] In a throwaway WSL instance, hand-create `k3s-br0` (`10.50.0.1/24`), two netns (`k3s-node-0/1`) with `veth` pairs and IPs `10.50.0.10/11`; confirm bidirectional ping across namespaces over the bridge.
- [ ] 1.2 [WSL] Run `k3s server` in `k3s-node-0` (`--flannel-backend=host-gw --flannel-iface=v0n --node-name n0 --data-dir /var/lib/rancher/k3s/node-0`) and `k3s agent` in `k3s-node-1` (`K3S_URL=https://10.50.0.10:6443`, token from node-0); confirm both nodes reach `Ready`.
- [ ] 1.3 [WSL] Deploy a 2-replica Deployment with anti-affinity; confirm pods land on different nodes AND cross-node pod-to-pod curl works (validates host-gw). Capture the exact `ip`/`k3s` command sequence into a scratch script for reuse in §2.
- [ ] 1.4 [WSL] From a pod on `k3s-node-1`, `wget http://10.255.255.254:9000/minio/health/live`; note which iptables/route additions are needed in the host netns to make it succeed (input to §4).

## 2. WSL boot orchestration — k3s-init.sh multi-node path

- [x] 2.1 [WSL] Add `NODE_COUNT`, `CLUSTER_BRIDGE`, `CLUSTER_BRIDGE_CIDR`, `CLUSTER_BRIDGE_GW`, `NODE_IP_BASE`, `NODE_NAME_PREFIX` + derived vars to the env block of `k3s-init.sh` with safe defaults (`NODE_COUNT=1`).
- [x] 2.2 [WSL] Add idempotent `teardown_node_namespaces()` (`ip netns del` `k3s-node-*`, delete `v*h` veths) run before (re)creation; bridge is kept idempotently by `ensure_cluster_bridge`.
- [x] 2.3 [WSL] Add `ensure_cluster_bridge()`, `ensure_host_netns_forwarding()` (ip_forward + MASQUERADE + FORWARD ACCEPT) and `ensure_node_namespace(i)` (veth pair, move peer into netns, assign IP, default route via gw).
- [x] 2.4 [WSL] Add `run_k3s_agent_node(i)` + `run_k3s_agent_supervised(i)` (own netns, data-dir, node-name, `--flannel-iface`) reusing the supervised-restart pattern; multi-node server flannel flags (`host-gw`, `--node-ip`, `--flannel-iface`, `--node-name-0`) added inside `run_k3s_server`.
- [x] 2.5 [WSL] Branch the main `ROLE=server` block on `NODE_COUNT`: `==1` → single-node path verbatim; `>1` → `start_multi_node_cluster` (bridge + supervised server in host netns + token wait + per-agent namespaces; token from `/var/lib/rancher/k3s/server/node-token`).
- [ ] 2.6 [WSL] Manually set `NODE_COUNT=3` in `/etc/k3s-env`, reboot the instance, confirm `kubectl get nodes` shows 3 Ready nodes and that `NODE_COUNT=1` still boots the legacy path unchanged. *(live)*

## 3. API reachability + TLS — keep `{name}.wsl:port` working

> **Design refinement applied:** the server runs in the **host netns** (not a node netns), so its API listens on host loopback exactly like single-node — **no republish forwarder is needed**. Agents join over the bridge at `https://<bridge-gw>:<api_backend_port>`.

- [x] 3.1 [WSL] Keep the server in the host network namespace; agents target `https://$CLUSTER_BRIDGE_GW:$API_PORT`. (Forwarder eliminated; API stays on host loopback as today.)
- [x] 3.2 [WSL] Add the bridge gateway IP (`$CLUSTER_BRIDGE_GW`) to the server cert SANs (`ensure_server_config` appends it to `tls-san` when `NODE_COUNT>1`) so agent join validates.
- [ ] 3.3 [WSL] Confirm the existing Traefik loopback port-forward still binds and serves ingress when the Traefik pod is scheduled on a non-server node. *(live)*

## 4. S3 routing across namespaces

- [x] 4.1 [WSL] Each node netns gets a default route via the bridge gw (`ensure_node_namespace`); the host netns MASQUERADEs the bridge CIDR + pod CIDR `10.42.0.0/16` and ACCEPTs FORWARD on the bridge (`ensure_host_netns_forwarding`); existing S3 DNAT unchanged.
- [ ] 4.2 [WSL] Verify `wget http://10.255.255.254:9000/minio/health/live` succeeds from a pod on a non-server node (expected HTTP 403 = routing OK). *(live)*

## 5. Tauri app — Cluster/Node data model

- [ ] 5.1 [Tauri app] Add `NodeRole` enum and `ClusterNode { role, name, netns, node_ip }`; extend `WslClusterStatus` with `node_count` and `nodes: Vec<ClusterNode>` in `home-lab/src-tauri/src/wsl.rs`. *(deferred — next increment)*
- [x] 5.2 [Tauri app] `NODE_COUNT` + bridge vars are written at provisioning by `setup-wsl.ps1` (§7); `render_k3s_env_file_for_instance()` keeps emitting the deterministic cluster-level vars unchanged, so a `node_count==1` env file is byte-identical to today (chosen over emitting `NODE_COUNT` from render, to avoid reconcile clobber).
- [x] 5.3 [Tauri app] `render_k3s_env_rewrite_script()` now preserves `NODE_COUNT` + bridge vars (`CLUSTER_BRIDGE*`, `NODE_IP_BASE`, `NODE_NAME_PREFIX`) the same way `ENABLE_NVIDIA_TOOLKIT` is preserved.
- [ ] 5.4 [Tauri app] In `attach_cluster_details()`, populate `nodes` from `kubectl get nodes -o json` (role from control-plane label, Ready from conditions). *(deferred — next increment)*

## 6. Tauri app — provisioning & reconciliation

- [x] 6.1 [Tauri app] Threaded `node_count: Option<u32>` through `wsl_import_instance` (tauri cmd) + `wsl_import_instance_headless` (MCP) → `wsl_import_instance_with_paths` (clamp 1..5) → `run_wsl_setup_with_paths`; default 1.
- [x] 6.2 [Tauri app] `run_wsl_setup_with_paths` passes `-NodeCount` only when `>1` (single-node command stays byte-identical); `instance_port_plan` is computed from the instance name only, so the port plan is unchanged regardless of `node_count`.
- [ ] 6.3 [Tauri app] Add a regression assertion: a `node_count == 1` provision yields the same port plan, DNS, TLS, HTTP route, and kubeconfig context as before this change. *(deferred — needs a unit test)*

## 7. setup-wsl.ps1 — provisioning vars

- [x] 7.1 [WSL] Added `-NodeCount` parameter to `setup-wsl.ps1`; `Configure-K3sEnv` writes `NODE_COUNT` + bridge vars (`CLUSTER_BRIDGE`, `CLUSTER_BRIDGE_CIDR`, `CLUSTER_BRIDGE_GW`, `NODE_IP_BASE`, `NODE_NAME_PREFIX=$Distro`) into the same UTF-8 no-BOM here-string.
- [x] 7.2 [WSL] `Configure-K3sEnv` clamps `NodeCount` to `1..5` and defaults to 1 when omitted.

## 8. MCP tools & UI

- [x] 8.1 [Tauri app] Extended `wsl_import_instance` MCP tool (`home-lab-mcp.rs`) with an optional experimental `node_count` field (capped, documented).
- [ ] 8.2 [Tauri app] Add `wsl_add_node` / `wsl_remove_node` MCP tools (online add via `ip netns` + `k3s agent`; remove via drain + `kubectl delete node` + netns teardown; update `NODE_COUNT`). *(deferred — complex online ops; design open question)*
- [ ] 8.3 [Tauri app] Update `<wsl-instance>` to render the node list (name, role, Ready) and a node-count control gated behind an experimental toggle. *(deferred — next increment)*

## 9. Build, test & verification

- [ ] 9.1 [Tauri app] `cargo test -p home-lab` (port-plan + env-render regression tests) pass. *(deferred — pending 6.3 tests)*
- [x] 9.2 [Tauri app] `cargo check -p home-lab` passes (lib + `home-lab-mcp` bin); only a pre-existing unrelated dead-code warning.
- [ ] 9.3 [WSL] End-to-end scheduling check: taint one node `NoSchedule`, deploy a Deployment + a DaemonSet, confirm the scheduler honors the taint and the DaemonSet fans out to all eligible nodes.
- [ ] 9.4 [WSL] `drain`/`cordon` a node and confirm pods reschedule onto remaining nodes.
- [ ] 9.5 [Tauri app] Backward-compat smoke test: provision a fresh `node_count=1` instance and an existing instance reboot — both behave exactly as before.

## 10. Documentation & experimental gating

- [x] 10.1 Documented the feature (experimental/opt-in) in `home-lab/src-tauri/resources/wsl/README.md`: server-in-host-netns + agents-in-netns, `k3s-br0` `10.50.0.0/24`, `NODE_COUNT`, why-netns, and `.wslconfig` sizing note. *(UI experimental marker lands with §8.3.)*
- [x] 10.2 Recorded the WSLAttachSwitch "LAN/VLAN-per-node exposure" path as a documented future variant in the README, with caveats (admin, pre-made vSwitch, does not survive VM restart) and a pointer to the `node-lan-vlan-hcs-hcn` proposal.
