## MODIFIED Requirements

### Requirement: k3s-init.sh boot configuration
The WSL image MUST run `k3s-init.sh` as the wsl.conf `[boot] command`.
This script reads `/etc/k3s-env`, configures k3s, Traefik, and networking. The script
MUST branch on `NODE_COUNT`: with `NODE_COUNT=1` (or unset) it runs the legacy
single-node path unchanged; with `NODE_COUNT > 1` it provisions the private bridge and
per-node network namespaces before launching one server node and the agent nodes.

#### Scenario: Single-node instance boots with correct port plan
- GIVEN `/etc/k3s-env` contains `NODE_COUNT=1`, `K3S_API_PORT=3915`, `K3S_INGRESS_HTTPS_PORT=3919`
- WHEN WSL starts and k3s-init.sh runs
- THEN k3s API listens on `:::3915` (IPv6 all interfaces) in the host netns
- AND Traefik loopback binds `127.0.0.1:3919` via kubectl port-forward
- AND home-http routes `tachyon-mesh.wsl → 3919`
- AND no bridge or node namespaces are created

#### Scenario: Multi-node instance boots a server plus agents
- GIVEN `/etc/k3s-env` contains `NODE_COUNT=3`, `K3S_API_PORT=3915`, `K3S_INGRESS_HTTPS_PORT=3919`
- WHEN WSL starts and k3s-init.sh runs
- THEN a private bridge and three node namespaces are created
- AND node `k3s-node-0` runs `k3s server` and nodes `k3s-node-1`/`k3s-node-2` run `k3s agent`
- AND the API is republished so `tachyon-mesh.wsl:3915` still reaches the server
- AND Traefik loopback binds `127.0.0.1:3919` and home-http routes `tachyon-mesh.wsl → 3919` unchanged

## ADDED Requirements

### Requirement: Cluster decoupled from node via node_count (experimental)
A cluster MUST be a first-class object that owns the deterministic port plan, DNS
records, TLS certificate, HTTP routes, and kubeconfig context, and that contains one or
more nodes. The number of nodes MUST be controllable via a `node_count` parameter
(default `1`) threaded through provisioning and persisted to `/etc/k3s-env` as
`NODE_COUNT`. Multi-node (`node_count > 1`) is an experimental, opt-in capability.

#### Scenario: Provision a multi-node cluster
- GIVEN an operator calls `wsl_import_instance(name="tachyon-mesh", node_count=3)`
- WHEN provisioning completes
- THEN `/etc/k3s-env` contains `NODE_COUNT=3` plus the bridge variables (`CLUSTER_BRIDGE`, `CLUSTER_BRIDGE_CIDR`, `NODE_IP_BASE`)
- AND the cluster exposes a single API endpoint `https://tachyon-mesh.wsl:<api_backend_port>`
- AND a single kubeconfig context `home-lab-wsl-tachyon-mesh` is synced to Windows

#### Scenario: Cluster-level assets remain singular
- GIVEN a multi-node cluster `tachyon-mesh`
- WHEN it is provisioned
- THEN exactly one deterministic port plan, one default TLS secret, one set of `{name}.wsl` DNS records, and one home-http route exist for the whole cluster (not one per node)

### Requirement: Single-node backward compatibility
With `node_count == 1`, provisioning and boot MUST be functionally identical to the
pre-existing single-node behavior. The new topology variables MAY be written to
`/etc/k3s-env` but MUST be inert. Existing already-provisioned instances MUST continue to
work without re-provisioning.

#### Scenario: Existing single-node instance is unaffected
- GIVEN an instance provisioned before this change (implicitly `node_count == 1`)
- WHEN the homelab app reconciles or the instance reboots
- THEN the deterministic port plan, DNS, TLS, HTTP route, and kubeconfig are unchanged
- AND no bridge or node namespaces are created
- AND k3s runs in the host network namespace as before

#### Scenario: Reconciliation preserves node_count
- GIVEN `/etc/k3s-env` contains `NODE_COUNT=3`
- WHEN the homelab app rewrites `/etc/k3s-env` during reconciliation
- THEN `NODE_COUNT=3` is preserved, in the same way `ENABLE_NVIDIA_TOOLKIT` is preserved today

### Requirement: Node add/remove lifecycle (experimental)
The homelab app SHALL expose operations to add and remove nodes on an experimental
multi-node cluster, reflected in the MCP surface and the instance UI.

#### Scenario: Add a node
- GIVEN a running cluster `tachyon-mesh` with `NODE_COUNT=2`
- WHEN the operator invokes `wsl_add_node("tachyon-mesh")`
- THEN a new node namespace joins the cluster as an agent
- AND `NODE_COUNT` is updated to `3` in `/etc/k3s-env`
- AND `kubectl get nodes` eventually lists the new node as `Ready`

#### Scenario: Remove a node
- GIVEN a running cluster `tachyon-mesh` with three nodes
- WHEN the operator invokes `wsl_remove_node("tachyon-mesh", "tachyon-mesh-2")`
- THEN the node is drained and deleted from the cluster
- AND its network namespace and `veth` are torn down
- AND `NODE_COUNT` is decremented in `/etc/k3s-env`

#### Scenario: UI lists nodes with roles
- GIVEN a multi-node cluster
- WHEN the `<wsl-instance>` component renders
- THEN it shows each node with its name, role (server/agent), and Ready status
