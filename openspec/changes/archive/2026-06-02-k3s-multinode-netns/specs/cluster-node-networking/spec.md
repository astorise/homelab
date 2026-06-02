## ADDED Requirements

### Requirement: Per-node network namespace on a private bridge
For a multi-node cluster (`node_count > 1`), each k3s node MUST run in its own Linux
network namespace, attached via a dedicated `veth` pair to a single private bridge in
the WSL host network namespace. This gives every node its own interface namespace
(`cni0`, `flannel.1`, pod `veth`s) and a distinct node IP, which is required because all
WSL2 distros otherwise share a single network namespace and IP.

#### Scenario: Bridge and agent namespaces created at boot
- GIVEN `/etc/k3s-env` contains `NODE_COUNT=3`, `CLUSTER_BRIDGE=k3s-br0`, `CLUSTER_BRIDGE_CIDR=10.50.0.0/24`, `CLUSTER_BRIDGE_GW=10.50.0.1`, `NODE_IP_BASE=10.50.0.10`
- WHEN `k3s-init.sh` runs
- THEN a bridge `k3s-br0` exists in the host netns with address `10.50.0.1/24`
- AND the server (node 0) runs in the host netns advertising `10.50.0.1`
- AND agent namespaces `k3s-node-1` and `k3s-node-2` exist with interface IPs `10.50.0.11` and `10.50.0.12`
- AND each agent namespace has a default route `via 10.50.0.1`

#### Scenario: No node namespaces for single-node clusters
- GIVEN `/etc/k3s-env` contains `NODE_COUNT=1`
- WHEN `k3s-init.sh` runs
- THEN no bridge `k3s-br0` and no `k3s-node-*` namespaces are created
- AND k3s runs in the host network namespace exactly as in the legacy single-node path

#### Scenario: Idempotent re-creation after restart
- GIVEN a previous boot left `k3s-node-*` namespaces or `veth` interfaces
- WHEN `k3s-init.sh` runs again
- THEN stale namespaces, `veth` pairs, and bridge state are torn down before recreation
- AND the resulting topology matches the `NODE_COUNT` in `/etc/k3s-env`

### Requirement: Distinct node identity per namespace
Each node MUST be launched with a unique `--node-name`, a unique `--data-dir`, and a
unique node IP so the nodes register as distinct Kubernetes nodes.

#### Scenario: Nodes register distinctly
- GIVEN a cluster `tachyon-mesh` with `NODE_COUNT=3`
- WHEN all nodes have started
- THEN `kubectl get nodes` lists `tachyon-mesh-0`, `tachyon-mesh-1`, `tachyon-mesh-2`
- AND node `tachyon-mesh-0` has the control-plane role
- AND the server uses the default data-dir while each agent uses `/var/lib/rancher/k3s-node-<i>` with no overlap

### Requirement: Server / agent join over the private bridge
The server (node 0) MUST run in the host network namespace and advertise the bridge
gateway IP; the remaining nodes MUST run `k3s agent` in their own namespaces, joining the
server over the private bridge using the server's node token. The join token MUST NOT
leave the WSL instance.

#### Scenario: Agents join the server
- GIVEN the server runs in the host netns, reachable on the bridge at `https://10.50.0.1:<api_backend_port>`
- WHEN agent nodes start with `K3S_URL=https://10.50.0.1:<api_backend_port>` and the token read from `/var/lib/rancher/k3s/server/node-token`
- THEN each agent node reaches `Ready` status
- AND the token is read locally and never transmitted outside the WSL VM

### Requirement: flannel host-gw backend for multi-node
Multi-node clusters MUST use the flannel `host-gw` backend (plain kernel routes) instead
of VXLAN, because all node namespaces share the private bridge L2 segment. flannel MUST
be bound to each node's bridge interface.

#### Scenario: Cross-node pod connectivity via host-gw
- GIVEN a multi-node cluster using `--flannel-backend=host-gw`
- WHEN a pod on `tachyon-mesh-1` connects to a pod on `tachyon-mesh-2`
- THEN traffic is routed via kernel routes `10.42.<i>.0/24 via 10.50.0.<10+i>` over `k3s-br0`
- AND no VXLAN (`flannel.1`) encapsulation is required between nodes

### Requirement: Cluster API reachable from Windows without a forwarder
The cluster API MUST remain reachable from Windows at the existing
`https://{name}.wsl:<api_backend_port>` endpoint. Because the server runs in the host
network namespace, its API listens on host loopback directly, so NO republish forwarder
is required.

#### Scenario: Windows reaches the API
- GIVEN the server runs in the host netns and binds `<api_backend_port>` on host interfaces
- WHEN Windows `kubectl` uses `server: https://tachyon-mesh.wsl:<api_backend_port>`
- THEN the request reaches the k3s server on host loopback exactly as in single-node mode
- AND the server certificate validates (its SAN list includes the bridge gateway `10.50.0.1` and the cluster domains)

#### Scenario: Traefik loopback unaffected
- GIVEN the Traefik pod may be scheduled on any node
- WHEN the existing `kubectl port-forward service/traefik` loopback wrapper runs in the host netns
- THEN ingress on `127.0.0.1:<ingress_https_backend_port>` continues to work unchanged

### Requirement: S3 routing works from every node namespace
Pod traffic to `home-s3` (`s3.wsl → 10.255.255.254:9000`) MUST succeed from pods on any
node, not only the server node.

#### Scenario: Pod on a non-server node reaches home-s3
- GIVEN the host-netns S3 DNAT redirects `10.255.255.254:9000` to the Hyper-V gateway
- AND each node namespace routes `10.255.255.254` via the bridge gateway `10.50.0.1`
- AND the host netns MASQUERADEs pod-sourced traffic (`10.42.0.0/16`)
- WHEN a pod scheduled on `tachyon-mesh-2` requests `http://10.255.255.254:9000/minio/health/live`
- THEN the request reaches `home-s3` and a response returns to the pod
