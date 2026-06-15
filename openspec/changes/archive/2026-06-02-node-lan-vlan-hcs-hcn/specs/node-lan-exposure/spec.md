## ADDED Requirements

### Requirement: Privileged host for HCS/HCN operations
All HCS/HCN attach/detach operations MUST run in a LocalSystem Windows service and MUST NOT be hosted in `home-http`. The non-elevated Tauri UI MUST request these operations over the existing Named Pipe gRPC pattern rather than calling the APIs directly.

#### Scenario: UI requests attach without elevation prompt
- GIVEN the privileged service runs as LocalSystem
- WHEN the non-elevated UI requests LAN exposure for a cluster over the Named Pipe
- THEN the service performs the HCS/HCN operation
- AND no per-action UAC elevation prompt is shown to the user

#### Scenario: home-http is never the host
- WHEN the codebase is inspected
- THEN no HCS/HCN attach logic exists in `home-http`
- AND `home-http`'s TLS/SNI routing behavior is unchanged

### Requirement: Attach and detach Hyper-V vSwitch NICs from Rust
The service MUST attach and detach Hyper-V vSwitch network adapters to the WSL2 utility VM at runtime via the HCS and HCN APIs (FFI through the `windows` crate), without shelling out to an external `WSLAttachSwitch` binary.

#### Scenario: Attach an additional NIC
- GIVEN a Hyper-V vSwitch referenced by GUID and a running WSL VM
- WHEN the service attaches a NIC for node index 1
- THEN a new interface appears inside the WSL VM (e.g. `eth1`)
- AND the operation uses `HcsModifyComputeSystem` with an HCN endpoint, not an external executable

#### Scenario: Detach is symmetric and idempotent
- GIVEN a previously attached NIC for a node
- WHEN the service detaches it (or re-runs detach)
- THEN the interface is removed from the WSL VM
- AND repeating the detach does not error

### Requirement: WSL VM identity guard
Before any modify operation, the service MUST verify that the targeted compute system is the WSL2 utility VM (by owner/type/GUID) and MUST refuse to modify any other compute system.

#### Scenario: Refuse a non-WSL compute system
- GIVEN compute-system enumeration returns a VM that is not the WSL utility VM
- WHEN an attach is attempted against it
- THEN the service refuses and returns an error
- AND no `HcsModifyComputeSystem` call is issued for that system

#### Scenario: Ambiguous or missing WSL VM
- WHEN no unambiguous WSL utility VM can be resolved
- THEN the service aborts the operation with a descriptive error
- AND makes no modification

### Requirement: Durable re-attachment across WSL VM restarts
The service MUST detect WSL VM (re)start and re-apply the configured NIC attachments automatically, so attachments survive restarts without manual re-runs.

#### Scenario: Re-attach after VM restart
- GIVEN a cluster configured with one attached LAN NIC per node
- WHEN the WSL VM stops and starts again
- THEN the service re-attaches the configured NICs before the cluster finishes booting
- AND `k3s-init.sh` finds the expected interfaces present

#### Scenario: Idempotent re-attach
- GIVEN the configured NICs are already attached
- WHEN the re-attach routine runs
- THEN already-present NICs are detected and skipped without error

### Requirement: Move attached NIC into the node namespace
When LAN exposure is enabled, the WSL boot script MUST move each pre-attached interface into the corresponding node network namespace and MUST fall back to the private-bridge veth if the interface is absent after a bounded wait.

#### Scenario: NIC claimed into node netns
- GIVEN node index 1 maps to interface `eth1` and namespace `k3s-node-1`
- WHEN `k3s-init.sh` runs with LAN exposure enabled
- THEN `eth1` is moved into `k3s-node-1`, addressed, and flannel binds it
- AND the node obtains a LAN-routable IP

#### Scenario: Fallback when the NIC is missing
- GIVEN the expected interface does not appear within the timeout
- WHEN `k3s-init.sh` proceeds
- THEN the node falls back to its private-bridge veth
- AND the cluster still comes up

### Requirement: Per-node VLAN tagging
The service SHALL support an optional access-VLAN ID per node, applied at attach time, so a node's traffic is confined to a chosen VLAN.

#### Scenario: Attach with a VLAN tag
- GIVEN a node configured with access VLAN 42
- WHEN its NIC is attached
- THEN the vSwitch port for that NIC is set to access VLAN 42
- AND the node's traffic is confined to VLAN 42 on the LAN

### Requirement: Opt-in and disabled by default
LAN exposure MUST be disabled by default and enabled only per cluster by an explicit admin-gated action; the private-bridge path MUST remain the default behavior.

#### Scenario: Default deployment uses the private bridge
- GIVEN a multi-node cluster with no LAN exposure configured
- WHEN it is provisioned and boots
- THEN no NICs are attached via HCS/HCN
- AND every node uses its private-bridge veth as today

#### Scenario: Enabling is explicit and surfaced
- WHEN an operator enables LAN exposure for a cluster
- THEN the action is admin-gated and recorded in the service configuration
- AND the UI surfaces a warning about LAN reachability and recommends VLAN scoping
