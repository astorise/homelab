## Why

The `k3s-multinode-netns` change gives each node a **private** bridge IP (`10.50.0.0/24`), invisible to the LAN. That is sufficient for scheduling tests, but some scenarios need each node reachable on the **real network**: exposing NodePorts/ingress on routable IPs, MetalLB-style L2 advertisement, per-node **VLAN** segmentation, or testing topologies where nodes look like distinct LAN hosts.

`WSLAttachSwitch` proves that additional Hyper-V vSwitch NICs (`eth1`, `eth2`, …) can be attached to the single WSL2 utility VM at runtime via the **HCS** (Host Compute System) and **HCN** (Host Compute Network) APIs — the same APIs `microsoft/hcsshim` wraps. Two weaknesses make it impractical as-is: it **requires administrator rights** and it **does not survive a WSL VM restart** (must be re-run manually).

Both weaknesses are exactly what a **privileged, long-running Windows service** solves: it already runs as LocalSystem (no UAC prompt for HCS/HCN), and it can watch the WSL VM lifecycle and **re-attach automatically on every boot**. Reimplementing the attach logic in Rust (FFI to `computecore.dll`/`computenetwork.dll`, which the `windows` crate exposes) lets us turn a fragile one-shot CLI into a durable capability.

This is an **opt-in, experimental enhancement on top of** `k3s-multinode-netns`. It does **not** replace the network namespace: an attached NIC still lands in the single shared VM netns and must be **moved into the per-node netns** to be usable as a node interface. It replaces the *private bridge veth* with a *real Hyper-V NIC*, nothing more.

## What Changes

- **Rust reimplementation of the HCS/HCN attach principle.** A privileged component attaches/detaches Hyper-V vSwitch network adapters to the WSL2 utility VM at runtime (locate the WSL compute system via HCS enumeration; `HcsModifyComputeSystem` to add/remove a NIC referencing an HCN endpoint/switch).
- **Hosted in a Windows service, never in `home-http`.** Either the existing elevated `home-lab` orchestration path or a new dedicated privileged service exposed over the standard Named Pipe gRPC pattern (decision in design.md). `home-http` (TLS SNI proxy) is explicitly out of scope as a host.
- **Per-node LAN interface.** Each attached NIC (`ethN`) is moved into the corresponding node network namespace created by `k3s-multinode-netns`, giving that node a real, LAN-routable IP.
- **VLAN tagging per node.** Optional access-VLAN ID per node, applied at the vSwitch/endpoint level.
- **Durability via lifecycle watch.** The service detects WSL VM (re)start and re-attaches the configured NICs automatically, eliminating the "re-run after restart" limitation.
- **Strict gating.** Disabled by default; requires admin, an existing/created Hyper-V vSwitch, and an existing multi-node cluster. Clearly marked experimental.

This proposal is **design + spec deltas + tasks only — no source code is modified.**

## Capabilities

### New Capabilities
- `node-lan-exposure`: privileged runtime attachment of Hyper-V vSwitch NICs to the WSL2 VM via HCS/HCN (Rust), optional per-node VLAN tagging, moving each NIC into its node netns, and automatic re-attachment across WSL VM restarts.

### Modified Capabilities
<!-- none: `cluster-node-networking` is introduced by the not-yet-applied `k3s-multinode-netns` change, so it cannot receive a delta here. The dependency is documented in Impact and design.md instead. -->

## Impact

- **Affects:** Windows services **and** WSL. New privileged Rust code calling HCS/HCN on the Windows side; NIC-into-netns plumbing on the WSL side.
- **Depends on:** `k3s-multinode-netns` (requires the per-node netns to move attached NICs into). This change is meaningless without it.
- **Named Pipe services impacted:** a host service for the new privileged operations (the `home-lab` orchestrator's elevated path, or a new `home-net`/`home-wsl` service) — decided in design.md. **`home-http`, `home-dns`, `home-s3`, `home-oidc` are NOT impacted.** If a new service is introduced, it follows the existing `#[pin_project] PipeConnection` Named Pipe gRPC pattern.
- **New dependency:** the `windows` crate's HostComputeSystem / HostComputeNetwork bindings (Win32 HCS/HCN). No pure-Rust hcsshim equivalent exists; FFI is required.
- **WSL assets:** `k3s-init.sh` gains a step to claim a pre-attached `ethN` into a node netns (when LAN exposure is enabled) instead of/in addition to the private-bridge veth.
- **Prerequisites:** Hyper-V feature available, an external or internal vSwitch present (or created by the service), administrator privileges.
- **Spec:** new `node-lan-exposure` spec; no change to `openspec/specs/` base specs (the multi-node base is delivered by the other change).

## Security considerations

- **High-privilege surface.** HCS/HCN `Modify` calls can reconfigure VM devices. The implementation MUST verify the target compute system is the WSL utility VM (by owner/type/GUID) and refuse to touch any other VM. This is the single most important guardrail.
- **Deliberate LAN exposure.** Moving a real vSwitch NIC into a node netns intentionally bypasses the private-bridge isolation: pods/NodePorts may become reachable from the LAN. This MUST be opt-in, per-cluster, and clearly surfaced in the UI, with guidance on Windows Firewall and VLAN scoping.
- **VLAN isolation** is the recommended way to contain exposure to a dedicated segment; document setting an access VLAN per node.
- **No change to existing posture:** `home-s3` still binds loopback only; the private-bridge default path (no LAN exposure) remains the norm. `home-http`'s attack surface is unchanged (not a host for this code).
- **Privilege locality:** the attach logic runs only in a LocalSystem service; the non-elevated Tauri UI merely requests it over the Named Pipe, so no new elevation prompt is introduced at use time.
