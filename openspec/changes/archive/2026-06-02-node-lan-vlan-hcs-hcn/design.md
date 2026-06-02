## Context

`k3s-multinode-netns` gives each k3s node its own Linux network namespace, with its interface sourced from a `veth` on a private bridge (`k3s-br0`, `10.50.0.0/24`). Those IPs are internal to the WSL VM. This change adds an **opt-in** way to give a node a **real Hyper-V vSwitch NIC** (LAN-routable, optionally VLAN-tagged) instead of/in addition to the private veth.

The enabling mechanism is the one `WSLAttachSwitch` demonstrates: the WSL2 utility VM is a Host Compute System; additional NICs can be attached at runtime via **HCS** (`computecore.dll`/`vmcompute.dll`) + **HCN** (`computenetwork.dll`). These are the APIs `microsoft/hcsshim` (Go) wraps and that the `windows` crate exposes for Rust. The two practical blockers — needs admin, does not survive VM restart — are solved by hosting the logic in a **LocalSystem Windows service** that re-attaches on VM lifecycle events.

Critically, attaching a NIC only adds it to the **single shared VM netns**; it must then be **moved into the node netns** (`ip link set ethN netns k3s-node-<i>`) to serve as that node's interface. The netns layer from `k3s-multinode-netns` is therefore a hard prerequisite, not a thing this change replaces.

## Goals / Non-Goals

**Goals:**
- Attach/detach Hyper-V vSwitch NICs to the WSL2 VM from Rust, at runtime, without shelling out to `WSLAttachSwitch`.
- Re-attach automatically when the WSL VM (re)starts, making the configuration durable.
- Move each attached NIC into its node netns so a node gets a real LAN IP, with optional per-node VLAN tag.
- Keep the whole feature opt-in and disabled by default; the private-bridge path stays the norm.
- Run all privileged operations in a LocalSystem service; keep the non-elevated UI as a mere requester.

**Non-Goals:**
- Replacing the per-node netns or the private bridge as the default (this is additive/optional).
- Hosting any of this in `home-http`.
- Managing physical NIC teaming, host routing tables on the LAN, or DHCP servers.
- Supporting non-WSL VMs or general Hyper-V VM management.
- Surviving across Windows updates that change HCS/HCN schemas without maintenance (version pinning is a known risk, see below).

## Decisions

### 1. Host: a privileged service, not `home-http`; reuse the orchestrator or add `home-net`
The attach logic needs LocalSystem and the WSL-lifecycle context. Two options:
- **(A) Extend the `home-lab` orchestration/elevated path** — it already owns WSL provisioning, portproxy, and DNAT. Lowest new surface.
- **(B) New dedicated service `home-net`** — clean separation, follows the `#[pin_project] PipeConnection` Named Pipe gRPC pattern, independently restartable, easiest to reason about for a high-privilege surface.

**Lean: (B) a dedicated `home-net` service**, because the surface is security-sensitive and benefits from isolation and an auditable, minimal API. `home-http` is rejected outright (TLS-proxy remit, unrelated).

**Alternatives considered:** shelling out to the prebuilt `WSLAttachSwitch.exe` (rejected: external unsigned binary, no lifecycle integration, no re-attach); doing it in the non-elevated Tauri app (rejected: would require a UAC prompt per action).

### 2. Mechanism: Rust FFI to HCS + HCN
- **Locate the WSL VM:** enumerate compute systems (HCS `HcsEnumerateComputeSystems`) and select the one owned by WSL (owner/type match), resolving its system ID (GUID). Refuse if no unambiguous WSL VM is found.
- **Prepare the network:** reference an existing Hyper-V vSwitch / HCN network by GUID, or create an HCN endpoint bound to it; capture the endpoint ID.
- **Attach:** `HcsModifyComputeSystem` with a `VirtualMachine/Devices/NetworkAdapters/<id>` add settings document referencing the endpoint. Detach is the symmetric remove.
- **Rust surface:** thin `unsafe` wrappers over the `windows` crate's HostComputeSystem/HostComputeNetwork functions, returning `anyhow::Result` with `.context()` chains; JSON settings documents built with `serde_json`.

**Alternatives considered:** raw `LoadLibrary`/`GetProcAddress` against `computecore.dll` (more code, no type safety — rejected in favor of the `windows` crate bindings).

### 3. Durability: watch the WSL VM lifecycle and re-attach
`HcsModifyComputeSystem` changes are lost when the VM stops. The service registers an HCS operation/event callback (or polls compute-system state) and, on a fresh WSL VM start, re-applies the configured attachments before/early in boot, so `k3s-init.sh` finds `ethN` present.

- Configuration (which switch, how many NICs, VLAN IDs, target cluster) is persisted under `C:\ProgramData\home-net\` (JSON), consistent with other services' config locations.
- Re-attach is idempotent: detect already-present NICs and skip.

### 4. WSL side: claim the pre-attached NIC into a node netns
When LAN exposure is enabled for a cluster, `k3s-init.sh` (from `k3s-multinode-netns`) gains a step: for node `i`, if a designated `ethN` exists in the host netns, `ip link set ethN netns k3s-node-<i>`, configure its address (static or DHCP on the LAN), and bind flannel to it. Otherwise fall back to the private-bridge veth.

- **VLAN:** the access-VLAN tag is applied on the Windows side at attach time (vSwitch port VLAN), so the Linux side sees an untagged interface on the chosen VLAN. (Alternative: 802.1Q subinterfaces inside the netns — deferred.)
- flannel backend with real LAN NICs is `host-gw` if all node NICs share an L2 segment, else `vxlan`; chosen per deployment.

### 5. Coordination between the service (Windows) and k3s-init (WSL)
Ordering matters: NICs must be attached before `k3s-init.sh` tries to claim them. The service re-attaches on VM start; `k3s-init.sh` waits (bounded) for the expected `ethN` to appear before claiming, then proceeds. If absent after timeout, it logs and falls back to the private bridge so the cluster still comes up.

## Risks / Trade-offs

- **[HCS/HCN schema drift across Windows builds]** → Pin to documented schema versions, feature-detect, and fail safe (log + fall back to private bridge) rather than corrupting VM state.
- **[Touching the wrong VM]** → Hard guard: verify WSL owner/type/GUID before any `Modify`; refuse otherwise. Cover with a unit test on the selection predicate.
- **[Lost attachment on restart races with k3s boot]** → Bounded wait in `k3s-init.sh` for `ethN`; service re-attaches as early as possible; idempotent claim.
- **[Unintended LAN exposure / security]** → Opt-in per cluster, VLAN guidance, firewall notes; default remains private bridge. Surface a clear warning in the UI.
- **[Admin requirement]** → Privileged ops live only in the LocalSystem service; UI stays non-elevated. Installer already has an elevated path (`install-elevated.ps1`).
- **[New dependency footprint]** → `windows` crate HCS/HCN features add build surface; isolate behind a small module/crate so the blast radius is contained.
- **[No clean rollback if a Modify half-applies]** → Detach is symmetric and idempotent; on error, attempt detach of the partial NIC and restore the private-bridge path.

## Migration Plan

- **Forward:** ship `home-net` (or the orchestrator extension) disabled by default. Enabling LAN exposure for a cluster is an explicit, admin-gated action that records config and triggers an attach + a WSL restart so `k3s-init.sh` claims the NICs.
- **Rollback:** disable LAN exposure → service detaches NICs, `k3s-init.sh` reverts each node to its private-bridge veth on next boot. The cluster keeps working (private IPs). Worst case, stop `home-net`; nodes fall back to the private bridge automatically.
- **No impact** to existing single-node or private-bridge multi-node clusters unless explicitly enabled.

## Open Questions

- Host decision: extend `home-lab` orchestrator (A) vs. new `home-net` service (B)? (Lean B; confirm with security review.)
- Address assignment on the LAN NIC: static (operator-provided) vs. DHCP vs. derived — pick during implementation; DHCP is simplest but less stable for kubeconfig SANs.
- Does the cluster API endpoint stay `{name}.wsl:port` (republished from the server netns) or switch to the server node's real LAN IP when exposure is on? (Lean: keep `{name}.wsl` for consistency; add the LAN IP to TLS SANs.)
- VLAN application: vSwitch access-VLAN at attach time vs. 802.1Q subinterface in netns — confirm which the HCN endpoint settings support cleanly.
- Should `home-net` also subsume the existing portproxy/DNAT responsibilities, or strictly own HCS/HCN? (Lean: strictly HCS/HCN for now.)
