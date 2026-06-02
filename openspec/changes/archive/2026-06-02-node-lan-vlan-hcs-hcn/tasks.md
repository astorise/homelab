## 1. Spike — validate HCS/HCN attach from Rust

- [ ] 1.1 [Windows service] Create a throwaway Rust binary that enumerates compute systems via the `windows` crate HCS bindings and prints the WSL utility VM's system ID (owner/type match); confirm it isolates exactly the WSL VM.
- [ ] 1.2 [Windows service] Manually create an internal Hyper-V vSwitch; from the spike, build the HCN endpoint + `HcsModifyComputeSystem` settings document and attach one NIC; confirm `eth1` appears inside the running WSL VM.
- [ ] 1.3 [Windows service] Detach the NIC via the symmetric remove; confirm `eth1` disappears and re-running detach is a no-op.
- [ ] 1.4 [WSL] With `eth1` attached, `ip link set eth1 netns k3s-node-1`, address it, and confirm a pod on that node can reach a LAN host (validates the end-to-end path).

## 2. Host service skeleton (decision A vs B)

- [ ] 2.1 [Windows service] Confirm the host decision from design.md (lean: new `home-net` service); scaffold it with the `#[pin_project] PipeConnection` Named Pipe gRPC pattern, flexi_logger, and `C:\ProgramData\home-net\` config.
- [ ] 2.2 [Windows service] Define the gRPC proto for `EnableLanExposure`/`DisableLanExposure`/`GetLanExposureStatus`; **update both the service and Tauri proto copies**.
- [ ] 2.3 [Windows service] Implement config persistence (JSON under `C:\ProgramData\home-net\`): per-cluster switch GUID, node→NIC mapping, optional VLAN IDs.

## 3. HCS/HCN module (Rust)

- [ ] 3.1 [Windows service] Implement the WSL-VM identity guard as a pure function over enumeration output; unit-test it accepts only the WSL VM and rejects others/ambiguous cases.
- [ ] 3.2 [Windows service] Implement `attach_nic(switch, vlan)` and `detach_nic(id)` as `unsafe` wrappers over HCS/HCN with `anyhow` context; build settings documents with `serde_json`.
- [ ] 3.3 [Windows service] Make attach/detach idempotent (detect already-present NIC, skip; tolerate repeated detach).
- [ ] 3.4 [Windows service] Apply optional access-VLAN at attach time on the vSwitch port for the NIC.

## 4. Durability — lifecycle watch & re-attach

- [ ] 4.1 [Windows service] Register an HCS event/operation callback (or bounded poll) for WSL VM state transitions to `running`.
- [ ] 4.2 [Windows service] On WSL VM start, re-apply all configured attachments (idempotent), logging each action; verify NICs reappear after a `wsl --shutdown` + restart.

## 5. WSL boot integration

- [ ] 5.1 [WSL] In `k3s-init.sh`, add a bounded wait for the expected `ethN` per node when LAN exposure is enabled; on success move it into `k3s-node-<i>`, address it, bind flannel.
- [ ] 5.2 [WSL] Implement fallback to the private-bridge veth when `ethN` is absent after timeout; ensure the cluster still reaches Ready.
- [ ] 5.3 [WSL] Add the node's LAN IP (and/or `{name}.wsl`) to `K3S_TLS_SANS` as decided; verify kubeconfig access still works.

## 6. Orchestration & UI

- [ ] 6.1 [Tauri app] Wire the homelab orchestrator to call `home-net` over the Named Pipe when enabling/disabling LAN exposure for a cluster, then trigger the WSL restart that lets `k3s-init.sh` claim the NICs.
- [ ] 6.2 [Tauri app] Add an experimental, admin-gated LAN-exposure toggle per cluster in `<wsl-instance>`, with a clear warning about LAN reachability and a VLAN field.

## 7. Build, test & verification

- [ ] 7.1 [Windows service] `cargo check`/`cargo test` for the new service (identity-guard + idempotency unit tests) pass.
- [ ] 7.2 [Windows service] `cargo check` for the workspace before any release build.
- [ ] 7.3 [WSL] End-to-end: enable LAN exposure on a 2-node cluster, confirm each node has a LAN IP, a NodePort is reachable from another LAN host, and a per-node VLAN confines traffic.
- [ ] 7.4 [WSL] Rollback test: disable LAN exposure, confirm NICs detach and nodes revert to the private bridge on next boot with the cluster still healthy.
- [ ] 7.5 [Windows service] Negative test: point the identity guard at a non-WSL VM and confirm the operation is refused with no `Modify` call.

## 8. Documentation & gating

- [ ] 8.1 Document prerequisites (Hyper-V vSwitch, admin), the security model (deliberate LAN exposure, VLAN scoping, firewall notes), and the dependency on `k3s-multinode-netns`.
- [ ] 8.2 Mark the feature experimental and disabled-by-default in the UI and in `home-lab/src-tauri/resources/wsl/README.md`; note HCS/HCN schema-drift as a maintenance risk.
