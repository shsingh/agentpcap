# deploy/README.md — the placement faces and their capability sets.

Spec: docs/spec.md#10-deployment. Both topologies run the same binary
and emit the same event schema. A consumer tells the records apart only
by their fields, never by topology.

## Host-native (systemd)

`deploy/systemd/agentpcap.service`: the tap under a dedicated
`agentpcap` user. The capability set is exactly:

- `CAP_BPF` - the eBPF probe load and map access.
- `CAP_PERFMON` - the kernel observer surface.
- `CAP_DAC_READ_SEARCH` - the `/proc` face the tap reads (the writer
  fds, the `PPid` lineage).

The ledger write access rides `StateDirectory=agentpcap`
(`/var/lib/agentpcap`), and the unit grants nothing beyond it
(`ProtectSystem=strict`, `ReadWritePaths`). The tap is read-only: it
never intercepts, delays, or terminates any traffic path.

## Cluster-native (DaemonSet)

`deploy/k8s/daemonset.yaml` runs the same binary per node. The
container carries the same three capabilities plus the
`hostPath` faces the node scope needs (`/proc`, `/sys`, the node
ledger). The image builds from `deploy/k8s/Containerfile`.

## Workstation template (launchd)

`deploy/launchd/dev.agentpcap.plist` serves the review subcommands on
the workstation. The eBPF collectors are Linux-only; the launchd face
runs no capture.

## Non-privilege claim

No face runs root when the platform grants ambient capabilities
(Linux 5.8+). Where the host kernel lacks `CAP_BPF`/`CAP_PERFMON`
support, the documented fallback is root with
`CapabilityBoundingSet=CAP_SYS_ADMIN` and the operator states it.
