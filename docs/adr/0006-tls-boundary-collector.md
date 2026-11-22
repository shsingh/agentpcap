# 0006 — The TLS-boundary collector: the uprobe on the host TLS library, the fd-less peer face, and the mode plumbing

Status: accepted (extends [0005](0005-wire-sample-layout-v3-socket-class.md); 0005's map-classified sample face stays in force)

## Context

The wire class gains the TLS-boundary collector (spec section 8/Modes:
attributed capture without TLS termination). Two kernel facts force
the design on the build VM's kernel 7.2.12:

- The host TLS workload rides the **OpenSSL 3.0 EX entry points**:
  the python ssl module calls `SSL_write_ex`/`SSL_read_ex` directly and
  the legacy `SSL_write`/`SSL_write` entries never fire during a live
  exchange (verified with cell receipts: `SSL_new` and `SSL_write_ex`
  counters move, the `SSL_write` counter stays flat).
- The uprobe surface works on this kernel (the falsification cell
  fires on libc's `write`, 14805 invokes), and the kernel's cgroup id
  is invisible from `/proc` inside a delegated container hierarchy
  (the socket-class cell calibrates it from the probe's own view).

## Decision

1. **The uprobes attach the host TLS library's `SSL_write_ex` and
   `SSL_read_ex`** (plus a documented fallback to the legacy
   `SSL_write` face for hosts whose TLS stack rides it — the attach
   symbol is a deployment face, not a code constant). The plaintext
   pointer and its length ride the same arm64 register file (x1, x2)
   on both faces; one shared capture pushes the classified sample.
2. **The sample rides the same 272-byte wire; the class comes from the
   `tls_events` map.** The fd field carries 0: the ssl object owns the
   connection, not a syscall, and the sample never reads the ssl
   struct.
3. **The peer resolves through the writer's /proc fd scan** - the
   first connected socket the writer holds, its `/proc/net` face
   canonicalized ADR-0005's way. Writers whose `/proc` entries are
   gone at pop time key honestly `unresolved` with the same evidence
   face as the pipe class. A writer with several connected sockets
   keys its first connected face; the ambiguity rides the evidence for
   the follow-up slices.
4. **The mode plumbing lands at the tap's feed face.** Attributed mode
   is the default; `--mode opaque` strips `params` and `result` from
   the parsed frame before the reassembler sees it - the record keeps
   the method and the id face, the arguments and results never ride.
   The reassembler stays mode-agnostic; the schema's
   `cap_fingerprint`-absent face emerges from the strip naturally.
5. The cgroup allow map and the `cgroup_seen` self-report ride the TLS
   programs exactly ADR-0005's way; the invoke counter lives before
   every gate so the probe's health stays observable.

## Consequences

- The TLS class needs no wire change and no schema change; the records
  carry `transport = tcp` with the `tls-boundary` evidence and the
  mode face their capture ran under.
- The tap now drains three class queues; the calibration, the pid
  offset and the cgroup face stay shared.
- Deployment hosts ride different libssl majors: the attach symbol set
  is the deployment's documented face (the release notes carry it with
  the capability set), never a build constant.
