# Pipe collector spike note (C003)

## Status of this document

**Status:** Draft. **Author:** agentpcap lane3 (probe spike). **Tracking:** issue #15-class.
This document records the C003 pipe collector spike for the agentpcap build (issue #15-class).
The collector ask reads from docs/spec.md section 5 and the status from section 17.
All kernel claims carry receipts from the build VM. Section 7 lists the receipts.

- **Build VM:** OrbStack `agentpcap-build-dev`, Ubuntu 24.04.5, arm64.
- **Kernel:** `7.2.12-orbstack-00394-gbecdd6130068` (receipt R0).
- **Verified on:** 2026-11-21, root shell on the VM.

## 1. Spike question and terms

The pipe collector (C003, spec section 5) captures newline-delimited JSON-RPC on stdio pipes.
It reads a pipe between one client and the client-launched server process.
The capture identifies the pair through process lineage and emits one frame record.
This note asks one question.
Which kernel probe points give the capture its attach sites, at what cost?

- **Probe point:** one kernel attach site per pipe read or write event.
  The event carries the write buffer or a bounded prefix, with the process ids.
- **Lineage:** the parent-child relation of the writer to the client process.
  The client spawns the MCP server as its child.
  The collector holds the client pid as the server's parent.
- **Sample:** the first N bytes of one syscall write buffer, N fixed at 256.
- **Decision (userspace):** one record verdict per spec section 6.
  The three forms: `mcp`, `agent-unidentified`, or `other`.

## 2. Probe points on the build kernel

### 2.1 Syscall tracepoints: present

The syscall event class carries 626 tracepoints on this kernel (receipt R1b).
Four entries give the capture its base (receipt R1). The command and output follow:

    $ sudo ls /sys/kernel/tracing/events/syscalls | grep -E '_(read|write)$'
    sys_enter_read
    sys_enter_write
    sys_exit_read
    sys_exit_write

The vector forms exist too (receipt R11): `sys_enter_writev`, `sys_enter_readv`,
`sys_enter_pwritev`, and the exit twins.
`sys_enter_writev` matters.
Rust and Node stdio layers use `writev(2)` under load.
So a write-only probe set misses lines without it.
The attach ids stay stable on this kernel (receipt R32).
`sys_enter_write` carries id 648. `sys_enter_writev` carries id 656.
`sys_enter_read` carries id 646. `sys_exit_read` carries id 647.

The `sys_enter_write` format shows the fields the capture needs (receipt R20).
The fields read: `fd` offset 16, `buf` offset 24, `count` offset 32.
The buffer bytes stay valid at entry.
So one enter-write probe gives the full payload.

### 2.2 Pipe-specific tracepoints: absent

No event class names pipefs on this kernel (receipt R3, empty grep).
The top-level event list carries no pipe event class (receipt R2).
A pipefs tracepoint attach is not a candidate here.
The candidate set holds two forms: syscall tracepoints (2.1) and function probes (2.3).

### 2.3 Kernel function probes: renamed symbols on this kernel

Mainline kernels put `pipe_read` and `pipe_write` in fs/pipe.c.
This kernel's BTF does not name either function (receipt R13, exact names checked).
The kallsyms census gives the working names on this build (receipt R27):

    $ sudo grep -E 'pipe[a-z_]*$' /proc/kallsyms | awk '{print $3}' | sort -u
    account_pipe_buffers  add_to_pipe  alloc_pipe_info  anon_pipe_buf_release
    anon_pipe_buf_try_steal  anon_pipe_put_page  anon_pipe_read  anon_pipe_write
    __arm64_sys_pipe ...

`anon_pipe_read` and `anon_pipe_write` are the data-path symbols for anonymous pipes.
A register one-shot proves the kprobe path on them (receipt R31).
The register line names `p:spikegrp anon_pipe_write`:

    $ echo 'p:spikegrp anon_pipe_write' > /sys/kernel/tracing/kprobe_events  # register-ok
    $ cat /sys/kernel/tracing/events/kprobes/*/id                            # 2022
    $ echo '-:spikegrp' > /sys/kernel/tracing/kprobe_events                  # cleanup-ok

A kprobe on the mainline name `pipe_write` fails to resolve (risk, section 5).
BTF is present (`/sys/kernel/btf/vmlinux`, receipt R9).
So fentry/fexit on `anon_pipe_write` plus CO-RE field reads resolve through the BPF loader.
The BTF strings carry 2240 `bpf_*` helper names (receipt R33).
The fd walk names also exist (receipt R14): `real_parent`, `files`, `pipe_inode_info`.

### 2.4 Kernel version specifics

OrbStack patches the syscall tracepoints. Two divergences shape the design:

- `sys_enter_write` carries an extra `__data_loc char[] __buf_val` field at
  offset 40 (receipt R20).
  The mainline `fd`/`buf`/`count` fields stay in place.
  The print line uses `__print_dynamic_array(__buf_val, 1)`.
  Aya tracepoint contexts MUST pin this layout from measured offsets.
- `sys_exit_read` carries only `ret` on this kernel (receipt R21).
  Mainline kernels add `fd`, `buf`, and `count` after it.
  An exit-side read probe with a buffer capture does not port here.
  The capture does not rely on `sys_exit_read`.

Two access facts fix the privilege shape (receipts R6, R30).
The sysctl `kernel.unprivileged_bpf_disabled` reads 2 (receipt R6).
bpffs and tracefs mount writable at the root paths (receipt R30).
The daemon loads with CAP_BPF and CAP_PERFMON per spec section 10.
No unprivileged path exists on this kernel.

bpftrace is not installed on the VM (receipt R5).
So the one-shot bpftrace probe of the spike protocol did not run.
The events listing plus the kprobe_events register test stand in.

## 3. Identification mechanics

### 3.1 Pipe identity from the fd

The probe receives `fd` as a syscall argument, not a file pointer.
The in-BPF check walks the calling task to the fd table and tests the file type:

1. `bpf_get_current_task_btf()` gives the `task_struct`.
2. CO-RE reads cross `task->files->fdt->fd[fd]` to the `struct file`.
3. The filter tests `f_inode->i_mode & S_IFIFO` (octal 0o010000, hex `0x1000`).
   The stronger test reads `f_inode->i_sb->s_magic == 0x50495045`
   (`PIPEFS_MAGIC`).
4. `file->private_data` points to the `pipe_inode_info` (receipt R14: the BTF
   name resolves).
   So a CO-RE field check is possible where the f_mode check reads too weak.

The three-step walk costs three memory reads per syscall event.
The lineage map (3.2) gates it.
The pipe walk runs only for processes the map marks.

Userspace keeps the channel identity.
Spec section 5 keys the record to the pipe pair.
The kernel probe cannot see the peer end cheaply.
So userspace links the two ends through the pipe inode number.
Receipt R26 shows the shape, from one process whose stdout is the pipe:

    $ bash -c 'ls -l /proc/self/fd/1' | cat
    l-wx------ 1 root root 64 Nov 21 18:29 /proc/self/fd/1 -> pipe:[8101691]

Both ends read back `pipe:[<n>]` with one shared `<n>`.
That number becomes the `peer` field and the `session_id` channel key (spec section 4).
The readlink fallback needs no BPF support and runs on any Linux.

### 3.2 Lineage: pid to ppid

Two mechanisms exist on this kernel. The design carries both.

- **In-BPF (primary).** The CO-RE read of `task->real_parent->tgid` gives the
  parent pid in the probe.
  The BTF name `real_parent` resolves on this kernel (receipt R14).
  No `get_current_ppid()` helper exists in mainline.
  The CO-RE read is the standard form.
- **Fork feed (map).** The tracepoint `sched:sched_process_fork` exists
  (receipt R4).
  It carries `parent_pid` and `child_pid` directly (receipt R15: offsets 12
  and 20).
  A fork event feeds a BPF map keyed by child pid.
  The map answers lineage asks for events in the same syscall tick.

The collector marks a writer as the MCP server when its parent reads the client pid.
The direction field follows the same read.
The writer with the client as parent is the server.
Its write direction is server-to-client.
The writer that carries its own pid as parent writes from the client side.

Fallback for the lineage match: userspace scans the `/proc/<pid>/status` PPid lines.
It scans on the first unknown pid and caches the answer.
Userspace also re-checks the fork map against exit events.
A periodic sweep clears a stale entry (risk, section 6).
The stale-entry risk stays bounded because the map key is a pid.
Pid reuse stays rare on one review build.

## 4. Capture mechanism

### 4.1 Kernel side

Aya builds two tracepoint programs: `sys_enter_write` and `sys_enter_writev`.
Each program runs the same three-stage body:

1. The program exits early when the pid is not in the lineage map.
   This keeps the host-wide write traffic out of the probe's cost path.
2. The fd walk (3.1) confirms an anonymous pipe fd.
3. A bounded copy: `bpf_probe_read_user` of `min(count, 256)` bytes from the
   buffer.
   Plus pid, ppid, fd, comm, and the byte count, into one event.

The event goes out on an `aya::maps::ring_buf::RingBuf` with an `output` call.
RingBuf fits the byte-event stream.
Per-CPU ArrayMaps carry the drop counters and the fork feed map.
One userspace task drains the RingBuf.
So the syscall path stays free of extra userspace wakeups.

Userspace turns each event into one agentpcap record:

- `transport` carries `stdio-pipe`.
- `source` carries `tap`.
- `evidence` carries `["stdio-pipe"]` on a matched event.
- The write fd's pipe inode number sets `peer` and `session_id` (3.1 userspace
  join).
- `classify_pipe_sample(pid, ppid, comm, first_bytes)` sets `verdict` and
  `event`.
- The framing rules follow spec section 6.
- The RED draft pins the contract (SPIKE-NOTES.md).

### 4.2 Sample policy: first N bytes

The policy is sample-first-256-bytes.
The probe copies at most 256 bytes.
It marks `truncated` in the event.
Userspace reassembles lines across events.
The reasons:

- One RingBuf record stays under one page.
- The JSON-RPC method name sits inside the first line of the buffer.
- The copy cost per event stays fixed regardless of write size.

The `count` field still leaves the probe with the event.
So the reassembler knows the full write length.
Bytes over the sample line never leave the kernel.

Framing reads tolerate a sample that starts mid-line.
Reassembly is line-based.
The classifier acts only on complete lines.
A record with verdict `agent-unidentified` stays the safe output.
It covers a sample with no complete line and no framing evidence.
Spec section 6 sets this default.

## 5. Recommendation

**Recommended probe point:**
the pair `syscalls:sys_enter_write` plus `syscalls:sys_enter_writev`,
lineage-gated, with the fd-to-pipe walk as filter.

One-line justification follows.
The buffer bytes stay valid at entry on both endpoints.
So one ABI-stable tracepoint capture covers client requests and server responses.
The alternatives fail here.
No pipefs tracepoint class exists (2.2).
`sys_exit_read` lacks the buffer fields on this kernel (2.4).

The alpha1 candidate set: attach `sys_enter_write` (id 648) and
`sys_enter_writev` (id 656).
Keep the kprobe on `anon_pipe_write` as the fallback attach.
It applies if a format change breaks the tracepoint contexts.

## 6. Risks and fallbacks

| Topic | Open risk | Fallback |
|---|---|---|
| Probe point | OrbStack patches the syscall tracepoint formats: `sys_enter_write` gains `__data_loc __buf_val` (R20) and `sys_exit_read` drops `fd`/`buf`/`count` (R21). Pinned offsets break on other kernels, and the exit-read data path does not exist here. | Generate the aya context structs from the VM's `/sys/kernel/tracing/.../format` files at build time, or keep the alpha1 set at enter-write plus enter-writev only. The write side covers both directions. |
| Lineage match | The fork feed map and the write event race: a write can land before the fork event feeds the map, and pid reuse can make one stale entry name a wrong parent. | Fall back to a `/proc/<pid>/status` PPid scan on the first unknown pid, cached with a TTL and exit-event clears. |
| M002 budget | The probe runs on every write on the host; a host-wide write storm floods the RingBuf and the drop handling pushes the delta over the sub-3% budget. | Stage the checks lineage-first, pipe-second, copy-last. Sample only the first 256 bytes. Count drops per CPU in one map and surface them as an `M002` counter. The last-resort fallback is the cgroup filter from spec section 5 plus a narrower probe set. |

## 7. Receipts

Commands ran as root on `agentpcap-build-dev` on 2026-11-21.
The R-numbers stay the same through this document.
The one-shot command from the spike protocol (bpftrace interval probe) did not run: bpftrace is absent (R5).

| Receipt | Command | Output line |
|---|---|---|
| R0 | `sudo uname -r` | `7.2.12-orbstack-00394-gbecdd6130068` |
| R1 | `sudo ls /sys/kernel/tracing/events/syscalls \| grep -E '_(read\|write)$'` | `sys_enter_read`, `sys_enter_write`, `sys_exit_read`, `sys_exit_write` |
| R1b | `sudo ls /sys/kernel/tracing/events/syscalls \| wc -l` | `626` |
| R2 | `sudo ls /sys/kernel/tracing/events/` | full class list; no `fs` pipe class |
| R3 | `sudo ls /sys/kernel/tracing/events/ \| grep -i pipe` | empty; no match |
| R5 | `command -v bpftrace` | no path; bpftrace not installed |
| R6 | `sysctl kernel.unprivileged_bpf_disabled` | `kernel.unprivileged_bpf_disabled = 2` |
| R9 | `test -f /sys/kernel/btf/vmlinux && echo present` | `BTF-vmlinux-present` |
| R11 | `sudo ls /sys/kernel/tracing/events/syscalls \| grep -E 'sys_(enter\|exit)_(read\|write\|readv\|writev)'` | 24 lines; `sys_enter_writev` present |
| R12 | `cat /proc/sys/kernel/kptr_restrict` | `1` |
| R13 | `strings /sys/kernel/btf/vmlinux \| grep -xE 'pipe_(read\|write\|writev\|ioctl\|poll\|release\|fifo)'` | `pipe_ioctl`, `pipe_poll`, `pipe_release` only |
| R14 | `strings /sys/kernel/btf/vmlinux \| grep -qx "real_parent"` (one check per name) | `real_parent`, `files`, `pipe_inode_info` all present |
| R15 | `sudo grep -E 'parent_pid\|child_pid' /sys/kernel/tracing/events/sched/sched_process_fork/format` | `field:pid_t parent_pid; offset:12;` and `field:pid_t child_pid; offset:20;` |
| R20 | `sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_write/format` | `fd` offset 16, `buf` 24, `count` 32, `__data_loc char[] __buf_val` offset 40 |
| R21 | `sudo cat /sys/kernel/tracing/events/syscalls/sys_exit_read/format` | only `ret` offset 16; no `fd`, `buf`, `count` |
| R23 | `strings /sys/kernel/btf/vmlinux \| grep -i '^pipe' \| grep -iE 'read\|write'` | `pipe_wait_readable` only |
| R26 | `bash -c 'ls -l /proc/self/fd/1' \| cat` | `l-wx------ ... /proc/self/fd/1 -> pipe:[8101691]` |
| R27 | `sudo grep -E 'pipe[a-z_]*$' /proc/kallsyms \| awk '{print $3}' \| sort -u` | `anon_pipe_read`, `anon_pipe_write`, `add_to_pipe`, and the rest of the census |
| R31 | `sudo sh -c "echo 'p:spikegrp anon_pipe_write' > /sys/kernel/tracing/kprobe_events && cat /sys/kernel/tracing/events/kprobes/*/id; echo '-:spikegrp' > /sys/kernel/tracing/kprobe_events"` | `register-ok`, id `2022`, `cleanup-ok` |
| R32 | `for e in sys_enter_write sys_enter_writev sys_enter_read sys_exit_read; do cat /sys/kernel/tracing/events/syscalls/$e/id; done` | `648`, `656`, `646`, `647` |
| R30 | `mount \| grep -E 'bpf\|tracefs'` | `bpf on /sys/fs/bpf ... (rw,...)`, `tracefs on /sys/kernel/tracing ... (rw,...)` |
| R33 | `strings /sys/kernel/btf/vmlinux \| grep -cE '^bpf_[a-z_]+'` | `2240` |

## 8. Next steps

SPIKE-NOTES.md at the worktree root lists the open items.
It also lists the RED cells: P001 lineage, P002 framing, P003 sample bound,
P004 ring buffer plumbing.
The first RED test draft lives in `crates/collector/tests/p001_red.rs`.
It pins the userspace match contract only.
