# SPIKE-NOTES.md — lane3 pipe collector spike (C003, issue #15-class)

## What this spike produced

- `docs/research/pipe-collector-spike.md`: the feasibility note with kernel
  receipts from the build VM.
- `crates/collector/`: the first RED test draft.
  `tests/p001_red.rs` pins the userspace match contract.
  `src/lib.rs` carries the `Decision` type and the `classify_pipe_sample` stub.
  The stub carries `unimplemented!()`.
  The RED is for the missing match function only.
  The alpha1 slice implements the body and turns the draft green.
- `Cargo.toml`: workspace `members` carry the new `crates/collector` entry.
- No other file changed. No git operations ran in this lane.

## What the VM verification established (receipts)

Kernel: `7.2.12-orbstack-00394-gbecdd6130068`, Ubuntu 24.04.5 arm64.
All commands ran as root in the VM shell.
Full commands and output live in section 7 of the note.
The load-bearing lines:

1. Syscall tracepoints for the capture exist: `sys_enter_read`, `sys_enter_write`, `sys_exit_read`, `sys_exit_write`.
   The host carries 626 syscall tracepoints plus `sys_enter_writev` for vector writes.
   Attach ids: write 648, writev 656.
2. No pipefs/pipe-specific tracepoint class exists on this kernel.
3. The mainline names `pipe_read`/`pipe_write` are absent from this kernel's BTF and kallsyms.
   The data-path symbols are `anon_pipe_read` and `anon_pipe_write`.
   A kprobe register on `anon_pipe_write` succeeds (event id 2022, then cleanup).
4. OrbStack patches the syscall tracepoint formats.
   `sys_enter_write` adds `__data_loc char[] __buf_val` at offset 40.
   `sys_exit_read` carries only `ret` (no `fd`/`buf`/`count`).
5. The tracepoint `sched:sched_process_fork` carries `parent_pid` and `child_pid` directly.
   The BTF names `real_parent`, `files`, `pipe_inode_info` resolve.
6. The command `bash -c 'ls -l /proc/self/fd/1' | cat` prints `pipe:[8101691]`.
   The pipe inode shape sets the userspace join.
7. `kernel.unprivileged_bpf_disabled` reads 2.
   bpffs and tracefs mount writable.
   BTF `/sys/kernel/btf/vmlinux` is present.
8. bpftrace is NOT installed on the VM.
   So the bpftrace one-shot probe of the spike protocol did not run.
   The events listing plus the kprobe_events register test stand in.

## What the RED run showed

The test draft ran in a scratch copy on the VM (`/tmp/spike-red`, no worktree
artifacts).
The toolchain: `rustc 1.100.0 (0ef1bc386 2026-11-09)`, root env.
The draft compiles clean and all 8 tests go RED.
The result line: `test result: FAILED. 0 passed; 8 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s`.
One panic line: `not implemented: P001 RED: classify_pipe_sample is the alpha1 match function; tests/p001_red.rs fails here`.
The RED is for the missing match function only, as the draft asks.

## Recommended probe point

`syscalls:sys_enter_write` plus `syscalls:sys_enter_writev`, lineage-gated,
with the fd-to-pipe walk as filter.
The buffer bytes stay valid at entry on both endpoints.
So this set covers both directions on one ABI-stable tracepoint.
The kprobe on `anon_pipe_write` stays the fallback attach (event id 2022, then cleanup).

## What remains open

- The aya tracepoint context structs for the OrbStack-patched formats.
  Pin the offsets from the VM's `/sys/kernel/tracing/.../format` files at
  build time.
- The writev iovec walk (`bpf_probe_read_user` of `iov_base`, bounded) has no
  VM test yet.
  The alpha1 slice carries it with a P003-tied unit test.
- The RingBuf drop behavior under a host-wide write storm is unmeasured.
  The M002 overhead number needs the tap-on/tap-off run on the VM.
- The toolchain env pins on the VM come from the build-VM brief.
  The pins read: `LLVM_SYS_230_PREFIX`, `LLVM_CONFIG_PATH`, nightly
  `-Zbuild-std=core` for `bpfel-unknown-none`.
  The spike did not run a cargo build.
- Cargo is not on the sudo shell PATH in the VM.
  The toolchain check moves to the alpha1 lane's environment setup.

## Recommended RED cell list for the alpha1 collector slice

- **P001 lineage**: the fork feed map plus the `real_parent` CO-RE read agree
  on the writer's parent.
  A first-write-before-fork-event race falls back to the `/proc` PPid scan.
  Cells: map hit, map miss plus scan, stale entry.
- **P002 framing**: the classify pass over one sample.
  The RED draft (`tests/p001_red.rs`, 8 tests) carries the first cells.
  The cells: MCP method framing, non-JSON binary, non-MCP method, plain text,
  partial line.
- **P003 sample-bound**: the probe copies at most 256 bytes, marks
  `truncated`, and the `count` field leaves with the event.
  Cells: short write, long write, multi-event line reassembly.
- **P004 ring-buffer plumbing**: RingBuf output from two tracepoint programs
  into one userspace poller.
  Per-CPU drop counters and clean detach on exit.
  Cells: event order, drop count increments, drain keeps up.
