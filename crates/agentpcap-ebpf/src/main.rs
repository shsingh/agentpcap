// The agentpcap probe. The alpha1 tap: a tracepoint on the write
// syscall that pushes one pipe sample per write into the `pipe_events`
// queue and keeps the canary counter current. The sample's ppid is 0;
// lineage resolves userspace-side (P003) — the in-probe fork feed is
// parked with its tracked kernel receipts.
// Spec: docs/spec.md#5-collectors.
#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_probe_read_user_buf,
};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{Array, HashMap, Queue};
use aya_ebpf::programs::TracePointContext;

/// Wire format: must match the collector crate's `PipeSample` exactly
/// (const-locked on both sides at 48 bytes).
#[repr(C, align(8))]
pub struct PipeSample {
    pid: u32,
    ppid: u32,
    len: u32,
    fd: u32,
    first_bytes: [u8; 256],
}

const _: () = assert!(core::mem::size_of::<PipeSample>() == 272);

const PAYLOAD_BYTES_CAP: u32 = 256;

#[map(name = "pipe_events")]
static mut EVENTS: Queue<PipeSample> = Queue::with_max_entries(16384, 0);

// The socket class rides the same wire; the class comes from the map
// (ADR-0005), not from a wire discriminant.
#[map(name = "sock_events")]
static mut SOCK_EVENTS: Queue<PipeSample> = Queue::with_max_entries(16384, 0);

const SLOT_INVOKE: u32 = 0;
const SLOT_READ_FAIL: u32 = 1;
const SLOT_PUSH_OK: u32 = 2;
const SLOT_PUSH_FAIL: u32 = 3;

#[map(name = "events")]
static mut CANARY: Array<u64> = Array::with_max_entries(4, 0);

#[map(name = "sock_canary")]
static mut SOCK_CANARY: Array<u64> = Array::with_max_entries(4, 0);

// The cgroup allow map (ADR-0005): the tap marks filtering active with
// the sentinel key `u64::MAX -> 1` and lists the allowed cgroup ids
// beside it. The sentinel absent: capture all (the lab default).
const CGROUP_SENTINEL: u64 = u64::MAX;
#[map(name = "cgroup_allow")]
static mut CGROUP_ALLOW: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);

// The probe self-reports the running task's cgroup id: the userspace
// face calibrates the allow set from the kernel's own view (the
// container boundary hides it from /proc on delegated hierarchies).
#[map(name = "cgroup_seen")]
static mut CGROUP_SEEN: Array<u64> = Array::with_max_entries(1, 0);

// The ADR-0003 capture filter, shared by the pipe and the socket taps:
// the calibration sentinel, or `{` plus the `jsonrpc` member within the
// first 40 bytes with the leading whitespace skipped.
#[inline(always)]
fn candidate(buf: *const u8) -> bool {
    unsafe {
        let mut sniff: [u8; 40] = [0u8; 40];
        if bpf_probe_read_user_buf(buf, &mut sniff).is_err() {
            return false;
        }
        if sniff.starts_with(b"agentpcap-c") {
            // the calibration sentinel rides
            return true;
        }
        let mut j = 0usize;
        while j < 16 {
            let c = sniff[j];
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                j += 1;
            } else {
                break;
            }
        }
        if sniff[j] != b'{' {
            return false;
        }
        let mut k = j;
        while k + 7 <= 40 {
            if sniff[k] == b'j'
                && sniff[k + 1] == b's'
                && sniff[k + 2] == b'o'
                && sniff[k + 3] == b'n'
                && sniff[k + 4] == b'r'
                && sniff[k + 5] == b'p'
                && sniff[k + 6] == b'c'
            {
                return true;
            }
            k += 1;
        }
        false
    }
}

// The ADR-0005 cgroup face: pass when the sentinel is absent, then pass
// only an allowed cgroup id.
#[inline(always)]
fn cgroup_allowed() -> bool {
    unsafe {
        let marked = CGROUP_ALLOW.get(&CGROUP_SENTINEL).is_some();
        if !marked {
            return true;
        }
        let id = bpf_get_current_cgroup_id();
        CGROUP_ALLOW.get(&id).is_some()
    }
}

#[tracepoint]
pub fn agentpcap(mut ctx: TracePointContext) -> i64 {
    // sys_enter_write tracepoint context (format-verified on this
    // kernel): fd at 16, buf at 24, count at 32 bytes.
    let buf: usize = match unsafe { ctx.read_at::<usize>(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let count: usize = match unsafe { ctx.read_at::<usize>(32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let take = if count > PAYLOAD_BYTES_CAP as usize {
        PAYLOAD_BYTES_CAP as usize
    } else {
        count
    };

    // The invoke counter lives before the capture filter: health stays
    // independent of the filter (ADR 0003).
    unsafe {
        if let Some(slot) = CANARY.get_ptr_mut(SLOT_INVOKE) {
            *slot += 1;
        }
    }

    // Capture filter: only JSON-RPC candidate lines and the calibration
    // sentinel ride the queue (spec framing: MCP over stdio is line-
    // delimited JSON-RPC starting `{`). The sniff skips leading
    // whitespace and requires the `jsonrpc` member within the first 40
    // bytes, so member reordering such as `{"id":3,"jsonrpc":...}` still
    // rides. Everything else is non-agent traffic and never becomes a
    // sample (ADR 0003).
    unsafe {
        let mut sniff: [u8; 40] = [0u8; 40];
        if bpf_probe_read_user_buf(buf as *const u8, &mut sniff).is_err() {
            return 0;
        }
        if sniff.starts_with(b"agentpcap-c") {
            // the calibration sentinel rides
        } else {
            let mut j = 0usize;
            while j < 16 {
                let c = sniff[j];
                if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                    j += 1;
                } else {
                    break;
                }
            }
            if sniff[j] != b'{' {
                return 0;
            }
            let mut is_jsonrpc = false;
            let mut k = j;
            while k + 7 <= 40 {
                if sniff[k] == b'j'
                    && sniff[k + 1] == b's'
                    && sniff[k + 2] == b'o'
                    && sniff[k + 3] == b'n'
                    && sniff[k + 4] == b'r'
                    && sniff[k + 5] == b'p'
                    && sniff[k + 6] == b'c'
                {
                    is_jsonrpc = true;
                    break;
                }
                k += 1;
            }
            if !is_jsonrpc {
                return 0;
            }
        }
    }

    unsafe {
        let mut sample = PipeSample {
            pid: (bpf_get_current_pid_tgid() >> 32) as u32,
            ppid: 0,
            len: take as u32,
            fd: match ctx.read_at::<u32>(16) {
                Ok(v) => v,
                Err(_) => return 0,
            },
            first_bytes: [0u8; 256],
        };
        if take > 0 {
            if bpf_probe_read_user_buf(buf as *const u8, &mut sample.first_bytes[..take]).is_err() {
                if let Some(slot) = CANARY.get_ptr_mut(SLOT_READ_FAIL) {
                    *slot += 1;
                }
                return 0;
            }
        }
        if EVENTS.push(&sample, 0).is_ok() {
            if let Some(slot) = CANARY.get_ptr_mut(SLOT_PUSH_OK) {
                *slot += 1;
            }
        } else if let Some(slot) = CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
            *slot += 1;
        }
    }
    0
}

/// The socket-class tap: `sys_enter_sendto` (the TCP-send face; the
/// kernel's `send` rides `sendto` with a null addr) and the receive
/// face mirrors it on `sys_enter_recvfrom` (ADR-0005). Format verified
/// on this kernel 7.2.12: fd at 16, ubuf at 24, size at 32.
#[tracepoint]
pub fn agentpcap_socket(mut ctx: TracePointContext) -> i64 {
    // the invoke counter lives before the cgroup gate: health stays
    // independent of the filter (the pipe probe's ADR-0003 face)
    unsafe {
        if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_INVOKE) {
            *slot += 1;
        }
        let id = bpf_get_current_cgroup_id();
        let _ = CGROUP_SEEN.set(0, &id, 0);
    }
    if !cgroup_allowed() {
        return 0;
    }
    let buf: usize = match unsafe { ctx.read_at::<usize>(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let count: usize = match unsafe { ctx.read_at::<usize>(32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let take = count.min(PAYLOAD_BYTES_CAP as usize);
    unsafe {
        // the ADR-0003 sniff, shared helper
        if !candidate(buf as *const u8) {
            return 0;
        }
        let mut sample = PipeSample {
            pid: (bpf_get_current_pid_tgid() >> 32) as u32,
            ppid: 0,
            len: take as u32,
            fd: match ctx.read_at::<u32>(16) {
                Ok(v) => v,
                Err(_) => return 0,
            },
            first_bytes: [0u8; 256],
        };
        if take > 0 {
            if bpf_probe_read_user_buf(buf as *const u8, &mut sample.first_bytes[..take]).is_err()
            {
                if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_READ_FAIL) {
                    *slot += 1;
                }
                return 0;
            }
        }
        if SOCK_EVENTS.push(&sample, 0).is_ok() {
            if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_OK) {
                *slot += 1;
            }
        } else if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
            *slot += 1;
        }
    }
    0
}

/// The receive face: `sys_enter_recvfrom` (ubuf at 24, size at 32, the
/// format verified on this kernel). Same wire, same queue, same filter.
#[tracepoint]
pub fn agentpcap_recv(mut ctx: TracePointContext) -> i64 {
    unsafe {
        if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_INVOKE) {
            *slot += 1;
        }
        let id = bpf_get_current_cgroup_id();
        let _ = CGROUP_SEEN.set(0, &id, 0);
    }
    if !cgroup_allowed() {
        return 0;
    }
    let buf: usize = match unsafe { ctx.read_at::<usize>(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let count: usize = match unsafe { ctx.read_at::<usize>(32) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let take = count.min(PAYLOAD_BYTES_CAP as usize);
    unsafe {
        if take == 0 {
            return 0;
        }
        if !candidate(buf as *const u8) {
            return 0;
        }
        let mut sample = PipeSample {
            pid: (bpf_get_current_pid_tgid() >> 32) as u32,
            ppid: 0,
            len: take as u32,
            fd: match ctx.read_at::<u32>(16) {
                Ok(v) => v,
                Err(_) => return 0,
            },
            first_bytes: [0u8; 256],
        };
        if bpf_probe_read_user_buf(buf as *const u8, &mut sample.first_bytes[..take]).is_err() {
            if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_READ_FAIL) {
                *slot += 1;
            }
            return 0;
        }
        if SOCK_EVENTS.push(&sample, 0).is_ok() {
            if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_OK) {
                *slot += 1;
            }
        } else if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
            *slot += 1;
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
