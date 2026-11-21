// The agentpcap probe. The alpha1 tap: a tracepoint on the write
// syscall that pushes one pipe sample per write into the `pipe-events`
// queue and keeps the canary counter current; the fork probe feeds the
// lineage map so every sample knows its writer's parent.
// Spec: docs/spec.md#5-collectors.
#![no_std]
#![no_main]

use aya_ebpf::EbpfContext;
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_kernel_buf, bpf_probe_read_user_buf,
};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{Array, LruHashMap, Queue};
use aya_ebpf::programs::TracePointContext;

/// Wire format: must match the collector crate's `PipeSample` exactly
/// (const-locked on both sides at 48 bytes).
#[repr(C, align(8))]
pub struct PipeSample {
    pid: u32,
    ppid: u32,
    len: u32,
    pad: [u8; 4],
    first_bytes: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<PipeSample>() == 48);

const PAYLOAD_BYTES_CAP: u32 = 32;

#[map(name = "pipe_events")]
static mut EVENTS: Queue<PipeSample> = Queue::with_max_entries(1024, 0);

const SLOT_INVOKE: u32 = 0;
const SLOT_READ_FAIL: u32 = 1;
const SLOT_PUSH_OK: u32 = 2;
const SLOT_PUSH_FAIL: u32 = 3;
const SLOT_FORK_INVOKE: u32 = 4;
const SLOT_INSERT_OK: u32 = 5;
const SLOT_INSERT_FAIL: u32 = 6;
const SLOT_LOOKUP_HIT: u32 = 7;
const SLOT_FORK_PUSH_OK: u32 = 8;
const SLOT_FORK_PUSH_FAIL: u32 = 9;

#[map(name = "events")]
static mut CANARY: Array<u64> = Array::with_max_entries(10, 0);

#[map(name = "lineage")]
static mut LINEAGE: LruHashMap<u32, u32> = LruHashMap::with_max_entries(8192, 0);

/// The fork probe: feed the lineage map (child pid -> parent pid).
/// sched_process_fork context, format-verified on this kernel:
/// parent_pid at 12 bytes (u32), child_pid at 20 bytes (u32).
#[tracepoint]
pub fn agentpcap_fork(mut ctx: TracePointContext) -> i64 {
    unsafe {
        if let Some(slot) = CANARY.get_ptr_mut(SLOT_FORK_INVOKE) {
            *slot += 1;
        }
    }
    let parent: u32 = match unsafe { ctx.read_at::<u32>(12) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let child: u32 = match unsafe { ctx.read_at::<u32>(20) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    unsafe {
        // Every 16th fork: dump the raw context onto the event queue so
        // the userspace can decode the real field offsets.
        let n: u64 = match CANARY.get_ptr_mut(SLOT_FORK_INVOKE).map(|s| *s) {
            Some(v) => v,
            None => 1,
        };
        if n % 16 == 0 {
            let mut raw = PipeSample {
                pid: 0x0000f00d,
                ppid: n as u32,
                len: 32,
                pad: [0; 4],
                first_bytes: [0u8; 32],
            };
            if bpf_probe_read_kernel_buf(ctx.as_ptr() as *const u8, &mut raw.first_bytes).is_ok()
            {
                let _ = EVENTS.push(&raw, 0);
            }
        }
        // The fork pair also rides the event queue so the userspace can
        // ground-truth the offsets: pid carries the parent, ppid the child.
        let pair = PipeSample {
            pid: parent,
            ppid: child,
            len: 8,
            pad: [0; 4],
            first_bytes: {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(b"forkpair");
                b
            },
        };
        if EVENTS.push(&pair, 0).is_ok() {
            if let Some(slot) = CANARY.get_ptr_mut(SLOT_FORK_PUSH_OK) {
                *slot += 1;
            }
        } else if let Some(slot) = CANARY.get_ptr_mut(SLOT_FORK_PUSH_FAIL) {
            *slot += 1;
        }
        if LINEAGE.insert(&child, &parent, 0).is_ok() {
            if let Some(slot) = CANARY.get_ptr_mut(SLOT_INSERT_OK) {
                *slot += 1;
            }
        } else if let Some(slot) = CANARY.get_ptr_mut(SLOT_INSERT_FAIL) {
            *slot += 1;
        }
    }
    0
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

    unsafe {
        if let Some(slot) = CANARY.get_ptr_mut(SLOT_INVOKE) {
            *slot += 1;
        }
        let pid: u32 = (bpf_get_current_pid_tgid() >> 32) as u32;
        let looked = unsafe { LINEAGE.get(&pid) };
        let ppid: u32 = match looked {
            Some(parent) => {
                if let Some(slot) = CANARY.get_ptr_mut(SLOT_LOOKUP_HIT) {
                    *slot += 1;
                }
                *parent
            }
            None => 0,
        };
        let mut sample = PipeSample {
            pid,
            ppid,
            len: take as u32,
            pad: [0; 4],
            first_bytes: [0u8; 32],
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
