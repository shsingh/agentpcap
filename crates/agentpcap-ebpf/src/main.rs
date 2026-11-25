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
use aya_ebpf::macros::{map, tracepoint, uretprobe, uprobe};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext, TracePointContext};

/// Wire format: must match the collector crate's `PipeSample` exactly
/// (const-locked on both sides at 48 bytes).
/// On the socket class the `ppid` field carries the DIRECTION face:
/// 1 = receive, 0 = send (the pipe class keeps ppid = 0: its lineage
/// resolves userspace-side). The face never rides the pipe samples.
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
static mut EVENTS: RingBuf = RingBuf::with_byte_size(4194304, 0);

// The socket class rides the same wire; the class comes from the map
// (ADR-0005), not from a wire discriminant.
#[map(name = "sock_events")]
static mut SOCK_EVENTS: RingBuf = RingBuf::with_byte_size(4194304, 0);

/// The saved-receive face: one entry per thread, the exit probe reads
/// and pops it. The capture runs at EXIT — the entry-time buffer
/// carries whatever the caller's last message left behind.
#[map(name = "recv_pending")]
static mut RECV_PENDING: HashMap<u64, SavedRecv> = HashMap::with_max_entries(8192, 0);

#[repr(C, align(8))]
pub struct SavedRecv {
    ubuf: u64,
    fd: u32,
    cap: u32,
}

const _: () = assert!(core::mem::size_of::<SavedRecv>() == 16);

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

// The raw binding face: fn id 120 (the kernel's bpf_get_ns_current_pid_tgid);
// aya-ebpf 0.3.0 has no generated wrapper for it, so call through its
// own helper table via the crate's binding module.
#[repr(C)]
pub struct BpfPidnsInfo {
    pub pid: u32,
    pub tgid: u32,
}

unsafe fn ns_current_pid_tgid(dev: u64, ino: u64, nsdata: *mut BpfPidnsInfo) -> i64 {
    type Fun = unsafe extern "C" fn(u64, u64, *mut BpfPidnsInfo, u32) -> i64;
    let fun: Fun = core::mem::transmute(120usize);
    fun(dev, ino, nsdata, core::mem::size_of::<BpfPidnsInfo>() as u32)
}

// The pid-namespace face (issue #106): the tap writes its own pid-ns
// identity (new_encode_dev(dev), ino) at boot; the helper's ns_match
// compares against the writer's own pid namespace (kernel/bpf/helpers.c),
// so same-namespace writers translate /proc-true and the userspace
// faces (readlink, pidfd_open) read under one pid space. Writers
// outside this pid ns ride the raw tgid — the faces unchanged.
#[map(name = "ns_config")]
static mut NS_CONFIG: Array<u64> = Array::with_max_entries(2, 0);

/// The namespace-visible tgid face, read through the pid-ns identity the
/// tap publishes at boot. The helper gates on the writer's own pid
/// namespace, so writers outside it ride the raw tgid unchanged.
fn ns_tgid() -> u32 {
    let dev = unsafe { match NS_CONFIG.get(0) { Some(v) => *v, None => 0 } };
    let ino = unsafe { match NS_CONFIG.get(1) { Some(v) => *v, None => 0 } };
    if dev == 0 || ino == 0 {
        return unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 };
    }
    let mut info = BpfPidnsInfo { pid: 0, tgid: 0 };
    let rc = unsafe { ns_current_pid_tgid(dev, ino, &mut info as *mut BpfPidnsInfo) };
    if rc == 0 { info.tgid } else { unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 } }
}

// The ADR-0003 capture filter, shared by the pipe and the socket taps:
// the calibration sentinel, or `{` plus the `jsonrpc` member within the
// first 40 bytes with the leading whitespace skipped.
#[inline(always)]
#[inline(never)]
fn candidate(buf: *const u8, avail: usize) -> bool {
    unsafe {
        let mut sniff: [u8; 40] = [0u8; 40];
        // the sniff bounds by the bytes the syscall actually used: a
        // short payload never reads past its own buffer page
        let probe = avail.min(40);
        if probe == 0 {
            return false;
        }
        let mut sniff_probed = [0u8; 40];
        if bpf_probe_read_user_buf(
            buf,
            &mut sniff_probed[..probe],
        )
        .is_err()
        {
            return false;
        }
        sniff[..probe].copy_from_slice(&sniff_probed[..probe]);
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
        while k + 7 <= probe {
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
            // the calibration sentinel rides — its own admission face:
            // the tap may sit outside the selected cgroup, and the
            // sentinel is how the offset face learns at all
        } else {
            if !cgroup_allowed() {
                return 0;
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
            pid: ns_tgid(),
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
        match EVENTS.reserve::<PipeSample>(0) {
            Some(mut entry) => {
                *entry = core::mem::MaybeUninit::new(sample);
                entry.submit(0);
                if let Some(slot) = CANARY.get_ptr_mut(SLOT_PUSH_OK) {
                    *slot += 1;
                }
            }
            None => {
                if let Some(slot) = CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
                    *slot += 1;
                }
            }
        }
    }
    0
}

/// The socket-class tap: `sys_enter_sendto` (the TCP-send face; the
/// kernel's `send` rides `sendto` with a null addr) and the receive
/// face mirrors it on `sys_enter_recvfrom` (ADR-0005). Format verified
/// on this kernel 7.2.12: fd at 16, ubuf at 24, size at 32.
/// The send ENTRY face: park the buffer coordinates per thread.
#[tracepoint]
pub fn agentpcap_socket(mut ctx: TracePointContext) -> i64 {
    // the cgroup gate rides BEFORE the park: excluded workloads never
    // fill the shared map, an allowed thread's park never fails
    if !cgroup_allowed() {
        return 0;
    }
    let buf: u64 = match unsafe { ctx.read_at::<usize>(24) }.map(|v| v as u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let fd: u32 = match unsafe { ctx.read_at::<u32>(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let cap: u32 = match unsafe { ctx.read_at::<usize>(32) }.map(|v| v as u32) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let key = unsafe { bpf_get_current_pid_tgid() };
    let saved = SavedRecv { ubuf: buf, fd, cap };
    unsafe {
        if RECV_PENDING.insert(&key, &saved, 0).is_err() {
            // a lost park means a lost send: the loss stays visible
            if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
                *slot += 1;
            }
        }
    }
    0
}

/// The send EXIT face: a positive return names the bytes the kernel
/// accepted — a failed or partial send never becomes a call.
#[tracepoint]
pub fn agentpcap_send_exit(mut ctx: TracePointContext) -> i64 {
    unsafe {
        if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_INVOKE) {
            *slot += 1;
        }
        let id = bpf_get_current_cgroup_id();
        let _ = CGROUP_SEEN.set(0, &id, 0);
    }
    let key = unsafe { bpf_get_current_pid_tgid() };
    let saved = match unsafe { RECV_PENDING.get(&key) } {
        Some(entry) => SavedRecv {
            ubuf: entry.ubuf,
            fd: entry.fd,
            cap: entry.cap,
        },
        None => return 0,
    };
    unsafe {
        let _ = RECV_PENDING.remove(&key);
    }
    if !cgroup_allowed() {
        return 0;
    }
    // the syscall-exit face: the return value rides offset 16
    let ret: i64 = match unsafe { ctx.read_at::<i64>(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if ret <= 0 {
        return 0;
    }
    let take = (ret as u64 as usize)
        .min(saved.cap as usize)
        .min(PAYLOAD_BYTES_CAP as usize);
    unsafe {
        if take == 0 || saved.ubuf == 0 {
            return 0;
        }
        if !candidate(saved.ubuf as *const u8, take) {
            return 0;
        }
        let mut sample = PipeSample {
            pid: ns_tgid(),
            ppid: 0,
            len: take as u32,
            fd: saved.fd,
            first_bytes: [0u8; 256],
        };
        if bpf_probe_read_user_buf(saved.ubuf as *const u8, &mut sample.first_bytes[..take])
            .is_err()
        {
            if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_READ_FAIL) {
                *slot += 1;
            }
            return 0;
        }
        match SOCK_EVENTS.reserve::<PipeSample>(0) {
            Some(mut entry) => {
                *entry = core::mem::MaybeUninit::new(sample);
                entry.submit(0);
                if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_OK) {
                    *slot += 1;
                }
            }
            None => {
                if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
                    *slot += 1;
                }
            }
        }
    }
    0
}


#[tracepoint]
pub fn agentpcap_recv_enter(mut ctx: TracePointContext) -> i64 {
    unsafe {
        // the invoke face lives before the gate: health stays
        // independent of the filter
        if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_INVOKE) {
            *slot += 1;
        }
        let id = bpf_get_current_cgroup_id();
        let _ = CGROUP_SEEN.set(0, &id, 0);
    }
    // the cgroup gate rides BEFORE the park: unrelated hosts' threads
    // never fill the map
    if !cgroup_allowed() {
        return 0;
    }
    let buf: u64 = match unsafe { ctx.read_at::<usize>(24) }.map(|v| v as u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let fd: u32 = match unsafe { ctx.read_at::<u32>(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let cap: u32 = match unsafe { ctx.read_at::<usize>(32) }.map(|v| v as u32) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // the MSG_PEEK face: a peeked receive consumes nothing - the later
    // consuming call owns the capture, one read per request
    let flags: u32 = match unsafe { ctx.read_at::<u32>(40) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if flags & 2 != 0 {
        return 0; // MSG_PEEK = 2
    }
    // the FULL pid_tgid: the low 32 bits name the thread, so
    // concurrent recvfrom calls on one process never overwrite each
    // other's parked coordinates
    let key = unsafe { bpf_get_current_pid_tgid() };
    let saved = SavedRecv { ubuf: buf, fd, cap };
    unsafe {
        if RECV_PENDING.insert(&key, &saved, 0).is_err() {
            // a lost park means a lost receive: the loss stays visible
            if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
                *slot += 1;
            }
        }
    }
    0
}

/// The receive EXIT face: a positive `ret` names the bytes the kernel
/// actually filled — capture bounded by that value, from the parked
/// buffer address, and drop the park either way.
#[tracepoint]
pub fn agentpcap_recv_exit(mut ctx: TracePointContext) -> i64 {
    unsafe {
        if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_INVOKE) {
            *slot += 1;
        }
        let id = bpf_get_current_cgroup_id();
        let _ = CGROUP_SEEN.set(0, &id, 0);
    }
    // the same full pid_tgid the entry face parked: the exit face
    // reads ITS own thread's coordinates and pops them
    let key = unsafe { bpf_get_current_pid_tgid() };
    let saved = match unsafe { RECV_PENDING.get(&key) } {
        Some(entry) => SavedRecv {
            ubuf: entry.ubuf,
            fd: entry.fd,
            cap: entry.cap,
        },
        None => return 0,
    };
    unsafe {
        let _ = RECV_PENDING.remove(&key);
    }
    if !cgroup_allowed() {
        return 0;
    }
    // the syscall-exit face: the return value rides offset 16 (the
    // repository's exit-tracepoint receipt)
    let ret: i64 = match unsafe { ctx.read_at::<i64>(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if ret <= 0 {
        return 0;
    }
    // the copy bounds BOTH by the bytes the kernel filled and by the
    // requested capacity — never past the caller's own buffer
    let take = (ret as u64 as usize)
        .min(saved.cap as usize)
        .min(PAYLOAD_BYTES_CAP as usize);
    unsafe {
        if take == 0 || saved.ubuf == 0 {
            return 0;
        }
        if !candidate(saved.ubuf as *const u8, take) {
            return 0;
        }
        let mut sample = PipeSample {
            pid: ns_tgid(),
            ppid: 1, // the receive direction face (the send faces ride 0)
            len: take as u32,
            fd: saved.fd,
            first_bytes: [0u8; 256],
        };
        if bpf_probe_read_user_buf(saved.ubuf as *const u8, &mut sample.first_bytes[..take]).is_err()
        {
            if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_READ_FAIL) {
                *slot += 1;
            }
            return 0;
        }
        match SOCK_EVENTS.reserve::<PipeSample>(0) {
            Some(mut entry) => {
                *entry = core::mem::MaybeUninit::new(sample);
                entry.submit(0);
                if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_OK) {
                    *slot += 1;
                }
            }
            None => {
                if let Some(slot) = SOCK_CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
                    *slot += 1;
                }
            }
        }
    }
    0
}

// The TLS-boundary tap (spec section 8/Modes, ADR-0006): uprobes on the
// host TLS library's SSL_write and SSL_read capture the plaintext
// before encryption. The plaintext bytes ride the same 272-byte wire
// as one fd-less sample (the fd = 0 face): the peer resolves through
// the writer's /proc fd scan, never the ssl struct. The class rides
// the `tls_events` map.
#[map(name = "tls_events")]
static mut TLS_EVENTS: RingBuf = RingBuf::with_byte_size(4194304, 0);

#[map(name = "tls_canary")]
static mut TLS_CANARY: Array<u64> = Array::with_max_entries(6, 0);

const SLOT_CGID: u32 = 4;
const SLOT_PENDING_LOSS: u32 = 5;

/// The parked TLS call: SSL_read_ex/SSL_write_ex carry their buffer at
/// x1 and the accepted-count pointer at x3 — the count only answers at
/// the RETURN face, so the entry never captures. The tgid rides the
/// entry: slots identify their owner, a foreign collect never consumes
/// another thread's park.
#[repr(C, align(8))]
pub struct SavedTls {
    ubuf: u64,
    wptr: u64,
    // The writer's namespace-visible pid (the ns face, issue #106):
    // the userspace bounded-cleanup sweep reads it — the key's pid
    // half stays kernel-space (the raw tgid) and never translates.
    ns_pid: u32,
}

const _: () = assert!(core::mem::size_of::<SavedTls>() == 24);

#[map(name = "tls_pending")]
static mut TLS_PENDING: HashMap<u64, SavedTls> = HashMap::with_max_entries(8192, 0);

#[uprobe]
pub fn agentpcap_tls_write(mut ctx: ProbeContext) -> i64 {
    // SSL_write_ex(ssl, buf, num, *written): park the coordinates —
    // the capture only collects at the return face, so a retried or
    // failed write never parks a call before any byte is accepted
    tls_park(&mut ctx)
}

#[uretprobe]
pub fn agentpcap_tls_write_ret(ctx: RetProbeContext) -> i64 {
    // the send face rides ppid 0 (the probe-face evidence keys send)
    tls_collect(ctx.ret(), 0)
}

#[uprobe]
pub fn agentpcap_tls_read(mut ctx: ProbeContext) -> i64 {
    // SSL_read_ex(ssl, buf, num, *written): the buffer is EMPTY at
    // entry — the destination never answers at the entry face, so the
    // read only collects after the call fills it
    tls_park(&mut ctx)
}

#[uretprobe]
pub fn agentpcap_tls_read_ret(ctx: RetProbeContext) -> i64 {
    // the receive face rides ppid 1 (the probe-face evidence keys it,
    // the shared endpoint face rides it both ways)
    tls_collect(ctx.ret(), 1)
}

/// The shared park: the cgroup gate rides before the parking (only the
/// calibrated scope ever fills the pending map); a lost park means a
/// lost observation and stays visible in the canary.
fn tls_park(ctx: &mut ProbeContext) -> i64 {
    unsafe {
        // the invoke counter lives before the cgroup gate, and the
        // cgroup id rides its own slot (it never overwrites the count)
        if let Some(slot) = TLS_CANARY.get_ptr_mut(SLOT_INVOKE) {
            *slot += 1;
        }
        let id = bpf_get_current_cgroup_id();
        let _ = TLS_CANARY.set(SLOT_CGID, &id, 0);
        if !cgroup_allowed() {
            return 0;
        }
        let ubuf: usize = match ctx.arg(1) {
            Some(v) => v,
            None => return 0,
        };
        let wptr: usize = match ctx.arg(3) {
            Some(v) => v,
            None => return 0,
        };
        if ubuf == 0 || wptr == 0 {
            return 0;
        }
        // the FULL pid_tgid keys the entry: two live threads own
        // disjoint keys — their parks and collects never mix. A thread
        // killed inside its call leaks its key; the tap sweeps dead
        // pids out of the map periodically (the bounded-cleanup face)
        let key = bpf_get_current_pid_tgid();
        let saved = SavedTls {
            ubuf: ubuf as u64,
            wptr: wptr as u64,
            ns_pid: ns_tgid(),
        };
        if TLS_PENDING.insert(&key, &saved, 0).is_err() {
            if let Some(slot_c) = TLS_CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
                *slot_c += 1;
            }
        }
    }
    0
}

/// The shared collect: the return value rides x0 at the return
/// address (the EX faces answer 1 on success); the accepted count
/// rides the caller's *written pointer. The capture bounds by the
/// bytes the call ACCEPTED — never by the requested capacity, never
/// at the entry face. The admission carries the JSON face AND the
/// HTTP framed face: an HTTPS client rides headers and a JSON body
/// in one buffer, and `POST ...` never passes the bare-JSON filter.
fn tls_collect(ret: i32, is_read: u32) -> i64 {
    let key = unsafe { bpf_get_current_pid_tgid() };
    let entry = match unsafe { TLS_PENDING.get(&key) } {
        Some(e) => SavedTls {
            ubuf: e.ubuf,
            wptr: e.wptr,
            ns_pid: e.ns_pid,
        },
        None => return 0,
    };
    unsafe {
        let _ = TLS_PENDING.remove(&key);
    }
    let (ubuf, wptr) = (entry.ubuf, entry.wptr);
    if !cgroup_allowed() {
        return 0;
    }
    if ret != 1 {
        // a failed or retried attempt collected nothing: the retry
        // parks again and only the accepted bytes capture
        return 0;
    }
    let count: u64 = match unsafe { aya_ebpf::helpers::bpf_probe_read_user(wptr as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let take = (count as usize).min(PAYLOAD_BYTES_CAP as usize);
    if take == 0 || ubuf == 0 {
        return 0;
    }
    unsafe {
        let buf = ubuf as *const u8;
        // the admission faces read their own small frames (40 or 8
        // bytes); the sample buffer reads once, directly into the wire
        // struct — the collect frame never holds two byte arrays
        if !candidate(buf, take) && !http_prefix(buf) {
            return 0;
        }
        let mut sample = PipeSample {
            pid: ns_tgid(),
            ppid: is_read,
            len: take as u32,
            fd: 0,
            first_bytes: [0u8; 256],
        };
        if bpf_probe_read_user_buf(buf, &mut sample.first_bytes[..take]).is_err() {
            if let Some(slot) = TLS_CANARY.get_ptr_mut(SLOT_READ_FAIL) {
                *slot += 1;
            }
            return 0;
        }
        match TLS_EVENTS.reserve::<PipeSample>(0) {
            Some(mut entry) => {
                *entry = core::mem::MaybeUninit::new(sample);
                entry.submit(0);
                if let Some(slot) = TLS_CANARY.get_ptr_mut(SLOT_PUSH_OK) {
                    *slot += 1;
                }
            }
            None => {
                if let Some(slot) = TLS_CANARY.get_ptr_mut(SLOT_PUSH_FAIL) {
                    *slot += 1;
                }
            }
        }
    }
    0
}

/// The HTTP framing face: the method or status prefixes the body —
/// the userspace classifier trims to the body's first brace, the
/// boundary only needs the buffer admitted. Fixed 8-byte compares
/// keep the verifier satisfied.
#[inline(never)]
fn http_prefix(buf: *const u8) -> bool {
    let mut head = [0u8; 8];
    unsafe {
        if bpf_probe_read_user_buf(buf, &mut head).is_err() {
            return false;
        }
    }
    starts_with(head, b"POST", true)
        || starts_with(head, b"GET", true)
        || starts_with(head, b"PUT", true)
        || starts_with(head, b"PATCH", false)
        || starts_with(head, b"HEAD", true)
        || starts_with(head, b"DELETE", false)
        || starts_with(head, b"HTTP/", false)
}

#[inline(never)]
fn starts_with(head: [u8; 8], m: &[u8], then_space: bool) -> bool {
    if m.len() + usize::from(then_space) > head.len() {
        return false;
    }
    let mut ok = true;
    for (i, c) in m.iter().enumerate() {
        if head[i] != *c {
            ok = false;
        }
    }
    if then_space {
        ok && head[m.len()] == b' '
    } else {
        ok
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
