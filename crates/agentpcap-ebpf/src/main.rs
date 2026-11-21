// The agentpcap probe. The alpha1 canary: a kprobe on the write
// syscall path that increments an observable counter per invocation.
// The ring-buffer data plane lands with the collector slice.
#![no_std]
#![no_main]

use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::ProbeContext;

#[map(name = "events")]
static mut EVENTS: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[kprobe]
pub fn agentpcap(_ctx: ProbeContext) -> i64 {
    unsafe {
        if let Some(ptr) = EVENTS.get_ptr_mut(&0u32) {
            *ptr += 1;
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
