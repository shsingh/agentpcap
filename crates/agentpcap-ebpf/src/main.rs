// The agentpcap probe. The alpha1 canary: a tracepoint on the write
// syscall that increments an observable counter per invocation.
// The ring-buffer data plane lands with the collector slice.
#![no_std]
#![no_main]

use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::Array;
use aya_ebpf::programs::TracePointContext;

#[map(name = "events")]
static mut EVENTS: Array<u64> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn agentpcap(_ctx: TracePointContext) -> i64 {
    unsafe {
        if let Some(ptr) = EVENTS.get_ptr_mut(0) {
            *ptr += 1;
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
