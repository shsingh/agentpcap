// The agentpcap probe. The alpha1 canary: a kprobe on the write
// syscall path that emits one observable marker per invocation.
// The ring-buffer data plane lands with the collector slice.
#![no_std]
#![no_main]

use aya_ebpf::programs::ProbeContext;
use aya_ebpf::macros::kprobe;
use aya_ebpf::bpf_printk;

#[kprobe]
pub fn agentpcap(_ctx: ProbeContext) -> i64 {
    bpf_printk!("canary-agentpcap-p000");
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
