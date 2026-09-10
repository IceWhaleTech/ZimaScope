//! ZimaScope eBPF object entry points.

#![no_std]
#![no_main]

mod maps;
mod tc;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Safety: the eBPF program must not unwind; any panic is a bug.
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
