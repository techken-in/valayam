#![no_std]
#![no_main]

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
    maps::PerfEventArray,
};
use aya_log_ebpf::info;

#[map]
pub static mut EVENTS: PerfEventArray<[u8; 256]> = PerfEventArray::with_max_entries(1024, 0);

#[kprobe]
pub fn sys_execve(ctx: ProbeContext) -> u32 {
    match try_sys_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_execve(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "sys_execve called");
    
    let mut payload = [0u8; 256];
    payload[0] = 1; // Event type: execve

    // Read PID / TGID (lower 32 bits is PID, upper 32 bits TGID)
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFF_FFFF) as u32;
    payload[1..5].copy_from_slice(&pid.to_le_bytes());

    // Read current comm (process name, up to 16 bytes)
    if let Ok(comm) = aya_ebpf::helpers::bpf_get_current_comm() {
        let len = comm.len().min(16);
        payload[5..5 + len].copy_from_slice(&comm[..len]);
    }

    unsafe {
        EVENTS.output(&ctx, &payload, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
