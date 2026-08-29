#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_current_comm},
};
use valayam_ebpf_agent_common::ProcessEvent;

#[map(name = "EVENTS")]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let filename_ptr: *const u8 = unsafe { ctx.read_at(16).map_err(|_| 0u32)? };
    
    let mut filename = [0u8; 128];
    let _ = unsafe { aya_ebpf::helpers::bpf_probe_read_user_str_bytes(filename_ptr as *const _, &mut filename) };

    let event = ProcessEvent {
        pid,
        ppid: 0,
        uid,
        comm,
        filename,
    };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
