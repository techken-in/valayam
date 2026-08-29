#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16], // TASK_COMM_LEN is 16
    pub filename: [u8; 128], // Truncated filename for simplicity
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}
