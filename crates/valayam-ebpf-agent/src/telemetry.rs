use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum TelemetryEvent {
    ProcessExecution {
        pid: u32,
        command: String,
        args: Vec<String>,
        user_id: u32,
    },
    NetworkConnection {
        pid: u32,
        source_ip: String,
        source_port: u16,
        dest_ip: String,
        dest_port: u16,
        protocol: String,
    },
    FileAccess {
        pid: u32,
        file_path: String,
        access_type: String, // "READ", "WRITE", "EXECUTE"
    },
}
