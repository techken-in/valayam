pub mod grpc;
pub mod telemetry;

use crate::grpc::valayam::scanner_client::ScannerClient;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[cfg(target_os = "linux")]
use aya::{maps::perf::AsyncPerfEventArray, programs::TracePoint, util::online_cpus, Ebpf};
#[cfg(target_os = "linux")]
use bytes::BytesMut;
use std::time::Duration;
use tokio::time::sleep;

#[cfg(target_os = "linux")]
use valayam_ebpf_agent_common::ProcessEvent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting Valayam eBPF Agent...");

    // Setup gRPC client
    let mut client = ScannerClient::connect("http://127.0.0.1:50051").await?;
    println!("[*] Connected to Valayam Engine gRPC server.");

    let (tx, rx) = mpsc::channel(100);

    // Spawn a task to send the stream
    tokio::spawn(async move {
        let stream = ReceiverStream::new(rx);
        if let Err(e) = client.stream_telemetry(stream).await {
            eprintln!("[!] gRPC stream error: {}", e);
        }
    });

    #[cfg(target_os = "linux")]
    {
        println!("[*] Loading eBPF programs...");

        // This bytecode will be loaded at runtime.
        // In a production environment, include_bytes_aligned! would be used.
        let mut bpf = Ebpf::load_file(
            "valayam-ebpf-agent-ebpf/target/bpfel-unknown-none/debug/valayam-ebpf-agent-ebpf",
        )?;

        let program: &mut TracePoint = bpf.program_mut("sys_enter_execve").unwrap().try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")?;
        println!("[*] eBPF TracePoint attached to syscalls:sys_enter_execve");

        let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

        for cpu_id in online_cpus()? {
            let mut buf = perf_array.open(cpu_id, None)?;
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        let ptr = buf.as_ptr() as *const ProcessEvent;
                        let data = unsafe { ptr.read_unaligned() };

                        let comm = String::from_utf8_lossy(&data.comm)
                            .trim_matches(char::from(0))
                            .to_string();
                        let filename = String::from_utf8_lossy(&data.filename)
                            .trim_matches(char::from(0))
                            .to_string();

                        println!(
                            "[eBPF] Process Executed: {} (PID: {}) -> {}",
                            comm, data.pid, filename
                        );

                        // We would send this over gRPC!
                        let pb_event = crate::grpc::valayam::TelemetryData {
                            node_id: "ebpf-node-1".to_string(),
                            timestamp: chrono::Utc::now().timestamp(),
                            event_type: "ProcessExecution".to_string(),
                            payload: format!(
                                "PID: {}, CMD: {}, FILE: {}",
                                data.pid, comm, filename
                            )
                            .into_bytes(),
                        };
                        let _ = tx.send(pb_event).await;
                    }
                }
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("[!] Non-Linux OS detected. eBPF framework (Aya) is only supported on Linux.");
        eprintln!("[!] Exiting eBPF agent...");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    loop {
        sleep(Duration::from_secs(5)).await;
    }

    Ok(())
}
