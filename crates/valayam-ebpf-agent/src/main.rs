pub mod grpc;
pub mod telemetry;

use crate::grpc::valayam::scanner_client::ScannerClient;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[cfg(target_os = "linux")]
use aya::programs::KProbe;
#[cfg(target_os = "linux")]
use aya::Ebpf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting Valayam eBPF Agent...");

    // Setup gRPC client
    let mut client = ScannerClient::connect("http://127.0.0.1:50051").await?;
    println!("[*] Connected to Valayam Engine gRPC server.");

    let (_tx, rx) = mpsc::channel(100);

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
        // In a real Linux environment, we load the compiled BPF bytecode
        // let mut bpf = Ebpf::load_file("valayam_ebpf_programs.o")?;
        // let program: &mut KProbe = bpf.program_mut("sys_execve").unwrap().try_into()?;
        // program.load()?;
        // program.attach("sys_execve", 0)?;
        //
        // Then we'd read from a PerfEventArray and send to the `tx` channel.
        // For now, this is a placeholder.
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("[!] Non-Linux OS detected. eBPF framework (Aya) is only supported on Linux.");
        eprintln!("[!] Exiting eBPF agent...");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    loop {
        // eBPF telemetry generation will go here.
        // For now, keep the agent alive.
        sleep(Duration::from_secs(5)).await;
    }

    Ok(())
}
