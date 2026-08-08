//! Build script for valayam-proto — single source of truth for all .proto compilation.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("proto_descriptor.bin");

    println!("cargo:rerun-if-changed=proto/valayam.proto");
    println!("cargo:rerun-if-changed=proto/plugin.proto");
    println!("cargo:rerun-if-changed=proto/reflection.proto");
    println!("cargo:rerun-if-changed=proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(descriptor_path)
        .compile(
            &[
                "proto/valayam.proto",
                "proto/plugin.proto",
                "proto/reflection.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
