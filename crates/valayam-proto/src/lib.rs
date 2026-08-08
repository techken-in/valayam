//! Shared proto definitions for the Valayam workspace.
//!
//! This crate is the single source of truth for all gRPC protobuf definitions.
//! All other crates depend on this one instead of compiling their own protos.

/// Core Valayam scanner RPCs — scan, telemetry, and control plane.
pub mod valayam {
    tonic::include_proto!("valayam");
}

/// Plugin service RPCs — external plugin lifecycle (init, execute, shutdown).
pub mod plugin {
    tonic::include_proto!("valayam.plugin");
}

/// gRPC server reflection protocol.
pub mod reflection {
    pub mod v1 {
        tonic::include_proto!("grpc.reflection.v1");
    }
}

/// Compiled file descriptor set for gRPC server reflection.
pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("proto_descriptor");
