//! # Build Script for Protocol Buffers Compilation
//!
//! This build script is executed by Cargo before compiling the `mpc-protocol` crate.
//! Its sole responsibility is to compile the `mpc.proto` definition file into 
//! strongly-typed Rust code using `tonic` and `prost`.
//!
//! ## Architecture Note
//! The `mpc-protocol` crate is a shared library used by both `mpc-node` and 
//! `mpc-coordinator`. Since both components act as both gRPC clients and servers 
//! depending on the specific RPC (e.g., nodes are servers for `MpcNode` but clients 
//! for `MpcCoordinator`), we explicitly enable both server and client code generation.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        // Generate server trait implementations (used by mpc-node and mpc-coordinator)
        .build_server(true)
        // Generate client stubs (used by mpc-node to talk to coordinator, and vice versa)
        .build_client(true)
        // Compile the specific proto file, using the `proto/` directory as the include path.
        .compile_protos(&["src/proto/mpc.proto"], &["proto/"])?; 
    Ok(())
}

