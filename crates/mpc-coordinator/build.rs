//! # Build Script for Protocol Buffers Compilation
//!
//! This build script is executed by Cargo before compiling the `mpc-coordinator` crate.
//! Its sole responsibility is to compile the `.proto` definition files into 
//! strongly-typed Rust code using `tonic` and `prost`.
//!
//! ## Architecture Note
//! The `mpc-coordinator` acts exclusively as a gRPC **Server** in this relationship.
//! It receives requests from the `mpc-api` gateway, `mpc-cli` administrative tool, 
//! and `mpc-node` participants. Therefore, we explicitly disable client code 
//! generation (`build_client(false)`) to reduce compilation time, binary size, 
//! and the attack surface of unused code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the tonic-prost-build compiler
    tonic_prost_build::configure()
        // The Coordinator serves the RPCs; it does not make outbound gRPC calls 
        // to itself. Generate server trait implementations.
        .build_server(true)
        // Do not generate client stubs, as the Coordinator is the server endpoint.
        .build_client(false)
        // Compile the specific proto file, using the `proto/` directory as the include path.
        .compile_protos(&["proto/coordinator.proto"], &["proto/"])?;
        
    Ok(())
}

