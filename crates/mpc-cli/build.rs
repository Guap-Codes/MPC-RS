//! # Build Script for Protocol Buffers Compilation
//!
//! This build script is executed by Cargo before compiling the `mpc-cli` crate.
//! Its sole responsibility is to compile the `.proto` definition files into 
//! strongly-typed Rust code using `tonic` and `prost`.
//!
//! ## Architecture Note
//! The `mpc-cli` acts as an administrative gRPC **Client** when communicating 
//! with the `mpc-coordinator`. This script generates the necessary client stubs 
//! and message types required to invoke administrative RPCs (e.g., key generation, 
//! status checks, emergency drains).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the coordinator.proto file. 
    // By default, tonic-prost-build generates both client and server code.
    // The CLI will primarily utilize the generated client stubs to communicate 
    // with the Coordinator service.
    tonic_prost_build::compile_protos("proto/coordinator.proto")?;
    Ok(())
}


