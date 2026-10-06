//! # Build Script for Protocol Buffers Compilation
//!
//! This build script is executed by Cargo before compiling the `mpc-api` crate.
//! Its sole responsibility is to compile the `.proto` definition files into 
//! strongly-typed Rust code using `tonic` and `prost`.
//!
//! ## Architecture Note
//! The `mpc-api` gateway acts exclusively as a **gRPC Client** when communicating 
//! with the `mpc-coordinator`. Therefore, we explicitly disable server code 
//! generation (`build_server(false)`) to reduce compilation time, binary size, 
//! and the attack surface of unused code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the tonic-prost-build compiler
    tonic_prost_build::configure() 
        // The API gateway only calls the coordinator; it does not serve gRPC requests.
        .build_server(false)
        // Generate the client stubs required to make RPC calls to the coordinator.
        .build_client(true)
        // Compile the specific proto file, using the `proto/` directory as the include path.
        .compile_protos(&["proto/coordinator.proto"], &["proto/"])?;
        
    Ok(())
}
