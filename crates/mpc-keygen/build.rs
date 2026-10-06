//! # Build Script for Protocol Buffers Compilation
//!
//! This build script is executed by Cargo before compiling the `mpc-keygen` crate.
//! Its sole responsibility is to compile the `node_ext.proto` definition file into 
//! strongly-typed Rust code using `tonic` and `prost`.
//!
//! ## Architecture Note
//! The `mpc-keygen` tool acts exclusively as a gRPC **Client** when communicating 
//! with the MPC nodes to trigger DKG ceremonies. Therefore, we explicitly disable 
//! server code generation (`build_server(false)`) to reduce compilation time, 
//! binary size, and the attack surface of unused code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure() 
        // The keygen tool only makes outbound gRPC calls to the nodes.
        .build_server(false)
        // Generate the client stubs required to invoke the admin RPCs.
        .build_client(true)
        // Compile the specific proto file, using the `proto/` directory as the include path.
        .compile_protos(&["proto/node_ext.proto"], &["proto/"])?; 
    Ok(())
}


