
//! # MPC Protocol: Secure Networking and Session Management
//!
//! This crate provides the foundational networking layer for the Multi-Party 
//! Computation (MPC) system. It defines the gRPC service interfaces, manages 
//! mutual TLS (mTLS) transport, and provides a robust session runner that 
//! bridges the pure cryptographic logic in `mpc-core` with real-world network streams.
//!
//! ## Core Responsibilities
//! - **Protocol Definitions**: Strongly-typed gRPC messages and services via Protobuf.
//! - **Secure Transport**: mTLS channel creation and peer registry management.
//! - **Session Orchestration**: A resilient `run_mpc_session` loop that handles 
//!   message routing, retries, and timeouts for distributed cryptographic protocols.

// Suppress clippy::double_must_use for auto-generated tonic/async_trait code
#![allow(clippy::double_must_use)]

pub mod proto;
pub mod routing;
pub mod session;
pub mod transport;

#[cfg(any(feature = "formal-verify", kani))]
pub mod verification {
    //! Formal verification proofs for the protocol layer.
    pub mod invariants;
}

// Re-export key types for ergonomic access by downstream crates (e.g., mpc-node, mpc-coordinator)
pub use proto::mpc_node_client::MpcNodeClient;
pub use proto::mpc_node_server::{MpcNode, MpcNodeServer};
pub use session::run_mpc_session;
