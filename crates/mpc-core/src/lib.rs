//! # MPC Core: Pure Cryptographic Protocols
//!
//! This crate implements the core cryptographic protocols for Multi-Party
//! Computation (MPC) and Threshold Signature Schemes (TSS) within the MPC-RS
//! institutional custody ecosystem.
//!
//! ## Supported Protocols
//! - **CGGMP21**: Threshold ECDSA for secp256k1 curves (Bitcoin, Ethereum, Tron),
//!   powered by the actively maintained `cggmp21` crate.
//! - **FROST**: Threshold Schnorr for Ed25519 curves (Solana).
//!
//! ## Architecture: Network Agnosticism
//! This crate is strictly **network-agnostic**. All protocol functions accept a
//! `round_based::MpcParty` trait object, which is connected to the actual transport
//! layer (e.g., gRPC, libp2p) by the caller (typically the `mpc-node` or `mpc-coordinator`).
//! This separation of concerns ensures that the cryptographic logic remains pure,
//! highly testable, and completely independent of network infrastructure.

pub mod curves;
pub mod primitives;

pub mod dkg {
    //! Distributed Key Generation (DKG) protocols.
    //!
    //! This module contains the implementations for generating threshold key shares
    //! across the MPC cluster collaboratively, ensuring that no single node ever
    //! knows the complete private key.
    pub mod cggmp21;
    pub mod refresh;
    pub mod frost;
}

pub mod signing {
    //! Threshold signing protocols.
    //!
    //! This module contains the implementations for collaboratively signing a message
    //! digest using the threshold key shares generated during the DKG phase, without
    //! ever reconstructing the full private key on any single node.
    pub mod cggmp21;
}

// Expose verification module when the feature is enabled OR when running `cargo kani`
#[cfg(any(feature = "formal-verify", kani))]
pub mod verification{
    //! Formal verification proofs for the core crate.
    pub mod invariants;
}

/*
#[cfg(feature = "formal-verify")]
pub mod verification;*/

// Re‑export the primary protocol entry points and conversion helpers for ergonomic access.
pub use dkg::cggmp21::{convert_key_share, run_dkg};
pub use dkg::frost::run_frost_dkg;
pub use signing::cggmp21::{convert_signature, generate_presignature, run_signing};

/// Convenience helper to create a `MpcError::TssProtocol` from a string.
///
/// This function simplifies error creation within the `mpc-core` crate,
/// ensuring consistent error categorization for cryptographic protocol failures
/// without requiring the caller to import the full error enum path.
///
/// # Arguments
///
/// * `reason` - A string or string-like type describing the reason for the failure.
///
/// # Returns
///
/// An `MpcError::TssProtocol` variant containing the provided reason.
pub fn crypto_error(reason: impl Into<String>) -> mpc_common::error::MpcError {
    mpc_common::error::MpcError::TssProtocol(reason.into())
}
