//! # Hardware Security Module Core (`hsm-core`)
//!
//! This crate provides the foundational traits, types, and error handling for
//! interacting with Hardware Security Modules (HSMs) within the MPC-RS ecosystem.
//!
//! ## Architecture
//! In the MPC-RS custody model, the HSM acts as a "Cryptographic Oracle" for key wrapping.
//! Rather than storing raw MPC key shares in plaintext on disk, the MPC nodes encrypt
//! (wrap) them using an AES key that is securely generated and stored *inside* the HSM.
//! The resulting encrypted blob is then safely stored on the local filesystem.
//!
//! This crate defines the [`HsmEngine`] trait, which abstracts away the specific
//! communication protocols (e.g., PKCS#11, native SDKs) of different HSM vendors
//! (e.g., YubiHSM, AWS CloudHSM, Azure Dedicated HSM), presenting a uniform
//! interface to the higher-level MPC node logic.

pub mod error;
pub mod traits;

// Re-export the most commonly used items for ergonomic access by HSM implementations
// and the higher-level MPC node crates.
pub use error::HsmError;
pub use traits::HsmEngine;

