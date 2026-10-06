//! # Azure Dedicated HSM Integration
//!
//! This crate provides a production-grade implementation of the [`HsmEngine`] trait
//! for Azure Dedicated HSM (typically Thales Luna appliances), utilizing the PKCS#11 
//! standard via the `cryptoki` crate.
//!
//! ## Architecture
//! In the MPC-RS custody model, the HSM acts as a "Cryptographic Oracle" for key wrapping.
//! Rather than storing raw MPC key shares on disk, this adapter encrypts (wraps) them
//! using an AES-256 key that is securely generated and stored *inside* the HSM.
//! The resulting encrypted blob is then safely stored on the local filesystem, ensuring
//! that the raw key material never persists outside the hardware security boundary.

mod pkcs11_engine;

// Re-export the engine for ergonomic access by the higher-level MPC node logic.
pub use pkcs11_engine::AzureHsm;
