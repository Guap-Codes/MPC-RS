//! # YubiHSM Integration
//!
//! This crate provides a production-grade implementation of the [`HsmEngine`] trait
//! for YubiHSM 2 devices, utilizing the official `yubihsm` Rust SDK.
//!
//! ## Architecture
//! In the MPC-RS custody model, the YubiHSM acts as a "Cryptographic Oracle" for key wrapping.
//! Rather than storing raw MPC key shares in plaintext on disk, this adapter encrypts (wraps) them
//! using an AES-CCM wrap key that is securely generated and stored *inside* the YubiHSM.
//! The resulting encrypted blob is then safely stored on the local filesystem, ensuring
//! that the raw key material never persists outside the hardware security boundary.
//!
//! ## Thread Safety & Async Compatibility
//! The underlying `yubihsm::Client` requires mutable access to send and receive commands.
//! To satisfy the `&self` requirement of the async `HsmEngine` trait while maintaining
//! thread safety, the client is wrapped in an `Arc<Mutex<...>>`. All blocking HSM I/O
//! operations are offloaded to a dedicated thread pool using `tokio::task::spawn_blocking`
//! to prevent freezing the Tokio async runtime.

mod engine;

// Re-export the engine for ergonomic access by the higher-level MPC node logic.
pub use engine::YubiHsm;

