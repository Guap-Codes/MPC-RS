//! # Hardware Wallet Common Interfaces
//!
//! This crate provides the foundational traits, types, and error handling for
//! interacting with hardware wallets (e.g., Ledger, Trezor, Keystone) within
//! the MPC-RS ecosystem.
//!
//! ## Architecture
//! By defining a generic `HwSigner` trait, this crate abstracts away the
//! specific communication protocols (USB, Bluetooth, QR codes) and device-specific
//! command sets. This allows the higher-level MPC-RS components to interact
//! with any supported hardware wallet through a uniform interface, facilitating
//! secure, air-gapped, or connected signing operations without coupling the core
//! logic to a specific vendor's SDK.

pub mod error;
pub mod traits;

// Re-export the most commonly used items for ergonomic access by adapter 
// implementations and the higher-level API/Coordinator crates.
pub use error::HwError;
pub use traits::HwSigner;

