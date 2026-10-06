//! # Trezor Hardware Wallet Integration
//!
//! This crate provides a production-grade implementation of the [`HwSigner`] trait
//! for Trezor hardware wallets (Model T and Model One), backed by the `trezor-client` library.
//!
//! ## Architecture
//! It abstracts away the low-level USB/UDP transport layer and the Protobuf message 
//! serialization, presenting a clean, asynchronous interface to the higher-level 
//! MPC-RS signing workflow. It supports both physical devices (via `WebUSB`) and 
//! local emulators (via UDP) for automated testing.
//!
//! ## Features
//! - Thread-safe client management via interior mutability (`Mutex`).
//! - Automatic handling of device interaction loops (e.g., PIN entry, passphrase prompts).
//! - Support for both Bitcoin (secp256k1) and Ethereum (secp256k1) derivation paths.

pub mod transport;
pub mod messages;
pub mod handler;

// Re-export the core handler and chain types for ergonomic access
pub use handler::{Chain, TrezorApp};


