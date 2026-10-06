//! # Ledger Hardware Wallet Integration
//!
//! This crate provides a production-grade implementation of the [`HwSigner`] trait
//! for Ledger hardware wallets (Nano S, Nano S Plus, Nano X), backed by the 
//! `ledger-transport-hid` and `ledger-apdu` libraries.
//!
//! ## Architecture
//! It abstracts away the low-level USB HID transport layer and the manual 
//! construction of Application Protocol Data Units (APDUs), presenting a clean, 
//! asynchronous interface to the higher-level MPC-RS signing workflow. It supports 
//! both Bitcoin (via the Bitcoin App) and Ethereum (via the Ethereum App).
//!
//! ## Features
//! - Thread-safe transport management via interior mutability (`Arc<Mutex<...>>`).
//! - Non-blocking async execution using `tokio::task::spawn_blocking` for HID I/O.
//! - Strict BIP32 derivation path parsing tailored to Ledger's binary format expectations.

pub mod transport;
pub mod apdu;
pub mod app;

// Re-export the core app and chain types for ergonomic access
pub use app::{Chain, LedgerApp};

