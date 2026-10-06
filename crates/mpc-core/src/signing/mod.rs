//! # Threshold Signing Protocols
//!
//! This module contains the implementations of the cryptographic protocols used
//! to collaboratively sign a message digest using threshold key shares, without
//! ever reconstructing the full private key on any single node.
//!
//! ## Supported Protocols
//! - **`cggmp21`**: Threshold ECDSA for secp256k1 curves (Bitcoin, Ethereum, Tron).
//! - **`frost`**: Threshold Schnorr for Ed25519 curves (Solana).

pub mod cggmp21;
pub mod frost;

