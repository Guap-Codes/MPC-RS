//! # Distributed Key Generation (DKG) Protocols
//!
//! This module contains the implementations of the cryptographic protocols used
//! to generate threshold key shares across the MPC cluster without any single
//! node ever knowing the complete private key.
//!
//! ## Supported Protocols
//! - **`cggmp21`**: Threshold ECDSA for secp256k1 curves (Bitcoin, Ethereum, Tron).
//! - **`frost`**: Threshold Schnorr for Ed25519 curves (Solana).
//! - **`refresh`**: Proactive secret sharing (key rotation) to maintain forward secrecy.

pub mod cggmp21;
pub mod refresh;
pub mod frost;



