//! # Bitcoin Address Derivation
//!
//! This module provides utilities for deriving standard Bitcoin addresses
//! from raw public keys, specifically tailored for the MPC-RS custody system.
//!
//! In MPC-RS, the cryptographic nodes operate on raw elliptic curve points.
//! This module bridges the gap between the cryptographic layer and the Bitcoin
//! network by formatting those keys into standard, human-readable Bech32 addresses.

use bitcoin::{Address, Network, CompressedPublicKey};
use adapter_core::error::AdapterError;

/// Derives a Native `SegWit` (P2WPKH) Bitcoin address from a compressed public key.
///
/// P2WPKH (Pay-to-Witness-Public-Key-Hash) is the modern standard for Bitcoin addresses,
/// offering lower transaction fees and improved security compared to legacy P2PKH.
///
/// # Arguments
///
/// * `pubkey` - A byte slice containing the raw, compressed public key. This **must** be exactly 33 bytes long.
/// * `network` - The target Bitcoin network (e.g., `Network::Bitcoin` for mainnet, `Network::Testnet`, or `Network::Regtest`).
///
/// # Returns
///
/// A `String` containing the Bech32-encoded P2WPKH address (e.g., `bc1q...` for mainnet, `tb1q...` for testnet).
///
/// # Errors
///
/// Returns an [`AdapterError::InvalidAddress`] if the provided `pubkey` slice is not exactly 33 bytes long,
/// or if the bytes do not represent a valid compressed secp256k1 public key.
///
/// # Example
///
/// ```rust
/// use bitcoin::Network;
/// // use bitcoin_adapter::address::derive_p2wpkh;
///
/// // A dummy 33-byte compressed public key (0x02 prefix + 32 bytes of X coordinate)
/// let mut pubkey = [0u8; 33];
/// pubkey[0] = 0x02; 
///
/// let address = derive_p2wpkh(&pubkey, Network::Bitcoin).unwrap();
/// assert!(address.starts_with("bc1q"));
/// ```
pub fn derive_p2wpkh(pubkey: &[u8], network: Network) -> Result<String, AdapterError> {
    // Parse directly into CompressedPublicKey to satisfy the strict type requirement
    // of the `bitcoin` crate, which validates the 33-byte length and curve validity.
    let pk = CompressedPublicKey::from_slice(pubkey)
        .map_err(|e| AdapterError::InvalidAddress(format!("Invalid compressed public key: {e}")))?;
        
    let address = Address::p2wpkh(&pk, network);
    Ok(address.to_string())
}




