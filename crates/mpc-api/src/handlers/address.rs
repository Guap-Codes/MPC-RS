//! # Address Derivation Handler
//!
//! This module handles HTTP requests to derive blockchain addresses from a given 
//! BIP32 derivation path. It bridges the gap between the unified MPC key manager 
//! and the specific address formatting rules of each supported blockchain.
//!
//! ## Chain-Specific Derivation Logic
//! - **Bitcoin**: Derives a Native SegWit (P2WPKH) address directly via the key manager.
//! - **Ethereum**: Computes the Keccak-256 hash of the uncompressed public key (dropping the `0x04` prefix) and takes the last 20 bytes.
//! - **Tron**: Similar to Ethereum, but prepends the `0x41` mainnet prefix and encodes the result using Base58Check.
//! - **XRP**: Computes `RIPEMD160(SHA256(compressed_pubkey))`, prepends the `0x00` classic address prefix, appends a 4-byte checksum, and encodes using the Ripple-specific Base58 alphabet.
//! - **Solana**: Explicitly rejected here, as Solana requires a separate Ed25519 FROST DKG workflow (see architecture notes).

use axum::{extract::State, response::Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use crate::AppState;
use crate::blockchain_builder::Chain;
use sha3::{Digest, Keccak256};
use sha2::Sha256;
use ripemd::Ripemd160;

/// Request payload for deriving a new blockchain address.
#[derive(Debug, Deserialize)]
pub struct AddressRequest {
    /// The target blockchain network (e.g., "bitcoin", "ethereum", "tron", "xrp").
    pub chain: String,
    /// Optional BIP32 derivation path. If omitted, defaults to `m/0/{account_index}`.
    pub derivation_path: Option<String>,
    /// Optional account index used to construct the default derivation path. Defaults to `0`.
    pub account_index: Option<u32>,
}

/// Response payload containing the derived address and the path used.
#[derive(Debug, Serialize)]
pub struct AddressResponse {
    /// The chain-specific, human-readable address string.
    pub address: String,
    /// The exact BIP32 derivation path used to generate this address.
    pub derivation_path: String,
}

/// HTTP handler for deriving a blockchain address from a derivation path.
///
/// # Arguments
///
/// * `state` - The shared application state containing the `MpcKeyManager`.
/// * `req` - The JSON payload containing the chain and derivation parameters.
///
/// # Returns
///
/// A JSON response containing the derived address and the derivation path.
///
/// # Errors
///
/// Returns `400 Bad Request` if the chain is unsupported or the request is malformed.
/// Returns `500 Internal Server Error` if the key manager fails to derive the key.
pub async fn derive_address(
    State(state): State<AppState>,
    Json(req): Json<AddressRequest>,
) -> Result<Json<AddressResponse>, (StatusCode, String)> {
    let chain: Chain = req.chain.parse().map_err(|_| (StatusCode::BAD_REQUEST, "unsupported chain".into()))?;
    
    // Default to BIP44 external chain path: m/0/{account_index}
    let path_str = req.derivation_path.unwrap_or_else(|| format!("m/0/{}", req.account_index.unwrap_or(0)));

    match chain {
        Chain::Bitcoin => {
            let (addr, _) = state.key_manager.derive_address(&path_str)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(Json(AddressResponse { address: addr.to_string(), derivation_path: path_str }))
        }
        Chain::Ethereum => {
            let uncompressed = state.key_manager.derive_pubkey_bytes(&path_str)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            
            // Drop the 0x04 prefix, leaving 64 bytes of X and Y coordinates
            let xy = &uncompressed[1..]; 
            let hash = Keccak256::digest(xy);
            
            // Ethereum address is the last 20 bytes of the Keccak-256 hash
            let eth_address = format!("0x{}", hex::encode(&hash[12..])); 
            Ok(Json(AddressResponse { address: eth_address, derivation_path: path_str }))
        }
        Chain::Tron => {
            let uncompressed = state.key_manager.derive_pubkey_bytes(&path_str)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let xy = &uncompressed[1..];
            let hash = Keccak256::digest(xy);
            
            // Tron mainnet prefix (0x41 corresponds to addresses starting with 'T')
            let mut payload = vec![0x41]; 
            payload.extend_from_slice(&hash[12..]);
            
            // Double SHA256 checksum
            let checksum = Sha256::digest(Sha256::digest(&payload));
            payload.extend_from_slice(&checksum[0..4]);
            
            let tron_address = bs58::encode(payload).into_string();
            Ok(Json(AddressResponse { address: tron_address, derivation_path: path_str }))
        }
        Chain::Xrp => {
            // derive_address safely returns the 33-byte CompressedPublicKey array
            let (_, pk) = state.key_manager.derive_address(&path_str)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let compressed = pk.to_bytes();
            
            // XRPL Address derivation: RIPEMD160(SHA256(compressed_pubkey))
            let hash1 = Sha256::digest(&compressed);
            let hash2 = Ripemd160::digest(hash1);
            
            // XRPL Account ID prefix (0x00 for classic addresses)
            let mut payload = vec![0x00]; 
            payload.extend_from_slice(&hash2);
            
            // Double SHA256 checksum
            let checksum = Sha256::digest(Sha256::digest(&payload));
            payload.extend_from_slice(&checksum[0..4]);
            
            // Use the built-in Ripple Base58 alphabet (different from Bitcoin's)
            let xrp_address = bs58::encode(payload)
                .with_alphabet(&bs58::Alphabet::RIPPLE)
                .into_string();
                
            Ok(Json(AddressResponse { address: xrp_address, derivation_path: path_str }))
        }
        Chain::Solana => {
            // Solana uses Ed25519, which requires a separate FROST DKG ceremony.
            // It cannot be derived from the secp256k1 master key used for BTC/ETH/TRX/XRP.
            Err((StatusCode::BAD_REQUEST, "Solana requires an Ed25519 FROST DKG. See architecture notes.".into()))
        }
    }
}


