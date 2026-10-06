//! # Transaction Signing Handler
//!
//! This module implements the core transaction signing workflow for the API Gateway.
//! It orchestrates the end-to-end process: request validation, blockchain-specific 
//! transaction building, MPC threshold signing coordination, signature attachment, 
//! and final transaction hash computation.
//!
//! ## Architecture Note: Vault per DKG
//! In the MPC-RS architecture, each vault is tied to a specific DKG ceremony. 
//! Therefore, the derivation path for signing defaults to an empty string `""`, 
//! instructing the MPC nodes to sign with the raw Master Key, unless explicitly 
//! overridden by the client for advanced use cases.

use axum::{
    extract::State, 
    http::StatusCode, 
    response::{IntoResponse, Response, Json}
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, error, warn};

use crate::AppState;
use crate::blockchain_builder::Chain;

// ==========================================
// 1. Production-Grade Error Handling
// ==========================================

/// Domain-specific errors for the transaction signing workflow.
///
/// This enum allows the API Gateway to map internal failures to appropriate 
/// HTTP status codes, providing clear feedback to clients without leaking 
/// sensitive internal state.
#[derive(Debug, Error)]
pub enum SignError {
    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),
    
    #[error("Invalid request: {0}")]
    ValidationError(String),
    
    #[error("Key management error: {0}")]
    KeyManager(String),
    
    #[error("Blockchain adapter error: {0}")]
    Adapter(String),
    
    #[error("MPC Coordinator error: {0}")]
    Coordinator(String),
    
    #[error("Signing operation timed out")]
    Timeout,
}

impl IntoResponse for SignError {
    fn into_response(self) -> Response {
        let status = match &self {
            SignError::UnsupportedChain(_) | SignError::ValidationError(_) => StatusCode::BAD_REQUEST,
            SignError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        
        error!("API Error: {}", self);
        (status, Json(ErrorResponse { error: self.to_string() })).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

// ==========================================
// 2. Request / Response Models
// ==========================================

/// Request payload for signing and broadcasting a transaction.
#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// The target blockchain network.
    pub chain: String,
    /// The source address (the MPC vault).
    pub from: String,
    /// The destination address.
    pub to: String,
    /// The amount to transfer (human-readable, e.g., "0.5" or "all").
    pub amount: String,
    /// Optional token contract address (e.g., for ERC-20 or SPL tokens).
    #[serde(default)]
    pub token: Option<String>,
    /// Optional BIP32 derivation path. Defaults to `""` (Master Key) for Vault per DKG.
    pub derivation_path: Option<String>,
}

/// Response payload containing the finalized transaction details.
#[derive(Debug, Serialize)]
pub struct SignResponse {
    /// The hex-encoded, fully signed transaction ready for broadcast.
    pub signed_tx: String,
    /// The chain-specific transaction hash (TXID).
    pub tx_hash: String,
    /// The MPC session ID, provided for audit trails and debugging.
    pub session_id: String,
}

// ==========================================
// 3. The Handler
// ==========================================

/// HTTP handler for executing a complete MPC transaction signing workflow.
///
/// # Workflow
/// 1. Validates the incoming request.
/// 2. Selects the appropriate `BlockchainAdapter`.
/// 3. Retrieves the public key and derives a change address (if needed).
/// 4. Builds the unsigned transaction and extracts the signing digest.
/// 5. Initiates the MPC signing session with the Coordinator.
/// 6. Polls for the final threshold signature.
/// 7. Attaches the signature and computes the final transaction hash.
pub async fn sign_transaction(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, SignError> {
    info!("📝 Received sign request: chain={}, from={}, to={}, amount={}", 
        req.chain, req.from, req.to, req.amount);

    // --- Input Validation ---
    if req.from.is_empty() || req.to.is_empty() {
        return Err(SignError::ValidationError("from and to addresses cannot be empty".into()));
    }
    if req.amount.is_empty() {
        return Err(SignError::ValidationError("amount cannot be empty".into()));
    }

    // --- Adapter Selection ---
    let chain: Chain = req.chain.parse().map_err(|_| {
        SignError::UnsupportedChain(req.chain.clone())
    })?;
    
    let adapter = state.blockchain_registry.get(chain).ok_or_else(|| {
        SignError::UnsupportedChain(format!("Adapter not registered for chain: {}", req.chain))
    })?;

    // --- Key Management & Vault Lookup ---
    let pubkey_bytes = state.key_manager
        .get_public_key_for_address(&req.from)
        .await
        .map_err(|e| SignError::KeyManager(format!("Failed to get pubkey for address {}: {}", req.from, e)))?;
    
    let pubkey_hex = hex::encode(&pubkey_bytes);

    let change_address = state.key_manager
        .get_next_change_address() 
        .await
        .map_err(|e| SignError::KeyManager(format!("Failed to derive change address: {}", e)))?
        .to_string();

    // --- Transaction Building ---
    let previous_tx_hex: Option<&str> = None;

    let (unsigned_tx_bytes, digest) = adapter
        .build_unsigned_tx(
            &req.from, 
            &req.to, 
            &req.amount, 
            req.token.as_deref(),
            Some(&change_address),
            previous_tx_hex,
        )
        .await
        .map_err(|e| SignError::Adapter(e.to_string()))?;

    // Removed needless borrow on `digest`
    info!("✅ Unsigned TX built. Sighash: {}", hex::encode(digest));

    // --- Signer Selection (Policy Engine) ---
    // ARCHITECTURAL NOTE: The API Gateway does not hold the NodeRegistry. 
    // It only communicates with the Coordinator. Therefore, we request the standard 
    // 3-party quorum, and the Coordinator's internal Policy Engine will enforce 
    // the actual threshold (e.g., picking 2 out of 3 nodes to execute the math).
    let signer_indices = vec![1u16, 2, 3]; 

    // In the "Vault per DKG" model, we default to an empty derivation path 
    // to sign with the raw Master Key, unless explicitly overridden.
    let derivation_path = req.derivation_path.unwrap_or_default();

    // --- MPC Signing ---
    let mut coordinator = state.coordinator.clone();
    let session_id = coordinator
        .start_signing(digest, signer_indices.clone(), &derivation_path)
        .await
        .map_err(|e| SignError::Coordinator(e.to_string()))?;

    info!("🚀 Initiated MPC signing session: {}", session_id);

    let signature = coordinator
        .get_result(
            session_id,
            std::time::Duration::from_secs(60), // 60-second timeout for MPC math
            std::time::Duration::from_millis(500), // Poll every 500ms
        )
        .await
        .map_err(|e| {
            if e.to_string().to_lowercase().contains("timeout") {
                SignError::Timeout
            } else {
                SignError::Coordinator(e.to_string())
            }
        })?;

    info!("✅ Received threshold signature ({} bytes)", signature.len());

    // --- Signature Attachment ---
    let signed_tx = adapter
        .attach_signature(&unsigned_tx_bytes, &signature, &pubkey_hex)
        .await
        .map_err(|e| SignError::Adapter(e.to_string()))?;

    // --- Transaction Hash Computation ---
    let tx_hash = compute_transaction_hash(chain, &signed_tx);

    info!("🎉 Transaction signed successfully! TX Hash: {}", tx_hash);

    Ok(Json(SignResponse {
        signed_tx: hex::encode(&signed_tx),
        tx_hash,
        session_id: session_id.to_string(),
    }))
}

// ==========================================
// 4. Chain-Specific Hashing Logic
// ==========================================

/// Computes the actual transaction hash based on the chain's specific algorithm.
///
/// # Note
///
/// The sighash (the message signed by the MPC nodes) is often different from 
/// the final transaction hash (the identifier used to track the tx on the blockchain).
/// This function computes the latter from the fully signed transaction bytes.
fn compute_transaction_hash(chain: Chain, signed_tx: &[u8]) -> String {
    match chain {
        Chain::Ethereum | Chain::Tron => {
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            hasher.update(signed_tx);
            format!("0x{}", hex::encode(hasher.finalize()))
        }
        Chain::Bitcoin => {
            use sha2::{Digest, Sha256};
            // Bitcoin uses double SHA256, and the hash is displayed in reverse byte order (little-endian)
            let hash1 = Sha256::digest(signed_tx);
            // Removed needless borrow on `hash1`
            let hash2 = Sha256::digest(hash1);
            let reversed: Vec<u8> = hash2.into_iter().rev().collect();
            // Removed useless `format!`
            hex::encode(reversed)
        }
        Chain::Solana => {
            use sha2::{Digest, Sha256};
            // Solana uses single SHA256 for transaction signatures/hashes
            let hash = Sha256::digest(signed_tx);
            // Removed useless `format!`
            hex::encode(hash)
        }
        Chain::Xrp => {
            use sha2::{Digest, Sha512};
            
            // 🚨 XRPL PRODUCTION HASH LOGIC:
            // XRPL uses SHA512Half for transaction hashes (TX_ID).
            // The hashing prefix for a transaction ID is "TXN\0" (0x54584E00).
            let mut data = vec![0x54, 0x58, 0x4E, 0x00];
            data.extend_from_slice(signed_tx);
            
            let hash512 = Sha512::digest(&data);
            
            // SHA512Half takes the first 32 bytes of the 64-byte SHA512 hash
            let tx_hash = &hash512[..32];
            hex::encode(tx_hash).to_uppercase()
        }
    }
}

