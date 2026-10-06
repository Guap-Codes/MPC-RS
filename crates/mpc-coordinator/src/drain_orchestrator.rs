//! # Emergency Drain Orchestrator
//!
//! This module implements the break-glass emergency drain workflow for the MPC Coordinator.
//! It orchestrates the end-to-end process of building, signing, and broadcasting a 
//! transaction that sweeps funds from a compromised or targeted MPC vault to a secure cold wallet.
//!
//! ## ⚠️ Security Warning
//! This is the most destructive operation in the system. In a mature production environment,
//! this orchestrator should be gated behind additional out-of-band human approvals (e.g., 
//! M-of-N signatures from security officers) before execution is permitted.

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use tracing::{info, error, warn};
use uuid::Uuid;
use bip32::PublicKey;

use adapter_core::traits::BlockchainAdapter;
use mpc_common::types::{PartyId, SessionId};
use mpc_protocol::proto::{SessionRequest, GetPublicKeyRequest, session_request::Type};
use crate::coordinator::NodeRegistry;
use crate::session_store::SessionStore;

use k256::ecdsa::{Signature, VerifyingKey, RecoveryId};
use k256::elliptic_curve::sec1::ToEncodedPoint;

/// Orchestrates the emergency drain workflow across the MPC cluster.
///
/// This struct holds the dependencies required to build chain-specific transactions,
/// fetch public keys from nodes, trigger the MPC signing protocol, and broadcast
/// the finalized transaction to the network.
pub struct DrainOrchestrator {
    /// Registry of known MPC nodes and their mTLS connection parameters.
    node_registry: Arc<NodeRegistry>,
    /// In-memory store for tracking active MPC signing sessions.
    session_store: Arc<SessionStore>,
    /// Map of chain names to their respective blockchain adapter implementations.
    adapters: HashMap<String, Arc<dyn BlockchainAdapter>>,
}

impl DrainOrchestrator {
    /// Creates a new `DrainOrchestrator`.
    ///
    /// # Arguments
    ///
    /// * `node_registry` - The registry of MPC nodes.
    /// * `session_store` - The session state manager.
    /// * `adapters` - A map of blockchain adapters (e.g., "ethereum" -> EthereumAdapter).
    pub fn new(
        node_registry: Arc<NodeRegistry>,
        session_store: Arc<SessionStore>,
        adapters: HashMap<String, Arc<dyn BlockchainAdapter>>,
    ) -> Self {
        Self { node_registry, session_store, adapters }
    }

    /// Executes the complete emergency drain workflow.
    ///
    /// # Workflow
    /// 1. Builds an unsigned transaction via the chain-specific adapter.
    /// 2. Fetches the master public key and chain code from an MPC node.
    /// 3. Locally derives the child public key (if a derivation path is provided).
    /// 4. Triggers the MPC threshold signing protocol (CGGMP21 or FROST).
    /// 5. Extends the signature with a recovery ID (for Ethereum).
    /// 6. Attaches the signature and broadcasts the transaction.
    ///
    /// # Arguments
    ///
    /// * `chain` - The target blockchain network (e.g., "bitcoin", "ethereum").
    /// * `from_address` - The source MPC vault address.
    /// * `target_address` - The destination cold wallet address.
    /// * `derivation_path` - The BIP32 path of the key to authorize the drain.
    /// * `amount` - The amount to drain (typically "all").
    ///
    /// # Returns
    ///
    /// The transaction hash (TXID) of the successfully broadcasted drain transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the chain is unsupported, transaction building fails, 
    /// node communication fails, MPC signing times out, or broadcasting is rejected.
    pub async fn execute_drain(
        &self,
        chain: &str,
        from_address: &str,
        target_address: &str,
        derivation_path: &str,
        amount: &str,
    ) -> Result<String> {
        info!("🚨 Initiating {} drain from {} to {}", chain, from_address, target_address);

        let adapter = self.adapters.get(chain)
            .ok_or_else(|| anyhow!("Unsupported chain: {}", chain))?;

        // 1. Build Transaction & Extract Sighash
        info!("Building unsigned transaction via {} adapter...", chain);
        let (unsigned_tx_bytes, sighash) = adapter.build_unsigned_tx(
            from_address,
            target_address,
            amount,
            None, // token
            None, // change_address (drain all)
            None, // previous_tx
        ).await.map_err(|e| anyhow!("Failed to build TX: {}", e))?;

        info!("✅ Unsigned TX built. Sighash: {}", hex::encode(sighash));

        // 2. Fetch Master Public Key and Chain Code from Node
        let (master_pubkey_bytes, master_chain_code) = self.get_pubkey_and_chaincode_from_node(chain).await?;
        info!("Fetched master public key from node ({} bytes)", master_pubkey_bytes.len());

        // 3. Derive Child Public Key Locally (if derivation path is provided)
        // This is required for Ethereum to compute the correct ECDSA recovery ID (v).
        let final_pubkey_bytes = if derivation_path.is_empty() || derivation_path == "m" {
            master_pubkey_bytes.clone()
        } else if chain == "ethereum" {
            use bip32::{XPub, ExtendedKeyAttrs, ChildNumber, DerivationPath};
            use bip32::secp256k1::ecdsa::VerifyingKey;

            let vk = VerifyingKey::from_sec1_bytes(&master_pubkey_bytes)
                .map_err(|e| anyhow!("Invalid master public key: {}", e))?;
            
            let mut chain_code_arr = [0u8; 32];
            if master_chain_code.len() == 32 {
                chain_code_arr.copy_from_slice(&master_chain_code);
            } else {
                return Err(anyhow!("Invalid master chain code length: {}. Did you regenerate the DKG?", master_chain_code.len()));
            }

            let attrs = ExtendedKeyAttrs {
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: ChildNumber(0), // Dummy for master
                chain_code: chain_code_arr,
            };
            
            let mut current_xpub = XPub::new(vk, attrs);
            
            let path: DerivationPath = derivation_path.parse()
                .map_err(|e| anyhow!("Invalid derivation path '{}': {:?}", derivation_path, e))?;
            
            // Iteratively derive the child public key over the path segments
            for child_number in path {
                current_xpub = current_xpub.derive_child(child_number)
                    .map_err(|e| anyhow!("Failed to derive child public key: {:?}", e))?;
            }
            
            let child_vk = current_xpub.public_key();
            let child_pubkey_bytes = child_vk.to_bytes().to_vec();
            
            info!("Derived child public key for path {}: {}", derivation_path, hex::encode(&child_pubkey_bytes));
            child_pubkey_bytes
        } else {
            master_pubkey_bytes.clone() 
        };

        let pubkey_hex = hex::encode(&final_pubkey_bytes);

        // 4. Request Threshold Signature
        let mut signature = if chain == "solana" {
            info!("Routing to FROST (Ed25519) signing protocol...");
            self.request_frost_signature(sighash, derivation_path).await?
        } else {
            info!("Routing to CGGMP21 (secp256k1) signing protocol...");
            self.request_cggmp21_signature(sighash, derivation_path).await?
        };

        // Ethereum requires a 65-byte signature (r || s || v). 
        // We use the DERIVED child public key to compute the correct recovery ID (v).
        if chain == "ethereum" && signature.len() == 64 {
            signature = extend_ecdsa_signature_with_recovery(&sighash, &signature, &final_pubkey_bytes)
                .map_err(|e| anyhow!("Failed to compute recovery ID: {}", e))?;
                
            info!("Extended signature to {} bytes with recovery ID", signature.len());
        }

        info!("✅ Threshold signature generated ({} bytes)", signature.len());

        // 5. Attach Signature to Transaction
        let finalized_tx = adapter.attach_signature(&unsigned_tx_bytes, &signature, &pubkey_hex)
            .await.map_err(|e| anyhow!("Failed to attach signature: {}", e))?;

        info!("🔍 RAW FINALIZED TX: 0x{}", hex::encode(&finalized_tx));

        // 6. Broadcast to Network
        info!("Broadcasting finalized transaction to {} network...", chain);
        let tx_id = adapter.broadcast(&finalized_tx)
            .await.map_err(|e| anyhow!("Broadcast failed: {}", e))?;

        info!("🎉 DRAIN SUCCESSFUL! TXID: {}", tx_id);
        Ok(tx_id)
    }

    /// Fetches the master public key and chain code directly from the first available MPC node.
    ///
    /// # Note
    ///
    /// We fetch from the first node because all nodes in a successful DKG share the same 
    /// master public key and chain code. Fetching from one is sufficient for local derivation.
    async fn get_pubkey_and_chaincode_from_node(&self, chain: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let parties = self.node_registry.all_parties();
        let first_node = parties.first().ok_or_else(|| anyhow!("No nodes registered"))?;
        
        let mut client = self.node_registry.get_client(*first_node).await
            .map_err(|e| anyhow!("Failed to connect to node: {}", e))?;

        let curve = if chain == "solana" { "ed25519" } else { "secp256k1" };

        let req = GetPublicKeyRequest {
            derivation_path: "".to_string(), // Always fetch master from node
            curve: curve.to_string(),
        };

        let resp = client.get_public_key(req).await
            .map_err(|e| anyhow!("Node rejected get_public_key: {}", e))?;
        
        let inner = resp.into_inner();
        Ok((inner.public_key, inner.chain_code))
    }

    /// Triggers the CGGMP21 protocol and waits for the aggregated signature.
    async fn request_cggmp21_signature(&self, msg_hash: [u8; 32], derivation_path: &str) -> Result<Vec<u8>> {
        let session_id = Uuid::new_v4();
        let parties = self.node_registry.all_parties();
        let signer_indices: Vec<u16> = parties.iter().map(|p| p.0 as u16).collect();
        
        let rx = self.session_store.create(
            SessionId(session_id), msg_hash, signer_indices.clone(), 2
        ).await;

        // Dispatch to nodes
        self.orchestrate_signing(session_id, msg_hash, signer_indices, derivation_path.to_string(), Type::Signing).await?;

        // Wait for signature with a 60-second timeout
        let signature = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            rx,
        ).await.map_err(|_| anyhow!("Signing timeout"))??;

        Ok(signature)
    }

    /// Triggers the FROST protocol (Stubbed for now).
    async fn request_frost_signature(&self, _msg_hash: [u8; 32], _derivation_path: &str) -> Result<Vec<u8>> {
        warn!("FROST signing orchestration triggered. Ensure Type::FrostSigning is implemented in the node.");
        Err(anyhow!("FROST signing orchestration not yet wired to session store"))
    }

    /// Orchestrates the signing session by sending `SessionRequest` to all specified nodes.
    async fn orchestrate_signing(
        &self,
        session_id: Uuid,
        msg_hash: [u8; 32],
        signer_indices: Vec<u16>,
        derivation_path: String,
        session_type: Type,
    ) -> Result<()> {
        for &party_idx in &signer_indices {
            let party_id = PartyId(party_idx as u32);
            let mut client = self.node_registry.get_client(party_id).await
                .map_err(|e| anyhow!("Node connection failed: {}", e))?;

            let request = SessionRequest {
                session_id: session_id.to_string(),
                session_type: session_type.into(),
                total_parties: 0,
                threshold: 0,
                curve: if session_type == Type::Signing { "secp256k1" } else { "ed25519" }.into(),
                message_hash: msg_hash.to_vec(),
                signer_indices: signer_indices.iter().map(|&i| i as u32).collect(),
                derivation_path: derivation_path.clone(),
            };

            client.start_session(request).await
                .map_err(|e| anyhow!("Node {} rejected session: {}", party_id.0, e))?;
        }
        Ok(())
    }
}

/// Extends a 64-byte ECDSA signature (r || s) to a 65-byte signature (r || s || v).
///
/// # Context
///
/// CGGMP21 produces a 64-byte signature. However, Ethereum's `eth_sendRawTransaction` 
/// requires a 65-byte signature where the 65th byte is the recovery ID (`v`), which 
/// indicates the y-parity of the public key point. This function tries both possible 
/// recovery IDs (0 and 1) and returns the one that successfully recovers the expected public key.
///
/// # Arguments
///
/// * `msg_hash` - The 32-byte message digest that was signed.
/// * `sig_64` - The 64-byte signature (r || s).
/// * `expected_pubkey_bytes` - The compressed or uncompressed public key bytes to match against.
///
/// # Returns
///
/// A 65-byte vector containing `r`, `s`, and the correct `v` (0 or 1).
///
/// # Errors
///
/// Returns an error if the 64-byte signature is invalid, or if neither recovery ID 
/// produces a public key that matches the `expected_pubkey_bytes`.
fn extend_ecdsa_signature_with_recovery(
    msg_hash: &[u8; 32],
    sig_64: &[u8],
    expected_pubkey_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let sig = Signature::from_slice(sig_64).map_err(|e| format!("Invalid 64-byte signature: {}", e))?;

    // Try both possible recovery IDs (y-parity: 0 or 1)
    for is_y_odd in [false, true] {
        let recovery_id = RecoveryId::new(is_y_odd, false);
        if let Ok(recovered_key) = VerifyingKey::recover_from_prehash(msg_hash, &sig, recovery_id) {
            let recovered_compressed = recovered_key.to_encoded_point(true);
            let recovered_uncompressed = recovered_key.to_encoded_point(false);

            if recovered_compressed.as_bytes() == expected_pubkey_bytes
                || recovered_uncompressed.as_bytes() == expected_pubkey_bytes
            {
                let mut sig_65 = sig_64.to_vec();
                let v = if is_y_odd { 1 } else { 0 };
                sig_65.push(v);
                return Ok(sig_65);
            }
        }
    }

    Err("Could not find matching recovery ID for the given public key".to_string())
}

