//! # FROST Distributed Key Generation (DKG)
//!
//! This module implements the FROST (Flexible Round-Optimized Schnorr Threshold)
//! protocol for the Ed25519 curve. This is the required DKG mechanism for Solana
//! vaults in the MPC-RS system.
//!
//! ## Protocol Overview
//! FROST DKG is a 3-round protocol:
//! 1. **Round 1**: Each party generates a secret polynomial and broadcasts commitments.
//! 2. **Round 2**: Each party sends point evaluations (secret shares) to all other parties.
//! 3. **Round 3**: Each party locally aggregates the received shares to compute their
//!    final key package and the shared public key package.
//!
//! ## Network Communication
//! This implementation handles the P2P routing of FROST messages directly via gRPC
//! streams, ensuring that messages are securely transmitted over mTLS channels.

use frost_ed25519::{
    keys::{
        dkg::{
            part1, part2, part3,
            round1::Package as Round1Package, 
            round2::Package as Round2Package,
        },
        KeyPackage, PublicKeyPackage,
    },
    Identifier,
};
use mpc_common::error::{MpcError, MpcResult};
use mpc_common::types::PartyId;
use mpc_protocol::proto::{mpc_node_client::MpcNodeClient, SignedEnvelope};
use mpc_protocol::routing::PartyRegistry;
use tokio::sync::mpsc;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use rand::rngs::OsRng; 

/// Wrapper enum for FROST DKG messages exchanged between nodes.
#[derive(Serialize, Deserialize)]
pub enum FrostDkgMsg {
    /// Round 1 commitment package.
    Round1(Round1Package),
    /// Round 2 secret share package.
    Round2(Round2Package),
}

/// The final output of a successful FROST DKG ceremony.
pub struct FrostDkgResult {
    /// The local node's secret key package (contains the secret share).
    pub key_package: KeyPackage,
    /// The shared public key package (contains the group public key and all participants' public keys).
    pub public_key_package: PublicKeyPackage,
    /// The raw 32-byte Ed25519 group verifying key, ready for address derivation.
    pub verifying_key: [u8; 32], 
}

/// Executes the 3-round FROST DKG protocol for Ed25519.
///
/// This function manages the entire lifecycle of the FROST DKG, including local
/// cryptographic computations and P2P message routing via gRPC.
///
/// # Arguments
///
/// * `session_id` - A unique UUID for this DKG session.
/// * `local_party` - The `PartyId` of the local node.
/// * `parties` - A list of all `PartyId`s participating in the DKG.
/// * `registry` - The registry containing network endpoints and TLS identities for all peers.
/// * `ca_cert` - The CA certificate used to verify peer TLS certificates.
/// * `incoming_rx` - An MPSC receiver for incoming signed gRPC messages from other nodes.
///
/// # Returns
///
/// A `FrostDkgResult` containing the local key package and the group public key.
///
/// # Errors
///
/// Returns `MpcError::Internal` for serialization, deserialization, or identifier parsing failures.
/// Returns `MpcError::Config` if a peer's network endpoint is not found in the registry.
/// Returns `MpcError::TssProtocol` if any of the three FROST DKG rounds fail cryptographically.
///
/// # Note
///
/// Rounds 2 and 3 strictly require exactly `N-1` messages from *other* participants.
/// The implementation explicitly filters out messages from `local_party` to prevent
/// self-injection errors that would cause the protocol to fail.
pub async fn run_frost_dkg(
    session_id: uuid::Uuid,
    local_party: PartyId,
    parties: Vec<PartyId>,
    registry: &PartyRegistry,
    ca_cert: tonic::transport::Certificate,
    mut incoming_rx: mpsc::UnboundedReceiver<SignedEnvelope>,
) -> MpcResult<FrostDkgResult> {
    let max_signers = parties.len() as u16;
    let min_signers = 2; // 2-of-3 threshold
    let my_id = Identifier::try_from(local_party.0 as u16).map_err(|e| MpcError::Internal(format!("invalid identifier: {:?}", e)))?;
    let rng = OsRng;

    // Pre-compute mapping from FROST Identifiers back to our PartyId
    let id_to_party: std::collections::HashMap<Identifier, PartyId> = parties.iter()
        .filter_map(|&p| Identifier::try_from(p.0 as u16).ok().map(|id| (id, p)))
        .collect();

    // --- ROUND 1: Generate and broadcast commitments ---
    // Removed needless `&mut` borrow; `part1` will auto-borrow `rng` mutably.
    let (round1_secret, round1_package) = part1(my_id, max_signers, min_signers, rng)
        .map_err(|e| MpcError::TssProtocol(format!("FROST DKG part1 failed: {:?}", e)))?;

    let r1_payload = bincode::serialize(&FrostDkgMsg::Round1(round1_package.clone()))
        .map_err(|e| MpcError::Internal(e.to_string()))?;
    
    for remote_id in &parties {
        if *remote_id == local_party { continue; }
        let endpoint = registry.get(*remote_id).ok_or_else(|| MpcError::Config("peer not found".into()))?;
        let channel = mpc_protocol::transport::create_tls_channel(&endpoint.address, &endpoint.domain, endpoint.identity.clone(), ca_cert.clone()).await?;
        let mut client = MpcNodeClient::new(channel).max_decoding_message_size(100 * 1024 * 1024).max_encoding_message_size(100 * 1024 * 1024);
        
        let env = SignedEnvelope {
            session_id: session_id.to_string(),
            // Removed unnecessary `as u32` casts since `PartyId.0` is already `u32`
            sender: local_party.0,
            receiver: remote_id.0,
            payload: r1_payload.clone(),
            timestamp_ms: 0,
            signature: vec![],
        };
        let stream = async_stream::stream! { yield env; loop { tokio::time::sleep(std::time::Duration::from_secs(3600)).await; } };
        tokio::spawn(async move { let _ = client.exchange_messages(stream).await; });
    }

    // FIX: DO NOT insert my_id. part2 expects exactly N-1 packages from OTHER participants.
    let mut round1_packages = BTreeMap::new();

    while round1_packages.len() < parties.len() - 1 {
        // Collapsed nested `if let` into a single `if let ... && let ...` chain
        if let Some(env) = incoming_rx.recv().await
            && let Ok(FrostDkgMsg::Round1(pkg)) = bincode::deserialize::<FrostDkgMsg>(&env.payload)
        {
            let sender_id = Identifier::try_from(env.sender as u16).map_err(|e| MpcError::Internal(format!("invalid sender id: {:?}", e)))?;
            round1_packages.insert(sender_id, pkg);
        }
    }

    // --- ROUND 2: Generate and send P2P secret shares ---
    let (round2_secret, round2_packages) = part2(round1_secret, &round1_packages)
        .map_err(|e| MpcError::TssProtocol(format!("FROST DKG part2 failed: {:?}", e)))?;

    for (peer_id, r2_pkg) in &round2_packages {
        let r2_payload = bincode::serialize(&FrostDkgMsg::Round2(r2_pkg.clone()))
            .map_err(|e| MpcError::Internal(e.to_string()))?;
        
        let peer_party = id_to_party.get(peer_id).copied().unwrap();
        if peer_party == local_party { continue; }

        let endpoint = registry.get(peer_party).unwrap();
        let channel = mpc_protocol::transport::create_tls_channel(&endpoint.address, &endpoint.domain, endpoint.identity.clone(), ca_cert.clone()).await?;
        let mut client = MpcNodeClient::new(channel).max_decoding_message_size(100 * 1024 * 1024).max_encoding_message_size(100 * 1024 * 1024);
        
        let env = SignedEnvelope {
            session_id: session_id.to_string(),
            // Removed unnecessary `as u32` casts
            sender: local_party.0,
            receiver: peer_party.0,
            payload: r2_payload,
            timestamp_ms: 1, 
            signature: vec![],
        };
        let stream = async_stream::stream! { yield env; loop { tokio::time::sleep(std::time::Duration::from_secs(3600)).await; } };
        tokio::spawn(async move { let _ = client.exchange_messages(stream).await; });
    }

    // Collect exactly N-1 packages from OTHER participants.
    let mut received_round2 = BTreeMap::new();
    
    while received_round2.len() < parties.len() - 1 {
        // Collapsed nested `if let` into a single `if let ... && let ...` chain
        if let Some(env) = incoming_rx.recv().await
            && let Ok(FrostDkgMsg::Round2(pkg)) = bincode::deserialize::<FrostDkgMsg>(&env.payload)
        {
            let sender_id = Identifier::try_from(env.sender as u16).map_err(|e| MpcError::Internal(format!("invalid sender id: {:?}", e)))?;
            received_round2.insert(sender_id, pkg);
        }
    }

    // --- ROUND 3: Local Aggregation ---
    let (key_package, public_key_package) = part3(&round2_secret, &round1_packages, &received_round2)
        .map_err(|e| MpcError::TssProtocol(format!("FROST DKG part3 failed: {:?}", e)))?;

    let vk_vec = public_key_package.verifying_key().serialize()
        .map_err(|e| MpcError::Internal(format!("Failed to serialize verifying key: {:?}", e)))?;
    let verifying_key: [u8; 32] = vk_vec.try_into()
        .map_err(|_| MpcError::Internal("Verifying key is not 32 bytes".into()))?;

    Ok(FrostDkgResult {
        key_package,
        public_key_package,
        verifying_key,
    })
}
