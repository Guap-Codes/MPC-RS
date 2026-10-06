//! # Auxiliary Information Generation (AuxGen) Command
//!
//! This module implements the CLI command for initiating an AuxGen ceremony.
//!
//! ## Cryptographic Context
//! In the CGGMP21 threshold ECDSA protocol, nodes must generate "Auxiliary Information"
//! (specifically, Paillier encryption keys and Ring-Pedersen commitment parameters) 
//! before they can participate in Distributed Key Generation (DKG) or signing.
//! This is a computationally heavy, one-time setup phase that must be completed 
//! successfully by all nodes before the cluster can perform any secp256k1 operations.

use anyhow::Result;
use crate::client::AdminClient;
use crate::client::coordinator_proto::StartAuxGenRequest;

/// Executes the AuxGen initiation command.
///
/// This function sends a request to the MPC Coordinator to begin the AuxGen 
/// ceremony across the cluster. The Coordinator will then route the necessary 
/// P2P messages to the participating nodes.
///
/// # Arguments
///
/// * `client` - A mutable reference to the authenticated `AdminClient` connected 
///   to the MPC Coordinator.
///
/// # Returns
///
/// `Ok(())` if the request was successfully sent and accepted by the Coordinator.
///
/// # Errors
///
/// Returns an error if the gRPC request fails, the Coordinator rejects the request,
/// or the network connection is lost.
///
/// # Note
///
/// - The `total_parties` is currently hardcoded to `3` to match the standard 
///   3-node cluster configuration. This can be promoted to a CLI argument if 
///   dynamic cluster sizing is required in the future.
/// - This process involves heavy cryptographic operations (large prime generation 
///   and Zero-Knowledge Proofs) and typically takes 2–5 minutes to complete.
/// - Operators should monitor individual node logs (e.g., `tail -f logs/node1.log`) 
///   to verify that all nodes successfully complete the ceremony.
pub async fn execute(client: &mut AdminClient) -> Result<()> {
    println!("Initiating AuxGen session...");
    println!("Note: This process involves heavy cryptography (RSA/Paillier) and may take 2-5 minutes.");

    let request = StartAuxGenRequest {
        total_parties: 3, // Hardcoded for the standard 3-node cluster
    };

    // Call the Coordinator, which orchestrates the P2P routing to the nodes
    let response = client.inner.start_aux_gen(request).await?;
    let session_id = response.into_inner().session_id;
    
    println!("AuxGen session accepted by coordinator. Session ID: {}", session_id);
    println!("Check your node logs (e.g., tail -f logs/node1.log) to monitor progress.");
    Ok(())
}

