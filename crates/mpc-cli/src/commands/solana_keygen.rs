//! # Solana FROST DKG Command
//!
//! This module implements the CLI command for initiating a Distributed Key 
//! Generation (DKG) ceremony specifically for the Solana network.
//!
//! ## Cryptographic Context
//! Unlike Bitcoin, Ethereum, and Tron (which use secp256k1 and the CGGMP21 
//! protocol), Solana uses the Ed25519 curve. Ed25519 threshold signatures 
//! require the FROST (Flexible Round-Optimized Schnorr Threshold) protocol. 
//! This command triggers the specialized FROST DKG workflow in the Coordinator, 
//! which orchestrates the polynomial sharing and verification rounds across 
//! the participating nodes.

use anyhow::Result;
use crate::client::AdminClient;
use crate::client::coordinator_proto;

/// Executes the Solana FROST DKG initiation command.
///
/// This function sends a request to the MPC Coordinator to begin the FROST 
/// DKG ceremony. The Coordinator will allocate a new session ID and route 
/// the necessary P2P messages to the registered nodes to generate the shared 
/// Ed25519 master key and individual secret shares.
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
/// Returns an error if the gRPC request fails, the Coordinator rejects the 
/// request (e.g., due to insufficient healthy nodes), or the network connection 
/// is lost.
///
/// # Note
///
/// FROST DKG is a multi-round, asynchronous cryptographic process. This command 
/// only *initiates* the ceremony. Operators must monitor the individual node 
/// logs (e.g., `tail -f logs/node1.log`) to verify that all nodes successfully 
/// complete the protocol and securely store their Ed25519 shares.
pub async fn execute(client: &mut AdminClient) -> Result<()> {
    println!("Initiating FROST DKG for Solana (Ed25519)...");
    
    let req = coordinator_proto::StartFrostDkgRequest {};
    
    // Access the public `inner` field of the AdminClient to invoke the gRPC method
    let response = client.inner.start_frost_dkg(req).await?;
    
    let session_id = response.into_inner().session_id;
    
    println!("✅ FROST DKG session triggered successfully!");
    println!("Session ID: {}", session_id);
    println!("Monitor progress using: tail -f logs/node1.log");
    println!("The Solana address will be printed in the logs as '🔑🔑🔑 SOLANA VAULT GENERATED! Address: ... 🔑🔑🔑'");
    
    Ok(())
}
