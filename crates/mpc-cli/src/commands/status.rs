//! # Cluster Status Command
//!
//! This module implements the CLI command for fetching and displaying the 
//! real-time operational status of the MPC-RS cluster.
//!
//! ## Operational Context
//! Before initiating critical cryptographic ceremonies (like DKG, AuxGen, or 
//! Emergency Drain), operators should always verify the cluster status. This 
//! command provides a snapshot of the Coordinator's active sessions and the 
//! health of all registered MPC nodes, including their HSM connectivity and 
//! last known heartbeat.

use crate::client::AdminClient;
use crate::client::coordinator_proto::GetStatusRequest;
use anyhow::Result;
use tracing::info;

/// Executes the cluster status check command.
///
/// This function queries the MPC Coordinator for the current state of the 
/// cluster and prints a formatted summary to the console.
///
/// # Arguments
///
/// * `client` - A mutable reference to the authenticated `AdminClient` connected 
///   to the MPC Coordinator.
///
/// # Returns
///
/// `Ok(())` if the status was successfully retrieved and printed.
///
/// # Errors
///
/// Returns an error if the gRPC request fails or the network connection to 
/// the Coordinator is lost.
///
/// # Note
///
/// The output includes:
/// - **Active Sessions**: The number of ongoing MPC ceremonies (e.g., DKG, signing).
/// - **Registered Nodes**: The total count of nodes configured in the cluster.
/// - **Node Details**: For each node, its unique ID, current operational status 
///   (e.g., "IDLE", "SIGNING"), HSM health (true/false), and the timestamp of 
///   its last successful heartbeat ping.
pub async fn execute(client: &mut AdminClient) -> Result<()> {
    info!("Fetching cluster status...");
    
    let request = tonic::Request::new(GetStatusRequest {});
    let response = client.inner.get_status(request).await?;
    let status = response.into_inner();
    
    println!("--- Coordinator Status ---");
    println!("Active Sessions: {}", status.active_sessions);
    println!("Registered Nodes: {}", status.nodes.len());
    
    for node in status.nodes {
        println!("\nNode ID: {}", node.id);
        println!("  Status: {:?}", node.status); 
        println!("  HSM Health: {}", if node.hsm_healthy { "✅ Healthy" } else { "❌ Unhealthy" });
        println!("  Last Ping: {}", node.last_ping);
    }
    
    Ok(())
}



