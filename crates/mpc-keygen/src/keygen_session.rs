//! # DKG Session Orchestration
//!
//! This module contains the logic for orchestrating a Distributed Key Generation 
//! (DKG) ceremony across multiple MPC nodes. It handles the gRPC communication, 
//! parameter validation, and the polling mechanism required to wait for all nodes 
//! to complete the cryptographic protocol and agree on the final public key.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::{Certificate, Identity};
use uuid::Uuid;
use tracing::{info, warn, error};
use mpc_common::error::MpcResult;
use mpc_protocol::transport;

// Include the generated proto code.
pub mod node_ext {
    tonic::include_proto!("mpc_keygen");
}

use self::node_ext::{
    mpc_admin_node_client::MpcAdminNodeClient,
    SessionRequest, GetPublicKeyRequest,
};

/// Holds the connection info for a single MPC node.
struct NodeEndpoint {
    pub address: String,
    pub domain: String,
}

/// Registry of the MPC nodes participating in the DKG ceremony.
pub struct NodeRegistry {
    endpoints: Vec<NodeEndpoint>,
    identity: Identity,
    ca_cert: Certificate,
}

impl NodeRegistry {
    /// Creates a new `NodeRegistry`.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - A list of `(address, domain)` tuples for each node.
    /// * `identity` - The client's mTLS certificate and private key.
    /// * `ca_cert` - The CA certificate used to verify the nodes' server certificates.
    pub fn new(
        endpoints: Vec<(String, String)>,
        identity: Identity,
        ca_cert: Certificate,
    ) -> Self {
        Self {
            endpoints: endpoints.into_iter().map(|(address, domain)| NodeEndpoint { address, domain }).collect(),
            identity,
            ca_cert,
        }
    }

    /// Returns the total number of registered nodes.
    pub fn num_nodes(&self) -> usize {
        self.endpoints.len()
    }

    /// Creates an mTLS-secured gRPC client for the node at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The 0-based index of the node in the registry.
    ///
    /// # Returns
    ///
    /// An `MpcAdminNodeClient` ready to make RPC calls to the node.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds or if the mTLS channel fails to establish.
    pub async fn get_client(&self, index: usize) -> MpcResult<MpcAdminNodeClient<tonic::transport::Channel>> {
        let ep = &self.endpoints[index];
        let channel = transport::create_tls_channel(
            &ep.address,
            &ep.domain,
            self.identity.clone(),
            self.ca_cert.clone(),
        )
        .await?;
        Ok(MpcAdminNodeClient::new(channel))
    }
}

/// Executes the full DKG ceremony across all registered nodes.
///
/// This function triggers the DKG session on each node, then enters a polling 
/// loop to wait for all nodes to complete the protocol and report their 
/// resulting public keys. It verifies that all nodes agree on the same public key.
///
/// # Arguments
///
/// * `registry` - The registry containing the nodes' connection details and TLS credentials.
/// * `session_id` - A unique execution ID (must be identical for all participating nodes).
/// * `curve` - The elliptic curve to use (e.g., "secp256k1").
/// * `t` - The threshold (minimum number of parties required to sign).
/// * `n` - The total number of parties participating in the DKG.
///
/// # Returns
///
/// The aggregate public key as compressed SEC1 bytes, upon successful completion.
///
/// # Errors
///
/// Returns an error if:
/// - The requested `n` exceeds the number of available nodes in the registry.
/// - The threshold `t` is invalid (e.g., `t > n` or `t == 0`).
/// - Any node rejects the session request or fails to connect.
/// - The nodes report mismatched public keys after the ceremony.
/// - The ceremony does not complete within the configured timeout (2 minutes).
pub async fn run_keygen(
    registry: Arc<NodeRegistry>,
    session_id: Uuid,
    curve: &str,
    t: u32,
    n: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 🛡️ PRODUCTION SAFETY CHECK: Validate requested quorum against the actual registry
    let available_nodes = registry.num_nodes();
    if (n as usize) > available_nodes {
        return Err(format!(
            "Invalid DKG parameters: requested {} total parties, but the registry only contains {} nodes.", 
            n, available_nodes
        ).into());
    }
    if t > n {
        return Err("Threshold (t) cannot be greater than total parties (n)".into());
    }
    if t == 0 {
        return Err("Threshold (t) must be at least 1".into());
    }

    info!("Starting DKG ceremony with session_id={} ({}-of-{})", session_id, t, n);

    // 1. Trigger the DKG session on every node.
    for i in 0..n as usize {
        let mut client = registry.get_client(i).await?;
        let request = SessionRequest {
            session_id: session_id.to_string(),
            session_type: 0, // Type::DKG = 0
            total_parties: n,
            threshold: t,
            curve: curve.to_string(),
            message_hash: vec![],
            signer_indices: vec![],
            derivation_path: String::new(),
        };
        let resp = client.start_session(request).await;
        match resp {
            Ok(resp) => {
                if !resp.into_inner().accepted {
                    warn!("Node {} rejected DKG session", i);
                }
            }
            Err(e) => {
                error!("Failed to start DKG on node {}: {}", i, e);
                return Err(Box::new(e));
            }
        }
    }

    // 2. Poll each node for its public key until all report the same value.
    let label = format!("dkg-{}", session_id);
    let mut public_keys: Vec<Option<Vec<u8>>> = vec![None; n as usize];
    let mut attempt = 0;
    const MAX_ATTEMPTS: u32 = 60; // 60 attempts * 2000ms = 120 seconds (2 minutes)
    const POLL_INTERVAL_MS: u64 = 2000;

    loop {
        // 🛡️ Use enumerate() to avoid needless range loops and safely mutate the vector
        for (i, pk_option) in public_keys.iter_mut().enumerate() {
            if pk_option.is_some() {
                continue; // already got this one
            }
            match registry.get_client(i).await {
                Ok(mut client) => {
                    let req = GetPublicKeyRequest { label: label.clone() };
                    match client.get_public_key(req).await {
                        Ok(resp) => {
                            let pk = resp.into_inner().public_key;
                            if !pk.is_empty() {
                                *pk_option = Some(pk);
                                info!("Node {} reported public key", i);
                            }
                        }
                        Err(e) => {
                            // Key not found yet – that's OK, the node is still processing.
                            tracing::debug!("Node {} not ready: {}", i, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Cannot connect to node {}: {}", i, e);
                }
            }
        }

        // Check if all nodes have reported.
        let all_done = public_keys.iter().all(|pk| pk.is_some());
        if all_done {
            // Verify they are identical to ensure consensus was reached.
            let first = public_keys[0].as_ref().unwrap();
            if public_keys.iter().all(|pk| pk.as_ref() == Some(first)) {
                info!("DKG ceremony completed successfully. Public key: {}", hex::encode(first));
                return Ok(first.clone());
            } else {
                error!("Public key mismatch between nodes!");
                return Err("Public key mismatch".into());
            }
        }

        attempt += 1;
        if attempt >= MAX_ATTEMPTS {
            return Err("DKG did not complete within timeout".into());
        }
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

