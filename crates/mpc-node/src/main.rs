//! # MPC Node Entry Point
//!
//! This is the main entry point for the MPC node daemon. It orchestrates
//! the initialization sequence: parsing arguments, loading configuration,
//! initializing the HSM backend, establishing mTLS connections to peers
//! and the Coordinator, and finally starting the gRPC server.
//!
//! ## Architecture Note: HSM Isolation
//! For local development using `SoftHsm`, this script dynamically overrides
//! the `share_label` to point to a node-specific directory (e.g., `data/node1`).
//! This prevents multiple node instances running on the same machine from
//! overwriting each other's encrypted key shares.

mod config;
mod logging;
mod hsm_manager;
mod node;

use std::sync::Arc;
use mpc_common::types::PartyId;
use mpc_protocol::routing::PartyRegistry;
use mpc_protocol::transport;
use mpc_protocol::proto::mpc_node_server::MpcNodeServer;
use mpc_protocol::proto::mpc_coordinator_client::MpcCoordinatorClient;
use node::Node;
use tonic::transport::{Server, ServerTlsConfig};

/// The main asynchronous entry point for the MPC node.
///
/// # Execution Flow
/// 1. Parses CLI arguments and loads the TOML configuration.
/// 2. Initializes structured logging and optional OTLP tracing.
/// 3. Ensures the local data directory exists and configures HSM isolation.
/// 4. Loads the configured HSM backend (e.g., SoftHsm).
/// 5. Builds the `PartyRegistry` for P2P communication with other nodes.
/// 6. Establishes an mTLS gRPC channel to the central Coordinator.
/// 7. Starts the `MpcNodeServer` to listen for incoming P2P protocol messages.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = config::CliArgs::from_env();
    let mut cfg = config::load_config(&args)?;

    logging::init_logging(&cfg.logging.level, cfg.logging.otlp_endpoint.as_deref());

    // Ensure the base data directory exists.
    std::fs::create_dir_all("data").ok();
    
    // Isolate the HSM directory per node to prevent data corruption in local dev.
    let node_hsm_dir = format!("data/node{}", cfg.party_id);
    std::fs::create_dir_all(&node_hsm_dir).ok();
    
    if let Some(ref mut soft_hsm) = cfg.hsm.soft_hsm {
        soft_hsm.data_dir = node_hsm_dir.clone();
    } else {
        // In a production environment, this panic would be replaced by proper
        // validation of the production HSM configuration.
        panic!("Expected SoftHSM configuration for local development!");
    }

    // 🎯 HSM Isolation Fix: SoftHsm::new() uses `share_label` as the base directory.
    // We must override `share_label` to point to our isolated node directory.
    cfg.hsm.share_label = node_hsm_dir.clone();
    
    tracing::info!("Node {} HSM isolated to directory: {}", cfg.party_id, cfg.hsm.share_label);

    // Initialize the HSM backend
    let hsm = hsm_manager::load_hsm(&cfg.hsm).await?;
    let party_id = PartyId(cfg.party_id);

    // Build the P2P registry from the configuration file
    let mut endpoints = Vec::new();
    for peer in &cfg.peers {
        endpoints.push((
            PartyId(peer.party_id),
            peer.address.clone(),
            peer.domain.clone(),
            peer.cert_path.clone(),
            peer.key_path.clone(),
        ));
    }
    let registry = PartyRegistry::new(endpoints)?;

    // Load mTLS credentials for securing P2P and Coordinator communication
    let identity = transport::load_identity(
        std::path::Path::new(&cfg.tls.certificate_path),
        std::path::Path::new(&cfg.tls.private_key_path),
    )?;
    let ca_cert = transport::load_ca_cert(
        std::path::Path::new(&cfg.tls.ca_certificate_path),
    )?;

    // Establish connection to the central Coordinator
    let coord_url = std::env::var("COORDINATOR_GRPC_URL").unwrap_or_else(|_| "https://127.0.0.1:50052".to_string());
    
    let channel = transport::create_tls_channel(
        &coord_url,
        "localhost", // Note: In production, this should match the Coordinator's certificate SAN
        identity.clone(),
        ca_cert.clone(),
    ).await
    .expect("Failed to create mTLS channel to Coordinator");

    let coordinator_client = MpcCoordinatorClient::new(channel);

    // Initialize the core Node state machine
    let node = Arc::new(Node::new(party_id, hsm, registry, coordinator_client));

    // Configure the gRPC server with mTLS and HTTP/2 keepalives
    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert);

    let mut tls_server = Server::builder()
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(60)))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(300)))
        .tls_config(tls_config)?;

    let addr = cfg.listen_addr;
    tracing::info!("Node {} listening on {} (HSM isolated to: {})", party_id.0, addr, node_hsm_dir);

    let node_service = MpcNodeServer::from_arc(node.clone())
        .max_decoding_message_size(100 * 1024 * 1024) // 100MB limit for large DKG messages
        .max_encoding_message_size(100 * 1024 * 1024);

    // Start serving gRPC requests
    tls_server
        .add_service(node_service)
        .serve(addr)
        .await?;

    Ok(())
}
