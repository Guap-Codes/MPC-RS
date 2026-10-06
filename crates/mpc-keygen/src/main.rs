//! # MPC Key Generation CLI Entry Point
//!
//! This is the main entry point for the `mpc-keygen` tool. It orchestrates the 
//! initialization sequence: parsing command-line arguments, loading the JSON 
//! configuration and mTLS certificates, establishing secure gRPC connections 
//! to the MPC nodes, and executing the DKG ceremony.

mod cli;
mod keygen_session;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;
use tracing::info;
use clap::Parser;
use mpc_protocol::transport::{load_identity, load_ca_cert};
use keygen_session::{NodeRegistry, run_keygen};

/// Configuration file structure (JSON).
#[derive(serde::Deserialize)]
struct Config {
    /// List of MPC nodes to participate in the DKG.
    nodes: Vec<NodeConfig>,
    /// Path to the client's public certificate for mTLS.
    tls_cert_path: PathBuf,
    /// Path to the client's private key for mTLS.
    tls_key_path: PathBuf,
    /// Path to the CA certificate used to verify the nodes.
    ca_cert_path: PathBuf,
}

/// Configuration for a single MPC node.
#[derive(serde::Deserialize)]
struct NodeConfig {
    /// The network address (IP:Port) of the node.
    address: String,
    /// The expected domain name in the node's TLS certificate (for SAN validation).
    domain: String,
}

/// The main asynchronous entry point for the `mpc-keygen` tool.
///
/// # Execution Flow
/// 1. Initializes tracing/logging.
/// 2. Parses CLI arguments.
/// 3. Loads the JSON configuration file.
/// 4. Loads the mTLS identity and CA certificate.
/// 5. Builds the `NodeRegistry` with the configured endpoints.
/// 6. Generates or parses the session ID.
/// 7. Executes the `run_keygen` ceremony and prints the resulting aggregate public key.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = cli::Args::parse();

    // Load configuration
    let cfg: Config = serde_json::from_str(&fs::read_to_string(&args.config)?)?;

    // Load admin's mTLS identity and CA certificate
    let identity = load_identity(&cfg.tls_cert_path, &cfg.tls_key_path)?;
    let ca_cert = load_ca_cert(&cfg.ca_cert_path)?;

    // Build node registry
    let endpoints: Vec<(String, String)> = cfg.nodes.into_iter().map(|n| (n.address, n.domain)).collect();
    let registry = Arc::new(NodeRegistry::new(endpoints, identity, ca_cert));

    // Session ID: use provided or generate a new v4 UUID
    let session_id = if let Some(id_str) = &args.session_id {
        Uuid::parse_str(id_str)?
    } else {
        let id = Uuid::new_v4();
        info!("Generated session ID: {}", id);
        id
    };

    // Execute the DKG ceremony
    let pk = run_keygen(
        registry,
        session_id,
        &args.curve,
        args.threshold,
        args.parties,
    )
    .await?;

    println!("Aggregate public key (hex): {}", hex::encode(&pk));
    Ok(())
}

