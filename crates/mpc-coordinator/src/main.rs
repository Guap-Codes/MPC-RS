//! # MPC Coordinator Entry Point
//!
//! This is the main entry point for the MPC Coordinator service. It orchestrates 
//! the initialization of all core dependencies (mTLS, JWT validation, node registry, 
//! blockchain adapters) and starts the gRPC server.
//!
//! ## Architectural Role
//! The Coordinator acts as the central hub for the MPC cluster. It exposes two 
//! distinct gRPC services on the same port:
//! 1. **`Coordinator`**: The external-facing service used by the API Gateway and CLI 
//!    to initiate sessions, check status, and request backups. Protected by JWT + mTLS.
//! 2. **`MpcCoordinator`**: The internal-facing service used exclusively by MPC nodes 
//!    to report their partial signature shares. Protected by mTLS only.

#![allow(clippy::double_must_use)]


mod auth;
mod coordinator;
mod api;
mod session_store;
mod drain_orchestrator; 

use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tonic::transport::{Server, ServerTlsConfig};
use mpc_common::types::PartyId;
use mpc_protocol::transport::{load_ca_cert, load_identity};
use coordinator::NodeRegistry;
use session_store::SessionStore;
use api::CoordinatorService;
use ::auth::JwtManager;
use jsonwebtoken::Algorithm;

// Import adapters natively!
use adapter_core::traits::BlockchainAdapter;
use bitcoin_adapter::{BitcoinAdapter, utxo_provider::MempoolUtxoProvider, fee_estimator::MempoolFeeEstimator};
use ethereum_adapter::{EthereumAdapter, rpc_provider::RpcEthStateProvider};
use solana_adapter::{SolanaAdapter, rpc_provider::RpcSolanaStateProvider};
use tron_adapter::{TronAdapter, HttpTronRpcClient};
use xrp_adapter::{XrpAdapter, JsonRpcClient};
use bitcoin::Network;

pub mod coordinator_proto {
    tonic::include_proto!("coordinator");
}

/// The main asynchronous entry point for the MPC Coordinator.
///
/// # Initialization Sequence
/// 1. Loads environment variables and initializes tracing.
/// 2. Loads mTLS certificates for secure gRPC communication.
/// 3. Initializes the JWT manager for authenticating external API/CLI requests.
/// 4. Registers the known MPC nodes and their network endpoints.
/// 5. Instantiates production blockchain adapters for transaction building/broadcasting.
/// 6. Starts the gRPC server, serving both the external `Coordinator` and internal `MpcCoordinator` services.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    // 1. Load mTLS identity and CA certificate
    let identity = load_identity(
        std::path::Path::new("config/coordinator-cert.pem"),
        std::path::Path::new("config/coordinator-key.pem"),
    )?;
    let ca_cert = load_ca_cert(std::path::Path::new("config/ca-cert.pem"))?;

    // 2. Initialize JWT Manager (strictly for "mpc-coordinator" audience)
    let jwt_public_pem = std::fs::read("config/public.pem")
        .expect("Failed to read config/public.pem for JWT validation");
    let jwt_manager = Arc::new(JwtManager::new(Algorithm::RS256, &jwt_public_pem, None)?.with_audience("mpc-coordinator"));

    // 3. Node Registry Setup
    let mut node_registry = NodeRegistry::new(identity.clone(), ca_cert.clone());
    for i in 1..=3 {
        let url = std::env::var(format!("NODE_{i}_URL")).unwrap_or_else(|_| format!("https://127.0.0.1:5000{i}"));
        let domain = std::env::var(format!("NODE_{i}_DOMAIN")).unwrap_or_else(|_| format!("node{i}"));
        node_registry.add_entry(PartyId(i as u32), url, domain);
    }
    let node_registry = Arc::new(node_registry);
    let session_store = Arc::new(SessionStore::new());

    // 4. Initialize Production Blockchain Adapters
    let mut adapters: HashMap<String, Arc<dyn BlockchainAdapter>> = HashMap::new();

    let mempool_url = std::env::var("MEMPOOL_API_URL").unwrap_or_else(|_| "https://mempool.space/api".into());
    adapters.insert("bitcoin".to_string(), Arc::new(BitcoinAdapter::new(
        Network::Bitcoin,
        MempoolUtxoProvider::new(mempool_url.clone()),
        MempoolFeeEstimator::new(mempool_url),
    )));

    let eth_rpc_url = std::env::var("ETH_RPC_URL").unwrap_or_else(|_| "https://ethereum-rpc.publicnode.com".into());
    let eth_chain_id = std::env::var("ETH_CHAIN_ID").unwrap_or_else(|_| "1".into()).parse::<u64>().unwrap_or(1);
    adapters.insert("ethereum".to_string(), Arc::new(EthereumAdapter::new(
        eth_chain_id, eth_rpc_url.clone(), Arc::new(RpcEthStateProvider::new(eth_rpc_url))
    )));

    let sol_rpc_url = std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into());
    adapters.insert("solana".to_string(), Arc::new(SolanaAdapter::new(
        sol_rpc_url.clone(), Arc::new(RpcSolanaStateProvider::new(sol_rpc_url))
    )));

    let tron_rpc_url = std::env::var("TRON_RPC_URL").unwrap_or_else(|_| "https://api.trongrid.io".into());
    adapters.insert("tron".to_string(), Arc::new(TronAdapter::new(
        HttpTronRpcClient::new(tron_rpc_url.clone()), format!("{}/wallet/broadcasthex", tron_rpc_url)
    )));

    let xrp_rpc_url = std::env::var("XRP_RPC_URL").unwrap_or_else(|_| "https://s1.ripple.com:51234".into());
    let xrp_client = JsonRpcClient::new(&xrp_rpc_url).expect("Failed to init XRP client");
    let xrp_network_id = std::env::var("XRP_NETWORK_ID").ok().and_then(|s| s.parse::<u32>().ok());
    adapters.insert("xrp".to_string(), Arc::new(XrpAdapter::new(xrp_client, xrp_rpc_url, xrp_network_id)));

    // 5. Initialize Coordinator Service
    // Wrap in Arc so we can share it between the two gRPC server implementations
    let coordinator_svc = Arc::new(CoordinatorService::new(session_store, node_registry, jwt_manager, adapters));

    // 6. Configure and start the gRPC Server
    let tls_config = ServerTlsConfig::new().identity(identity).client_ca_root(ca_cert);
    let addr: SocketAddr = std::env::var("COORDINATOR_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:50052".to_string()).parse()?;
        
    tracing::info!("Coordinator listening on {}", addr);

    Server::builder()
        .tls_config(tls_config)?
        // Service 1: External-facing (CLI / Admin / API Gateway)
        .add_service(coordinator_proto::coordinator_server::CoordinatorServer::from_arc(coordinator_svc.clone()))
        // Service 2: Internal-facing (MPC Nodes reporting signatures)
        .add_service(mpc_protocol::proto::mpc_coordinator_server::MpcCoordinatorServer::from_arc(coordinator_svc))
        .serve(addr).await?;

    Ok(())
}

