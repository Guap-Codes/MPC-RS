//! # MPC API Gateway
//!
//! This is the entry point for the MPC-RS API Gateway. It orchestrates the 
//! initialization of all core dependencies (database, key manager, JWT auth, 
//! coordinator client, and blockchain adapters) and configures the Axum HTTP 
//! router with middleware for authentication and rate limiting.
//!
//! ## Architecture
//! The API Gateway acts as the public-facing interface for the custody system. 
//! It validates incoming requests, constructs unsigned transactions via the 
//! `BlockchainRegistry`, and forwards the signing digest to the `mpc-coordinator` 
//! via secure mTLS gRPC.

mod routes;
mod handlers;
mod middleware;
mod blockchain_builder;
mod key_manager;

use std::net::SocketAddr;
use std::sync::Arc;
use axum::Router; 
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use auth::jwt::JwtManager;

use crate::blockchain_builder::{BlockchainRegistry, Chain};
use crate::middleware::auth::auth_middleware;
use crate::middleware::ratelimit::{RateLimitState, rate_limit_middleware};
use crate::handlers::CoordinatorClient;
use crate::key_manager::MpcKeyManager;
use bitcoin_adapter::fee_estimator::MempoolFeeEstimator;
use bitcoin_adapter::utxo_provider::MempoolUtxoProvider; 
use ethereum_adapter::rpc_provider::RpcEthStateProvider;
use solana_adapter::rpc_provider::RpcSolanaStateProvider; 

use bitcoin::bip32::Xpub;
use bitcoin::Network;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

use bitcoin_adapter::BitcoinAdapter;
use ethereum_adapter::EthereumAdapter;
use solana_adapter::SolanaAdapter;
use tron_adapter::{TronAdapter, HttpTronRpcClient};
use xrp_adapter::{XrpAdapter, JsonRpcClient};

pub mod coordinator_proto {
    tonic::include_proto!("coordinator");
}
use coordinator_proto::coordinator_client::CoordinatorClient as ProtoCoordinatorClient;

/// Shared application state passed to all Axum request handlers.
///
/// This struct is wrapped in Axum's `State` extractor, allowing handlers to 
/// access the coordinator client, blockchain adapters, authentication manager, 
/// rate limiter, and key manager without global variables.
#[derive(Clone)]
pub struct AppState {
    pub coordinator: CoordinatorClient,
    pub blockchain_registry: BlockchainRegistry,
    pub jwt_manager: Arc<JwtManager>,
    pub rate_limit_state: Arc<RateLimitState>,
    pub key_manager: Arc<MpcKeyManager>,
}

/// The main entry point for the API Gateway.
///
/// # Initialization Phases
/// 1. **Environment**: Loads `.env` variables and configures `tracing` to stderr.
/// 2. **Database**: Initializes the SQLite pool and runs migrations.
/// 3. **Key Management**: Initializes the `MpcKeyManager` with the master `Xpub`.
/// 4. **Authentication**: Loads the RSA public key for JWT validation.
/// 5. **Coordinator**: Establishes a secure mTLS gRPC channel to the MPC Coordinator.
/// 6. **Adapters**: Instantiates and registers chain-specific adapters (BTC, ETH, SOL, TRX, XRP).
/// 7. **Routing**: Configures Axum routers with CORS, tracing, auth, and rate-limiting middleware.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 0. Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Force logs to write to stderr (which is unbuffered, ensuring immediate visibility)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    
    // 1. Initialize Database
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://./mpc_wallet.db".to_string());
    
    // Parse the URL into connection options and explicitly enable file creation
    let options = SqliteConnectOptions::from_str(&database_url)
        .expect("Invalid DATABASE_URL format")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    // 2. Initialize Master XPub from Environment (Production Best Practice)
    let master_xpub_str = std::env::var("MASTER_XPUB")
        .expect("MASTER_XPUB environment variable must be set");
    let master_xpub: Xpub = master_xpub_str.parse().expect("Invalid master xpub format");
    let key_manager = Arc::new(MpcKeyManager::new(pool, master_xpub, Network::Bitcoin).await?);

    // 3. Initialize JWT Manager
    let jwt_manager = Arc::new(JwtManager::new(
        jsonwebtoken::Algorithm::RS256,
        include_bytes!("../../../config/public.pem"),
        None, // Private key is None because the API Gateway only validates, not signs, tokens
    )?);

    // 4. Coordinator client setup 
    let identity = mpc_protocol::transport::load_identity(
        std::path::Path::new("config/api-cert.pem"),
        std::path::Path::new("config/api-key.pem"),
    )?;
    
    let ca_cert = mpc_protocol::transport::load_ca_cert(
        std::path::Path::new("config/ca-cert.pem")
    )?;

    // Read from .env, fallback to localhost for local dev
    let coordinator_url = std::env::var("COORDINATOR_URL")
        .unwrap_or_else(|_| "https://127.0.0.1:50052".to_string());
    
    let channel = mpc_protocol::transport::create_tls_channel(
        &coordinator_url,     // The actual IP/URL to connect to
        "coordinator",        // The domain name expected in the TLS certificate
        identity,
        ca_cert,
    ).await?;

    let proto_client = ProtoCoordinatorClient::new(channel);
    let coordinator = CoordinatorClient::new(proto_client);

    // 5. Initialize External Services from .env
    let mempool_url = std::env::var("MEMPOOL_API_URL")
        .unwrap_or_else(|_| "https://mempool.space/api".to_string());
        
    let utxo_provider = MempoolUtxoProvider::new(mempool_url.clone());
    let fee_estimator = MempoolFeeEstimator::new(mempool_url);

    // 6. Initialize and Register Blockchain Adapters
    
    // Bitcoin
    let btc_adapter = Arc::new(BitcoinAdapter::new(
        Network::Bitcoin, 
        utxo_provider, 
        fee_estimator
    ));
    
    // Ethereum
    let eth_rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "https://ethereum-rpc.publicnode.com".to_string());
    let eth_state_provider = Arc::new(RpcEthStateProvider::new(eth_rpc_url.clone()));
    let eth_chain_id = std::env::var("ETH_CHAIN_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse::<u64>()
        .expect("ETH_CHAIN_ID must be a valid u64");
    let eth_adapter = Arc::new(EthereumAdapter::new(eth_chain_id, eth_rpc_url, eth_state_provider));

    // Solana
    let sol_rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let sol_state_provider = Arc::new(RpcSolanaStateProvider::new(sol_rpc_url.clone()));
    let sol_adapter = Arc::new(SolanaAdapter::new(sol_rpc_url, sol_state_provider));

    // Tron
    let tron_rpc_url = std::env::var("TRON_RPC_URL")
        .unwrap_or_else(|_| "https://api.trongrid.io".to_string());
    let tron_rpc_client = HttpTronRpcClient::new(tron_rpc_url.clone());
    let tron_broadcast_url = format!("{}/wallet/broadcasthex", tron_rpc_url);
    let tron_adapter = Arc::new(TronAdapter::new(tron_rpc_client, tron_broadcast_url));

    // XRP
    let xrp_rpc_url = std::env::var("XRP_RPC_URL")
        .unwrap_or_else(|_| "https://s1.ripple.com:51234".to_string());
    let xrp_client = JsonRpcClient::new(&xrp_rpc_url)
        .expect("Failed to initialize XRPL JsonRpcClient");
    
    let xrp_network_id = std::env::var("XRP_NETWORK_ID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let xrp_adapter = Arc::new(XrpAdapter::new(xrp_client, xrp_rpc_url, xrp_network_id));

    // Register all adapters into the unified registry
    let mut blockchain_registry = BlockchainRegistry::new();
    blockchain_registry.register(Chain::Bitcoin, btc_adapter);
    blockchain_registry.register(Chain::Ethereum, eth_adapter); 
    blockchain_registry.register(Chain::Solana, sol_adapter); 
    blockchain_registry.register(Chain::Tron, tron_adapter);
    blockchain_registry.register(Chain::Xrp, xrp_adapter);

    // Initialize rate limiter (e.g., 10 requests per 60 seconds)
    let rate_limit_state = Arc::new(RateLimitState::new(10, 60));

    // Assemble shared application state
    let state = AppState {
        coordinator,
        blockchain_registry,
        jwt_manager,
        rate_limit_state,
        key_manager,
    };

    // 7. Define PROTECTED routes (Auth & Rate Limiting applied)
    let api_routes = Router::new()
        .nest("/api/v1", routes::wallet::routes())
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), rate_limit_middleware));

    // 8. Merge PUBLIC routes (like /health) with the protected routes
    let app = Router::new()
        .merge(routes::health::routes()) // Public routes bypass auth
        .merge(api_routes)               // Protected routes require auth
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    tracing::info!("API gateway listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

