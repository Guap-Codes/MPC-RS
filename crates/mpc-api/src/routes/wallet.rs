//! # Wallet Operation Routes
//!
//! This module defines the protected HTTP endpoints for core custody operations,
//! including cryptographic address derivation and MPC transaction signing.
//!
//! ## Security Context
//! These routes are designed to be mounted under a middleware stack that enforces
//! JWT-based authentication and IP-based rate limiting. They rely on the shared
//! `AppState` to securely access the `MpcKeyManager`, `BlockchainRegistry`, and 
//! the mTLS-secured `CoordinatorClient`.

use axum::{Router, routing::post};
use crate::handlers::{sign, address};
use crate::AppState;

/// Constructs the router for protected wallet operation endpoints.
///
/// This router is intended to be nested under the `/api/v1` path prefix and 
/// wrapped with authentication and rate-limiting middleware layers.
///
/// # Endpoints
///
/// - `POST /wallet/sign`: Initiates the end-to-end MPC transaction signing workflow, 
///   returning the finalized signed transaction and its hash.
/// - `POST /wallet/address`: Derives a new, chain-specific blockchain address from 
///   a provided BIP32 derivation path.
///
/// # Returns
///
/// An Axum `Router` explicitly typed to require `AppState` for its handlers, 
/// ensuring compile-time guarantees that all necessary dependencies are available.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/wallet/sign", post(sign::sign_transaction))
        .route("/wallet/address", post(address::derive_address))
}
