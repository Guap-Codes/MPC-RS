//! # Health Check Routes
//!
//! This module provides public, unauthenticated endpoints for infrastructure
//! health monitoring, load balancer probes, and Kubernetes readiness/liveness checks.
//!
//! ## Performance Note
//! Because these endpoints do not require authentication or database access, 
//! they are designed to be extremely lightweight and must not perform expensive 
//! operations, ensuring they can respond instantly even under heavy load.

use axum::{Router, routing::get, response::Json};
use serde::Serialize;

/// Response payload for the health check endpoint.
#[derive(Debug, Serialize)]
pub struct Health {
    /// The operational status of the service (e.g., `"ok"`).
    pub status: &'static str,
    /// The current version of the `mpc-api` crate, sourced at compile time 
    /// from the `CARGO_PKG_VERSION` environment variable.
    pub version: &'static str,
}

/// Handles GET requests to the `/health` endpoint.
///
/// # Returns
///
/// A JSON response containing the service status and version, automatically 
/// mapped to a `200 OK` HTTP status code by Axum.
async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Constructs the router for public health check endpoints.
///
/// # Arguments
///
/// * `S` - The type of the shared application state. It must be `Clone`, 
///   `Send`, `Sync`, and `'static` to be compatible with Axum's `State` extractor.
///
/// # Returns
///
/// An Axum `Router` configured with the `/health` GET route.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/health", get(health))
}
