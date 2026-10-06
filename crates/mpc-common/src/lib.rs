//! # MPC Common Types and Utilities
//!
//! This crate serves as the foundational data layer for the entire MPC-RS ecosystem.
//! It contains shared types, error definitions, configuration schemas, and audit 
//! logging utilities.
//!
//! ## Architectural Role
//! This crate is intentionally kept free of network or protocol logic. It acts as 
//! the single source of truth for data structures used across all other `mpc-*` 
//! crates (e.g., `mpc-core`, `mpc-api`, `mpc-node`), ensuring strict consistency 
//! and preventing circular dependencies.

pub mod audit;
pub mod config;
pub mod error;
pub mod types;

// Re-export commonly used items for ergonomic access by downstream crates.
pub use audit::AuditEvent;
pub use config::NodeConfig;
pub use error::MpcError;
pub use types::*;

