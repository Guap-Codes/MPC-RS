//! # CLI Command Implementations
//!
//! This module contains the business logic for all administrative commands
//! available in the `mpc-cli` tool. Each submodule corresponds to a specific
//! operational workflow, such as cryptographic ceremony initiation, cluster
//! monitoring, disaster recovery, and break-glass procedures.
//!
//! ## Command Overview
//! - `keygen`: Initiate a new Distributed Key Generation (DKG) ceremony.
//! - `rotate`: Trigger a proactive key share refresh (rotation) for forward secrecy.
//! - `status`: Check the health and operational status of the Coordinator and nodes.
//! - `backup`: Request and save encrypted share backups from all nodes.
//! - `drain`: Execute an emergency break-glass transaction to sweep vault funds.
//! - `dev_token`: Generate a local development JWT for testing administrative endpoints.
//! - `aux_gen`: Initiate the Auxiliary Information Generation phase for CGGMP21.
//! - `solana_keygen`: Initiate a FROST DKG ceremony specifically for Ed25519 (Solana).

pub mod keygen;
pub mod rotate;
pub mod status;
pub mod backup;
pub mod drain;
pub mod dev_token;
pub mod aux_gen;
pub mod solana_keygen;
