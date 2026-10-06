//! # Command-Line Interface Definitions
//!
//! This module defines the structure and arguments for the `mpc-cli` administrative
//! tool using the `clap` crate. It serves as the primary interface for operators
//! to manage the MPC-RS cluster, initiate cryptographic ceremonies, and execute
//! break-glass procedures.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::commands::dev_token::DevTokenArgs;

/// The root command-line interface for the MPC-RS Admin CLI.
///
/// This struct parses the global arguments (like the configuration file path)
/// and dispatches to the appropriate subcommand.
#[derive(Parser)]
#[command(name = "mpc-cli", version = "1.0", about = "Admin CLI for MPC-RS cluster management")]
pub struct Cli {
    /// Path to the admin configuration file (TOML format).
    ///
    /// This file contains the coordinator URL and paths to the mTLS certificates
    /// required for secure communication with the cluster.
    #[arg(short, long, default_value = "config/admin.toml")]
    pub config: PathBuf,

    /// The specific administrative command to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// The set of available administrative commands for the MPC-RS cluster.
#[derive(Subcommand)]
pub enum Commands {
    /// Initiates a Distributed Key Generation (DKG) session for secp256k1 curves.
    ///
    /// This command orchestrates the multi-party computation required to generate
    /// a new threshold vault without any single node ever holding the complete private key.
    Keygen {
        /// The elliptic curve to use for the DKG (e.g., "secp256k1").
        #[arg(short, long, default_value = "secp256k1")]
        curve: String,
        
        /// The threshold (t) for the t-of-n secret sharing scheme.
        #[arg(short, long, default_value_t = 2)]
        threshold: u32,
    },

    /// Generates a new Solana (Ed25519) vault using the FROST DKG protocol.
    ///
    /// This is distinct from the standard `keygen` command because Solana requires
    /// the FROST (Flexible Round-Optimized Schnorr Threshold) protocol rather than CGGMP21.
    SolanaKeygen,

    /// Generates Auxiliary Information (Paillier/RSA keys) for all nodes.
    ///
    /// This is a mandatory, one-time setup step required before any CGGMP21 ECDSA
    /// signing ceremonies can take place, as it generates the zero-knowledge proof parameters.
    AuxGen,

    /// Generates a local development JWT for testing administrative endpoints.
    ///
    /// This command runs entirely locally and requires access to the `config/private.pem`
    /// file to sign the token. It does not require a network connection to the coordinator.
    DevToken(DevTokenArgs),

    /// Triggers a proactive key share refresh (rotation) for an existing vault.
    ///
    /// This updates the secret shares held by all nodes without changing the master
    /// public key or blockchain addresses, invalidating any previously compromised shares.
    Rotate {
        /// The unique identifier of the vault/key to refresh.
        #[arg(short, long)]
        key_id: String,
    },

    /// Checks the health and operational status of the coordinator and all registered nodes.
    ///
    /// This is useful for verifying that all nodes are online, their HSMs are responsive,
    /// and no sessions are stuck before initiating a critical operation.
    Status,

    /// Requests encrypted share backups from all registered nodes.
    ///
    /// This is a critical disaster recovery operation. The retrieved encrypted blobs
    /// should be stored in geographically distributed, physically secure locations.
    Backup {
        /// The local directory where the node backup files will be saved.
        #[arg(short, long)]
        output_dir: PathBuf,
    },

    /// Emergency break-glass: Signs and broadcasts a transaction draining funds to a cold wallet.
    ///
    /// ⚠️ **WARNING**: This is a highly privileged, destructive operation. It requires
    /// a valid human approver signature and will permanently move funds out of the MPC vault.
    Drain {
        /// The target blockchain network (e.g., "bitcoin", "ethereum").
        #[arg(short, long)]
        chain: String,
        
        /// The source MPC address currently holding the funds.
        #[arg(short, long)]
        from_address: String,
        
        /// The destination cold wallet or recovery address.
        #[arg(short, long)]
        target_address: String,
        
        /// The BIP32 derivation path of the key to authorize the drain (e.g., "m/0/0").
        #[arg(short, long, default_value = "m/0/0")]
        derivation_path: String,
    },
}

