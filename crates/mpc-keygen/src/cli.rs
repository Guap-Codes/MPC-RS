//! # Command-Line Interface Definitions
//!
//! This module defines the structure and arguments for the `mpc-keygen` 
//! administrative tool using the `clap` crate. It serves as the primary 
//! interface for operators to trigger and monitor DKG ceremonies across the cluster.

use clap::Parser;
use std::path::PathBuf;

/// MPC Key Generation CLI – triggers a DKG ceremony across the configured nodes.
#[derive(Parser, Debug)]
#[command(name = "mpc-keygen", version, about = "Triggers a DKG ceremony on the MPC nodes")]
pub struct Args {
    /// Path to the JSON configuration file containing node endpoints and TLS paths.
    #[arg(short, long, default_value = "config/keygen.json")]
    pub config: PathBuf,

    /// Optional session ID for the DKG ceremony (UUID format). 
    /// If omitted, a new v4 UUID will be generated automatically.
    #[arg(short, long)]
    pub session_id: Option<String>,

    /// The elliptic curve to use for the DKG ceremony.
    #[arg(long, default_value = "secp256k1")]
    pub curve: String,

    /// The total number of parties (n) participating in the DKG.
    #[arg(long, default_value = "3")]
    pub parties: u32,

    /// The threshold (t) required to reconstruct the key or sign a message.
    #[arg(long, default_value = "2")]
    pub threshold: u32,
}
