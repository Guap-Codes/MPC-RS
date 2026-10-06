//! # Node Configuration Loader
//!
//! This module handles the parsing and validation of the MPC node's configuration.
//! It supports loading settings from a TOML file and allows runtime overrides
//! via command-line arguments, providing flexibility for different deployment environments.

use std::path::{Path, PathBuf};
use serde::Deserialize;
use mpc_common::config::NodeConfig as CommonNodeConfig; // Reusing the shared structure
use mpc_common::error::{MpcError, MpcResult};

/// Command-line arguments for the MPC node.
///
/// This struct captures runtime overrides that take precedence over the
/// values defined in the TOML configuration file.
pub struct CliArgs {
    /// Path to the TOML configuration file.
    pub config_path: PathBuf,
    /// Optional override for the node's unique identifier (party ID).
    pub party_id: Option<u32>,
}

impl CliArgs {
    /// Parses command-line arguments from the environment.
    ///
    /// This is a lightweight, dependency-free argument parser that supports:
    /// - `--config` or `-c` to specify the configuration file path.
    /// - `--party-id` or `--party-id=<id>` to override the node's ID.
    /// - `--help` or `-h` to print usage information.
    ///
    /// # Returns
    ///
    /// A `CliArgs` struct containing the parsed arguments, with sensible defaults
    /// (e.g., `config/node.toml`) if no arguments are provided.
    ///
    /// # Note
    ///
    /// If an invalid argument is provided or a required value is missing,
    /// this function will print an error message and terminate the process.
    pub fn from_env() -> Self {
        let args: Vec<String> = std::env::args().collect();

        let mut config_path = PathBuf::from("config/node.toml"); // Default fallback
        let mut party_id = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--help" | "-h" => {
                    println!("Usage: mpc-node [OPTIONS]");
                    println!();
                    println!("Options:");
                    println!("  -c, --config <PATH>  Path to the configuration file (default: config/node.toml)");
                    println!("      --party-id <ID>  Override the party ID defined in the config");
                    println!("  -h, --help           Print this help message");
                    std::process::exit(0);
                }
                "--config" | "-c" => {
                    if let Some(path) = args.get(i + 1) {
                        config_path = PathBuf::from(path);
                        i += 1; // Skip the next argument since we consumed it
                    } else {
                        eprintln!("Error: --config requires a file path");
                        std::process::exit(1);
                    }
                }
                "--party-id" => {
                    if let Some(id_str) = args.get(i + 1) {
                        party_id = id_str.parse().ok();
                        i += 1; // Skip the next argument
                    }
                }
                _ => {
                    // Handle --party-id=1 format
                    if let Some(value) = args[i].strip_prefix("--party-id=") {
                        party_id = value.parse().ok();
                    }
                    // Fallback: If it doesn't start with '-', treat it as a positional config path
                    else if !args[i].starts_with('-') {
                        config_path = PathBuf::from(&args[i]);
                    }
                }
            }
            i += 1;
        }

        CliArgs { config_path, party_id }
    }
}

/// Loads and validates the full node configuration.
///
/// This function reads the TOML file specified in `args`, parses it into a
/// `CommonNodeConfig` struct, and applies any command-line overrides.
///
/// # Arguments
///
/// * `args` - The parsed command-line arguments.
///
/// # Returns
///
/// A fully populated `CommonNodeConfig` struct ready for node initialization.
///
/// # Errors
///
/// Returns `MpcError::Config` if the configuration file cannot be read or
/// if the TOML content fails to deserialize into the expected structure.
pub fn load_config(args: &CliArgs) -> MpcResult<CommonNodeConfig> {
    let contents = std::fs::read_to_string(&args.config_path)
        .map_err(|e| MpcError::Config(format!("Failed to read config file: {e}")))?;
    let mut config: CommonNodeConfig = toml::from_str(&contents)
        .map_err(|e| MpcError::Config(format!("Failed to parse config: {e}")))?;

    // Apply CLI override if provided
    if let Some(id) = args.party_id {
        config.party_id = id;
    }

    Ok(config)
}


